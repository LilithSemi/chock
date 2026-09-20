//! Every test here reads a claim out of a file a person reads and compares it
//! with the code. The truth always comes from the code or from the disk, never
//! from a second list in this file.
//!
//! Each test collects what it found into one string and compares that against
//! the empty string, so one run reports every wrong sentence and nothing goes
//! to standard error, which `zig build test` refuses.

const std = @import("std");
const chock_main = @import("chock_main");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

/// From `build.zig`. Not the working directory: a test binary cannot say what
/// directory `zig build` was started from.
const repo_root = @import("repo_root").repo_root;

const testing = std.testing;

const max_doc_bytes = 512 * 1024;

const max_source_bytes = 4 * 1024 * 1024;

/// Words the documentation shows after `chock` on purpose that name no command:
/// the pages teach the first word with a line that is refused. Both ends are
/// checked, so an entry cannot rot.
const refused_examples = [_][]const u8{ "fix", "rnu" };

/// Options the documentation names that belong to another program. `--jitless`
/// is Node's, and `--offline` is Nix's, where it turns a substituter off without
/// stopping a fixed output build from fetching. Both ends are checked.
const foreign_options = [_][]const u8{ "--jitless", "--offline" };

const Doc = struct {
    path: []const u8,
    text: []const u8,
};

/// The root is read one level deep, because the fetched packages under
/// `zig-pkg/` carry markdown of their own and are not ours. Sorted by path, so
/// a failure reads the same way twice.
fn loadDocs(arena: std.mem.Allocator, io: std.Io) ![]Doc {
    var docs: std.ArrayList(Doc) = .empty;

    var root = try std.Io.Dir.openDirAbsolute(io, repo_root, .{ .iterate = true });
    defer root.close(io);

    var root_entries = root.iterate();
    while (try root_entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
        try docs.append(arena, .{
            .path = try arena.dupe(u8, entry.name),
            .text = try root.readFileAlloc(io, entry.name, arena, .limited(max_doc_bytes)),
        });
    }

    var pages = try root.openDir(io, "docs", .{ .iterate = true });
    defer pages.close(io);

    var page_entries = try pages.walk(arena);
    defer page_entries.deinit();
    while (try page_entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.path, ".md")) continue;
        try docs.append(arena, .{
            .path = try std.fmt.allocPrint(arena, "docs/{s}", .{entry.path}),
            .text = try pages.readFileAlloc(io, entry.path, arena, .limited(max_doc_bytes)),
        });
    }

    std.mem.sort(Doc, docs.items, {}, lessByPath);
    return docs.items;
}

fn lessByPath(_: void, a: Doc, b: Doc) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

fn docText(docs: []const Doc, path: []const u8) ![]const u8 {
    for (docs) |doc| {
        if (std.mem.eql(u8, doc.path, path)) return doc.text;
    }
    return error.NoSuchDoc;
}

fn loadSources(arena: std.mem.Allocator, io: std.Io, tops: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;

    var root = try std.Io.Dir.openDirAbsolute(io, repo_root, .{ .iterate = true });
    defer root.close(io);

    for (tops) |top| {
        var dir = try root.openDir(io, top, .{ .iterate = true });
        defer dir.close(io);

        var walker = try dir.walk(arena);
        defer walker.deinit();

        while (try walker.next(io)) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.path, ".zig")) continue;
            const text = try dir.readFileAlloc(io, entry.path, arena, .limited(max_source_bytes));
            try out.appendSlice(arena, text);
            try out.append(arena, '\n');
        }
    }

    return out.items;
}

const all_code = [_][]const u8{ "src", "lib" };

/// `lib/` never parses a command line, so every option is a literal under
/// `src/`. A search of the libraries too would accept `--quiet`, which
/// `chock-broker` gives to git.
const command_line_code = [_][]const u8{"src"};

const Span = struct {
    doc: []const u8,
    line: usize,
    text: []const u8,
    fenced: bool,
};

/// A fenced block gives one span per line, because a command line is a line.
fn collectSpans(arena: std.mem.Allocator, doc: Doc, out: *std.ArrayList(Span)) !void {
    var lines = std.mem.splitScalar(u8, doc.text, '\n');
    var number: usize = 0;
    var fenced = false;
    while (lines.next()) |line| {
        number += 1;
        if (std.mem.startsWith(u8, line, "```")) {
            fenced = !fenced;
            continue;
        }
        if (fenced) {
            const text = std.mem.trim(u8, line, " \t");
            if (text.len == 0) continue;
            try out.append(arena, .{ .doc = doc.path, .line = number, .text = text, .fenced = true });
            continue;
        }
        var rest = line;
        while (std.mem.indexOfScalar(u8, rest, '`')) |open| {
            const after = rest[open + 1 ..];
            const close = std.mem.indexOfScalar(u8, after, '`') orelse break;
            try out.append(arena, .{
                .doc = doc.path,
                .line = number,
                .text = after[0..close],
                .fenced = false,
            });
            rest = after[close + 1 ..];
        }
    }
}

fn allSpans(arena: std.mem.Allocator, docs: []const Doc) ![]const Span {
    var spans: std.ArrayList(Span) = .empty;
    for (docs) |doc| try collectSpans(arena, doc, &spans);
    return spans.items;
}

fn isChockLine(span: Span) bool {
    var words = std.mem.tokenizeAny(u8, span.text, " \t");
    const first = words.next() orelse return false;
    return std.mem.eql(u8, first, "chock");
}

/// `--` alone ends the options and is never one of them.
fn optionName(token: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, token, "--")) return null;
    var end: usize = 2;
    while (end < token.len) : (end += 1) {
        const c = token[end];
        const ok = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9') or c == '-';
        if (!ok) break;
    }
    if (end == 2) return null;
    return token[0..end];
}

/// Both spellings, because `src/tty.zig` reads `--color=<when>` with one
/// literal that carries the `=`.
fn sourceHasOption(source: []const u8, option: []const u8, arena: std.mem.Allocator) !bool {
    const plain = try std.fmt.allocPrint(arena, "\"{s}\"", .{option});
    if (std.mem.indexOf(u8, source, plain) != null) return true;
    const valued = try std.fmt.allocPrint(arena, "\"{s}=", .{option});
    return std.mem.indexOf(u8, source, valued) != null;
}

fn isCommand(name: []const u8) bool {
    for (chock_main.commands) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return true;
    }
    return false;
}

fn isMadeOf(word: []const u8, comptime extra: []const u8) bool {
    if (word.len == 0) return false;
    for (word) |c| {
        const plain = (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9');
        if (plain) continue;
        if (std.mem.indexOfScalar(u8, extra, c) != null) continue;
        return false;
    }
    return true;
}

fn countWord(word: []const u8) ?usize {
    if (std.fmt.parseInt(usize, word, 10)) |digits| return digits else |_| {}
    return numberWord(word);
}

fn numberWord(word: []const u8) ?usize {
    const words = [_][]const u8{
        "zero",    "one",     "two",       "three",    "four",
        "five",    "six",     "seven",     "eight",    "nine",
        "ten",     "eleven",  "twelve",    "thirteen", "fourteen",
        "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
        "twenty",
    };
    for (words, 0..) |one, value| {
        if (std.ascii.eqlIgnoreCase(one, word)) return value;
    }
    return null;
}

fn checkCount(
    arena: std.mem.Allocator,
    docs: []const Doc,
    only: ?[]const u8,
    noun: []const u8,
    truth: usize,
    out: *std.ArrayList(u8),
) !void {
    for (docs) |doc| {
        if (only) |path| {
            if (!std.mem.eql(u8, doc.path, path)) continue;
        }
        var lines = std.mem.splitScalar(u8, doc.text, '\n');
        var number: usize = 0;
        while (lines.next()) |line| {
            number += 1;
            var words = std.mem.tokenizeAny(u8, line, " \t");
            var previous: ?[]const u8 = null;
            while (words.next()) |word| {
                defer previous = word;
                const trimmed = std.mem.trim(u8, word, ".,:;`*");
                if (!std.mem.eql(u8, trimmed, noun)) continue;
                const before = previous orelse continue;
                const said = countWord(std.mem.trim(u8, before, ".,:;`*")) orelse continue;
                if (said == truth) continue;
                try out.print(arena, "{s}:{d}: says {s} {s}, and the code has {d}\n", .{
                    doc.path, number, before, noun, truth,
                });
            }
        }
    }
}

fn namesInTicks(text: []const u8, word: []const u8, arena: std.mem.Allocator) !bool {
    const ticked = try std.fmt.allocPrint(arena, "`{s}`", .{word});
    return std.mem.indexOf(u8, text, ticked) != null;
}

fn repoHas(io: std.Io, arena: std.mem.Allocator, path: []const u8) !bool {
    const full = try std.fs.path.join(arena, &.{ repo_root, path });
    _ = std.Io.Dir.cwd().statFile(io, full, .{}) catch return false;
    return true;
}

test "the documentation index names every page under docs/" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const index = try docText(docs, "docs/README.md");

    var missing: std.ArrayList(u8) = .empty;
    for (docs) |doc| {
        if (!std.mem.startsWith(u8, doc.path, "docs/")) continue;
        if (std.mem.eql(u8, doc.path, "docs/README.md")) continue;
        const name = doc.path["docs/".len..];
        const link = try std.fmt.allocPrint(arena, "]({s})", .{name});
        if (std.mem.indexOf(u8, index, link) != null) continue;
        try missing.print(arena, "docs/README.md names no link to {s}\n", .{name});
    }

    try testing.expectEqualStrings("", missing.items);
}

test "every path the documentation names is in the repository" {
    // A link is read relative to the page it is on, the way a browser reads it.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var tops: std.ArrayList([]const u8) = .empty;
    {
        var root = try std.Io.Dir.openDirAbsolute(testing.io, repo_root, .{ .iterate = true });
        defer root.close(testing.io);
        var entries = root.iterate();
        while (try entries.next(testing.io)) |entry| {
            if (entry.kind != .directory) continue;
            if (std.mem.startsWith(u8, entry.name, ".")) continue;
            try tops.append(arena, try std.fmt.allocPrint(arena, "{s}/", .{entry.name}));
        }
    }
    try testing.expect(tops.items.len > 0);

    var missing: std.ArrayList(u8) = .empty;
    var checked: usize = 0;

    for (docs) |doc| {
        const directory = std.fs.path.dirname(doc.path) orelse "";
        var rest = doc.text;
        while (std.mem.indexOf(u8, rest, "](")) |open| {
            rest = rest[open + 2 ..];
            const close = std.mem.indexOfScalar(u8, rest, ')') orelse break;
            const target = rest[0..close];
            rest = rest[close + 1 ..];
            if (std.mem.startsWith(u8, target, "http")) continue;
            if (std.mem.startsWith(u8, target, "mailto:")) continue;
            if (std.mem.startsWith(u8, target, "#")) continue;
            const file = if (std.mem.indexOfScalar(u8, target, '#')) |hash| target[0..hash] else target;
            if (file.len == 0) continue;
            checked += 1;
            const path = try std.fs.path.join(arena, &.{ directory, file });
            if (try repoHas(testing.io, arena, path)) continue;
            try missing.print(arena, "{s}: the link to {s} reaches nothing\n", .{ doc.path, target });
        }
    }

    const spans = try allSpans(arena, docs);
    for (spans) |span| {
        // A fence holds an example of what a reader writes in their own
        // project, so a path in one is theirs and not ours.
        if (span.fenced) continue;
        var words = std.mem.tokenizeAny(u8, span.text, " \t,()");
        while (words.next()) |word| {
            const token = std.mem.trim(u8, word, ".,:;`\"");
            var names_repo = false;
            for (tops.items) |top| {
                if (std.mem.startsWith(u8, token, top)) names_repo = true;
            }
            if (!names_repo) continue;
            checked += 1;
            if (try repoHas(testing.io, arena, token)) continue;
            try missing.print(arena, "{s}:{d}: {s} is not in the repository\n", .{
                span.doc, span.line, token,
            });
        }
    }

    try testing.expect(checked >= 40);
    try testing.expectEqualStrings("", missing.items);
}

test "every command the documentation shows is a command Chock answers to" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const spans = try allSpans(arena, docs);

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (spans) |span| {
        if (!isChockLine(span)) continue;
        var words = std.mem.tokenizeAny(u8, span.text, " \t");
        _ = words.next();
        const second = words.next() orelse continue;
        if (std.mem.startsWith(u8, second, "#")) continue;
        if (std.mem.startsWith(u8, second, "\"")) continue;
        if (std.mem.startsWith(u8, second, "<")) continue;
        if (std.mem.startsWith(u8, second, "[")) continue;
        if (std.mem.startsWith(u8, second, "-")) continue;
        const name = std.mem.trimEnd(u8, second, ":");
        if (!isMadeOf(name, "-")) continue;
        checked += 1;
        if (isCommand(name)) continue;
        var excused = false;
        for (refused_examples) |example| {
            if (std.mem.eql(u8, name, example)) excused = true;
        }
        if (excused) continue;
        try wrong.print(arena, "{s}:{d}: chock {s} names no command\n", .{
            span.doc, span.line, name,
        });
    }

    // A floor well under what the pages hold today, so an ordinary edit never
    // reaches it and a scanner that stopped working does.
    try testing.expect(checked >= 20);
    try testing.expectEqualStrings("", wrong.items);
}

test "the words the documentation shows as refused are still refused, and still shown" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var wrong: std.ArrayList(u8) = .empty;
    for (refused_examples) |example| {
        if (isCommand(example)) {
            try wrong.print(arena, "chock {s} is a command now, so it is no longer an example of a refusal\n", .{example});
        }
        const shown = try std.fmt.allocPrint(arena, "chock {s}", .{example});
        var found = false;
        for (docs) |doc| {
            if (std.mem.indexOf(u8, doc.text, shown) != null) found = true;
        }
        if (!found) {
            try wrong.print(arena, "no page shows `chock {s}`, so this exception is dead\n", .{example});
        }
    }

    try testing.expectEqualStrings("", wrong.items);
}

test "every subcommand word the documentation shows is read by that command" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var root = try std.Io.Dir.openDirAbsolute(testing.io, repo_root, .{});
    defer root.close(testing.io);

    const spans = try allSpans(arena, docs);

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (spans) |span| {
        if (!isChockLine(span)) continue;
        var words = std.mem.tokenizeAny(u8, span.text, " \t");
        _ = words.next();
        const command = words.next() orelse continue;
        if (!isCommand(command)) continue;
        const word = words.next() orelse continue;
        if (std.mem.startsWith(u8, word, "-")) continue;
        if (!isMadeOf(word, "-")) continue;

        const file = try std.fmt.allocPrint(arena, "src/{s}.zig", .{command});
        const text = root.readFileAlloc(testing.io, file, arena, .limited(max_source_bytes)) catch {
            try wrong.print(arena, "{s}:{d}: chock {s} has no {s}\n", .{
                span.doc, span.line, command, file,
            });
            continue;
        };
        const literal = try std.fmt.allocPrint(arena, "\"{s}\"", .{word});
        checked += 1;
        if (std.mem.indexOf(u8, text, literal) != null) continue;
        try wrong.print(arena, "{s}:{d}: chock {s} {s}: {s} reads no such word\n", .{
            span.doc, span.line, command, word, file,
        });
    }

    try testing.expect(checked >= 10);
    try testing.expectEqualStrings("", wrong.items);
}

test "every option the documentation names is an option the code reads" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &command_line_code);
    const spans = try allSpans(arena, docs);

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (spans) |span| {
        const bare_option = std.mem.startsWith(u8, span.text, "--") and !span.fenced;
        if (!isChockLine(span) and !bare_option) continue;

        var words = std.mem.tokenizeAny(u8, span.text, " \t");
        // A message Chock writes is not a command line. One can name another
        // program's option inside Chock's own sentence.
        if (isChockLine(span)) {
            var head = std.mem.tokenizeAny(u8, span.text, " \t");
            _ = head.next();
            if (head.next()) |second| {
                if (std.mem.endsWith(u8, second, ":")) continue;
            }
        }
        while (words.next()) |word| {
            if (std.mem.startsWith(u8, word, "#")) break;
            if (std.mem.eql(u8, word, "--")) break;
            const option = optionName(std.mem.trim(u8, word, "`\"")) orelse continue;
            checked += 1;
            if (try sourceHasOption(source, option, arena)) continue;
            var excused = false;
            for (foreign_options) |foreign| {
                if (std.mem.eql(u8, option, foreign)) excused = true;
            }
            if (excused) continue;
            try wrong.print(arena, "{s}:{d}: {s} is not an option the code reads\n", .{
                span.doc, span.line, option,
            });
        }
    }

    try testing.expect(checked >= 25);
    try testing.expectEqualStrings("", wrong.items);
}

test "the options the documentation credits to another program are still not ours" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &command_line_code);

    var wrong: std.ArrayList(u8) = .empty;
    for (foreign_options) |foreign| {
        if (try sourceHasOption(source, foreign, arena)) {
            try wrong.print(arena, "{s} is an option of ours now, so it is not another program's\n", .{foreign});
        }
        var found = false;
        for (docs) |doc| {
            if (std.mem.indexOf(u8, doc.text, foreign) != null) found = true;
        }
        if (!found) {
            try wrong.print(arena, "no page names {s}, so this exception is dead\n", .{foreign});
        }
    }

    try testing.expectEqualStrings("", wrong.items);
}

test "every command Chock answers to is named in the documentation" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var missing: std.ArrayList(u8) = .empty;
    for (chock_main.commands) |entry| {
        const shown = try std.fmt.allocPrint(arena, "chock {s}", .{entry.name});
        var found = false;
        for (docs) |doc| {
            if (std.mem.indexOf(u8, doc.text, shown) != null) found = true;
        }
        if (found) continue;
        try missing.print(arena, "no page names chock {s}\n", .{entry.name});
    }

    try testing.expectEqualStrings("", missing.items);
}

test "the exit code table has one row for each code, with the number the code has" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const running = try docText(docs, "docs/running.md");

    var rows: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, running, '\n');
    var found: usize = 0;
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "|")) continue;
        var cells = std.mem.splitScalar(u8, line[1..], '|');
        const first = std.mem.trim(u8, cells.next() orelse continue, " \t");
        const number = std.fmt.parseInt(u8, first, 10) catch continue;
        const wanted: u8 = @intCast(found);
        if (number != wanted) {
            try rows.print(arena, "docs/running.md: row {d} carries the code {d}\n", .{ found, number });
        }
        found += 1;
    }

    const codes = @typeInfo(chock_main.Exit).@"enum".fields.len;
    if (found != codes) {
        try rows.print(arena, "docs/running.md: the table has {d} rows, and Exit has {d} members\n", .{ found, codes });
    }

    try testing.expectEqualStrings("", rows.items);
}

test "the tool list names every tool, and counts them right" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const page = try docText(docs, "docs/using/tools.md");
    const fields = @typeInfo(chock_core.tools.Tool).@"enum".fields;

    var wrong: std.ArrayList(u8) = .empty;
    inline for (fields) |field| {
        if (!try namesInTicks(page, field.name, arena)) {
            try wrong.print(arena, "docs/using/tools.md names no tool `{s}`\n", .{field.name});
        }
    }
    try checkCount(arena, docs, null, "tools", fields.len, &wrong);

    try testing.expectEqualStrings("", wrong.items);
}

test "the policy page names every decision and every field of a rule, and counts them right" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const policy = try docText(docs, "docs/configure/policy.md");
    const decisions = @typeInfo(chock_policy.table.Decision).@"enum".fields;
    const rule_fields = @typeInfo(chock_policy.table.Rule).@"struct".fields;

    var wrong: std.ArrayList(u8) = .empty;
    inline for (decisions) |field| {
        if (!try namesInTicks(policy, field.name, arena)) {
            try wrong.print(arena, "docs/configure/policy.md names no decision `{s}`\n", .{field.name});
        }
    }
    inline for (rule_fields) |field| {
        if (!try namesInTicks(policy, field.name, arena)) {
            try wrong.print(arena, "docs/configure/policy.md names no rule field `{s}`\n", .{field.name});
        }
    }
    // Only this page: `fields` and `decisions` are ordinary words elsewhere.
    try checkCount(arena, docs, "docs/configure/policy.md", "decisions", decisions.len, &wrong);
    try checkCount(arena, docs, "docs/configure/policy.md", "fields", rule_fields.len, &wrong);

    try testing.expectEqualStrings("", wrong.items);
}

test "every name the documentation spells with an underscore is a name the code has" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &all_code);
    const spans = try allSpans(arena, docs);

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (spans) |span| {
        if (span.fenced) continue;
        if (!isMadeOf(span.text, "_")) continue;
        if (std.mem.indexOfScalar(u8, span.text, '_') == null) continue;
        checked += 1;
        if (std.mem.indexOf(u8, source, span.text) != null) continue;
        try wrong.print(arena, "{s}:{d}: the code has no {s}\n", .{
            span.doc, span.line, span.text,
        });
    }

    try testing.expect(checked >= 50);
    try testing.expectEqualStrings("", wrong.items);
}

test "every action a table row names is an action the code has" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &all_code);

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (docs) |doc| {
        var lines = std.mem.splitScalar(u8, doc.text, '\n');
        var number: usize = 0;
        while (lines.next()) |line| {
            number += 1;
            if (!std.mem.startsWith(u8, line, "|")) continue;
            var cells = std.mem.splitScalar(u8, line[1..], '|');
            const first = std.mem.trim(u8, cells.next() orelse continue, " \t");
            if (first.len < 3 or first[0] != '`' or first[first.len - 1] != '`') continue;
            const name = first[1 .. first.len - 1];
            if (!isMadeOf(name, "_.")) continue;
            if (std.mem.indexOfScalar(u8, name, '.') == null) continue;
            const literal = try std.fmt.allocPrint(arena, "\"{s}\"", .{name});
            checked += 1;
            if (std.mem.indexOf(u8, source, literal) != null) continue;
            try wrong.print(arena, "{s}:{d}: the code holds no action {s}\n", .{
                doc.path, number, name,
            });
        }
    }

    try testing.expect(checked >= 8);
    try testing.expectEqualStrings("", wrong.items);
}

test "a message the documentation shows is a message the code writes" {
    // Byte for byte is not possible: a sample block carries a session
    // identifier, a hash and a path from another machine. Only the words in
    // front of the first of those are compared.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &all_code);
    const spans = try allSpans(arena, docs);

    const words_compared = 3;

    var wrong: std.ArrayList(u8) = .empty;
    var checked: usize = 0;
    for (spans) |span| {
        if (!span.fenced) continue;
        if (!isChockLine(span)) continue;
        var words = std.mem.tokenizeAny(u8, span.text, " \t");
        _ = words.next();
        const second = words.next() orelse continue;
        if (!std.mem.endsWith(u8, second, ":")) continue;
        const command = std.mem.trimEnd(u8, second, ":");
        if (!isCommand(command)) continue;

        var message: std.ArrayList(u8) = .empty;
        try message.print(arena, "chock {s}:", .{command});
        var taken: usize = 0;
        while (taken < words_compared) {
            const word = words.next() orelse break;
            if (std.mem.indexOfScalar(u8, word, '/') != null) break;
            if (std.mem.indexOfAny(u8, word, "0123456789`") != null) break;
            try message.print(arena, " {s}", .{word});
            taken += 1;
        }
        checked += 1;
        if (std.mem.indexOf(u8, source, message.items) != null) continue;
        try wrong.print(arena, "{s}:{d}: the code writes no message starting \"{s}\"\n", .{
            span.doc, span.line, message.items,
        });
    }

    try testing.expect(checked >= 4);
    try testing.expectEqualStrings("", wrong.items);
}

test "the repository layout names every library and every test area" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const contributing = try docText(docs, "CONTRIBUTING.md");

    var root = try std.Io.Dir.openDirAbsolute(testing.io, repo_root, .{});
    defer root.close(testing.io);

    var missing: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "lib", "test" }) |top| {
        var dir = try root.openDir(testing.io, top, .{ .iterate = true });
        defer dir.close(testing.io);
        var entries = dir.iterate();
        while (try entries.next(testing.io)) |entry| {
            if (entry.kind != .directory) continue;
            if (try namesInTicks(contributing, entry.name, arena)) continue;
            try missing.print(arena, "CONTRIBUTING.md names no `{s}` under {s}/\n", .{ entry.name, top });
        }
    }

    try testing.expectEqualStrings("", missing.items);
}

test "the sandbox page counts the calls it blocks and the proc entries it masks" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var wrong: std.ArrayList(u8) = .empty;
    try checkCount(
        arena,
        docs,
        "docs/security/sandbox.md",
        "entries",
        chock_sandbox.namespace.masked_proc_entries.len,
        &wrong,
    );
    try checkCount(
        arena,
        docs,
        "docs/security/sandbox.md",
        "calls",
        chock_sandbox.seccomp.blocked_calls.len,
        &wrong,
    );

    try testing.expectEqualStrings("", wrong.items);
}
