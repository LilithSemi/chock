//! Reads documentation claims off disk and checks each one against the code,
//! so the truth is never duplicated into a second list here.

const std = @import("std");
const chock_main = @import("chock_main");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

/// From `build.zig`, not the working directory a test binary cannot know.
const repo_root = @import("repo_root").repo_root;

const testing = std.testing;

const max_doc_bytes = 512 * 1024;

const max_source_bytes = 4 * 1024 * 1024;

/// Words the documentation shows after `chock` on purpose that name no command.
const refused_examples = [_][]const u8{ "fix", "rnu" };

/// Options the documentation names that belong to another program.
const foreign_options = [_][]const u8{ "--jitless", "--offline" };

const Doc = struct {
    path: []const u8,
    text: []const u8,
};

/// Reads docs one level deep. `zig-pkg/` carries markdown that is not ours.
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

/// Only `src/` parses a command line. `lib/` never does.
const command_line_code = [_][]const u8{"src"};

const Span = struct {
    doc: []const u8,
    line: usize,
    text: []const u8,
    fenced: bool,
};

/// A fenced block gives one span per line.
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

/// Checks both the bare option and the `=value` spelling.
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
        // A fenced path is the reader's own example, not ours.
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

    // Low enough to survive an edit, high enough to catch a broken scanner.
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
        // A message Chock writes is not a command line.
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
    // Only the words before a session identifier, hash, or path are compared.
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

/// Every ```` ```zon ```` block of one page, with the line its fence opened on.
fn zonBlocksIn(arena: std.mem.Allocator, doc: Doc) ![]const Span {
    var out: std.ArrayList(Span) = .empty;
    var lines = std.mem.splitScalar(u8, doc.text, '\n');
    var number: usize = 0;
    var body: std.ArrayList(u8) = .empty;
    var opened: usize = 0;
    var inside = false;
    while (lines.next()) |line| {
        number += 1;
        if (std.mem.startsWith(u8, line, "```")) {
            if (inside) {
                try out.append(arena, .{
                    .doc = doc.path,
                    .line = opened,
                    .text = try body.toOwnedSlice(arena),
                    .fenced = true,
                });
                inside = false;
                continue;
            }
            if (!std.mem.eql(u8, std.mem.trim(u8, line, "`\r\n "), "zon")) continue;
            inside = true;
            opened = number;
            continue;
        }
        if (!inside) continue;
        try body.appendSlice(arena, line);
        try body.append(arena, '\n');
    }
    return out.items;
}

test "the microVM page counts the roots a guest is granted and the offers it takes" {
    // Both numbers bound how much of the host a compromised VMM can name.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var wrong: std.ArrayList(u8) = .empty;
    try checkCount(
        arena,
        docs,
        "docs/security/microvm.md",
        "roots",
        chock_main.daemon.max_granted_roots,
        &wrong,
    );
    try checkCount(
        arena,
        docs,
        "docs/security/microvm.md",
        "offers",
        chock_sandbox.vm_shares.max_offers,
        &wrong,
    );

    try testing.expectEqualStrings("", wrong.items);
}

test "the guest size table is the size the code chooses for that machine" {
    // Every row here is recomputed from the code, not read from the table.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);
    const page = try docText(docs, "docs/security/microvm.md");

    var wrong: std.ArrayList(u8) = .empty;
    var rows: usize = 0;

    var lines = std.mem.splitScalar(u8, page, '\n');
    var number: usize = 0;
    while (lines.next()) |line| {
        number += 1;
        if (!std.mem.startsWith(u8, line, "| ")) continue;

        var cells = std.mem.splitScalar(u8, line, '|');
        _ = cells.next();
        const machine_cell = std.mem.trim(u8, cells.next() orelse continue, " ");
        const processor_cell = std.mem.trim(u8, cells.next() orelse continue, " ");
        const memory_cell = std.mem.trim(u8, cells.next() orelse continue, " ");

        const machine = machineIn(machine_cell) orelse continue;
        const said_processors = std.fmt.parseInt(u32, processor_cell, 10) catch continue;
        const said_memory_mb = megabytesIn(memory_cell) orelse continue;
        rows += 1;

        // Linux: a Mac's count is clamped by the interrupt controller instead.
        const processors = chock_policy.sandbox.processorsOn(machine, .linux);
        const memory_mb = chock_policy.sandbox.memoryOn(machine, .linux);
        if (said_processors != processors or said_memory_mb != memory_mb) {
            try wrong.print(arena, "docs/security/microvm.md:{d}: says {d} and {d}MB, " ++
                "and the code answers {d} and {d}MB\n", .{
                number,
                said_processors,
                said_memory_mb,
                processors,
                memory_mb,
            });
        }
    }

    // A table nobody could read is not a table that agrees.
    if (rows != 5) {
        try wrong.print(arena, "docs/security/microvm.md: {d} machine rows were read, wanted 5\n", .{rows});
    }
    try testing.expectEqualStrings("", wrong.items);
}

/// `128 cores, 511GB`, or the row for a machine nothing could be read from.
fn machineIn(cell: []const u8) ?chock_policy.sandbox.Machine {
    if (std.mem.indexOf(u8, cell, "nothing could be read") != null) {
        return chock_policy.sandbox.Machine.unknown;
    }
    const comma = std.mem.indexOfScalar(u8, cell, ',') orelse return null;
    const cores_word = std.mem.trim(u8, cell[0..comma], " ");
    const cores_end = std.mem.indexOfScalar(u8, cores_word, ' ') orelse return null;
    const cores = std.fmt.parseInt(usize, cores_word[0..cores_end], 10) catch return null;
    const total_mb = megabytesIn(std.mem.trim(u8, cell[comma + 1 ..], " ")) orelse return null;
    return .{ .total_mb = total_mb, .cores = cores };
}

/// `12GB` or `512MB`, in megabytes.
fn megabytesIn(cell: []const u8) ?u64 {
    if (std.mem.endsWith(u8, cell, "GB")) {
        const value = std.fmt.parseInt(u64, cell[0 .. cell.len - 2], 10) catch return null;
        return value * 1024;
    }
    if (std.mem.endsWith(u8, cell, "MB")) {
        return std.fmt.parseInt(u64, cell[0 .. cell.len - 2], 10) catch null;
    }
    return null;
}

test "every sandbox block the documentation shows is read the way the page says" {
    // Each block is parsed and checked against the driver name it spells.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var wrong: std.ArrayList(u8) = .empty;
    var seen: usize = 0;

    for (docs) |doc| {
        for (try zonBlocksIn(arena, doc)) |block| {
            if (std.mem.indexOf(u8, block.text, ".driver") == null) continue;
            // `.drivers` is the org bundle's own list and a different reader.
            if (std.mem.indexOf(u8, block.text, ".drivers") != null) continue;
            seen += 1;

            const source = try arena.dupeZ(u8, block.text);
            var read = chock_policy.sandbox.parse(gpa, source, null) catch |err| {
                try wrong.print(arena, "{s}:{d}: {t}\n", .{ doc.path, block.line, err });
                continue;
            };
            defer read.deinit(gpa);

            const named = for (std.enums.values(chock_policy.sandbox.Driver)) |one| {
                const quoted = try std.fmt.allocPrint(arena, "\"{s}\"", .{one.wireName()});
                if (std.mem.indexOf(u8, block.text, quoted) != null) break one;
            } else {
                try wrong.print(arena, "{s}:{d}: names no driver this build has\n", .{ doc.path, block.line });
                continue;
            };
            if (read.chosen() != named) {
                try wrong.print(arena, "{s}:{d}: spells {s} and is read as {s}\n", .{
                    doc.path,
                    block.line,
                    named.wireName(),
                    read.chosen().wireName(),
                });
            }
        }
    }

    // A page whose blocks stopped being found would pass this test silently.
    if (seen == 0) try wrong.appendSlice(arena, "no sandbox block was found at all\n");
    try testing.expectEqualStrings("", wrong.items);
}

test "the microVM page's memory encryption claims are the ones the code makes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const page = try docText(docs, "docs/security/microvm.md");
    const code = try loadSources(arena, testing.io, &all_code);

    var wrong: std.ArrayList(u8) = .empty;

    // The page claim and the code setting must change together.
    const says_zero = std.mem.indexOf(u8, page, "The launch policy is zero") != null;
    const is_zero = std.mem.indexOf(u8, code, "const sev_policy: u32 = 0;") != null;
    if (says_zero != is_zero) {
        try wrong.print(arena, "the page says the policy is zero: {}, the code sets zero: {}\n", .{ says_zero, is_zero });
    }

    // The claim holds exactly while nothing names Mirage's `createSevEs`.
    const says_no_es = std.mem.indexOf(u8, page, "SEV-ES is not selected") != null;
    const names_es = std.mem.indexOf(u8, code, "createSevEs") != null;
    if (says_no_es and names_es) {
        try wrong.appendSlice(arena, "the page says SEV-ES is not selected and the code names createSevEs\n");
    }

    try testing.expectEqualStrings("", wrong.items);
}
