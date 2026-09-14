//! **The documentation must describe the software that is here.**
//!
//! Every test below reads a claim out of a file a person reads, and compares
//! it with the code. A claim that no longer agrees with the code fails the
//! build.
//!
//! ## Why this file exists
//!
//! `CONTRIBUTING.md` names "prose that expired" as a fault nothing catches: a
//! sentence that was true when it was written and is false now. The
//! documentation is the part of Chock that a reader cannot compile. So the
//! mechanical half of it is compiled here.
//!
//! ## The truth comes from the code, never from a second list
//!
//! No test below holds a copy of what Chock can do. The command names come
//! from `main.commands`, the exit codes from `main.Exit`, the tool names from
//! `tools.Tool`, the policy words from `table.Decision` and `table.Rule`, the
//! counted sandbox lists from the arrays themselves, and every path from the
//! repository on disk. A test that held its own list would be a third place
//! for the same judgement to drift, which is the fault this file is written
//! against.
//!
//! ## The two exception lists, and why they clean themselves
//!
//! `refused_examples` and `foreign_options` are the only hand written words
//! here, and neither one says what Chock can do. Each says the opposite: a
//! word the documentation shows on purpose that Chock answers to. Both lists
//! are checked from both ends. An entry that stops being an example, and an
//! entry that becomes real, each fail a test of their own. So a dead entry
//! cannot sit here and hide a real fault.
//!
//! ## A failure names every offender at once
//!
//! Each test collects what it found into one string and compares it against
//! the empty string. So one run reports every wrong sentence, and a person
//! reads the whole list rather than fixing one and running again. Nothing is
//! written to standard error, which `zig build test` refuses.

const std = @import("std");
const chock_main = @import("chock_main");
const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

/// Where this repository is, from `build.zig`, which is the one thing that
/// knows. Not the working directory: a test binary cannot say what directory
/// `zig build` was started from.
const repo_root = @import("repo_root").repo_root;

const testing = std.testing;

/// The longest documentation file this test reads. The longest today is about
/// 15 kB.
const max_doc_bytes = 512 * 1024;

/// The longest source file this test reads. The longest today is `src/run.zig`
/// at about 830 kB.
const max_source_bytes = 4 * 1024 * 1024;

/// Words the documentation shows after `chock` that name no command, on
/// purpose.
///
/// **This is not a list of what Chock can do.** `README.md` and
/// `docs/running.md` both teach that a first word is read as a command name,
/// and they teach it with a line that is refused. A test that did not know
/// that would report the lesson as a fault.
///
/// Both ends are checked, so an entry cannot rot. See the test named for
/// these words.
const refused_examples = [_][]const u8{ "fix", "rnu" };

/// Options the documentation names that belong to another program.
///
/// `docs/sandbox.md` says that Node is started with `--jitless`, which is
/// Node's option and not Chock's. Both ends are checked here too: an entry
/// that Chock starts to accept fails its test, and so does one that no
/// documentation names any more.
const foreign_options = [_][]const u8{"--jitless"};

/// One documentation file, with its path relative to the root of the
/// repository.
const Doc = struct {
    path: []const u8,
    text: []const u8,
};

/// Every `*.md` file a reader of this project reads: the ones in the root, and
/// the ones under `docs/`.
///
/// Read off the disk and never listed here, so a page added tomorrow is
/// checked tomorrow. The fetched packages under `zig-pkg/` carry markdown of
/// their own and are not ours, so the walk does not recurse.
///
/// Sorted by path, so a failure reads the same way twice.
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

    var page_entries = pages.iterate();
    while (try page_entries.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".md")) continue;
        try docs.append(arena, .{
            .path = try std.fmt.allocPrint(arena, "docs/{s}", .{entry.name}),
            .text = try pages.readFileAlloc(io, entry.name, arena, .limited(max_doc_bytes)),
        });
    }

    std.mem.sort(Doc, docs.items, {}, lessByPath);
    return docs.items;
}

fn lessByPath(_: void, a: Doc, b: Doc) bool {
    return std.mem.order(u8, a.path, b.path) == .lt;
}

/// The text of one documentation file.
fn docText(docs: []const Doc, path: []const u8) ![]const u8 {
    for (docs) |doc| {
        if (std.mem.eql(u8, doc.path, path)) return doc.text;
    }
    return error.NoSuchDoc;
}

/// Every Zig file under the named top level directories, joined into one
/// buffer.
///
/// **What a name, an action and a message are checked against.** The code is
/// the only record of which of those Chock really has, and a search of the
/// source is a search that nobody can forget to update when a file is added.
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

/// Everything a reader of the documentation can name.
const all_code = [_][]const u8{ "src", "lib" };

/// The command line, and nothing below it.
///
/// **An option is read in `src/` alone.** `CONTRIBUTING.md` states the rule
/// that makes this exact: `lib/` never prints and never parses a command line,
/// so every option Chock takes is a literal in a file under `src/`. Searching
/// the libraries as well would accept `--quiet`, which is an argument
/// `chock-broker` gives to git and not an option of ours.
const command_line_code = [_][]const u8{"src"};

/// One piece of a documentation file that holds code: the text between two
/// backticks on one line, or one line inside a fenced block.
const Span = struct {
    doc: []const u8,
    line: usize,
    text: []const u8,
    fenced: bool,
};

/// Every code span in one file, in the order a reader meets them.
///
/// A fenced block gives one span per line, because a command line is a line.
/// Outside a fence, each pair of backticks on one line gives one span. A
/// backtick that opens nothing is not a span and is skipped.
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

/// Every code span in every file.
fn allSpans(arena: std.mem.Allocator, docs: []const Doc) ![]const Span {
    var spans: std.ArrayList(Span) = .empty;
    for (docs) |doc| try collectSpans(arena, doc, &spans);
    return spans.items;
}

/// Whether this span is a `chock` command line rather than prose.
fn isChockLine(span: Span) bool {
    var words = std.mem.tokenizeAny(u8, span.text, " \t");
    const first = words.next() orelse return false;
    return std.mem.eql(u8, first, "chock");
}

/// The word an option token names, with any `=value` and any punctuation
/// removed. Null when the token is not an option.
///
/// `--` alone is the end of the options and never one of them: it is how a
/// task reaches bare `chock`.
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

/// Whether the source declares this option.
///
/// Both spellings, because `src/tty.zig` reads `--color=<when>` with one
/// literal that carries the `=`, and a parser that took a separate value would
/// hold the plain word.
fn sourceHasOption(source: []const u8, option: []const u8, arena: std.mem.Allocator) !bool {
    const plain = try std.fmt.allocPrint(arena, "\"{s}\"", .{option});
    if (std.mem.indexOf(u8, source, plain) != null) return true;
    const valued = try std.fmt.allocPrint(arena, "\"{s}=", .{option});
    return std.mem.indexOf(u8, source, valued) != null;
}

/// Whether `commands` holds this name.
fn isCommand(name: []const u8) bool {
    for (chock_main.commands) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return true;
    }
    return false;
}

/// Whether every character is a lower case letter, a digit, or one of
/// `extra`.
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

/// The value a documented count carries, spelled as a word or as digits.
/// Null for a word that is neither.
///
/// **The words, and never the counts.** Every number this maps to is read
/// from the code at the place it is compared.
fn countWord(word: []const u8) ?usize {
    if (std.fmt.parseInt(usize, word, 10)) |digits| return digits else |_| {}
    return numberWord(word);
}

/// The value of an English number word. Null for a word that is not one.
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

/// Report every place a documentation file claims `<number word> <noun>` and
/// the number is not `truth`.
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

/// Whether the text names this word between backticks.
fn namesInTicks(text: []const u8, word: []const u8, arena: std.mem.Allocator) !bool {
    const ticked = try std.fmt.allocPrint(arena, "`{s}`", .{word});
    return std.mem.indexOf(u8, text, ticked) != null;
}

/// Whether a path is in the repository. A directory answers yes.
fn repoHas(io: std.Io, arena: std.mem.Allocator, path: []const u8) !bool {
    const full = try std.fs.path.join(arena, &.{ repo_root, path });
    _ = std.Io.Dir.cwd().statFile(io, full, .{}) catch return false;
    return true;
}

test "the documentation index names every page under docs/" {
    // The index is the first thing a reader opens, so a page it does not name
    // is a page nobody finds. Mutation check: add a page under `docs/` and do
    // not name it in `docs/README.md`.
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
    // Two shapes: the target of a markdown link, and a path between backticks.
    // A link is read relative to the page it is on, the way a reader's own
    // browser reads it. Mutation check: name a file that does not exist.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    // The top level directories of this repository, read off the disk. A token
    // is a repository path when it starts with one of these, so nothing here
    // is a list a person maintains.
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
        // **Prose only, and never a fenced block.** A fence holds an example
        // of what a reader writes in their own project: `docs/plugins.md`
        // names `plugins/chock-plugin-hello.wasm` in a sample `chock.zon`,
        // and that path is theirs and not ours. A path in a sentence is a
        // reference to this repository.
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

    // A scan that found nothing proves nothing: see the test for commands.
    try testing.expect(checked >= 40);
    try testing.expectEqualStrings("", missing.items);
}

test "every command the documentation shows is a command Chock answers to" {
    // The word after `chock` on a documented command line, and the word in the
    // prefix of a documented message. Truth is `main.commands` and nothing
    // else. Mutation check: write `chock rnu --verbose` into a page.
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
        // A comment, a quoted task, or a placeholder is not a command name.
        if (std.mem.startsWith(u8, second, "#")) continue;
        if (std.mem.startsWith(u8, second, "\"")) continue;
        if (std.mem.startsWith(u8, second, "<")) continue;
        if (std.mem.startsWith(u8, second, "[")) continue;
        // An option is checked by the test for options, and `--` is the end of
        // them, after which every word is the task.
        if (std.mem.startsWith(u8, second, "-")) continue;
        // `chock run: ...` is a message Chock writes, and the word in front of
        // the colon is still a command.
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

    // **A scan that found nothing proves nothing.** The floor is well under
    // what the pages hold today, so an ordinary edit never reaches it, and a
    // scanner that stopped working does.
    try testing.expect(checked >= 20);
    try testing.expectEqualStrings("", wrong.items);
}

test "the words the documentation shows as refused are still refused, and still shown" {
    // Both ends of `refused_examples`. An entry that becomes a real command,
    // and an entry no page shows any more, each fail here, so a dead entry
    // cannot sit in this file and hide a real fault.
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
    // `chock sessions verify` and the eleven like it. The command's own file
    // is what reads the word, so that file is where the word must be.
    // Mutation check: write `chock sessions confirm` into a page.
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
        // An option is not a subcommand word. `isMadeOf` lets a dash through,
        // because `older-than` and `require-card` hold one in the middle.
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

    // A scan that found nothing proves nothing: see the test for commands.
    try testing.expect(checked >= 10);
    try testing.expectEqualStrings("", wrong.items);
}

test "every option the documentation names is an option the code reads" {
    // An option on a documented command line, and an option a page names on
    // its own. Truth is the source of `src/`, which is where every command
    // line is read. Mutation check: write `chock run --quietly` into a page.
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
        // **A message Chock writes is not a command line.** `chock run: put it
        // back with `git reset --hard ...`` names git's option inside Chock's
        // own sentence, and that option is git's business. The test for a
        // message reads those lines.
        if (isChockLine(span)) {
            var head = std.mem.tokenizeAny(u8, span.text, " \t");
            _ = head.next();
            if (head.next()) |second| {
                if (std.mem.endsWith(u8, second, ":")) continue;
            }
        }
        while (words.next()) |word| {
            // Everything after a comment is prose, and everything after `--`
            // alone is the task.
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

    // A scan that found nothing proves nothing: see the test for commands.
    try testing.expect(checked >= 25);
    try testing.expectEqualStrings("", wrong.items);
}

test "the options the documentation credits to another program are still not ours" {
    // Both ends of `foreign_options`, for the reason the refused words have
    // both ends checked.
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
    // The other direction. A command that ships with no page is a command
    // nobody can find. Mutation check: add an entry to `main.commands`.
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
    // A script reads these, so a row that names the wrong number is worse than
    // no table. Truth is `main.Exit`. Mutation check: add a member to `Exit`,
    // or change a number in the table.
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
    // `docs/README.md` said "the seventeen tools" while the enum held
    // eighteen. Truth is `tools.Tool`. Mutation check: add a member to the
    // enum, or write a different number into a page.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const running = try docText(docs, "docs/running.md");
    const fields = @typeInfo(chock_core.tools.Tool).@"enum".fields;

    var wrong: std.ArrayList(u8) = .empty;
    inline for (fields) |field| {
        if (!try namesInTicks(running, field.name, arena)) {
            try wrong.print(arena, "docs/running.md names no tool `{s}`\n", .{field.name});
        }
    }
    try checkCount(arena, docs, null, "tools", fields.len, &wrong);

    try testing.expectEqualStrings("", wrong.items);
}

test "the policy page names every decision and every field of a rule, and counts them right" {
    // The vocabulary a person writes into their own `chock.zon`. A decision
    // the page does not name is a decision nobody uses, and one it names that
    // the code has not got is a file that will not load. Truth is
    // `table.Decision` and `table.Rule`. Mutation check: add a member to
    // either.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const policy = try docText(docs, "docs/policy.md");
    const decisions = @typeInfo(chock_policy.table.Decision).@"enum".fields;
    const rule_fields = @typeInfo(chock_policy.table.Rule).@"struct".fields;

    var wrong: std.ArrayList(u8) = .empty;
    inline for (decisions) |field| {
        if (!try namesInTicks(policy, field.name, arena)) {
            try wrong.print(arena, "docs/policy.md names no decision `{s}`\n", .{field.name});
        }
    }
    inline for (rule_fields) |field| {
        if (!try namesInTicks(policy, field.name, arena)) {
            try wrong.print(arena, "docs/policy.md names no rule field `{s}`\n", .{field.name});
        }
    }
    // Only this page, because `fields` and `decisions` are ordinary words and
    // another page may count something else with them.
    try checkCount(arena, docs, "docs/policy.md", "decisions", decisions.len, &wrong);
    try checkCount(arena, docs, "docs/policy.md", "fields", rule_fields.len, &wrong);

    try testing.expectEqualStrings("", wrong.items);
}

test "every name the documentation spells with an underscore is a name the code has" {
    // A tool, a policy key, a doctor row, a system call: every one of them is
    // written in the code, so a page that names one the code has not got is a
    // page that has expired. Mutation check: rename any of them in a page.
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

    // A scan that found nothing proves nothing: see the test for commands.
    try testing.expect(checked >= 50);
    try testing.expectEqualStrings("", wrong.items);
}

test "every action a table row names is an action the code has" {
    // The actions table of `docs/policy.md` is what a person copies into a
    // rule, and a rule that names an action the broker never asks about is a
    // rule that never fires. Mutation check: rename a row.
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

    // A scan that found nothing proves nothing: see the test for commands.
    try testing.expect(checked >= 8);
    try testing.expectEqualStrings("", wrong.items);
}

test "a message the documentation shows is a message the code writes" {
    // The sample output in a fenced block. Byte for byte is not possible: the
    // blocks carry a session identifier, a hash and a path from somebody
    // else's machine. So the words in front of the first of those are
    // compared, which is the part the code holds as a literal. Mutation
    // check: reword the front of one of those lines.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    const source = try loadSources(arena, testing.io, &all_code);
    const spans = try allSpans(arena, docs);

    // Enough to tell one message from another, and short enough to stop
    // before the first value a run fills in.
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
            // A path, a number and a quoted name are what the run fills in,
            // so the comparison stops in front of them.
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

    // The check is worth nothing if the pages stop holding sample output, so
    // say how many were read.
    try testing.expect(checked >= 4);
    try testing.expectEqualStrings("", wrong.items);
}

test "the repository layout names every library and every test area" {
    // `CONTRIBUTING.md` is where somebody new reads what is here. Truth is the
    // disk. Mutation check: add a directory under `test/`.
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
    // Two numbers a reader has no way to check, and both are an array in the
    // code. The page said 22 masked entries while the array held 20. Mutation
    // check: remove a member of either array.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const docs = try loadDocs(arena, testing.io);

    var wrong: std.ArrayList(u8) = .empty;
    try checkCount(
        arena,
        docs,
        "docs/sandbox.md",
        "entries",
        chock_sandbox.namespace.masked_proc_entries.len,
        &wrong,
    );
    try checkCount(
        arena,
        docs,
        "docs/sandbox.md",
        "calls",
        chock_sandbox.seccomp.blocked_calls.len,
        &wrong,
    );

    try testing.expectEqualStrings("", wrong.items);
}
