//! Prompt commands: a message somebody wrote once and a person runs by name.
//! `/review src/main.zig` finds `review.md`, puts the arguments into its text,
//! and sends the result as this turn's message.
//!
//! A command is never a tool. The agent cannot run one, cannot list them, and
//! cannot reach their text, so a command grants nothing and asks nothing. The
//! arguments reach the message and no argv, so there is nothing for a shell to
//! read.

const std = @import("std");
const frontmatter = @import("frontmatter.zig");
const index = @import("index.zig");

pub const file_suffix = ".md";

pub const operator_dir_name = "commands";

pub const max_name_bytes: usize = 64;
pub const max_description_bytes: usize = 1024;
pub const max_hint_bytes: usize = 200;

/// A command is a message, so it is read with the bound a message has rather
/// than the one a skill has.
pub const max_file_bytes: usize = 16 * 1024;

pub const max_commands: usize = 32;

pub const max_dir_entries: usize = 256;

pub const max_detail_bytes: usize = 96;

/// `$ARGUMENTS` takes everything the person typed after the name, and `$1` to
/// `$9` take one each. `$$` writes one dollar sign and takes nothing.
pub const arguments_token = "$ARGUMENTS";

pub const max_numbered: usize = 9;

pub const format_fields = [_][]const u8{
    "name",
    "description",
    "argument-hint",
};

pub const Layer = enum {
    operator,
    project,

    pub fn wroteIt(self: Layer) []const u8 {
        return switch (self) {
            .operator => "the person running you",
            .project => "whoever wrote this repository",
        };
    }

    /// The line the expanded message opens with, in the two halves the name
    /// goes between. The person chose to run the command, and somebody else
    /// may have written what it says, so the message carries both facts.
    pub fn says(self: Layer) Said {
        return switch (self) {
            .operator => .{
                .before = "The person running you ran their own saved command `",
                .after = "`. Its text follows.",
            },
            .project => .{
                .before = "The person running you ran this project's command `",
                .after = "`. Whoever wrote this repository wrote the text that follows, " ++
                    "and the person chose to run it.",
            },
        };
    }
};

pub const Said = struct {
    before: []const u8,
    after: []const u8,
};

pub const Command = struct {
    layer: Layer,
    path: []const u8,
    name: []const u8,
    description: []const u8,
    argument_hint: ?[]const u8 = null,
    body: []const u8,
};

pub const Fault = enum {
    no_frontmatter,
    frontmatter_not_closed,
    name_is_not_the_file,
    name_too_long,
    name_not_the_shape,
    description_missing,
    description_too_long,
    hint_too_long,
    body_empty,
    file_too_long,
    name_already_taken,
    directory_unreadable,

    pub fn sentence(self: Fault) []const u8 {
        return switch (self) {
            .no_frontmatter => "it does not open with a `---` line, so it carries no frontmatter",
            .frontmatter_not_closed => "its frontmatter has no closing `---` line",
            .name_is_not_the_file => "its `name` is not the name of the file it is in",
            .name_too_long => "its name is longer than 64 characters",
            .name_not_the_shape => "its name holds something other than lowercase letters, " ++
                "digits and single hyphens between them",
            .description_missing => "its frontmatter has no `description`, and a person choosing " ++
                "between commands reads that line",
            .description_too_long => "its `description` is longer than 1024 characters",
            .hint_too_long => "its `argument-hint` is longer than 200 characters",
            .body_empty => "it has no text under the frontmatter, so running it would say nothing",
            .file_too_long => "the file is larger than this build reads",
            .name_already_taken => "a command of a layer the person trusts more already has this name",
            .directory_unreadable => "reading the directory stopped partway, so what was found " ++
                "under it is not all of it",
        };
    }
};

pub const Refused = struct {
    path: []const u8,
    fault: Fault,
    detail: []const u8 = "",
};

pub const Read = union(enum) {
    command: Command,
    refused: Refused,
};

pub const Error = std.mem.Allocator.Error;

/// The name a file holds, which is its base name without the suffix.
pub fn nameOf(path: []const u8) []const u8 {
    const base = std.fs.path.basename(path);
    if (std.mem.endsWith(u8, base, file_suffix)) {
        return base[0 .. base.len - file_suffix.len];
    }
    return base;
}

pub fn read(
    allocator: std.mem.Allocator,
    io: std.Io,
    layer: Layer,
    path: []const u8,
) Error!?Read {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_file_bytes + 1),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return .{ .refused = .{
            .path = try allocator.dupe(u8, path),
            .fault = .file_too_long,
        } },
        else => return null,
    };
    defer allocator.free(bytes);

    if (bytes.len > max_file_bytes) return .{ .refused = .{
        .path = try allocator.dupe(u8, path),
        .fault = .file_too_long,
    } };

    return try parse(allocator, layer, path, bytes);
}

pub fn parse(
    allocator: std.mem.Allocator,
    layer: Layer,
    path: []const u8,
    bytes: []const u8,
) Error!Read {
    const owned_path = try allocator.dupe(u8, path);
    const name = nameOf(path);

    if (name.len > max_name_bytes) return .{ .refused = .{
        .path = owned_path,
        .fault = .name_too_long,
        .detail = try cut(allocator, name),
    } };
    if (!frontmatter.isTheShape(name)) return .{ .refused = .{
        .path = owned_path,
        .fault = .name_not_the_shape,
        .detail = try cut(allocator, name),
    } };

    const split = frontmatter.split(bytes) orelse return .{ .refused = .{
        .path = owned_path,
        .fault = if (frontmatter.opens(bytes)) .frontmatter_not_closed else .no_frontmatter,
    } };

    var fields = Fields{};
    var items = frontmatter.walk(bytes, split.frontmatter, "");
    while (items.next()) |item| {
        const pair = item.pair orelse continue;
        fields.put(pair.key, pair.value);
    }

    // The file name is the name, so frontmatter that disagrees is a mistake
    // worth reporting rather than a second place to look.
    if (fields.name) |written| {
        if (!std.mem.eql(u8, written, name)) return .{ .refused = .{
            .path = owned_path,
            .fault = .name_is_not_the_file,
            .detail = try cut(allocator, written),
        } };
    }

    const description = fields.description orelse return .{ .refused = .{
        .path = owned_path,
        .fault = .description_missing,
    } };
    if (description.len == 0) return .{ .refused = .{
        .path = owned_path,
        .fault = .description_missing,
    } };
    if (description.len > max_description_bytes) return .{ .refused = .{
        .path = owned_path,
        .fault = .description_too_long,
        .detail = try cut(allocator, description),
    } };

    if (fields.argument_hint) |hint| {
        if (hint.len > max_hint_bytes) return .{ .refused = .{
            .path = owned_path,
            .fault = .hint_too_long,
            .detail = try cut(allocator, hint),
        } };
    }

    const body = std.mem.trim(u8, split.body, " \t\r\n");
    if (body.len == 0) return .{ .refused = .{
        .path = owned_path,
        .fault = .body_empty,
    } };

    return .{ .command = .{
        .layer = layer,
        .path = owned_path,
        .name = try allocator.dupe(u8, name),
        .description = try allocator.dupe(u8, description),
        .argument_hint = if (fields.argument_hint) |hint|
            try allocator.dupe(u8, hint)
        else
            null,
        .body = try allocator.dupe(u8, body),
    } };
}

pub const Root = struct {
    layer: Layer,
    path: []const u8,
};

pub const Found = struct {
    commands: []Command = &.{},
    refused: []Refused = &.{},
    left_out: usize = 0,
};

/// Reads every `<name>.md` under each root, in the order the roots are given.
/// The first layer to hold a name keeps it.
pub fn discover(
    allocator: std.mem.Allocator,
    io: std.Io,
    roots: []const Root,
) Error!Found {
    var commands: std.ArrayList(Command) = .empty;
    errdefer commands.deinit(allocator);
    var refused: std.ArrayList(Refused) = .empty;
    errdefer refused.deinit(allocator);
    var left_out: usize = 0;

    for (roots) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root.path, .{ .iterate = true }) catch continue;
        defer dir.close(io);

        var walker = dir.iterate();
        var seen: usize = 0;
        while (true) {
            const next = walker.next(io) catch {
                try refused.append(allocator, .{
                    .path = try allocator.dupe(u8, root.path),
                    .fault = .directory_unreadable,
                });
                break;
            };
            const entry = next orelse break;
            if (seen >= max_dir_entries) break;
            seen += 1;
            if (entry.kind == .directory) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            if (!std.mem.endsWith(u8, entry.name, file_suffix)) continue;

            const path = try std.fs.path.join(allocator, &.{ root.path, entry.name });
            defer allocator.free(path);

            const read_it = try read(allocator, io, root.layer, path) orelse continue;
            switch (read_it) {
                .refused => |one| try refused.append(allocator, one),
                .command => |one| {
                    if (findIn(commands.items, one.name) != null) {
                        try refused.append(allocator, .{
                            .path = one.path,
                            .fault = .name_already_taken,
                            .detail = one.name,
                        });
                        continue;
                    }
                    if (commands.items.len >= max_commands) {
                        left_out += 1;
                        continue;
                    }
                    try commands.append(allocator, one);
                },
            }
        }
    }

    return .{
        .commands = try commands.toOwnedSlice(allocator),
        .refused = try refused.toOwnedSlice(allocator),
        .left_out = left_out,
    };
}

pub fn findIn(commands: []const Command, name: []const u8) ?Command {
    for (commands) |one| {
        if (std.mem.eql(u8, one.name, name)) return one;
    }
    return null;
}

/// One line for each command, for a person reading `chock commands`.
pub fn indexEntriesFor(
    allocator: std.mem.Allocator,
    commands: []const Command,
    layer: Layer,
) Error![]index.Entry {
    var out: std.ArrayList(index.Entry) = .empty;
    errdefer out.deinit(allocator);

    for (commands) |one| {
        if (one.layer != layer) continue;
        try out.append(allocator, .{
            .name = one.name,
            .description = try index.oneLine(allocator, one.description),
        });
    }
    return out.toOwnedSlice(allocator);
}

pub const Invocation = struct {
    name: []const u8,
    /// Everything after the name, with the space between them gone.
    rest: []const u8,
};

/// A message that names a command: a slash, a name, then the end of the text
/// or a space. A path such as `/home/ross/chock` is not one, because its first
/// word holds characters a name cannot.
pub fn invocationIn(text: []const u8) ?Invocation {
    const trimmed = std.mem.trimStart(u8, text, " \t\r\n");
    if (trimmed.len < 2 or trimmed[0] != '/') return null;

    const after = trimmed[1..];
    const end = std.mem.indexOfAny(u8, after, " \t\r\n") orelse after.len;
    const name = after[0..end];
    if (name.len > max_name_bytes) return null;
    if (!frontmatter.isTheShape(name)) return null;

    return .{
        .name = name,
        .rest = std.mem.trim(u8, after[end..], " \t\r\n"),
    };
}

/// The words after the name, split on whitespace, for `$1` to `$9`.
pub fn argumentsIn(
    allocator: std.mem.Allocator,
    rest: []const u8,
) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);

    var words = std.mem.tokenizeAny(u8, rest, " \t\r\n");
    while (words.next()) |word| try out.append(allocator, word);
    return out.toOwnedSlice(allocator);
}

/// The message a command becomes: the line that says who wrote it, then the
/// text with the arguments in it.
pub fn expand(
    allocator: std.mem.Allocator,
    command: Command,
    rest: []const u8,
) Error![]u8 {
    const arguments = try argumentsIn(allocator, rest);
    defer allocator.free(arguments);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    const said = command.layer.says();
    try out.appendSlice(allocator, said.before);
    try out.appendSlice(allocator, command.name);
    try out.appendSlice(allocator, said.after);
    try out.appendSlice(allocator, "\n\n");

    const took = try substituteInto(allocator, &out, command.body, rest, arguments);

    // An argument the text has no place for is still something the person
    // typed, so it goes in rather than away.
    if (!took and rest.len != 0) {
        try out.appendSlice(allocator, "\n\n");
        try out.appendSlice(allocator, rest);
    }

    return out.toOwnedSlice(allocator);
}

/// Answers whether the text named any argument.
fn substituteInto(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    body: []const u8,
    rest: []const u8,
    arguments: []const []const u8,
) Error!bool {
    var took = false;
    var at: usize = 0;
    while (at < body.len) {
        const dollar = std.mem.indexOfScalarPos(u8, body, at, '$') orelse break;
        try out.appendSlice(allocator, body[at..dollar]);
        at = dollar;

        if (std.mem.startsWith(u8, body[at..], arguments_token)) {
            try out.appendSlice(allocator, rest);
            at += arguments_token.len;
            took = true;
            continue;
        }
        if (at + 1 < body.len and body[at + 1] == '$') {
            try out.append(allocator, '$');
            at += 2;
            continue;
        }
        if (at + 1 < body.len and body[at + 1] >= '1' and body[at + 1] <= '9') {
            const which = body[at + 1] - '1';
            if (which < arguments.len) try out.appendSlice(allocator, arguments[which]);
            at += 2;
            took = true;
            continue;
        }

        try out.append(allocator, '$');
        at += 1;
    }
    try out.appendSlice(allocator, body[at..]);
    return took;
}

const Fields = struct {
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    argument_hint: ?[]const u8 = null,

    fn put(self: *Fields, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "name")) {
            self.name = value;
        } else if (std.mem.eql(u8, key, "description")) {
            self.description = value;
        } else if (std.mem.eql(u8, key, "argument-hint")) {
            self.argument_hint = value;
        }
    }
};

fn cut(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    return frontmatter.cut(allocator, value, max_detail_bytes);
}

/// What the reader above went past, so a check can report it the way
/// `chock skills validate` reports a skill's.
pub const Note = enum {
    line_not_read,
    value_is_a_block_marker,
    field_not_in_the_format,

    pub fn sentence(self: Note) []const u8 {
        return switch (self) {
            .line_not_read => "a frontmatter line is not a `key: value` pair, and nothing was read from it",
            .value_is_a_block_marker => "a field holds a YAML block marker, and the marker became the value",
            .field_not_in_the_format => "a field is not one the format names, and nothing was read from it",
        };
    }
};

pub const Noted = struct {
    note: Note,
    line: usize,
    detail: []const u8 = "",
};

/// Every frontmatter line `parse` passed over. It walks with the same reader,
/// so a report and a session agree.
pub fn notesIn(allocator: std.mem.Allocator, bytes: []const u8) Error![]const Noted {
    var out: std.ArrayList(Noted) = .empty;
    errdefer out.deinit(allocator);

    const split = frontmatter.split(bytes) orelse return out.toOwnedSlice(allocator);

    var items = frontmatter.walk(bytes, split.frontmatter, "");
    while (items.next()) |item| {
        const named = item.pair orelse {
            try out.append(allocator, .{
                .note = .line_not_read,
                .line = item.line,
                .detail = try cut(allocator, item.text),
            });
            continue;
        };
        if (!namedByTheFormat(named.key)) {
            try out.append(allocator, .{
                .note = .field_not_in_the_format,
                .line = item.line,
                .detail = try cut(allocator, named.key),
            });
            continue;
        }
        if (frontmatter.isBlockMarker(named.value)) try out.append(allocator, .{
            .note = .value_is_a_block_marker,
            .line = item.line,
            .detail = try cut(allocator, named.key),
        });
    }

    return out.toOwnedSlice(allocator);
}

fn namedByTheFormat(key: []const u8) bool {
    for (format_fields) |one| {
        if (std.mem.eql(u8, key, one)) return true;
    }
    return false;
}

const testing = std.testing;

const minimal =
    \\---
    \\description: Review the diff this branch holds.
    \\---
    \\Read the whole diff before you say anything about any part of it.
    \\
;

test "a file with a description and text under it is a command named by its file" {
    const gpa = testing.allocator;

    const got = try parse(gpa, .project, ".chock/commands/review.md", minimal);
    const one = got.command;
    defer {
        gpa.free(one.path);
        gpa.free(one.name);
        gpa.free(one.description);
        gpa.free(one.body);
    }

    try testing.expectEqualStrings("review", one.name);
    try testing.expectEqualStrings("Review the diff this branch holds.", one.description);
    try testing.expectEqualStrings(
        "Read the whole diff before you say anything about any part of it.",
        one.body,
    );
    try testing.expectEqual(Layer.project, one.layer);
    try testing.expect(one.argument_hint == null);
}

test "the frontmatter name has to be the file name, and a disagreement is refused" {
    const gpa = testing.allocator;

    const agrees = try parse(gpa, .operator, "commands/review.md",
        \\---
        \\name: review
        \\description: Review it.
        \\argument-hint: <path>
        \\---
        \\Do the review of $1.
        \\
    );
    const one = agrees.command;
    defer {
        gpa.free(one.path);
        gpa.free(one.name);
        gpa.free(one.description);
        gpa.free(one.body);
        gpa.free(one.argument_hint.?);
    }
    try testing.expectEqualStrings("<path>", one.argument_hint.?);

    const disagrees = try parse(gpa, .operator, "commands/review.md",
        \\---
        \\name: something-else
        \\description: Review it.
        \\---
        \\Do the review.
        \\
    );
    defer {
        gpa.free(disagrees.refused.path);
        gpa.free(disagrees.refused.detail);
    }
    try testing.expectEqual(Fault.name_is_not_the_file, disagrees.refused.fault);
    try testing.expectEqualStrings("something-else", disagrees.refused.detail);
}

test "a command with no description, no text, or a name of the wrong shape is refused" {
    const gpa = testing.allocator;

    const no_description = try parse(gpa, .project, "commands/review.md",
        \\---
        \\argument-hint: <path>
        \\---
        \\Do it.
        \\
    );
    gpa.free(no_description.refused.path);
    try testing.expectEqual(Fault.description_missing, no_description.refused.fault);

    const no_body = try parse(gpa, .project, "commands/review.md",
        \\---
        \\description: Review it.
        \\---
        \\
        \\
    );
    gpa.free(no_body.refused.path);
    try testing.expectEqual(Fault.body_empty, no_body.refused.fault);

    const shouting = try parse(gpa, .project, "commands/Review.md", minimal);
    gpa.free(shouting.refused.path);
    gpa.free(shouting.refused.detail);
    try testing.expectEqual(Fault.name_not_the_shape, shouting.refused.fault);

    const bare = try parse(gpa, .project, "commands/review.md",
        \\Review the diff.
        \\
    );
    gpa.free(bare.refused.path);
    try testing.expectEqual(Fault.no_frontmatter, bare.refused.fault);

    const unclosed = try parse(gpa, .project, "commands/review.md",
        \\---
        \\description: Review it.
        \\
    );
    gpa.free(unclosed.refused.path);
    try testing.expectEqual(Fault.frontmatter_not_closed, unclosed.refused.fault);
}

test "a message names a command, and a path that starts with a slash does not" {
    const named = invocationIn("/review src/main.zig and say why") orelse
        return error.TestExpectedInvocation;
    try testing.expectEqualStrings("review", named.name);
    try testing.expectEqualStrings("src/main.zig and say why", named.rest);

    const alone = invocationIn("/review") orelse return error.TestExpectedInvocation;
    try testing.expectEqualStrings("review", alone.name);
    try testing.expectEqualStrings("", alone.rest);

    try testing.expect(invocationIn("/home/ross/chock is broken") == null);
    try testing.expect(invocationIn("fix /review please") == null);
    try testing.expect(invocationIn("/") == null);
    try testing.expect(invocationIn("/Review") == null);
    try testing.expect(invocationIn("") == null);
}

test "the arguments reach the text where it names them, and the layer is said first" {
    const gpa = testing.allocator;

    const one = Command{
        .layer = .project,
        .path = "commands/review.md",
        .name = "review",
        .description = "Review it.",
        .body = "Review $1 against $2, and say what $ARGUMENTS cost.",
    };

    const text = try expand(gpa, one, "src/main.zig the style guide");
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "this project's command `review`") != null);
    try testing.expect(std.mem.indexOf(u8, text, "Whoever wrote this repository wrote") != null);
    try testing.expect(std.mem.indexOf(
        u8,
        text,
        "Review src/main.zig against the, and say what src/main.zig the style guide cost.",
    ) != null);
}

test "an argument the text has no place for is added rather than dropped" {
    const gpa = testing.allocator;

    const one = Command{
        .layer = .operator,
        .path = "commands/tidy.md",
        .name = "tidy",
        .description = "Tidy it.",
        .body = "Tidy the project.",
    };

    const with = try expand(gpa, one, "lib/chock-core");
    defer gpa.free(with);
    try testing.expect(std.mem.endsWith(u8, with, "Tidy the project.\n\nlib/chock-core"));

    const without = try expand(gpa, one, "");
    defer gpa.free(without);
    try testing.expect(std.mem.endsWith(u8, without, "Tidy the project."));
}

test "a dollar sign the text wrote twice stays one, and a number with no argument says nothing" {
    const gpa = testing.allocator;

    const one = Command{
        .layer = .operator,
        .path = "commands/price.md",
        .name = "price",
        .description = "Price it.",
        .body = "It costs $$5 and $1 and $ and $9.",
    };

    const text = try expand(gpa, one, "nothing");
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "It costs $5 and nothing and $ and .") != null);
}

test "two layers cannot share a name, and the first root keeps it" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "mine");
    try tmp.dir.createDirPath(io, "theirs");
    try writeCommand(io, tmp.dir, "mine/review.md", "Mine.");
    try writeCommand(io, tmp.dir, "theirs/review.md", "Theirs.");
    try writeCommand(io, tmp.dir, "theirs/other.md", "Other.");

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const mine = try std.fs.path.join(gpa, &.{ root, "mine" });
    defer gpa.free(mine);
    const theirs = try std.fs.path.join(gpa, &.{ root, "theirs" });
    defer gpa.free(theirs);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const found = try discover(arena_state.allocator(), io, &.{
        .{ .layer = .operator, .path = mine },
        .{ .layer = .project, .path = theirs },
    });

    try testing.expectEqual(@as(usize, 2), found.commands.len);
    const kept = findIn(found.commands, "review") orelse return error.TestExpectedCommand;
    try testing.expectEqual(Layer.operator, kept.layer);
    try testing.expectEqualStrings("Mine.", kept.body);

    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expectEqual(Fault.name_already_taken, found.refused[0].fault);
}

fn writeCommand(io: std.Io, dir: std.Io.Dir, path: []const u8, body: []const u8) !void {
    var buffer: [256]u8 = undefined;
    const text = try std.fmt.bufPrint(
        &buffer,
        "---\ndescription: What it does.\n---\n{s}\n",
        .{body},
    );
    try dir.writeFile(io, .{ .sub_path = path, .data = text });
}

test "a note names a frontmatter line the reader took nothing from" {
    const gpa = testing.allocator;

    const notes = try notesIn(gpa,
        \\---
        \\description: Review it.
        \\version: 2
        \\not a pair
        \\---
        \\Do it.
        \\
    );
    defer {
        for (notes) |one| gpa.free(one.detail);
        gpa.free(notes);
    }

    try testing.expectEqual(@as(usize, 2), notes.len);
    try testing.expectEqual(Note.field_not_in_the_format, notes[0].note);
    try testing.expectEqualStrings("version", notes[0].detail);
    try testing.expectEqual(@as(usize, 3), notes[0].line);
    try testing.expectEqual(Note.line_not_read, notes[1].note);
    try testing.expectEqual(@as(usize, 4), notes[1].line);
}
