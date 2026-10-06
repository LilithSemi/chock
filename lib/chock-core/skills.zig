//! Agent Skills, read in: one SKILL.md directory, bounded, and marked
//! with the layer it came from.

const std = @import("std");
const index = @import("index.zig");

pub const file_name = "SKILL.md";

pub const operator_dir_name = "skills";

pub const inside_root = "/skills";

pub const optional_dirs = [_][]const u8{ "scripts", "references", "assets" };

pub const max_name_bytes: usize = 64;
pub const max_description_bytes: usize = 1024;
pub const max_compatibility_bytes: usize = 500;

pub const max_file_bytes: usize = 64 * 1024;

pub const max_metadata_entries: usize = 32;

pub const Layer = enum {
    operator,
    project,
    packaged,

    pub fn actionName(self: Layer) []const u8 {
        return switch (self) {
            .operator => "skill.read.operator",
            .project => "skill.read.project",
            .packaged => "skill.read.packaged",
        };
    }

    pub fn wroteIt(self: Layer) []const u8 {
        return switch (self) {
            .operator => "written by the person running you",
            .project => "written by whoever wrote this repository, not by your operator",
            .packaged => "written by a package author, not by your operator",
        };
    }

    pub fn heading(self: Layer) []const u8 {
        return switch (self) {
            .operator =>
            \\## Skills your operator installed
            \\## (written by the person running you. Call read_skill with one of these names for the whole of it.)
            ,
            .project =>
            \\## Skills this project ships
            \\## (written by whoever wrote this repository, not by your operator. Call read_skill with one of these names for the whole of it.)
            ,
            .packaged =>
            \\## Skills a package brought in
            \\## (written by a package author, not by your operator. Call read_skill with one of these names for the whole of it.)
            ,
        };
    }
};

pub const Pair = struct {
    key: []const u8,
    value: []const u8,
};

pub const Skill = struct {
    layer: Layer,
    dir: []const u8,
    inside: []const u8 = "",
    name: []const u8,
    description: []const u8,
    license: ?[]const u8 = null,
    compatibility: ?[]const u8 = null,
    metadata: []const Pair = &.{},
    allowed_tools: ?[]const u8 = null,
    body: []const u8,
    metadata_left_out: usize = 0,
};

pub const Fault = enum {
    no_frontmatter,
    frontmatter_not_closed,
    name_missing,
    name_too_long,
    name_not_the_shape,
    name_is_not_the_directory,
    description_missing,
    description_too_long,
    compatibility_too_long,
    file_too_long,
    name_already_taken,
    directory_unreadable,

    pub fn sentence(self: Fault) []const u8 {
        return switch (self) {
            .no_frontmatter => "it does not open with a `---` line, so it carries no frontmatter",
            .frontmatter_not_closed => "its frontmatter has no closing `---` line",
            .name_missing => "its frontmatter has no `name`",
            .name_too_long => "its `name` is longer than 64 characters",
            .name_not_the_shape => "its `name` holds something other than lowercase letters, " ++
                "digits and single hyphens between them",
            .name_is_not_the_directory => "its `name` is not the name of the directory it is in",
            .description_missing => "its frontmatter has no `description`",
            .description_too_long => "its `description` is longer than 1024 characters",
            .compatibility_too_long => "its `compatibility` is longer than 500 characters",
            .file_too_long => "the file is larger than this build reads",
            .name_already_taken => "a skill of a layer the user trusts more already has this name",
            .directory_unreadable => "reading the directory stopped partway, so what was found " ++
                "under it is not all of it",
        };
    }
};

pub const Refused = struct {
    dir: []const u8,
    fault: Fault,
    detail: []const u8 = "",
};

pub const max_detail_bytes: usize = 96;

pub const Read = union(enum) {
    skill: Skill,
    refused: Refused,
};

pub const Error = std.mem.Allocator.Error;

pub fn read(
    allocator: std.mem.Allocator,
    io: std.Io,
    layer: Layer,
    dir: []const u8,
) Error!?Read {
    const path = try std.fs.path.join(allocator, &.{ dir, file_name });
    defer allocator.free(path);

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(max_file_bytes + 1),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return .{ .refused = .{
            .dir = try allocator.dupe(u8, dir),
            .fault = .file_too_long,
        } },
        else => return null,
    };
    defer allocator.free(bytes);

    if (bytes.len > max_file_bytes) return .{ .refused = .{
        .dir = try allocator.dupe(u8, dir),
        .fault = .file_too_long,
    } };

    return try parse(allocator, layer, dir, bytes);
}

pub fn parse(
    allocator: std.mem.Allocator,
    layer: Layer,
    dir: []const u8,
    bytes: []const u8,
) Error!Read {
    const owned_dir = try allocator.dupe(u8, dir);

    const split = frontmatterOf(bytes) orelse return .{ .refused = .{
        .dir = owned_dir,
        .fault = if (opensFrontmatter(bytes)) .frontmatter_not_closed else .no_frontmatter,
    } };

    var fields = Fields{};
    var metadata: std.ArrayList(Pair) = .empty;
    errdefer metadata.deinit(allocator);
    var left_out: usize = 0;

    var metadata_indent: ?usize = null;
    var lines = std.mem.splitScalar(u8, split.frontmatter, '\n');
    while (lines.next()) |raw_line| {
        const raw = std.mem.trimEnd(u8, raw_line, "\r");
        const trimmed = std.mem.trim(u8, raw, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const indent = indentOf(raw);

        if (metadata_indent) |under| {
            if (indent > under) {
                const pair = splitPair(trimmed) orelse continue;
                if (metadata.items.len >= max_metadata_entries) {
                    left_out += 1;
                    continue;
                }
                try metadata.append(allocator, .{
                    .key = try allocator.dupe(u8, pair.key),
                    .value = try allocator.dupe(u8, pair.value),
                });
                continue;
            }
            metadata_indent = null;
        }

        if (indent != 0) continue;
        const pair = splitPair(trimmed) orelse continue;

        if (std.mem.eql(u8, pair.key, "metadata")) {
            if (pair.value.len == 0) metadata_indent = indent;
            continue;
        }
        fields.put(pair.key, pair.value);
    }

    const name = fields.name orelse return .{ .refused = .{
        .dir = owned_dir,
        .fault = .name_missing,
    } };
    if (name.len == 0) return .{ .refused = .{ .dir = owned_dir, .fault = .name_missing } };
    if (name.len > max_name_bytes) return .{ .refused = .{
        .dir = owned_dir,
        .fault = .name_too_long,
        .detail = try cut(allocator, name),
    } };
    if (!isTheShape(name)) return .{ .refused = .{
        .dir = owned_dir,
        .fault = .name_not_the_shape,
        .detail = try cut(allocator, name),
    } };
    if (!std.mem.eql(u8, name, std.fs.path.basename(dir))) return .{ .refused = .{
        .dir = owned_dir,
        .fault = .name_is_not_the_directory,
        .detail = try cut(allocator, name),
    } };

    const description = fields.description orelse return .{ .refused = .{
        .dir = owned_dir,
        .fault = .description_missing,
    } };
    if (description.len == 0) return .{ .refused = .{
        .dir = owned_dir,
        .fault = .description_missing,
    } };
    if (description.len > max_description_bytes) return .{ .refused = .{
        .dir = owned_dir,
        .fault = .description_too_long,
        .detail = try cut(allocator, description),
    } };

    if (fields.compatibility) |it| {
        if (it.len > max_compatibility_bytes) return .{ .refused = .{
            .dir = owned_dir,
            .fault = .compatibility_too_long,
            .detail = try cut(allocator, it),
        } };
    }

    return .{ .skill = .{
        .layer = layer,
        .dir = owned_dir,
        .name = try allocator.dupe(u8, name),
        .description = try allocator.dupe(u8, description),
        .license = try dupeMaybe(allocator, fields.license),
        .compatibility = try dupeMaybe(allocator, fields.compatibility),
        .metadata = try metadata.toOwnedSlice(allocator),
        .allowed_tools = try dupeMaybe(allocator, fields.allowed_tools),
        .body = try allocator.dupe(u8, split.body),
        .metadata_left_out = left_out,
    } };
}

pub const max_skills: usize = 32;

pub const max_dir_entries: usize = 256;

pub const Root = struct {
    layer: Layer,
    path: []const u8,
};

pub const Found = struct {
    skills: []Skill = &.{},
    refused: []Refused = &.{},
    left_out: usize = 0,
};

pub fn discover(
    allocator: std.mem.Allocator,
    io: std.Io,
    roots: []const Root,
) Error!Found {
    var skills: std.ArrayList(Skill) = .empty;
    errdefer skills.deinit(allocator);
    var refused: std.ArrayList(Refused) = .empty;
    errdefer refused.deinit(allocator);
    var left_out: usize = 0;

    for (roots) |root| {
        var dir = std.Io.Dir.cwd().openDir(io, root.path, .{ .iterate = true }) catch continue;
        defer dir.close(io);

        var walk = dir.iterate();
        var seen: usize = 0;
        while (true) {
            const next = walk.next(io) catch {
                try refused.append(allocator, .{
                    .dir = try allocator.dupe(u8, root.path),
                    .fault = .directory_unreadable,
                });
                break;
            };
            const entry = next orelse break;
            if (seen >= max_dir_entries) break;
            seen += 1;
            if (entry.kind != .directory) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;

            const path = try std.fs.path.join(allocator, &.{ root.path, entry.name });
            defer allocator.free(path);

            const read_it = try read(allocator, io, root.layer, path) orelse continue;
            switch (read_it) {
                .refused => |one| try refused.append(allocator, one),
                .skill => |one| {
                    if (findIn(skills.items, one.name) != null) {
                        try refused.append(allocator, .{
                            .dir = one.dir,
                            .fault = .name_already_taken,
                            .detail = one.name,
                        });
                        continue;
                    }
                    if (skills.items.len >= max_skills) {
                        left_out += 1;
                        continue;
                    }
                    try skills.append(allocator, one);
                },
            }
        }
    }

    return .{
        .skills = try skills.toOwnedSlice(allocator),
        .refused = try refused.toOwnedSlice(allocator),
        .left_out = left_out,
    };
}

pub const packaged_subdir = "share/agent-skills";

pub fn packagedRootsIn(
    allocator: std.mem.Allocator,
    io: std.Io,
    store_paths: []const []const u8,
) Error![]const Root {
    var out: std.ArrayList(Root) = .empty;
    errdefer out.deinit(allocator);

    for (store_paths) |base| {
        const path = try std.fs.path.join(allocator, &.{ base, packaged_subdir });
        var dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch {
            allocator.free(path);
            continue;
        };
        dir.close(io);
        try out.append(allocator, .{ .layer = .packaged, .path = path });
    }

    return try out.toOwnedSlice(allocator);
}

pub fn indexEntriesFor(
    allocator: std.mem.Allocator,
    found: []const Skill,
    layer: Layer,
) Error![]index.Entry {
    var out: std.ArrayList(index.Entry) = .empty;
    errdefer out.deinit(allocator);

    for (found) |one| {
        if (one.layer != layer) continue;
        try out.append(allocator, .{
            .name = one.name,
            .description = try index.oneLine(allocator, one.description),
        });
    }

    return try out.toOwnedSlice(allocator);
}

pub const Ask = struct {
    name: []const u8,
};

pub const Named = union(enum) {
    skill: Skill,
    unparsed,
    unknown: []const u8,
};

pub fn namedIn(
    allocator: std.mem.Allocator,
    found: []const Skill,
    arguments: []const u8,
) Error!Named {
    const parsed = std.json.parseFromSlice(Ask, allocator, arguments, .{
        .ignore_unknown_fields = true,
    }) catch return .unparsed;
    defer parsed.deinit();

    if (findIn(found, parsed.value.name)) |one| return .{ .skill = one };
    return .{ .unknown = try allocator.dupe(u8, parsed.value.name) };
}

pub fn detailFor(
    allocator: std.mem.Allocator,
    named: Named,
    found: []const Skill,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    switch (named) {
        .skill => return allocator.dupe(u8, ""),
        .unparsed => try out.appendSlice(
            allocator,
            "nothing was read: this call takes one field, \"name\", holding a string.",
        ),
        .unknown => |name| try out.print(
            allocator,
            "nothing was read: there is no skill named \"{s}\" in this session.",
            .{name},
        ),
    }

    if (found.len == 0) {
        try out.appendSlice(allocator, " This session found no skill at all.");
        return out.toOwnedSlice(allocator);
    }

    try out.appendSlice(allocator, " There is: ");
    for (found, 0..) |one, at| {
        if (at != 0) try out.appendSlice(allocator, ", ");
        try out.appendSlice(allocator, one.name);
    }
    try out.append(allocator, '.');
    return out.toOwnedSlice(allocator);
}

pub fn answerFor(allocator: std.mem.Allocator, skill: Skill) Error![]u8 {
    const files = if (skill.inside.len != 0)
        try std.fmt.allocPrint(allocator, "Its own files are under {s}", .{skill.inside})
    else
        try allocator.dupe(u8, "Its own files are not in this sandbox, so read none of them");
    defer allocator.free(files);

    return std.fmt.allocPrint(
        allocator,
        "## The skill {s}\n## ({s}. {s}.)\n\n{s}",
        .{ skill.name, skill.layer.wroteIt(), files, skill.body },
    );
}

pub fn findIn(skills: []const Skill, name: []const u8) ?Skill {
    for (skills) |one| {
        if (std.mem.eql(u8, one.name, name)) return one;
    }
    return null;
}

const Fields = struct {
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    compatibility: ?[]const u8 = null,
    allowed_tools: ?[]const u8 = null,

    fn put(self: *Fields, key: []const u8, value: []const u8) void {
        if (std.mem.eql(u8, key, "name")) {
            self.name = value;
        } else if (std.mem.eql(u8, key, "description")) {
            self.description = value;
        } else if (std.mem.eql(u8, key, "license")) {
            self.license = value;
        } else if (std.mem.eql(u8, key, "compatibility")) {
            self.compatibility = value;
        } else if (std.mem.eql(u8, key, "allowed-tools")) {
            self.allowed_tools = value;
        }
    }
};

const Split = struct {
    frontmatter: []const u8,
    body: []const u8,
};

const fence = "---";

fn opensFrontmatter(bytes: []const u8) bool {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw| {
        const trimmed = std.mem.trim(u8, raw, " \t\r");
        if (trimmed.len == 0) continue;
        return std.mem.eql(u8, trimmed, fence);
    }
    return false;
}

fn frontmatterOf(bytes: []const u8) ?Split {
    var at: usize = 0;
    while (nextLine(bytes, &at)) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        if (!std.mem.eql(u8, trimmed, fence)) return null;
        break;
    }

    const starts = at;
    while (true) {
        const before = at;
        const line = nextLine(bytes, &at) orelse return null;
        if (!std.mem.eql(u8, std.mem.trim(u8, line, " \t\r"), fence)) continue;
        return .{ .frontmatter = bytes[starts..before], .body = bytes[at..] };
    }
}

fn nextLine(bytes: []const u8, at: *usize) ?[]const u8 {
    if (at.* >= bytes.len) return null;
    const rest = bytes[at.*..];
    const end = std.mem.indexOfScalar(u8, rest, '\n') orelse {
        at.* = bytes.len;
        return rest;
    };
    at.* += end + 1;
    return rest[0..end];
}

fn isTheShape(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name, 0..) |byte, at| {
        switch (byte) {
            'a'...'z', '0'...'9' => {},
            '-' => if (at != 0 and name[at - 1] == '-') return false,
            else => return false,
        }
    }
    return true;
}

fn indentOf(raw: []const u8) usize {
    var count: usize = 0;
    while (count < raw.len and raw[count] == ' ') count += 1;
    return count;
}

fn splitPair(trimmed: []const u8) ?Pair {
    const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return null;
    const key = unquote(std.mem.trim(u8, trimmed[0..colon], " \t"));
    if (key.len == 0) return null;
    return .{ .key = key, .value = unquote(std.mem.trim(u8, trimmed[colon + 1 ..], " \t")) };
}

fn unquote(value: []const u8) []const u8 {
    if (value.len < 2) return value;
    const first = value[0];
    if (first != '"' and first != '\'') return value;
    if (value[value.len - 1] != first) return value;
    return value[1 .. value.len - 1];
}

fn dupeMaybe(allocator: std.mem.Allocator, value: ?[]const u8) Error!?[]const u8 {
    const it = value orelse return null;
    return try allocator.dupe(u8, it);
}

fn cut(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    if (value.len <= max_detail_bytes) return try allocator.dupe(u8, value);
    return try std.fmt.allocPrint(allocator, "{s}...", .{value[0..max_detail_bytes]});
}

const testing = std.testing;

const minimal =
    \\---
    \\name: skill-name
    \\description: A description of what this skill does and when to use it.
    \\---
    \\
;

test "the spec's minimal example reads, and the body after it is the body" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document = minimal ++ "# Do the thing\n\nOne step, then another.\n";
    const read_it = try parse(arena, .operator, "/skills/skill-name", document);

    const skill = read_it.skill;
    try testing.expectEqualStrings("skill-name", skill.name);
    try testing.expectEqualStrings(
        "A description of what this skill does and when to use it.",
        skill.description,
    );
    try testing.expectEqualStrings("# Do the thing\n\nOne step, then another.\n", skill.body);
    try testing.expectEqual(Layer.operator, skill.layer);
    try testing.expectEqual(@as(?[]const u8, null), skill.license);
    try testing.expectEqual(@as(usize, 0), skill.metadata.len);
}

test "the spec's example with optional fields keeps every one of them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document =
        \\---
        \\name: pdf-processing
        \\description: Extract PDF text, fill forms, merge files. Use when handling PDFs.
        \\license: Apache-2.0
        \\compatibility: Requires Python 3.14+ and uv
        \\metadata:
        \\  author: example-org
        \\  version: "1.0"
        \\---
        \\body
    ;
    const read_it = try parse(arena, .packaged, "/nix/store/aaa-pdf/pdf-processing", document);

    const skill = read_it.skill;
    try testing.expectEqualStrings("Apache-2.0", skill.license.?);
    try testing.expectEqualStrings("Requires Python 3.14+ and uv", skill.compatibility.?);
    try testing.expectEqual(@as(usize, 2), skill.metadata.len);
    try testing.expectEqualStrings("author", skill.metadata[0].key);
    try testing.expectEqualStrings("example-org", skill.metadata[0].value);
    try testing.expectEqualStrings("1.0", skill.metadata[1].value);
    try testing.expectEqualStrings("body", skill.body);
}

test "every name the spec calls invalid is refused, and every valid one reads" {
    try testing.expect(isTheShape("pdf-processing"));
    try testing.expect(isTheShape("data-analysis"));
    try testing.expect(isTheShape("code-review"));
    try testing.expect(isTheShape("a"));
    try testing.expect(isTheShape("a1"));

    try testing.expect(!isTheShape("PDF-Processing"));
    try testing.expect(!isTheShape("-pdf"));
    try testing.expect(!isTheShape("pdf-"));
    try testing.expect(!isTheShape("pdf--processing"));
    try testing.expect(!isTheShape(""));
    try testing.expect(!isTheShape("pdf_processing"));
    try testing.expect(!isTheShape("pdf processing"));
    try testing.expect(!isTheShape("pdf.processing"));
}

test "a name that is not the directory's own name is refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document =
        \\---
        \\name: deploy-to-production
        \\description: Does something else entirely.
        \\---
    ;
    const read_it = try parse(arena, .project, "/repo/.chock/skills/read-a-file", document);
    try testing.expectEqual(Fault.name_is_not_the_directory, read_it.refused.fault);
    try testing.expectEqualStrings("deploy-to-production", read_it.refused.detail);
}

test "a document with no frontmatter is refused, and an unclosed one says which" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const plain = try parse(arena, .operator, "/skills/a", "# Just markdown\n\nand a body.\n");
    try testing.expectEqual(Fault.no_frontmatter, plain.refused.fault);

    const unclosed = try parse(arena, .operator, "/skills/a", "---\nname: a\n");
    try testing.expectEqual(Fault.frontmatter_not_closed, unclosed.refused.fault);

    const rule = try parse(arena, .operator, "/skills/a", "# Title\n\n---\n\nmore\n");
    try testing.expectEqual(Fault.no_frontmatter, rule.refused.fault);
}

test "a missing or empty required field is refused by name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const no_name = try parse(arena, .operator, "/skills/a", "---\ndescription: d\n---\n");
    try testing.expectEqual(Fault.name_missing, no_name.refused.fault);

    const no_description = try parse(arena, .operator, "/skills/a", "---\nname: a\n---\n");
    try testing.expectEqual(Fault.description_missing, no_description.refused.fault);

    const empty = try parse(arena, .operator, "/skills/a", "---\nname: a\ndescription:\n---\n");
    try testing.expectEqual(Fault.description_missing, empty.refused.fault);
}

test "a field past the spec's bound is refused, and the refusal does not quote the whole of it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const long = "a" ** (max_description_bytes + 1);
    const document = try std.fmt.allocPrint(
        arena,
        "---\nname: a\ndescription: {s}\n---\n",
        .{long},
    );
    const read_it = try parse(arena, .operator, "/skills/a", document);
    try testing.expectEqual(Fault.description_too_long, read_it.refused.fault);
    try testing.expect(read_it.refused.detail.len < max_detail_bytes + 8);

    const wide = "b" ** (max_name_bytes + 1);
    const named = try std.fmt.allocPrint(arena, "---\nname: {s}\ndescription: d\n---\n", .{wide});
    const second = try parse(arena, .operator, "/skills/a", named);
    try testing.expectEqual(Fault.name_too_long, second.refused.fault);
}

test "allowed-tools is kept verbatim and is never split into anything" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document =
        \\---
        \\name: a
        \\description: d
        \\allowed-tools: Bash(git:*) Bash(jq:*) Read
        \\---
    ;
    const read_it = try parse(arena, .project, "/repo/skills/a", document);
    try testing.expectEqualStrings("Bash(git:*) Bash(jq:*) Read", read_it.skill.allowed_tools.?);

    const fields = @typeInfo(Skill).@"struct".fields;
    inline for (fields) |field| {
        try testing.expect(std.mem.indexOf(u8, field.name, "allow") == null or
            std.mem.eql(u8, field.name, "allowed_tools"));
        try testing.expect(std.mem.indexOf(u8, field.name, "permit") == null);
        try testing.expect(std.mem.indexOf(u8, field.name, "grant") == null);
    }
}

test "the action name is per layer, so no skill can put a name of its own in the table" {
    try testing.expectEqualStrings("skill.read.operator", Layer.operator.actionName());
    try testing.expectEqualStrings("skill.read.project", Layer.project.actionName());
    try testing.expectEqualStrings("skill.read.packaged", Layer.packaged.actionName());

    inline for (@typeInfo(Layer).@"enum".fields) |field| {
        const layer = @field(Layer, field.name);
        try testing.expect(std.mem.startsWith(u8, layer.actionName(), "skill.read."));
        try testing.expect(layer.wroteIt().len != 0);
    }

    try testing.expect(std.mem.indexOf(u8, Layer.project.wroteIt(), "not by your operator") != null);
    try testing.expect(std.mem.indexOf(u8, Layer.packaged.wroteIt(), "not by your operator") != null);
    try testing.expect(std.mem.indexOf(u8, Layer.operator.wroteIt(), "not by your operator") == null);
}

test "metadata is bounded, and the count left out is reported" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var document: std.ArrayList(u8) = .empty;
    try document.appendSlice(arena, "---\nname: a\ndescription: d\nmetadata:\n");
    for (0..max_metadata_entries + 3) |at| {
        try document.print(arena, "  key{d}: value\n", .{at});
    }
    try document.appendSlice(arena, "---\n");

    const read_it = try parse(arena, .operator, "/skills/a", document.items);
    try testing.expectEqual(max_metadata_entries, read_it.skill.metadata.len);
    try testing.expectEqual(@as(usize, 3), read_it.skill.metadata_left_out);
}

test "a key at the top level after metadata is a top level key again" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document =
        \\---
        \\name: a
        \\metadata:
        \\  author: somebody
        \\description: the one after the nested block
        \\---
    ;
    const read_it = try parse(arena, .operator, "/skills/a", document);
    try testing.expectEqualStrings("the one after the nested block", read_it.skill.description);
    try testing.expectEqual(@as(usize, 1), read_it.skill.metadata.len);
}

test "a comment and a blank line are skipped, and an unknown key is not a refusal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document =
        \\---
        \\# what this is
        \\name: a
        \\
        \\description: d
        \\version: 3
        \\---
    ;
    const read_it = try parse(arena, .operator, "/skills/a", document);
    try testing.expectEqualStrings("a", read_it.skill.name);
    try testing.expectEqualStrings("d", read_it.skill.description);
}

test "a directory with no SKILL.md is null, and one too large is refused by size" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    try testing.expectEqual(@as(?Read, null), try read(gpa, io, .operator, root));

    const big = try gpa.alloc(u8, max_file_bytes + 1);
    defer gpa.free(big);
    @memset(big, 'a');
    try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = big });

    const refused = (try read(gpa, io, .operator, root)).?;
    defer gpa.free(refused.refused.dir);
    try testing.expectEqual(Fault.file_too_long, refused.refused.fault);
}

test "a skill on disk reads, and the directory it came from is what it says" {
    const gpa = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "write-a-test");
    try tmp.dir.writeFile(io, .{
        .sub_path = "write-a-test/" ++ file_name,
        .data = "---\nname: write-a-test\ndescription: How this repository writes a test.\n---\nbody\n",
    });

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const dir = try std.fs.path.join(gpa, &.{ root, "write-a-test" });
    defer gpa.free(dir);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const read_it = (try read(arena_state.allocator(), io, .project, dir)).?;
    try testing.expectEqualStrings("write-a-test", read_it.skill.name);
    try testing.expectEqualStrings(dir, read_it.skill.dir);
    try testing.expectEqualStrings("body\n", read_it.skill.body);
}

fn writeSkill(io: std.Io, dir: std.Io.Dir, name: []const u8, description: []const u8) !void {
    try dir.createDirPath(io, name);
    var buffer: [512]u8 = undefined;
    const body = try std.fmt.bufPrint(
        &buffer,
        "---\nname: {s}\ndescription: {s}\n---\nThe body of {s}.\n",
        .{ name, description, name },
    );
    const sub = try std.fmt.allocPrint(testing.allocator, "{s}/{s}", .{ name, file_name });
    defer testing.allocator.free(sub);
    try dir.writeFile(io, .{ .sub_path = sub, .data = body });
}

test "discovery reads every skill under a root and leaves the rest of the tree alone" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeSkill(io, tmp.dir, "read-a-file", "How to read a file here.");
    try writeSkill(io, tmp.dir, "write-a-test", "How this repository writes a test.");
    try tmp.dir.createDirPath(io, "notes");
    try tmp.dir.createDirPath(io, ".hidden");
    try tmp.dir.writeFile(io, .{
        .sub_path = ".hidden/" ++ file_name,
        .data = "---\nname: hidden\ndescription: d\n---\n",
    });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const found = try discover(arena, io, &.{.{ .layer = .operator, .path = root }});
    try testing.expectEqual(@as(usize, 2), found.skills.len);
    try testing.expectEqual(@as(usize, 0), found.refused.len);
    try testing.expect(findIn(found.skills, "read-a-file") != null);
    try testing.expect(findIn(found.skills, "write-a-test") != null);
    try testing.expect(findIn(found.skills, "hidden") == null);
    try testing.expect(findIn(found.skills, "notes") == null);
}

test "a root that is not there is no skills and not a failure" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const found = try discover(arena_state.allocator(), testing.io, &.{
        .{ .layer = .operator, .path = "/nowhere/at/all/skills" },
        .{ .layer = .project, .path = "/nor/here" },
    });
    try testing.expectEqual(@as(usize, 0), found.skills.len);
    try testing.expectEqual(@as(usize, 0), found.refused.len);
}

test "the first root keeps a name both hold, so a repository cannot shadow the user's own" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "operator");
    try tmp.dir.createDirPath(io, "project");
    var operator_dir = try tmp.dir.openDir(io, "operator", .{});
    defer operator_dir.close(io);
    var project_dir = try tmp.dir.openDir(io, "project", .{});
    defer project_dir.close(io);

    try writeSkill(io, operator_dir, "deploy", "The way the user deploys.");
    try writeSkill(io, project_dir, "deploy", "The way this repository says to deploy.");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    const operator = try std.fs.path.join(arena, &.{ root, "operator" });
    const project = try std.fs.path.join(arena, &.{ root, "project" });

    const found = try discover(arena, io, &.{
        .{ .layer = .operator, .path = operator },
        .{ .layer = .project, .path = project },
    });

    try testing.expectEqual(@as(usize, 1), found.skills.len);
    try testing.expectEqual(Layer.operator, found.skills[0].layer);
    try testing.expectEqualStrings("The way the user deploys.", found.skills[0].description);

    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expectEqual(Fault.name_already_taken, found.refused[0].fault);
    try testing.expectEqualStrings("deploy", found.refused[0].detail);
}

test "a directory that holds a broken SKILL.md is refused by name and not dropped" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try writeSkill(io, tmp.dir, "good-one", "A skill that reads.");
    try tmp.dir.createDirPath(io, "bad-one");
    try tmp.dir.writeFile(io, .{
        .sub_path = "bad-one/" ++ file_name,
        .data = "---\nname: bad-one\n---\nno description at all\n",
    });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const found = try discover(arena, io, &.{.{ .layer = .project, .path = root }});
    try testing.expectEqual(@as(usize, 1), found.skills.len);
    try testing.expectEqual(@as(usize, 1), found.refused.len);
    try testing.expectEqual(Fault.description_missing, found.refused[0].fault);
    try testing.expect(std.mem.endsWith(u8, found.refused[0].dir, "bad-one"));
}

test "discovery stops at the bound and counts what it left out" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var name_buffer: [32]u8 = undefined;
    for (0..max_skills + 4) |at| {
        const name = try std.fmt.bufPrint(&name_buffer, "skill-{d:0>3}", .{at});
        try writeSkill(io, tmp.dir, name, "One of many.");
    }

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    const found = try discover(arena, io, &.{.{ .layer = .operator, .path = root }});
    try testing.expectEqual(max_skills, found.skills.len);
    try testing.expectEqual(@as(usize, 4), found.left_out);
}

test "only a store path that holds the packaged directory becomes a root" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "aaa-with-skills/" ++ packaged_subdir);
    var with = try tmp.dir.openDir(io, "aaa-with-skills/" ++ packaged_subdir, .{});
    defer with.close(io);
    try writeSkill(io, with, "review-a-diff", "How this package reviews a diff.");

    try tmp.dir.createDirPath(io, "bbb-plain/bin");
    try tmp.dir.createDirPath(io, "ccc-file/share");
    try tmp.dir.writeFile(io, .{ .sub_path = "ccc-file/share/agent-skills", .data = "not a dir" });

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];
    var closure: [3][]const u8 = undefined;
    for ([_][]const u8{ "aaa-with-skills", "bbb-plain", "ccc-file" }, 0..) |name, at| {
        closure[at] = try std.fs.path.join(arena, &.{ root, name });
    }

    const roots = try packagedRootsIn(arena, io, &closure);
    try testing.expectEqual(@as(usize, 1), roots.len);
    try testing.expectEqual(Layer.packaged, roots[0].layer);

    const found = try discover(arena, io, roots);
    try testing.expectEqual(@as(usize, 1), found.skills.len);
    try testing.expectEqualStrings("review-a-diff", found.skills[0].name);
    try testing.expectEqual(Layer.packaged, found.skills[0].layer);
}

test "a walk that stops partway says so rather than reporting the skills it did reach" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try tmp.dir.writeFile(io, .{ .sub_path = "not-a-dir", .data = "x" });
    const file_root = try std.fs.path.join(arena, &.{ root, "not-a-dir" });
    const nothing = try discover(arena, io, &.{.{ .layer = .operator, .path = file_root }});
    try testing.expectEqual(@as(usize, 0), nothing.skills.len);
    try testing.expectEqual(@as(usize, 0), nothing.refused.len);

    try testing.expect(std.mem.indexOf(
        u8,
        Fault.directory_unreadable.sentence(),
        "not all of it",
    ) != null);
}

test "a heading says who wrote the layer's skills, and never disagrees with wroteIt" {
    inline for (@typeInfo(Layer).@"enum".fields) |field| {
        const layer = @field(Layer, field.name);
        const head = layer.heading();

        try testing.expect(std.mem.indexOf(u8, head, layer.wroteIt()) != null);
        try testing.expect(std.mem.indexOf(u8, head, "read_skill") != null);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "\n"));
    }
}

test "an index line is one line a skill, with the body left behind" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const long = "x" ** 400;
    const document = try std.fmt.allocPrint(
        arena,
        "---\nname: a\ndescription: first line\n  and a second\n---\n{s}",
        .{long},
    );
    const one = (try parse(arena, .project, "/repo/skills/a", document)).skill;

    const entries = try indexEntriesFor(arena, &.{one}, .project);
    try testing.expectEqual(@as(usize, 1), entries.len);
    try testing.expectEqualStrings("a", entries[0].name);
    try testing.expect(std.mem.indexOfScalar(u8, entries[0].description, '\n') == null);
    try testing.expect(entries[0].description.len <= index.max_description_bytes);

    try testing.expectEqual(@as(usize, 0), (try indexEntriesFor(arena, &.{one}, .operator)).len);

    var rendered: std.ArrayList(u8) = .empty;
    try index.renderInto(arena, &rendered, entries);
    try testing.expect(std.mem.indexOf(u8, rendered.items, long) == null);
}

test "the answer names who wrote it, and a path only when the agent can open it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const document = "---\nname: deploy\ndescription: How to deploy.\n---\nStep one.\n";
    var one = (try parse(arena, .packaged, "/nix/store/aaa-x/deploy", document)).skill;

    one.inside = "/nix/store/aaa-x/deploy";
    const placed = try answerFor(arena, one);
    try testing.expect(std.mem.startsWith(u8, placed, "## The skill deploy\n"));
    try testing.expect(std.mem.indexOf(u8, placed, "not by your operator") != null);
    try testing.expect(std.mem.indexOf(u8, placed, "under /nix/store/aaa-x/deploy") != null);
    try testing.expect(std.mem.endsWith(u8, placed, "Step one.\n"));

    one.inside = "";
    const loose = try answerFor(arena, one);
    try testing.expect(std.mem.indexOf(u8, loose, "not in this sandbox") != null);
    try testing.expect(std.mem.indexOf(u8, loose, "/nix/store/aaa-x/deploy") == null);
    try testing.expect(std.mem.endsWith(u8, loose, "Step one.\n"));
}
