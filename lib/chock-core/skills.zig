//! Agent Skills, read in: one `SKILL.md` directory, bounded, and marked with
//! the layer it came from.
//!
//! The format is `docs/specification.mdx` of
//! <https://github.com/agentskills/agentskills>, pinned at 217be54.
//!
//! ## Two modules, and this one invents neither
//!
//! `guidance.zig` already has the disclosure the format asks for: the prompt
//! names what exists in one line each, and a tool fetches the whole of one
//! when the model decides it applies. `instructions.zig` already has the trust
//! handling a skill needs: a layer on every block, a bound applied to every
//! file, and a list of what was read for the run to print. A skill is the
//! first mechanism with the second one's marking.
//!
//! ## `allowed-tools` is read as a narrowing and never as a grant
//!
//! The field is "a space-separated string of tools that are pre-approved to
//! run". A skill is content that arrived in a directory somebody else wrote,
//! so a client that honours that lets a downloaded file widen what an agent
//! may do. `instructions.zig` states the rule this breaks: never let an
//! instruction file change the policy, the budget, or the tool list.
//!
//! So the field is kept verbatim and it decides nothing. A caller may read it
//! as the skill saying it needs no more than these, which narrows and is free.
//! Nothing here turns it into a permission, and `Skill.allowed_tools` is a
//! string this module never parses.
//!
//! ## The frontmatter scanner
//!
//! This build carries no YAML parser and adds none for one file. `parse` reads
//! block style mappings: one `key: value` pair a line, spaces for indentation,
//! an optionally quoted scalar, a whole line comment whose first character is
//! `#`, and one nested mapping under `metadata:`. What it does not read, and
//! never guesses at: flow style, multi-line scalars, anchors and aliases,
//! tabs for indentation, and a trailing comment after a value on the same
//! line, which is read as part of the value.
//!
//! A shape it does not read is a refusal that names the field, never silence.
//! A skill is something a person installed and expects to work, so one that is
//! dropped without a word is worse than one that is refused out loud.

const std = @import("std");
const index = @import("index.zig");

/// The one file a skill directory must hold.
pub const file_name = "SKILL.md";

/// Where the operator's own skills live, under Chock's configuration directory.
/// Chock reads it and never writes it, the rule `lib/chock-auth/paths.zig`
/// already states for that directory.
pub const operator_dir_name = "skills";

/// Where a skill that is not otherwise in the sandbox is bound, read only.
///
/// The operator's own directory is the one that needs this: a project's skills
/// are in the workspace already and a package's are in the store the session
/// mounted. The host path is not reused inside, because it holds the user's home
/// directory and a session has no business learning its shape.
pub const inside_root = "/skills";

/// The three directories the format names. Nothing here reads them: they are
/// the skill's own files, which the agent reads with `read_file` once the
/// sandbox binds them.
pub const optional_dirs = [_][]const u8{ "scripts", "references", "assets" };

/// The spec's own bounds.
pub const max_name_bytes: usize = 64;
pub const max_description_bytes: usize = 1024;
pub const max_compatibility_bytes: usize = 500;

/// How much of one `SKILL.md` is read off disk. The spec recommends a body
/// under 500 lines and under 5000 tokens, so this is generous, and a file past
/// it is refused rather than cut: a body that stops halfway through a step is
/// a body a model acts on believing it read the whole one.
pub const max_file_bytes: usize = 64 * 1024;

/// How many `metadata` pairs are kept. The map is arbitrary and belongs to
/// whoever wrote the skill, so it gets a bound like everything else that
/// arrives from outside.
pub const max_metadata_entries: usize = 32;

/// Where a skill came from, which is what decides its trust. The prompt prints
/// it and the policy table names it, so it is a value and not a comment.
///
/// Chock's own compiled in advice is `guidance.zig` and is not a layer here: a
/// skill is a file on disk, and guidance is a string in the binary.
pub const Layer = enum {
    /// `<config dir>/skills/<name>/`, which only the user writes.
    operator,
    /// A path the project's own `chock.zon` names.
    project,
    /// A store path a dev shell brought in.
    packaged,

    /// The policy action for reading a skill of this layer. **Per layer and
    /// never per skill**: a name a stranger's package chose must not become
    /// part of the action namespace.
    pub fn actionName(self: Layer) []const u8 {
        return switch (self) {
            .operator => "skill.read.operator",
            .project => "skill.read.project",
            .packaged => "skill.read.packaged",
        };
    }

    /// Who wrote a skill of this layer, for the line above its body.
    ///
    /// **The parenthetical is the part that does the work**, for the reason
    /// `instructions.Layer.heading` gives: a model told where a block came
    /// from can weigh it, and a model told to fear its own input reasons
    /// worse.
    pub fn wroteIt(self: Layer) []const u8 {
        return switch (self) {
            .operator => "written by the person running you",
            .project => "written by whoever wrote this repository, not by your operator",
            .packaged => "written by a package author, not by your operator",
        };
    }

    /// The heading over this layer's index in the prompt. One heading a layer,
    /// because a layer is the whole of what tells a model how much weight to
    /// give what it is about to read.
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

/// One skill, read and within every bound. Everything in it is owned by the
/// allocator `parse` was given.
pub const Skill = struct {
    layer: Layer,
    /// The skill's own directory on the host, which is what was read.
    dir: []const u8,
    /// The same directory as the agent sees it, or empty when nothing in the
    /// sandbox reaches it. **The answer names this one**, because a path the
    /// agent cannot open is worse than no path: it spends a turn finding out.
    inside: []const u8 = "",
    name: []const u8,
    description: []const u8,
    license: ?[]const u8 = null,
    compatibility: ?[]const u8 = null,
    metadata: []const Pair = &.{},
    /// What `allowed-tools` said, verbatim and unparsed. Read this module's
    /// own top comment before using it: it is never a grant.
    allowed_tools: ?[]const u8 = null,
    /// The Markdown after the frontmatter, which is what the read tool
    /// answers with.
    body: []const u8,
    /// How many `metadata` pairs were left out past `max_metadata_entries`.
    metadata_left_out: usize = 0,
};

/// Why a directory is not a skill. Every one of these names a field or a rule
/// the format states, so a refusal can be read against the spec.
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

/// A directory that holds a `SKILL.md` and is not a skill. The detail is the
/// value that broke the rule, cut to a length a diagnostic can print.
pub const Refused = struct {
    dir: []const u8,
    fault: Fault,
    detail: []const u8 = "",
};

/// How much of an offending value a refusal quotes.
pub const max_detail_bytes: usize = 96;

pub const Read = union(enum) {
    skill: Skill,
    refused: Refused,
};

pub const Error = std.mem.Allocator.Error;

/// Read the `SKILL.md` of `dir`, or null when there is nothing readable there.
///
/// **An absent file is not an error.** Most directories are not skills, and a
/// caller that walks a tree must not stop at the first one that is not.
pub fn read(
    allocator: std.mem.Allocator,
    io: std.Io,
    layer: Layer,
    dir: []const u8,
) Error!?Read {
    const path = try std.fs.path.join(allocator, &.{ dir, file_name });
    defer allocator.free(path);

    // One byte past the bound, so a file exactly at the bound is read and a
    // file past it is refused by size rather than cut.
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

/// Read one `SKILL.md` document. `dir` is the skill's own directory, and the
/// format requires the `name` to be that directory's own name.
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

/// How many skills reach the prompt. Every one costs a line of every turn, so
/// this is a real bound. What is left out is counted, because a repository that
/// arrived with two hundred skills is a fact worth telling the user.
pub const max_skills: usize = 32;

/// How many entries one directory is read for before the walk stops. A runaway
/// directory must not be able to hold a session up.
pub const max_dir_entries: usize = 256;

/// One directory that holds skill directories, and the layer everything under
/// it belongs to.
pub const Root = struct {
    layer: Layer,
    path: []const u8,
};

/// What a session's skills came to. Everything in it is owned by the allocator
/// `discover` was given, and an arena frees the whole thing at once, which is
/// how `instructions.Loaded` is held for the same reason.
pub const Found = struct {
    /// Not `[]const`: the caller places each one, filling in `Skill.inside` once
    /// it knows what the sandbox binds where.
    skills: []Skill = &.{},
    /// Directories that hold a `SKILL.md` and are not skills. The run prints
    /// these: a skill a person installed and that silently did nothing is the
    /// failure this list exists to stop.
    refused: []Refused = &.{},
    /// How many skills were found past `max_skills`.
    left_out: usize = 0,
};

/// Read every skill under every root, one level deep: the format puts each
/// skill in its own directory, named after it.
///
/// **Order is precedence.** A name that two roots both hold belongs to the
/// first, and the later one is refused. Give the roots most trusted first, so
/// the user's own skill wins over a repository's.
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
            // Not `catch null`: a walk that stopped partway is not a
            // directory with nothing more in it, and reporting the two the
            // same way is how a skill goes missing without a word.
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
            // A dotted name is not a skill directory, and `.git` is the one
            // that costs the most to walk into.
            if (entry.name.len == 0 or entry.name[0] == '.') continue;

            // `read` keeps a copy of the directory it was given, so this one
            // is this loop's own.
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

/// Where a package puts its skills under a store path. A package that installs
/// here has said its skills are for any agent that looks, which is the only
/// signal a store path carries. The closure is read for this one name, and
/// nothing about a package's intent is guessed at beyond it.
pub const packaged_subdir = "share/agent-skills";

/// Every store path that holds `packaged_subdir`, as roots of the `packaged`
/// layer. `store_paths` is the dev shell's own closure, which `chock-nix`
/// produces: this module asks Nix nothing.
///
/// One directory open a path. A closure of 2735 paths costs 16ms warm and 43ms
/// cold on the development machine, so the whole closure is read rather than
/// some guessed subset of it.
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

/// One index line per skill of `layer`, in the order they were found.
///
/// **Every description goes through `index.oneLine`.** A skill's description
/// is a stranger's writing and the format allows 1024 bytes of it with
/// newlines in the middle, and the prompt carries one line a skill.
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

/// What a `read_skill` call names. One shape, so the gate that decides the call
/// and the tool that answers it read the same field out of the same JSON.
pub const Ask = struct {
    name: []const u8,
};

/// Which skill a `read_skill` call asks for.
pub const Named = union(enum) {
    /// The skill, found in this session's own list.
    skill: Skill,
    /// The arguments did not parse as this call's shape.
    unparsed,
    /// They parsed and named nothing this session found.
    unknown: []const u8,
};

/// The skill a `read_skill` call names. **Neither refusal is a policy question**:
/// there is nothing to decide about a skill that is not there, so the gate
/// answers both itself.
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

/// What a call that named no skill is told. The list is built from the session's
/// own skills, so one that was found cannot be missing from the message.
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

/// What a `read_skill` call answers with: the body, under a line saying which
/// layer it came from and who wrote it.
///
/// The header is the whole of the trust marking. Without it a skill's body
/// reads as though Chock wrote it, which is the one thing a model must not
/// believe about a directory somebody else shipped.
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

/// The skill of this name, or null. What the read tool resolves a name with.
pub fn findIn(skills: []const Skill, name: []const u8) ?Skill {
    for (skills) |one| {
        if (std.mem.eql(u8, one.name, name)) return one;
    }
    return null;
}

/// Every field this module reads. A key it does not know is dropped: the
/// format lets a client store its own properties under `metadata`, and a
/// refusal for an unknown top level key would refuse a skill a later spec
/// makes valid.
const Fields = struct {
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    license: ?[]const u8 = null,
    compatibility: ?[]const u8 = null,
    allowed_tools: ?[]const u8 = null,

    /// The last of two identical keys wins, which is what a YAML reader does.
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

/// The frontmatter and the body, or null when the document has neither shape.
/// The opening fence must be the first line that holds anything, so a Markdown
/// file with a horizontal rule in the middle of it is not read as frontmatter.
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

/// The next line, with its newline removed, advancing `at` past it.
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

/// The spec's own rules for `name`: lowercase letters, digits and hyphens, no
/// hyphen at either end, and no two hyphens together.
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

/// The front of an offending value, for a refusal to quote. A skill that got
/// its `description` wrong by pasting a whole page into it must not put that
/// page in the diagnostic.
fn cut(allocator: std.mem.Allocator, value: []const u8) Error![]const u8 {
    if (value.len <= max_detail_bytes) return try allocator.dupe(u8, value);
    return try std.fmt.allocPrint(allocator, "{s}...", .{value[0..max_detail_bytes]});
}

const testing = std.testing;

/// The spec's own minimal example, which has to read as a skill.
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
    // The quotes are the YAML's and not the value's.
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

    // The spec requires the two to match, and a directory listing a person
    // reads is the only name they see before the agent reads the body.
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

    // A horizontal rule in the middle of a Markdown file is not frontmatter.
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

    // The field decides nothing, so there is no member on `Skill` that a
    // caller could mistake for a permission. This names every one there is.
    const fields = @typeInfo(Skill).@"struct".fields;
    inline for (fields) |field| {
        try testing.expect(std.mem.indexOf(u8, field.name, "allow") == null or
            std.mem.eql(u8, field.name, "allowed_tools"));
        try testing.expect(std.mem.indexOf(u8, field.name, "permit") == null);
        try testing.expect(std.mem.indexOf(u8, field.name, "grant") == null);
    }
}

test "the action name is per layer, so no skill can put a name of its own in the table" {
    // A package that chose the name `../../root` would reach the policy table
    // through a per skill action. Per layer, there are three names and a
    // skill cannot spell any of them.
    try testing.expectEqualStrings("skill.read.operator", Layer.operator.actionName());
    try testing.expectEqualStrings("skill.read.project", Layer.project.actionName());
    try testing.expectEqualStrings("skill.read.packaged", Layer.packaged.actionName());

    inline for (@typeInfo(Layer).@"enum".fields) |field| {
        const layer = @field(Layer, field.name);
        try testing.expect(std.mem.startsWith(u8, layer.actionName(), "skill.read."));
        try testing.expect(layer.wroteIt().len != 0);
    }

    // Two of the three say the operator did not write it, which is the line
    // that lets a model weigh what it reads.
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

/// Writes a skill directory under `dir`, with `name` as both the directory and
/// the frontmatter name, which is what the format requires.
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
    // Neither of these is a skill: one holds no SKILL.md, and a dotted
    // directory is never walked into.
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

    // And the one that lost says so, rather than vanishing.
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

    // A store path that installs nothing here, and one that puts a file where
    // the directory would be.
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

    // A root that is a file rather than a directory never opens, which is the
    // silent case: no skills and no refusal, the same as an absent root.
    try tmp.dir.writeFile(io, .{ .sub_path = "not-a-dir", .data = "x" });
    const file_root = try std.fs.path.join(arena, &.{ root, "not-a-dir" });
    const nothing = try discover(arena, io, &.{.{ .layer = .operator, .path = file_root }});
    try testing.expectEqual(@as(usize, 0), nothing.skills.len);
    try testing.expectEqual(@as(usize, 0), nothing.refused.len);

    // And the fault a partway walk records names the root, so a user can see
    // which directory was only half read.
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

        // The same words in both places, so the index heading and the line
        // above a body cannot drift apart.
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

    // A skill of another layer is not in this layer's index.
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

    // Nothing binds it, so the host path is never named: the agent would spend a
    // turn finding out it cannot open it.
    one.inside = "";
    const loose = try answerFor(arena, one);
    try testing.expect(std.mem.indexOf(u8, loose, "not in this sandbox") != null);
    try testing.expect(std.mem.indexOf(u8, loose, "/nix/store/aaa-x/deploy") == null);
    try testing.expect(std.mem.endsWith(u8, loose, "Step one.\n"));
}
