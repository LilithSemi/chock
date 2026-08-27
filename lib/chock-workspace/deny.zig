//! The `deny_read` block of a project's own `chock.zon`: the files the agent
//! may not read.
//!
//! ## Why this is the layer that holds
//!
//! **Bytes that never enter the process cannot be missed.**
//! `lib/chock-core/redact.zig` searches a request on its way to a provider for
//! a value Chock already knows, which catches an accident and stops no attack:
//! an agent that can read a file can also base64 it, split it across three
//! results, or spell it out one character at a time. That file's own top
//! comment says so plainly and names this layer as the missing one. This is
//! that layer. A denied file is not in the mount tree a tool call reads
//! through, so there is nothing left to search for.
//!
//! ## Which copy of `chock.zon` governs, and why it is not the obvious one
//!
//! **The host project's own copy, read before the sandbox is built.** The
//! agent works in a checkout or an overlay that carries its own `chock.zon`,
//! and although `Workspace.sandboxConfig` binds that path read only, a rule
//! that decides what the sandbox may hold must not be read out of the sandbox
//! at all. `lib/chock-policy/table.zig`'s own `load` already takes the project
//! root and not a workspace path, for the same reason, and `Workspace.adopt`
//! is the case that makes the difference concrete: it takes over a checkout a
//! whole session has already worked in.
//!
//! ## What this supports, and what it refuses by name
//!
//! **One file, named by a path relative to the project root.** A path in a
//! subdirectory is fine. Every one of these is refused, by its own error, when
//! the list is read and never later:
//!
//! * an absolute path, `error.DenyPathNotRelative`. The sandbox holds the
//!   project and the read only toolchain closure and little else, so an
//!   absolute path such as `/home/you/.aws/credentials` names something that
//!   is already absent. Accepting it would promise a protection that is not
//!   this file's to give.
//! * a path that climbs out with `..`, `error.DenyPathLeavesProject`.
//! * a directory, `error.DenyPathIsDirectory`. See `chock-sandbox`'s own
//!   `Mount.Deny`: a covered directory reads as "this project keeps no
//!   credentials here", which is the confusion this whole design avoids, and
//!   there is nowhere in an empty directory to put a line that corrects it.
//!   **So `~/.aws` is refused twice over, once for being absolute and once for
//!   being a directory, and neither refusal is a gap this file hides.**
//! * a glob, `error.DenyPathIsAPattern`. `*` and `?` and `[` are refused
//!   rather than matched, because a pattern that matches nothing today reads
//!   exactly like a pattern that protects something.
//! * `chock.zon` itself, `error.DenyPathIsChockZon`. It is already bound read
//!   only by `Workspace.sandboxConfig`, and denying it would only hide the
//!   project's own rules from the agent that has to work under them.
//! * more than `max_paths` entries, `error.TooManyDenyPaths`. Every entry is a
//!   `statx` and a mount on every tool call.
//!
//! **A `chock.zon` this file cannot read is refused, and not read as an empty
//! list.** A file nobody can parse is not a file that said "deny nothing".
//!
//! ## Two errors for that, and not one, because one of them was a lie
//!
//! **Measured on the owner's own machine on 2026-08-25.** They added a policy
//! rule to `chock.zon`, put it directly under `.policy` instead of under
//! `.policy.rules`, and read:
//!
//! ```
//! chock run: the workspace for /home/ross/tristanxr.com could not be built:
//! DenyBlockNotValid
//! ```
//!
//! They had written no `deny_read` block at all. This file has to parse the
//! whole of `chock.zon` to find its own field in it, so it saw the fault in
//! the *policy* block and reported it as its own. There is no line, no column
//! and no hint, and the one word in the message points at a block that is not
//! in the file. `chock.zon` is the first thing a person writes with Chock, so
//! this is the ordinary case and not an edge case.
//!
//! So the two faults are two errors, and only one of them names this block:
//!
//! * `error.ChockZonNotValid`, for a file that is not ZON, or whose top level
//!   is not a struct literal. **The fault can be in any block, or in none**,
//!   and this error claims no more than "this file". The `Diagnostic` carries
//!   Zoir's own message, with the line and the column.
//! * `error.DenyBlockNotValid`, for a `deny_read` that is there and is not a
//!   list of strings. This one names the block, and it is true: it is only
//!   reached after the file parsed and a `deny_read` field was found.
//!
//! ## Two readers of one file, and why both still parse it
//!
//! `lib/chock-policy/table.zig` and `lib/chock-cost/budget.zig` read the same
//! file and each has its own errors. Three readers each parsing the whole file
//! is what made the fault above: whichever runs first sees every fault and,
//! before this change, named them all as its own.
//!
//! **The parse is not what was wrong. The claim was.** One parse per reader
//! costs microseconds on a file bounded at `max_file_bytes`, and the three
//! readers run at three different moments of a session for three different
//! reasons: this one before the workspace is built, the policy table when the
//! broker starts, the budget when the cap is set. Threading one shared syntax
//! tree between three libraries in two packages, so that the *last* reader
//! could still refuse a file the *first* one already accepted, buys nothing a
//! person can see. All three now open a file level fault with the same
//! sentence, `chock.zon is not valid`, and follow it with Zoir's own line and
//! column, so it does not matter which one speaks first.
//!
//! ## The offending entry is not in the error, and here is why
//!
//! `chock-workspace/diagnostic.zig` owns no memory and allocates nothing,
//! which is a property with a test on it, so there is no slot to put the
//! offending path in. Each path error above names the rule that was broken
//! instead, and the list it was broken in is one short block of one file. The
//! two ZON errors are the exception, and they carry their detail in a fixed
//! array: see `Diagnostic.Said`.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

pub const Diagnostic = diagnostic.Diagnostic;

/// The file a project writes this in, in its own root.
pub const file_name = "chock.zon";

/// The block this reads. See this file's own top comment.
pub const block_name = "deny_read";

/// The most entries one project may name. Every entry costs a `statx` and a
/// mount inside every tool call, so this is a real bound and not a formality.
/// A project that wants to deny more than this many separate files is asking
/// for a directory, which this design refuses on purpose.
pub const max_paths: usize = 64;

/// The largest `chock.zon` this reads.
///
/// **It is not the cap the other two readers of this file use.**
/// `lib/chock-policy/table.zig` and `lib/chock-cost/budget.zig` both accept
/// `1 << 20`, so a `chock.zon` between this number and theirs is refused here
/// and accepted there. This reader runs first, so that file never reaches
/// them. The number is left where it is because widening a bound on a file
/// the project directory supplies is a decision of its own, and
/// `error.ChockZonTooLarge` now says which reader refused and what its bound
/// is, rather than reading as a fault of the `deny_read` block.
pub const max_file_bytes: usize = 64 * 1024;

pub const Error = error{
    OutOfMemory,
    /// `chock.zon` is not ZON, or its top level is not a struct literal. **The
    /// fault can be in any block of that file, or in none of them**, so this
    /// names the file and never a block. See this file's own top comment.
    ChockZonNotValid,
    /// `chock.zon` is larger than `max_file_bytes`.
    ChockZonTooLarge,
    /// `deny_read` is there and is not a list of strings.
    DenyBlockNotValid,
    /// An entry is absolute, or is empty.
    DenyPathNotRelative,
    /// An entry has a `..` component.
    DenyPathLeavesProject,
    /// An entry holds a glob character.
    DenyPathIsAPattern,
    /// An entry names `chock.zon`, which is already protected.
    DenyPathIsChockZon,
    /// An entry names a directory in the project.
    DenyPathIsDirectory,
    /// The list is longer than `max_paths`.
    TooManyDenyPaths,
    /// `chock.zon` is there and could not be read.
    ReadFailed,
};

/// Read the `deny_read` block of `project_root`'s own `chock.zon` and give
/// back one absolute path per entry, each already joined onto `project_root`,
/// which is where a denied file lands inside the sandbox as well as on the
/// host: `Workspace.sandboxConfig` mounts the project at its own real path.
///
/// An empty slice for a project with no `chock.zon`, and for one whose
/// `chock.zon` names no `deny_read`. **Those two are the same answer on
/// purpose**: both are a project that denied nothing, and
/// `Workspace.sandboxConfig` adds no mount for either, so such a project
/// behaves byte for byte as it did before this block existed.
///
/// `io` is used twice: to read the file, and to ask the project whether each
/// entry is a directory. A path this cannot find on the host is accepted, and
/// is the case `chock-sandbox`'s own `Mount.Deny` covers by making an empty
/// file to bind over.
///
/// `diag` is optional. A caller that passes null pays nothing and learns only
/// the error name, which for the two ZON errors is not enough to fix a file.
///
/// The caller owns the returned slice and every string in it. `free` releases
/// both.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    return loadFor(gpa, io, project_root, project_root, diag);
}

/// `load`, for a sandbox that sees the project somewhere other than where it
/// really is.
///
/// **The block is always read from `project_root`, and only the join
/// changes.** `deny.zig`'s own top comment says why: a rule that decides what
/// the sandbox may hold must not be read out of the sandbox. `sandbox_root`
/// is `Worktree.sandboxRoot` or `Overlay.sandboxRoot`, which under
/// `Layout.in_place` is the agent's own copy at its own real path.
pub fn loadFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    sandbox_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    const entries = try loadEntries(gpa, io, project_root, diag);
    defer free(gpa, entries);
    return joinOnto(gpa, entries, sandbox_root);
}

/// Every entry of the block, checked against every rule this file keeps, and
/// still relative.
///
/// **Split from the join so a caller can refuse a bad block before it builds
/// anything.** `Workspace.openWithLayout` cannot know where the sandbox will
/// see the project until the backing exists, and a `deny_read` block this
/// cannot honour must refuse the session rather than half build one. So the
/// reading and the checking happen first, and `joinOnto` happens afterwards.
///
/// The caller owns the returned slice and every string in it. `free` releases
/// both.
pub fn loadEntries(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // No policy file at all, and no policy file where a directory should
        // be: a project that denied nothing either way.
        error.FileNotFound, error.NotDir => return &.{},
        // A `chock.zon` larger than every other reader of the same file will
        // accept is not a file this may quietly read as empty. **Its own
        // error**: reading this as "your deny_read block is wrong" is the
        // fault this file's top comment is about.
        error.StreamTooLong => {
            diagnostic.note(diag, .{ .chock_zon_too_large = max_file_bytes });
            return error.ChockZonTooLarge;
        },
        else => {
            diagnostic.noteErr(diag, .chock_zon_read, err);
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parseEntries(gpa, io, source, project_root, diag);
}

/// Every entry joined onto `root`, one absolute path each. The caller owns the
/// result and releases it with `free`.
pub fn joinOnto(
    gpa: std.mem.Allocator,
    entries: []const []u8,
    root: []const u8,
) Error![]const []u8 {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }
    for (entries) |entry| {
        try out.append(gpa, try std.fs.path.join(gpa, &.{ root, entry }));
    }
    return out.toOwnedSlice(gpa);
}

/// `load`, given the bytes. `project_root` is still needed, both to join each
/// entry onto and to ask whether an entry is a directory there.
///
/// Split out from `load` so this module's own tests measure the rules against
/// real ZON text without a file on disk for every case, and so a caller that
/// already holds the source does not read it twice.
pub fn parse(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    return parseFor(gpa, io, source, project_root, project_root, diag);
}

/// `parse`, for a sandbox that sees the project somewhere other than where it
/// really is. Each entry is joined onto `sandbox_root`, and the question of
/// whether an entry names a directory is still asked of `project_root`, which
/// is the disk that has the answer.
pub fn parseFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    sandbox_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    const entries = try parseEntries(gpa, io, source, project_root, diag);
    defer free(gpa, entries);
    return joinOnto(gpa, entries, sandbox_root);
}

/// `loadEntries`, given the bytes. Every rule of this file is checked here,
/// and nothing is joined onto anything.
pub fn parseEntries(
    gpa: std.mem.Allocator,
    io: std.Io,
    source: [:0]const u8,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) Error![]const []u8 {
    // **`trees_owned` is the handover flag `lib/chock-cost/budget.zig` also
    // keeps.** The type check below can be given the two trees, and a
    // `std.zon.parse.Diagnostics` that holds them frees them itself. Only one
    // of the two may free them.
    var trees_owned = true;
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer if (trees_owned) ast.deinit(gpa);

    // `parse_str_lits = false` matches what `std.zon.parse.fromSliceAlloc`
    // does, the same as every other reader of this one file.
    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer if (trees_owned) zoir.deinit(gpa);

    // A syntax error arrives here too, because `ZonGen.generate` lowers the
    // errors of the `Ast` into its own. When there is one, the `Zoir` holds no
    // nodes at all, so nothing may walk it.
    //
    // **A fault of the whole file, and reported as one.** This reader has not
    // reached its own block yet and cannot: a file that does not parse has no
    // fields to look through. See this file's own top comment for the day this
    // was reported as `DenyBlockNotValid` instead.
    if (zoir.hasCompileErrors()) {
        diagnostic.note(diag, .{ .chock_zon_not_valid = saidOf(ast, zoir) });
        return error.ChockZonNotValid;
    }

    const node = try findBlockNode(zoir, diag) orelse return &.{};

    // **A `std.zon.parse.Diagnostics`, the same as `lib/chock-cost/budget.zig`
    // and `lib/chock-policy/table.zig`.** This is what names the line and the
    // column of a fault inside the block. `fromZoirNodeAlloc` puts the two
    // trees in it, so from the refusal below it owns them.
    var zon_diag: std.zon.parse.Diagnostics = .{};
    const entries = std.zon.parse.fromZoirNodeAlloc(
        []const []const u8,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // **The block, named truthfully.** The file parsed and a `deny_read`
        // field was found in it, so this fault really is in this block.
        error.ParseZon => {
            // The message is copied into the `Said` before anything is
            // released, and the `Said` is an array, so nothing it carries
            // points into the trees freed on the next line.
            diagnostic.note(diag, .{ .deny_block_not_valid = .of(&zon_diag) });
            // The trees, and the type check failure whose own `deinit` is not
            // public. Releasing all three through the diagnostics is what
            // makes that one reachable, so the two `defer`s above stand down.
            trees_owned = false;
            zon_diag.deinit(gpa);
            return error.DenyBlockNotValid;
        },
    };
    defer std.zon.parse.free(gpa, entries);

    if (entries.len > max_paths) return error.TooManyDenyPaths;

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (entries) |entry| {
        try check(entry);

        const on_the_host = try std.fs.path.join(gpa, &.{ project_root, entry });
        defer gpa.free(on_the_host);
        if (try isDirectory(io, on_the_host)) return error.DenyPathIsDirectory;

        try out.append(gpa, try gpa.dupe(u8, entry));
    }

    return out.toOwnedSlice(gpa);
}

/// Release what `load` or `parse` returned, with the allocator that built it.
pub fn free(gpa: std.mem.Allocator, paths: []const []u8) void {
    for (paths) |one| gpa.free(one);
    gpa.free(paths);
}

/// Whether one entry is a path this file supports. See this file's own top
/// comment for each rule and why it is a refusal rather than a best effort.
///
/// **Public, because the rules are what a reader wants to test.** A test that
/// drove every rule through `parse` would need a project on disk for each one,
/// and the rule it was checking would be the least visible thing in it.
pub fn check(entry: []const u8) Error!void {
    if (entry.len == 0) return error.DenyPathNotRelative;
    if (std.fs.path.isAbsolute(entry)) return error.DenyPathNotRelative;

    for (entry) |byte| {
        switch (byte) {
            '*', '?', '[' => return error.DenyPathIsAPattern,
            else => {},
        }
    }

    var parts = std.mem.tokenizeScalar(u8, entry, '/');
    var named: usize = 0;
    var last: []const u8 = "";
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, ".")) continue;
        // A `..` anywhere leaves, whatever came before it: `a/../../b` climbs
        // out of the project as surely as `../b` does, and this file refuses a
        // path rather than working out where one lands.
        if (std.mem.eql(u8, part, "..")) return error.DenyPathLeavesProject;
        named += 1;
        last = part;
    }
    // "." and "./" and "" all name the project root itself, which is a
    // directory, and a directory is refused.
    if (named == 0) return error.DenyPathIsDirectory;

    // **The project's own policy file, and only that one.** A `chock.zon` in a
    // subdirectory belongs to some nested project and is an ordinary file to
    // this one, so refusing it too would take a name away for no gain. This
    // refuses the file `Workspace.sandboxConfig` already binds read only,
    // however it is spelled.
    if (named == 1 and std.mem.eql(u8, last, file_name)) return error.DenyPathIsChockZon;
}

/// The node of the `deny_read` field at the top of the file, or null when the
/// file has no such field. Every other top level field is skipped, because
/// other parts of Chock own the other blocks of this one file: the same shape
/// `lib/chock-cost/budget.zig` and `lib/chock-policy/table.zig` both use.
fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) Error!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        // **A fault of the file and not of this block.** A `chock.zon` whose
        // top level is a tuple, or a number, holds no block of any name, so
        // saying `deny_read` here would name a block that cannot exist. Zoir
        // reports no error for this, so the words are this file's own.
        else => {
            diagnostic.note(diag, .{
                .chock_zon_not_valid = .ofText("the file must hold a struct literal"),
            });
            return error.ChockZonNotValid;
        },
    }
}

/// What Zoir said about `ast`, ready to travel in a `Diagnostic`.
///
/// **The trees stay this module's.** `Diagnostic.Said.of` reads the
/// `std.zon.parse.Diagnostics` and copies the bytes out, so the value built
/// here is never released and never frees the two trees `parseEntries` frees
/// itself.
fn saidOf(ast: std.zig.Ast, zoir: std.zig.Zoir) Diagnostic.Said {
    const zon_diag: std.zon.parse.Diagnostics = .{ .ast = ast, .zoir = zoir };
    return .of(&zon_diag);
}

/// Whether `absolute_path` is a directory on the host today. False for a path
/// that is not there at all, which is the case `chock-sandbox`'s own
/// `applyDenyMounts` covers by making an empty file. Any other failure reads
/// as false too: this is a check that improves the message a project author
/// gets, and `applyDenyMounts` refuses a directory again with the sandbox in
/// front of it, so a `statx` this process could not make cannot let a
/// directory through.
fn isDirectory(io: std.Io, absolute_path: []const u8) Error!bool {
    const stat = std.Io.Dir.cwd().statFile(io, absolute_path, .{}) catch return false;
    return stat.kind == .directory;
}

const testing = std.testing;

test "a project with no deny_read block denies nothing" {
    // **The case that must cost nothing**, because it is every project that
    // exists today. An empty answer here is what makes `sandboxConfig` add no
    // mount at all, so such a project builds exactly the sandbox it always
    // did.
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .budget = .{ .max_cost = 5.0 } }
    , "/project", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "an empty struct literal denies nothing, and is not a fault" {
    // `.{}` is a real `chock.zon` that several tests in this project write,
    // and Zoir gives it its own node kind rather than a struct literal with no
    // fields. Reading it as a fault would refuse to build a workspace for a
    // project whose policy file is simply empty.
    const paths = try parse(testing.allocator, testing.io, ".{}", "/project", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "each named path comes back joined onto the project root" {
    // The join is the whole output of this module: a denied path lands at the
    // project's own real path inside the sandbox, because that is where
    // `Workspace.sandboxConfig` mounts the project. A version that returned
    // the relative entry would build a mount at a path with no project under
    // it, and the mount would cover nothing.
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .deny_read = .{ ".env", "config/secret.txt" } }
    , "/project", null);
    defer free(testing.allocator, paths);

    try testing.expectEqual(@as(usize, 2), paths.len);
    try testing.expectEqualStrings("/project/.env", paths[0]);
    try testing.expectEqualStrings("/project/config/secret.txt", paths[1]);
}

test "the block is read out of a file that also holds every other block" {
    // `chock.zon` is one file with six other blocks in it, each owned by a
    // different part of Chock. A reader that took the first field, or that
    // refused a field it did not know, would break every project that already
    // has one.
    const paths = try parse(testing.allocator, testing.io,
        \\.{
        \\    .budget = .{ .max_cost = 5.0, .currency = "USD" },
        \\    .deny_read = .{ ".env" },
        \\    .subagents = .{ .max_width = 2 },
        \\}
    , "/p", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
    try testing.expectEqualStrings("/p/.env", paths[0]);
}

test "a chock.zon that is not ZON is refused, and never read as an empty list" {
    // **The direction this must fail in.** A file nobody can parse has not
    // said "deny nothing", and reading it that way would drop a project's
    // whole secret protection for a missing brace.
    try testing.expectError(error.ChockZonNotValid, parse(
        testing.allocator,
        testing.io,
        ".{ .deny_read = ",
        "/p",
        null,
    ));
    // A `deny_read` that is not a list of strings is this block's own fault,
    // and it keeps this block's own error.
    try testing.expectError(error.DenyBlockNotValid, parse(
        testing.allocator,
        testing.io,
        ".{ .deny_read = 7 }",
        "/p",
        null,
    ));
}

/// Read `source` and give back the message a person sees, in `buffer`.
/// `error.NoFault` when the file was accepted, which is a failure of the case
/// that used it.
fn messageFor(source: [:0]const u8, buffer: []u8) ![]const u8 {
    var diag: ?Diagnostic = null;
    if (parse(testing.allocator, testing.io, source, "/p", &diag)) |paths| {
        free(testing.allocator, paths);
        return error.NoFault;
    } else |_| {}
    const fault = diag orelse return error.NoDiagnostic;
    return std.fmt.bufPrint(buffer, "{f}", .{&fault});
}

test "a fault in any block of chock.zon names the file and the line, and no block" {
    // **The whole bug, and the test the old one could not be.** A single
    // malformed file proves nothing about a reader that reported every fault
    // under one name, so this drives one file per block and one file per kind
    // of mistake. Each case states where the fault really is.
    var buffer: [512]u8 = undefined;

    // 1. The owner's own file, measured on 2026-08-25: a rule written beside
    //    a named field of the policy block, which is what a person writes
    //    when they have not read where `.rules` goes. The fault is on line 4
    //    of the policy block. The old message was `DenyBlockNotValid`, and
    //    the file holds no `deny_read` at all.
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n4:9: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .policy = .{
            \\        .agents = .{ .{ .kind = "main" } },
            \\        .{ .action = "net.fetch.org.ziglang", .decision = .allow },
            \\    },
            \\}
        , &buffer),
    );

    // 2. A stray comma, in the budget block, on line 2.
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n2:36: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .budget = .{ .max_cost = 5.0 },,
            \\}
        , &buffer),
    );

    // 3. A missing dot before a block name, on line 3.
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n3:5: error: expected field initializer",
        try messageFor(
            \\.{
            \\    .budget = .{ .max_cost = 5.0 },
            \\    policy = .{ .rules = .{} },
            \\}
        , &buffer),
    );

    // 4. A file that is not ZON at all. Still the file, still a line.
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n1:7: error: expected 'EOF', found 'an identifier'",
        try messageFor("hello world\n", &buffer),
    );

    // 5. A top level that is a tuple of rules, which is a file with no blocks
    //    in it at all. Zoir reports no error for this one, so the words are
    //    this module's own, and they still name the file and not a block.
    try testing.expectEqualStrings(
        "chock.zon is not valid:\nthe file must hold a struct literal",
        try messageFor(
            \\.{
            \\    .{ .action = "net.fetch.org.ziglang", .decision = .allow },
            \\}
        , &buffer),
    );

    // 6. And the one case that may name this block: `deny_read` is there, the
    //    file parsed, and the block is not a list of strings. The message
    //    names the block and the line inside it.
    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n2:18: error: expected array",
        try messageFor(
            \\.{
            \\    .deny_read = 7,
            \\}
        , &buffer),
    );

    // 7. A wrong type on one entry of the block, which is the same claim with
    //    a narrower line.
    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n2:29: error: expected string",
        try messageFor(
            \\.{
            \\    .deny_read = .{ ".env", 7 },
            \\}
        , &buffer),
    );
}

test "a misspelled block name is not this reader's fault to report" {
    // **The other half of the truthfulness rule.** `.polcy` is a real mistake
    // and a real ZON struct, so this reader must walk past it: it owns one
    // field of this file and the policy reader owns the rest. A reader that
    // refused every field it did not know would refuse every `chock.zon` that
    // gains a block in a later release.
    const paths = try parse(testing.allocator, testing.io,
        \\.{ .polcy = .{ .rules = .{} } }
    , "/p", null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 0), paths.len);
}

test "a chock.zon above the bound is its own error, and not this block's" {
    // The last of the four faults that all read as `DenyBlockNotValid`. A file
    // too big to read says nothing about `deny_read`, and the number in the
    // message is what tells a person the file is the problem.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(testing.allocator);
    try big.appendSlice(testing.allocator, ".{ .deny_read = .{ \".env\" } } // ");
    try big.appendNTimes(testing.allocator, 'x', max_file_bytes);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = file_name, .data = big.items });

    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.ChockZonTooLarge,
        loadEntries(testing.allocator, testing.io, root, &diag),
    );

    var line: [128]u8 = undefined;
    try testing.expectEqualStrings(
        "chock.zon is larger than the 65536 bytes this reader accepts",
        try std.fmt.bufPrint(&line, "{f}", .{&diag.?}),
    );
}

test "a caller that wants no diagnostic pays nothing and still gets the error" {
    // The ordinary caller. Null in, and no store is reached at all.
    try testing.expectError(error.ChockZonNotValid, parse(
        testing.allocator,
        testing.io,
        "not zon",
        "/p",
        null,
    ));
}

test "every refused shape of path has its own error" {
    // Each of these is a rule this file promises to keep, and a project author
    // reads the error name to learn which one they broke. Collapse any two
    // into one error and this test says so.
    try testing.expectError(error.DenyPathNotRelative, check(""));
    try testing.expectError(error.DenyPathNotRelative, check("/etc/passwd"));
    try testing.expectError(error.DenyPathLeavesProject, check("../outside"));
    try testing.expectError(error.DenyPathLeavesProject, check("a/../../outside"));
    try testing.expectError(error.DenyPathIsAPattern, check("*.env"));
    try testing.expectError(error.DenyPathIsAPattern, check("secret?.txt"));
    try testing.expectError(error.DenyPathIsAPattern, check("secret[12].txt"));
    try testing.expectError(error.DenyPathIsChockZon, check("chock.zon"));
    try testing.expectError(error.DenyPathIsChockZon, check("./chock.zon"));
    try testing.expectError(error.DenyPathIsDirectory, check("."));
    try testing.expectError(error.DenyPathIsDirectory, check("./"));
    // And only the project's own policy file: a `chock.zon` in a subdirectory
    // is a nested project's file and an ordinary one to this project.
    try check("nested/chock.zon");

    // And the shapes that are accepted, so the rules above are not simply a
    // refusal of everything.
    try check(".env");
    try check("config/secret.txt");
    try check("./config/secret.txt");
    try check("a/b/c/id_rsa");
}

test "a directory in the project is refused by name" {
    // **The `~/.aws` question, answered.** A directory cannot be covered with
    // a file, and covering it with an empty directory would teach the model
    // that the project keeps nothing there. See this file's own top comment.
    // This half of the refusal needs a real directory, because it is the only
    // rule that reads the disk.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    try tmp.dir.createDir(testing.io, "credentials", .default_dir);

    try testing.expectError(error.DenyPathIsDirectory, parse(
        testing.allocator,
        testing.io,
        \\.{ .deny_read = .{ "credentials" } }
    ,
        root,
        null,
    ));
}

test "a path the project does not hold yet is accepted" {
    // A `.env` that is in `.gitignore` is not in a checkout at all, and a
    // project that denies one has said something true about a name rather than
    // about a file. Refusing here would make the block useless for the most
    // common secret file there is. `chock-sandbox`'s own `applyDenyMounts` is
    // what makes that name unreadable when it appears.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    const root = buffer[0..len];

    const paths = try parse(testing.allocator, testing.io,
        \\.{ .deny_read = .{ ".env" } }
    , root, null);
    defer free(testing.allocator, paths);
    try testing.expectEqual(@as(usize, 1), paths.len);
}

test "a list longer than max_paths is refused" {
    const allocator = testing.allocator;

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(allocator);
    try source.appendSlice(allocator, ".{ .deny_read = .{");
    for (0..max_paths + 1) |index| {
        try source.print(allocator, "\"f{d}\",", .{index});
    }
    try source.appendSlice(allocator, "} }");
    const owned = try source.toOwnedSliceSentinel(allocator, 0);
    defer allocator.free(owned);

    try testing.expectError(error.TooManyDenyPaths, parse(allocator, testing.io, owned, "/p", null));
}

test "a refusal in the middle of a list frees every path already built" {
    // The testing allocator is the check: a refusal on the second entry must
    // not leak the first. An `errdefer` that only freed the list and not the
    // strings in it would pass every other test in this file.
    try testing.expectError(error.DenyPathNotRelative, parse(
        testing.allocator,
        testing.io,
        \\.{ .deny_read = .{ ".env", "/etc/passwd" } }
    ,
        "/p",
        null,
    ));
}
