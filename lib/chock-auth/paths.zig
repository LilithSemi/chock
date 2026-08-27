//! Chock's two directories, and the two rules that decide whether a file in
//! one of them is safe to read or safe to write.
//!
//! **The split of directory is the split of ownership.** Everything under the
//! configuration directory belongs to the user, or to home-manager, and Chock
//! only reads it. Everything Chock writes goes under the data directory,
//! where home-manager does not look. A user can give home-manager the whole
//! configuration directory and `chock login` still works, because the two
//! never touch the same file.
//!
//! | | Default | Owner |
//! |---|---|---|
//! | configuration | `~/.config/chock` | the user, or home-manager |
//! | data | `~/.local/share/chock` | Chock, always |

const std = @import("std");

/// The directory name Chock uses inside both XDG directories.
pub const dir_name = "chock";

/// The prefix a Nix store path starts with. A constant, because the store
/// location is fixed on every machine Chock supports, and reading it from
/// the environment would let a caller turn the check off.
pub const nix_store_prefix = "/nix/store/";

pub const DirError = std.mem.Allocator.Error || error{
    /// Neither the XDG variable nor `HOME` says where the directory is, so
    /// Chock cannot name a path at all. Reported rather than guessed: a
    /// guessed path is a credential written somewhere the user cannot find.
    NoHomeDirectory,
};

/// The configuration directory: `$XDG_CONFIG_HOME/chock`, or
/// `$HOME/.config/chock`. **Chock only ever reads this.** Caller owns the
/// result.
pub fn configDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_CONFIG_HOME", &.{".config"});
}

/// The data directory: `$XDG_DATA_HOME/chock`, or
/// `$HOME/.local/share/chock`. **Chock alone writes this.** Caller owns the
/// result.
pub fn dataDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_DATA_HOME", &.{ ".local", "share" });
}

/// The state directory, where a session log goes: `$XDG_STATE_HOME/chock`,
/// or `$HOME/.local/state/chock`. This holds no credential, so it has no
/// mode rule of its own. It is here, and not in `chock-proto`, because it is
/// the same XDG question the two directories above answer and a second
/// answer to one question is how two answers drift apart. Caller owns the
/// result.
pub fn stateDir(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) DirError![]u8 {
    return xdgDir(gpa, env, "XDG_STATE_HOME", &.{ ".local", "state" });
}

fn xdgDir(
    gpa: std.mem.Allocator,
    env: *const std.process.Environ.Map,
    variable: []const u8,
    home_relative: []const []const u8,
) DirError![]u8 {
    if (env.get(variable)) |base| {
        if (base.len != 0) return std.fs.path.join(gpa, &.{ base, dir_name });
    }
    const home = env.get("HOME") orelse return error.NoHomeDirectory;
    if (home.len == 0) return error.NoHomeDirectory;

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(gpa);
    try parts.append(gpa, home);
    try parts.appendSlice(gpa, home_relative);
    try parts.append(gpa, dir_name);
    return std.fs.path.join(gpa, parts.items);
}

/// Why a path was refused, and the facts the error alone throws away.
///
/// **This owns nothing and allocates nothing.** `path` points at the caller's
/// own argument, and `target` points into the buffer the caller gives
/// `refuseNixStore`, so both live as long as the caller's own memory does.
pub const Diagnostic = union(enum) {
    stat_failed: StatFailed,
    readable_by_others: ReadableByOthers,
    in_the_nix_store: []const u8,
    /// The path is a symbolic link into the Nix store, which is what
    /// home-manager writes.
    links_into_the_nix_store: LinksIntoTheNixStore,

    pub const StatFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const ReadableByOthers = struct {
        path: []const u8,
        mode: u32,
    };

    pub const LinksIntoTheNixStore = struct {
        path: []const u8,
        target: []const u8,
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .stat_failed => |fault| try writer.print(
                "the credential file {s} could not be read: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .readable_by_others => |fault| try writer.print(
                "the credential file {s} has mode {o:0>4}, and a credential must be readable by its owner only. " ++
                    "Run: chmod 600 {s}",
                .{ fault.path, fault.mode, fault.path },
            ),
            .in_the_nix_store => |path| try writer.print(
                "{s} is in the Nix store, which is read only and readable by every user on this machine, " ++
                    "so Chock will not write a credential there",
                .{path},
            ),
            .links_into_the_nix_store => |fault| try writer.print(
                "{s} is a symbolic link into the Nix store ({s}), so home-manager owns it: it is read only, " ++
                    "it is readable by every user on this machine, and it is replaced on the next activation. " ++
                    "Chock will not write a credential there",
                .{ fault.path, fault.target },
            ),
        }
    }
};

/// Fill `out` when the caller asked for one.
///
/// **The first fault is kept, not the last.** A path is checked once here, so
/// this only matters to a caller that reuses one slot over several paths: the
/// first refusal is the one that stopped the run.
fn note(out: ?*?Diagnostic, value: Diagnostic) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

pub const PrivateError = error{
    /// Somebody other than the owner can read this file. Pass a `Diagnostic`
    /// to learn the mode that was found. A wrong mode is a fault, never a
    /// warning.
    CredentialFileIsReadable,
    /// There is no such file. Its own member, and silent, because "this
    /// source holds nothing" is the ordinary case for two of the three lookup
    /// sources: a user who never wrote a token file must not be told about it
    /// on every run.
    CredentialFileMissing,
    /// The file is there and could not be inspected. Pass a `Diagnostic` to
    /// learn why. Never folded into `CredentialFileMissing`: a file Chock
    /// cannot look at is not a file that is not there.
    StatFailed,
};

/// Refuse `path` when any class other than the owner can read it.
///
/// This is the one check that makes an inline `token` safe, so it runs over
/// every one of the three lookup sources, not only over the store Chock
/// writes itself.
///
/// Three answers, and each one is a different fact. A file that is not there
/// is `error.CredentialFileMissing`, quietly, because two of the three lookup
/// sources are ordinarily absent. A file that is there and cannot be
/// inspected is `error.StatFailed`, with the reason in `diag`, because a
/// credential file Chock cannot look at is not a credential file that may be
/// read. Neither is ever success.
///
/// `diag` borrows `path`, so it stays valid as long as the caller's own
/// argument does. A caller that passes null pays nothing.
pub fn requirePrivate(io: std.Io, path: []const u8, diag: ?*?Diagnostic) PrivateError!void {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return error.CredentialFileMissing,
        else => {
            note(diag, .{ .stat_failed = .{ .path = path, .err = err } });
            return error.StatFailed;
        },
    };
    const mode = stat.permissions.toMode() & 0o7777;
    if (mode & 0o077 == 0) return;
    note(diag, .{ .readable_by_others = .{ .path = path, .mode = mode } });
    return error.CredentialFileIsReadable;
}

pub const NixStoreError = error{
    /// The path is in the Nix store, or is a symbolic link into it. Pass a
    /// `Diagnostic` to learn which of the two, and where the link goes.
    PathIsInTheNixStore,
};

/// Refuse to write `path` when it is in the Nix store, or is a symbolic link
/// into it.
///
/// The Nix store is world readable and every file in it is read only, and
/// home-manager replaces its symbolic links on each activation. So a write
/// here either fails, or succeeds and is lost on the next `home-manager
/// switch`. Both are worth one `readlink` and a message that says which of
/// the two the user is looking at.
///
/// A path that does not exist yet is fine: there is no link to follow, so
/// there is nothing to refuse.
///
/// **`link_buffer` is the caller's, and it must hold `std.fs.max_path_bytes`
/// bytes.** The link is read into it, and a diagnostic that names the target
/// points into it, so it belongs to the caller for the same reason `path`
/// does: this function allocates nothing and a diagnostic that borrowed a
/// buffer of this function's own would dangle the moment it returned.
pub fn refuseNixStore(
    io: std.Io,
    path: []const u8,
    link_buffer: []u8,
    diag: ?*?Diagnostic,
) NixStoreError!void {
    std.debug.assert(link_buffer.len >= std.fs.max_path_bytes);

    if (std.mem.startsWith(u8, path, nix_store_prefix)) {
        note(diag, .{ .in_the_nix_store = path });
        return error.PathIsInTheNixStore;
    }

    const len = std.Io.Dir.readLinkAbsolute(io, path, link_buffer) catch return;
    const target = link_buffer[0..len];
    if (!std.mem.startsWith(u8, target, nix_store_prefix)) return;
    note(diag, .{ .links_into_the_nix_store = .{ .path = path, .target = target } });
    return error.PathIsInTheNixStore;
}

const testing = std.testing;

fn tmpPath(buffer: []u8, tmp: std.testing.TmpDir, name: []const u8) ![]const u8 {
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &dir_buffer);
    return std.fmt.bufPrint(buffer, "{s}/{s}", .{ dir_buffer[0..len], name });
}

fn writeWithMode(path: []const u8, mode: std.posix.mode_t, contents: []const u8) !void {
    var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(testing.io);
    try file.writeStreamingAll(testing.io, contents);
    // The process umask narrows the mode `createFileAbsolute` asks for, so a
    // test that wants a wide mode has to widen it again after the fact.
    try file.setPermissions(testing.io, .fromMode(mode));
}

test "a credential file others can read is refused, and the message names the mode" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "wide");
    try writeWithMode(path, 0o644, "sk-not-a-real-key\n");

    // The mode itself is the fact this pins. A test that only checked for an
    // error would pass against a version that refused every file.
    try testing.expectError(error.CredentialFileIsReadable, requirePrivate(testing.io, path, null));

    var narrow_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const narrow = try tmpPath(&narrow_buffer, tmp, "narrow");
    try writeWithMode(narrow, 0o600, "sk-not-a-real-key\n");
    try requirePrivate(testing.io, narrow, null);
}

test "a group readable credential file is refused too, not only a world readable one" {
    // 0640 is the mode a user reaches for when they want their own group to
    // share a key. It is still a credential another account can read, so the
    // rule is "the owner only", never "not everybody".
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "group");
    try writeWithMode(path, 0o640, "sk-not-a-real-key\n");
    try testing.expectError(error.CredentialFileIsReadable, requirePrivate(testing.io, path, null));
}

test "a missing credential file is its own answer, and never reads back as a mode that is fine" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "absent");
    try testing.expectError(error.CredentialFileMissing, requirePrivate(testing.io, path, null));
}

test "a symbolic link into the Nix store is refused for writing, and a plain file is not" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var scratch_link_buffer: [std.fs.max_path_bytes]u8 = undefined;

    var plain_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const plain = try tmpPath(&plain_buffer, tmp, "plain.zon");
    try writeWithMode(plain, 0o600, ".{}\n");
    try refuseNixStore(testing.io, plain, &scratch_link_buffer, null);

    // A link to a path under the store prefix. The target does not have to
    // exist: home-manager's own links point at paths this test cannot make,
    // and `readlink` reads the link and never the target.
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link = try tmpPath(&link_buffer, tmp, "managed.zon");
    try tmp.dir.symLink(
        testing.io,
        nix_store_prefix ++ "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-home-manager-files/.config/chock/config.zon",
        "managed.zon",
        .{},
    );
    try testing.expectError(error.PathIsInTheNixStore, refuseNixStore(testing.io, link, &scratch_link_buffer, null));

    try testing.expectError(
        error.PathIsInTheNixStore,
        refuseNixStore(testing.io, nix_store_prefix ++ "aaaa-chock/config.zon", &scratch_link_buffer, null),
    );

    // A path that does not exist yet has no link to follow, so there is
    // nothing to refuse. `chock login` writes a store that was never there
    // before, and this is that case.
    var absent_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const absent = try tmpPath(&absent_buffer, tmp, "not-yet.zon");
    try refuseNixStore(testing.io, absent, &scratch_link_buffer, null);
}

test "the two directories come from XDG when it is set and from HOME otherwise, and neither is inside the other" {
    const gpa = testing.allocator;

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try env.put("HOME", "/home/somebody");

    {
        const config = try configDir(gpa, &env);
        defer gpa.free(config);
        const data = try dataDir(gpa, &env);
        defer gpa.free(data);
        try testing.expectEqualStrings("/home/somebody/.config/chock", config);
        try testing.expectEqualStrings("/home/somebody/.local/share/chock", data);
        // Nothing Chock writes ever lands under the configuration
        // directory. Different directories, not merely
        // different files, because a user who points home-manager at a
        // directory gets the whole directory managed.
        try testing.expect(!std.mem.startsWith(u8, data, config));
    }

    try env.put("XDG_CONFIG_HOME", "/elsewhere/config");
    try env.put("XDG_DATA_HOME", "/elsewhere/data");
    {
        const config = try configDir(gpa, &env);
        defer gpa.free(config);
        const data = try dataDir(gpa, &env);
        defer gpa.free(data);
        try testing.expectEqualStrings("/elsewhere/config/chock", config);
        try testing.expectEqualStrings("/elsewhere/data/chock", data);
        try testing.expect(!std.mem.startsWith(u8, data, config));
    }
}

test "a machine with no home directory is told so, never given a guessed path" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    try testing.expectError(error.NoHomeDirectory, configDir(gpa, &env));
    try testing.expectError(error.NoHomeDirectory, dataDir(gpa, &env));
}

test "the mode a credential file holds reaches the caller, and no longer only a terminal" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmpPath(&buffer, tmp, "group");
    try writeWithMode(path, 0o640, "sk-not-a-real-key\n");

    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.CredentialFileIsReadable,
        requirePrivate(testing.io, path, &diag),
    );
    try testing.expectEqual(@as(u32, 0o640), diag.?.readable_by_others.mode);
    try testing.expectEqualStrings(path, diag.?.readable_by_others.path);

    var line_buffer: [1024]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "has mode 0640") != null);
    try testing.expect(std.mem.indexOf(u8, line, "chmod 600") != null);
}

test "a link target is borrowed from the caller's own buffer, so it outlives the call" {
    // `refuseNixStore` reads the link into the buffer its caller gives it,
    // which is the reason that buffer is a parameter: a diagnostic that
    // named a buffer of the function's own would dangle the moment it
    // returned.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const link = try tmpPath(&path_buffer, tmp, "managed.zon");
    const target = nix_store_prefix ++ "zzzz-home-manager-files/.config/chock/config.zon";
    try tmp.dir.symLink(testing.io, target, "managed.zon", .{});

    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.PathIsInTheNixStore,
        refuseNixStore(testing.io, link, &link_buffer, &diag),
    );
    try testing.expectEqualStrings(target, diag.?.links_into_the_nix_store.target);
    try testing.expectEqualStrings(link, diag.?.links_into_the_nix_store.path);
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    note(&diag, .{ .in_the_nix_store = "/nix/store/aaaa-x/config.zon" });
    note(&diag, .{ .readable_by_others = .{ .path = "/other", .mode = 0o644 } });
    try testing.expectEqualStrings("/nix/store/aaaa-x/config.zon", diag.?.in_the_nix_store);

    // A caller that asked for no diagnostic must reach no store at all.
    note(null, .{ .in_the_nix_store = "/nix/store/aaaa-x/config.zon" });
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .stat_failed = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .readable_by_others = .{ .path = "/x", .mode = 0o644 } },
        .{ .in_the_nix_store = "/x" },
        .{ .links_into_the_nix_store = .{ .path = "/x", .target = "/nix/store/aaaa-y" } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
