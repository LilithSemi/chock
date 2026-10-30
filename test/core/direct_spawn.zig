//! The pieces two tests share: a staging spawn that runs a program as itself,
//! and the fixture around it. A sandbox cannot nest inside CI, so neither
//! test covers Chock's own mount set.

const std = @import("std");

const chock_core = @import("chock-core");

const ast = chock_core.ast;
const ast_command = chock_core.ast_command;

/// Both found on the dev shell at build time. Null is a skip, not a failure:
/// `pkgs/chock/default.nix` names them, and the package build has them not.
pub const program_path: ?[]const u8 = @import("ast_real_path").tree_sitter_path;
pub const parsers_dir: ?[]const u8 = @import("ast_real_path").parsers_dir;

const max_output_bytes: usize = 1 << 20;

/// A file staged in a directory of this test's own, and the program run as
/// itself. The paths it answers with are host paths, because nothing here is
/// moved into a sandbox.
pub const DirectSpawn = struct {
    gpa: std.mem.Allocator,
    dir: std.Io.Dir,
    root: []const u8,
    staged: usize = 0,

    pub fn spawn(self: *DirectSpawn) ast_command.Spawn {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = ast_command.Spawn.VTable{ .stage = stageFn, .run = runFn };

    fn stageFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        bytes: []const u8,
    ) ast_command.Error![]const u8 {
        const self: *DirectSpawn = @ptrCast(@alignCast(ptr));
        const name = try std.fmt.allocPrint(arena, "staged-{d}", .{self.staged});
        self.staged += 1;
        self.dir.writeFile(io, .{ .sub_path = name, .data = bytes }) catch return error.Staging;
        return std.fs.path.join(arena, &.{ self.root, name });
    }

    fn runFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        argv: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ast_command.Error!ast_command.Output {
        _ = ptr;
        _ = deadline;

        var child = std.process.spawn(io, .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch return error.ParserFailed;

        var reader: std.Io.File.Reader = .initStreaming(child.stdout.?, io, &.{});
        const text = reader.interface.allocRemaining(arena, .limited(max_output_bytes)) catch
            return error.ParserFailed;

        const term = child.wait(io) catch return error.ParserFailed;
        return .{
            .text = text,
            .ok = switch (term) {
                .exited => |code| code == 0,
                else => false,
            },
            .timed_out = false,
        };
    }
};

pub const Fixture = struct {
    tmp: std.testing.TmpDir,
    root: []u8,
    spawn: DirectSpawn,
    session: ast_command.Session,

    pub fn init(gpa: std.mem.Allocator, io: std.Io) !Fixture {
        var tmp = std.testing.tmpDir(.{});
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..length]);
        return .{
            .tmp = tmp,
            .root = root,
            .spawn = .{ .gpa = gpa, .dir = tmp.dir, .root = root },
            .session = undefined,
        };
    }

    pub fn parser(self: *Fixture) ast.Parser {
        self.session = .{
            .parsers_dir = parsers_dir.?,
            .spawn = self.spawn.spawn(),
            .this = program_path.?,
        };
        return self.session.parser();
    }

    pub fn deinit(self: *Fixture, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        self.tmp.cleanup();
    }
};

pub fn deadlineIn(io: std.Io, budget_ns: u64) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{
        .raw = .fromNanoseconds(@intCast(budget_ns)),
        .clock = .awake,
    });
}
