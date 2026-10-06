//! Why a `nix` call, or the shell that sources a dev environment, did not

const std = @import("std");

pub const max_shown_bytes: usize = 4096;

pub const Diagnostic = union(enum) {
    program_not_started: ProgramFailed,
    program_wait_failed: ProgramFailed,
    command_refused: CommandRefused,
    nix_not_runnable: anyerror,
    toolchain_not_rooted: anyerror,
    cache_not_written: ProgramFailed,
    store_paths_dropped: PathsDropped,

    pub const What = enum {
        nix_print_dev_env,
        dev_env_shell,
        nix_path_info,
        nix_store_add_root,

        pub fn text(self: What) []const u8 {
            return switch (self) {
                .nix_print_dev_env => "nix print-dev-env",
                .dev_env_shell => "the shell that sources the dev environment",
                .nix_path_info => "nix path-info",
                .nix_store_add_root => "nix-store --add-root",
            };
        }
    };

    pub const ProgramFailed = struct {
        name: []const u8,
        err: anyerror,
    };

    pub const CommandRefused = struct {
        what: What,
        said: []const u8,
    };

    pub const PathsDropped = struct {
        count: usize,
        said: []const u8,
    };

    pub fn deinit(self: *Diagnostic, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .program_not_started,
            .program_wait_failed,
            .cache_not_written,
            => |fault| allocator.free(fault.name),
            .command_refused => |refusal| allocator.free(refusal.said),
            .store_paths_dropped => |dropped| allocator.free(dropped.said),
            .nix_not_runnable, .toolchain_not_rooted => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .program_not_started => |fault| try writer.print(
                "spawning {s} failed: {s}",
                .{ fault.name, @errorName(fault.err) },
            ),
            .program_wait_failed => |fault| try writer.print(
                "waiting for {s} failed: {s}",
                .{ fault.name, @errorName(fault.err) },
            ),
            .command_refused => |refusal| try writer.print(
                "{s} failed:\n{s}",
                .{ refusal.what.text(), refusal.said },
            ),
            .nix_not_runnable => |err| try writer.print(
                "nix could not be run ({s})",
                .{@errorName(err)},
            ),
            .toolchain_not_rooted => |err| try writer.print(
                "the dev shell's toolchain could not be held against the garbage collector ({s}). " ++
                    "A nix-collect-garbage during this session can break it.",
                .{@errorName(err)},
            ),
            .cache_not_written => |fault| try writer.print(
                "the dev shell cache under {s} could not be written ({s}), so the next session " ++
                    "evaluates this flake again",
                .{ fault.name, @errorName(fault.err) },
            ),
            .store_paths_dropped => |dropped| try writer.print(
                "{d} store paths this dev shell names are not mounted, because nix path-info " ++
                    "would not answer for them. A tool call that needs one of them fails. " ++
                    "nix said:\n{s}",
                .{ dropped.count, dropped.said },
            ),
        }
    }
};

pub const Sink = struct {
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

pub fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

pub fn note(out: ?Sink, value: Diagnostic) bool {
    const sink = out orelse return false;
    if (sink.slot.* != null) return false;
    sink.slot.* = value;
    return true;
}

pub fn wants(out: ?Sink) bool {
    const sink = out orelse return false;
    return sink.slot.* == null;
}

pub fn noteRefusal(
    out: ?Sink,
    what: Diagnostic.What,
    stderr: []const u8,
) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    const tail = if (stderr.len > max_shown_bytes)
        stderr[stderr.len - max_shown_bytes ..]
    else
        stderr;
    sink.slot.* = .{ .command_refused = .{
        .what = what,
        .said = try sink.allocator.dupe(u8, tail),
    } };
}

pub fn noteDropped(out: ?Sink, count: usize, said: []const u8) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    const tail = if (said.len > max_shown_bytes) said[said.len - max_shown_bytes ..] else said;
    sink.slot.* = .{ .store_paths_dropped = .{
        .count = count,
        .said = try sink.allocator.dupe(u8, tail),
    } };
}

pub fn noteNamed(
    out: ?Sink,
    comptime tag: std.meta.Tag(Diagnostic),
    name: []const u8,
    err: anyerror,
) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    const copy = try sink.allocator.dupe(u8, name);
    sink.slot.* = @unionInit(Diagnostic, @tagName(tag), .{ .name = copy, .err = err });
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    const sink = sinkOf(testing.allocator, &diag);
    try testing.expect(note(sink, .{ .nix_not_runnable = error.FileNotFound }));
    try testing.expect(!note(sink, .{ .toolchain_not_rooted = error.AccessDenied }));
    try testing.expectEqual(@as(anyerror, error.FileNotFound), diag.?.nix_not_runnable);

    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .nix_not_runnable = error.FileNotFound }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
    try noteRefusal(null, .nix_path_info, "a trace");
    try noteNamed(null, .program_not_started, "nix", error.AccessDenied);

    try noteRefusal(sink, .nix_path_info, "a trace");
    try noteNamed(sink, .program_not_started, "nix", error.AccessDenied);
    diag.?.deinit(testing.allocator);
}

test "a refusal keeps the tail of what nix said, which is the part a user acts on" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);

    const long = try testing.allocator.alloc(u8, max_shown_bytes + 32);
    defer testing.allocator.free(long);
    @memset(long, 'x');
    @memcpy(long[long.len - 5 ..], "endin");

    try noteRefusal(sinkOf(testing.allocator, &diag), .nix_print_dev_env, long);
    try testing.expectEqual(max_shown_bytes, diag.?.command_refused.said.len);
    try testing.expect(std.mem.endsWith(u8, diag.?.command_refused.said, "endin"));
}

test "a message outlives the memory the call that filled it was working in" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const said = try arena.dupe(u8, "error: this flake does not evaluate");
        const program = try arena.dupe(u8, "/nix/store/aaaa-nix/bin/nix");

        try noteNamed(sinkOf(gpa, &diag), .program_not_started, program, error.AccessDenied);
        try testing.expect(diag != null);
        diag.?.deinit(gpa);
        diag = null;

        try noteRefusal(sinkOf(gpa, &diag), .nix_print_dev_env, said);
    }

    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "nix print-dev-env failed:") != null);
    try testing.expect(std.mem.indexOf(u8, line, "this flake does not evaluate") != null);
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .program_not_started = .{ .name = "nix", .err = error.AccessDenied } },
        .{ .program_wait_failed = .{ .name = "nix", .err = error.AccessDenied } },
        .{ .command_refused = .{ .what = .nix_path_info, .said = "no" } },
        .{ .nix_not_runnable = error.FileNotFound },
        .{ .toolchain_not_rooted = error.AccessDenied },
        .{ .cache_not_written = .{ .name = "/cache", .err = error.AccessDenied } },
        .{ .store_paths_dropped = .{ .count = 2, .said = "no" } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "every command this library runs reads as itself" {
    var seen: [std.meta.fields(Diagnostic.What).len][]const u8 = undefined;
    inline for (std.meta.fields(Diagnostic.What), 0..) |field, i| {
        const text = (@field(Diagnostic.What, field.name)).text();
        try testing.expect(text.len > 0);
        for (seen[0..i]) |other| try testing.expect(!std.mem.eql(u8, text, other));
        seen[i] = text;
    }
}
