//! Why a container runtime call, or the extraction that follows it, did not
//! give an answer. Owns every string it carries.

const std = @import("std");

/// How much of the error stream is kept, from the end.
pub const max_shown_bytes: usize = 4096;

pub const Diagnostic = union(enum) {
    program_not_started: ProgramFailed,
    program_wait_failed: ProgramFailed,
    command_refused: CommandRefused,
    runtime_not_runnable: anyerror,
    /// A notice, not a fault: the image could not be cached.
    cache_not_written: ProgramFailed,
    /// A notice, not a fault: entries of the root filesystem were refused.
    entry_refused: EntryRefused,
    /// A notice, not a fault: an entry was left out of the mount set.
    mount_skipped: MountSkipped,

    /// An enumeration and not a string.
    pub const What = enum {
        container_create,
        container_export,

        pub fn text(self: What) []const u8 {
            return switch (self) {
                .container_create => "container create",
                .container_export => "container export",
            };
        }
    };

    pub const Why = enum {
        not_a_file_or_directory,
        link_unreadable,
        link_names_nothing,
        link_leaves_the_image,
        link_points_at_nothing,
        link_points_at_a_link,

        pub fn text(self: Why) []const u8 {
            return switch (self) {
                .not_a_file_or_directory => "it is not a file or a directory",
                .link_unreadable => "it is a link that cannot be read",
                .link_names_nothing => "it is a link that names nothing",
                .link_leaves_the_image => "it points out of the image",
                .link_points_at_nothing => "it points at nothing",
                .link_points_at_a_link => "it points at another link",
            };
        }
    };

    pub const ProgramFailed = struct {
        /// A program name, or a directory.
        name: []const u8,
        err: anyerror,
    };

    pub const CommandRefused = struct {
        what: What,
        /// The tail of what the command wrote.
        said: []const u8,
    };

    pub const MountSkipped = struct {
        /// The top level name, such as `lib`.
        entry: []const u8,
        why: Why,
    };

    pub const EntryRefused = struct {
        entry: []const u8,
        /// Including this one.
        total: usize,
    };

    pub fn deinit(self: *Diagnostic, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .program_not_started,
            .program_wait_failed,
            .cache_not_written,
            => |fault| allocator.free(fault.name),
            .command_refused => |refusal| allocator.free(refusal.said),
            .entry_refused => |refused| allocator.free(refused.entry),
            .mount_skipped => |skipped| allocator.free(skipped.entry),
            .runtime_not_runnable => {},
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
            .runtime_not_runnable => |err| try writer.print(
                "the container runtime could not be run ({s})",
                .{@errorName(err)},
            ),
            .cache_not_written => |fault| try writer.print(
                "the image cache under {s} could not be written ({s}), so the next session " ++
                    "extracts this image again",
                .{ fault.name, @errorName(fault.err) },
            ),
            .entry_refused => |refused| try writer.print(
                "{d} entries of the image root filesystem were not extracted, the first is {s}. " ++
                    "A program that needs one of them fails inside the sandbox.",
                .{ refused.total, refused.entry },
            ),
            .mount_skipped => |skipped| try writer.print(
                "the image entry /{s} is not mounted, because {s}. A program that needs it " ++
                    "fails inside the sandbox.",
                .{ skipped.entry, skipped.why.text() },
            ),
        }
    }
};

/// The allocator travels with the slot.
pub const Sink = struct {
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

/// Null in, null out.
pub fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

/// For the variant that carries no string.
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

/// `tag` must carry a `ProgramFailed` (compile error otherwise).
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

pub fn noteEntry(
    out: ?Sink,
    entry: []const u8,
    total: usize,
) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    sink.slot.* = .{ .entry_refused = .{
        .entry = try sink.allocator.dupe(u8, entry),
        .total = total,
    } };
}

pub fn noteSkipped(
    out: ?Sink,
    entry: []const u8,
    why: Diagnostic.Why,
) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    sink.slot.* = .{ .mount_skipped = .{
        .entry = try sink.allocator.dupe(u8, entry),
        .why = why,
    } };
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    const sink = sinkOf(testing.allocator, &diag);
    try testing.expect(note(sink, .{ .runtime_not_runnable = error.FileNotFound }));
    try testing.expect(!note(sink, .{ .runtime_not_runnable = error.AccessDenied }));
    try testing.expectEqual(@as(anyerror, error.FileNotFound), diag.?.runtime_not_runnable);

    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .runtime_not_runnable = error.FileNotFound }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
    try noteRefusal(null, .container_export, "a trace");
    try noteNamed(null, .program_not_started, "docker", error.AccessDenied);
    try noteEntry(null, "/dev/tty", 1);
    try noteSkipped(null, "lib", .link_leaves_the_image);

    try noteRefusal(sink, .container_export, "a trace");
    try noteNamed(sink, .program_not_started, "docker", error.AccessDenied);
    try noteEntry(sink, "/dev/tty", 1);
    try noteSkipped(sink, "lib", .link_leaves_the_image);
}

test "every string a diagnostic carries outlives the allocator that produced it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    const arena = arena_state.allocator();

    var refusal: ?Diagnostic = null;
    var named: ?Diagnostic = null;
    var entry: ?Diagnostic = null;
    var skipped: ?Diagnostic = null;
    var cache: ?Diagnostic = null;
    defer {
        refusal.?.deinit(testing.allocator);
        named.?.deinit(testing.allocator);
        entry.?.deinit(testing.allocator);
        skipped.?.deinit(testing.allocator);
        cache.?.deinit(testing.allocator);
    }

    try noteRefusal(sinkOf(testing.allocator, &refusal), .container_create, try arena.dupe(u8, "no such image"));
    try noteNamed(sinkOf(testing.allocator, &named), .program_not_started, try arena.dupe(u8, "docker"), error.AccessDenied);
    try noteEntry(sinkOf(testing.allocator, &entry), try arena.dupe(u8, "/dev/tty"), 7);
    try noteSkipped(sinkOf(testing.allocator, &skipped), try arena.dupe(u8, "lib"), .link_leaves_the_image);
    try noteNamed(sinkOf(testing.allocator, &cache), .cache_not_written, try arena.dupe(u8, "/cache"), error.AccessDenied);

    arena_state.deinit();

    var buffer: [512]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        try std.fmt.bufPrint(&buffer, "{f}", .{&refusal.?}),
        "no such image",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        try std.fmt.bufPrint(&buffer, "{f}", .{&named.?}),
        "docker",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        try std.fmt.bufPrint(&buffer, "{f}", .{&entry.?}),
        "/dev/tty",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        try std.fmt.bufPrint(&buffer, "{f}", .{&skipped.?}),
        "lib",
    ) != null);
    try testing.expect(std.mem.indexOf(
        u8,
        try std.fmt.bufPrint(&buffer, "{f}", .{&cache.?}),
        "/cache",
    ) != null);
}

test "a refusal keeps the tail of what the runtime said, which is the part a user acts on" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);

    const long = try testing.allocator.alloc(u8, max_shown_bytes + 32);
    defer testing.allocator.free(long);
    @memset(long, 'x');
    @memcpy(long[long.len - 5 ..], "endin");

    try noteRefusal(sinkOf(testing.allocator, &diag), .container_export, long);
    try testing.expectEqual(max_shown_bytes, diag.?.command_refused.said.len);
    try testing.expect(std.mem.endsWith(u8, diag.?.command_refused.said, "endin"));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .program_not_started = .{ .name = "docker", .err = error.AccessDenied } },
        .{ .program_wait_failed = .{ .name = "docker", .err = error.AccessDenied } },
        .{ .command_refused = .{ .what = .container_export, .said = "no" } },
        .{ .runtime_not_runnable = error.FileNotFound },
        .{ .cache_not_written = .{ .name = "/cache", .err = error.AccessDenied } },
        .{ .entry_refused = .{ .entry = "/dev/null", .total = 1 } },
        .{ .mount_skipped = .{ .entry = "lib", .why = .link_leaves_the_image } },
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

test "no two reasons for a skipped mount read the same" {
    const all = [_]Diagnostic.Why{
        .not_a_file_or_directory,
        .link_unreadable,
        .link_names_nothing,
        .link_leaves_the_image,
        .link_points_at_nothing,
        .link_points_at_a_link,
    };
    for (all, 0..) |one, i| {
        try testing.expect(one.text().len > 0);
        for (all[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one.text(), other.text()));
    }
}

test "a refused entry names the first one and counts the rest" {
    const case = Diagnostic{ .entry_refused = .{ .entry = "/dev/tty", .total = 7 } };
    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&case});
    try testing.expect(std.mem.indexOf(u8, line, "7 entries") != null);
    try testing.expect(std.mem.indexOf(u8, line, "/dev/tty") != null);
}
