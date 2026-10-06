//! Why a piece of the loop's own scaffolding could not be made or kept.
//! One type carries the reason so a caller decides what a person sees.

const std = @import("std");

pub const Diagnostic = union(enum) {
    scratchpad_directory_not_made: PathFailed,
    cache_directory_not_made: PathFailed,
    packages_not_resolved: PathFailed,
    subagent_thread_not_tracked,
    subagent_record_not_kept,
    subagent_record_not_built,
    task_thread_not_tracked,
    task_record_not_kept,

    pub const PathFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub fn deinit(self: *Diagnostic, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .scratchpad_directory_not_made,
            .cache_directory_not_made,
            .packages_not_resolved,
            => |fault| allocator.free(fault.path),
            .subagent_thread_not_tracked,
            .subagent_record_not_kept,
            .subagent_record_not_built,
            .task_thread_not_tracked,
            .task_record_not_kept,
            => {},
        }
        self.* = undefined;
    }

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .scratchpad_directory_not_made => |fault| try writer.print(
                "making the scratchpad directory {s} failed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .cache_directory_not_made => |fault| try writer.print(
                "making the cache directory {s} failed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .packages_not_resolved => |fault| try writer.print(
                "running {s} to resolve this project's declared packages failed: {s}",
                .{ fault.path, @errorName(fault.err) },
            ),
            .subagent_thread_not_tracked => try writer.writeAll(
                "a subagent started and its thread could not be tracked",
            ),
            .subagent_record_not_kept => try writer.writeAll(
                "a subagent finished and its record could not be kept",
            ),
            .subagent_record_not_built => try writer.writeAll(
                "a subagent finished and its record could not be built",
            ),
            .task_thread_not_tracked => try writer.writeAll(
                "a background task started and its thread could not be tracked",
            ),
            .task_record_not_kept => try writer.writeAll(
                "a background task finished and its record could not be kept",
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

pub fn note(out: ?*?Diagnostic, comptime tag: std.meta.Tag(Diagnostic)) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = @unionInit(Diagnostic, @tagName(tag), {});
}

pub fn notePath(
    out: ?Sink,
    comptime tag: std.meta.Tag(Diagnostic),
    path: []const u8,
    err: anyerror,
) void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    const copy = sink.allocator.dupe(u8, path) catch return;
    sink.slot.* = @unionInit(Diagnostic, @tagName(tag), .{ .path = copy, .err = err });
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(testing.allocator);

    const sink = sinkOf(testing.allocator, &diag);
    notePath(sink, .scratchpad_directory_not_made, "/a", error.AccessDenied);
    notePath(sink, .cache_directory_not_made, "/b", error.IsDir);
    try testing.expectEqualStrings("/a", diag.?.scratchpad_directory_not_made.path);

    try testing.expect(sinkOf(testing.allocator, null) == null);
    notePath(null, .cache_directory_not_made, "/c", error.IsDir);
    note(null, .subagent_record_not_kept);
}

test "a path in a message outlives the frame the caller built it in" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*fault| fault.deinit(gpa);

    fillFromAFrameThatEnds(sinkOf(gpa, &diag));
    std.mem.doNotOptimizeAway(dirtyTheFrame());

    var buffer: [std.fs.max_path_bytes + 256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "/deep/enough/to/matter/home") != null);
}

fn fillFromAFrameThatEnds(sink: ?Sink) void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ "/deep/enough/to/matter", "home" }) catch return;
    notePath(sink, .cache_directory_not_made, path, error.NotDir);
}

fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}

test "a message is released by the allocator that filled it, and by nothing else" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    inline for (@typeInfo(Diagnostic).@"union".fields) |field| {
        var diag: ?Diagnostic = null;
        if (field.type == Diagnostic.PathFailed) {
            notePath(sinkOf(gpa, &diag), @field(std.meta.Tag(Diagnostic), field.name), "/a/path", error.AccessDenied);
        } else {
            note(&diag, @field(std.meta.Tag(Diagnostic), field.name));
        }
        try testing.expect(diag != null);
        diag.?.deinit(gpa);
    }
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .scratchpad_directory_not_made = .{ .path = "/a", .err = error.AccessDenied } },
        .{ .cache_directory_not_made = .{ .path = "/a", .err = error.AccessDenied } },
        .{ .packages_not_resolved = .{ .path = "/a", .err = error.AccessDenied } },
        .subagent_thread_not_tracked,
        .subagent_record_not_kept,
        .subagent_record_not_built,
        .task_thread_not_tracked,
        .task_record_not_kept,
    };
    var buffers: [cases.len][256]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
