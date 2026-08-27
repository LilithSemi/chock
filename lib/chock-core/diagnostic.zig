//! Why a piece of the loop's own scaffolding could not be made or kept.
//!
//! **A library must not decide what a person sees.** Every fault below used
//! to print a line to the terminal and then return a coarse error, or in the
//! five thread pool cases return nothing at all, because there was no channel
//! and the print was the only record. That put a library in charge of what a
//! person reads, and it left `chockd` and every test with silence.
//!
//! **The diagnostic owns every string it carries, and one allocator holds
//! all of them.** No field is borrowed. A half owned diagnostic is a use
//! after free waiting for a caller, and this module had one: the three
//! variants that name a path took the slice a caller passed to `makeDirAll`,
//! and `makeLayout` builds that slice in a `[std.fs.max_path_bytes]u8` buffer
//! in its own frame. The frame ends with the call. The message is read after
//! it, by a printer whose own frames sit on the dead buffer, so the path a
//! person read was whatever those frames left behind.
//!
//! **`Sink` names the owner beside the slot.** A caller passes the allocator
//! that owns the message with the slot the message goes in, and it releases
//! the message with that same allocator. See `sinkOf` and `Diagnostic.deinit`.
//!
//! **The five thread pool faults carry no string, and they take a bare slot.**
//! They are noted at the one moment a diagnostic must not ask for memory: the
//! allocator has already refused, which is why the record was lost. `note`
//! takes a tag and not a value, so a variant that carries a path cannot reach
//! that allocation free path at all. It is a compile error.

const std = @import("std");

pub const Diagnostic = union(enum) {
    /// The session's scratchpad directory could not be made. The path is
    /// owned, and `deinit` releases it.
    scratchpad_directory_not_made: PathFailed,
    /// The session's cache directory could not be made. The path is owned.
    cache_directory_not_made: PathFailed,
    /// The compiler that resolves this project's declared packages could not
    /// be run at all, so the session starts with none of them. The path is
    /// the program, and it is owned. Distinct from a compiler that ran and
    /// refused, which is an `Answer.refused` that a person and the agent both
    /// read: see `chock-core/packages.zig`.
    packages_not_resolved: PathFailed,
    /// A subagent started and its thread could not be tracked. The child is
    /// already running and records its own completion, so the only thing
    /// lost is the join in `waitAll`.
    subagent_thread_not_tracked,
    /// A subagent finished and its record could not be kept. The child's own
    /// log is still on disk.
    subagent_record_not_kept,
    /// A subagent finished and its record could not be built. The log then
    /// holds a `session.spawn` with no `agent.complete` after it.
    subagent_record_not_built,
    /// A background task started and its thread could not be tracked.
    task_thread_not_tracked,
    /// A background task finished and its record could not be kept. The
    /// file itself is still on disk.
    task_record_not_kept,

    pub const PathFailed = struct {
        /// A directory, or a program. **Owned**, and released by `deinit`. A
        /// copy, because every caller of `notePath` builds this path in a
        /// stack buffer of its own frame.
        path: []const u8,
        err: anyerror,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again, which is the check a borrowed field used to escape.
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

/// Where a fault goes, and who owns what it points at.
pub const Sink = struct {
    /// Holds every string the diagnostic carries. The caller passes the same
    /// one to `Diagnostic.deinit`.
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

/// The sink for a caller outside this library: the slot it passed, owned by
/// the allocator it passed with it. Null in, null out, and a caller that
/// wants no diagnostic then pays no allocation at all.
///
/// **Give it an allocator that outlives the read.** The message is read after
/// the call that filled it returns, and often after the working memory of that
/// call is gone.
pub fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

/// Fill `out` with a fault that carries nothing.
///
/// **The first fault is kept, not the last.** A directory below the session's
/// own can only be made after that one was, so the first fault is the one
/// that explains the rest.
///
/// **A tag and not a value, and no allocator.** The five faults this takes are
/// noted when an allocator has already refused, which is the one moment a
/// diagnostic must not ask for memory. A tag that carries a path is a compile
/// error here, so no borrowed string can reach this path.
pub fn note(out: ?*?Diagnostic, comptime tag: std.meta.Tag(Diagnostic)) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = @unionInit(Diagnostic, @tagName(tag), {});
}

/// Fill `out` with a fault that names a path, keeping a copy of the path.
///
/// **A copy and not the caller's own slice.** Every caller builds the path in
/// a `[std.fs.max_path_bytes]u8` buffer in its own frame, and that frame is
/// gone before a person reads the message.
///
/// **A copy that fails leaves the slot empty**, and this says nothing. The
/// caller still gets its own error, which is the answer it acts on. Asking a
/// refused allocator again, or failing a call because a message could not be
/// built, would both make a bad moment worse.
///
/// `tag` must be a variant that carries a `PathFailed`. Any other one is a
/// compile error, which is what keeps this one helper honest.
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

    // A caller that asked for no diagnostic must reach no store at all rather
    // than write into a scratch value, and it must allocate nothing. The
    // testing allocator fails this test if it does.
    try testing.expect(sinkOf(testing.allocator, null) == null);
    notePath(null, .cache_directory_not_made, "/c", error.IsDir);
    note(null, .subagent_record_not_kept);
}

test "a path in a message outlives the frame the caller built it in" {
    // The debug allocator underneath is what makes this a test and not a
    // hope. A diagnostic that pointed into the frame reads bytes the frame no
    // longer owns, and `dirtyTheFrame` is what puts known bytes there.
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

/// The shape of `cache.makeLayout` and `scratchpad.makeLayout`: a path built
/// in a buffer of this frame, handed to a sink, and the frame ends.
fn fillFromAFrameThatEnds(sink: ?Sink) void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ "/deep/enough/to/matter", "home" }) catch return;
    notePath(sink, .cache_directory_not_made, path, error.NotDir);
}

/// Write known bytes over the frame the call above used. A printer does this
/// by accident, which is why the old shape printed a row of whatever byte the
/// last call left.
fn dirtyTheFrame() u64 {
    var scratch: [2 * std.fs.max_path_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}

test "a message is released by the allocator that filled it, and by nothing else" {
    // The ownership half, and the half a dangling read does not catch: a
    // freed page often still holds readable text, and an invalid free never
    // passes. Every variant goes through `deinit` here, so a variant added
    // later that borrows a string fails this test rather than a user's run.
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
    // The five thread pool faults are the pair this pins hardest: each names
    // a different thing that was lost, and a reader has to be able to tell a
    // record that was never built from one that was built and not kept.
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
