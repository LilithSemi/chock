//! Why a container runtime call, or the extraction that follows it, did not
//! give an answer.
//!
//! **The diagnostic owns every string it carries, and one allocator holds all
//! of them.** No field is borrowed. A half owned diagnostic is a use after
//! free waiting for a caller: `Image.load` builds its answer in a private
//! arena and destroys that arena the moment it fails, so a message that
//! pointed into the arena read freed memory in the very next line of the
//! caller, and no caller could name the allocator to release it with either.
//! The same fault was found and fixed in `chock-nix/diagnostic.zig` first,
//! where it segfaulted `chock doctor` on a flake that does not evaluate.

const std = @import("std");

/// How much of a runtime's error stream a message keeps. **The tail and not
/// the head**: a daemon puts the line a user can act on at the end.
pub const max_shown_bytes: usize = 4096;

pub const Diagnostic = union(enum) {
    /// A program could not be started. The name is owned.
    program_not_started: ProgramFailed,
    /// Waiting for a program failed. The name is owned.
    program_wait_failed: ProgramFailed,
    /// A runtime command exited nonzero. `said` is a copy of the tail of its
    /// error stream.
    command_refused: CommandRefused,
    /// The runtime could not be run at all.
    runtime_not_runnable: anyerror,
    /// **A notice, not a fault.** The extracted image could not be written
    /// down, so the next session extracts this image again. The directory name
    /// is owned.
    cache_not_written: ProgramFailed,
    /// **A notice, not a fault.** One entry of the image's root filesystem was
    /// refused during extraction, and the rest of the tree was written. A
    /// device node and a hard link out of the tree both land here. The name is
    /// owned.
    entry_refused: EntryRefused,
    /// **A notice, not a fault.** One top level entry of the extracted tree
    /// was left out of the mount set. A symbolic link that points out of the
    /// tree is the case this exists for, and leaving it out is the safe
    /// answer. The name is owned and the reason carries no string at all.
    mount_skipped: MountSkipped,

    /// Which command refused. **An enumeration and not a string**, so this
    /// field has no lifetime and cannot dangle. A reader of the message wants
    /// the name of a command they could type again by hand.
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

    /// Why one top level entry of an image tree is not mounted. **An
    /// enumeration for the same reason `What` is.**
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
        /// A program name, or a directory. **Owned**, and released by
        /// `deinit`. A copy, because the argument vector it comes from, or the
        /// arena that holds a directory name, can go before the message is
        /// read.
        name: []const u8,
        err: anyerror,
    };

    pub const CommandRefused = struct {
        what: What,
        /// The tail of what the command wrote. **Owned.**
        said: []const u8,
    };

    pub const MountSkipped = struct {
        /// The top level name, such as `lib`. **Owned.**
        entry: []const u8,
        why: Why,
    };

    pub const EntryRefused = struct {
        /// The path inside the image that was not written. **Owned.**
        entry: []const u8,
        /// How many entries were refused in total, including this one. Only
        /// the first is named, and the count says whether there were more.
        total: usize,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again, which is the check a borrowed field used to escape.
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

/// Where a fault goes, and who owns what it points at.
///
/// **The allocator travels with the slot.** A site that fills a diagnostic and
/// a site that reads one are far apart, and the working allocator of the
/// filling site can be an arena that is gone by then. Carrying the owner
/// beside the slot is what makes the message outlive the call.
pub const Sink = struct {
    /// Holds every string the diagnostic carries. The caller passes the same
    /// one to `Diagnostic.deinit`.
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

/// The sink for a caller outside this library: the slot it passed, owned by
/// the allocator it passed with it. Null in, null out, and a caller that wants
/// no diagnostic then pays no allocation at all.
pub fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** An extraction can only run after
/// an inspection did, so a later fault overwriting an earlier one would replace
/// the fault that explains the run with the fault it caused.
///
/// For the variant that carries no string. Every other one goes through
/// `noteRefusal`, `noteNamed`, `noteEntry` or `noteSkipped`, which copy it.
pub fn note(out: ?Sink, value: Diagnostic) bool {
    const sink = out orelse return false;
    if (sink.slot.* != null) return false;
    sink.slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should do work for it. A caller that passes null must pay no
/// allocation at all.
pub fn wants(out: ?Sink) bool {
    const sink = out orelse return false;
    return sink.slot.* == null;
}

/// Note a command that ran and refused, keeping the tail of what it said.
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

/// Note a fault that names a program or a directory, keeping a copy of the
/// name. **A copy and not the caller's own slice**: the argument vector, or
/// the arena the name came from, can be released long before a person reads
/// the message.
///
/// `tag` must be a variant that carries a `ProgramFailed`. Any other one is a
/// compile error, which is what keeps this one helper honest.
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

/// Note that entries of the image tree were refused during extraction, keeping
/// a copy of the first name.
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

/// Note that one top level entry of the image tree is not mounted, keeping a
/// copy of its name.
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

    // A caller that asked for no diagnostic must reach no store at all, and it
    // must allocate nothing. The testing allocator fails this test if it does.
    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .runtime_not_runnable = error.FileNotFound }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
    try noteRefusal(null, .container_export, "a trace");
    try noteNamed(null, .program_not_started, "docker", error.AccessDenied);
    try noteEntry(null, "/dev/tty", 1);
    try noteSkipped(null, "lib", .link_leaves_the_image);

    // And a slot that is already full takes no copy either, so nothing here
    // leaks past the one fault above.
    try noteRefusal(sink, .container_export, "a trace");
    try noteNamed(sink, .program_not_started, "docker", error.AccessDenied);
    try noteEntry(sink, "/dev/tty", 1);
    try noteSkipped(sink, "lib", .link_leaves_the_image);
}

test "every string a diagnostic carries outlives the allocator that produced it" {
    // The bug this file was rewritten for. `Image.load` fills a diagnostic
    // from a private arena and destroys that arena on the way out, so a
    // message that borrowed from it read freed memory. An arena that is gone
    // stands in for that here: every variant that carries a string is filled
    // through a sink owned by the testing allocator, from bytes owned by an
    // arena, and then read after the arena is destroyed.
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
    // Each one names a different thing a person would fix, so a message that
    // repeated another would send them to the wrong place.
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
    // The count is the part a person acts on. One refused entry in a base
    // image is ordinary. Two hundred means the extraction did not work, and a
    // message that named only the first would read the same in both cases.
    const case = Diagnostic{ .entry_refused = .{ .entry = "/dev/tty", .total = 7 } };
    var buffer: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&case});
    try testing.expect(std.mem.indexOf(u8, line, "7 entries") != null);
    try testing.expect(std.mem.indexOf(u8, line, "/dev/tty") != null);
}
