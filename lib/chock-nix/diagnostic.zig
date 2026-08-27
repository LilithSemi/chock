//! Why a `nix` call, or the shell that sources a dev environment, did not
//! give an answer.
//!
//! **Three variants are notices and not faults.** A toolchain that could not
//! be rooted, a cache that could not be written, and store paths left out of
//! the mount set all leave a session that runs. See `toolchain_not_rooted`,
//! `cache_not_written`, and `store_paths_dropped`.
//!
//! **The diagnostic owns every string it carries, and one allocator holds
//! all of them.** No field is borrowed. A half owned diagnostic is a use
//! after free waiting for a caller: `DevShell.load` builds its answer in an
//! arena and destroys that arena the moment it fails, so a message that
//! pointed into the arena read freed memory in the very next line of the
//! caller. `what` carries no string at all. It is a `What`, an enumeration,
//! so the one field that used to be a literal now has no lifetime to get
//! wrong.
//!
//! **`Sink` names the owner beside the slot.** A caller outside this library
//! passes `?*?Diagnostic`, and the allocator of that same call owns the
//! message. Inside, every function takes a `Sink`, because `DevShell.load`
//! holds two allocators: an arena for the answer, which does not live long
//! enough, and the caller's own, which does. See `sinkOf`.

const std = @import("std");

/// How much of a `nix` error stream a message keeps. **The tail and not the
/// head**: `nix` puts the line a user can act on at the end of a trace.
pub const max_shown_bytes: usize = 4096;

pub const Diagnostic = union(enum) {
    /// A program could not be started. The name is owned.
    program_not_started: ProgramFailed,
    /// Waiting for a program failed. The name is owned.
    program_wait_failed: ProgramFailed,
    /// A `nix` call, or the shell that sources the dev environment, exited
    /// nonzero. `said` is a copy of the tail of its error stream.
    command_refused: CommandRefused,
    /// `nix` could not be run at all while a package was provisioned.
    nix_not_runnable: anyerror,
    /// **A notice, not a fault.** The dev shell's toolchain could not be held
    /// against the garbage collector. The session still works, and only a
    /// `nix-collect-garbage` during it would find this out.
    toolchain_not_rooted: anyerror,
    /// **A notice, not a fault.** The dev shell cache could not be written,
    /// so the next session evaluates this flake again. The directory name is
    /// owned.
    cache_not_written: ProgramFailed,
    /// **A notice, not a fault.** Some of the store paths the dev shell names
    /// could not be asked about, so they are not mounted. The session still
    /// runs, and a tool call that wanted one of them fails.
    store_paths_dropped: PathsDropped,

    /// Which command refused. **An enumeration and not a string**, so this
    /// field has no lifetime and cannot dangle. Every command this library
    /// runs is one of these four, and a reader of the message wants the name
    /// a user could type again by hand.
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
        /// A program name, or a directory. **Owned**, and released by
        /// `deinit`. A copy, because the argument vector it comes from can be
        /// released before the message is read.
        name: []const u8,
        err: anyerror,
    };

    pub const CommandRefused = struct {
        what: What,
        /// The tail of what the command wrote. **Owned**, and released by
        /// `deinit`.
        said: []const u8,
    };

    pub const PathsDropped = struct {
        count: usize,
        /// The tail of what `nix path-info` said about the first one.
        /// **Owned**, and released by `deinit`.
        said: []const u8,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again, which is the check that a borrowed field used to escape.
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

/// Where a fault goes, and who owns what it points at.
///
/// **The allocator travels with the slot.** A site that fills a diagnostic
/// and a site that reads one are far apart, and the working allocator of the
/// filling site can be an arena that is gone by then. Carrying the owner
/// beside the slot is what makes the message outlive the call.
pub const Sink = struct {
    /// Holds every string the diagnostic carries. The caller passes the same
    /// one to `Diagnostic.deinit`.
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

/// The sink for a caller outside this library: the slot it passed, owned by
/// the allocator it passed with it. Null in, null out, and a caller that
/// wants no diagnostic then pays no allocation at all.
pub fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A closure can only be read
/// after the dev environment was, so a later fault overwriting an earlier one
/// would replace the fault that explains the run with the fault it caused.
///
/// For the variants that carry no string. The three that carry one go
/// through `noteRefusal` or `noteNamed`, which copy it.
pub fn note(out: ?Sink, value: Diagnostic) bool {
    const sink = out orelse return false;
    if (sink.slot.* != null) return false;
    sink.slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy an error stream for it. A caller that passes null
/// must pay no allocation at all.
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

/// Note store paths that are not in the mount set, keeping the tail of what
/// Nix said about the first of them.
pub fn noteDropped(out: ?Sink, count: usize, said: []const u8) std.mem.Allocator.Error!void {
    const sink = out orelse return;
    if (sink.slot.* != null) return;
    const tail = if (said.len > max_shown_bytes) said[said.len - max_shown_bytes ..] else said;
    sink.slot.* = .{ .store_paths_dropped = .{
        .count = count,
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

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    const sink = sinkOf(testing.allocator, &diag);
    try testing.expect(note(sink, .{ .nix_not_runnable = error.FileNotFound }));
    try testing.expect(!note(sink, .{ .toolchain_not_rooted = error.AccessDenied }));
    try testing.expectEqual(@as(anyerror, error.FileNotFound), diag.?.nix_not_runnable);

    // A caller that asked for no diagnostic must reach no store at all, and
    // it must allocate nothing. The testing allocator fails this test if it
    // does.
    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .nix_not_runnable = error.FileNotFound }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
    try noteRefusal(null, .nix_path_info, "a trace");
    try noteNamed(null, .program_not_started, "nix", error.AccessDenied);

    // And a slot that is already full takes no copy either, so nothing here
    // leaks past the one fault above.
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
    // The whole point of `Sink`. This is the shape of `DevShell.load`: a
    // working arena for the answer, and the caller's own allocator for the
    // message. The arena is destroyed the way `load` destroys it when it
    // fails, and only then is the message read.
    //
    // The debug allocator underneath is what makes this a test and not a
    // hope. A diagnostic that pointed into the arena reads memory the arena
    // has released, and this allocator poisons that memory rather than
    // leaving it readable by luck.
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        // What a refused command wrote, in the arena, the way `proc.run`
        // leaves it. The name of the program is in the arena too, the way
        // `proc.resolve` leaves it.
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
    // The enumeration replaced four literals. A member added later with no
    // text, or with the text of another, would make two different refusals
    // read the same.
    var seen: [std.meta.fields(Diagnostic.What).len][]const u8 = undefined;
    inline for (std.meta.fields(Diagnostic.What), 0..) |field, i| {
        const text = (@field(Diagnostic.What, field.name)).text();
        try testing.expect(text.len > 0);
        for (seen[0..i]) |other| try testing.expect(!std.mem.eql(u8, text, other));
        seen[i] = text;
    }
}
