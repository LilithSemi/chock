//! Why a workspace call failed, past what its error set can say.
//!
//! **A library must not decide what a person sees.** Before this type, every
//! site below printed a line to the terminal and then returned
//! `error.Unexpected`, so the print *was* the error detail: it named the call
//! and the fault, and the error named neither. That put a library in charge
//! of what a person reads, and it left a caller that is not a terminal, such
//! as `chockd` or a test, with nothing at all.
//!
//! **This owns no memory and allocates nothing.** It holds enumerations and
//! fixed arrays, the same shape `lib/chock-sandbox/linux/namespace.zig` chose,
//! which is the prototype this follows. A reader turns it into words with
//! `format`, at the caller, which is where the decision belongs.
//!
//! **One type for the whole module, and not one per file.** A worktree, an
//! overlay, and a `git` call are three ways of making the one directory the
//! sandbox mounts, and a caller of `Workspace.open` cannot say in advance
//! which of the three will answer. A caller holds one slot and reads one
//! answer.
//!
//! ## The `chock.zon` variants, and why the message is a fixed array
//!
//! `deny.zig` reads the project's own `chock.zon` before either backing is
//! built, so a fault in that file is a fault of `Workspace.open`. To name the
//! line, this type must carry what the ZON reader said, and a string is a
//! thing that can be released before a person reads it. **Four dangling
//! diagnostics have shipped in this project**, so `Said` holds the bytes in
//! the value itself. It owns no memory, it needs no allocator, and it cannot
//! point at a frame that ended. The cost is a bound on the message length,
//! which `Said.truncated` states rather than hides.

const std = @import("std");

/// Why a workspace call failed.
///
/// **A union and not a struct, because two of the faults are not a call.** A
/// `chock.zon` that does not parse is not "opening the upper layer failed",
/// and reading it under that template gave a person a call name and an error
/// name that both said nothing. See `Said`.
pub const Diagnostic = union(enum) {
    /// A call this module made to a filesystem, or to `git`, answered with a
    /// fault. This is every variant of `Call`.
    call_failed: CallFailed,
    /// The project's own `chock.zon` is not valid ZON, or its top level is
    /// not a struct literal.
    ///
    /// **The fault can be anywhere in that file, and this variant claims no
    /// more than that.** One `chock.zon` holds the policy table, the budget,
    /// the subagent limits, the denied paths and the plugin list, and a
    /// reader that must parse the whole file to find its own block sees every
    /// other block's faults too. Naming a block here would send a person to
    /// look at something they did not write. `Said` names the line instead.
    chock_zon_not_valid: Said,
    /// `chock.zon` parses, and its `deny_read` block is not a list of
    /// strings. **This one does name the block, and it is true**: it is only
    /// reached after the file parsed and a `deny_read` field was found in it.
    deny_block_not_valid: Said,
    /// `chock.zon` is larger than `deny.max_file_bytes`, which is the number
    /// this carries. A file nobody will read is not a file that denied
    /// nothing.
    chock_zon_too_large: usize,

    /// What was being done, and what it answered.
    pub const CallFailed = struct {
        call: Call,
        fault: Fault,
    };

    /// The fault a call gave. Two kinds, because this module reaches a
    /// filesystem two ways: through `std.Io`, which answers with a Zig
    /// error, and through a raw system call such as `statx` or `clonefile`,
    /// which answers with an errno.
    pub const Fault = union(enum) {
        err: anyerror,
        errno: std.posix.E,

        pub fn text(self: Fault) []const u8 {
            return switch (self) {
                .err => |e| @errorName(e),
                .errno => |e| @tagName(e),
            };
        }
    };

    /// What a ZON reader said about `chock.zon`, with the line and the
    /// column, copied into this value.
    ///
    /// **An array and not a slice.** See this file's own top comment: a slice
    /// here would point at the syntax tree that the reader frees on its way
    /// out, or at a buffer in a frame that has ended. This cannot.
    pub const Said = struct {
        bytes: [max_bytes]u8 = undefined,
        len: u16 = 0,
        /// Whether the reader said more than `max_bytes` and the rest was
        /// dropped. The first fault is always kept, because it is written
        /// first and it is the one a person acts on.
        truncated: bool = false,

        /// The longest message this holds. Long enough for a first error and
        /// its note, which is what Zig's own ZON reader writes.
        pub const max_bytes = 256;

        pub fn text(self: *const Said) []const u8 {
            return self.bytes[0..self.len];
        }

        /// What `zon_diag` says, up to `max_bytes` of it.
        ///
        /// **The trees stay the caller's.** This only reads `zon_diag`, so a
        /// caller that frees the `Ast` and the `Zoir` itself must not also
        /// call `std.zon.parse.Diagnostics.deinit`, and a caller that does
        /// call it must not free them twice.
        pub fn of(zon_diag: *const std.zon.parse.Diagnostics) Said {
            var said: Said = .{};
            var writer = std.Io.Writer.fixed(&said.bytes);
            // A message longer than the buffer leaves what fits, because
            // `fixedDrain` copies up to the end before it refuses. The first
            // line is written first, so the line number survives.
            writer.print("{f}", .{zon_diag}) catch {
                said.truncated = true;
            };
            said.len = @intCast(writer.end);
            said.trimTrailingNewlines();
            return said;
        }

        /// What `words` says, for a fault the ZON reader has no error for.
        pub fn ofText(words: []const u8) Said {
            var said: Said = .{ .truncated = words.len > max_bytes };
            const kept = @min(words.len, max_bytes);
            @memcpy(said.bytes[0..kept], words[0..kept]);
            said.len = @intCast(kept);
            return said;
        }

        /// Drop the trailing newlines Zig's own ZON format writes, so a
        /// caller decides where the message ends.
        fn trimTrailingNewlines(self: *Said) void {
            while (self.len > 0 and self.bytes[self.len - 1] == '\n') self.len -= 1;
        }
    };

    /// What was being done. Named for the work and not for the call alone,
    /// because `open` says much less than "opening the upper layer".
    pub const Call = enum {
        // git
        git_spawn,
        git_wait,
        // the worktree builder
        scratch_object_store_create,
        config_worktree_check,
        worktree_git_file_read,
        git_pointer_file_create,
        git_pointer_file_write,
        empty_scratch_file_create,
        scratch_file_delete,
        worktree_meta_copy,
        worktree_meta_commondir_write,
        // the project's own chock.zon
        chock_zon_check,
        chock_zon_read,
        // the overlay scratch layout, both drivers
        overlay_scratch_mkdir,
        // the Linux driver
        upper_layer_open,
        upper_layer_walk,
        upper_entry_kind,
        upper_directory_enter,
        upper_entry_stat,
        project_open,
        project_walk,
        project_directory_enter,
        project_entry_check,
        whiteout_stat,
        opaque_directory_getxattr,
        // the Darwin driver
        project_clone,
        clone_read,
        project_read,
        clone_link_read,
        project_link_read,
        clone_file_open,
        project_file_open,
        compared_file_read,
        entry_metadata_read,
        entry_device_read,
        directory_open,

        /// What was being done, as a phrase that reads after "chock: ".
        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .git_spawn => "starting git",
                .git_wait => "waiting for git",
                .scratch_object_store_create => "creating the scratch object store",
                .config_worktree_check => "checking for config.worktree",
                .worktree_git_file_read => "reading the worktree's own .git file",
                .git_pointer_file_create => "creating the replacement .git file",
                .git_pointer_file_write => "writing the replacement .git file",
                .empty_scratch_file_create => "creating the empty config.worktree scratch file",
                .scratch_file_delete => "deleting a scratch file",
                .worktree_meta_copy => "copying the worktree's own metadata directory",
                .worktree_meta_commondir_write => "writing the copied metadata directory's commondir",
                .chock_zon_check => "checking for chock.zon",
                .chock_zon_read => "reading the project's own chock.zon",
                .overlay_scratch_mkdir => "making an overlay scratch directory",
                .upper_layer_open => "opening the upper layer",
                .upper_layer_walk => "walking the upper layer",
                .upper_entry_kind => "resolving an upper layer entry's kind",
                .upper_directory_enter => "entering an upper layer directory",
                .upper_entry_stat => "statx on an upper layer entry",
                .project_open => "opening the project",
                .project_walk => "walking the project",
                .project_directory_enter => "entering a project directory",
                .project_entry_check => "checking the project",
                .whiteout_stat => "statx on a whiteout candidate",
                .opaque_directory_getxattr => "getxattr on an opaque directory candidate",
                .project_clone => "cloning the project",
                .clone_read => "reading the clone",
                .project_read => "reading the project",
                .clone_link_read => "reading a link in the clone",
                .project_link_read => "reading a link in the project",
                .clone_file_open => "opening a file in the clone",
                .project_file_open => "opening a file in the project",
                .compared_file_read => "reading a file to compare it",
                .entry_metadata_read => "reading an entry's metadata",
                .entry_device_read => "reading a path's filesystem number",
                .directory_open => "opening a directory",
            };
        }
    };

    /// **A pointer and not a value**, so the `Said` a message reads from is
    /// the one the caller holds and not a copy this call leaves behind. A
    /// caller writes `{f}` with `&fault`.
    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .call_failed => |failed| try writer.print(
                "{s} failed: {s}",
                .{ failed.call.text(), failed.fault.text() },
            ),
            // **The file, and no block.** See the variant's own comment.
            .chock_zon_not_valid => |*said| try writer.print(
                "{s} is not valid:\n{s}",
                .{ chock_zon_name, said.text() },
            ),
            .deny_block_not_valid => |*said| try writer.print(
                "{s}: the deny_read block is not valid:\n{s}",
                .{ chock_zon_name, said.text() },
            ),
            .chock_zon_too_large => |bytes| try writer.print(
                "{s} is larger than the {d} bytes this reader accepts",
                .{ chock_zon_name, bytes },
            ),
        }
    }
};

/// The name of the file the three `chock.zon` variants above are about. A
/// literal here rather than an import of `deny.zig`, which imports this.
const chock_zon_name = "chock.zon";

/// Fill `diag` when the caller asked for one.
///
/// **The first fault is kept, not the last.** A later call can only fail
/// because an earlier one did: an overlay cannot be walked if its scratch
/// directory was never made. So the first is the one that explains the rest.
pub fn note(diag: ?*?Diagnostic, value: Diagnostic) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

/// `note`, for the common case of a `std.Io` call that answered with a Zig
/// error. Saves every site the `.{ .err = e }` wrapper.
pub fn noteErr(diag: ?*?Diagnostic, call: Diagnostic.Call, err: anyerror) void {
    note(diag, .{ .call_failed = .{ .call = call, .fault = .{ .err = err } } });
}

/// `note`, for a raw system call that answered with an errno.
pub fn noteErrno(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: std.posix.E) void {
    note(diag, .{ .call_failed = .{ .call = call, .fault = .{ .errno = errno } } });
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    // **The first, not the last.** A walk of the upper layer can only fail
    // after the layer opened, so a later fault overwriting an earlier one
    // would replace the fault that explains the run with the fault it caused.
    var diag: ?Diagnostic = null;
    noteErr(&diag, .upper_layer_open, error.AccessDenied);
    noteErr(&diag, .upper_layer_walk, error.FileNotFound);
    try testing.expectEqual(Diagnostic.Call.upper_layer_open, diag.?.call_failed.call);
    try testing.expectEqual(@as(anyerror, error.AccessDenied), diag.?.call_failed.fault.err);

    // A caller that asked for no diagnostic is the ordinary case, and it must
    // reach no store at all rather than write into a scratch value.
    noteErr(null, .upper_layer_walk, error.FileNotFound);
    noteErrno(null, .whiteout_stat, .PERM);
}

test "a diagnostic names the call and the fault, and allocates nothing" {
    // The two facts `error.Unexpected` throws away. Rendering happens at a
    // caller with a buffer, the same way the sandbox's own prototype does it.
    var buffer: [512]u8 = undefined;
    const opening: Diagnostic = .{ .call_failed = .{
        .call = .upper_layer_open,
        .fault = .{ .err = error.AccessDenied },
    } };
    try testing.expectEqualStrings(
        "opening the upper layer failed: AccessDenied",
        try std.fmt.bufPrint(&buffer, "{f}", .{&opening}),
    );
    // A raw system call answers with an errno, and it reads by its own name.
    const whiteout: Diagnostic = .{ .call_failed = .{
        .call = .whiteout_stat,
        .fault = .{ .errno = .NOENT },
    } };
    try testing.expectEqualStrings(
        "statx on a whiteout candidate failed: NOENT",
        try std.fmt.bufPrint(&buffer, "{f}", .{&whiteout}),
    );
}

test "a chock.zon fault names the file and never a block the person did not write" {
    // **The whole point of the two variants.** `deny.zig` must parse the whole
    // file to find its own block, so it sees a fault in the policy block, in
    // the budget block, or in no block at all. Naming `deny_read` for any of
    // those sends a person to look at something that is not in their file.
    var buffer: [512]u8 = undefined;
    const whole_file: Diagnostic = .{
        .chock_zon_not_valid = Diagnostic.Said.ofText("4:9: error: expected field initializer"),
    };
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n4:9: error: expected field initializer",
        try std.fmt.bufPrint(&buffer, "{f}", .{&whole_file}),
    );

    // And the one case in which the block may be named, because the file
    // parsed and a `deny_read` field was found in it.
    const block: Diagnostic = .{
        .deny_block_not_valid = Diagnostic.Said.ofText("1:20: error: expected type '[]const u8'"),
    };
    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n1:20: error: expected type '[]const u8'",
        try std.fmt.bufPrint(&buffer, "{f}", .{&block}),
    );
}

test "a message survives the frame the reader built it in" {
    // **The class of bug this shape rules out.** Four diagnostics in this
    // project have shipped pointing at freed or dead stack memory. `Said`
    // holds an array, so a message filled in a frame that ends is still
    // readable after that frame is written over.
    var diag: ?Diagnostic = null;
    fillFromAFrameThatEnds(&diag);
    std.mem.doNotOptimizeAway(dirtyTheFrame());

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n2:36: error: expected field initializer",
        line,
    );
}

/// A reader that builds its message in its own frame and returns.
fn fillFromAFrameThatEnds(diag: *?Diagnostic) void {
    var scratch: [Diagnostic.Said.max_bytes]u8 = undefined;
    const words = std.fmt.bufPrint(
        &scratch,
        "{d}:{d}: error: expected field initializer",
        .{ 2, 36 },
    ) catch return;
    note(diag, .{ .chock_zon_not_valid = Diagnostic.Said.ofText(words) });
}

/// Write known bytes over the frame the call above used.
fn dirtyTheFrame() u64 {
    var scratch: [4 * Diagnostic.Said.max_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}

test "a message longer than the buffer keeps its first line and says it was cut" {
    // The bound `Said` trades for owning no memory, stated rather than
    // hidden. The line number is written first, so it is the part that
    // survives.
    var long: [Diagnostic.Said.max_bytes * 2]u8 = undefined;
    @memset(&long, 'x');
    @memcpy(long[0..4], "1:1:");
    const said: Diagnostic.Said = .ofText(&long);
    try testing.expect(said.truncated);
    try testing.expectEqual(@as(usize, Diagnostic.Said.max_bytes), said.text().len);
    try testing.expectEqualStrings("1:1:", said.text()[0..4]);

    // And a message that fits says nothing was cut.
    const short: Diagnostic.Said = .ofText("1:1: error: no");
    try testing.expect(!short.truncated);
    try testing.expectEqualStrings("1:1: error: no", short.text());
}

test "no two calls of this module read the same" {
    // **The fact worth pinning.** A reader has to be able to tell which call
    // failed, and this module has a driver on each platform doing similar
    // work over two different trees, so "reading the clone" and "reading the
    // project" are exactly the pair that would collapse into one phrase.
    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}
