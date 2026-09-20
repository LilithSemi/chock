//! Why a workspace call failed, past what its error set can say. One type for
//! the whole module, because a caller of `Workspace.open` cannot say in advance
//! which of the three backings will answer.

const std = @import("std");

pub const Diagnostic = union(enum) {
    call_failed: CallFailed,
    chock_zon_not_valid: Said,
    deny_block_not_valid: Said,
    chock_zon_too_large: usize,

    pub const CallFailed = struct {
        call: Call,
        fault: Fault,
    };

    /// Two kinds, because this module reaches a filesystem through `std.Io`
    /// and reaches some calls raw.
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

    /// Four dangling diagnostics have shipped in this project, so this holds
    /// the bytes in the value itself and cannot point at a frame that ended.
    /// The cost is a bound on the message length, stated by `truncated`.
    pub const Said = struct {
        bytes: [max_bytes]u8 = undefined,
        len: u16 = 0,
        /// Whether the reader said more than `max_bytes` and the rest was cut.
        truncated: bool = false,

        pub const max_bytes = 256;

        pub fn text(self: *const Said) []const u8 {
            return self.bytes[0..self.len];
        }

        pub fn of(zon_diag: *const std.zon.parse.Diagnostics) Said {
            var said: Said = .{};
            var writer = std.Io.Writer.fixed(&said.bytes);
            // A message longer than the buffer leaves what fits, because a reader
            // needs the first error more than the last.
            writer.print("{f}", .{zon_diag}) catch {
                said.truncated = true;
            };
            said.len = @intCast(writer.end);
            said.trimTrailingNewlines();
            return said;
        }

        pub fn ofText(words: []const u8) Said {
            var said: Said = .{ .truncated = words.len > max_bytes };
            const kept = @min(words.len, max_bytes);
            @memcpy(said.bytes[0..kept], words[0..kept]);
            said.len = @intCast(kept);
            return said;
        }

        /// Drop the trailing newlines Zig's own ZON format writes.
        fn trimTrailingNewlines(self: *Said) void {
            while (self.len > 0 and self.bytes[self.len - 1] == '\n') self.len -= 1;
        }
    };

    pub const Call = enum {
        git_spawn,
        git_wait,
        scratch_object_store_create,
        config_worktree_check,
        worktree_git_file_read,
        git_pointer_file_create,
        git_pointer_file_write,
        empty_scratch_file_create,
        scratch_file_delete,
        worktree_meta_copy,
        worktree_meta_commondir_write,
        chock_zon_check,
        chock_zon_read,
        overlay_scratch_mkdir,
        overlay_scratch_check,
        carried_work_check,
        carried_work_mkdir,
        carried_entry_stat,
        carried_file_copy,
        carried_link_read,
        carried_link_write,
        carried_list_write,
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
                .overlay_scratch_check => "checking for an overlay scratch layout",
                .carried_work_check => "checking where the work is to be carried out to",
                .carried_work_mkdir => "making the directory the work is carried out to",
                .carried_entry_stat => "reading a changed path's own metadata",
                .carried_file_copy => "copying a changed file out of the upper layer",
                .carried_link_read => "reading a changed symbolic link",
                .carried_link_write => "writing a carried symbolic link",
                .carried_list_write => "writing the list of deleted or skipped paths",
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

    /// A pointer and not a value, so the `Said` a message reads from is the
    /// one in the caller's own slot.
    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .call_failed => |failed| try writer.print(
                "{s} failed: {s}",
                .{ failed.call.text(), failed.fault.text() },
            ),
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

const chock_zon_name = "chock.zon";

pub fn note(diag: ?*?Diagnostic, value: Diagnostic) void {
    const slot = diag orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

pub fn noteErr(diag: ?*?Diagnostic, call: Diagnostic.Call, err: anyerror) void {
    note(diag, .{ .call_failed = .{ .call = call, .fault = .{ .err = err } } });
}

pub fn noteErrno(diag: ?*?Diagnostic, call: Diagnostic.Call, errno: std.posix.E) void {
    note(diag, .{ .call_failed = .{ .call = call, .fault = .{ .errno = errno } } });
}

const testing = std.testing;

test "the first fault is kept, and a caller that wants none pays nothing" {
    // The first, not the last. A walk of the upper layer can only fail after
    // an earlier step already did.
    var diag: ?Diagnostic = null;
    noteErr(&diag, .upper_layer_open, error.AccessDenied);
    noteErr(&diag, .upper_layer_walk, error.FileNotFound);
    try testing.expectEqual(Diagnostic.Call.upper_layer_open, diag.?.call_failed.call);
    try testing.expectEqual(@as(anyerror, error.AccessDenied), diag.?.call_failed.fault.err);

    noteErr(null, .upper_layer_walk, error.FileNotFound);
    noteErrno(null, .whiteout_stat, .PERM);
}

test "a diagnostic names the call and the fault, and allocates nothing" {
    // The two facts `error.Unexpected` throws away. Rendering happens at a
    // caller, which is where the decision belongs.
    var buffer: [512]u8 = undefined;
    const opening: Diagnostic = .{ .call_failed = .{
        .call = .upper_layer_open,
        .fault = .{ .err = error.AccessDenied },
    } };
    try testing.expectEqualStrings(
        "opening the upper layer failed: AccessDenied",
        try std.fmt.bufPrint(&buffer, "{f}", .{&opening}),
    );
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
    // `deny.zig` must parse the whole file before it can name a block, so a
    // syntax error has no block to blame.
    var buffer: [512]u8 = undefined;
    const whole_file: Diagnostic = .{
        .chock_zon_not_valid = Diagnostic.Said.ofText("4:9: error: expected field initializer"),
    };
    try testing.expectEqualStrings(
        "chock.zon is not valid:\n4:9: error: expected field initializer",
        try std.fmt.bufPrint(&buffer, "{f}", .{&whole_file}),
    );

    const block: Diagnostic = .{
        .deny_block_not_valid = Diagnostic.Said.ofText("1:20: error: expected type '[]const u8'"),
    };
    try testing.expectEqualStrings(
        "chock.zon: the deny_read block is not valid:\n1:20: error: expected type '[]const u8'",
        try std.fmt.bufPrint(&buffer, "{f}", .{&block}),
    );
}

test "a message survives the frame the reader built it in" {
    // Four diagnostics in this project have dangled, so nothing here borrows a
    // string out of a frame that ends.
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

fn fillFromAFrameThatEnds(diag: *?Diagnostic) void {
    var scratch: [Diagnostic.Said.max_bytes]u8 = undefined;
    const words = std.fmt.bufPrint(
        &scratch,
        "{d}:{d}: error: expected field initializer",
        .{ 2, 36 },
    ) catch return;
    note(diag, .{ .chock_zon_not_valid = Diagnostic.Said.ofText(words) });
}

fn dirtyTheFrame() u64 {
    var scratch: [4 * Diagnostic.Said.max_bytes]u8 = undefined;
    @memset(&scratch, 0xAA);
    var sum: u64 = 0;
    for (scratch) |byte| sum +%= byte;
    return sum;
}

test "a message longer than the buffer keeps its first line and says it was cut" {
    // The bound `Said` trades for owning no memory, stated rather than hidden.
    var long: [Diagnostic.Said.max_bytes * 2]u8 = undefined;
    @memset(&long, 'x');
    @memcpy(long[0..4], "1:1:");
    const said: Diagnostic.Said = .ofText(&long);
    try testing.expect(said.truncated);
    try testing.expectEqual(@as(usize, Diagnostic.Said.max_bytes), said.text().len);
    try testing.expectEqualStrings("1:1:", said.text()[0..4]);

    const short: Diagnostic.Said = .ofText("1:1: error: no");
    try testing.expect(!short.truncated);
    try testing.expectEqualStrings("1:1: error: no", short.text());
}

test "no two calls of this module read the same" {
    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |call, i| {
        try testing.expect(call.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, call.text(), other.text()));
        }
    }
}
