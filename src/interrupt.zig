//! Signal handler for Ctrl-C: sets one flag, writes one line.

const std = @import("std");
const builtin = @import("builtin");
const chock_core = @import("chock-core");
const tty = @import("tty.zig");

pub const first_message = "\nchock: stopping at the next safe point, and writing the session end. " ++
    "Press Ctrl-C again to stop now.\n";

var message_fd: std.atomic.Value(i32) = .init(std.posix.STDERR_FILENO);

pub fn messageToForTest(fd: std.posix.fd_t) std.posix.fd_t {
    return message_fd.swap(fd, .monotonic);
}

pub const restore_bytes = "\x1b[?25h" ++ "\x1b[?1049l" ++ "\x1b[0m";

var display_up: std.atomic.Value(bool) = .init(false);

pub fn armTerminalRestore() void {
    display_up.store(true, .monotonic);
}

pub fn disarmTerminalRestore() void {
    display_up.store(false, .monotonic);
}

var saved_settings: std.posix.termios = undefined;

var settings_fd: std.atomic.Value(i32) = .init(-1);

pub fn armTerminalSettings(fd: std.posix.fd_t, was: std.posix.termios) void {
    saved_settings = was;
    settings_fd.store(fd, .monotonic);
}

pub fn disarmTerminalSettings() void {
    settings_fd.store(-1, .monotonic);
}

pub const Armed = struct {
    fd: std.posix.fd_t,
    was: std.posix.termios,
};

pub fn settingsIfArmed() ?Armed {
    const fd = settings_fd.load(.monotonic);
    if (fd < 0) return null;
    return .{ .fd = fd, .was = saved_settings };
}

pub fn restoreTerminalSettings() void {
    const armed = settingsIfArmed() orelse return;
    std.posix.tcsetattr(armed.fd, .FLUSH, armed.was) catch {};
}

pub fn restoreBytesIfArmed() ?[]const u8 {
    if (!display_up.load(.monotonic)) return null;
    return restore_bytes;
}

var stop_asked: std.atomic.Value(bool) = .init(false);

const handled = [_]std.posix.SIG{ .INT, .TERM };

pub fn requested() bool {
    return stop_asked.load(.monotonic);
}

pub fn requestStop() void {
    stop_asked.store(true, .monotonic);
}

pub fn forgetForTest() void {
    stop_asked.store(false, .monotonic);
}

pub fn install() void {
    if (builtin.os.tag == .windows) return;

    // No SA_RESTART: a restarted syscall would hide the signal from a read that is already waiting.
    const action = std.posix.Sigaction{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (handled) |sig| std.posix.sigaction(sig, &action, null);
}

fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    if (stop_asked.swap(true, .monotonic)) {
        chock_core.tools.cancelRunningTool();
        if (restoreBytesIfArmed()) |bytes| {
            _ = std.posix.system.write(std.posix.STDOUT_FILENO, bytes.ptr, bytes.len);
        }
        restoreTerminalSettings();
        // Restores the default handler and re-raises, so the process ends exactly as it would have with no handler installed.
        const default = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.DFL },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(sig, &default, null);
        std.posix.raise(sig) catch {};
        return;
    }
    tty.noteScroll();
    _ = std.posix.system.write(message_fd.load(.monotonic), first_message.ptr, first_message.len);
}

const testing = std.testing;

const Said = struct {
    tmp: testing.TmpDir,
    file: std.Io.File,
    was: std.posix.fd_t,
    path: [std.fs.max_path_bytes]u8 = undefined,
    len: usize = 0,

    fn open(self: *Said) !void {
        const io = testing.io;
        self.tmp = testing.tmpDir(.{});
        var dir: [std.fs.max_path_bytes]u8 = undefined;
        const at = try self.tmp.dir.realPath(io, &dir);
        const named = try std.fmt.bufPrint(&self.path, "{s}/said", .{dir[0..at]});
        self.len = named.len;
        self.file = try std.Io.Dir.createFileAbsolute(io, named, .{});
        self.was = messageToForTest(self.file.handle);
    }

    fn close(self: *Said, gpa: std.mem.Allocator) ![]u8 {
        const io = testing.io;
        _ = messageToForTest(self.was);
        self.file.close(io);
        const text = try std.Io.Dir.cwd().readFileAlloc(
            io,
            self.path[0..self.len],
            gpa,
            .limited(4096),
        );
        self.tmp.cleanup();
        return text;
    }
};

test "a real signal is what sets the flag, and the line a person reads says both presses" {
    const gpa = testing.allocator;
    forgetForTest();
    try testing.expect(!requested());

    var said: Said = undefined;
    try said.open();

    install();
    try std.posix.raise(.INT);
    try testing.expect(requested());

    const line = try said.close(gpa);
    defer gpa.free(line);
    try testing.expectEqualStrings(first_message, line);
    try testing.expect(std.mem.indexOf(u8, line, "next safe point") != null);
    try testing.expect(std.mem.indexOf(u8, line, "again to stop now") != null);
    try testing.expect(requested());
    forgetForTest();
}

test "a second press has the terminal's own settings to put back, and only while a display holds them" {
    try testing.expect(settingsIfArmed() == null);

    var was = std.mem.zeroes(std.posix.termios);
    was.lflag.ECHO = true;
    was.lflag.ISIG = true;
    armTerminalSettings(7, was);

    const armed = settingsIfArmed().?;
    try testing.expectEqual(@as(std.posix.fd_t, 7), armed.fd);
    try testing.expect(armed.was.lflag.ECHO);
    try testing.expect(armed.was.lflag.ISIG);

    disarmTerminalSettings();
    try testing.expect(settingsIfArmed() == null);
}

test "a terminated session is asked to stop the same way an interrupted one is" {
    const gpa = testing.allocator;
    forgetForTest();

    var said: Said = undefined;
    try said.open();

    install();
    try std.posix.raise(.TERM);
    try testing.expect(requested());

    const line = try said.close(gpa);
    defer gpa.free(line);
    try testing.expectEqualStrings(first_message, line);
    forgetForTest();
}
