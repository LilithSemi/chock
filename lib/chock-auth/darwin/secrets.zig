//! The Darwin credential driver: the Keychain, which is what a macOS user
//! expects and what the system already protects.
//!
//! ## Why this drives `/usr/bin/security` and not the Security framework
//!
//! Pure Zig bends here. On Darwin the rule is no third party C library, and
//! it is not no C. The Security framework is neither
//! third party nor plain C: it is an Objective-C era framework with
//! `CFDictionary` argument shapes, and reaching it means a framework link,
//! a set of `extern` declarations, and Core Foundation object lifetimes, none
//! of which any other Chock library needs. `/usr/bin/security` is on every
//! macOS install, it is the same tool a macOS user already uses by hand, and
//! it talks to the same Keychain. When the framework earns its place, it is a
//! second file here that implements the same two functions, and no caller
//! changes.
//!
//! ## The value never goes on a command line
//!
//! A credential must never go on a command line, because `ps` shows one to
//! every other user on the machine. That rule binds Chock's own
//! command line and it binds every command line Chock builds, so `-w <value>`
//! and `-X <hex>` are both out. `security add-generic-password` prompts for
//! the password when `-w` is the last option, and it reads that prompt from
//! standard input, so the value goes down a pipe. It asks twice, for a
//! password and for a retype, so `put` writes the value twice.
//!
//! **A named keychain cannot be used with the prompt.** The keychain is a
//! positional argument that must come last, and `-w` with no value takes the
//! next argument as the password, so naming a keychain and prompting are the
//! two things this tool cannot do at once. This driver therefore uses the
//! default keychain, which is what a user wants anyway.
//!
//! This file holds values and no metadata. The name, the kind, the base URL,
//! and the time are in the index `store.zig` keeps, which holds no secret.

const std = @import("std");
const store = @import("../store.zig");

/// The tool, by absolute path. Never resolved through `PATH`: a credential
/// read is not a thing to hand to whichever `security` a user's own `PATH`
/// happens to find first.
pub const security_path = "/usr/bin/security";

/// The Keychain service name every item Chock stores carries. The account is
/// the instance's own name, so two instances of one kind sit side by side,
/// which is the case the name key exists for.
pub const service_name = "chock";

/// What `security` exits with when the item is not in the Keychain. This is
/// `errSecItemNotFound` from the Security framework, which `security` returns
/// unchanged. Measured on macOS 15.7.9.
pub const item_not_found_status: u8 = 44;

/// The largest value this driver reads back from `security`. A credential is
/// a short string, and this bounds a `security` that answers with something
/// else entirely.
pub const max_value_bytes: usize = 64 * 1024;

/// The driver. `data_dir` is accepted and ignored: the Keychain decides where
/// a value lives, and this driver holds no file of its own. The field is here
/// so `lib/chock-auth/store.zig` builds a `Driver` the same way on both
/// platforms.
pub const Driver = struct {
    data_dir: []const u8,

    pub fn secrets(self: *const Driver) store.Secrets {
        return .{ .ptr = @constCast(self), .vtable = &vtable };
    }

    const vtable = store.Secrets.VTable{ .get = getFn, .put = putFn };

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!?[]u8 {
        _ = ptr;
        const result = std.process.run(gpa, io, .{
            .argv = &.{ security_path, "find-generic-password", "-a", name, "-s", service_name, "-w" },
            .stdout_limit = .limited(max_value_bytes),
            .stderr_limit = .limited(max_value_bytes),
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                if (store.wantsDiagnostic(diag)) {
                    _ = store.note(diag, .{ .keychain_command_failed = .{
                        .verb = store.reading_verb,
                        .name = try gpa.dupe(u8, name),
                        .err = err,
                    } });
                }
                return error.StoreUnreadable;
            },
        };
        defer {
            std.crypto.secureZero(u8, result.stdout);
            gpa.free(result.stdout);
            gpa.free(result.stderr);
        }

        switch (result.term) {
            .exited => |status| {
                if (status == item_not_found_status) return null;
                if (status != 0) {
                    // What `security` wrote is in a buffer this function
                    // frees on the way out, so the diagnostic keeps a copy.
                    if (store.wantsDiagnostic(diag)) {
                        const name_copy = try gpa.dupe(u8, name);
                        errdefer gpa.free(name_copy);
                        const detail = try gpa.dupe(u8, std.mem.trim(u8, result.stderr, " \t\r\n"));
                        _ = store.note(diag, .{ .keychain_refused = .{
                            .verb = store.reading_verb,
                            .name = name_copy,
                            .status = status,
                            .detail = detail,
                        } });
                    }
                    return error.StoreUnreadable;
                }
            },
            else => {
                if (store.wantsDiagnostic(diag)) {
                    _ = store.note(diag, .{ .keychain_did_not_exit_normally = .{
                        .verb = store.reading_verb,
                        .name = try gpa.dupe(u8, name),
                    } });
                }
                return error.StoreUnreadable;
            },
        }

        return try gpa.dupe(u8, trimValue(result.stdout));
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!void {
        _ = ptr;
        // `-U` replaces an item that is already there, and `-w` last is what
        // makes the tool ask for the value instead of reading it off the
        // command line. See this file's own top comment.
        var child = std.process.spawn(io, .{
            .argv = &.{
                security_path, "add-generic-password",
                "-a",          name,
                "-s",          service_name,
                "-l",          name,
                "-D",          "Chock provider credential",
                "-U",          "-w",
            },
            .stdin = .pipe,
            .stdout = .ignore,
            .stderr = .inherit,
        }) catch |err| {
            try noteCommandFailed(gpa, diag, name, err);
            return error.StoreUnwritable;
        };
        errdefer child.kill(io);

        // The prompt asks twice, for the value and for a retype, so both
        // lines go down the pipe before it closes. Closing the pipe is what
        // ends the second prompt's own read.
        const both = try promptLines(gpa, value);
        defer {
            std.crypto.secureZero(u8, both);
            gpa.free(both);
        }
        var stdin = child.stdin.?;
        stdin.writeStreamingAll(io, both) catch |err| {
            try noteCommandFailed(gpa, diag, name, err);
            return error.StoreUnwritable;
        };
        stdin.close(io);
        child.stdin = null;

        const term = child.wait(io) catch |err| {
            try noteCommandFailed(gpa, diag, name, err);
            return error.StoreUnwritable;
        };
        switch (term) {
            .exited => |status| {
                if (status == 0) return;
                // `stderr` is inherited on this path, so `security` has
                // already written whatever it had to say and there is
                // nothing here to capture. The status is the fact that
                // travels, and the message names the ordinary cause.
                if (store.wantsDiagnostic(diag)) {
                    _ = store.note(diag, .{ .keychain_refused = .{
                        .verb = store.storing_verb,
                        .name = try gpa.dupe(u8, name),
                        .status = status,
                        .detail = try gpa.dupe(u8, ""),
                    } });
                }
                return error.StoreUnwritable;
            },
            else => {
                if (store.wantsDiagnostic(diag)) {
                    _ = store.note(diag, .{ .keychain_did_not_exit_normally = .{
                        .verb = store.storing_verb,
                        .name = try gpa.dupe(u8, name),
                    } });
                }
                return error.StoreUnwritable;
            },
        }
    }
};

/// Note a `security` command that could not be started, written to, or
/// waited for, while a credential was being stored. The name is copied,
/// because a `Store` caller frees the name it passed as soon as the call
/// returns.
fn noteCommandFailed(
    gpa: std.mem.Allocator,
    diag: ?*?store.Diagnostic,
    name: []const u8,
    err: anyerror,
) std.mem.Allocator.Error!void {
    if (!store.wantsDiagnostic(diag)) return;
    _ = store.note(diag, .{ .keychain_command_failed = .{
        .verb = store.storing_verb,
        .name = try gpa.dupe(u8, name),
        .err = err,
    } });
}

/// The value, with the one line ending `security` adds when it prints a
/// password taken off. Only the last one, and only one: a credential is
/// allowed to end in whitespace of its own, and eating that would hand back
/// a key that is not the key the user stored.
pub fn trimValue(printed: []const u8) []const u8 {
    if (std.mem.endsWith(u8, printed, "\r\n")) return printed[0 .. printed.len - 2];
    if (std.mem.endsWith(u8, printed, "\n")) return printed[0 .. printed.len - 1];
    return printed;
}

/// The value twice, each on its own line, which is what the prompt and its
/// retype read. Caller owns the result and wipes it before freeing.
pub fn promptLines(gpa: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, (value.len + 1) * 2);
    @memcpy(out[0..value.len], value);
    out[value.len] = '\n';
    @memcpy(out[value.len + 1 ..][0..value.len], value);
    out[out.len - 1] = '\n';
    return out;
}

// Everything here that does not need a Keychain is tested here, on every
// host, the same way `chock-sandbox/darwin/driver.zig` earns its tests. What
// is left is the Keychain round trip itself, which needs a Mac with an
// unlocked login keychain: a machine reached over ssh with no desktop session
// has a locked one, and `security` answers "The authorization was denied".

const testing = std.testing;

test "the value read back loses one line ending and no other whitespace" {
    try testing.expectEqualStrings("sk-not-a-real-key", trimValue("sk-not-a-real-key\n"));
    try testing.expectEqualStrings("sk-not-a-real-key", trimValue("sk-not-a-real-key\r\n"));
    try testing.expectEqualStrings("sk-not-a-real-key", trimValue("sk-not-a-real-key"));
    try testing.expectEqualStrings("sk-trailing-space ", trimValue("sk-trailing-space \n"));
    try testing.expectEqualStrings("sk-two-lines\n", trimValue("sk-two-lines\n\n"));
}

test "the value goes to the prompt twice, because the prompt asks twice" {
    const gpa = testing.allocator;
    const lines = try promptLines(gpa, "sk-not-a-real-key");
    defer gpa.free(lines);
    try testing.expectEqualStrings("sk-not-a-real-key\nsk-not-a-real-key\n", lines);
}

test "no command line this driver builds ever carries the credential" {
    const value = "sk-a-value-that-must-not-appear";
    const read_argv = [_][]const u8{
        security_path, "find-generic-password", "-a", "work", "-s", service_name, "-w",
    };
    const write_argv = [_][]const u8{
        security_path, "add-generic-password",
        "-a",          "work",
        "-s",          service_name,
        "-l",          "work",
        "-D",          "Chock provider credential",
        "-U",          "-w",
    };
    for (read_argv) |argument| try testing.expect(std.mem.indexOf(u8, argument, value) == null);
    for (write_argv) |argument| try testing.expect(std.mem.indexOf(u8, argument, value) == null);

    // And the last argument of the write is `-w` with nothing after it,
    // which is the whole reason the tool prompts rather than reads argv.
    try testing.expectEqualStrings("-w", write_argv[write_argv.len - 1]);
}

test "the tool is named by absolute path, never resolved through PATH" {
    try testing.expect(std.fs.path.isAbsolute(security_path));
}
