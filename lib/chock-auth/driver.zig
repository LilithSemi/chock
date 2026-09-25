//! Which store a credential goes to, and the ones this platform has.
//!
//! ## The choice is configured and never guessed
//!
//! A secret service can look reachable and still be unusable. On a session with
//! no desktop the bus is there, the service starts on demand, and opening a
//! session works, and then the collection is locked and the prompt that would
//! unlock it cannot be drawn. So every cheap check passes while the operation
//! fails.
//!
//! A driver that probed would put a credential somewhere the user did not ask
//! for. The `credentials` block of the operator's own `config.zon` names the
//! store, `chock_auth.config` refuses one this platform does not have when the
//! file is read, and this file only does what it was told.
//!
//! **No store falls back to another.** One that cannot work is an error a
//! person reads, not a quiet move to somewhere less protected.

const std = @import("std");
const builtin = @import("builtin");
const store = @import("store.zig");
const config = @import("config.zig");

// **Only the store this platform has is imported.** A comptime `if` analyses
// the branch it takes and no other, so a Linux build never reaches the Keychain
// and a macOS build never reaches the D-Bus library.
const file = if (builtin.os.tag == .linux) @import("linux/secrets.zig") else void;
const secret_service = if (builtin.os.tag == .linux) @import("linux/secret_service.zig") else void;
const keychain = if (builtin.os.tag == .macos) @import("darwin/secrets.zig") else void;
const secretspec = @import("secretspec.zig");

pub const Driver = struct {
    data_dir: []const u8,
    /// Which store.
    ///
    /// The default is the file, which is the one that cannot surprise: it needs
    /// no bus, no desktop and no daemon. What a user gets is the keystore, and
    /// that comes from the `credentials` block, which `chock run` and
    /// `chock login` read and pass in. So a caller that names nothing writes a
    /// file, and a caller that read a configuration does what it says.
    store: config.CredentialStore = .file,
    /// Read for `DBUS_SESSION_BUS_ADDRESS`, and needed by the secret service
    /// store alone. Null is what a caller with no environment passes.
    env: ?*const std.process.Environ.Map = null,
    /// Why the last secret service call failed, when one did. Linux only, and
    /// null everywhere else.
    last_fault: ?(if (builtin.os.tag == .linux) secret_service.Fault else void) = null,

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
        const self: *Driver = @ptrCast(@alignCast(ptr));
        switch (self.store) {
            .file => {
                if (builtin.os.tag != .linux) return error.StoreUnreadable;
                var backing = file.Driver{ .data_dir = self.data_dir };
                return backing.secrets().get(gpa, io, name, diag);
            },
            .secret_service => {
                if (builtin.os.tag != .linux) return error.StoreUnreadable;
                const env = self.env orelse return error.StoreUnreadable;
                var backing = secret_service.Driver{ .env = env };
                defer self.last_fault = backing.last_fault;
                return backing.secrets().get(gpa, io, name, diag);
            },
            .keychain => {
                if (builtin.os.tag != .macos) return error.StoreUnreadable;
                var backing = keychain.Driver{ .data_dir = self.data_dir };
                return backing.secrets().get(gpa, io, name, diag);
            },
            .secretspec => {
                var backing = secretspec.Driver{ .env = self.env };
                return backing.secrets().get(gpa, io, name, diag);
            },
        }
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!void {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        switch (self.store) {
            .file => {
                if (builtin.os.tag != .linux) return error.StoreUnwritable;
                var backing = file.Driver{ .data_dir = self.data_dir };
                return backing.secrets().put(gpa, io, name, value, diag);
            },
            .secret_service => {
                if (builtin.os.tag != .linux) return error.StoreUnwritable;
                const env = self.env orelse return error.StoreUnwritable;
                var backing = secret_service.Driver{ .env = env };
                defer self.last_fault = backing.last_fault;
                return backing.secrets().put(gpa, io, name, value, diag);
            },
            .keychain => {
                if (builtin.os.tag != .macos) return error.StoreUnwritable;
                var backing = keychain.Driver{ .data_dir = self.data_dir };
                return backing.secrets().put(gpa, io, name, value, diag);
            },
            .secretspec => {
                var backing = secretspec.Driver{ .env = self.env };
                return backing.secrets().put(gpa, io, name, value, diag);
            },
        }
    }
};

const testing = std.testing;

test "the file store reads back what it wrote, through the chooser" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..root_len];

    var driver = Driver{ .data_dir = root, .store = .file };

    try driver.secrets().put(gpa, testing.io, "work", "sk-not-a-real-key-0123", null);
    const held = (try driver.secrets().get(gpa, testing.io, "work", null)).?;
    defer {
        std.crypto.secureZero(u8, held);
        gpa.free(held);
    }
    try testing.expectEqualStrings("sk-not-a-real-key-0123", held);
}

test "a name the file store does not hold reads back as nothing" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..root_len];

    var driver = Driver{ .data_dir = root, .store = .file };
    try testing.expectEqual(
        @as(?[]u8, null),
        try driver.secrets().get(gpa, testing.io, "never-stored", null),
    );
}

test "the secret service store with no environment refuses rather than reaching a bus" {
    const gpa = testing.allocator;

    // A caller that passes no environment cannot name a session bus, so this
    // refuses instead of guessing at one.
    var driver = Driver{ .data_dir = "", .store = .secret_service };
    try testing.expectError(
        error.StoreUnreadable,
        driver.secrets().get(gpa, testing.io, "work", null),
    );
    try testing.expectError(
        error.StoreUnwritable,
        driver.secrets().put(gpa, testing.io, "work", "x", null),
    );
}

test "the store this platform does not have is refused and never dispatched" {
    const gpa = testing.allocator;

    var driver = Driver{ .data_dir = "", .store = .keychain };
    try testing.expectError(
        error.StoreUnreadable,
        driver.secrets().get(gpa, testing.io, "work", null),
    );
}
