//! Which store a credential goes to, and the ones this platform has.

const std = @import("std");
const builtin = @import("builtin");
const store = @import("store.zig");
const config = @import("config.zig");

// A comptime if analyses only the branch it takes, so a Linux build never reaches the Keychain and a macOS build never reaches the D-Bus library.
const file = if (builtin.os.tag == .linux) @import("linux/secrets.zig") else void;
const secret_service = if (builtin.os.tag == .linux) @import("linux/secret_service.zig") else void;
const keychain = if (builtin.os.tag == .macos) @import("darwin/secrets.zig") else void;
const secretspec = @import("secretspec.zig");

pub const Driver = struct {
    data_dir: []const u8,
    store: config.CredentialStore = .file,
    env: ?*const std.process.Environ.Map = null,
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
    if (builtin.os.tag != .linux) return error.SkipZigTest;
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
    if (builtin.os.tag != .linux) return error.SkipZigTest;
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
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

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

    const absent: config.CredentialStore = if (builtin.os.tag == .macos) .file else .keychain;
    try testing.expect(!absent.availableHere());

    var driver = Driver{ .data_dir = "", .store = absent };
    try testing.expectError(
        error.StoreUnreadable,
        driver.secrets().get(gpa, testing.io, "work", null),
    );
    try testing.expectError(
        error.StoreUnwritable,
        driver.secrets().put(gpa, testing.io, "work", "x", null),
    );
}
