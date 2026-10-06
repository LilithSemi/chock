//! The Darwin credential driver: the Keychain, reached through the Security

const std = @import("std");
const store = @import("../store.zig");
const config = @import("../config.zig");

pub const status = @import("status.zig");

const OSStatus = status.OSStatus;

pub const service_name = "chock";

// UInt32 is unsigned int and Boolean is unsigned char on every Apple target this builds for. A SecKeychainItemRef is an opaque pointer.
extern fn SecKeychainSetUserInteractionAllowed(state: u8) OSStatus;
extern fn SecKeychainFindGenericPassword(
    keychainOrArray: ?*const anyopaque,
    serviceNameLength: c_uint,
    serviceName: ?[*]const u8,
    accountNameLength: c_uint,
    accountName: ?[*]const u8,
    passwordLength: ?*c_uint,
    passwordData: ?*?*anyopaque,
    itemRef: ?*?*anyopaque,
) OSStatus;
extern fn SecKeychainAddGenericPassword(
    keychain: ?*anyopaque,
    serviceNameLength: c_uint,
    serviceName: ?[*]const u8,
    accountNameLength: c_uint,
    accountName: ?[*]const u8,
    passwordLength: c_uint,
    passwordData: ?*const anyopaque,
    itemRef: ?*?*anyopaque,
) OSStatus;
extern fn SecKeychainItemFreeContent(attrList: ?*anyopaque, data: ?*anyopaque) OSStatus;
extern fn SecKeychainItemModifyAttributesAndData(
    itemRef: ?*anyopaque,
    attrList: ?*const anyopaque,
    length: c_uint,
    data: ?*const anyopaque,
) OSStatus;
extern fn CFRelease(cf: ?*const anyopaque) void;

fn refuseToAskAnybody() void {
    _ = SecKeychainSetUserInteractionAllowed(0);
}

pub const Driver = struct {
    data_dir: []const u8,
    store: config.CredentialStore = .keychain,

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
        _ = io;
        const self: *Driver = @ptrCast(@alignCast(ptr));
        if (self.store != .keychain) return error.StoreUnreadable;
        refuseToAskAnybody();

        var length: c_uint = 0;
        var data: ?*anyopaque = null;
        const answer = SecKeychainFindGenericPassword(
            null,
            @intCast(service_name.len),
            service_name.ptr,
            @intCast(name.len),
            name.ptr,
            &length,
            &data,
            null,
        );
        switch (status.meaningOf(answer)) {
            .absent => return null,
            .ok => {},
            else => return noteRefusal(gpa, diag, store.reading_verb, name, answer),
        }

        const bytes: [*]u8 = @ptrCast(data orelse return null);
        // The Keychain owns that buffer and this frees it regardless. Wiping it first keeps the value out of memory the allocator hands on next.
        defer {
            std.crypto.secureZero(u8, bytes[0..length]);
            _ = SecKeychainItemFreeContent(null, data);
        }
        return try gpa.dupe(u8, bytes[0..length]);
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store.Diagnostic,
    ) store.Error!void {
        _ = io;
        const self: *Driver = @ptrCast(@alignCast(ptr));
        if (self.store != .keychain) return error.StoreUnwritable;
        refuseToAskAnybody();

        const added = SecKeychainAddGenericPassword(
            null,
            @intCast(service_name.len),
            service_name.ptr,
            @intCast(name.len),
            name.ptr,
            @intCast(value.len),
            value.ptr,
            null,
        );
        if (added == status.success) return;
        if (added != status.duplicate_item) {
            return noteRefusal(gpa, diag, store.storing_verb, name, added);
        }

        // Replacing is a second call, not a flag: the Keychain has no add or replace, so the item is looked up and its data written over.
        var item: ?*anyopaque = null;
        const found = SecKeychainFindGenericPassword(
            null,
            @intCast(service_name.len),
            service_name.ptr,
            @intCast(name.len),
            name.ptr,
            null,
            null,
            &item,
        );
        if (found != status.success) return noteRefusal(gpa, diag, store.storing_verb, name, found);
        defer CFRelease(item);

        const changed = SecKeychainItemModifyAttributesAndData(
            item,
            null,
            @intCast(value.len),
            value.ptr,
        );
        if (changed != status.success) return noteRefusal(gpa, diag, store.storing_verb, name, changed);
    }
};

fn noteRefusal(
    gpa: std.mem.Allocator,
    diag: ?*?store.Diagnostic,
    verb: []const u8,
    name: []const u8,
    answered: OSStatus,
) store.Error {
    if (store.wantsDiagnostic(diag)) {
        _ = store.note(diag, .{ .keychain_refused = .{
            .verb = verb,
            .name = try gpa.dupe(u8, name),
            .status = answered,
        } });
    }
    return if (std.mem.eql(u8, verb, store.reading_verb))
        error.StoreUnreadable
    else
        error.StoreUnwritable;
}

const testing = std.testing;

test "a name the Keychain does not hold reads back as nothing" {
    var driver = Driver{ .data_dir = "" };

    var diag: ?store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);

    const held = driver.secrets().get(
        testing.allocator,
        testing.io,
        "chock-test-name-no-login-ever-stored",
        &diag,
    ) catch |err| {
        const met = diag orelse return err;
        const refused = switch (met) {
            .keychain_refused => |one| one,
            else => return err,
        };
        switch (status.meaningOf(refused.status)) {
            .no_keychain, .needs_unlock => return error.SkipZigTest,
            else => return err,
        }
    };
    try testing.expectEqual(@as(?[]u8, null), held);
}
