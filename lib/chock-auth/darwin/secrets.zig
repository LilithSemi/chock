//! The Darwin credential driver: the Keychain, reached through the Security
//! framework.
//!
//! ## Why the framework and not `/usr/bin/security`
//!
//! This driver used to run the `security` command. That worked until the
//! Keychain wanted a person, and then it did not fail: it **hung**. The command
//! blocked on an authorisation dialog while Chock waited on a child that would
//! never exit, with the child's output captured so nothing on screen said why.
//! A credential is read early in `chock run`, so a session hung at the start
//! with an empty terminal.
//!
//! The framework fixes that at the root. `SecKeychainSetUserInteractionAllowed`
//! turns the dialog off, so a call that would have asked a person returns
//! `errSecInteractionNotAllowed` instead. **Nothing here can block on a human.**
//!
//! Two smaller things come with it. There is no command line and no pipe, so a
//! credential never leaves this process. And `SecKeychainFindGenericPassword`
//! gives an explicit length, so a value that ends in a newline reads back
//! exactly as it was stored: the old driver had to guess, because the command
//! printed a trailing newline of its own.
//!
//! ## The item is the same item
//!
//! The service and the account are unchanged, so an item the old driver stored
//! is the item this one finds. Nobody has to log in again.
//!
//! ## What protects the value
//!
//! The Keychain gives a new item an access list holding the application that
//! created it, and nothing else. That is the behaviour Chock wants once its
//! binaries are signed: Chock reads its own credential with no prompt, and
//! another program asking for it meets the Keychain's own refusal. Until the
//! binaries are signed a rebuilt Chock is a different application to the
//! Keychain, so it meets that refusal itself and reports it.
//!
//! This file holds values and no metadata. The name, the kind, the base URL,
//! and the time are in the index `store.zig` keeps, which holds no secret.

const std = @import("std");
const store = @import("../store.zig");

pub const status = @import("status.zig");

const OSStatus = status.OSStatus;

/// The Keychain service name every item Chock stores carries. The account is
/// the instance's own name, so two instances of one kind sit side by side.
pub const service_name = "chock";

// `UInt32` is `unsigned int` and `Boolean` is `unsigned char` on every Apple
// target this builds for. A `SecKeychainItemRef` is an opaque pointer.
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

/// Turn the authorisation dialog off for this process, once per call.
///
/// **This is what makes a hang impossible**, so it runs before every Keychain
/// call and its own result is not worth reading: a build where it failed would
/// still be safer asking than hanging, and the call that follows reports
/// whatever really went wrong.
fn refuseToAskAnybody() void {
    _ = SecKeychainSetUserInteractionAllowed(0);
}

/// The driver. `data_dir` is accepted and ignored: the Keychain decides where a
/// value lives. The field is here so `lib/chock-auth/store.zig` builds a
/// `Driver` the same way on both platforms.
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
        _ = io;
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
        // The Keychain owns that buffer and this frees it whatever happens.
        // Wiping it first keeps the value out of memory the allocator hands on.
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
        _ = ptr;
        _ = io;
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
        // Anything but "that name is taken" is the answer. Only a duplicate
        // sends this on to the replace below.
        if (added != status.duplicate_item) {
            return noteRefusal(gpa, diag, store.storing_verb, name, added);
        }

        // **Replacing is a second call and not a flag.** The Keychain has no
        // add-or-replace, so the item is looked up and its data written over.
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

/// Note what the Keychain answered, and give back the error the caller sees.
/// The name is copied, because a `Store` caller frees the name it passed as
/// soon as the call returns.
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
