//! A secret store that keeps its entries in memory, for tests. It also records the
//! last name it was asked for, which is how a caller proves the key it built.

const std = @import("std");
const store = @import("store.zig");

pub const FakeSecrets = struct {
    const Entry = struct { name: []const u8, value: []const u8 };

    entries: std.ArrayList(Entry) = .empty,
    last_name: []const u8 = "",

    pub fn secrets(self: *FakeSecrets) store.Secrets {
        return .{ .ptr = self, .vtable = &vtable };
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
        _ = diag;
        const self: *FakeSecrets = @ptrCast(@alignCast(ptr));
        gpa.free(self.last_name);
        self.last_name = try gpa.dupe(u8, name);
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return try gpa.dupe(u8, entry.value);
        }
        return null;
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
        _ = diag;
        const self: *FakeSecrets = @ptrCast(@alignCast(ptr));
        gpa.free(self.last_name);
        self.last_name = try gpa.dupe(u8, name);
        for (self.entries.items) |*entry| {
            if (std.mem.eql(u8, entry.name, name)) {
                gpa.free(entry.value);
                entry.value = try gpa.dupe(u8, value);
                return;
            }
        }
        try self.entries.append(gpa, .{
            .name = try gpa.dupe(u8, name),
            .value = try gpa.dupe(u8, value),
        });
    }

    pub fn deinit(self: *FakeSecrets, gpa: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            gpa.free(entry.name);
            gpa.free(entry.value);
        }
        self.entries.deinit(gpa);
        gpa.free(self.last_name);
        self.* = undefined;
    }
};
