//! The Linux credential driver: a file in the data directory, mode `0600`.

const std = @import("std");
const store = @import("../store.zig");
const paths = @import("../paths.zig");

pub const file_name = "credentials.zon";

pub const lock_file_name = "credentials.lock";

pub const max_file_bytes: usize = 1024 * 1024;

const Entry = struct {
    name: []const u8,
    token: []const u8,
};

const File = struct {
    version: u32 = 1,
    credentials: []const Entry = &.{},
};

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
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const file_path = try self.filePath(gpa);
        defer gpa.free(file_path);

        const parsed = try read(gpa, io, file_path, diag) orelse return null;
        defer std.zon.parse.free(gpa, parsed);

        for (parsed.credentials) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return try gpa.dupe(u8, entry.token);
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
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const file_path = try self.filePath(gpa);
        defer gpa.free(file_path);

        var held = try store.takeStoreLock(gpa, io, self.data_dir, lock_file_name, diag);
        defer held.release(io);

        const parsed = try read(gpa, io, file_path, diag);
        defer if (parsed) |p| std.zon.parse.free(gpa, p);

        var list: std.ArrayList(Entry) = .empty;
        defer list.deinit(gpa);
        if (parsed) |p| {
            for (p.credentials) |entry| {
                if (std.mem.eql(u8, entry.name, name)) continue;
                try list.append(gpa, entry);
            }
        }
        try list.append(gpa, .{ .name = name, .token = value });

        const text = try store.serializeZon(gpa, File{ .version = 1, .credentials = list.items });
        defer {
            // The whole serialized file holds every credential this driver knows, so the buffer it was built in is wiped before it goes back to the allocator.
            std.crypto.secureZero(u8, text);
            gpa.free(text);
        }

        try store.writePrivateFile(gpa, io, file_path, text, diag);
    }

    fn filePath(self: *const Driver, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fs.path.join(gpa, &.{ self.data_dir, file_name });
    }
};

fn read(
    gpa: std.mem.Allocator,
    io: std.Io,
    file_path: []const u8,
    diag: ?*?store.Diagnostic,
) store.Error!?File {
    var mode_fault: ?paths.Diagnostic = null;
    paths.requirePrivate(io, file_path, &mode_fault) catch |err| switch (err) {
        error.CredentialFileMissing => return null,
        error.StatFailed => {
            if (store.wantsDiagnostic(diag)) {
                _ = store.note(diag, .{ .credential_file_unreadable = .{
                    .path = try gpa.dupe(u8, file_path),
                    .err = mode_fault.?.stat_failed.err,
                } });
            }
            return error.StoreUnreadable;
        },
        error.CredentialFileIsReadable => {
            if (store.wantsDiagnostic(diag)) {
                _ = store.note(diag, .{ .credential_file_readable_by_others = .{
                    .path = try gpa.dupe(u8, file_path),
                    .mode = mode_fault.?.readable_by_others.mode,
                } });
            }
            return error.StoreIsReadable;
        },
    };

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        file_path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return null,
        else => {
            if (store.wantsDiagnostic(diag)) {
                _ = store.note(diag, .{ .credential_file_unreadable = .{
                    .path = try gpa.dupe(u8, file_path),
                    .err = err,
                } });
            }
            return error.StoreUnreadable;
        },
    };
    defer {
        std.crypto.secureZero(u8, source);
        gpa.free(source);
    }

    var diagnostics: std.zon.parse.Diagnostics = .{};
    defer diagnostics.deinit(gpa);
    return std.zon.parse.fromSliceAlloc(File, gpa, source, &diagnostics, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            // The diagnostics are dropped here on purpose: they carry the file's own text, which is the credential, so only the path travels and never what is in it.
            if (store.wantsDiagnostic(diag)) {
                _ = store.note(diag, .{ .credential_file_not_valid = try gpa.dupe(u8, file_path) });
            }
            return error.StoreCorrupt;
        },
    };
}

const testing = std.testing;

fn tmpDirPath(buffer: []u8, tmp: std.testing.TmpDir) ![]const u8 {
    const len = try tmp.dir.realPath(testing.io, buffer);
    return buffer[0..len];
}

test "a value round trips, and a name this driver does not hold reads back as nothing" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const driver = Driver{ .data_dir = dir };
    const secrets = driver.secrets();

    try testing.expect((try secrets.get(gpa, testing.io, "aiand", null)) == null);

    try secrets.put(gpa, testing.io, "work", "sk-work-not-a-real-key", null);
    try secrets.put(gpa, testing.io, "personal", "sk-personal-not-a-real-key", null);

    const work = (try secrets.get(gpa, testing.io, "work", null)).?;
    defer gpa.free(work);
    const personal = (try secrets.get(gpa, testing.io, "personal", null)).?;
    defer gpa.free(personal);
    try testing.expectEqualStrings("sk-work-not-a-real-key", work);
    try testing.expectEqualStrings("sk-personal-not-a-real-key", personal);
    try testing.expect((try secrets.get(gpa, testing.io, "never-stored", null)) == null);
}

test "the file this driver writes is mode 0600, and one that others can read is refused" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const driver = Driver{ .data_dir = dir };
    const secrets = driver.secrets();
    try secrets.put(gpa, testing.io, "aiand", "sk-not-a-real-key", null);

    const file_path = try std.fs.path.join(gpa, &.{ dir, file_name });
    defer gpa.free(file_path);

    const stat = try std.Io.Dir.cwd().statFile(testing.io, file_path, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);

    {
        var file = try std.Io.Dir.openFileAbsolute(testing.io, file_path, .{});
        defer file.close(testing.io);
        try file.setPermissions(testing.io, .fromMode(0o644));
    }
    try testing.expectError(error.StoreIsReadable, secrets.get(gpa, testing.io, "aiand", null));
}

test "a replaced value leaves no copy of the old one in the file" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const driver = Driver{ .data_dir = dir };
    const secrets = driver.secrets();
    try secrets.put(gpa, testing.io, "aiand", "sk-the-old-one", null);
    try secrets.put(gpa, testing.io, "aiand", "sk-the-new-one", null);

    const file_path = try std.fs.path.join(gpa, &.{ dir, file_name });
    defer gpa.free(file_path);
    const source = try std.Io.Dir.cwd().readFileAlloc(testing.io, file_path, gpa, .limited(max_file_bytes));
    defer gpa.free(source);

    try testing.expect(std.mem.indexOf(u8, source, "sk-the-old-one") == null);
    try testing.expect(std.mem.indexOf(u8, source, "sk-the-new-one") != null);
}

test {
    testing.refAllDecls(@This());
}
