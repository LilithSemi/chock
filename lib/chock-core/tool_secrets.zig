//! What a secret a project granted reaches, and for how long.

const std = @import("std");

pub const Used = struct {
    name: []const u8,
    bind: []const u8,
    variable: []const u8,
};

pub const File = struct {
    variable: []const u8,
    value: []const u8,
};

pub const Grant = struct {
    env: []const []const u8 = &.{},
    files: []const File = &.{},
    used: []const Used = &.{},
};

pub const Seam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        grant: *const fn (
            ptr: *anyopaque,
            tool: []const u8,
            action: []const u8,
            call_id: []const u8,
        ) ?Grant,
        release: *const fn (ptr: *anyopaque, call_id: []const u8) void,
    };

    pub fn grant(
        self: Seam,
        tool: []const u8,
        action: []const u8,
        call_id: []const u8,
    ) ?Grant {
        return self.vtable.grant(self.ptr, tool, action, call_id);
    }

    pub fn release(self: Seam, call_id: []const u8) void {
        self.vtable.release(self.ptr, call_id);
    }
};

const testing = std.testing;

const Fake = struct {
    granted_for: []const u8,
    released: usize = 0,

    fn seam(self: *Fake) Seam {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Seam.VTable{ .grant = grantFn, .release = releaseFn };

    fn grantFn(ptr: *anyopaque, tool: []const u8, action: []const u8, call_id: []const u8) ?Grant {
        _ = tool;
        _ = call_id;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        if (!std.mem.eql(u8, action, self.granted_for)) return null;
        return .{
            .env = &.{"GITHUB_TOKEN=not-a-real-token"},
            .used = &.{.{ .name = "GITHUB_TOKEN", .bind = "env", .variable = "GITHUB_TOKEN" }},
        };
    }

    fn releaseFn(ptr: *anyopaque, call_id: []const u8) void {
        _ = call_id;
        const self: *Fake = @ptrCast(@alignCast(ptr));
        self.released += 1;
    }
};

test "a grant reaches the action it was written for and no other" {
    var fake = Fake{ .granted_for = "exec.path.gh" };

    const given = fake.seam().grant("run_command", "exec.path.gh", "call-1").?;
    try testing.expectEqual(@as(usize, 1), given.env.len);
    try testing.expectEqual(@as(usize, 1), given.used.len);

    try testing.expectEqual(
        @as(?Grant, null),
        fake.seam().grant("run_command", "exec.path.env", "call-2"),
    );
}

test "what is recorded names the secret and never carries a value" {
    var fake = Fake{ .granted_for = "exec.path.gh" };
    const given = fake.seam().grant("run_command", "exec.path.gh", "call-1").?;

    const record = given.used[0];
    try testing.expectEqualStrings("GITHUB_TOKEN", record.name);
    try testing.expectEqualStrings("env", record.bind);

    inline for (@typeInfo(Used).@"struct".fields) |field| {
        try testing.expect(!std.mem.eql(u8, field.name, "value"));
    }
    try testing.expect(std.mem.indexOf(u8, given.env[0], "not-a-real-token") != null);
}

test "release is called for a call that was granted nothing" {
    var fake = Fake{ .granted_for = "exec.path.gh" };
    fake.seam().release("call-2");
    try testing.expectEqual(@as(usize, 1), fake.released);
}

test "a file bind carries the value and never a path" {
    inline for (@typeInfo(File).@"struct".fields) |field| {
        try testing.expect(!std.mem.eql(u8, field.name, "path"));
        try testing.expect(!std.mem.eql(u8, field.name, "host_path"));
    }

    const one = File{ .variable = "GOOGLE_APPLICATION_CREDENTIALS", .value = "{}" };
    const grant = Grant{ .files = &.{one}, .used = &.{
        .{ .name = "GCP_KEY", .bind = "file", .variable = one.variable },
    } };

    try testing.expectEqual(@as(usize, 0), grant.env.len);
    try testing.expectEqual(@as(usize, 1), grant.files.len);
    try testing.expectEqualStrings("file", grant.used[0].bind);
}
