//! What a secret a project granted reaches, and for how long.
//!
//! ## A sibling of `credentials.zig`, and deliberately not the same seam
//!
//! `credentials.zig` hands a tool call a **capability**: a socket path, with
//! whatever answers on that socket held by the host. Its `Grant.env` says "a
//! path and never a value" and means it.
//!
//! This one hands over a **secret**. The value itself reaches the child,
//! because a program that reads `GITHUB_TOKEN` wants the token and not a
//! socket. Keeping the two apart means the older promise stays true, and a
//! reader of either one knows which they are looking at.
//!
//! ## The lifetime is the whole of the security property
//!
//! `grant` is asked once per tool call, right before that call's own sandbox
//! is built, and it is answered for the calls a project's own `secrets` block
//! names and no others. So a token reaches `gh` and is absent from the call
//! that runs `env`.
//!
//! ## The agent still never sees it
//!
//! The environment is not what hides the value: an agent chooses the argument
//! list, so it can ask a program to print its own token. What hides it is
//! redaction of every tool result, which the caller arms with the same value
//! it grants here. See `lib/chock-broker/secrets.zig`.

const std = @import("std");

/// One secret, as it reached one tool call. The value is not here: this is
/// what the session log records, and a log holding the value would undo the
/// whole arrangement.
pub const Used = struct {
    /// The secret's own name, as the project's `secrets` block spells it.
    name: []const u8,
    /// How it arrived.
    bind: []const u8,
    /// The variable it arrived under, or that named its file.
    variable: []const u8,
};

/// One secret that must arrive as a file, because the program will not read an
/// environment variable for it.
///
/// The value is here and the path is not: only `chock-core` knows what a path
/// inside a sandbox is, so it writes the file, mounts it read only, and puts its
/// own path in the environment under `variable`.
pub const File = struct {
    /// The variable that names the file's path.
    variable: []const u8,
    /// The bytes the file holds.
    value: []const u8,
};

/// What one tool call is given.
pub const Grant = struct {
    /// `KEY=VALUE` entries to add to the call's environment. For a file bind
    /// the value is the path inside the sandbox, and the file is the caller's
    /// to make and to remove.
    ///
    /// **A value, unlike `credentials.Grant.env`.** That is the difference
    /// between the two seams and the reason there are two.
    env: []const []const u8 = &.{},
    /// Secrets that arrive as a file. The caller of this seam does not write
    /// them: see `File`.
    files: []const File = &.{},
    /// What to record, one entry per secret, in the same order.
    used: []const Used = &.{},
};

/// The seam itself. `chock-core` knows how to build a tool call's sandbox and
/// nothing about where a secret is kept, so the caller that holds the store,
/// the policy and the log answers this.
pub const Seam = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// What this tool call may be given, or null for one that may be
        /// given nothing. Asked once per call, right before the sandbox is
        /// built.
        ///
        /// `action` is the name the call was gated under, which is what the
        /// project's grants are written against.
        grant: *const fn (
            ptr: *anyopaque,
            tool: []const u8,
            action: []const u8,
            call_id: []const u8,
        ) ?Grant,
        /// Release whatever `grant` made for this call. Called once, after the
        /// sandboxed program has ended, however it ended.
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

/// A seam that grants one fixed entry, for the tests below.
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

    // The same tool, a different action, and nothing is given.
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

    // The record carries no field a value could travel in, so this holds for
    // any secret and not only this one.
    inline for (@typeInfo(Used).@"struct".fields) |field| {
        try testing.expect(!std.mem.eql(u8, field.name, "value"));
    }
    // And the value that does exist is in `env`, which the log never reads.
    try testing.expect(std.mem.indexOf(u8, given.env[0], "not-a-real-token") != null);
}

test "release is called for a call that was granted nothing" {
    // The caller cannot know whether `grant` answered, so `release` runs for
    // every call. A seam that only cleaned up after a grant would leak the one
    // time the caller got that wrong.
    var fake = Fake{ .granted_for = "exec.path.gh" };
    fake.seam().release("call-2");
    try testing.expectEqual(@as(usize, 1), fake.released);
}

test "a file bind carries the value and never a path" {
    // The path is the sandbox's to choose, so a seam that named one would be
    // deciding something only `chock-core` can know.
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
