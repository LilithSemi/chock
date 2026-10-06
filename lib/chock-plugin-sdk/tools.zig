//! What a plugin tool is handed and what it answers. A tool body never
//! touches the host directly, which is what keeps it plain Zig that a test
//! can call without a wasm engine nearby.

const std = @import("std");

/// Two states and no third: a tool that is unsure has failed, since an
/// agent reads an unclear answer as a success.
pub const Outcome = enum(u8) {
    success,
    failure,
};

pub const Result = struct {
    outcome: Outcome,
    text: []const u8,

    pub fn isSuccess(self: Result) bool {
        return self.outcome == .success;
    }
};

/// `tool` names which tool the host called. `arguments` is the host's own
/// record, not the model's JSON: a generated thunk decodes it, so a tool
/// body rarely reads it directly.
pub const Context = struct {
    tool: []const u8 = "",
    arguments: []const u8 = "",

    pub fn successResult(_: Context, text: []const u8) Result {
        return .{ .outcome = .success, .text = text };
    }

    /// `text` says why: an agent that reads only "failed" repeats the call.
    pub fn errorResult(_: Context, text: []const u8) Result {
        return .{ .outcome = .failure, .text = text };
    }
};

test "successResult and errorResult differ in outcome and keep their text" {
    const ctx: Context = .{ .tool = "hello" };
    const good = ctx.successResult("done");
    const bad = ctx.errorResult("no such file");

    try std.testing.expectEqual(Outcome.success, good.outcome);
    try std.testing.expectEqual(Outcome.failure, bad.outcome);
    try std.testing.expect(good.isSuccess());
    try std.testing.expect(!bad.isSuccess());
    try std.testing.expectEqualStrings("done", good.text);
    try std.testing.expectEqualStrings("no such file", bad.text);
}
