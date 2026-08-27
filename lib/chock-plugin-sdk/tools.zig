//! What a plugin tool is handed and what it answers.
//!
//! A tool body never touches the host directly. It receives a `Context` and
//! its own arguments, and it answers a `Result`. Everything that crosses the
//! sandbox boundary is the host's job, which is what keeps a tool body plain
//! Zig that a test can call without a wasm engine anywhere near it.

const std = @import("std");

/// Whether a tool did the thing it was asked to do. Two states and no third:
/// a tool that is unsure has failed, because the caller of a tool is an agent
/// and an agent reads an unclear answer as a success.
pub const Outcome = enum(u8) {
    success,
    failure,
};

/// What a tool answers. `text` is what the agent reads, in either outcome.
pub const Result = struct {
    outcome: Outcome,
    text: []const u8,

    pub fn isSuccess(self: Result) bool {
        return self.outcome == .success;
    }
};

/// What a tool is handed.
///
/// `tool` is the name of the tool the host called, so one body that serves
/// several tools can tell them apart.
///
/// `arguments` is the argument text the model wrote, carried through
/// untouched. **It is text and not a parsed value**, because nothing lowers
/// the model's arguments into a tool's own argument type yet: see the comptime
/// block in `lib/chock-plugin-sdk/exports.zig`, which refuses to compile a
/// tool that declares one. A tool that needs an argument today reads this.
///
/// **Every byte of it was written by a model.** A tool body treats it as data
/// the same way the harness does, and a body that cannot read it answers
/// `errorResult` rather than guessing.
pub const Context = struct {
    tool: []const u8 = "",
    arguments: []const u8 = "",

    /// The tool did what it was asked to do. `text` is the answer.
    pub fn successResult(_: Context, text: []const u8) Result {
        return .{ .outcome = .success, .text = text };
    }

    /// The tool did not do what it was asked to do. `text` says why, because
    /// an agent that reads only "failed" repeats the call.
    pub fn errorResult(_: Context, text: []const u8) Result {
        return .{ .outcome = .failure, .text = text };
    }
};

test "successResult and errorResult differ in outcome and keep their text" {
    // A failure that answered `.success` would let a plugin report a refusal
    // as work done, which the agent then builds on.
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
