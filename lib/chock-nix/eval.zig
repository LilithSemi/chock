//! Nix evaluation inside Chock's own process, through fix rather than through
//! the `nix` binary the rest of this library spawns.
//!
//! **An evaluation needs nothing from the host.** Store writes stay off until
//! a caller asks for them, so an engine built here reaches no daemon, no
//! store mount and no network. Even a derivation's own path is computed, not
//! looked up: see this file's own test. What needs the host is a build, and a
//! build is brokered rather than done here.
//!
//! **Pure evaluation is the default, and the roots are the flake's own source
//! tree.** Impure evaluation reads the environment and any path on the
//! machine, which is the whole surface Chock exists to close, so a caller
//! that wants it says so and names what it may read.

const std = @import("std");
const expr = @import("expr");

/// What one evaluation may see.
pub const Options = struct {
    /// Whether `getEnv`, `<nixpkgs>` and out of tree reads are refused.
    pure: bool = true,
    /// The directories a pure evaluation may still read, which is the source
    /// tree of the flake being evaluated. The store is always readable.
    roots: []const []const u8 = &.{},
    /// How many threads the evaluator may use. One is the whole engine on the
    /// calling thread, which is what a tool call inside a sandbox gets: see
    /// `src/run.zig`, whose phase 2 io cannot start a thread.
    workers: u8 = 1,
};

/// One Nix evaluator. Holds every value it answers, so a caller reads what it
/// needs and then calls `deinit`.
pub const Session = struct {
    engine: expr.Engine,

    pub fn init(gpa: std.mem.Allocator, options: Options) !Session {
        var engine = try expr.Engine.init(gpa, .{ .worker_count = options.workers });
        errdefer engine.deinit();
        try engine.setPureEval(options.pure, options.roots);
        return .{ .engine = engine };
    }

    pub fn deinit(self: *Session) void {
        self.engine.deinit();
    }

    /// `source` evaluated, and the answer rendered the way the repl renders
    /// it. The text is written into `buffer` and borrowed from it.
    pub fn evaluate(self: *Session, buffer: []u8, source: []const u8) ![]const u8 {
        const value = try self.engine.evaluate(source);
        var writer: std.Io.Writer = .fixed(buffer);
        try self.engine.writeValue(&writer, value);
        return writer.buffered();
    }

    /// Why the last evaluation failed, in fix's own words, written into
    /// `writer`. Empty when nothing was recorded, which is what a runtime
    /// fault rather than a parse fault leaves behind.
    pub fn writeDiagnostics(self: *const Session, writer: *std.Io.Writer, source: []const u8) !void {
        try self.engine.writeDiagnostics(writer, source, false);
    }
};

const testing = std.testing;

/// `source` through a whole session, for a test that asks about the answer
/// and not about the engine.
fn evaluateText(buffer: []u8, source: []const u8) ![]const u8 {
    var session = try Session.init(testing.allocator, .{});
    defer session.deinit();
    return session.evaluate(buffer, source);
}

test "an expression evaluates in this process, with no nix binary" {
    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings("2", try evaluateText(&buffer, "1 + 1"));
    try testing.expectEqualStrings(
        "{ a = 1; b = \"two\"; }",
        try evaluateText(&buffer, "{ a = 1; b = \"two\"; }"),
    );
}

test "a derivation path computes with no store behind the engine" {
    // The fact the eval and build split rests on. Store writes are off until
    // a caller enables them, so an evaluation that asks only what a
    // derivation is needs no daemon, no store mount and no backend driver.
    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "\"/nix/store/97qlv6h78lxlm9zc8849ahsbcklhsi2y-x.drv\"",
        try evaluateText(&buffer,
            \\(derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }).drvPath
        ),
    );
}

test "a pure evaluation cannot read the environment, and cannot read a path outside its roots" {
    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings("\"\"", try evaluateText(&buffer, "builtins.getEnv \"PATH\""));

    // An engine is given no environment map either way, so `getEnv` is empty
    // in both modes. What purity really decides is the filesystem: a path
    // outside every root is refused rather than read.
    var session = try Session.init(testing.allocator, .{});
    defer session.deinit();
    try testing.expectError(error.RestrictedInPureEval, session.evaluate(&buffer, "builtins.readFile /etc/hostname"));
}
