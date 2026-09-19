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
//!
//! **An evaluation runs in Chock's own process, so it is bounded here.**
//! `Options.max_call_depth` stops a runaway recursion and
//! `Options.gc_budget_bytes` is the line the collector defends. **Nothing
//! here bounds wall clock time**, and fix offers no deadline to pass on, so
//! an expression that loops without recursing runs until the process is
//! stopped. That gap is open.

const std = @import("std");
const expr = @import("expr");
const store = @import("store");

/// What one evaluation may see, and how much of the machine it may take.
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
    /// How deep a call may nest before the evaluation stops. The expression
    /// can come from a model, and a recursion nobody bounded is an
    /// allocation nobody bounded, in Chock's own process rather than in a
    /// sandbox.
    max_call_depth: u32 = default_call_depth,
    /// The bytes of garbage the engine may hold before it collects. Null
    /// lets fix size the line from the machine's own memory, which is what a
    /// caller with no number of its own wants.
    ///
    /// **This is a collection line and not a refusal.** It bounds how much is
    /// held at once. Nothing here bounds how long an evaluation runs: see
    /// this file's own top comment.
    gc_budget_bytes: ?u64 = null,
    /// What reads a file for `builtins.readFile` and the rest. Null gives an
    /// engine that evaluates but reads nothing, which every caller that only
    /// computes wants.
    io: ?std.Io = null,
    /// Where a store operation goes, or null for an engine with no store
    /// behind it at all. See `chock-nix/backend.zig`: a driver over a
    /// refusing seam answers every store question with a refusal that names
    /// the path, which is the answer a reader can act on.
    store_backend: ?store.backend.Driver = null,
    /// Whether the evaluation may put an object in the store behind
    /// `store_backend`.
    ///
    /// **Off, because an evaluation that only says what a value is needs no
    /// store at all.** A caller turns it on when the derivation must be
    /// registered through the driver, which is what makes
    /// `chock-nix/backend.zig`'s produced set able to authorise a build of
    /// it. Nothing is written when `store_backend` is null.
    store_writes: bool = false,
};

/// The call depth this library keeps when a caller names none. fix's own
/// default, read from fix rather than written out a second time.
pub const default_call_depth: u32 = (expr.LanguagePolicy{}).max_call_depth;

/// What one evaluation came to.
pub const Answer = struct {
    /// The value rendered the way the repl renders it, borrowed from the
    /// buffer the caller passed to `answer`.
    text: []const u8,
    /// The derivation path, when the value is a derivation, and null for
    /// every other value. Borrowed from the session.
    derivation_path: ?[]const u8 = null,
};

/// One Nix evaluator. Holds every value it answers, so a caller reads what it
/// needs and then calls `deinit`.
pub const Session = struct {
    engine: expr.Engine,

    pub fn init(gpa: std.mem.Allocator, options: Options) !Session {
        var engine = try expr.Engine.init(gpa, .{ .worker_count = options.workers });
        errdefer engine.deinit();

        // Before `setPureEval`, which writes into the same policy record
        // that `configureLanguage` replaces whole.
        var language = engine.languagePolicy();
        language.max_call_depth = options.max_call_depth;
        engine.configureLanguage(language);

        engine.configureMemory(options.gc_budget_bytes, null, false);
        if (options.io) |io| engine.setFileIo(io);
        if (options.store_backend) |driver| try engine.setStoreBackend(driver);
        if (options.store_writes) engine.enableStoreWrites();
        try engine.setPureEval(options.pure, options.roots);
        return .{ .engine = engine };
    }

    pub fn deinit(self: *Session) void {
        self.engine.deinit();
    }

    /// `source` evaluated, and the answer rendered the way the repl renders
    /// it. The text is written into `buffer` and borrowed from it.
    pub fn evaluate(self: *Session, buffer: []u8, source: []const u8) ![]const u8 {
        return (try self.answer(buffer, source)).text;
    }

    /// `evaluate`, with the derivation path beside the rendered text.
    ///
    /// **A derivation renders as its own path and a string renders as a
    /// quoted path**, so a reader cannot tell the two apart from the text.
    /// This says which one it was.
    pub fn answer(self: *Session, buffer: []u8, source: []const u8) !Answer {
        const value = try self.engine.evaluate(source);
        var writer: std.Io.Writer = .fixed(buffer);
        try self.engine.writeValue(&writer, value);
        return .{
            .text = writer.buffered(),
            // A value that renders but will not force as an attribute set is
            // not a derivation, which is an answer and not a fault.
            .derivation_path = self.engine.derivationDrvPath(value) catch null,
        };
    }

    /// Write the derivation at `drv_path`, and everything it is built from,
    /// through the store backend.
    ///
    /// **This is what puts the derivation in the driver's produced set**, so
    /// a build of it is one the driver can authorise. An evaluation alone
    /// computes the path and writes nothing: see this file's own test.
    /// `Options.store_writes` must be on, and the session must have a store
    /// backend, or this refuses.
    pub fn ensureDerivation(self: *Session, drv_path: []const u8) !void {
        return self.engine.ensureDerivationClosure(drv_path);
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

test "a file inside a root is read, and the same file outside every root is not" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    {
        var file = try tmp.dir.createFile(testing.io, "note.txt", .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, "hello");
    }

    var root_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = root_buffer[0..try tmp.dir.realPath(testing.io, &root_buffer)];

    const source = try std.fmt.allocPrint(testing.allocator, "builtins.readFile {s}/note.txt", .{root});
    defer testing.allocator.free(source);

    var buffer: [256]u8 = undefined;
    {
        var session = try Session.init(testing.allocator, .{ .roots = &.{root}, .io = testing.io });
        defer session.deinit();
        try testing.expectEqualStrings("\"hello\"", try session.evaluate(&buffer, source));
    }

    // The same expression, the same file, and no root naming it. Drop `roots`
    // from the call above and the read below is what every path gets.
    var without = try Session.init(testing.allocator, .{ .io = testing.io });
    defer without.deinit();
    try testing.expectError(error.RestrictedInPureEval, without.evaluate(&buffer, source));
}

test "a recursion deeper than the call depth stops rather than taking the process with it" {
    var session = try Session.init(testing.allocator, .{ .max_call_depth = 64 });
    defer session.deinit();

    var buffer: [256]u8 = undefined;
    try testing.expectError(error.CallDepthExceeded, session.evaluate(
        &buffer,
        "let f = n: if n == 0 then 0 else 1 + f (n - 1); in f 10000",
    ));

    // The same expression under the default depth, so the test measures the
    // bound and not the expression.
    var deeper = try Session.init(testing.allocator, .{});
    defer deeper.deinit();
    try testing.expectEqualStrings("1000", try deeper.evaluate(
        &buffer,
        "let f = n: if n == 0 then 0 else 1 + f (n - 1); in f 1000",
    ));
}

test "a derivation answers its path beside the rendered value, and an ordinary value answers none" {
    var session = try Session.init(testing.allocator, .{});
    defer session.deinit();

    var buffer: [256]u8 = undefined;
    const drv = try session.answer(&buffer,
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    try testing.expectEqualStrings("/nix/store/97qlv6h78lxlm9zc8849ahsbcklhsi2y-x.drv", drv.derivation_path.?);

    const plain = try session.answer(&buffer, "{ a = 1; }");
    try testing.expectEqual(@as(?[]const u8, null), plain.derivation_path);
}
