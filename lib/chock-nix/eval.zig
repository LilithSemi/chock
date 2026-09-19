//! Nix evaluation inside Chock's own process, through fix rather than through
//! the `nix` binary the rest of this library spawns. Store writes stay off
//! until a caller asks for them, so an engine built here reaches no daemon, no
//! store mount and no network.

const std = @import("std");
const expr = @import("expr");
const store = @import("store");

pub const Options = struct {
    /// Whether `getEnv`, `<nixpkgs>` and out of tree reads are refused.
    pure: bool = true,
    /// The directories a pure evaluation may still read. The store is always
    /// readable.
    roots: []const []const u8 = &.{},
    /// One is the whole engine on the calling thread, which is what a tool
    /// call gets: the phase 2 io of `src/run.zig` cannot start a thread.
    workers: u8 = 1,
    /// The expression can come from a model, and a recursion nobody bounded
    /// is an allocation nobody bounded, in Chock's own process.
    max_call_depth: u32 = default_call_depth,
    /// The bytes of garbage the engine may hold before it collects. Null lets
    /// fix size the line from the machine's own memory.
    ///
    /// Nothing bounds how long an evaluation runs, because fix offers no
    /// deadline to pass on, so an expression that loops without recursing
    /// runs until the process is stopped. That gap is open.
    gc_budget_bytes: ?u64 = null,
    /// What reads a file for `builtins.readFile` and the rest. Null gives an
    /// engine that evaluates but reads nothing.
    io: ?std.Io = null,
    /// Off, and it stays off. fix has a fetcher, and an expression that
    /// reached it would fetch over a socket no rule of this project ever saw,
    /// so the `io` above reaches the file reader and the store and never the
    /// fetcher. A fetch answers `FetchIoUnavailable`. What a flake really
    /// needs is fetched on the host first: see `inputs.zig`.
    network: bool = false,
    /// Off. fix keeps flakes behind the same experimental feature Nix does,
    /// so an evaluation with this off answers `MissingExperimentalFeature`.
    flakes: bool = false,
    /// Where a store operation goes, or null for an engine with no store
    /// behind it at all.
    store_backend: ?store.backend.Driver = null,
    /// Whether the evaluation may put an object in the store behind
    /// `store_backend`. A caller turns it on when the derivation must be
    /// registered through the driver, which is what lets the produced set of
    /// `backend.zig` authorise a build of it.
    store_writes: bool = false,
};

/// fix's own default, read from fix rather than written out a second time.
pub const default_call_depth: u32 = (expr.LanguagePolicy{}).max_call_depth;

pub const Answer = struct {
    /// Rendered the way the repl renders it, borrowed from the buffer the
    /// caller passed to `answer`.
    text: []const u8,
    /// Null for a value that is not a derivation. Borrowed from the session.
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
        language.flakes_enabled = options.flakes;
        language.fetch_tree_enabled = options.flakes;
        engine.configureLanguage(language);

        engine.configureMemory(options.gc_budget_bytes, null, false);
        if (options.io) |io| {
            if (options.network) {
                engine.setFileIo(io);
            } else {
                // The file reader and the store, and never the fetcher.
                engine.sources.files.setIo(io);
                engine.store.realization.setIo(io);
            }
        }
        if (options.store_backend) |driver| try engine.setStoreBackend(driver);
        if (options.store_writes) engine.enableStoreWrites();
        try engine.setPureEval(options.pure, options.roots);
        return .{ .engine = engine };
    }

    pub fn deinit(self: *Session) void {
        self.engine.deinit();
    }

    /// The text is written into `buffer` and borrowed from it.
    pub fn evaluate(self: *Session, buffer: []u8, source: []const u8) ![]const u8 {
        return (try self.answer(buffer, source)).text;
    }

    /// `evaluate`, with the derivation path beside the rendered text. A
    /// derivation renders as its own path and a string renders as a quoted
    /// path, so the text alone cannot tell the two apart.
    pub fn answer(self: *Session, buffer: []u8, source: []const u8) !Answer {
        const value = try self.engine.evaluate(source);
        // Forced first, because a renderer writes `<CODE>` for a thunk it was
        // not asked to force. This is what `nix eval --strict` does. A value
        // that will not force deeply is still rendered: forcing all of a
        // derivation reaches attributes that fail on their own.
        self.engine.forceDeep(value) catch {};
        var writer: std.Io.Writer = .fixed(buffer);
        try self.engine.writeValue(&writer, value);
        return .{
            .text = writer.buffered(),
            // A value that will not force as an attribute set is not a
            // derivation, which is an answer and not a fault.
            .derivation_path = self.engine.derivationDrvPath(value) catch null,
        };
    }

    /// Write the derivation at `drv_path`, and everything it is built from,
    /// through the store backend. This is what puts it in the driver's
    /// produced set, so a build of it is one the driver can authorise.
    /// `Options.store_writes` must be on, or this refuses.
    pub fn ensureDerivation(self: *Session, drv_path: []const u8) !void {
        return self.engine.ensureDerivationClosure(drv_path);
    }

    /// Why the last evaluation failed, in fix's own words. Empty for a
    /// runtime fault rather than a parse fault.
    pub fn writeDiagnostics(self: *const Session, writer: *std.Io.Writer, source: []const u8) !void {
        try self.engine.writeDiagnostics(writer, source, false);
    }
};

const testing = std.testing;

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

test "a nested value comes back rendered, and never as <CODE>" {
    // The repl writes `{ z = <CODE>; }` for an unforced thunk, which answers
    // nothing to a model.
    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "{ z = \"ab\"; }",
        try evaluateText(&buffer, "{ z = \"a\" + \"b\"; }"),
    );
    try testing.expectEqualStrings(
        "{ a = { b = [ 1 2 ]; }; }",
        try evaluateText(&buffer, "{ a = { b = [ 1 (1 + 1) ]; }; }"),
    );
}

test "a derivation path computes with no store behind the engine" {
    // What the eval and build split rests on: an evaluation that asks only
    // what a derivation is needs no daemon, no store mount and no driver.
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
    // in both modes. What purity decides is the filesystem.
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

    // Drop `roots` from the call above and this read is what every path gets.
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

test "an evaluation cannot reach a flake until a caller asks for one" {
    var buffer: [256]u8 = undefined;
    var session = try Session.init(testing.allocator, .{ .io = testing.io });
    defer session.deinit();
    try testing.expectError(
        error.MissingExperimentalFeature,
        session.evaluate(&buffer, "builtins.getFlake \"/work\""),
    );
}

test "an evaluation with a flake cannot open a connection of its own" {
    var buffer: [256]u8 = undefined;

    // fix has a fetcher, this session gives it no io, and a flake reference
    // that would be downloaded stops here.
    var session = try Session.init(testing.allocator, .{ .io = testing.io, .flakes = true });
    defer session.deinit();
    try testing.expectError(
        error.FetchIoUnavailable,
        session.evaluate(&buffer, "builtins.getFlake \"github:NixOS/nixpkgs\""),
    );
}
