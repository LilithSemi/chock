//! Nix evaluation inside Chock's own process, through fix rather than through

const std = @import("std");
const expr = @import("expr");
const store = @import("store");

pub const Options = struct {
    pure: bool = true,
    roots: []const []const u8 = &.{},
    workers: u8 = 1,
    max_call_depth: u32 = default_call_depth,
    gc_budget_bytes: ?u64 = null,
    io: ?std.Io = null,
    network: bool = false,
    flakes: bool = false,
    store_backend: ?store.backend.Driver = null,
    store_writes: bool = false,
};

pub const default_call_depth: u32 = (expr.LanguagePolicy{}).max_call_depth;

pub const Answer = struct {
    text: []const u8,
    derivation_path: ?[]const u8 = null,
};

pub const Session = struct {
    engine: expr.Engine,

    pub fn init(gpa: std.mem.Allocator, options: Options) !Session {
        var engine = try expr.Engine.init(gpa, .{ .worker_count = options.workers });
        errdefer engine.deinit();

        // Before setPureEval, which writes into the same policy record that configureLanguage replaces whole.
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

    pub fn evaluate(self: *Session, buffer: []u8, source: []const u8) ![]const u8 {
        return (try self.answer(buffer, source)).text;
    }

    pub fn answer(self: *Session, buffer: []u8, source: []const u8) !Answer {
        const value = try self.engine.evaluate(source);
        // Forced first, because a renderer writes <CODE> for a thunk it was not asked to force, the same as nix eval --strict. A value that will not force deeply is still rendered, since forcing all of a derivation reaches attributes that fail on their own.
        self.engine.forceDeep(value) catch {};
        var writer: std.Io.Writer = .fixed(buffer);
        try self.engine.writeValue(&writer, value);
        return .{
            .text = writer.buffered(),
            .derivation_path = self.engine.derivationDrvPath(value) catch null,
        };
    }

    pub fn ensureDerivation(self: *Session, drv_path: []const u8) !void {
        return self.engine.ensureDerivationClosure(drv_path);
    }

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

    var session = try Session.init(testing.allocator, .{ .io = testing.io, .flakes = true });
    defer session.deinit();
    try testing.expectError(
        error.FetchIoUnavailable,
        session.evaluate(&buffer, "builtins.getFlake \"github:NixOS/nixpkgs\""),
    );
}
