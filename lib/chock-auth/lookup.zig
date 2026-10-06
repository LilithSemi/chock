//! Where a credential is looked up, and in which order.

const std = @import("std");
const config = @import("config.zig");
const paths = @import("paths.zig");
const store_mod = @import("store.zig");

pub const Source = enum {
    instance_token,
    instance_token_file,
    token_file,
    login_store,
    none,

    pub fn describe(self: Source) []const u8 {
        return switch (self) {
            .instance_token => "the token written in the configuration file",
            .instance_token_file => "the file the instance's token_file names",
            .token_file => "the token file in the configuration directory",
            .login_store => "the credential store chock login wrote",
            .none => "no credential",
        };
    }
};

pub const Error = std.mem.Allocator.Error || store_mod.Error || error{
    CredentialFileIsReadable,
    TokenFileUnreadable,
    TokenFileInvalid,
};

pub const Diagnostic = union(enum) {
    path_refused: PathRefused,
    token_file_unreadable: TokenFileUnreadable,
    token_file_invalid: config.Diagnostic,
    store_refused: store_mod.Diagnostic,

    pub const PathRefused = struct {
        path: []const u8,
        reason: Reason,

        pub const Reason = union(enum) {
            stat_failed: anyerror,
            readable_by_others: u32,
        };

        fn asPathFault(self: PathRefused) paths.Diagnostic {
            return switch (self.reason) {
                .stat_failed => |err| .{ .stat_failed = .{ .path = self.path, .err = err } },
                .readable_by_others => |mode| .{ .readable_by_others = .{ .path = self.path, .mode = mode } },
            };
        }
    };

    pub const TokenFileUnreadable = struct {
        path: []const u8,
        err: anyerror,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .path_refused => |fault| gpa.free(fault.path),
            .token_file_unreadable => |failure| gpa.free(failure.path),
            .token_file_invalid => |*inner| inner.deinit(gpa),
            .store_refused => |*inner| inner.deinit(gpa),
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .path_refused => |fault| try writer.print("{f}", .{fault.asPathFault()}),
            .token_file_unreadable => |failure| try writer.print(
                "reading the credential file {s} failed: {s}",
                .{ failure.path, @errorName(failure.err) },
            ),
            .token_file_invalid => |*inner| try writer.print("{f}", .{inner}),
            .store_refused => |*inner| try writer.print("{f}", .{inner}),
        }
    }
};

const Sink = struct {
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

fn note(out: ?Sink, value: Diagnostic) bool {
    const sink = out orelse return false;
    if (sink.slot.* != null) return false;
    sink.slot.* = value;
    return true;
}

fn wants(out: ?Sink) bool {
    const sink = out orelse return false;
    return sink.slot.* == null;
}

pub const Resolved = struct {
    gpa: std.mem.Allocator,
    source: Source,
    token: []u8,

    pub fn deinit(self: *Resolved) void {
        std.crypto.secureZero(u8, self.token);
        self.gpa.free(self.token);
        self.* = undefined;
    }
};

pub fn credentialIsMissing(instance: config.Instance, source: Source) bool {
    if (source != .none) return false;
    if (!instance.kind.hostedEndpointNeedsCredential()) return false;
    return sameEndpoint(instance.base_url, instance.kind.defaultBaseUrl());
}

fn sameEndpoint(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, std.mem.trimEnd(u8, left, "/"), std.mem.trimEnd(u8, right, "/"));
}

pub const max_token_file_bytes: usize = 64 * 1024;

pub fn resolve(
    gpa: std.mem.Allocator,
    io: std.Io,
    instance: config.Instance,
    config_dir: []const u8,
    store: store_mod.Store,
    diag: ?*?Diagnostic,
) Error!Resolved {
    const sink = sinkOf(gpa, diag);

    switch (instance.credential) {
        .token => |token| {
            // The mode rule applies to the file the token is written in, not to the token itself, so the check happens here, where a credential is actually read, rather than when the file is parsed.
            const path = try std.fs.path.join(gpa, &.{ config_dir, config.file_name });
            defer gpa.free(path);
            try requirePrivate(io, path, sink);
            return .{ .gpa = gpa, .source = .instance_token, .token = try gpa.dupe(u8, token) };
        },
        .token_file => |path| {
            try requirePrivate(io, path, sink);
            const value = readTokenFile(gpa, io, path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    if (wants(sink)) {
                        _ = note(sink, .{ .token_file_unreadable = .{
                            .path = try gpa.dupe(u8, path),
                            .err = err,
                        } });
                    }
                    return error.TokenFileUnreadable;
                },
            };
            return .{ .gpa = gpa, .source = .instance_token_file, .token = value };
        },
        .absent => {},
    }

    tokens: {
        var token_file_diag: ?config.Diagnostic = null;
        var token_file_diag_owned = true;
        defer if (token_file_diag_owned) {
            if (token_file_diag) |*d| d.deinit(gpa);
        };
        var tokens = config.loadTokens(gpa, io, config_dir, &token_file_diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoConfigFile => break :tokens,
            else => {
                if (token_file_diag) |inner| {
                    if (note(sink, .{ .token_file_invalid = inner })) token_file_diag_owned = false;
                }
                return error.TokenFileInvalid;
            },
        };
        defer tokens.deinit();
        if (tokens.find(instance.name)) |token| {
            return .{ .gpa = gpa, .source = .token_file, .token = try gpa.dupe(u8, token) };
        }
    }

    var store_diag: ?store_mod.Diagnostic = null;
    var store_diag_owned = true;
    defer if (store_diag_owned) {
        if (store_diag) |*d| d.deinit(gpa);
    };
    errdefer if (store_diag) |inner| {
        if (note(sink, .{ .store_refused = inner })) store_diag_owned = false;
    };
    if (try store.get(gpa, io, instance.name, &store_diag)) |found| {
        var stored = found;
        defer stored.deinit();
        return .{ .gpa = gpa, .source = .login_store, .token = try gpa.dupe(u8, stored.token) };
    }

    return .{ .gpa = gpa, .source = .none, .token = try gpa.dupe(u8, "") };
}

fn requirePrivate(io: std.Io, path: []const u8, sink: ?Sink) Error!void {
    var fault: ?paths.Diagnostic = null;
    paths.requirePrivate(io, path, &fault) catch |err| {
        if (fault) |inner| try notePathRefused(sink, path, inner);
        switch (err) {
            error.CredentialFileIsReadable => return error.CredentialFileIsReadable,
            error.CredentialFileMissing, error.StatFailed => return error.TokenFileUnreadable,
        }
    };
}

fn notePathRefused(
    sink: ?Sink,
    path: []const u8,
    fault: paths.Diagnostic,
) std.mem.Allocator.Error!void {
    if (!wants(sink)) return;
    const reason: Diagnostic.PathRefused.Reason = switch (fault) {
        .stat_failed => |failure| .{ .stat_failed = failure.err },
        .readable_by_others => |failure| .{ .readable_by_others = failure.mode },
        .in_the_nix_store, .links_into_the_nix_store => unreachable,
    };
    _ = note(sink, .{ .path_refused = .{
        .path = try sink.?.allocator.dupe(u8, path),
        .reason = reason,
    } });
}

fn readTokenFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const source = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_token_file_bytes));
    defer {
        std.crypto.secureZero(u8, source);
        gpa.free(source);
    }
    return gpa.dupe(u8, std.mem.trimEnd(u8, source, "\r\n"));
}

const testing = std.testing;

const TestSecrets = struct {
    name: []const u8 = "",
    value: []const u8 = "",

    fn secrets(self: *TestSecrets) store_mod.Secrets {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?store_mod.Diagnostic,
    ) store_mod.Error!?[]u8 {
        _ = io;
        _ = diag;
        const self: *TestSecrets = @ptrCast(@alignCast(ptr));
        if (self.name.len == 0 or !std.mem.eql(u8, self.name, name)) return null;
        return try gpa.dupe(u8, self.value);
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?store_mod.Diagnostic,
    ) store_mod.Error!void {
        _ = gpa;
        _ = io;
        _ = diag;
        const self: *TestSecrets = @ptrCast(@alignCast(ptr));
        std.debug.assert(std.mem.eql(u8, self.name, name));
        std.debug.assert(std.mem.eql(u8, self.value, value));
    }

    const vtable = store_mod.Secrets.VTable{ .get = getFn, .put = putFn };
};

fn seedLoginStore(gpa: std.mem.Allocator, store: store_mod.Store, secrets: TestSecrets) !void {
    try store.put(gpa, testing.io, .{
        .name = secrets.name,
        .kind = .aiand,
        .token = secrets.value,
        .stored_ms = 1_700_000_000_000,
    }, null);
}

const Scratch = struct {
    tmp: std.testing.TmpDir,
    config_dir: []u8,
    data_dir: []u8,
    gpa: std.mem.Allocator,

    fn init(gpa: std.mem.Allocator) !Scratch {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const root = buffer[0..len];

        const config_dir = try std.fs.path.join(gpa, &.{ root, "config" });
        errdefer gpa.free(config_dir);
        const data_dir = try std.fs.path.join(gpa, &.{ root, "data" });
        errdefer gpa.free(data_dir);
        try std.Io.Dir.createDirAbsolute(testing.io, config_dir, .fromMode(0o700));
        try std.Io.Dir.createDirAbsolute(testing.io, data_dir, .fromMode(0o700));
        return .{ .tmp = tmp, .config_dir = config_dir, .data_dir = data_dir, .gpa = gpa };
    }

    fn deinit(self: *Scratch) void {
        self.gpa.free(self.config_dir);
        self.gpa.free(self.data_dir);
        self.tmp.cleanup();
    }

    fn write(self: *Scratch, name: []const u8, contents: []const u8, mode: std.posix.mode_t) ![]u8 {
        const path = try std.fs.path.join(self.gpa, &.{ self.config_dir, name });
        errdefer self.gpa.free(path);
        var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, contents);
        try file.setPermissions(testing.io, .fromMode(mode));
        return path;
    }
};

test "the instance beats the token file, and the token file beats the login store" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const config_path = try scratch.write(config.file_name,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand", .token = "sk-from-the-instance" },
        \\    },
        \\}
    , 0o600);
    defer gpa.free(config_path);
    const tokens_path = try scratch.write(config.token_file_name,
        \\.{ .{ .name = "work", .token = "sk-from-the-token-file" } }
    , 0o600);
    defer gpa.free(tokens_path);

    var secrets = TestSecrets{ .name = "work", .value = "sk-from-the-login-store" };
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };
    try seedLoginStore(gpa, store, secrets);

    {
        var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
        defer parsed.deinit();
        var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
        defer resolved.deinit();
        try testing.expectEqual(Source.instance_token, resolved.source);
        try testing.expectEqualStrings("sk-from-the-instance", resolved.token);
    }

    {
        const rewritten = try scratch.write(config.file_name,
            \\.{ .providers = .{ .{ .name = "work", .kind = "aiand" } } }
        , 0o600);
        gpa.free(rewritten);
        var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
        defer parsed.deinit();
        var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
        defer resolved.deinit();
        try testing.expectEqual(Source.token_file, resolved.source);
        try testing.expectEqualStrings("sk-from-the-token-file", resolved.token);
    }

    {
        const rewritten = try scratch.write(config.token_file_name,
            \\.{ .{ .name = "personal", .token = "sk-for-another-account" } }
        , 0o600);
        gpa.free(rewritten);
        var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
        defer parsed.deinit();
        var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
        defer resolved.deinit();
        try testing.expectEqual(Source.login_store, resolved.source);
        try testing.expectEqualStrings("sk-from-the-login-store", resolved.token);
    }
}

test "an instance with no credential anywhere sends none, which is not a failure" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const config_path = try scratch.write(config.file_name,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
        \\    },
        \\}
    , 0o600);
    defer gpa.free(config_path);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();
    var resolved = try resolve(gpa, testing.io, parsed.find("local").?, scratch.config_dir, store, null);
    defer resolved.deinit();

    try testing.expectEqual(Source.none, resolved.source);
    try testing.expectEqualStrings("", resolved.token);
}

test "a token_file resolves, and its trailing newline is not part of the credential" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const secret_path = try scratch.write("decrypted-secret", "sk-from-a-secrets-manager\n", 0o600);
    defer gpa.free(secret_path);

    const source = try std.fmt.allocPrint(gpa,
        \\.{{ .providers = .{{ .{{ .name = "work", .kind = "aiand", .token_file = "{s}" }} }} }}
    , .{secret_path});
    defer gpa.free(source);
    const config_path = try scratch.write(config.file_name, source, 0o600);
    defer gpa.free(config_path);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();
    var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
    defer resolved.deinit();

    try testing.expectEqual(Source.instance_token_file, resolved.source);
    try testing.expectEqualStrings("sk-from-a-secrets-manager", resolved.token);
}

test "a token written in a file others can read is refused, and the same file with 0600 is not" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const wide = try scratch.write(config.file_name,
        \\.{ .providers = .{ .{ .name = "work", .kind = "aiand", .token = "sk-in-a-wide-file" } } }
    , 0o644);
    defer gpa.free(wide);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();
    try testing.expectError(
        error.CredentialFileIsReadable,
        resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null),
    );

    {
        const path = try std.fs.path.join(gpa, &.{ scratch.config_dir, config.file_name });
        defer gpa.free(path);
        var file = try std.Io.Dir.openFileAbsolute(testing.io, path, .{});
        defer file.close(testing.io);
        try file.setPermissions(testing.io, .fromMode(0o600));
    }
    var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
    defer resolved.deinit();
    try testing.expectEqualStrings("sk-in-a-wide-file", resolved.token);
}

test "a configuration file with no credential in it needs no narrow mode" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const path = try scratch.write(config.file_name,
        \\.{ .providers = .{ .{ .name = "work", .kind = "aiand" } } }
    , 0o644);
    defer gpa.free(path);

    var secrets = TestSecrets{ .name = "work", .value = "sk-from-the-login-store" };
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };
    try seedLoginStore(gpa, store, secrets);

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();
    var resolved = try resolve(gpa, testing.io, parsed.find("work").?, scratch.config_dir, store, null);
    defer resolved.deinit();
    try testing.expectEqual(Source.login_store, resolved.source);
}

test {
    testing.refAllDecls(@This());
}

test "the source that refused, and its own reason, reach the caller" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const token_path = try scratch.write("instance-token", "sk-not-a-real-key\n", 0o644);
    defer gpa.free(token_path);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };
    const instance = config.Instance{
        .name = "work",
        .kind = .aiand,
        .base_url = "https://example.invalid/v1",
        .credential = .{ .token_file = token_path },
        .context_tokens = null,
        .capabilities = .{},
    };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.CredentialFileIsReadable,
        resolve(gpa, testing.io, instance, scratch.config_dir, store, &diag),
    );
    try testing.expectEqual(@as(u32, 0o644), diag.?.path_refused.reason.readable_by_others);

    var buffer: [1024]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "has mode 0644") != null);
}

test "the message names the path after the scope that checked it has returned" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const wide = try scratch.write(config.file_name,
        \\.{ .providers = .{ .{ .name = "work", .kind = "aiand", .token = "sk-in-a-wide-file" } } }
    , 0o644);
    defer gpa.free(wide);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(arena);
    {
        var parsed = try config.load(arena, testing.io, scratch.config_dir, null);
        defer parsed.deinit();
        try testing.expectError(
            error.CredentialFileIsReadable,
            resolve(arena, testing.io, parsed.find("work").?, scratch.config_dir, store, &diag),
        );
    }

    var buffer: [2048]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, wide) != null);
    try testing.expect(std.mem.indexOf(u8, line, "chmod 600") != null);
}

test "the diagnostic owns the path it names, and one allocator releases it" {
    var debug: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer testing.expect(debug.deinit() == .ok) catch @panic("a leak");
    const gpa = debug.allocator();

    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();
    const token_path = try scratch.write("instance-token", "sk-not-a-real-key\n", 0o644);
    defer gpa.free(token_path);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };
    const instance = config.Instance{
        .name = "work",
        .kind = .aiand,
        .base_url = "https://example.invalid/v1",
        .credential = .{ .token_file = token_path },
        .context_tokens = null,
        .capabilities = .{},
    };

    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.CredentialFileIsReadable,
        resolve(gpa, testing.io, instance, scratch.config_dir, store, &diag),
    );
    try testing.expectEqualStrings(token_path, diag.?.path_refused.path);
    diag.?.deinit(gpa);
}

test "a hosted instance with no credential is a missing one, and a local endpoint is not" {
    const hosted = config.Instance{
        .name = "work",
        .kind = .aiand,
        .base_url = config.Kind.aiand.defaultBaseUrl(),
        .credential = .absent,
        .context_tokens = null,
        .capabilities = .{},
    };
    try testing.expect(credentialIsMissing(hosted, .none));

    for ([_]Source{ .instance_token, .instance_token_file, .token_file, .login_store }) |source| {
        try testing.expect(!credentialIsMissing(hosted, source));
    }

    var local = hosted;
    local.kind = .openai_compat;
    local.base_url = "http://127.0.0.1:5000/v1";
    try testing.expect(!credentialIsMissing(local, .none));

    var proxied = hosted;
    proxied.base_url = "http://127.0.0.1:8080/v1";
    try testing.expect(!credentialIsMissing(proxied, .none));

    var anthropic = hosted;
    anthropic.kind = .anthropic;
    anthropic.base_url = config.Kind.anthropic.defaultBaseUrl();
    try testing.expect(credentialIsMissing(anthropic, .none));
}

test "the hosted address written out by hand is the same address" {
    const written = config.Instance{
        .name = "work",
        .kind = .aiand,
        .base_url = "https://api.aiand.com/v1/",
        .credential = .absent,
        .context_tokens = null,
        .capabilities = .{},
    };
    try testing.expect(credentialIsMissing(written, .none));
    try testing.expect(sameEndpoint("https://api.aiand.com/v1", "https://api.aiand.com/v1//"));
    try testing.expect(!sameEndpoint("https://api.aiand.com/v1", "https://api.aiand.com/v2"));
}

test "an instance with no credential anywhere is reported as missing, end to end" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const config_path = try scratch.write(config.file_name,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand" },
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
        \\    },
        \\}
    , 0o600);
    defer gpa.free(config_path);

    var secrets = TestSecrets{};
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();

    {
        const instance = parsed.find("work").?;
        var resolved = try resolve(gpa, testing.io, instance, scratch.config_dir, store, null);
        defer resolved.deinit();
        try testing.expectEqual(Source.none, resolved.source);
        try testing.expect(credentialIsMissing(instance, resolved.source));
    }
    {
        const instance = parsed.find("local").?;
        var resolved = try resolve(gpa, testing.io, instance, scratch.config_dir, store, null);
        defer resolved.deinit();
        try testing.expectEqual(Source.none, resolved.source);
        try testing.expect(!credentialIsMissing(instance, resolved.source));
    }
}

test "an instance whose credential the login store holds is not missing" {
    const gpa = testing.allocator;
    var scratch = try Scratch.init(gpa);
    defer scratch.deinit();

    const config_path = try scratch.write(config.file_name,
        \\.{ .providers = .{ .{ .name = "work", .kind = "aiand" } } }
    , 0o600);
    defer gpa.free(config_path);

    var secrets = TestSecrets{ .name = "work", .value = "sk-from-the-login-store" };
    const store = store_mod.Store{ .data_dir = scratch.data_dir, .secrets = secrets.secrets() };
    try seedLoginStore(gpa, store, secrets);

    var parsed = try config.load(gpa, testing.io, scratch.config_dir, null);
    defer parsed.deinit();
    const instance = parsed.find("work").?;
    var resolved = try resolve(gpa, testing.io, instance, scratch.config_dir, store, null);
    defer resolved.deinit();
    try testing.expectEqual(Source.login_store, resolved.source);
    try testing.expect(!credentialIsMissing(instance, resolved.source));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    const sink = sinkOf(testing.allocator, &diag);
    try testing.expect(note(sink, .{ .path_refused = .{
        .path = "/kept",
        .reason = .{ .readable_by_others = 0o644 },
    } }));
    try testing.expect(!note(sink, .{ .token_file_unreadable = .{ .path = "/x", .err = error.IsDir } }));
    try testing.expectEqualStrings("/kept", diag.?.path_refused.path);

    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .token_file_unreadable = .{ .path = "/x", .err = error.IsDir } }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .path_refused = .{ .path = "/x", .reason = .{ .stat_failed = error.AccessDenied } } },
        .{ .path_refused = .{ .path = "/x", .reason = .{ .readable_by_others = 0o644 } } },
        .{ .token_file_unreadable = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .token_file_invalid = .not_a_struct_literal },
        .{ .store_refused = .{ .credential_file_not_valid = "/y" } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
