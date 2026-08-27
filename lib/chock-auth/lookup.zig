//! Where a credential is looked up, and in which order.
//!
//! | | Path | Owner |
//! |---|---|---|
//! | 1. the instance's own `token` or `token_file` | the configuration directory | the user, or home-manager |
//! | 2. a separate token file, name to token | the configuration directory | the user, always |
//! | 3. what `chock login` wrote | the data directory | **Chock, always** |
//!
//! **First match wins, and a lookup that finds nothing sends no credential.**
//! That last case is not a failure. It is what a local llama.cpp server
//! needs, and it is the reason there is no `none` spelling and no placeholder
//! string pretending to be a secret: an instance that says nothing about a
//! credential and has none stored simply sends none.

const std = @import("std");
const config = @import("config.zig");
const paths = @import("paths.zig");
const store_mod = @import("store.zig");

/// Which of the three sources answered. Reported so `chock run` can say
/// where a credential came from without ever printing the credential.
pub const Source = enum {
    instance_token,
    /// The instance's own `token_file`, read at run time. This is how
    /// sops-nix and agenix work.
    instance_token_file,
    token_file,
    login_store,
    /// Nothing named a credential and nothing was stored, so the request
    /// carries none. Not a failure: see this file's own top comment.
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
    /// A file that holds a credential can be read by somebody other than its
    /// owner. Pass a `Diagnostic` to learn the mode that was found.
    CredentialFileIsReadable,
    /// The path an instance's `token_file` names could not be read. Pass a
    /// `Diagnostic` to learn why.
    TokenFileUnreadable,
    /// The separate token file exists and is not valid. Pass a `Diagnostic`
    /// to learn why.
    TokenFileInvalid,
};

/// Why a credential could not be resolved.
///
/// Three of the variants pass a fault through from the reader that found it,
/// because a lookup walks three sources and the source that refused is the
/// fact a reader needs.
///
/// **Every string this carries is owned, and one allocator holds all of
/// them**: the one `resolve` was given, which is the one `deinit` takes. A
/// lookup releases each path it checks on its way out, and a person reads the
/// message after that, so a borrowed path here named freed memory. The mode
/// fault is the one a person is meant to act on, and it asked them to `chmod`
/// a path made of dead bytes.
pub const Diagnostic = union(enum) {
    /// The mode rule refused one of the three sources.
    path_refused: PathRefused,
    /// The path an instance's `token_file` names could not be read.
    token_file_unreadable: TokenFileUnreadable,
    /// The separate token file in the configuration directory is not valid.
    token_file_invalid: config.Diagnostic,
    /// The credential store refused. See `chock_auth.store.Diagnostic`.
    store_refused: store_mod.Diagnostic,

    /// The mode rule's own fault, over this module's own copy of the path.
    pub const PathRefused = struct {
        /// **Owned**, and released by `deinit`.
        path: []const u8,
        reason: Reason,

        /// Which of the two answers `paths.requirePrivate` gives, with the
        /// fact each one carries. The path is not repeated here: it is the
        /// same path either way, and one field cannot then disagree with the
        /// other.
        pub const Reason = union(enum) {
            /// The file is there and could not be inspected.
            stat_failed: anyerror,
            /// Somebody other than the owner can read it, at this mode.
            readable_by_others: u32,
        };

        /// The same fault in `paths.Diagnostic`'s own shape. **It borrows
        /// this value**, so it lives only as long as the call that renders
        /// it: the words of the mode rule stay in the module that owns the
        /// rule.
        fn asPathFault(self: PathRefused) paths.Diagnostic {
            return switch (self.reason) {
                .stat_failed => |err| .{ .stat_failed = .{ .path = self.path, .err = err } },
                .readable_by_others => |mode| .{ .readable_by_others = .{ .path = self.path, .mode = mode } },
            };
        }
    };

    pub const TokenFileUnreadable = struct {
        /// **Owned**: `token_file` points into a `Config` the caller can
        /// release before it reads this.
        path: []const u8,
        err: anyerror,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    ///
    /// **Every variant is named here, and there is no `else`.** A variant
    /// added later must say whether it owns memory before this file compiles
    /// again, which is the check a borrowed path escaped.
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

/// Where a fault goes, and who owns what it points at.
///
/// **The allocator travels with the slot**, the shape
/// `lib/chock-nix/diagnostic.zig` settled. The site that copies a path and the
/// site that releases it are in different files, and naming the owner once,
/// beside the slot, is what keeps the two the same allocator.
const Sink = struct {
    /// Holds every string the diagnostic carries. The caller passes the same
    /// one to `Diagnostic.deinit`.
    allocator: std.mem.Allocator,
    slot: *?Diagnostic,
};

/// The sink for the caller's own slot, owned by the allocator it passed to
/// the same call. Null in, null out, and a caller that wants no diagnostic
/// then pays no allocation at all.
fn sinkOf(allocator: std.mem.Allocator, out: ?*?Diagnostic) ?Sink {
    const slot = out orelse return null;
    return .{ .allocator = allocator, .slot = slot };
}

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A lookup walks three sources in
/// order and stops at the first refusal, so the first is also the only one.
/// The rule is kept anyway, because a caller may reuse one slot.
///
/// The answer matters because every variant owns memory: a site that hands one
/// over must release it itself when the answer is false.
fn note(out: ?Sink, value: Diagnostic) bool {
    const sink = out orelse return false;
    if (sink.slot.* != null) return false;
    sink.slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy a path for it. See
/// `chock_auth.store.wantsDiagnostic`.
fn wants(out: ?Sink) bool {
    const sink = out orelse return false;
    return sink.slot.* == null;
}

/// The credential an instance uses, and which source gave it.
pub const Resolved = struct {
    gpa: std.mem.Allocator,
    source: Source,
    /// Empty exactly when `source` is `.none`. A caller sends no
    /// `Authorization` header for an empty token.
    token: []u8,

    pub fn deinit(self: *Resolved) void {
        std.crypto.secureZero(u8, self.token);
        self.gpa.free(self.token);
        self.* = undefined;
    }
};

/// Whether an instance that resolved to `.none` cannot work at all, so a
/// caller must refuse before it builds anything.
///
/// **`.none` holds two facts and the configuration cannot tell them apart.**
/// One is "this endpoint asks for nothing", which is what a local llama.cpp
/// server needs and why `.none` is not an error. The other is "one was needed
/// and none was found", which is a session that builds a workspace, opens a
/// log, and possibly unpacks a container image, and then dies on the
/// provider's own 401. A person then reads a failed session and a log full of
/// setup, and learns from the provider's words, not Chock's, that Chock never
/// had a key.
///
/// So this reads the one thing the configuration does know: **the address the
/// instance talks to**. True only when the instance still talks to its kind's
/// own hosted address, which is an address that refuses every request that
/// carries no credential. An `anthropic` instance pointed at a local proxy
/// keeps running keyless, exactly as it does today, because nothing here
/// knows that proxy needs a key. That case falls back to the 401, which is
/// the behaviour it already had, so this adds no refusal a working setup
/// could hit.
///
/// This answers a question and never a fault, so it allocates nothing and has
/// no diagnostic: there is no string for a caller to own or release.
pub fn credentialIsMissing(instance: config.Instance, source: Source) bool {
    if (source != .none) return false;
    if (!instance.kind.hostedEndpointNeedsCredential()) return false;
    return sameEndpoint(instance.base_url, instance.kind.defaultBaseUrl());
}

/// Whether two base URLs name one endpoint. A trailing slash is the one
/// difference between the spelling `Kind.defaultBaseUrl` holds and the same
/// address written out by hand, so it is the one difference this folds.
/// Anything else is a different address, and a different address is one this
/// module knows nothing about.
fn sameEndpoint(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, std.mem.trimEnd(u8, left, "/"), std.mem.trimEnd(u8, right, "/"));
}

/// The largest credential file this reader accepts. A token is a short
/// string, so this bounds a `token_file` that names something else entirely,
/// for example a disk image, rather than a hostile author: the paths here all
/// belong to the user already.
pub const max_token_file_bytes: usize = 64 * 1024;

/// Resolve the credential for `instance`, in the order this file's own top
/// comment gives.
///
/// `config_dir` is where sources 1 and 2 live, and `store` is source 3.
/// Every source is mode checked before it is read.
pub fn resolve(
    gpa: std.mem.Allocator,
    io: std.Io,
    instance: config.Instance,
    config_dir: []const u8,
    store: store_mod.Store,
    diag: ?*?Diagnostic,
) Error!Resolved {
    const sink = sinkOf(gpa, diag);

    // Source 1: what the instance says about itself.
    switch (instance.credential) {
        .token => |token| {
            // The mode rule applies to the file the token is written in, not
            // to the token. A configuration file with no credential in it
            // needs no such mode, so the check happens here, where a
            // credential is actually being read, and not when the file is
            // parsed.
            const path = try std.fs.path.join(gpa, &.{ config_dir, config.file_name });
            defer gpa.free(path);
            // The mode fault takes its own copy of `path`, which this scope
            // releases. A caller reads the message after that.
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

    // Source 2: the separate token file a person maintains.
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

    // Source 3: what `chock login` wrote.
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

    // Nothing anywhere. Send none, which is what a local server wants.
    return .{ .gpa = gpa, .source = .none, .token = try gpa.dupe(u8, "") };
}

/// The mode rule, with the fault passed through to `sink`. **`path` is only
/// read here**: what lands in the sink is a copy, so `path` may be released as
/// soon as this returns.
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

/// Turn the borrowing diagnostic `paths.requirePrivate` fills into the owning
/// one this module hands its callers, the same way
/// `chock_auth.store.noteNixStore` does for the write rule.
fn notePathRefused(
    sink: ?Sink,
    path: []const u8,
    fault: paths.Diagnostic,
) std.mem.Allocator.Error!void {
    if (!wants(sink)) return;
    const reason: Diagnostic.PathRefused.Reason = switch (fault) {
        .stat_failed => |failure| .{ .stat_failed = failure.err },
        .readable_by_others => |failure| .{ .readable_by_others = failure.mode },
        // `paths.requirePrivate` fills neither of these. They belong to the
        // write rule, which reads no credential.
        .in_the_nix_store, .links_into_the_nix_store => unreachable,
    };
    _ = note(sink, .{ .path_refused = .{
        .path = try sink.?.allocator.dupe(u8, path),
        .reason = reason,
    } });
}

/// Read a whole token file and take the line ending off. `sops-nix` and
/// `agenix` both write a decrypted secret with a trailing newline, and a
/// bearer token with a newline in it is a header a provider refuses with no
/// useful message.
fn readTokenFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    // The fault goes back as an error and `resolve` turns it into the
    // diagnostic, because `resolve` is the one place that knows whether its
    // own caller asked for one.
    const source = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_token_file_bytes));
    defer {
        std.crypto.secureZero(u8, source);
        gpa.free(source);
    }
    return gpa.dupe(u8, std.mem.trimEnd(u8, source, "\r\n"));
}

const testing = std.testing;

/// A store whose driver keeps one value in memory, so these tests exercise
/// the lookup order and not a platform driver. `name` and `value` are set by
/// the test and are borrowed, never owned: nothing here is ever replaced, so
/// there is nothing to free.
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
        // The pair is already on this fixture. This only checks that
        // `Store.put` asked for the one the test meant to seed, so a mistake
        // in a test shows up here rather than as a lookup that silently found
        // nothing.
        std.debug.assert(std.mem.eql(u8, self.name, name));
        std.debug.assert(std.mem.eql(u8, self.value, value));
    }

    const vtable = store_mod.Secrets.VTable{ .get = getFn, .put = putFn };
};

/// Seed the login store, source 3, the way `chock login` would: an index
/// entry as well as a value. `Store.get` reads the index first, so a test
/// that only set the driver's value would be testing a store state
/// `chock login` cannot produce.
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
    // The check that makes an inline token safe. A home-manager generated
    // configuration file is a symbolic link into the world readable Nix
    // store, so this is the check that catches it.
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

    // The same file, narrowed, resolves. Without this half the test above
    // would pass against a version that refused every configuration file.
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
    // The mode rule is about a file that holds a credential. A user whose
    // providers all use `token_file` or the login store keeps an ordinary
    // 0644 configuration file, and Chock must not refuse it.
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
    // What `chock run` does, allocator and all: `src/run.zig` resolves out of
    // the process arena and formats the fault after `resolve` has returned.
    // The path a mode fault names is joined inside `resolve` and released on
    // the way out, so a diagnostic that pointed at it read whatever the
    // allocator left behind: measured as a `chmod 600` over dead bytes, which
    // is a security message a person cannot act on.
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
    // The other half of the test above, and the half that fails loudly. This
    // allocator poisons what it frees and refuses a free of memory it did not
    // hand out, so a diagnostic that borrowed the path `resolve` releases is
    // a free of a freed pointer here rather than a message nobody checks.
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
    // The fault this answers: `.none` is not an error, so a session with no
    // key used to build a workspace and a log and then die on the provider's
    // 401, at the same exit code as every other failure.
    const hosted = config.Instance{
        .name = "work",
        .kind = .aiand,
        .base_url = config.Kind.aiand.defaultBaseUrl(),
        .credential = .absent,
        .context_tokens = null,
        .capabilities = .{},
    };
    try testing.expect(credentialIsMissing(hosted, .none));

    // A credential was found, so nothing is missing whatever the address is.
    for ([_]Source{ .instance_token, .instance_token_file, .token_file, .login_store }) |source| {
        try testing.expect(!credentialIsMissing(hosted, source));
    }

    // The case `.none` exists for. A local server needs no key, and refusing
    // this would break the setup this project develops against.
    var local = hosted;
    local.kind = .openai_compat;
    local.base_url = "http://127.0.0.1:5000/v1";
    try testing.expect(!credentialIsMissing(local, .none));

    // A kind with a hosted address of its own, pointed somewhere else. Chock
    // knows nothing about that address, so it does not refuse: the session
    // behaves as it did before this check existed.
    var proxied = hosted;
    proxied.base_url = "http://127.0.0.1:8080/v1";
    try testing.expect(!credentialIsMissing(proxied, .none));

    // Anthropic is the other hosted kind, and it must not be left out.
    var anthropic = hosted;
    anthropic.kind = .anthropic;
    anthropic.base_url = config.Kind.anthropic.defaultBaseUrl();
    try testing.expect(credentialIsMissing(anthropic, .none));
}

test "the hosted address written out by hand is the same address" {
    // A person who spells `.base_url` themselves rather than leaving it out
    // must get the same answer, trailing slash and all. Without this the
    // refusal is one a user can turn off by retyping the default.
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
    // The half above is a predicate over a literal. This one runs the real
    // lookup, over a real configuration file with nothing in any of the three
    // sources, and checks that the pair says what `chock run` acts on.
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
    // The other half of the test above, and the one that fails if the check
    // ever refuses a session that has a key. Source 3 is the one `chock login`
    // writes, so this is the ordinary logged in case.
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

    // A caller that asked for no diagnostic must reach no store at all. The
    // false answer is what tells an owning site to release what it holds
    // rather than leak it into a slot that does not exist.
    try testing.expect(sinkOf(testing.allocator, null) == null);
    try testing.expect(!note(null, .{ .token_file_unreadable = .{ .path = "/x", .err = error.IsDir } }));
    try testing.expect(!wants(null));
    try testing.expect(!wants(sink));
}

test "no two faults of this module read the same" {
    // Three of the four pass a fault through from the reader that found it,
    // so each renders that reader's own words.
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
