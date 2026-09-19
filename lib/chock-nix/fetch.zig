//! Every host a build would reach while it runs, named before it runs.
//!
//! ## Why a fixed output derivation is not safe by itself
//!
//! Nix gives a fixed output derivation's builder the network, because the
//! output hash is checked afterwards. That check is worth something for
//! integrity and nothing at all for egress: a URL of
//! `https://somewhere/?d=<a secret of the workspace>` with the hash of an
//! innocuous file passes the check, and the request already happened. So "it
//! is fixed output, therefore the network is safe" is wrong, and a build that
//! reached the network with no rule consulted was a hole.
//!
//! ## A fetch is a connection
//!
//! There is one egress namespace, `net.connect`, and this library does not
//! build its names: `lib/chock-broker/network.zig` holds the builder, because
//! it holds the label reversal that makes a class rule safe. This file reads
//! the closure and answers a host and a port. The caller names it and asks.
//!
//! A second namespace would need that reversal written and tested again, and
//! would let a project allow a host in one namespace while denying it in the
//! other.
//!
//! ## The closure is read with `nix derivation show`
//!
//! The derivation closure is already in the host store by the time a build is
//! asked for, so it can be read. `nix derivation show -r` answers the whole
//! closure as JSON, through the same `provision.Runner` seam every other
//! command of this library goes through, so a test reads the argument vector
//! and reaches no store.
//!
//! **The alternative was reading the `.drv` files.** fix models a derivation
//! and writes the ATerm form, and it parses none, so that route needs a
//! parser of its own for a format Nix already reads. A parser that disagreed
//! with Nix about one field would name the wrong host, which is the one
//! failure this file must not have.
//!
//! ## What it asks about, and what it over asks
//!
//! Every fixed output derivation of the closure, whether or not its output is
//! in the store already. A derivation whose output is there fetches nothing,
//! so a question about it is a question nobody had to answer. Asking is the
//! safe direction: the store can lose that output between the question and
//! the build, and a reader that skipped it would then have let a fetch
//! through.
//!
//! Hosts are answered once each. One closure can hold twenty derivations that
//! fetch from the same host, and twenty questions with one answer is a person
//! trained to say yes.
//!
//! **A fixed output derivation that says nowhere it fetches from is a
//! refusal.** Some fetchers read their URLs out of a lock file while they
//! build, so they hold no `url` anywhere. The network is open to them and no
//! rule can name what they reach, so they are refused rather than run.
//!
//! **`mirror://` is a refusal too, and nixpkgs writes it.** The real host is
//! chosen from a list of mirrors while the build runs, so the derivation names
//! no host, and a reader that picked one would put a question to the policy
//! about a connection that may never happen while the real one goes unasked.

const std = @import("std");

const provision = @import("provision.zig");

pub const Error = provision.Error;

/// One host a build would reach.
pub const Fetch = struct {
    /// What asked for the host: the derivation that fetches it, or the
    /// input a lock names. Part of every refusal, because a person reading one
    /// wants to know what asked.
    subject: []const u8,
    url: []const u8,
    host: []const u8,
    port: u16,
};

/// A URL of a fixed output derivation that could not be turned into a host
/// and a port.
pub const Unreadable = struct {
    subject: []const u8,
    /// Empty when the derivation carried no URL at all.
    url: []const u8,
    why: Why,

    pub const Why = enum {
        /// A fixed output derivation with no `url` and no `urls`.
        no_url,
        scheme_unknown,
        no_host,
        port_not_a_port,
    };
};

/// What one closure says about the network.
pub const Closure = union(enum) {
    /// One entry per host and port, in the order they were found.
    fetches: []const Fetch,
    /// The first URL this file could not name. **A refusal and never a skip**:
    /// a fetch nobody can name is a fetch nobody can rule on.
    unreadable: Unreadable,
    /// What `nix` wrote when it would not read the closure.
    nix_said: []const u8,
};

pub const UrlError = error{
    UrlSchemeUnknown,
    UrlHasNoHost,
    UrlPortNotAPort,
};

/// Where a URL points.
pub const Target = struct {
    host: []const u8,
    port: u16,
};

/// The host and the port of `url`, both borrowed from it.
///
/// **A scheme this does not know is a refusal and never a guess.** `https` is
/// 443 and `http` is 80. Anything else, `mirror:` and `ftp:` included, has no
/// port this file may invent, and a wrong port would put a question to the
/// policy about a connection that never happens while the real one goes
/// unasked.
pub fn targetOf(url: []const u8) UrlError!Target {
    const mark = std.mem.indexOf(u8, url, "://") orelse return error.UrlSchemeUnknown;
    const scheme = url[0..mark];
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(scheme, "https"))
        443
    else if (std.ascii.eqlIgnoreCase(scheme, "http"))
        80
    else
        return error.UrlSchemeUnknown;

    const rest = url[mark + 3 ..];
    const authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
    // A user name and a password belong to nobody's policy key, and the `@`
    // is what tells the host apart from them.
    const after_user = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at|
        authority[at + 1 ..]
    else
        authority;
    if (after_user.len == 0) return error.UrlHasNoHost;
    // An address in brackets is the one host shape whose colons are not a
    // port boundary. Refused rather than parsed: the action namer takes
    // letters, digits, hyphen and dot, so a name it cannot build is a
    // question nobody can answer.
    if (after_user[0] == '[') return error.UrlHasNoHost;

    if (std.mem.lastIndexOfScalar(u8, after_user, ':')) |colon| {
        const host = after_user[0..colon];
        if (host.len == 0) return error.UrlHasNoHost;
        const port = std.fmt.parseInt(u16, after_user[colon + 1 ..], 10) catch
            return error.UrlPortNotAPort;
        if (port == 0) return error.UrlPortNotAPort;
        return .{ .host = host, .port = port };
    }
    return .{ .host = after_user, .port = default_port };
}

/// Every host the closure of `derivation_path` would reach.
///
/// **Give this an arena**: every string of the answer comes from `allocator`,
/// and so does the JSON `nix` wrote.
pub fn fetchesOf(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    derivation_path: []const u8,
) Error!Closure {
    const shown = try runner.run(allocator, io, &.{
        "derivation",
        "show",
        "-r",
        "--",
        derivation_path,
    });
    if (!shown.succeeded()) return .{ .nix_said = provision.lastLine(shown.stderr) };

    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        shown.stdout,
        .{},
    ) catch return .{ .nix_said = "the derivation closure could not be read as JSON" };
    defer parsed.deinit();

    const listed = derivationsOf(parsed.value) orelse
        return .{ .nix_said = "the derivation closure holds no derivations" };

    var fetches: std.ArrayList(Fetch) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);

    var each = listed.iterator();
    while (each.next()) |entry| {
        const one = entry.value_ptr.*;
        if (one != .object) continue;
        if (!isFixedOutput(one.object)) continue;

        const name = try allocator.dupe(u8, entry.key_ptr.*);
        const urls = try urlsOf(allocator, one.object) orelse return .{ .unreadable = .{
            .subject = name,
            .url = "",
            .why = .no_url,
        } };

        for (urls) |url| {
            const target = targetOf(url) catch |err| return .{ .unreadable = .{
                .subject = name,
                .url = try allocator.dupe(u8, url),
                .why = switch (err) {
                    error.UrlSchemeUnknown => .scheme_unknown,
                    error.UrlHasNoHost => .no_host,
                    error.UrlPortNotAPort => .port_not_a_port,
                },
            } };

            const key = try std.fmt.allocPrint(
                allocator,
                "{s}:{d}",
                .{ target.host, target.port },
            );
            if ((try seen.getOrPut(allocator, key)).found_existing) continue;
            try fetches.append(allocator, .{
                .subject = name,
                .url = try allocator.dupe(u8, url),
                .host = try allocator.dupe(u8, target.host),
                .port = target.port,
            });
        }
    }

    return .{ .fetches = try fetches.toOwnedSlice(allocator) };
}

/// The map of derivations, whichever shape this `nix` wrote.
///
/// Nix 2.36 and later wrap the map in a `derivations` member beside a version
/// number, and every earlier one puts the map at the top. Both are read,
/// because the Nix on a user's machine is theirs and not ours.
fn derivationsOf(root: std.json.Value) ?std.json.ObjectMap {
    if (root != .object) return null;
    if (root.object.get("derivations")) |wrapped| {
        if (wrapped != .object) return null;
        return wrapped.object;
    }
    return root.object;
}

/// True when one output of this derivation carries an output hash, which is
/// what makes a derivation fixed output and what gives its builder the
/// network.
fn isFixedOutput(one: std.json.ObjectMap) bool {
    const outputs = one.get("outputs") orelse return false;
    if (outputs != .object) return false;
    var each = outputs.object.iterator();
    while (each.next()) |entry| {
        const output = entry.value_ptr.*;
        if (output != .object) continue;
        // `hash` is what every Nix writes. `hashAlgo` is there as well on the
        // older shape, and a derivation with one and not the other is still
        // fixed output.
        if (output.object.contains("hash")) return true;
        if (output.object.contains("hashAlgo")) return true;
    }
    return false;
}

/// What the builder will fetch, in the order the derivation writes them, each
/// borrowed from the parsed JSON. Null when it says nowhere it fetches from.
///
/// **Two places hold this, and both are read.** An ordinary derivation puts
/// `url` or `urls` in its environment, where a list is one string joined with
/// spaces. A derivation with structured attributes puts them in
/// `structuredAttrs` instead, where a list is a real JSON array, and its
/// environment then holds only the output names. nixpkgs builds `fetchurl`
/// the second way today, so a reader of the environment alone finds no URL on
/// the very derivation a person asked to build.
fn urlsOf(
    allocator: std.mem.Allocator,
    one: std.json.ObjectMap,
) std.mem.Allocator.Error!?[]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(allocator);

    if (one.get("structuredAttrs")) |attrs| {
        if (attrs == .object) {
            for ([_][]const u8{ "url", "urls" }) |name| {
                const value = attrs.object.get(name) orelse continue;
                switch (value) {
                    .string => |text| try found.append(allocator, text),
                    .array => |items| for (items.items) |item| {
                        if (item == .string) try found.append(allocator, item.string);
                    },
                    else => continue,
                }
                if (found.items.len != 0) return try found.toOwnedSlice(allocator);
            }
        }
    }

    const env = one.get("env") orelse return null;
    if (env != .object) return null;
    for ([_][]const u8{ "url", "urls" }) |name| {
        const value = env.object.get(name) orelse continue;
        if (value != .string) continue;
        var each = std.mem.tokenizeAny(u8, value.string, " \t\n");
        while (each.next()) |url| try found.append(allocator, url);
        if (found.items.len != 0) return try found.toOwnedSlice(allocator);
    }

    found.deinit(allocator);
    return null;
}

/// One sentence for a URL this file could not name. The caller owns it.
pub fn unreadableRefusal(
    allocator: std.mem.Allocator,
    one: Unreadable,
) std.mem.Allocator.Error![]u8 {
    return switch (one.why) {
        .no_url => std.fmt.allocPrint(
            allocator,
            "{s} fetches over the network and says nowhere it fetches from, so no rule can " ++
                "cover it and nothing was built.",
            .{one.subject},
        ),
        .scheme_unknown => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and that is not a scheme this reads. Only http and https can be " ++
                "named as a host and a port, so nothing was built. Use an input that fetches " ++
                "over https.",
            .{ one.subject, one.url },
        ),
        .no_host => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, which names no host this can put to a rule, so nothing was built.",
            .{ one.subject, one.url },
        ),
        .port_not_a_port => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, whose port is not a port, so nothing was built.",
            .{ one.subject, one.url },
        ),
    };
}

/// One sentence for a closure `nix` would not read. The caller owns it.
pub fn closureRefusal(
    allocator: std.mem.Allocator,
    derivation_path: []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "what {s} would fetch could not be read, so nothing was built. Nix said: {s}",
        .{ derivation_path, said },
    );
}

/// Whether one fetch may happen.
pub const Verdict = union(enum) {
    permitted,
    /// Why not, in words the model reads. Borrowed from the allocator the
    /// gate was given.
    refused: []const u8,
};

/// Who answers for a host a build would reach.
///
/// **A seam, because the answer is the policy table's and this library holds
/// no policy.** `src/run.zig` fills it in with the action name
/// `chock_broker.network.actionInto` writes and the arbiter every other
/// mid-call question goes through.
pub const Gate = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        permit: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            one: Fetch,
        ) std.mem.Allocator.Error!Verdict,
    };

    pub fn permit(
        self: Gate,
        allocator: std.mem.Allocator,
        one: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return self.vtable.permit(self.ptr, allocator, one);
    }

    /// The gate a caller that wired none gets. It permits nothing, so a
    /// wiring somebody forgot refuses a build that fetches rather than
    /// letting it reach a host.
    pub const refusing: Gate = .{ .ptr = undefined, .vtable = &refusing_vtable };

    const refusing_vtable: VTable = .{ .permit = refuseFn };

    fn refuseFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return .{ .refused = "this session can ask nobody about a host" };
    }
};

const testing = std.testing;

test "a url becomes a host and a port, and a scheme this does not know is refused" {
    const secure = try targetOf("https://example.com/a/b.tar.gz");
    try testing.expectEqualStrings("example.com", secure.host);
    try testing.expectEqual(@as(u16, 443), secure.port);

    const plain = try targetOf("http://example.com/a");
    try testing.expectEqualStrings("example.com", plain.host);
    try testing.expectEqual(@as(u16, 80), plain.port);

    const named = try targetOf("https://example.com:8443/a?q=1#f");
    try testing.expectEqualStrings("example.com", named.host);
    try testing.expectEqual(@as(u16, 8443), named.port);

    // A user name is not part of the host, so it is not part of the key.
    const with_user = try targetOf("https://someone:secret@example.com/a");
    try testing.expectEqualStrings("example.com", with_user.host);

    // No port this file may invent, so none is invented.
    try testing.expectError(error.UrlSchemeUnknown, targetOf("ftp://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("mirror://gnu/a.tar.gz"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("git+ssh://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("example.com/a"));

    try testing.expectError(error.UrlHasNoHost, targetOf("https:///a/b"));
    try testing.expectError(error.UrlHasNoHost, targetOf("https://[2001:db8::1]/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:http/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:0/a"));
}

/// A `provision.Runner` that answers one reply and records what it was asked.
const FakeRunner = struct {
    gpa: std.mem.Allocator,
    code: u8 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    seen: []const []const u8 = &.{},

    fn deinit(self: *FakeRunner) void {
        for (self.seen) |one| self.gpa.free(one);
        self.gpa.free(self.seen);
    }

    fn runner(self: *FakeRunner) provision.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provision.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        args: []const []const u8,
    ) provision.Error!@import("proc.zig").Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.alloc([]const u8, args.len);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        self.seen = copy;
        return .{
            .term = .{ .exited = self.code },
            .stdout = try allocator.dupe(u8, self.stdout),
            .stderr = try allocator.dupe(u8, self.stderr),
        };
    }
};

/// What `nix derivation show -r` writes for a closure of two derivations, one
/// of which fetches. The shape Nix 2.36 writes, with the map wrapped.
const closure_with_one_fetch =
    \\{"version":4,"derivations":{
    \\ "a-top.drv":{"env":{"name":"top"},"outputs":{"out":{"path":"/nix/store/x-top"}}},
    \\ "b-src.drv":{"env":{"name":"src","url":"https://files.example.com/src.tar.gz"},
    \\  "outputs":{"out":{"hash":"sha256-AAAA","method":"flat"}}}
    \\}}
;

test "a closure that holds a fixed output derivation answers its host and its port" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{ .gpa = gpa, .stdout = closure_with_one_fetch };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-top.drv",
    );

    try testing.expect(closure == .fetches);
    try testing.expectEqual(@as(usize, 1), closure.fetches.len);
    try testing.expectEqualStrings("files.example.com", closure.fetches[0].host);
    try testing.expectEqual(@as(u16, 443), closure.fetches[0].port);
    try testing.expectEqualStrings("b-src.drv", closure.fetches[0].subject);

    // The whole closure and not the one derivation, so an input that fetches
    // is found however deep it is.
    try testing.expectEqualStrings("derivation", fake.seen[0]);
    try testing.expectEqualStrings("show", fake.seen[1]);
    try testing.expectEqualStrings("-r", fake.seen[2]);
    try testing.expectEqualStrings("/nix/store/a-top.drv", fake.seen[4]);
}

test "a closure with no fixed output derivation reaches no host at all" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"a-top.drv":{"env":{"name":"top"},"outputs":{"out":{"path":"/nix/store/x-top"}}},
        \\ "b-dep.drv":{"env":{"name":"dep"},"outputs":{"out":{"path":"/nix/store/y-dep"}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-top.drv",
    );

    try testing.expect(closure == .fetches);
    try testing.expectEqual(@as(usize, 0), closure.fetches.len);
}

test "one host is answered once, however many derivations of the closure fetch it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{
        \\ "a.drv":{"env":{"url":"https://files.example.com/one.tar.gz"},
        \\  "outputs":{"out":{"hash":"sha256-A"}}},
        \\ "b.drv":{"env":{"url":"https://files.example.com/two.tar.gz"},
        \\  "outputs":{"out":{"hash":"sha256-B"}}},
        \\ "c.drv":{"env":{"urls":"https://other.example.org/three https://files.example.com/four"},
        \\  "outputs":{"out":{"hashAlgo":"sha256"}}}
        \\}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a.drv",
    );

    try testing.expect(closure == .fetches);
    try testing.expectEqual(@as(usize, 2), closure.fetches.len);
    try testing.expectEqualStrings("files.example.com", closure.fetches[0].host);
    try testing.expectEqualStrings("other.example.org", closure.fetches[1].host);
}

test "a fetch this cannot name is a refusal, and it names the derivation and the url" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var unknown = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a.drv":{"env":{"url":"ftp://files.example.com/one.tar.gz"},
        \\ "outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer unknown.deinit();

    const bad_scheme = try fetchesOf(arena, testing.io, unknown.runner(), "/nix/store/a.drv");
    try testing.expect(bad_scheme == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, bad_scheme.unreadable.why);

    const said = try unreadableRefusal(gpa, bad_scheme.unreadable);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "a.drv") != null);
    try testing.expect(std.mem.indexOf(u8, said, "ftp://files.example.com") != null);

    var hostless = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"b.drv":{"env":{"url":"https:///one.tar.gz"},
        \\ "outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer hostless.deinit();

    const no_host = try fetchesOf(arena, testing.io, hostless.runner(), "/nix/store/b.drv");
    try testing.expect(no_host == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_host, no_host.unreadable.why);

    // A fixed output derivation that says nowhere it fetches from is the same
    // refusal: the network is open to it and no rule can cover it.
    var silent = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"c.drv":{"env":{"name":"c"},"outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer silent.deinit();

    const no_url = try fetchesOf(arena, testing.io, silent.runner(), "/nix/store/c.drv");
    try testing.expect(no_url == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_url, no_url.unreadable.why);
}

test "a nix that would not read the closure answers its own last line" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .code = 1,
        .stderr = "error: path '/nix/store/a.drv' is not valid",
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a.drv",
    );
    try testing.expect(closure == .nix_said);
    try testing.expect(std.mem.indexOf(u8, closure.nix_said, "is not valid") != null);
}

test "the gate a caller wired none of permits nothing" {
    const answer = try Gate.refusing.permit(testing.allocator, .{
        .subject = "a.drv",
        .url = "https://example.com/a",
        .host = "example.com",
        .port = 443,
    });
    try testing.expect(answer == .refused);
}

test "a derivation with structured attributes holds its urls there, and they are read" {
    // **The shape nixpkgs writes for `fetchurl` today.** Its environment holds
    // the output name and nothing else, and a reader of the environment alone
    // finds no URL on the very derivation a person asked to build. Trimmed
    // from what `nix derivation show` really answers.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a-src.drv":{
        \\ "env":{"out":"/nix/store/x-src"},
        \\ "outputs":{"out":{"hash":"sha256-A","method":"flat"}},
        \\ "structuredAttrs":{"urls":["https://files.example.com/a.tar.gz",
        \\  "https://backup.example.org/a.tar.gz"],"postFetch":""}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-src.drv",
    );

    try testing.expect(closure == .fetches);
    try testing.expectEqual(@as(usize, 2), closure.fetches.len);
    try testing.expectEqualStrings("files.example.com", closure.fetches[0].host);
    try testing.expectEqualStrings("backup.example.org", closure.fetches[1].host);
}

test "a mirror url names no host, so it is a refusal and never a guess" {
    // nixpkgs writes `mirror://gnu/...` and chooses the real host from a list
    // while the build runs. Picking one here would ask about a connection that
    // may never happen while the real one goes unasked.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a-src.drv":{"env":{"out":"/nix/store/x-src"},
        \\ "outputs":{"out":{"hash":"sha256-A","method":"flat"}},
        \\ "structuredAttrs":{"urls":["mirror://gnu/hello/hello-2.12.3.tar.gz"]}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-src.drv",
    );

    try testing.expect(closure == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, closure.unreadable.why);
    try testing.expect(std.mem.indexOf(u8, closure.unreadable.url, "mirror://gnu") != null);
}
