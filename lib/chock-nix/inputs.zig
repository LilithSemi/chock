//! A flake's inputs are fetched on the host, once, before anything evaluates.
//!
//! ## Why the fetch cannot happen inside the evaluator
//!
//! `lib/chock-nix/eval.zig` runs fix in Chock's own process. fix can fetch a
//! flake input for itself, over its own connection, and no rule of this
//! project would see it. So the evaluator is given no fetcher at all, and a
//! flake input reaches it one way: it is already in the host store when the
//! evaluation starts.
//!
//! fix reads it from there. A locked input carries a `narHash`, the store
//! path of a fetched input is that hash, and fix takes the path when the store
//! says it is valid rather than downloading the tree again. `nix flake
//! archive` is what puts it there. Both halves are pinned in
//! `test/nix/real.zig`, because both are claims about somebody else's code.
//!
//! ## The lock is a file of the project, so it is read as one
//!
//! `flake.lock` sits in the project directory beside `chock.zon`, and this
//! project reads a file there as something an attacker may have written. So
//! every host the lock names goes to the same `fetch.Gate` a build's own
//! fetches go to, and a host nobody permitted stops the fetch. One question
//! per host, whatever number of inputs share it.
//!
//! **A node whose host cannot be named is a refusal**, the rule
//! `lib/chock-nix/fetch.zig` already keeps. An `indirect` node names a
//! registry rather than a host, an `ssh` URL is not a scheme this can turn
//! into a host and a port, and a guess would put a question to the policy
//! about a connection that never happens while the real one goes unasked.
//!
//! **A forge node names no URL, so the host comes from the type.** `github`
//! with no `host` of its own is fetched from `api.github.com`, which redirects
//! to `codeload.github.com`, so both are named and both are asked about.
//! `gitlab` is `gitlab.com` and `sourcehut` is `git.sr.ht`. A node with a
//! `host` of its own names that one and nothing else.
//!
//! ## A session whose inputs did not arrive still starts
//!
//! Nothing else a session start does refuses the session because an optional
//! thing was missing, and a project with no flake at all is the ordinary case.
//! What this owes instead is a later failure somebody can act on: `refusal`
//! writes the sentence a build reads when it wanted an input this session does
//! not have, and it names the input and the host it would have come from.

const std = @import("std");

const fetch = @import("fetch.zig");
const provision = @import("provision.zig");

pub const Error = provision.Error;

/// The longest `flake.lock` this reads. A lock for a flake with many inputs is
/// a few hundred kilobytes.
pub const max_lock_bytes: usize = 4 << 20;

/// The most nodes one lock may hold. A real lock holds tens.
pub const max_nodes: usize = 1024;

/// Why a lock node could not be turned into a host and a port.
pub const Unreadable = struct {
    /// The node the lock calls it.
    input: []const u8,
    /// What the node says it is, or its URL when it has one. Empty when the
    /// node carries neither.
    reference: []const u8,
    why: Why,

    pub const Why = enum {
        /// The node holds no `locked` object, or no `type` in it.
        not_a_node,
        /// A type this file will not turn into a host: `indirect`, which names
        /// a registry rather than a host, and anything nobody has taught it.
        type_unknown,
        /// A node of a type that fetches, with no `url` to fetch.
        no_url,
        scheme_unknown,
        no_host,
        port_not_a_port,
    };
};

/// What one lock says about the network.
pub const Wants = union(enum) {
    /// One entry per host and port, in the order they were found.
    hosts: []const fetch.Fetch,
    /// The first node this file could not name. **A refusal and never a
    /// skip**: a fetch nobody can name is a fetch nobody can rule on.
    unreadable: Unreadable,
    /// Why the bytes are not a lock at all.
    not_a_lock: []const u8,
};

/// Every host the inputs of `lock_bytes` would be fetched from.
///
/// **Give this an arena**: every string of the answer comes from `allocator`,
/// and so does the parsed JSON.
pub fn wantsOf(allocator: std.mem.Allocator, lock_bytes: []const u8) std.mem.Allocator.Error!Wants {
    if (lock_bytes.len > max_lock_bytes) return .{ .not_a_lock = "the lock file is too long to read" };

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, lock_bytes, .{}) catch
        return .{ .not_a_lock = "the lock file is not JSON" };
    defer parsed.deinit();

    if (parsed.value != .object) return .{ .not_a_lock = "the lock file is not an object" };
    const nodes_value = parsed.value.object.get("nodes") orelse
        return .{ .not_a_lock = "the lock file names no nodes" };
    if (nodes_value != .object) return .{ .not_a_lock = "the lock file names no nodes" };
    const nodes = nodes_value.object;
    if (nodes.count() > max_nodes) return .{ .not_a_lock = "the lock file holds more nodes than this reads" };

    const root_name = if (parsed.value.object.get("root")) |one|
        (if (one == .string) one.string else "root")
    else
        "root";

    var found: std.ArrayList(fetch.Fetch) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);

    var each = nodes.iterator();
    while (each.next()) |entry| {
        const name = entry.key_ptr.*;
        // The root node is the flake itself. It has no `locked` reference to
        // fetch, because it is the tree the lock lives in.
        if (std.mem.eql(u8, name, root_name)) continue;

        const targets = switch (try targetsOf(allocator, name, entry.value_ptr.*)) {
            .targets => |list| list,
            .nothing => continue,
            .unreadable => |one| return .{ .unreadable = one },
        };
        for (targets) |one| {
            const key = try std.fmt.allocPrint(allocator, "{s}:{d}", .{ one.host, one.port });
            if ((try seen.getOrPut(allocator, key)).found_existing) continue;
            try found.append(allocator, one);
        }
    }

    return .{ .hosts = try found.toOwnedSlice(allocator) };
}

/// What one node of a lock wants.
const Targets = union(enum) {
    targets: []const fetch.Fetch,
    /// A node that fetches nothing, which is what a `path` node is.
    nothing,
    unreadable: Unreadable,
};

fn targetsOf(
    allocator: std.mem.Allocator,
    name: []const u8,
    node: std.json.Value,
) std.mem.Allocator.Error!Targets {
    if (node != .object) return .{ .unreadable = .{ .input = name, .reference = "", .why = .not_a_node } };
    const locked = node.object.get("locked") orelse
        return .{ .unreadable = .{ .input = name, .reference = "", .why = .not_a_node } };
    if (locked != .object) return .{ .unreadable = .{ .input = name, .reference = "", .why = .not_a_node } };

    const kind = stringOf(locked.object, "type") orelse
        return .{ .unreadable = .{ .input = name, .reference = "", .why = .not_a_node } };

    // A tree that is already a path on this machine is not fetched at all.
    if (std.mem.eql(u8, kind, "path")) return .nothing;

    var forge_buffer: [2][]const u8 = undefined;
    if (forgeHosts(kind, stringOf(locked.object, "host"), &forge_buffer)) |hosts| {
        const list = try allocator.alloc(fetch.Fetch, hosts.len);
        for (hosts, list) |host, *slot| slot.* = .{
            .subject = try allocator.dupe(u8, name),
            .url = try std.fmt.allocPrint(allocator, "https://{s}", .{host}),
            .host = try allocator.dupe(u8, host),
            .port = 443,
        };
        return .{ .targets = list };
    }

    if (!fetchesByUrl(kind)) return .{
        .unreadable = .{ .input = name, .reference = try allocator.dupe(u8, kind), .why = .type_unknown },
    };

    const url = stringOf(locked.object, "url") orelse return .{
        .unreadable = .{ .input = name, .reference = try allocator.dupe(u8, kind), .why = .no_url },
    };
    // `git+https://…` and `hg+https://…` are one transport written in front of
    // one URL. `fetch.targetOf` takes the prefix off, so the strip lives in
    // one place and a lock node and a derivation read the same URL the same
    // way.
    const target = fetch.targetOf(url) catch |err| return .{ .unreadable = .{
        .input = name,
        .reference = try allocator.dupe(u8, url),
        .why = switch (err) {
            error.UrlSchemeUnknown => .scheme_unknown,
            error.UrlHasNoHost => .no_host,
            error.UrlPortNotAPort => .port_not_a_port,
        },
    } };

    const one = try allocator.alloc(fetch.Fetch, 1);
    one[0] = .{
        .subject = try allocator.dupe(u8, name),
        .url = try allocator.dupe(u8, url),
        .host = try allocator.dupe(u8, target.host),
        .port = target.port,
    };
    return .{ .targets = one };
}

/// The hosts a forge node is fetched from, or null when `kind` is not a forge.
///
/// `github` with no host of its own is fetched from the API host, which
/// redirects to the download host, so both are named. A node that states a
/// host states the whole answer.
fn forgeHosts(
    kind: []const u8,
    host: ?[]const u8,
    buffer: *[2][]const u8,
) ?[]const []const u8 {
    const github = std.mem.eql(u8, kind, "github");
    const gitlab = std.mem.eql(u8, kind, "gitlab");
    const sourcehut = std.mem.eql(u8, kind, "sourcehut");
    if (!github and !gitlab and !sourcehut) return null;
    if (host) |named| {
        if (named.len != 0) {
            buffer[0] = named;
            return buffer[0..1];
        }
    }
    if (github) {
        buffer[0] = "api.github.com";
        buffer[1] = "codeload.github.com";
        return buffer[0..2];
    }
    buffer[0] = if (gitlab) "gitlab.com" else "git.sr.ht";
    return buffer[0..1];
}

/// True when a node of this type carries the URL it is fetched from.
fn fetchesByUrl(kind: []const u8) bool {
    for ([_][]const u8{ "tarball", "file", "git", "mercurial" }) |one| {
        if (std.mem.eql(u8, kind, one)) return true;
    }
    return false;
}

fn stringOf(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const value = object.get(name) orelse return null;
    if (value != .string) return null;
    return value.string;
}

/// What one fetch of a flake's inputs came to.
pub const Answer = union(enum) {
    /// Every store path the fetch put there: the flake's own tree and every
    /// input of it, at every depth.
    fetched: []const []const u8,
    /// Why nothing was fetched, in one sentence a person and a model both
    /// read.
    refused: []const u8,
};

/// Fetch every input of `reference` into the host store, after the gate has
/// answered for every host `lock_bytes` names.
///
/// **On the host, outside every sandbox**, the same place the rest of this
/// library runs `nix`. **Give it an arena.**
pub fn fetchAll(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    gate: fetch.Gate,
    reference: []const u8,
    lock_bytes: []const u8,
) Error!Answer {
    switch (try wantsOf(allocator, lock_bytes)) {
        // One call for every host the lock names, the same way a build puts
        // every host of its closure at once.
        .hosts => |list| switch (try gate.permitAll(allocator, list)) {
            .permitted => {},
            .refused => |why| return .{ .refused = why },
        },
        .unreadable => |one| return .{ .refused = try unreadableRefusal(allocator, one) },
        .not_a_lock => |said| return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched, because {s}",
            .{said},
        ) },
    }
    return archive(allocator, io, runner, reference);
}

/// Run `nix flake archive` for `reference` and answer every store path it
/// named. **The caller has already put every host to the gate.**
pub fn archive(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    reference: []const u8,
) Error!Answer {
    const archived = try runner.run(allocator, io, &.{
        "flake",
        "archive",
        "--json",
        // The user's own lock file is theirs. A fetch that rewrote it would
        // change what the project builds from without anybody asking.
        "--no-write-lock-file",
        "--",
        reference,
    });
    if (!archived.succeeded()) return .{ .refused = try std.fmt.allocPrint(
        allocator,
        "the flake inputs were not fetched. Nix said: {s}",
        .{provision.lastLine(archived.stderr)},
    ) };

    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        archived.stdout,
        .{},
    ) catch return .{ .refused = "the flake inputs were fetched and what Nix wrote about them " ++
        "could not be read, so none of them can be used" };
    defer parsed.deinit();

    var paths: std.ArrayList([]const u8) = .empty;
    try collectPaths(allocator, parsed.value, &paths);
    const owned = try paths.toOwnedSlice(allocator);
    std.mem.sort([]const u8, owned, {}, lessThanPath);
    return .{ .fetched = owned };
}

fn lessThanPath(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Every `path` of the tree `nix flake archive --json` writes, at every depth.
fn collectPaths(
    allocator: std.mem.Allocator,
    value: std.json.Value,
    into: *std.ArrayList([]const u8),
) std.mem.Allocator.Error!void {
    if (value != .object) return;
    if (value.object.get("path")) |one| {
        if (one == .string) try into.append(allocator, try allocator.dupe(u8, one.string));
    }
    const inputs = value.object.get("inputs") orelse return;
    if (inputs != .object) return;
    var each = inputs.object.iterator();
    while (each.next()) |entry| try collectPaths(allocator, entry.value_ptr.*, into);
}

/// One sentence for a lock node this file could not name. The caller owns it.
pub fn unreadableRefusal(
    allocator: std.mem.Allocator,
    one: Unreadable,
) std.mem.Allocator.Error![]u8 {
    return switch (one.why) {
        .not_a_node => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: the lock file entry for {s} is not an input this " ++
                "reads.",
            .{one.input},
        ),
        .type_unknown => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: the lock file pins {s} as a {s} input, which " ++
                "names no host, so no rule can cover it. Pin it to a forge, a tarball or a git " ++
                "URL.",
            .{ one.input, one.reference },
        ),
        .no_url => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: the lock file pins {s} as a {s} input with no " ++
                "url, so no rule can cover it.",
            .{ one.input, one.reference },
        ),
        .scheme_unknown => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: {s} is pinned to {s}, and that is not a scheme " ++
                "this reads. Only http and https can be named as a host and a port.",
            .{ one.input, one.reference },
        ),
        .no_host => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: {s} is pinned to {s}, which names no host this " ++
                "can put to a rule.",
            .{ one.input, one.reference },
        ),
        .port_not_a_port => std.fmt.allocPrint(
            allocator,
            "the flake inputs were not fetched: {s} is pinned to {s}, whose port is not a port.",
            .{ one.input, one.reference },
        ),
    };
}

/// True when `text` already ends a sentence.
///
/// **A refusal is written by whoever refused**, so a caller that joins one to a
/// sentence of its own cannot know how it ends. `endSentence` is what keeps the
/// seam reading as prose rather than running one sentence into the next.
fn endsSentence(text: []const u8) bool {
    if (text.len == 0) return true;
    return switch (text[text.len - 1]) {
        '.', '!', '?' => true,
        else => false,
    };
}

/// Append `said` to `text` as a whole sentence, with the full stop it may not
/// carry itself.
fn endSentence(
    allocator: std.mem.Allocator,
    text: *std.ArrayList(u8),
    said: []const u8,
) std.mem.Allocator.Error!void {
    try text.appendSlice(allocator, said);
    if (!endsSentence(said)) try text.append(allocator, '.');
}

/// What a build reads when an input it needed is still not there.
///
/// **It names the input and the host**, because a model that reads a refusal
/// with no subject builds the same attribute again. `why` is what the fetch
/// itself said, which is the part a person acts on.
///
/// **The advice is what is true by the time this is written.** A build fetches
/// a missing input through the gate that can ask, so reaching here means
/// somebody was asked and said no, or the fetch itself failed. Telling the
/// model to ask for a host it has just been refused would send the same
/// attribute back a second time.
pub fn missingRefusal(
    allocator: std.mem.Allocator,
    installable: []const u8,
    why: []const u8,
    wanted: []const fetch.Fetch,
) std.mem.Allocator.Error![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);

    try text.print(
        allocator,
        "{s} was not built: evaluating it needs a flake input this session does not have. ",
        .{installable},
    );
    try endSentence(allocator, &text, why);
    if (wanted.len != 0) {
        try text.appendSlice(allocator, " The inputs it would have fetched are");
        for (wanted, 0..) |one, index| {
            if (index != 0) try text.append(allocator, ',');
            try text.print(allocator, " {s} from {s}", .{ one.subject, one.host });
        }
        try text.append(allocator, '.');
    }
    try text.appendSlice(allocator, " Nothing was fetched and nothing connected. Build an " ++
        "attribute whose inputs are already in the store, or do the work without a build.");
    return text.toOwnedSlice(allocator);
}

const testing = std.testing;

const one_github_input =
    \\{
    \\  "nodes": {
    \\    "nixpkgs": {
    \\      "locked": {
    \\        "narHash": "sha256-A", "owner": "NixOS", "repo": "nixpkgs",
    \\        "rev": "deadbeef", "type": "github"
    \\      }
    \\    },
    \\    "treefmt": {
    \\      "locked": {
    \\        "narHash": "sha256-B", "owner": "numtide", "repo": "treefmt-nix",
    \\        "rev": "feedface", "type": "github"
    \\      }
    \\    },
    \\    "root": { "inputs": { "nixpkgs": "nixpkgs", "treefmt": "treefmt" } }
    \\  },
    \\  "root": "root",
    \\  "version": 7
    \\}
;

test "two inputs from one forge are two hosts and never two questions each" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wants = try wantsOf(arena, one_github_input);
    try testing.expect(wants == .hosts);
    // Two inputs, one forge, and the two hosts that forge is really fetched
    // from. Not four.
    try testing.expectEqual(@as(usize, 2), wants.hosts.len);
    for (wants.hosts) |one| {
        try testing.expect(std.mem.endsWith(u8, one.host, ".github.com"));
        try testing.expectEqual(@as(u16, 443), one.port);
    }
}

test "a node that names its own host names that one and no default" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wants = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"github","host":"git.example.com",
        \\ "owner":"a","repo":"b","narHash":"sha256-A"}},
        \\ "root":{"inputs":{"dep":"dep"}}},"root":"root","version":7}
    );
    try testing.expect(wants == .hosts);
    try testing.expectEqual(@as(usize, 1), wants.hosts.len);
    try testing.expectEqualStrings("git.example.com", wants.hosts[0].host);
}

test "a url input names the host of its url, with the transport in front stripped" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wants = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"git",
        \\ "url":"git+https://git.example.com/a/b.git","narHash":"sha256-A"}},
        \\ "tar":{"locked":{"type":"tarball","url":"https://files.example.com/x.tar.gz",
        \\ "narHash":"sha256-B"}},
        \\ "root":{"inputs":{"dep":"dep","tar":"tar"}}},"root":"root","version":7}
    );
    try testing.expect(wants == .hosts);
    try testing.expectEqual(@as(usize, 2), wants.hosts.len);
}

test "a path input fetches nothing, so nobody is asked about it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const wants = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"path","path":"/nix/store/x-source",
        \\ "narHash":"sha256-A"}},"root":{"inputs":{"dep":"dep"}}},"root":"root","version":7}
    );
    try testing.expect(wants == .hosts);
    try testing.expectEqual(@as(usize, 0), wants.hosts.len);
}

test "a node nothing can name is a refusal that names the input" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // An indirect node names a registry entry, and the registry is itself a
    // fetch, so there is no host in the lock to ask about.
    const indirect = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"indirect","id":"nixpkgs"}},
        \\ "root":{"inputs":{"dep":"dep"}}},"root":"root","version":7}
    );
    try testing.expect(indirect == .unreadable);
    try testing.expectEqual(Unreadable.Why.type_unknown, indirect.unreadable.why);

    const said = try unreadableRefusal(arena, indirect.unreadable);
    try testing.expect(std.mem.indexOf(u8, said, "dep") != null);

    // `ssh` names a host at 22 like any other scheme with one, so a node that
    // uses it is asked about rather than refused.
    const ssh = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"git","url":"ssh://git@example.com/a.git"}},
        \\ "root":{"inputs":{"dep":"dep"}}},"root":"root","version":7}
    );
    try testing.expect(ssh == .hosts);
    try testing.expectEqualStrings("example.com", ssh.hosts[0].host);
    try testing.expectEqual(@as(u16, 22), ssh.hosts[0].port);

    // A scheme with no port this file may invent is still a refusal.
    const unknown = try wantsOf(arena,
        \\{"nodes":{"dep":{"locked":{"type":"git","url":"s3://example.com/a.git"}},
        \\ "root":{"inputs":{"dep":"dep"}}},"root":"root","version":7}
    );
    try testing.expect(unknown == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, unknown.unreadable.why);
}

test "bytes that are not a lock answer one sentence and never a host" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expect(try wantsOf(arena, "not json at all") == .not_a_lock);
    try testing.expect(try wantsOf(arena, "{}") == .not_a_lock);
    try testing.expect(try wantsOf(arena, "[]") == .not_a_lock);
}

/// A `provision.Runner` that runs nothing and records what it was asked.
const FakeRunner = struct {
    gpa: std.mem.Allocator,
    code: u8 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    calls: usize = 0,
    seen: std.ArrayList([]const []const u8) = .empty,

    fn deinit(self: *FakeRunner) void {
        for (self.seen.items) |args| {
            for (args) |one| self.gpa.free(one);
            self.gpa.free(args);
        }
        self.seen.deinit(self.gpa);
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
        _: []const provision.Variable,
    ) provision.Error!@import("proc.zig").Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.alloc([]const u8, args.len);
        errdefer self.gpa.free(copy);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        try self.seen.append(self.gpa, copy);
        self.calls += 1;
        return .{
            .term = .{ .exited = self.code },
            .stdout = try allocator.dupe(u8, self.stdout),
            .stderr = try allocator.dupe(u8, self.stderr),
        };
    }
};

/// A `fetch.Gate` that answers the same way about every host and records what
/// it was asked. **Not a policy table**: what the real one answers is the
/// project's own rules, and no test here claims otherwise.
const AnsweringGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool = true,
    asked: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *AnsweringGate) void {
        for (self.asked.items) |one| self.gpa.free(one);
        self.asked.deinit(self.gpa);
    }

    fn gate(self: *AnsweringGate) fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: fetch.Gate.VTable = .{
        .permit_all = permitAllFn,
        .permit_opaque = permitNothing,
        .allows_by_rule = allowsNothing,
    };

    /// A lock node names a host or it is refused, so nothing here reaches the
    /// question a build with no URL puts.
    fn permitNothing(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const []const u8,
    ) std.mem.Allocator.Error!fetch.Verdict {
        return .{ .refused = "a flake input is fetched by host and never without one" };
    }

    /// No rule here at all, so no mirror of a site is taken without a
    /// question. A flake input names a host and never a site.
    fn allowsNothing(_: *anyopaque, _: fetch.Fetch) bool {
        return false;
    }

    fn permitAllFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        wanted: []const fetch.Fetch,
    ) std.mem.Allocator.Error!fetch.Verdict {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        for (wanted) |one| try self.asked.append(self.gpa, try self.gpa.dupe(u8, one.host));
        if (self.permitted) return .permitted;
        const one = wanted[0];
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} would be fetched from {s}, and this project allows no connection to it",
            .{ one.subject, one.host },
        ) };
    }
};

const archived_json =
    \\{"inputs":{"nixpkgs":{"inputs":{},"path":"/nix/store/bbbb-source"},
    \\ "treefmt":{"inputs":{"nixpkgs":{"inputs":{},"path":"/nix/store/cccc-source"}},
    \\ "path":"/nix/store/dddd-source"}},"path":"/nix/store/aaaa-source"}
;

test "every host of the lock is asked about once, and then the inputs are fetched" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = AnsweringGate{ .gpa = gpa };
    defer gate.deinit();
    var fake = FakeRunner{ .gpa = gpa, .stdout = archived_json };
    defer fake.deinit();

    const answer = try fetchAll(arena, testing.io, fake.runner(), gate.gate(), "/work", one_github_input);
    try testing.expect(answer == .fetched);

    // Every path of the tree, at every depth, which is what a later evaluation
    // reads from the store instead of fetching.
    try testing.expectEqual(@as(usize, 4), answer.fetched.len);
    try testing.expectEqualStrings("/nix/store/aaaa-source", answer.fetched[0]);
    try testing.expectEqualStrings("/nix/store/dddd-source", answer.fetched[3]);

    try testing.expectEqual(@as(usize, 2), gate.asked.items.len);
    try testing.expectEqualStrings("flake", fake.seen.items[0][0]);
    try testing.expectEqualStrings("archive", fake.seen.items[0][1]);
    try testing.expectEqualStrings("--no-write-lock-file", fake.seen.items[0][3]);
    try testing.expectEqualStrings("/work", fake.seen.items[0][5]);
}

test "a host nobody allowed refuses the fetch, and nix is never run" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = AnsweringGate{ .gpa = gpa, .permitted = false };
    defer gate.deinit();
    var fake = FakeRunner{ .gpa = gpa, .stdout = archived_json };
    defer fake.deinit();

    const answer = try fetchAll(arena, testing.io, fake.runner(), gate.gate(), "/work", one_github_input);
    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "github.com") != null);

    // Every host the lock names goes to the gate in one call, and a no there
    // stops the fetch, so nothing was fetched.
    try testing.expectEqual(@as(usize, 2), gate.asked.items.len);
    try testing.expectEqual(@as(usize, 0), fake.calls);
}

test "a nix that would not archive answers one sentence and no path" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var gate = AnsweringGate{ .gpa = gpa };
    defer gate.deinit();
    var fake = FakeRunner{
        .gpa = gpa,
        .code = 1,
        .stderr = "error: cannot connect to socket at '/nix/var/nix/daemon-socket'",
    };
    defer fake.deinit();

    const answer = try fetchAll(arena, testing.io, fake.runner(), gate.gate(), "/work", one_github_input);
    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "daemon-socket") != null);
}

test "the sentence a later build reads names the input and the host, and reads as prose" {
    const gpa = testing.allocator;
    const wanted = [_]fetch.Fetch{
        .{ .subject = "nixpkgs", .url = "https://api.github.com", .host = "api.github.com", .port = 443 },
    };

    // **The seam is the point.** A refusal is written by whoever refused, and
    // one that ends on an action name ran straight into the next sentence.
    const said = try missingRefusal(
        gpa,
        "/work#packages.default",
        "the answer was no for net.connect.com.github.api.443",
        &wanted,
    );
    defer gpa.free(said);

    try testing.expect(std.mem.indexOf(u8, said, "/work#packages.default") != null);
    try testing.expect(std.mem.indexOf(u8, said, "nixpkgs") != null);
    try testing.expect(std.mem.indexOf(u8, said, "api.github.com.443 The") == null);
    try testing.expect(std.mem.indexOf(u8, said, "api.github.api.443. The") != null or
        std.mem.indexOf(u8, said, "net.connect.com.github.api.443. The") != null);

    // A refusal that ends its own sentence keeps the one full stop it wrote.
    const already = try missingRefusal(gpa, "/work#a", "no rule allows it.", &.{});
    defer gpa.free(already);
    try testing.expect(std.mem.indexOf(u8, already, "allows it.. ") == null);
    try testing.expect(std.mem.indexOf(u8, already, "allows it. Nothing was fetched") != null);

    // The model is never told to ask for a host it has just been refused.
    try testing.expect(std.mem.indexOf(u8, said, "ask the user") == null);
}
