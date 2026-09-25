//! Reading a URL for the agent. A host becomes a policy action with its labels
//! reversed, and nothing here opens a socket: `actions.perform` does that.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

const actions = @import("actions.zig");
const diagnostic = @import("diagnostic.zig");
const network = @import("network.zig");

pub const Diagnostic = diagnostic.Diagnostic;

const table = chock_policy.table;
const ratchet = chock_policy.ratchet;

pub const action_prefix = actions.Kind.net_fetch.wireName();

pub const max_host_bytes = 255;

pub const max_action_bytes = action_prefix.len + 1 + max_host_bytes;

pub const max_hops: usize = 5;

pub const max_body_bytes: usize = 1 << 20;

pub const max_robots_bytes: usize = 64 * 1024;

pub const max_robots_rules: usize = 512;

pub const max_robots_hosts: usize = 64;

pub const user_agent = actions.user_agent;

/// A `robots.txt` group is matched against this token and not against the whole
/// header, so a group written for `chock` still binds a later build.
pub const product_token = actions.product_token;

/// The action name for reading `host`, written into `buffer`. The labels are
/// reversed, so a host name can only fall under the class an author wrote.
pub fn actionInto(buffer: []u8, host: []const u8) ?[]const u8 {
    if (buffer.len < max_action_bytes) return null;
    if (host.len > max_host_bytes) return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;

    @memcpy(buffer[0..action_prefix.len], action_prefix);
    var written: usize = action_prefix.len;

    var end = host.len;
    while (end > 0) {
        const start = if (std.mem.lastIndexOfScalar(u8, host[0..end], '.')) |dot| dot + 1 else 0;
        const label = host[start..end];
        buffer[written] = '.';
        written += 1;
        for (label, buffer[written..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        written += label.len;
        end = if (start == 0) 0 else start - 1;
    }
    return buffer[0..written];
}

pub const Refusal = struct {
    kind: Kind,
    text: []u8,

    pub const Kind = enum {
        url_not_usable,
        scheme_not_fetchable,
        url_carries_user_information,
        host_not_a_name,
        host_not_permitted,
        address_not_permitted,
        robots_disallow,
        too_many_hops,
        redirect_without_a_location,
        fetch_failed,
        response_too_large,
        encoding_not_readable,
    };
};

pub const Fetched = struct {
    url: []u8,
    status: u16,
    body: []u8,
    hops: usize,

    pub fn deinit(self: *Fetched, gpa: std.mem.Allocator) void {
        gpa.free(self.url);
        gpa.free(self.body);
        self.* = undefined;
    }
};

pub const Outcome = union(enum) {
    fetched: Fetched,
    refused: Refusal,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .fetched => |*one| one.deinit(gpa),
            .refused => |one| gpa.free(one.text),
        }
        self.* = undefined;
    }
};

pub const Error = std.mem.Allocator.Error;

pub const Rule = struct {
    allow: bool,
    path: []const u8,
};

pub const Robots = struct {
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        authority: []u8,
        rules: []Rule,
    };

    pub fn deinit(self: *Robots, gpa: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            gpa.free(entry.authority);
            for (entry.rules) |rule| gpa.free(rule.path);
            gpa.free(entry.rules);
        }
        self.entries.deinit(gpa);
        self.* = undefined;
    }

    pub fn find(self: *const Robots, authority: []const u8) ?[]const Rule {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.authority, authority)) return entry.rules;
        }
        return null;
    }

    /// A full cache drops the site read longest ago, and never the rules it was
    /// just given: a site read under no rules at all fails silently.
    pub fn keep(
        self: *Robots,
        gpa: std.mem.Allocator,
        authority: []const u8,
        rules: []Rule,
    ) Error!void {
        const owned = try gpa.dupe(u8, authority);
        errdefer gpa.free(owned);
        try self.entries.ensureTotalCapacity(gpa, @min(self.entries.items.len + 1, max_robots_hosts));

        if (self.entries.items.len >= max_robots_hosts) {
            const oldest = self.entries.orderedRemove(0);
            gpa.free(oldest.authority);
            for (oldest.rules) |rule| gpa.free(rule.path);
            gpa.free(oldest.rules);
        }
        self.entries.appendAssumeCapacity(.{ .authority = owned, .rules = rules });
    }
};

/// `robots.txt` is honoured for convention parity and it is not a boundary.
pub fn rulesFor(gpa: std.mem.Allocator, source: []const u8, agent: []const u8) Error![]Rule {
    var specific: std.ArrayList(Rule) = .empty;
    defer freeRules(gpa, &specific);
    var wildcard: std.ArrayList(Rule) = .empty;
    defer freeRules(gpa, &wildcard);

    var in_specific = false;
    var in_wildcard = false;
    var naming_agents = false;

    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = trimComment(raw);
        if (line.len == 0) {
            in_specific = false;
            in_wildcard = false;
            naming_agents = false;
            continue;
        }
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");

        if (std.ascii.eqlIgnoreCase(field, "user-agent")) {
            if (!naming_agents) {
                in_specific = false;
                in_wildcard = false;
                naming_agents = true;
            }
            if (std.mem.eql(u8, value, "*")) in_wildcard = true;
            if (std.ascii.eqlIgnoreCase(value, agent)) in_specific = true;
            continue;
        }

        naming_agents = false;
        const allow = if (std.ascii.eqlIgnoreCase(field, "allow"))
            true
        else if (std.ascii.eqlIgnoreCase(field, "disallow"))
            false
        else
            continue;

        // An empty `Disallow` is the convention's own way of writing "no rules".
        if (value.len == 0) continue;

        const into: *std.ArrayList(Rule) = if (in_specific)
            &specific
        else if (in_wildcard)
            &wildcard
        else
            continue;
        if (into.items.len >= max_robots_rules) continue;

        const path = try gpa.dupe(u8, value);
        errdefer gpa.free(path);
        try into.append(gpa, .{ .allow = allow, .path = path });
    }

    // The group that names this agent wins whole, empty or not.
    const chosen: *std.ArrayList(Rule) = if (namesTheAgent(source, agent)) &specific else &wildcard;
    return chosen.toOwnedSlice(gpa);
}

fn namesTheAgent(source: []const u8, agent: []const u8) bool {
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = trimComment(raw);
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const field = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(field, "user-agent")) continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[colon + 1 ..], " \t"), agent)) return true;
    }
    return false;
}

fn trimComment(raw: []const u8) []const u8 {
    const without_cr = std.mem.trimEnd(u8, raw, "\r");
    const body = if (std.mem.indexOfScalar(u8, without_cr, '#')) |hash|
        without_cr[0..hash]
    else
        without_cr;
    return std.mem.trim(u8, body, " \t");
}

fn freeRules(gpa: std.mem.Allocator, list: *std.ArrayList(Rule)) void {
    for (list.items) |rule| gpa.free(rule.path);
    list.deinit(gpa);
}

/// The longest matching prefix decides and an `Allow` wins a tie. A `*` or a
/// `$` in a rule is read as an ordinary character.
pub fn pathIsAllowed(rules: []const Rule, path: []const u8) bool {
    var best_len: usize = 0;
    var best_allow = true;
    for (rules) |rule| {
        if (!std.mem.startsWith(u8, path, rule.path)) continue;
        if (rule.path.len < best_len) continue;
        if (rule.path.len == best_len and !rule.allow) continue;
        best_len = rule.path.len;
        best_allow = rule.allow;
    }
    return best_allow;
}

pub const Session = struct {
    gpa: std.mem.Allocator,
    table: *const table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,
    env: *const std.process.Environ.Map,
    resolver: actions.Resolver = .system,
    /// The address check lives in `network.zig` and nowhere else: two copies of
    /// a security check drift apart.
    reachable: *const fn (address: actions.Resolver.Address) bool = network.addressIsReachable,
    robots: Robots = .{},
    hop_limit: usize = max_hops,

    pub fn deinit(self: *Session) void {
        self.robots.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn fetch(
        self: *Session,
        io: std.Io,
        request: Request,
        diag: ?*?Diagnostic,
    ) Error!Outcome {
        var url = try self.gpa.dupe(u8, request.url);
        defer self.gpa.free(url);

        var hop: usize = 0;
        while (true) : (hop += 1) {
            if (hop > self.hop_limit) return refuse(.too_many_hops, try std.fmt.allocPrint(
                self.gpa,
                "nothing was read: that URL redirects more than {d} times, which is a redirect " ++
                    "loop or a chain too long to be worth following.",
                .{self.hop_limit},
            ));

            const uri = std.Uri.parse(url) catch return refuse(
                .url_not_usable,
                try self.gpa.dupe(u8, "nothing was read: that is not a URL this can parse. " ++
                    "Give a whole URL, scheme first, such as \"https://example.com/page\"."),
            );
            if (!std.mem.eql(u8, uri.scheme, "http") and !std.mem.eql(u8, uri.scheme, "https")) {
                return refuse(.scheme_not_fetchable, try std.fmt.allocPrint(
                    self.gpa,
                    "nothing was read: \"{s}\" is not a scheme this reads. Only http and https " ++
                        "are read.",
                    .{uri.scheme},
                ));
            }
            // `std.http.Client` turns `http://user:secret@host/` into an
            // `Authorization` header, so a credential would leave here.
            if (uri.user != null or uri.password != null) return refuse(
                .url_carries_user_information,
                try self.gpa.dupe(u8, "nothing was read: that URL carries user information " ++
                    "before the host, which would send an Authorization header. Chock never " ++
                    "sends a credential to a fetched host. Give the URL without it."),
            );

            var arena_state = std.heap.ArenaAllocator.init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const host_component = uri.host orelse return refuse(
                .url_not_usable,
                try self.gpa.dupe(u8, "nothing was read: that URL names no host."),
            );
            const host = try host_component.toRawMaybeAlloc(arena);

            var decision = self.decide(host, request.self_policy);

            // Only the host the agent named, which is the first hop. A
            // redirect keeps the refusal, so a page cannot chain hops to make
            // a person answer one question after another.
            if (mayAsk(decision, hop)) {
                if (request.ask_host) |asker| {
                    var key_buffer: [max_action_bytes]u8 = undefined;
                    if (actionInto(&key_buffer, host)) |action| {
                        if (try asker.permits(host, action)) decision = .allow;
                    }
                }
            }

            if (decision != .allow) {
                if (diagnostic.wants(diag)) {
                    var key_buffer: [max_action_bytes]u8 = undefined;
                    const key = actionInto(&key_buffer, host);
                    _ = diagnostic.note(diag, .{ .fetch_host_not_permitted = .{
                        .host = try self.gpa.dupe(u8, host),
                        .decision = decision,
                        .action = if (key) |one| try self.gpa.dupe(u8, one) else null,
                    } });
                }
                return refuse(.host_not_permitted, try self.refusalForHost(host, decision));
            }

            const path = try uri.path.toRawMaybeAlloc(arena);
            const authority = try authorityOf(arena, uri);
            const rules = self.robotsFor(io, arena, uri, authority, diag) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AddressNotPermitted => return refuse(
                    .address_not_permitted,
                    try self.addressRefusal(host),
                ),
            };
            if (!pathIsAllowed(rules, if (path.len == 0) "/" else path)) {
                if (diagnostic.wants(diag)) {
                    _ = diagnostic.note(diag, .{ .fetch_robots_disallow = .{
                        .host = try self.gpa.dupe(u8, host),
                        .path = try self.gpa.dupe(u8, path),
                    } });
                }
                return refuse(.robots_disallow, try std.fmt.allocPrint(
                    self.gpa,
                    "nothing was read: the robots.txt of {s} disallows {s} for \"{s}\". That " ++
                        "file is the site operator's own instruction to automated clients, and " ++
                        "Chock follows it. Read something else on that host, or ask the user.",
                    .{ host, if (path.len == 0) "/" else path, product_token },
                ));
            }

            const result = self.perform(io, .{
                .host = host,
                .url = url,
                .max_bytes = max_body_bytes,
            }, diag) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.AddressNotPermitted => return refuse(
                    .address_not_permitted,
                    try self.addressRefusal(host),
                ),
                error.ResponseTooLarge => return refuse(
                    .response_too_large,
                    try std.fmt.allocPrint(
                        self.gpa,
                        "nothing was read: that page is larger than {d} bytes.",
                        .{max_body_bytes},
                    ),
                ),
                error.ResponseEncodingNotReadable => return refuse(
                    .encoding_not_readable,
                    try std.fmt.allocPrint(
                        self.gpa,
                        "nothing was read: {s} answered in a content encoding Chock cannot " ++
                            "decode. Chock offers gzip and deflate, and it will not give you " ++
                            "bytes it could not read as if they were the page. Read the same " ++
                            "content from another URL, or ask the user for it.",
                        .{host},
                    ),
                ),
                else => return refuse(.fetch_failed, try std.fmt.allocPrint(
                    self.gpa,
                    "nothing was read: the request to {s} failed ({t}).",
                    .{ host, err },
                )),
            };
            const answered = result.net_fetch;

            if (isRedirect(answered.status)) {
                // Every redirect hop is authorised in its own right.
                defer self.gpa.free(answered.body);
                defer self.gpa.free(answered.location);

                if (answered.location.len == 0) return refuse(
                    .redirect_without_a_location,
                    try std.fmt.allocPrint(
                        self.gpa,
                        "nothing was read: {s} answered {d} with no Location to follow.",
                        .{ host, answered.status },
                    ),
                );

                const next = resolve(arena, uri, answered.location) catch return refuse(
                    .url_not_usable,
                    try self.gpa.dupe(u8, "nothing was read: that URL redirects to something " ++
                        "this cannot parse as a URL."),
                );
                const owned = try self.gpa.dupe(u8, next);
                self.gpa.free(url);
                url = owned;
                continue;
            }

            self.gpa.free(answered.location);
            errdefer self.gpa.free(answered.body);
            return .{ .fetched = .{
                .url = try self.gpa.dupe(u8, url),
                .status = answered.status,
                .body = answered.body,
                .hops = hop,
            } };
        }
    }

    /// Only `allow` reads a page. `ask` refuses here, because `Loop.run` holds
    /// the session log lock and nobody could answer a question asked on this path.
    pub fn decide(
        self: *const Session,
        host: []const u8,
        self_policy: []const ratchet.Restriction,
    ) table.Decision {
        var buffer: [max_action_bytes]u8 = undefined;
        const action = actionInto(&buffer, host) orelse return .deny;

        const answer = self.table.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, null);

        return ratchet.narrow(answer, self_policy, action)
            .intersect(ratchet.ceilingFor(self_policy, action_prefix));
    }

    fn addressRefusal(self: *Session, host: []const u8) Error![]u8 {
        return std.fmt.allocPrint(
            self.gpa,
            "nothing was read: {s} answers with an address on this machine rather than on the " ++
                "network, so nothing was contacted. The loopback interface, the cloud metadata " ++
                "address, and the unspecified address are all refused, whatever the policy says " ++
                "about the name. Read a host on the network, or ask the user.",
            .{host},
        );
    }

    const AddressError = error{AddressNotPermitted};

    fn robotsFor(
        self: *Session,
        io: std.Io,
        arena: std.mem.Allocator,
        uri: std.Uri,
        authority: []const u8,
        diag: ?*?Diagnostic,
    ) (Error || AddressError)![]const Rule {
        if (self.robots.find(authority)) |known| return known;

        const url = try std.fmt.allocPrint(arena, "{s}/robots.txt", .{authority});
        const host = try (uri.host.?).toRawMaybeAlloc(arena);
        var result = self.perform(io, .{
            .host = host,
            .url = url,
            .max_bytes = max_robots_bytes,
        }, diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.AddressNotPermitted => return error.AddressNotPermitted,
            // A site that does not answer for `robots.txt` has stated no rules.
            else => {
                try self.robots.keep(self.gpa, authority, &.{});
                return &.{};
            },
        };
        defer result.deinit(self.gpa);

        // Anything but 200 states no rules, and a redirect for `robots.txt` is
        // not followed.
        const rules = if (result.net_fetch.status == 200)
            try rulesFor(self.gpa, result.net_fetch.body, product_token)
        else
            try self.gpa.alloc(Rule, 0);
        errdefer {
            for (rules) |rule| self.gpa.free(rule.path);
            self.gpa.free(rules);
        }
        try self.robots.keep(self.gpa, authority, rules);
        return self.robots.find(authority) orelse &.{};
    }

    fn perform(
        self: *Session,
        io: std.Io,
        one: actions.NetFetch,
        diag: ?*?Diagnostic,
    ) actions.PerformError!actions.Result {
        return actions.perform(
            self.gpa,
            io,
            .{ .env = self.env, .resolver = self.resolver, .reachable = self.reachable },
            .{ .net_fetch = one },
            diag,
        );
    }

    fn refusalForHost(self: *Session, host: []const u8, decision: table.Decision) Error![]u8 {
        var buffer: [max_action_bytes]u8 = undefined;
        const action = actionInto(&buffer, host) orelse return std.fmt.allocPrint(
            self.gpa,
            "nothing was read: \"{s}\" is not a host name this builds a policy key from.",
            .{host},
        );
        return std.fmt.allocPrint(
            self.gpa,
            "nothing was read: this project's policy answers \"{s}\" for the host {s}. Only " ++
                "\"allow\" reads a host. The rule that would permit it is " ++
                "`.{{ .action = \"{s}\", .decision = .allow }}` in the .policy.rules block of " ++
                "chock.zon, which you cannot write and the user can. Ask the user, or work " ++
                "without that page.",
            .{ @tagName(decision), host, action },
        );
    }
};

/// Puts one host to a person while the agent waits. `chock-broker` cannot
/// import `chock-core`, so this carries the same shape as
/// `chock_core.fetch.HostAsk` and `src/run.zig` hands one across.
pub const HostAsk = struct {
    ptr: *anyopaque,
    call: *const fn (ptr: *anyopaque, host: []const u8, action: []const u8) Error!bool,

    pub fn permits(self: HostAsk, host: []const u8, action: []const u8) Error!bool {
        return self.call(self.ptr, host, action);
    }
};

pub const Request = struct {
    url: []const u8,
    self_policy: []const ratchet.Restriction = &.{},
    /// Null where nobody can be asked, and then `ask` stays a refusal.
    ask_host: ?HostAsk = null,
};

/// Whether this host may be put to a person while the agent waits.
///
/// **Only the host the agent named, which is hop zero.** A redirect hop keeps
/// the refusal a host no rule names already gets. A page that could ask at
/// every hop would let whoever wrote it chain redirects and turn the prompt
/// into a way to tire a person out, and an approval answered wearily is worth
/// nothing.
fn mayAsk(decision: table.Decision, hop: usize) bool {
    return decision == .ask and hop == 0;
}

fn refuse(kind: Refusal.Kind, text: []u8) Outcome {
    return .{ .refused = .{ .kind = kind, .text = text } };
}

fn isRedirect(status: u16) bool {
    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |text| text,
        .percent_encoded => |text| text,
    };
}

fn authorityOf(arena: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const host = try (uri.host.?).toRawMaybeAlloc(arena);
    if (uri.port) |port| {
        return std.fmt.allocPrint(arena, "{s}://{s}:{d}", .{ uri.scheme, host, port });
    }
    return std.fmt.allocPrint(arena, "{s}://{s}", .{ uri.scheme, host });
}

/// A `Location` may be relative, so this is where a redirect target becomes a
/// whole URL again.
fn resolve(
    arena: std.mem.Allocator,
    base: std.Uri,
    location: []const u8,
) (Error || std.Uri.ResolveInPlaceError)![]u8 {
    // `resolveInPlace` wants the location at the head of a buffer it may also
    // use for the merged path, and it writes into it.
    const room = location.len * 2 + componentBytes(base.path).len + 2;
    const scratch = try arena.alloc(u8, room);
    @memcpy(scratch[0..location.len], location);
    var rest: []u8 = scratch;
    const resolved = try base.resolveInPlace(location.len, &rest);

    var out: std.Io.Writer.Allocating = .init(arena);
    resolved.writeToStream(&out.writer, .{
        .scheme = true,
        .authentication = false,
        .authority = true,
        .path = true,
        .query = true,
        .fragment = false,
    }) catch return error.OutOfMemory;
    return out.written();
}

const testing = std.testing;

fn actionFor(buffer: []u8, host: []const u8) []const u8 {
    return actionInto(buffer, host) orelse "";
}

test "a host becomes a reversed action, so a class rule names a real subtree" {
    var buffer: [max_action_bytes]u8 = undefined;
    try testing.expectEqualStrings("net.fetch.org.ziglang.docs", actionFor(&buffer, "docs.ziglang.org"));
    try testing.expectEqualStrings("net.fetch.com.example", actionFor(&buffer, "example.com"));
    try testing.expectEqualStrings("net.fetch.com.example.www", actionFor(&buffer, "WWW.Example.COM"));
    try testing.expectEqualStrings("net.fetch.1.0.0.127", actionFor(&buffer, "127.0.0.1"));
}

test "a class rule covers only the subtree below it, and never a host that merely ends the same way" {
    var buffer: [max_action_bytes]u8 = undefined;
    const inside = actionFor(&buffer, "docs.example.com");
    try testing.expect(table.patternMatches("net.fetch.com.example.*", inside));

    var other: [max_action_bytes]u8 = undefined;
    const outside = actionFor(&other, "example.com.evil.net");
    try testing.expect(!table.patternMatches("net.fetch.com.example.*", outside));
    try testing.expectEqualStrings("net.fetch.net.evil.com.example", outside);
}

test "bytes that are not a host name build no key at all" {
    var buffer: [max_action_bytes]u8 = undefined;
    try testing.expect(actionInto(&buffer, "") == null);
    try testing.expect(actionInto(&buffer, "example..com") == null);
    try testing.expect(actionInto(&buffer, ".example.com") == null);
    try testing.expect(actionInto(&buffer, "*.example.com") == null);
}

test "a robots.txt disallow for this agent stops that path and nothing else" {
    const gpa = testing.allocator;
    const source =
        \\User-agent: *
        \\Disallow: /private
        \\
    ;
    const rules = try rulesFor(gpa, source, product_token);
    defer {
        for (rules) |rule| gpa.free(rule.path);
        gpa.free(rules);
    }
    try testing.expectEqual(@as(usize, 1), rules.len);
    try testing.expect(!pathIsAllowed(rules, "/private/notes"));
    try testing.expect(pathIsAllowed(rules, "/public/notes"));
}

test "the group naming this agent wins over the wildcard group, whichever order they are in" {
    const gpa = testing.allocator;
    const source =
        \\User-agent: *
        \\Disallow: /
        \\
        \\User-agent: chock
        \\Disallow: /private
        \\
    ;
    const rules = try rulesFor(gpa, source, product_token);
    defer {
        for (rules) |rule| gpa.free(rule.path);
        gpa.free(rules);
    }
    try testing.expect(pathIsAllowed(rules, "/public"));
    try testing.expect(!pathIsAllowed(rules, "/private"));

    const by_header = try rulesFor(gpa, source, user_agent);
    defer {
        for (by_header) |rule| gpa.free(rule.path);
        gpa.free(by_header);
    }
    try testing.expect(!pathIsAllowed(by_header, "/public"));
    try testing.expect(!std.mem.eql(u8, user_agent, product_token));
}

test "the longest matching rule decides, and an allow wins a tie" {
    const gpa = testing.allocator;
    const source =
        \\User-agent: *
        \\Disallow: /docs
        \\Allow: /docs/public
        \\
    ;
    const rules = try rulesFor(gpa, source, product_token);
    defer {
        for (rules) |rule| gpa.free(rule.path);
        gpa.free(rules);
    }
    try testing.expect(!pathIsAllowed(rules, "/docs/private"));
    try testing.expect(pathIsAllowed(rules, "/docs/public/one"));
}

test "an empty disallow states no rule, and a comment is not a rule" {
    const gpa = testing.allocator;
    const source =
        \\# everything is fine
        \\User-agent: *
        \\Disallow:
        \\
    ;
    const rules = try rulesFor(gpa, source, product_token);
    defer {
        for (rules) |rule| gpa.free(rule.path);
        gpa.free(rules);
    }
    try testing.expectEqual(@as(usize, 0), rules.len);
    try testing.expect(pathIsAllowed(rules, "/anything"));
}

test "a full robots cache drops the oldest site and keeps the rules it was just given" {
    const gpa = testing.allocator;
    var cache: Robots = .{};
    defer cache.deinit(gpa);

    var index: usize = 0;
    while (index < max_robots_hosts + 1) : (index += 1) {
        var name: [64]u8 = undefined;
        const authority = try std.fmt.bufPrint(&name, "http://host{d}.example.com", .{index});
        const rules = try gpa.alloc(Rule, 1);
        rules[0] = .{ .allow = false, .path = try gpa.dupe(u8, "/private") };
        try cache.keep(gpa, authority, rules);
    }

    try testing.expectEqual(max_robots_hosts, cache.entries.items.len);
    var last: [64]u8 = undefined;
    const newest = try std.fmt.bufPrint(&last, "http://host{d}.example.com", .{max_robots_hosts});
    const kept = cache.find(newest) orelse return error.NewestSiteWasDropped;
    try testing.expect(!pathIsAllowed(kept, "/private/notes"));
    try testing.expect(cache.find("http://host0.example.com") == null);
}

fn tableFrom(gpa: std.mem.Allocator, source: [:0]const u8) !*const table.Table {
    return table.Table.parse(gpa, source, null);
}

const allows_example: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.fetch.com.example.*", .decision = .allow },
    \\            .{ .action = "net.fetch.com.example", .decision = .allow },
    \\        },
    \\    },
    \\}
;

test "a host under an allowed class is permitted, and a host nobody named is not" {
    const gpa = testing.allocator;
    const policy = try tableFrom(gpa, allows_example);
    defer table.Table.destroy(gpa, policy);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var session = Session{
        .gpa = gpa,
        .table = policy,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "test",
        .tool = "fetch_url",
        .env = &env,
    };
    defer session.deinit();

    try testing.expectEqual(table.Decision.allow, session.decide("docs.example.com", &.{}));
    try testing.expectEqual(table.Decision.allow, session.decide("example.com", &.{}));
    try testing.expectEqual(table.Decision.ask, session.decide("example.org", &.{}));
    try testing.expectEqual(table.Decision.ask, session.decide("example.com.evil.net", &.{}));
}

test "a promise on the bare class binds a host the project allowed" {
    const gpa = testing.allocator;
    const policy = try tableFrom(gpa, allows_example);
    defer table.Table.destroy(gpa, policy);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var session = Session{
        .gpa = gpa,
        .table = policy,
        .chain = &.{"main"},
        .agent_kind = "main",
        .model = "test",
        .tool = "fetch_url",
        .env = &env,
    };
    defer session.deinit();

    const promised = [_]ratchet.Restriction{.{
        .action = "net.fetch",
        .ceiling = .deny,
        .reason = "this task reads local files",
    }};
    try testing.expectEqual(table.Decision.deny, session.decide("docs.example.com", &promised));
    const one_host = [_]ratchet.Restriction{.{
        .action = "net.fetch.com.example.www",
        .ceiling = .deny,
        .reason = "not that one",
    }};
    try testing.expectEqual(table.Decision.deny, session.decide("www.example.com", &one_host));
    try testing.expectEqual(table.Decision.allow, session.decide("docs.example.com", &one_host));
}

test "only the host the agent named may be put to a person" {
    // The host the agent asked for, and the table wants a person.
    try std.testing.expect(mayAsk(.ask, 0));

    // Every redirect hop keeps the refusal. This is the whole of the bound on
    // a page that would otherwise chain hops to make a person answer again
    // and again.
    try std.testing.expect(!mayAsk(.ask, 1));
    try std.testing.expect(!mayAsk(.ask, 2));

    // Nothing else is a question. A deny is a deny and an allow needs nobody.
    try std.testing.expect(!mayAsk(.deny, 0));
    try std.testing.expect(!mayAsk(.allow, 0));
}
