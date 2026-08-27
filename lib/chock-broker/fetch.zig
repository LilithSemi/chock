//! Reading a URL for the agent: who decides which host may be reached, what a
//! redirect costs, and why `robots.txt` is honoured here at all.
//!
//! `lib/chock-broker/actions.zig` already holds `net.fetch`, which reads **one
//! URL on one host and follows nothing**. That is the privileged act, and it
//! stays exactly as narrow as it was. This file is the layer above it: it asks
//! the policy table about a host, reads `robots.txt`, performs one hop through
//! that action, and then asks the whole question again for the host a redirect
//! named. Nothing here opens a socket of its own.
//!
//! ## Authorisation is a policy row, not a flag
//!
//! The policy table answers on dotted action names. A host is a dotted name
//! too, and its hierarchy runs the other way: `docs.ziglang.org` is inside
//! `ziglang.org`, which is inside `org`. So the labels are **reversed** and the
//! result is an ordinary action:
//!
//! ```
//! docs.ziglang.org   ->   net.fetch.org.ziglang.docs
//! ```
//!
//! Which makes a rule in the table's own language mean what an author would
//! take it to mean:
//!
//! ```zon
//! .{ .action = "net.fetch.org.ziglang.*", .decision = .allow }     // any host under ziglang.org
//! .{ .action = "net.fetch.org.ziglang.docs", .decision = .allow }  // that host, and nothing else
//! .{ .action = "net.fetch.*", .decision = .deny }                  // nothing is read at all
//! ```
//!
//! **Reversal is what makes a class rule safe.** Without it, `net.fetch.docs.*`
//! would cover `docs.anything.at.all`, which is the opposite of what a reader
//! would take it to mean. With it, a name the model invents can only fall
//! **under** the class an author wrote. `lib/chock-broker/network.zig` builds
//! `net.connect` keys the same way, for the same reason, and this is
//! deliberately the same spelling.
//!
//! **The port is not in the key**, which is the one difference from
//! `net.connect`. That key answers a raw connection, where the port is most of
//! what a rule is about. This one answers a URL, where the scheme already fixes
//! the port in the ordinary case, and where an author who wrote
//! `net.fetch.com.example` means the site and not one socket on it.
//!
//! ## Only `allow` permits, and everything else is a refusal
//!
//! `Table.evaluateChain` gives one of five decisions. This grants on `allow`
//! and refuses on the other four, `ask` included.
//!
//! **That is a narrowing and not a shortcut.** A fetch is answered from inside
//! a tool call, and `Loop.run` holds the session log's exclusive lock for the
//! whole session, so a question asked here could not be answered by anybody.
//! `lib/chock-broker/network.zig` refuses for the same reason and says so at
//! length. An author who wants a host read writes `allow` for it.
//!
//! ## Every redirect hop is authorised in its own right
//!
//! **A permitted host that redirects to a denied one is a denial.** This is the
//! whole reason the chain cannot be handed to an HTTP client that follows
//! redirects for you: such a client would authorise the first host and reach
//! the last. So each hop is a fresh `net.fetch` action for its own host, with
//! its own policy question and its own `robots.txt` check in front of it, and
//! `max_hops` bounds how many of them one call may cost.
//!
//! ## The address a permitted name answers with is checked too
//!
//! A permitted name that answers `127.0.0.1` or `169.254.169.254` would turn a
//! rule about a host on the internet into a handle on this machine and on the
//! cloud metadata service beside it, which hands out credentials to whoever
//! asks. Whoever runs the permitted zone decides that answer, so the policy
//! saying yes to a name is not the same as the name being reachable.
//!
//! **The check is one function and it lives in one place.**
//! `lib/chock-broker/network.zig` holds `addressIsReachable`, and
//! `actions.perform` calls it after the lookup and before anything opens. So
//! this file holds no copy of it: two copies of a security check drift apart.
//!
//! **A redirect hop is checked in its own right**, for the same reason its host
//! is: every hop of the loop below goes back through `actions.perform`, which
//! resolves and checks afresh. A redirect is exactly how an attacker would
//! reach the metadata address from a name that looked fine.
//!
//! **The checked address is also the one that is dialled, for a name with an
//! IPv4 address.** A guard that checked one answer while the HTTP client asked
//! the same name again and dialled a second answer would guard nothing, because
//! whoever runs the zone chooses both answers. `actions.pinnedConnection` opens
//! the socket to a checked address and hands the client a connection.
//!
//! **A name that answers with IPv6 addresses only is not held to an address,
//! and the rebinding window is open for it.** Zig 0.16 cannot write a colon
//! into the `HostName` the dial takes, so such a name is read by the ordinary
//! path instead of being refused. That keeps Chock usable on an IPv6-only or a
//! NAT64 network, and `actions.pinnedConnection` holds the whole decision. The
//! address check still runs over every address, IPv6 included.
//!
//! ## robots.txt is convention parity, not a security control
//!
//! **It is not a boundary and nothing here treats it as one.** A file served by
//! the host being read cannot restrain a client that does not want to be
//! restrained, and an operator who needs a request refused needs authentication
//! and not a text file. It is honoured because every other harness fetch tool
//! honours it, and because a well behaved client is what a site operator is
//! entitled to expect. The boundary is the policy table above, which the agent
//! cannot reach and which a project writes.
//!
//! It is read one time per authority and kept for the session, so one page
//! fetch does not become two requests every time.
//!
//! ## No credential ever travels to a fetched host
//!
//! Credentials live in the store and there is no environment variable path to
//! one. Two things follow, and both are enforced here rather than trusted:
//!
//! * **A URL that carries user information is refused.** `std.http.Client`
//!   turns `http://user:secret@host/` into an `Authorization` header, so a URL
//!   the model wrote could otherwise put a value on the wire.
//! * **Nothing here reads the credential store, an environment variable, or a
//!   proxy setting.** The only header this adds is `User-Agent`.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");

const actions = @import("actions.zig");
const diagnostic = @import("diagnostic.zig");
const network = @import("network.zig");

/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

const table = chock_policy.table;
const ratchet = chock_policy.ratchet;

/// What every action name in this file starts with. Read from the action the
/// broker really performs, so the class a rule names and the act it governs
/// cannot drift apart.
pub const action_prefix = actions.Kind.net_fetch.wireName();

/// The longest host name a key is built from. The bound DNS itself has.
pub const max_host_bytes = 255;

/// The longest action name `actionInto` can build: the prefix, a separator,
/// and the reversed name.
pub const max_action_bytes = action_prefix.len + 1 + max_host_bytes;

/// How many redirects one call may follow. Five is what a browser allows in
/// practice, and each one costs a policy question and a `robots.txt` check.
pub const max_hops: usize = 5;

/// The most of one page this reads. Smaller than
/// `actions.default_fetch_bytes`, because this body reaches a model context
/// and that one only reaches a caller.
pub const max_body_bytes: usize = 1 << 20;

/// The most of one `robots.txt` this reads. A large one is a mistake, and the
/// rules that matter are at the top of it either way.
pub const max_robots_bytes: usize = 64 * 1024;

/// The most rules one `robots.txt` contributes. Past this the rest is ignored,
/// which is the direction a convention should fail in.
pub const max_robots_rules: usize = 512;

/// The most authorities one session keeps a `robots.txt` for.
pub const max_robots_hosts: usize = 64;

/// What Chock calls itself on the wire, version and all. Read from the action
/// that really sets the header, because a client that obeys the rules for a
/// name it does not send is obeying nothing.
pub const user_agent = actions.user_agent;

/// The product token a `robots.txt` group is matched against, which is what
/// `user_agent` opens with and carries no version.
///
/// **Matching on the token and not on the whole header is the convention**, and
/// here it is what keeps a promise: a site that wrote a group for `chock`
/// before this build existed still binds this build. Matching the header
/// instead would leave every such group unmatched, and Chock would go on
/// reading the file and stop obeying it. `actions.product_token` holds the
/// whole argument.
pub const product_token = actions.product_token;

/// The action name for reading `host`, written into `buffer`. Null when the
/// bytes are not a host name, or when they do not fit.
///
/// **The labels are reversed**: see this file's own top comment. `buffer` must
/// hold `max_action_bytes`.
pub fn actionInto(buffer: []u8, host: []const u8) ?[]const u8 {
    if (buffer.len < max_action_bytes) return null;
    if (host.len > max_host_bytes) return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;

    @memcpy(buffer[0..action_prefix.len], action_prefix);
    var written: usize = action_prefix.len;

    // The labels, last one first. `hostBytesAreUsable` has already refused an
    // empty label, a leading dot and a trailing dot, so every step here has
    // something to write.
    var end = host.len;
    while (end > 0) {
        const start = if (std.mem.lastIndexOfScalar(u8, host[0..end], '.')) |dot| dot + 1 else 0;
        const label = host[start..end];
        buffer[written] = '.';
        written += 1;
        // Lowercased, because a host name is not case sensitive and a policy
        // key is. Without this, `Docs.Ziglang.Org` would be a different action
        // from `docs.ziglang.org` and would match no rule.
        for (label, buffer[written..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        written += label.len;
        end = if (start == 0) 0 else start - 1;
    }
    return buffer[0..written];
}

/// Why one call read nothing. The tag is what a test asserts on; `text` is the
/// sentence the agent reads, and it is owned by whoever holds the `Outcome`.
pub const Refusal = struct {
    kind: Kind,
    text: []u8,

    pub const Kind = enum {
        /// The URL does not parse, or names no host.
        url_not_usable,
        /// The scheme is not one this reads. Only `http` and `https` are.
        scheme_not_fetchable,
        /// The URL carries user information, which would become an
        /// `Authorization` header. See this file's own top comment.
        url_carries_user_information,
        /// The bytes between the scheme and the path are not a host name.
        host_not_a_name,
        /// The policy does not permit this host for this spawn chain.
        host_not_permitted,
        /// The host resolved onto this machine rather than onto the network.
        /// See this file's own top comment.
        address_not_permitted,
        /// The host's own `robots.txt` disallows this path for
        /// `product_token`.
        robots_disallow,
        /// The chain of redirects is longer than `max_hops`.
        too_many_hops,
        /// A redirect status arrived with no `Location` to follow.
        redirect_without_a_location,
        /// The request itself failed: no connection, or a broken response.
        fetch_failed,
        /// The body is larger than `max_body_bytes`.
        response_too_large,
        /// The site answered in a content encoding Chock cannot decode.
        encoding_not_readable,
    };
};

/// What one page read came back with. Every field is owned by the caller.
pub const Fetched = struct {
    /// The URL the bytes really came from, after every redirect.
    url: []u8,
    status: u16,
    body: []u8,
    /// How many redirects were followed. Zero for a URL that answered
    /// directly.
    hops: usize,

    pub fn deinit(self: *Fetched, gpa: std.mem.Allocator) void {
        gpa.free(self.url);
        gpa.free(self.body);
        self.* = undefined;
    }
};

/// What one call ended as.
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

/// What a call can fail with. **A refusal is not in here**: a refusal is an
/// `Outcome.refused`, because the agent has to read why and act on it.
pub const Error = std.mem.Allocator.Error;

/// One `robots.txt` rule: a path prefix, and whether it permits.
pub const Rule = struct {
    allow: bool,
    /// The path prefix, as it was written. `*` and `$` are not read: see
    /// `pathIsAllowed`.
    path: []const u8,
};

/// The `robots.txt` of every authority this session has already asked about.
///
/// **One read per authority, kept for the session.** A page fetch must not
/// become two requests every time, and a site that answered once has answered.
pub const Robots = struct {
    entries: std.ArrayList(Entry) = .empty,

    pub const Entry = struct {
        /// `<scheme>://<host>[:<port>]`, which is what a `robots.txt` belongs
        /// to. Two ports on one host are two sites.
        authority: []u8,
        /// The rules for `product_token`, in the order they were written.
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

    /// The rules already known for `authority`, or null when it has not been
    /// read yet.
    pub fn find(self: *const Robots, authority: []const u8) ?[]const Rule {
        for (self.entries.items) |entry| {
            if (std.mem.eql(u8, entry.authority, authority)) return entry.rules;
        }
        return null;
    }

    /// Keep `rules` for `authority`, and take ownership of them.
    ///
    /// **A full cache drops the site that was read longest ago, and never the
    /// rules it was just given.** Dropping the new ones would leave the caller
    /// reading a site under no rules at all, which is the one direction a
    /// convention must not fail in, and it would do so silently.
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

/// Read one `robots.txt` into the rules that apply to `agent`.
///
/// **Convention parity, and not a security control.** See this file's own top
/// comment: nothing a host serves can restrain a client that does not want to
/// be restrained, and this exists because a well behaved client is what a site
/// operator is entitled to expect.
///
/// `agent` is a product token and never a whole `User-Agent` header: see
/// `product_token`. The group for it wins over the group for `*`, which is what
/// the convention asks for. A file that names neither gives no rules at all,
/// and no rules permits everything.
///
/// The caller owns the result and every path in it.
pub fn rulesFor(gpa: std.mem.Allocator, source: []const u8, agent: []const u8) Error![]Rule {
    var specific: std.ArrayList(Rule) = .empty;
    defer freeRules(gpa, &specific);
    var wildcard: std.ArrayList(Rule) = .empty;
    defer freeRules(gpa, &wildcard);

    // Which groups the line being read belongs to. A run of `User-agent`
    // lines with no rule between them is one group with several names, which
    // is what the convention says and what a real file uses.
    var in_specific = false;
    var in_wildcard = false;
    var naming_agents = false;

    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw| {
        const line = trimComment(raw);
        if (line.len == 0) {
            // A blank line ends a group. Without this, a `Disallow` written
            // under nobody would attach to the group above it.
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

        // An empty `Disallow` permits everything, which is the convention's
        // own way of writing "no rules". It contributes nothing rather than a
        // rule that matches every path.
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

    // The group that named this agent wins whole, so a file that says
    // "everybody is disallowed, chock is allowed" is read the way it was
    // written. An empty specific group is still a group: it means this agent
    // was named and given no rule.
    const chosen: *std.ArrayList(Rule) = if (namesTheAgent(source, agent)) &specific else &wildcard;
    return chosen.toOwnedSlice(gpa);
}

/// Whether `source` names `agent` in any `User-agent` line at all.
///
/// Its own pass, because `rulesFor` cannot know while it reads the first group
/// whether a later group names this agent, and a file that names it after the
/// wildcard group must still be read for the specific one.
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

/// True when `rules` permit `path`.
///
/// The longest matching prefix decides, and an `Allow` wins a tie against a
/// `Disallow` of the same length. That is what the convention asks for and
/// what every other client does.
///
/// **A `*` and a `$` in a rule are read as ordinary characters.** Those are an
/// extension rather than the convention, matching them needs a pattern engine,
/// and reading them literally errs towards fetching less than a permissive
/// reading would: a rule written `Disallow: /*.pdf` then matches nothing, so
/// only the plain prefixes decide. See this file's own top comment on what
/// this is for.
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

/// One session's fetching: the policy it runs under, the `robots.txt` it has
/// already read, and the one call that reads a URL.
///
/// **One of these belongs to one session.** It holds the spawn chain that
/// session runs under, so a subagent's own fetcher answers with its parent's
/// limits folded in.
pub const Session = struct {
    gpa: std.mem.Allocator,
    /// The project's own table, read one time at the start of the session.
    /// It cannot change while the session runs.
    table: *const table.Table,
    /// Every agent kind from the root of the spawn tree down to this session,
    /// root first. The same chain every other policy question uses.
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    /// The tool the agent called, which is one of the four parts of a policy
    /// key. See `chock_policy.table.Key`.
    tool: []const u8,
    /// The environment `actions.perform` starts from. Borrowed, and never read
    /// for a credential: see this file's own top comment.
    env: *const std.process.Environ.Map,
    /// Where a host name becomes the addresses the broker checks before it
    /// opens anything. **The default is the real resolver**, so a session that
    /// says nothing gets the guard, and there is no configuration path to this
    /// field: see `actions.Resolver`.
    resolver: actions.Resolver = .system,
    /// Whether a connection may be opened to an address at all. Carried
    /// straight to `actions.Context.reachable`, which holds the whole reason
    /// this field exists and names its one caller.
    reachable: *const fn (address: actions.Resolver.Address) bool = network.addressIsReachable,
    robots: Robots = .{},
    /// How many redirects one call may follow.
    hop_limit: usize = max_hops,

    pub fn deinit(self: *Session) void {
        self.robots.deinit(self.gpa);
        self.* = undefined;
    }

    /// Read one URL, following a redirect only to a host the policy permits in
    /// its own right.
    ///
    /// `self_policy` is what the asking session promised about itself, folded
    /// from its own `policy.self` events. **It is applied here and not by the
    /// agent**, which is the rule `lib/chock-policy/ratchet.zig` states: a
    /// check an agent performs on itself is worth nothing.
    ///
    /// `diag` carries the detail a person reads. The agent reads
    /// `Refusal.text`, which never holds a path or a host the agent did not
    /// already name.
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
            // A URL with user information becomes an `Authorization` header,
            // so this is where a credential would leave. See this file's own
            // top comment.
            if (uri.user != null or uri.password != null) return refuse(
                .url_carries_user_information,
                try self.gpa.dupe(u8, "nothing was read: that URL carries user information " ++
                    "before the host, which would send an Authorization header. Chock never " ++
                    "sends a credential to a fetched host. Give the URL without it."),
            );

            // A scratch arena per hop, for the host, the authority and the
            // path. Every one of them points into `url` or into a decoded
            // copy of it, and `url` is replaced at the end of the loop.
            var arena_state = std.heap.ArenaAllocator.init(self.gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            const host_component = uri.host orelse return refuse(
                .url_not_usable,
                try self.gpa.dupe(u8, "nothing was read: that URL names no host."),
            );
            const host = try host_component.toRawMaybeAlloc(arena);

            const decision = self.decide(host, request.self_policy);
            if (decision != .allow) {
                if (diagnostic.wants(diag)) {
                    // The same key `refusalForHost` names to the agent, built
                    // the same way, so the two readers are never told to write
                    // two different rules.
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
            // **The address guard can stop this request too**, and it is the
            // first request of the hop, so a refusal that came from it must
            // say so rather than be read as a site that stated no rules.
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
                // The address the name answered with, refused after the lookup
                // and before anything was opened. See this file's own top
                // comment: this arrives on every hop, because every hop asks
                // the broker afresh.
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
                // **The bytes are dropped and the agent is told so.** Handing
                // over a body nothing decoded would put a page of unreadable
                // bytes in the context under a header that calls it the page.
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
                // **The whole reason a redirect is not delegated to the HTTP
                // client.** The next turn of this loop asks the policy about
                // the host the Location names, before anything reaches it.
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
            // The body is handed on rather than copied. The URL is copied,
            // because this function's own `defer` frees `url`.
            errdefer self.gpa.free(answered.body);
            return .{ .fetched = .{
                .url = try self.gpa.dupe(u8, url),
                .status = answered.status,
                .body = answered.body,
                .hops = hop,
            } };
        }
    }

    /// What the policy answers for one host, with this session's own promises
    /// folded in.
    ///
    /// **Two readings of the same rules, and both are needed.** The host key
    /// is read as a decision, so a host no rule names answers `ask` and is
    /// refused: a policy that forgot a case must not become permission. The
    /// bare class name `net.fetch` is read as a **ceiling** over the promises
    /// only, so a session that promised nothing is narrowed by nothing, and a
    /// session that promised `net.fetch` at `deny` is stopped even though that
    /// name is not the host key. `restrict_self` offers exactly that promise in
    /// its own description, so it has to bind here.
    pub fn decide(
        self: *const Session,
        host: []const u8,
        self_policy: []const ratchet.Restriction,
    ) table.Decision {
        var buffer: [max_action_bytes]u8 = undefined;
        const action = actionInto(&buffer, host) orelse return .deny;

        // A chain this table cannot fold answers `ask`, which is a refusal
        // here, so the fault changes nothing about the outcome and is not
        // kept. It could not be kept as it stands either: a `ChainFault`
        // borrows the action, and the action lives in the stack buffer above.
        // The same reading `lib/chock-broker/network.zig` makes.
        const answer = self.table.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, null);

        return ratchet.narrow(answer, self_policy, action)
            .intersect(ratchet.ceilingFor(self_policy, action_prefix));
    }

    /// What the agent is told about a name that answers this machine.
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

    /// The fault that means the address guard stopped a request, rather than
    /// the request failing on the network.
    const AddressError = error{AddressNotPermitted};

    /// The rules of one authority's `robots.txt`, read once and kept.
    ///
    /// **A refusal from the address guard is given back and not swallowed.**
    /// This is the first request of a hop, so it is the one that meets the
    /// guard, and a caller that read it as "the site stated no rules" would
    /// keep that emptiness for the whole session and report the page request
    /// as the cause instead.
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
        // **The detail travels from here too.** This is the first request of a
        // hop, so it is the one that meets the address guard, and a `diag` left
        // null here would lose the only reason a person reads.
        var result = self.perform(io, .{
            .host = host,
            .url = url,
            .max_bytes = max_robots_bytes,
        }, diag) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Not a network fault at all: the guard turned this request away
            // before anything opened, and the same guard would turn the page
            // request away for the same reason. The caller names it.
            error.AddressNotPermitted => return error.AddressNotPermitted,
            // A site that does not answer for `robots.txt` has stated no
            // rules. **Failing open is the convention's own answer**, and it
            // is the honest one here: this is not a boundary, so a network
            // fault must not become a refusal the agent cannot explain.
            else => {
                try self.robots.keep(self.gpa, authority, &.{});
                return &.{};
            },
        };
        defer result.deinit(self.gpa);

        // Anything but 200 states no rules. A 404 is the ordinary case for a
        // site with no file, and a redirect for `robots.txt` is not followed:
        // the redirect rule of this file would need a second policy question
        // for a request the agent never asked for.
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

    /// One hop, through the broker's own `net.fetch` action.
    ///
    /// **Nothing here opens a socket.** `actions.perform` is the privileged
    /// act, it reads one URL on one host, and it follows nothing. This file
    /// decides which host, and that is the whole division.
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

    /// What the agent is told about a host the policy turned away. It names
    /// the row that would permit it, because a refusal a reader cannot act on
    /// costs a turn and teaches nothing.
    ///
    /// **This is the model's sentence and not the person's.** It tells the
    /// agent that the file is the user's to write and its own to leave alone,
    /// which is what stops the agent trying to write it or going round it.
    /// The person watching reads
    /// `chock_broker.Diagnostic.fetch_host_not_permitted` instead, which says
    /// the same fact in the second person. Do not fold the two together: see
    /// `chock_proto.event.ToolResult.note`.
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

/// What one `fetch` call asks for.
pub const Request = struct {
    /// The URL the agent named. Borrowed for the call.
    url: []const u8,
    /// What the asking session promised about itself, folded from its own
    /// `policy.self` events. Empty narrows nothing.
    self_policy: []const ratchet.Restriction = &.{},
};

/// One refusal, with the sentence the agent reads. `text` is owned by whoever
/// holds the `Outcome`.
fn refuse(kind: Refusal.Kind, text: []u8) Outcome {
    return .{ .refused = .{ .kind = kind, .text = text } };
}

/// True for the redirect statuses that name a new location.
fn isRedirect(status: u16) bool {
    return switch (status) {
        301, 302, 303, 307, 308 => true,
        else => false,
    };
}

/// The bytes of one URL component, whichever way it is spelled. A `Component`
/// is either raw or percent encoded, and this is only used to measure a
/// buffer, so the two are the same thing here.
fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |text| text,
        .percent_encoded => |text| text,
    };
}

/// `<scheme>://<host>[:<port>]` for `uri`, in `arena`.
fn authorityOf(arena: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const host = try (uri.host.?).toRawMaybeAlloc(arena);
    if (uri.port) |port| {
        return std.fmt.allocPrint(arena, "{s}://{s}:{d}", .{ uri.scheme, host, port });
    }
    return std.fmt.allocPrint(arena, "{s}://{s}", .{ uri.scheme, host });
}

/// The absolute URL `location` names, resolved against `base`, in `arena`.
///
/// A `Location` may be relative, so this is the one place a redirect target
/// becomes a whole URL again. It is written out rather than kept as a
/// `std.Uri`, because the next turn of the loop parses it afresh and every
/// check runs again over exactly the bytes the next request will use.
fn resolve(
    arena: std.mem.Allocator,
    base: std.Uri,
    location: []const u8,
) (Error || std.Uri.ResolveInPlaceError)![]u8 {
    // `resolveInPlace` wants the location at the head of a buffer it may also
    // use for a merged path, and it writes into it. The merged path is at most
    // the base path and the new one together, and the new one is inside
    // `location`.
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
    // Case folded, because a host name is not case sensitive and a key is.
    try testing.expectEqualStrings("net.fetch.com.example.www", actionFor(&buffer, "WWW.Example.COM"));
    // A literal address is a name here too, and needs a row of its own.
    try testing.expectEqualStrings("net.fetch.1.0.0.127", actionFor(&buffer, "127.0.0.1"));
}

test "a class rule covers only the subtree below it, and never a host that merely ends the same way" {
    var buffer: [max_action_bytes]u8 = undefined;
    const inside = actionFor(&buffer, "docs.example.com");
    try testing.expect(table.patternMatches("net.fetch.com.example.*", inside));

    var other: [max_action_bytes]u8 = undefined;
    // The whole point of reversing: a name an agent invents falls under the
    // class an author wrote, and can never climb out of it.
    const outside = actionFor(&other, "example.com.evil.net");
    try testing.expect(!table.patternMatches("net.fetch.com.example.*", outside));
    try testing.expectEqualStrings("net.fetch.net.evil.com.example", outside);
}

test "bytes that are not a host name build no key at all" {
    var buffer: [max_action_bytes]u8 = undefined;
    try testing.expect(actionInto(&buffer, "") == null);
    try testing.expect(actionInto(&buffer, "example..com") == null);
    try testing.expect(actionInto(&buffer, ".example.com") == null);
    // A `*` would otherwise let a name match a class rule an author never
    // wrote.
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
    // The wildcard group disallows everything. Reading it here instead of the
    // specific group would refuse every path on the site.
    try testing.expect(pathIsAllowed(rules, "/public"));
    try testing.expect(!pathIsAllowed(rules, "/private"));

    // **And the header is not what a group names.** The `User-Agent` on the
    // wire carries the version, so matching a group against it would leave the
    // `chock` group above unmatched and read the wildcard group instead, which
    // disallows the whole site. Nothing would say so: the file would still be
    // fetched, and every rule written for Chock would stop binding it. That is
    // the cost of the mistake, measured here on the reader itself.
    //
    // Mutation check: drop the version from `user_agent` and the first line
    // below fails, because the two readings stop differing. Pass `user_agent`
    // to `rulesFor` in `robotsFor` instead and this test still passes, because
    // it reads `rulesFor` and not a session: what catches that is "a robots.txt
    // group naming chock beats the wildcard group on a real server" in
    // `test/broker/fetch.zig`, which drives the whole session against a real
    // server.
    const by_header = try rulesFor(gpa, source, user_agent);
    defer {
        for (by_header) |rule| gpa.free(rule.path);
        gpa.free(by_header);
    }
    try testing.expect(!pathIsAllowed(by_header, "/public"));
    // Which says something only while the two really differ.
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
    // The suspicious edge, and the one a test is worth: a cache that dropped
    // the new rules instead would leave every site past the bound read under no
    // rules at all, and nothing would say so.
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
    // The site read last is there, with its rules.
    var last: [64]u8 = undefined;
    const newest = try std.fmt.bufPrint(&last, "http://host{d}.example.com", .{max_robots_hosts});
    const kept = cache.find(newest) orelse return error.NewestSiteWasDropped;
    try testing.expect(!pathIsAllowed(kept, "/private/notes"));
    // The site read first is gone, which is the one that was dropped.
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
    // Nobody named it, so the answer is `ask`, and only `allow` reads a host.
    try testing.expectEqual(table.Decision.ask, session.decide("example.org", &.{}));
    // The reversal again, at the decision rather than at the key.
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

    // This is the promise `restrict_self` offers in its own description. It
    // names the class and not a host, so only the second reading in `decide`
    // catches it.
    const promised = [_]ratchet.Restriction{.{
        .action = "net.fetch",
        .ceiling = .deny,
        .reason = "this task reads local files",
    }};
    try testing.expectEqual(table.Decision.deny, session.decide("docs.example.com", &promised));
    // And a promise about one host still binds only that host.
    const one_host = [_]ratchet.Restriction{.{
        .action = "net.fetch.com.example.www",
        .ceiling = .deny,
        .reason = "not that one",
    }};
    try testing.expectEqual(table.Decision.deny, session.decide("www.example.com", &one_host));
    try testing.expectEqual(table.Decision.allow, session.decide("docs.example.com", &one_host));
}
