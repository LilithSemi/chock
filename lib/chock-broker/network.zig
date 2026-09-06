//! The network broker: who answers when a sandboxed process asks to reach a
//! host, and on what grounds.
//!
//! This is the implementation of `chock_sandbox.NetBroker`. The mechanism
//! lives in `lib/chock-sandbox/linux/netbroker.zig`, which carries the request
//! across the sandbox boundary and the connected descriptor back. **The
//! decision lives here**, in the library that already holds the policy table,
//! because a sandboxed process must not be able to reach a host merely by
//! knowing its address.
//!
//! ## Why this exists at all
//!
//! A tool call gets `Network.none`, and that is right for a tool call and for
//! a language server. It is useless for an MCP server: most of them exist to
//! reach the network, and `host` hands a third party program the exact thing
//! the sandbox exists to withhold. `filtered` is the only honest answer, and
//! this is the half of it that decides.
//!
//! ## A host rule is an action name, and not a second policy system
//!
//! The policy table answers on dotted action names, with `.*` matching
//! everything below a prefix. A host is a dotted name too, and its hierarchy
//! runs the other way: `api.anthropic.com` is inside `anthropic.com`, which is
//! inside `com`. So the labels are **reversed**, the port is put last, and the
//! result is an ordinary action:
//!
//! ```
//! api.anthropic.com:443   ->   net.connect.com.anthropic.api.443
//! ```
//!
//! Which makes every rule in the table's own language mean what an author
//! would expect it to mean:
//!
//! ```zon
//! .{ .action = "net.connect.com.anthropic.*", .decision = .allow }      // any host under anthropic.com, any port
//! .{ .action = "net.connect.com.anthropic.api.443", .decision = .allow } // that host, that port, and nothing else
//! .{ .action = "net.connect.*", .decision = .deny }                      // nothing reaches anything
//! ```
//!
//! **Reversal is what makes a class rule safe.** Without it, `net.connect.api.*`
//! would cover `api.anything.at.all`, which is the opposite of what a reader
//! would take it to mean. With it, a name a sandboxed process invents can only
//! ever fall **under** the class an author wrote: a request for
//! `evil.com.anthropic.api` becomes `net.connect.api.anthropic.com.evil.443`,
//! which `net.connect.com.anthropic.*` does not match.
//!
//! ## Only `allow` grants outright, and `ask` may now ask
//!
//! `evaluateChain` gives one of five decisions. `allow` grants at once,
//! `deny`, `agent_review` and `agent_then_human` still refuse outright, and
//! `ask` reaches a person when there is a way to ask one.
//!
//! **This used to be a flat refusal on every decision but `allow`, and the
//! reasoning for it was correct at the time.** A connection is served from
//! inside a tool call that is already running: `Sandbox.spawn` is in its wait
//! loop, called from the same turn of `Loop.run` that holds the session log's
//! own exclusive lock. Asking meant writing a question into that log and
//! waiting for an answer, and the one thing that could write an answer was
//! the very loop that was blocked on this call. A question with no possible
//! answer is not a question, so refusing was the safe direction and the only
//! honest one.
//!
//! **The fact under that reasoning changed, and not the reasoning itself.**
//! `Broker.request` writes the question and waits for the answer through the
//! caller's own locked handle, in the same process, rather than through a
//! second lock of its own: see `lib/chock-broker/Broker.zig`'s own top
//! comment on the one seam that made this possible. `Network` is broker side
//! already, so it can call `Broker.request` directly and let the same wait
//! that answers every other approval answer this one. `deny`, `agent_review`
//! and `agent_then_human` are not part of this change: a review still needs a
//! reviewer this file has no way to start, and a `deny` needs nobody asked at
//! all, so both still refuse outright the way they always did. An author who
//! wants a host reached without a question writes `allow` for it.
//!
//! ## The volume this creates, and the memory that bounds it
//!
//! `Broker.request` writes an `approval.response` for every decision it
//! reaches, `allow` included. This file still decides `allow` itself and
//! never calls the broker for it, so the common case costs what it always
//! did: nothing written. Only `ask` reaches the broker, and one MCP server
//! can open the same host and port hundreds of times in one session, so
//! asking a person every single time would flood the log with the same
//! question answered the same way. `chock_proto.state.SessionGrants`, held by
//! `Broker.request` itself, is what a person's `approved_by_user_for_session`
//! answer is remembered in: the second and every later connection to that
//! same action is answered from that memory, with no `approval.request` and
//! no `approval.response` of its own. See `Broker.request`'s own comment on
//! its `ask` branch for where that memory is read, and why there and nowhere
//! else.
//!
//! ## A child is never stronger than its parent
//!
//! It costs nothing to keep here: the key goes through `Table.evaluateChain`
//! with the same spawn chain every other question uses. `intersect` is a
//! minimum, so a subagent whose own kind says `allow` under a parent kind that
//! does not gets the parent's answer. There is no second path to a grant in
//! this file.
//!
//! ## DNS, and what a hostile name can do
//!
//! A name has to become an address somewhere. Doing it inside the sandbox
//! needs the network the sandbox does not have, so it happens here, which
//! means **this process resolves names a sandboxed process chose**. That is a
//! channel, and it is bounded like this:
//!
//! * **The policy is read first, and the name is resolved only after it
//!   permits.** So a name the table does not cover is never looked up at all,
//!   and a sandboxed process cannot use a lookup for a name nobody permitted
//!   as a way to reach the operator of that name.
//! * **Inside a class an author wrote, the leftmost labels are the sandboxed
//!   process's to choose.** Under `net.connect.com.example.*` it can have this
//!   process look up `anything.example.com`, and that query reaches the
//!   nameservers of `example.com`. So a class rule is a channel to whoever
//!   runs that zone, and this is the thing to know before writing one. An
//!   author who does not want that writes an exact rule, which leaves no
//!   labels to choose.
//! * **An address written out is a name here too, and nothing is special
//!   about it.** `93.184.216.34` passes the shape rule, because its bytes are
//!   digits and dots, so it becomes the action `net.connect.34.216.184.93.443`
//!   and needs a rule of its own before anything is reached. It resolves to
//!   itself and never leaves this process, and `addressIsReachable` still
//!   applies to it. An author who wants one permitted writes it out reversed,
//!   the same as any other name.
//! * **A name cannot be made to mean something else.** Every byte is checked
//!   against the shape rule before it reaches a key: letters, digits, hyphen
//!   and dot, no empty label, no leading or trailing dot, no label past 63
//!   bytes, and a total of at most 255. So a name cannot carry a `*`, a `\0`,
//!   or a run of dots, and cannot be built to match a rule an author did not
//!   write.
//!
//! ## The address the name resolved to is checked as well
//!
//! A permitted name that answers `127.0.0.1` or `169.254.169.254` would turn a
//! rule about a host on the internet into a handle on this machine and on the
//! cloud metadata service beside it. Whoever runs the permitted zone controls
//! that answer, so the address is checked after the lookup and before the
//! connect: see `addressIsReachable`, which names what is refused and what is
//! deliberately not.
//!
//! ## No test in this file reaches the network
//!
//! `Transport` is the seam, the same shape `chock_nix.provision.Runner` and
//! `Broker.Waiter` use. `System` is the real one, and it is the only thing in
//! this file that resolves a name or opens a socket. Every test drives a fake
//! that answers from a table and counts what it was asked, which is what lets
//! a test pin that a refused host **was never looked up**.
//!
//! ## One caller builds these, and it is the only one
//!
//! **This is the mechanism, not a feature that is switched on.** The MCP host
//! in `src/run.zig` is the only caller that sets `Sandbox.Config.network` to
//! `.filtered`, and it does so for one server only when this project's policy
//! answers `allow` for `mcp.<server>.network`. A tool call gets `Network.none`
//! and a language server gets `Network.none`, and neither should change.
//!
//! **A server that is let out still reaches nothing until a `net.connect.*`
//! rule names a host.** The two rules are separate on purpose: the first says
//! a server may have a socket, and the second says where it may point.
//!
//! **This caller builds every `Network` with `asker` left null.** MCP servers
//! start before `Loop.run` takes the session log's exclusive lock, so there is
//! no `Locked` handle yet to hand one. An `ask` decision there still refuses
//! outright, exactly as it always has: see `Network.Asker` and this file's
//! own top comment on the volume `ask` can now answer for a caller that does
//! hold one.
//!
//! What is real besides is `test/sandbox/escape.zig`, which drives this file
//! through a real `Sandbox.spawn` on every test run.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_sandbox = @import("chock-sandbox");
const chock_proto = @import("chock-proto");

const diagnostic = @import("diagnostic.zig");
/// Why the broker refused an act, or could not carry one out. One type for
/// the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

const Broker = @import("Broker.zig");
const event = chock_proto.event;

const table = chock_policy.table;
const NetBroker = chock_sandbox.NetBroker;

/// `chock_proto.storage.Locked` is not `pub`, so no file outside
/// `chock-proto` can name it. This reaches the same type through the return
/// type of `Storage.lock`, which is public: the same route
/// `chock_core.arbiter.Locked` uses, and for the same reason. `Broker.request`
/// takes a locked handle as `anytype` because it cannot name this either. A
/// struct field has to name a real type, so this file needs its own copy of
/// the trick.
pub const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// What every action name in this file starts with. This is the action class
/// for reaching a host.
pub const action_prefix = "net.connect";

/// The longest host name a request can carry. The same bound the mechanism
/// uses, and the same one DNS itself has.
pub const max_host_bytes = chock_sandbox.net_broker.max_host_bytes;

/// The longest action name `actionInto` can build: the prefix, a separator,
/// the reversed name, a separator, and a port of at most five digits.
pub const max_action_bytes = action_prefix.len + 1 + max_host_bytes + 1 + 5;

/// The action name for reaching `host` on `port`, written into `buffer`.
/// Null when the name is not a name this file will build a key out of, or
/// when it does not fit.
///
/// **The labels are reversed, and that is the whole trick.** See this file's
/// own top comment. `buffer` must hold `max_action_bytes`.
///
/// Allocates nothing: `NetBroker.connect` has no allocator and no error to
/// give back, so every step of answering one request runs in a fixed buffer.
pub fn actionInto(buffer: []u8, host: []const u8, port: u16) ?[]const u8 {
    if (buffer.len < max_action_bytes) return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;

    var written: usize = 0;
    @memcpy(buffer[0..action_prefix.len], action_prefix);
    written += action_prefix.len;

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
        // key is. Without this, `API.Anthropic.Com` would be a different
        // action from `api.anthropic.com` and would match no rule.
        for (label, buffer[written..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        written += label.len;
        end = if (start == 0) 0 else start - 1;
    }

    const tail = std.fmt.bufPrint(buffer[written..], ".{d}", .{port}) catch return null;
    return buffer[0 .. written + tail.len];
}

/// Where a name is resolved and a connection is opened. **The one seam in this
/// file**, and the reason no test here reaches the network.
///
/// Two methods and not one, because the check between them is the point: the
/// address a name resolved to is refused or accepted before anything dials it,
/// and a seam that did both at once would leave that check untestable.
pub const Transport = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Address = std.Io.net.IpAddress;

    pub const LookupError = error{
        /// The name did not resolve, whatever the reason was. **One member and
        /// not the resolver's own set**, because none of the reasons changes
        /// what happens here: there is no address, so there is no connection.
        NotResolved,
    };

    pub const DialError = error{
        /// The connection was not opened. One member, for the reason
        /// `LookupError` has one.
        NotConnected,
    };

    pub const VTable = struct {
        /// One address for `host` on `port`. The first the resolver gives.
        lookup: *const fn (ptr: *anyopaque, io: std.Io, host: []const u8, port: u16) LookupError!Address,
        /// A connected descriptor for an address this file has already
        /// permitted. **The caller owns it**, and hands it straight to the
        /// driver, which closes it after the send.
        dial: *const fn (ptr: *anyopaque, io: std.Io, address: Address) DialError!std.posix.fd_t,
    };

    pub fn lookup(self: Transport, io: std.Io, host: []const u8, port: u16) LookupError!Address {
        return self.vtable.lookup(self.ptr, io, host, port);
    }

    pub fn dial(self: Transport, io: std.Io, address: Address) DialError!std.posix.fd_t {
        return self.vtable.dial(self.ptr, io, address);
    }
};

/// True when a connection may be opened to `address` at all.
///
/// **This is not a host policy.** The host policy already said yes; this is
/// the answer to a different question, which is whether the name it said yes
/// to resolved to something on the network or to this machine. Whoever runs
/// the permitted zone decides what the name answers, so a rule about a host on
/// the internet must not become a handle on the loopback interface or on the
/// cloud metadata service.
///
/// Refused:
///
/// * **Loopback**, `127.0.0.0/8` and `::1`. This machine's own services,
///   including whatever the harness itself is listening on.
/// * **Link local**, `169.254.0.0/16` and `fe80::/10`. `169.254.169.254` is
///   the cloud metadata service on every large provider, and it hands out
///   credentials to whoever asks.
/// * **Unspecified**, `0.0.0.0` and `::`, which name this machine on Linux.
/// * **Multicast and broadcast**, `224.0.0.0/4`, `255.255.255.255`, and
///   `ff00::/8`. Nothing a stream connection does needs one.
/// * **A refused IPv4 address behind the NAT64 well-known prefix**,
///   `64:ff9b::/96`. A translator turns `64:ff9b::a9fe:a9fe` into
///   `169.254.169.254`, so the prefix is unwrapped and the IPv4 rules above
///   answer for it.
/// * **`fd00:ec2::254`**, the EC2 instance metadata service over IPv6, which
///   hands out the same credentials as its IPv4 twin.
///
/// **The private ranges are deliberately not refused**, `10.0.0.0/8`,
/// `172.16.0.0/12` and `192.168.0.0/16`. A company's own API on its own
/// network is a legitimate thing for a permitted name to resolve to, and
/// refusing it would make this useless in exactly the place a host policy is
/// most wanted. An author who does not want one writes no rule that reaches
/// it.
///
/// **`fc00::/7` is deliberately not refused either**, and only the one address
/// inside it above is. Unique local addressing is the IPv6 form of exactly the
/// case the private IPv4 ranges are permitted for. Refusing the range would
/// break a company's own API on its own IPv6 network, and would push those
/// deployments back onto IPv4.
pub fn addressIsReachable(address: Transport.Address) bool {
    switch (address) {
        .ip4 => |ip4| return ip4BytesAreReachable(ip4.bytes),
        .ip6 => |ip6| {
            // An IPv4 address written as an IPv6 one is still that IPv4
            // address, so it is checked by the same rules. Without this,
            // `::ffff:127.0.0.1` would walk straight past every check below.
            if (std.Io.net.Ip4Address.fromIp6(ip6)) |ip4| return ip4BytesAreReachable(ip4.bytes);
            // `fromIp6` knows `::ffff:/96` and no other prefix, so NAT64 is
            // unwrapped here. On a NAT64 network `64:ff9b::a9fe:a9fe` reaches
            // `169.254.169.254`, and a NAT64 network is what the IPv6 fallback
            // of `actions.pinnedConnection` exists to keep working. One unwrap
            // closes the loopback twin and the unspecified twin with the
            // metadata one, so there is no second set of IPv4 rules here.
            if (std.mem.startsWith(u8, &ip6.bytes, &nat64_well_known_prefix))
                return ip4BytesAreReachable(ip6.bytes[12..16].*);
            if (std.mem.eql(u8, &ip6.bytes, &ec2_metadata_ip6)) return false;
            if (ip6.isLoopBack() or ip6.isLinkLocal() or ip6.isMultiCast()) return false;
            for (ip6.bytes) |byte| {
                if (byte != 0) return true;
            }
            // All zero is the unspecified address.
            return false;
        },
    }
}

/// The first 12 bytes of `64:ff9b::/96`, the NAT64 well-known prefix of RFC
/// 6052 section 2.1. The last four bytes are the IPv4 address a translator
/// reaches.
const nat64_well_known_prefix = [_]u8{ 0x00, 0x64, 0xff, 0x9b } ++ [_]u8{0} ** 8;

/// `fd00:ec2::254`, the EC2 instance metadata service over IPv6. AWS documents
/// this one address, and it answers with the same credentials as
/// `169.254.169.254`.
const ec2_metadata_ip6 = [_]u8{ 0xfd, 0x00, 0x0e, 0xc2 } ++ [_]u8{0} ** 10 ++ [_]u8{ 0x02, 0x54 };

fn ip4BytesAreReachable(bytes: [4]u8) bool {
    if (bytes[0] == 127) return false;
    if (bytes[0] == 169 and bytes[1] == 254) return false;
    if (bytes[0] == 0) return false;
    // `224.0.0.0/4` is multicast, and everything above it is reserved or the
    // broadcast address.
    if (bytes[0] >= 224) return false;
    return true;
}

/// What a `Network` needs to turn a refusal into a question. Every part of
/// this is borrowed: the caller that builds one still owns the broker, the
/// storage, and the lock, for as long as the `Network` beside it lives.
///
/// **`broker.policy` must be the same table this file's own `Network.table`
/// is.** Nothing here checks that. It is a caller invariant the same way a
/// subagent's own chain is. The two are read separately, once here and once
/// inside `Broker.request`, so an author who wires them to different tables
/// has built a `Network` that decides on one policy and asks on another.
pub const Asker = struct {
    broker: *const Broker,
    storage: chock_proto.storage.Storage,
    locked: *Locked,
};

/// The most parents `askPermits` will build a `Broker.Request` for.
/// Generous against `chock_policy.subagents.default_max_depth`, which is 6,
/// so no session built under this project's own limits comes near it. A
/// chain deeper than this refuses rather than allocates, the same safe
/// direction every other bound in this file takes.
const max_chain_parents = 32;

/// The network broker for one sandboxed call.
///
/// **One of these belongs to one `Sandbox.spawn`.** It holds the policy that
/// call runs under, including the spawn chain of the agent that asked for it,
/// so a subagent's own broker answers with its parent's limits folded in and
/// there is nothing to pass along at request time.
pub const Network = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    /// The project's own table, read one time at the start of the session.
    /// It cannot change while the session runs, which is what makes a granted
    /// descriptor's age harmless. See `NetBroker` itself.
    table: *const table.Table,
    /// Every agent kind from the root of the spawn tree down to the agent this
    /// call belongs to, root first. The same chain every other policy question
    /// uses: see `Table.evaluateChain`.
    chain: []const []const u8,
    /// The three parts of the key that are not the action.
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,
    /// Where a name is resolved and a connection is opened.
    transport: Transport,
    /// What lets a refusal become a question, when there is one to ask. Null
    /// for a `Network` built where there is no `Locked` handle to give it:
    /// the MCP startup path in `src/run.zig` builds one before `Loop.run`
    /// takes the session lock, so it has none to give. See this file's own
    /// top comment on what changed and what did not.
    asker: ?Asker = null,

    /// How many connections were granted and how many were refused, so a
    /// caller can say what a call did without reading a log.
    granted: usize = 0,
    refused: usize = 0,
    /// Why the first refusal happened, for the caller to report. **The first
    /// and not the last**, the same rule every other diagnostic in this
    /// project follows: a later refusal is usually the same one again.
    ///
    /// `NetBroker.connect` has no error to give back and nothing it says
    /// crosses the boundary, so this is the only place a reason can go. The
    /// caller releases it with `Diagnostic.deinit`.
    diagnostic: ?Diagnostic = null,

    pub fn netBroker(self: *Network) NetBroker {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = NetBroker.VTable{ .connect = connectFn };

    fn connectFn(ptr: *anyopaque, host: []const u8, port: u16) NetBroker.Grant {
        const self: *Network = @ptrCast(@alignCast(ptr));
        return self.answer(host, port);
    }

    /// Answer one request. Its own function, taking and giving ordinary
    /// values, so every test below drives the same code the driver drives.
    pub fn answer(self: *Network, host: []const u8, port: u16) NetBroker.Grant {
        // **The policy first, and the name second.** Nothing above this line
        // touches the network, and nothing below it runs for a host the table
        // does not permit: see this file's own top comment on DNS.
        var buffer: [max_action_bytes]u8 = undefined;
        // **The name is not kept for this one.** It failed the shape rule, so
        // it holds bytes a host name cannot hold, and this diagnostic reaches
        // a terminal and a session log. A name that never passed the rule is
        // not a name worth putting in either.
        const action = actionInto(&buffer, host, port) orelse
            return self.refuse(.{ .net_host_not_a_name = .{ .host = "", .port = port } });

        // A chain this table cannot fold answers `ask`, which is a refusal
        // here, so the fault changes nothing about the outcome and is not
        // kept. **It could not be kept as it stands**: a `ChainFault` borrows
        // the action, and the action lives in the stack buffer above, which is
        // gone the moment this returns. The decision the refusal records says
        // `ask` either way, which is the same thing a table with no rule says.
        var fault: ?table.ChainFault = null;
        const decision = self.table.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, &fault);
        if (decision != .allow) {
            // **Only `ask` is ever sent on.** `deny`, `agent_review` and
            // `agent_then_human` are refused right here, exactly as they
            // always were: see this file's own top comment for why asking a
            // person is the one case that changed, and not the other two.
            if (decision == .ask) {
                if (self.asker) |asker| {
                    if (self.askPermits(asker, action, host, port)) return self.finishConnect(host, port);
                    return .refused;
                }
            }
            return self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = decision,
            } });
        }

        return self.finishConnect(host, port);
    }

    /// Ask the broker about a connection this file's own table did not answer
    /// `allow` about. True when it may proceed. A refusal is recorded exactly
    /// the way every other refusal in this file is, so a caller reads
    /// `diagnostic` and `refused` for either path and never a third one.
    ///
    /// **`action` is a `net.connect` action, never a general one.** Building
    /// the same key twice, once here and once inside `Broker.request`, is not
    /// the second evaluation this file's own top comment warns against: the
    /// table `Broker.request` reads is the one that decides, and this
    /// function never reads its answer to grant anything on its own. The
    /// evaluation above this call is what routes here in the first place, and
    /// nothing routes here that the table did not already say `ask` about.
    fn askPermits(self: *Network, asker: Asker, action: []const u8, host: []const u8, port: u16) bool {
        // The parents of this agent, in the shape `Broker.Request` wants: see
        // `event.SpawnLink`. `self.chain` already ends with this agent's own
        // kind, which `Broker.Request.agent_kind` carries separately, so only
        // what comes before it is a parent.
        const parents = self.chain[0 .. self.chain.len - 1];
        if (parents.len > max_chain_parents) {
            _ = self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = .ask,
            } });
            return false;
        }
        var links: [max_chain_parents]event.SpawnLink = undefined;
        for (parents, links[0..parents.len]) |kind, *slot| slot.* = .{ .agent_kind = kind, .reason = "" };

        // A description for whoever answers. `NetBroker.connect` gives this
        // file only a host and a port, so that is all either string can say.
        var summary_buf: [max_host_bytes + 40]u8 = undefined;
        const summary = std.fmt.bufPrint(&summary_buf, "reach {s} on port {d}", .{ host, port }) catch
            "reach a host this session's MCP server asked for";

        const outcome = asker.broker.request(self.gpa, self.io, asker.storage, asker.locked, .{
            .action = action,
            .summary = summary,
            .detail = summary,
            .reason = "",
            .agent_kind = self.agent_kind,
            .model_alias = self.model,
            .tool = self.tool,
            .tool_call_id = "",
            .spawn_chain = links[0..parents.len],
        }, null) catch {
            _ = self.refuse(.{ .net_host_not_permitted = .{
                .host = self.copy(host),
                .port = port,
                .decision = .ask,
            } });
            return false;
        };

        if (outcome.permits()) return true;
        _ = self.refuse(.{ .net_host_not_permitted = .{
            .host = self.copy(host),
            .port = port,
            .decision = .ask,
        } });
        return false;
    }

    /// The name is resolved and the connection is opened, for a request this
    /// file has already decided may proceed, whether the table said `allow`
    /// on its own or the broker said yes on its behalf.
    fn finishConnect(self: *Network, host: []const u8, port: u16) NetBroker.Grant {
        const address = self.transport.lookup(self.io, host, port) catch
            return self.refuse(.{ .net_host_not_resolved = self.about(host, port) });

        if (!addressIsReachable(address))
            return self.refuse(.{ .net_address_not_permitted = self.about(host, port) });

        const handle = self.transport.dial(self.io, address) catch
            return self.refuse(.{ .net_not_connected = self.about(host, port) });

        self.granted += 1;
        return .{ .granted = handle };
    }

    /// Count the refusal, keep the first reason, and say no.
    fn refuse(self: *Network, reason: Diagnostic) NetBroker.Grant {
        self.refused += 1;
        var owned = reason;
        if (!diagnostic.note(&self.diagnostic, owned)) owned.deinit(self.gpa);
        return .refused;
    }

    /// A `NetHost` for a reason that names only the host and the port.
    fn about(self: *Network, host: []const u8, port: u16) Diagnostic.NetHost {
        return .{ .host = self.copy(host), .port = port };
    }

    /// A copy of `host` for a diagnostic to keep.
    ///
    /// **The name has to be copied.** It points into the driver's own request
    /// buffer, which is gone the moment this answer returns, and the caller
    /// reads the diagnostic long after the call has ended.
    ///
    /// An allocation that fails gives an empty name rather than a fault. There
    /// is nowhere to report one from here, the answer is a refusal either way,
    /// and a refusal that says nothing is better than one that does not
    /// happen.
    fn copy(self: *Network, host: []const u8) []const u8 {
        return self.gpa.dupe(u8, host) catch "";
    }
};

/// The real transport: the resolver of this machine, and a real socket.
///
/// **Nothing else in this file reaches the network**, which is what makes
/// every test below honest. `chock_nix.provision.Runner` and `Broker.Waiter`
/// are the same shape and exist for the same reason.
///
/// **The lookup has no deadline of its own, and that is a known gap.** The
/// connect does, below. A resolver that never answers holds the driver's own
/// serve loop, and through it the sandboxed call, until the call's own
/// deadline ends the whole thing: see `lib/chock-core/tools.zig`, which
/// cancels a call that runs too long through the handle `spawn` gives it. So
/// nothing hangs forever, and the failure a person reads is the call's
/// deadline rather than the name that caused it. Giving the lookup a deadline
/// of its own would make that message better and is not built here.
pub const System = struct {
    /// How long one connection may take to open. A connection that never
    /// answers must not hold the sandboxed call, and the call's own deadline
    /// is a long way above this.
    timeout_ms: u64 = 10_000,

    pub fn transport(self: *System) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Transport.VTable{ .lookup = lookupFn, .dial = dialFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        port: u16,
    ) Transport.LookupError!Transport.Address {
        _ = ptr;
        // A literal address is still an address, and `hostBytesAreUsable`
        // lets one through because its digits and dots are a valid name. It
        // resolves to itself, and `addressIsReachable` then applies to it the
        // same way it applies to a name's answer.
        if (std.Io.net.IpAddress.parse(host, port)) |parsed| return parsed else |_| {}

        const name = std.Io.net.HostName.init(host) catch return error.NotResolved;
        var results: [16]std.Io.net.HostName.LookupResult = undefined;
        var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);

        var future = io.async(std.Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port } });
        defer future.cancel(io) catch {};

        // The first address, and nothing after it. A name with several
        // addresses is ordinary; every one of them is the same host as far as
        // this file is concerned, and taking the first is what a connect
        // would have done anyway.
        var found: ?Transport.Address = null;
        while (queue.getOne(io)) |result| {
            switch (result) {
                .address => |address| {
                    if (found == null) found = address;
                },
                .canonical_name => {},
            }
        } else |_| {}

        return found orelse error.NotResolved;
    }

    fn dialFn(ptr: *anyopaque, io: std.Io, address: Transport.Address) Transport.DialError!std.posix.fd_t {
        const self: *System = @ptrCast(@alignCast(ptr));
        const stream = address.connect(io, .{
            .mode = .stream,
            // `.awake` and not `.real`: a deadline must not move when NTP
            // steps the wall clock, or it fires early or never fires at all.
            // The same choice `chock_core.helper.Channel.deadlineIn` makes.
            .timeout = .{ .duration = .{
                .raw = .fromMilliseconds(@intCast(self.timeout_ms)),
                .clock = .awake,
            } },
        }) catch return error.NotConnected;
        return stream.socket.handle;
    }
};

const testing = std.testing;

/// A transport that resolves from a table and hands out a descriptor on a
/// pipe. It records every call, so a test reads what really happened rather
/// than trusting that it did.
const FakeTransport = struct {
    /// What each name resolves to. A name that is not here does not resolve.
    answers: []const Answer,
    lookups: usize = 0,
    dials: usize = 0,
    /// The last name a lookup was asked for, so a test can pin which name
    /// crossed and in what case.
    last_lookup: [max_host_bytes]u8 = @splat(0),
    last_lookup_len: usize = 0,
    /// Handed out on a dial, so a test can close it. The whole file and not
    /// only its number, because closing one needs both.
    handed: std.ArrayList(std.Io.File) = .empty,
    gpa: std.mem.Allocator,

    const Answer = struct {
        host: []const u8,
        address: Transport.Address,
    };

    fn transport(self: *FakeTransport) Transport {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Transport.VTable{ .lookup = lookupFn, .dial = dialFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        port: u16,
    ) Transport.LookupError!Transport.Address {
        _ = io;
        const self: *FakeTransport = @ptrCast(@alignCast(ptr));
        self.lookups += 1;
        @memcpy(self.last_lookup[0..host.len], host);
        self.last_lookup_len = host.len;
        for (self.answers) |one| {
            if (!std.mem.eql(u8, one.host, host)) continue;
            var address = one.address;
            address.setPort(port);
            return address;
        }
        return error.NotResolved;
    }

    fn dialFn(ptr: *anyopaque, io: std.Io, address: Transport.Address) Transport.DialError!std.posix.fd_t {
        _ = address;
        const self: *FakeTransport = @ptrCast(@alignCast(ptr));
        self.dials += 1;
        // **A real descriptor, and the plainest one both platforms have.**
        // What `Network` does with a descriptor is hand it back untouched, so
        // a real one is what proves it did: a test can then close exactly the
        // numbers that were handed out and find nothing left over. It is a
        // file and not a socket because this file's own tests build for Darwin
        // as well, where the socket calls of the Linux mechanism do not exist.
        const file = std.Io.Dir.cwd().openFile(io, "/dev/null", .{}) catch return error.NotConnected;
        self.handed.append(self.gpa, file) catch {
            file.close(io);
            return error.NotConnected;
        };
        return file.handle;
    }

    fn askedFor(self: *const FakeTransport) []const u8 {
        return self.last_lookup[0..self.last_lookup_len];
    }

    fn deinit(self: *FakeTransport, io: std.Io) void {
        for (self.handed.items) |file| file.close(io);
        self.handed.deinit(self.gpa);
    }
};

/// A table built from one policy source, for a test to ask.
fn tableFrom(gpa: std.mem.Allocator, source: [:0]const u8) !*const table.Table {
    return table.Table.parse(gpa, source, null);
}

/// A `Network` over a fake transport, with a chain of one link named "main".
const Bench = struct {
    gpa: std.mem.Allocator,
    policy: *const table.Table,
    fake: FakeTransport,
    network: Network = undefined,

    fn init(gpa: std.mem.Allocator, source: [:0]const u8, answers: []const FakeTransport.Answer) !Bench {
        return .{
            .gpa = gpa,
            .policy = try tableFrom(gpa, source),
            .fake = .{ .answers = answers, .gpa = gpa },
        };
    }

    /// Finish building. Separate from `init` because `Network` points at the
    /// fake, and a struct returned by value moves.
    fn ready(self: *Bench, chain: []const []const u8) *Network {
        self.network = .{
            .gpa = self.gpa,
            .io = testing.io,
            .table = self.policy,
            .chain = chain,
            .agent_kind = chain[chain.len - 1],
            .model = "main",
            .tool = "mcp",
            .transport = self.fake.transport(),
        };
        return &self.network;
    }

    fn deinit(self: *Bench) void {
        if (self.network.diagnostic) |*one| one.deinit(self.gpa);
        self.fake.deinit(testing.io);
        table.Table.destroy(self.gpa, self.policy);
    }
};

const allow_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .allow },
    \\        },
    \\    },
    \\}
;

test "a host name becomes an action whose labels run the other way" {
    // **This is what makes a class rule mean what a reader takes it to mean.**
    // Without the reversal, `net.connect.api.*` would cover `api.evil.test`,
    // and an author who wrote a rule about their own API host would have
    // written a rule about every host named `api` anywhere.
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "net.connect.com.anthropic.api.443",
        actionInto(&buffer, "api.anthropic.com", 443).?,
    );
    try testing.expectEqualStrings(
        "net.connect.localhost.8080",
        actionInto(&buffer, "localhost", 8080).?,
    );
    // A host name is not case sensitive and an action name is, so the name is
    // lowered. Without this a name in capitals would match no rule at all,
    // which is a refusal, and a name in capitals would also be a second
    // spelling of a name an author already permitted.
    try testing.expectEqualStrings(
        "net.connect.com.anthropic.api.443",
        actionInto(&buffer, "API.Anthropic.COM", 443).?,
    );

    // A name that is not a name builds no key at all, so nothing hostile can
    // reach the table.
    try testing.expect(actionInto(&buffer, "", 443) == null);
    try testing.expect(actionInto(&buffer, "a..b.com", 443) == null);
    try testing.expect(actionInto(&buffer, "a*b.com", 443) == null);
    try testing.expect(actionInto(&buffer, ".a.com", 443) == null);
    try testing.expect(actionInto(&buffer, "a.com.", 443) == null);
    try testing.expect(actionInto(&buffer, "a b.com", 443) == null);

    // A buffer that is too short is a refusal and never a truncated key. A
    // truncated key names a different action, and this file's whole job is to
    // build the right one.
    var small: [8]u8 = undefined;
    try testing.expect(actionInto(&small, "api.anthropic.com", 443) == null);

    // An address written out is a name here too, and it is reversed like any
    // other. So it needs a rule of its own, and a class rule about a host name
    // can never cover one. See this file's own top comment.
    try testing.expectEqualStrings(
        "net.connect.34.216.184.93.443",
        actionInto(&buffer, "93.184.216.34", 443).?,
    );
}

test "a class rule covers what is under the host and nothing that only looks like it" {
    // The attack a class rule invites: a name built so that the label an
    // author permitted is somewhere in the middle of it. Every one of these
    // must fall outside `net.connect.com.anthropic.*`, and the last two must
    // fall inside, or the rule permits nothing and the test is vacuous.
    var buffer: [max_action_bytes]u8 = undefined;
    const class = "net.connect.com.anthropic.*";

    const outside = [_][]const u8{
        "evil.com.anthropic.api",
        "anthropic.com.evil.test",
        "api.anthropic.com.evil.test",
        "anthropiccom",
        "notanthropic.com",
        "com.anthropic",
    };
    for (outside) |host| {
        const action = actionInto(&buffer, host, 443).?;
        try testing.expect(!table.patternMatches(class, action));
    }

    const inside = [_][]const u8{ "api.anthropic.com", "a.b.c.anthropic.com" };
    for (inside) |host| {
        const action = actionInto(&buffer, host, 443).?;
        try testing.expect(table.patternMatches(class, action));
    }
}

test "a permitted host is looked up, dialled, and the descriptor is handed back" {
    // The whole file in one call, and the case every other test here is a
    // refusal of. Without this one, a broker that refused everything would
    // pass every test below.
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const grant = network.answer("api.anthropic.com", 443);
    switch (grant) {
        .granted => |fd| try testing.expect(fd >= 0),
        .refused => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 0), network.refused);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), bench.fake.dials);
    // The name that crossed is the name that was asked for.
    try testing.expectEqualStrings("api.anthropic.com", bench.fake.askedFor());
}

test "a host the table does not permit is never looked up at all" {
    // **The DNS claim of this file's own top comment.** A refusal that
    // resolved first would make a lookup for any name a sandboxed process
    // chose, and a DNS query is a message to whoever runs that zone: a name
    // is a place to put bytes. So the count has to be zero, and not merely
    // the answer a refusal.
    //
    // Mutation check: move the `evaluateChain` block below the lookup in
    // `Network.answer` and this test fails while every other test in this
    // file still passes.
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "secret.evil.test", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("secret.evil.test", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);

    // A name this file would not build a key out of is refused earlier still,
    // and it is also never looked up.
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("a..b.evil.test", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
}

test "only allow permits, and every other decision is a refusal" {
    // A connection cannot wait for a person: it is served from inside a tool
    // call that is already running, and the loop that would ask is holding the
    // log's own lock and waiting for that call. So `ask` is a refusal here,
    // and so is `agent_review`, which needs a reviewer this has no way to
    // start. Both are narrowings and both are safe; what would not be safe is
    // reading either one as permission.
    const gpa = testing.allocator;

    const sources = [_][:0]const u8{
        // No rule at all, which the table answers with `ask`.
        \\.{ .policy = .{ .rules = .{} } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .ask } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .deny } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .agent_review } } } }
        ,
        \\.{ .policy = .{ .rules = .{ .{ .action = "net.connect.*", .decision = .agent_then_human } } } }
        ,
    };

    for (sources) |source| {
        var bench = try Bench.init(gpa, source, &.{
            .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
        });
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    }

    // And `allow` on the same host really does permit, or every case above is
    // vacuous.
    var permitted = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer permitted.deinit();
    const network = permitted.ready(&.{"main"});
    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
}

test "a subagent cannot reach a host its parent could not" {
    // The intersection, on the one question this file answers. The child kind
    // is permitted the host outright; the parent kind is not. `evaluateChain`
    // takes the intersection over the whole chain, so the child's own rule
    // never applies on its own.
    //
    // Mutation check: swap `evaluateChain` for `evaluateKindAlone` in
    // `Network.answer` and the second half of this test grants.
    const gpa = testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "net.connect.com.anthropic.*", .decision = .deny },
        \\            .{ .agent_kind = "fetcher", .action = "net.connect.com.anthropic.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const answers = [_]FakeTransport.Answer{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    };

    // The subagent on its own kind alone would be permitted: the table really
    // does say `allow` for it, so the refusal below is the fold and not a
    // missing rule.
    {
        var bench = try Bench.init(gpa, source, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"fetcher"});
        try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    }

    // Under the parent that cannot reach it, it cannot either.
    {
        var bench = try Bench.init(gpa, source, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{ "main", "fetcher" });
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        // And it was refused before anything was looked up, so a subagent
        // cannot even use its parent's refusal as a way to send a name out.
        try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    }
}

test "a permitted name that resolves onto this machine is still refused" {
    // Whoever runs the permitted zone decides what the name answers. A rule
    // about a host on the internet must not become a handle on the loopback
    // interface, or on the cloud metadata service that hands out credentials
    // to whoever asks it.
    //
    // Every address here is under a name the policy permits, so the policy is
    // not what refuses them: `addressIsReachable` is, after the lookup and
    // before the dial. The dial count says so.
    const gpa = testing.allocator;

    const refused = [_]Transport.Address{
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 127, 9, 9, 9 }, .port = 0 } },
        // The cloud metadata service.
        .{ .ip4 = .{ .bytes = .{ 169, 254, 169, 254 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 239, 1, 1, 1 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 255, 255, 255, 255 }, .port = 0 } },
        .{ .ip6 = .loopback(0) },
        .{ .ip6 = .unspecified(0) },
        // `fe80::1`, link local.
        .{ .ip6 = .{ .bytes = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        // `ff02::1`, multicast.
        .{ .ip6 = .{ .bytes = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 0 } },
        // **`::ffff:127.0.0.1`.** An IPv4 address written the other way is
        // still that address, and a check that only read the IPv6 rules would
        // let this one straight through.
        .{ .ip6 = .fromIp4(.{ .bytes = .{ 127, 0, 0, 1 }, .port = 0 }) },
        .{ .ip6 = .fromIp4(.{ .bytes = .{ 169, 254, 169, 254 }, .port = 0 }) },
        // **`64:ff9b::a9fe:a9fe`.** The metadata service behind the NAT64
        // well-known prefix. `Ip4Address.fromIp6` does not know this prefix, so
        // an unwrap of its own is what refuses it.
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 169, 254, 169, 254 }, .port = 0 } },
        // `64:ff9b::7f00:1`, which is `127.0.0.1` behind the same prefix. The
        // unwrap covers every IPv4 rule and not the metadata address alone.
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 127, 0, 0, 1 }, .port = 0 } },
        // `64:ff9b::`, which unwraps to the unspecified address.
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 0, 0, 0, 0 }, .port = 0 } },
        // The EC2 metadata service over IPv6.
        .{ .ip6 = .{ .bytes = ec2_metadata_ip6, .port = 0 } },
    };

    for (refused) |address| {
        const answers = [_]FakeTransport.Answer{
            .{ .host = "api.anthropic.com", .address = address },
        };
        var bench = try Bench.init(gpa, allow_anthropic, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
        // The lookup happened, so this really is the address check and not the
        // policy, and nothing was dialled.
        try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
        try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    }

    // **The private ranges are deliberately not refused.** A company's own API
    // on its own network is a legitimate thing for a permitted name to answer,
    // and a rule that refused these would make a host policy useless where it
    // is most wanted. This half of the test is what stops a later reader
    // adding them without noticing.
    const permitted = [_]Transport.Address{
        .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 5 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 172, 16, 3, 4 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 20 }, .port = 0 } },
        .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } },
        .{ .ip6 = .{ .bytes = .{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1}, .port = 0 } },
        // **`fd12:3456:789a::1`, an ordinary unique local address.** ULA is the
        // IPv6 form of the private ranges above, so the whole of `fc00::/7`
        // must stay permitted. Only `fd00:ec2::254` inside it is refused. This
        // line is what stops a later reader widening that one address into the
        // range.
        .{ .ip6 = .{ .bytes = .{ 0xfd, 0x12, 0x34, 0x56, 0x78, 0x9a } ++ [_]u8{0} ** 9 ++ [_]u8{1}, .port = 0 } },
        // A public IPv6 address behind the NAT64 prefix, so the unwrap refuses
        // by the IPv4 rules and does not refuse the prefix itself.
        .{ .ip6 = .{ .bytes = nat64_well_known_prefix ++ [_]u8{ 93, 184, 216, 34 }, .port = 0 } },
    };
    for (permitted) |address| {
        const answers = [_]FakeTransport.Answer{
            .{ .host = "api.anthropic.com", .address = address },
        };
        var bench = try Bench.init(gpa, allow_anthropic, &answers);
        defer bench.deinit();
        const network = bench.ready(&.{"main"});
        try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    }
}

test "a name that does not resolve, and a connection that does not open, are refusals and not faults" {
    // Both are ordinary: a name can be wrong and a host can be down. Neither
    // may end the call, and neither may look to the sandboxed process like
    // anything other than the refusal a policy gives.
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{});
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);

    // And the reason is kept for the person reading the session, which is the
    // only place a reason ever goes.
    try testing.expect(network.diagnostic != null);
    try testing.expectEqual(
        std.meta.Tag(Diagnostic).net_host_not_resolved,
        std.meta.activeTag(network.diagnostic.?),
    );
}

test "the first refusal is the one kept, and it names the host it was about" {
    // The first and not the last, the rule every diagnostic in this project
    // follows. A later refusal is usually the same one again, and the first is
    // the one that explains the run.
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{});
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    _ = network.answer("first.evil.test", 443);
    _ = network.answer("second.evil.test", 443);
    try testing.expectEqual(@as(usize, 2), network.refused);

    const kept = network.diagnostic orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("first.evil.test", kept.net_host_not_permitted.host);
    try testing.expectEqual(@as(u16, 443), kept.net_host_not_permitted.port);
    // The decision the table really gave, so a person reads which rule turned
    // it away and not only that something did.
    try testing.expectEqual(table.Decision.ask, kept.net_host_not_permitted.decision);
}

test "the broker answers through the interface the sandbox calls, and not only directly" {
    // Every test above calls `answer` directly, which is the readable way to
    // drive it. This one goes through the vtable the driver actually uses, so
    // a `netBroker` that pointed at the wrong function, or at the wrong
    // instance, cannot pass unnoticed.
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    const broker = network.netBroker();
    try testing.expect(broker.connect("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(NetBroker.Grant.refused, broker.connect("api.evil.test", 443));
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a port is part of the key, so a rule about one port is not a rule about every port" {
    // The port is the last label of the action, so an exact rule names one
    // service and a class rule names them all. An author who writes the exact
    // form has to get the port they wrote and no other.
    const gpa = testing.allocator;
    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.connect.com.anthropic.api.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const answers = [_]FakeTransport.Answer{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    };

    var bench = try Bench.init(gpa, source, &answers);
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 80));
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 4433));
}

// ## A connection can now ask, through a real `Broker`
//
// Everything above this line builds no `Asker` and reaches no `Broker`; every
// test above still passes unchanged, which is the proof that a `Network`
// nobody wires an `Asker` into behaves exactly as it always has. The tests
// below build a real `chock_broker.Broker` over a real, in-memory
// `chock_proto.storage.Storage`, the same pieces `Broker.zig`'s own tests use,
// so the question this file now asks is answered by the same code a live
// session answers it with.

const ask_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .ask },
    \\        },
    \\    },
    \\}
;

const deny_anthropic: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "net.connect.com.anthropic.*", .decision = .deny },
    \\        },
    \\    },
    \\}
;

/// A `Broker.Waiter` that answers the one open request the first time it is
/// asked to wait, with a fixed decision, and counts how many times it was
/// asked to wait at all. **The count is the whole point of `test 4`**: a
/// second connection answered from memory never calls `wait` a second time,
/// because `Broker.request`'s own `ask` branch returns before it ever does.
const AnswerOnWait = struct {
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *Locked,
    decision: event.ApprovalDecision,
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    answered: bool = false,

    fn waiter(self: *AnswerOnWait) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *AnswerOnWait = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *AnswerOnWait = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (!self.answered) {
            self.answered = true;
            if (Broker.openRequest(self.gpa, io, self.store) catch null) |id| {
                // **The action is read back and echoed, not guessed.**
                // `SessionGrants.apply` only ever keys on the action a real
                // response names, so a response that left it out, the way
                // `answerAsUser` in `Broker.zig`'s own tests does for a plain
                // yes, would never be remembered here either.
                if (requestActionFor(self.gpa, io, self.store, id) catch null) |owned_action| {
                    defer self.gpa.free(owned_action);
                    _ = self.locked.append(self.gpa, io, .{ .approval_response = .{
                        .request_id = id,
                        .decision = self.decision,
                        .responder = "tester",
                        .action = owned_action,
                    } }, self.now_ms) catch {};
                }
            }
        }
        self.now_ms += @intCast(budget_ms);
        return .slept;
    }
};

/// The `action` of the `approval.request` envelope with this id, copied so
/// the caller can use it after the replay that found it ends. Null when
/// there is no such envelope.
fn requestActionFor(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    id: u64,
) !?[]u8 {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.id != id) continue;
        if (parsed.value.event != .approval_request) continue;
        return try gpa.dupe(u8, parsed.value.event.approval_request.action);
    }
    return null;
}

/// How many events of `kind` are in the whole log, from the start. Used to
/// pin that a memory served grant writes nothing at all: not a second
/// `approval.request`, and not a second `approval.response` either.
fn countKind(
    gpa: std.mem.Allocator,
    io: std.Io,
    storage: chock_proto.storage.Storage,
    kind: event.Kind,
) !usize {
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    var count: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (std.meta.activeTag(parsed.value.event) == kind) count += 1;
    }
    return count;
}

test "an allow decision still grants with nobody asked and no question written, even when the network could ask" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, allow_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK1");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expect(network.answer("api.anthropic.com", 443) == .granted);
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
}

test "ask with a broker that permits grants the connection" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK2");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    const grant = network.answer("api.anthropic.com", 443);
    switch (grant) {
        .granted => |fd| try testing.expect(fd >= 0),
        .refused => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), network.granted);
    try testing.expectEqual(@as(usize, 1), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), waiter.waits);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
}

test "ask with a broker that refuses does not connect, and the name is never resolved" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK3");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .refused_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    // Mutation check: move the broker call below the lookup and this fails
    // while the granted case above still passes.
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), bench.fake.dials);
    try testing.expectEqual(@as(usize, 1), network.refused);
}

test "a second connection to the same host and port is answered from the session's own memory, with no second question" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK4");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = .approved_by_user_for_session,
    };
    var grants: chock_proto.state.SessionGrants = .{};
    defer {
        var it = grants.granted.keyIterator();
        while (it.next()) |key| gpa.free(key.*);
        grants.granted.deinit(gpa);
    }
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter(), .grants = &grants };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    const first = network.answer("api.anthropic.com", 443);
    try testing.expect(first == .granted);
    try testing.expectEqual(@as(usize, 1), waiter.waits);

    const second = network.answer("api.anthropic.com", 443);
    try testing.expect(second == .granted);
    // No second question: the waiter was never asked to wait again, because
    // `Broker.request` answered out of memory before it ever called `wait`.
    try testing.expectEqual(@as(usize, 1), waiter.waits);
    try testing.expectEqual(@as(usize, 2), network.granted);
    try testing.expectEqual(@as(usize, 1), try countKind(gpa, io, store, .approval_request));
}

test "a deny decision never reaches the broker's question path at all" {
    const gpa = testing.allocator;
    const io = testing.io;
    var bench = try Bench.init(gpa, deny_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    var backing = try chock_proto.storage.Memory.init(gpa, "01NETASK5");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = AnswerOnWait{ .gpa = gpa, .store = store, .locked = &locked, .decision = .approved_by_user };
    const broker = Broker{ .policy = bench.policy, .waiter = waiter.waiter() };
    network.asker = .{ .broker = &broker, .storage = store, .locked = &locked };

    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), waiter.waits);
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 0), try countKind(gpa, io, store, .approval_request));
}

test "a network built with no asker refuses ask exactly as it always has, because the MCP startup path has no locked handle to give it" {
    const gpa = testing.allocator;
    var bench = try Bench.init(gpa, ask_anthropic, &.{
        .{ .host = "api.anthropic.com", .address = .{ .ip4 = .{ .bytes = .{ 93, 184, 216, 34 }, .port = 0 } } },
    });
    defer bench.deinit();
    const network = bench.ready(&.{"main"});

    // `network.asker` is null, the default `Bench.ready` leaves it at.
    try testing.expectEqual(NetBroker.Grant.refused, network.answer("api.anthropic.com", 443));
    try testing.expectEqual(@as(usize, 0), bench.fake.lookups);
    try testing.expectEqual(@as(usize, 1), network.refused);
}
