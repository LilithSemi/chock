//! The password helper. `git` and `ssh` ask a program for a password, and this
//! is the half of that program which runs beside the credentials.
//! `src/askpass.zig` is the other half.
//!
//! ## The helper prevents a mistake. It does not prevent an attack
//!
//! Say it plainly, the way `chock-broker/git_shim.zig` says it, because a file
//! about credentials is the easiest one to mistake for a control. **The
//! capability layers are the boundary, and the rule that the credential store
//! is never mounted is the boundary. This file is neither, and nothing in Chock
//! may be built as though it were.**
//!
//! An agent that wants to avoid this file has several ways and none of them is
//! difficult:
//!
//! - Set `core.askPass` in the repository's own `.git/config`, which wins over
//!   `GIT_ASKPASS` for that repository.
//! - Write its own program and point `SSH_ASKPASS` at it.
//! - Call the real `git` by its absolute path with an environment of its own.
//!
//! Every one of those still runs inside the sandbox, with no network, with no
//! credential store on any path it can reach, and with the seccomp filter and
//! the Landlock rules in front of it. **A helper it wrote itself answers its
//! own prompts with nothing**, because the value is not in the sandbox to
//! find: it is in this process, on the other side of a socket the sandbox has
//! no path to. That is what stops an attack. This file only stops the ordinary
//! case, which is a real `git` that needs a password and has nobody to ask.
//!
//! ## The whole protocol, which is why care is needed
//!
//! `git` runs the program named by `GIT_ASKPASS`, or by `core.askPass`, with
//! the prompt as one argument. `ssh` runs `SSH_ASKPASS` the same way. The
//! answer is whatever the program writes to standard output. There is no
//! status, no key, and no structure. A program that prints the wrong thing has
//! given a password away, and a program that prints nothing has refused.
//!
//! **One program and one argument, with no room for a subcommand.** Measured
//! against git 2.55: `GIT_ASKPASS="/path/to/chock askpass"` fails with
//! `cannot exec '/path/to/chock askpass'`. Git puts no shell in the way, and
//! neither does ssh, so the value has to be one executable path. So `link`
//! makes a symbolic link named `askpass` beside the socket, and `src/main.zig`
//! runs the askpass command when the name it was invoked as is that one. It is
//! the multi-call trick a coreutils install already uses, and this project
//! already depends on reading it correctly: see `tool_bin_dir` in
//! `lib/chock-core/tools.zig`.
//!
//! ## Four gates, and the prompt passes none of them by itself
//!
//! The prompt text comes from `git`, and `git` builds it out of a remote URL,
//! which comes out of the repository the agent is working in. **It is
//! untrusted input and it is read as such.** A prompt selects nothing. It is
//! read for one host name, and then:
//!
//! 1. `readPrompt` must recognise the prompt at all. Two shapes are known,
//!    which are the two `git` writes. Anything else is refused, which is the
//!    same safe default `git_shim.classify` keeps for a subcommand it does not
//!    know.
//! 2. The bytes between the quotes must parse as an `http` or `https` URL
//!    whose authority is a host name. See `hostOf` for the order the parts are
//!    cut in, which is the whole of the defence.
//! 3. The policy table must answer `allow` for that host, on an action name
//!    built the way `chock-broker/network.zig` builds one: the labels
//!    reversed, so `secret.password.com.github.*` cannot be reached by a host
//!    called `github.com.evil.example`.
//! 4. A `Grant` must name that exact host. No suffix match and no pattern: the
//!    policy language is where a class of hosts is spelled, and a second
//!    matcher here would be a second answer to the same question.
//!
//! **The policy is asked before the grants are read**, the same order
//! `Network.answer` keeps. A refusal that changed depending on whether Chock
//! holds a credential would tell the caller which hosts Chock holds one for.
//!
//! ## A grant has no name, so no handle can spell it
//!
//! A `Grant` is keyed by host and holds no name of its own. That is
//! deliberate and `Grant`'s own comptime block below fails the build if a name
//! appears.
//!
//! `chock-broker/secrets.zig` holds the other kind of credential, the one a
//! tool definition reaches with a `{{secret:name}}` handle, and `resolve`
//! replaces that handle in the environment of a sandboxed child. **A git
//! password must never be reachable that way.** If it were an entry of
//! `secrets.Store`, then a tool definition naming it would put it in the
//! environment of a program the model chose. There is no name here for such a
//! handle to hold, and `secrets.resolve` cannot read a `Grants` at all,
//! because it takes a `Store`.
//!
//! `Grants.redactor` is how the values still reach the redaction of section
//! 11.3 without ever becoming a name.
//!
//! ## Nobody to ask is a refusal
//!
//! A subagent, a session `chock daemon` started, and a piped `chock run` all
//! have nobody at a keyboard, and the process performing a `git.push` is
//! waiting on `git` while `git` waits on this helper. **So this file asks
//! nobody anything.** The only decision that gives a value is a policy table
//! that already said `allow` before `git` ever ran. Every other decision,
//! including `ask`, is a refusal here.
//!
//! That is the approval rule read in the safe direction, and it is the same
//! reading `socket.timeoutMs` gives: a question nobody can answer is answered
//! no.
//!
//! ## Where the value goes, and every place it does not
//!
//! It goes into one write on one connected socket, and out of `chock askpass`
//! on standard output, into the `git` that asked. That is all.
//!
//! - **Not into the session log.** `appendPrompt` is what this file writes,
//!   and it records that a prompt happened and what the prompt said. It takes
//!   no `Grants` and has no value in scope to record. `event.PromptPassword`
//!   says the same thing in its own comment, and the comptime block at the end
//!   of this file fails the build if that record grows a field that could hold
//!   an answer.
//! - **Not into an environment variable.** `env_socket` holds a path. A path
//!   is not a credential, which is the same reason `GIT_ASKPASS` may name this
//!   program.
//! - **Not onto a command line.** `ps` shows every argument to every other
//!   user of the machine, and a shell keeps them in a history file. The
//!   argument this helper is given is the prompt, which `git` wrote.
//! - **Not into a tool result.** A tool call runs inside the sandbox, which
//!   has no route to this socket at all.
//!
//! ## How a caller drives this
//!
//! `git` runs while the caller waits for it, so the caller polls between
//! looks:
//!
//! ```zig
//! var endpoint = try askpass.Endpoint.open(io, socket_path, &diag);
//! defer endpoint.close(io);
//! // spawn git with GIT_ASKPASS and env_socket set, then, until it exits:
//! _ = try endpoint.step(gpa, io, &locked, asker, 50);
//! ```
//!
//! A caller that never polls answers nothing, and `git` fails for want of a
//! password. That failure is the safe direction too.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
const secrets = @import("secrets.zig");
const socket = @import("socket.zig");

/// Why the broker could not answer a prompt, past what `Refusal` says. One
/// type for the whole module: see `chock-broker/diagnostic.zig`.
pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const table = chock_policy.table;

/// The variable that names this session's askpass socket. **It holds a path
/// and never a value**, which is the only reason a variable may be in this
/// design at all: see this file's own top comment.
pub const env_socket = "CHOCK_ASKPASS_SOCKET";

/// The socket's own name inside a session's `.ctl` directory, beside the
/// approval socket `s` and the handover socket `h`. One character, because a
/// unix socket path is bounded at `socket.max_socket_path` and the session
/// directory has already spent most of it.
pub const socket_name = "p";

/// The name of the link `GIT_ASKPASS` and `SSH_ASKPASS` are pointed at, beside
/// the socket in the same directory. **The name is the whole of what selects
/// the command**, so it is spelled here once and read by `src/main.zig`: see
/// this file's own top comment on why a subcommand cannot be in the variable.
pub const link_name = "askpass";

/// What making that link can fail with. Each name says which step failed, and
/// the caller already holds the only path involved, so there is nothing left
/// for a diagnostic to add.
pub const LinkError = error{
    /// `exe_path` is not absolute. A link to a bare name resolves against the
    /// directory the link sits in, which is a session's own control
    /// directory, so a relative one would point at nothing.
    NotAnAbsolutePath,
    /// The control directory could not be made, or made private.
    DirectoryUnavailable,
    /// A link or file was already there and would not go.
    LinkNotRemoved,
    LinkNotMade,
};

/// Make the link `git` and `ssh` run. `link_path` is the link itself, and its
/// parent is made `0o700` by `socket.ensureDir`, which is the same gate the
/// socket beside it sits behind.
///
/// **A link and not a copy.** A copy is a second binary that ages apart from
/// the one it was copied from, and a session that outlived an upgrade would
/// answer prompts with the old one.
pub fn link(io: std.Io, link_path: []const u8, exe_path: []const u8) LinkError!void {
    if (!std.fs.path.isAbsolute(exe_path)) return error.NotAnAbsolutePath;

    const parent = std.fs.path.dirname(link_path) orelse return error.DirectoryUnavailable;
    socket.ensureDir(io, parent, null) catch return error.DirectoryUnavailable;

    // A link a crash left behind points at whichever binary that session ran,
    // which may no longer exist. Removed rather than kept, for the reason
    // `Endpoint.open` removes a stale socket.
    std.Io.Dir.deleteFileAbsolute(io, link_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return error.LinkNotRemoved,
    };
    std.Io.Dir.symLinkAbsolute(io, exe_path, link_path, .{}) catch return error.LinkNotMade;
}

/// The longest prompt this reads. A prompt `git` writes is under a hundred
/// bytes. This is room for a long remote URL and far less than a repository
/// could use to make this process hold memory on its behalf.
pub const max_prompt_bytes: usize = 512;

/// The longest line this reads from one peer before it gives up on that peer.
/// A prompt frame is the prompt plus a little JSON.
pub const max_frame_bytes: usize = 4096;

/// What every action name in this file starts with. This is the action class
/// for answering a password prompt.
pub const action_prefix = "secret.password";

/// The longest host name a prompt can carry. The same bound
/// `chock-broker/network.zig` uses, and the same one DNS itself has.
pub const max_host_bytes = chock_sandbox.net_broker.max_host_bytes;

/// The longest action name `actionInto` can build: the prefix, then one
/// separator and one label for every byte of the host.
pub const max_action_bytes = action_prefix.len + 1 + max_host_bytes;

/// The `tool` part of the policy key for a prompt. **Not the name of a tool a
/// model may call**, because no model may call this: `git` calls it, and
/// `git` was started by the broker for an act a person already approved. The
/// key still needs three parts beside the action, so this is the honest name
/// for the one that asked.
pub const policy_tool = "askpass";

/// The two prompts `git` writes when it has no credential helper. Read as
/// prefixes, because the rest of each one is the remote URL in quotes.
///
/// **Written out rather than matched loosely.** `git` builds both through
/// `gettext`, so a translated `git` writes a prompt this file cannot read, and
/// then refuses. That is the safe direction, and a caller that wants the
/// helper to work sets `LC_ALL=C` for the `git` it starts.
const password_lead = "Password for ";
const username_lead = "Username for ";

/// What the prompt is asking for.
pub const Want = enum { username, password };

/// What one prompt came to. `host` borrows from the caller's own prompt text.
pub const Prompt = struct {
    want: Want,
    host: []const u8,
};

/// Read one prompt, or answer null for one this file does not recognise.
///
/// **Every rejection here is a refusal and never a guess.** See this file's
/// own top comment: a prompt is untrusted, and a reader that tried to find a
/// host in text it did not understand is a reader that can be steered.
pub fn readPrompt(text: []const u8) ?Prompt {
    if (text.len == 0 or text.len > max_prompt_bytes) return null;

    const want: Want, const lead: []const u8 =
        if (std.mem.startsWith(u8, text, password_lead))
            .{ .password, password_lead }
        else if (std.mem.startsWith(u8, text, username_lead))
            .{ .username, username_lead }
        else
            return null;

    const rest = text[lead.len..];
    if (rest.len == 0 or rest[0] != '\'') return null;
    // The **first** closing quote, so a second quoted run later in the text
    // cannot be the one that is read.
    const close = std.mem.indexOfScalarPos(u8, rest, 1, '\'') orelse return null;

    const host = hostOf(rest[1..close]) orelse return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;
    return .{ .want = want, .host = host };
}

/// The host of an `http` or `https` URL, or null when these bytes are not one.
///
/// **The order the parts are cut in is the whole defence.** The path is cut
/// off first and the user information second. Do it the other way round and
/// `https://evil.example/x@github.com` reads as the host `github.com`, because
/// the last `@` of the whole string is in the path. Cutting at the first `/`
/// leaves the authority `evil.example`, which is the host that URL really
/// names.
fn hostOf(url: []const u8) ?[]const u8 {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return null;
    const scheme = url[0..scheme_end];
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return null;

    const after = url[scheme_end + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, after, "/?#") orelse after.len;
    var authority = after[0..authority_end];

    // The user information ends at the last `@` of the authority, which is
    // what a password holding an `@` makes necessary.
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    // The port. A host name holds no colon, so anything from the last one on
    // is not part of the name. An IPv6 literal in brackets survives this and
    // is then refused by `hostBytesAreUsable`, which is the safe direction for
    // a spelling no rule in this project can name.
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| authority = authority[0..colon];

    if (authority.len == 0) return null;
    return authority;
}

/// The action name for answering a password prompt for `host`, written into
/// `buffer`. Null when the bytes are not a host name, or when they do not fit.
///
/// **The labels are reversed**, exactly as `chock-broker/network.zig` and
/// `chock-broker/fetch.zig` reverse them, and for the reason those files give
/// at length: without it a class rule about one domain would be reachable by
/// any host that ends with the right words in the wrong order. `buffer` must
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
        // key is.
        for (label, buffer[written..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        written += label.len;
        end = if (start == 0) 0 else start - 1;
    }
    return buffer[0..written];
}

/// One credential, for one host.
///
/// **There is no name field and there must never be one.** See this file's own
/// top comment: a name is what a `{{secret:name}}` handle spells, and a
/// credential an agent can spell is a credential an agent can put in the
/// environment of a program it chose.
pub const Grant = struct {
    /// The host `git` is asking about, as `readPrompt` reads it.
    host: []const u8,
    secret: []const u8,
};

/// The credentials this broker answers prompts out of.
pub const Grants = struct {
    entries: []const Grant = &.{},

    /// The credential for `host`, or null. **Exact, and folded for case
    /// alone**, because a host name is not case sensitive and nothing else
    /// about it is negotiable. There is no suffix match here on purpose: a
    /// class of hosts is spelled in the policy table, and a second matcher
    /// would be a second answer to the same question.
    pub fn find(self: Grants, host: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.host, host)) return entry.secret;
        }
        return null;
    }

    /// A redactor over these values, for the redaction scan.
    ///
    /// **This is how a grant reaches redaction without becoming a name.** A
    /// `secrets.Redactor` searches values and never reads a name, so the
    /// values can be given to it directly. Turning the grants into a
    /// `secrets.Store` to get the same result would give each one a name, and
    /// a name is exactly what must not exist here.
    pub fn redactor(
        self: Grants,
        gpa: std.mem.Allocator,
    ) std.mem.Allocator.Error!secrets.Redactor {
        const values = try gpa.alloc([]const u8, self.entries.len);
        defer gpa.free(values);
        for (self.entries, values) |entry, *slot| slot.* = entry.secret;
        return secrets.Redactor.initValues(gpa, values);
    }
};

/// Why one prompt got no value.
pub const Refusal = enum {
    /// The bytes are not a prompt this file recognises. See `readPrompt`.
    prompt_not_read,
    /// The prompt asks for a user name. See `Asker.answer`.
    prompt_wants_a_user_name,
    /// The policy table does not answer `allow` for this host. Every decision
    /// that is not `allow` reaches here, including `ask`: see this file's own
    /// top comment on why nobody can be asked.
    host_not_permitted,
    /// The policy permits it and no `Grant` names this host.
    no_credential_for_that_host,
    /// The client could not reach a session at all, or the session said
    /// nothing. This one is only ever reached in `src/askpass.zig`.
    nobody_answered,

    /// One line, for the person reading `git`'s standard error. **Each one
    /// names what to do instead**, which is the rule `git_shim.networkRefusal`
    /// keeps: a message that only says no leaves the reader with the question
    /// they started with.
    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .prompt_not_read => "chock askpass does not recognise this prompt, so it answered nothing. " ++
                "It reads the two prompts git writes in the C locale. Set LC_ALL=C for the git that asks.",
            .prompt_wants_a_user_name => "chock askpass answers a password and never a user name. " ++
                "Put the user in the remote URL, as in https://you@example.com/project.git.",
            .host_not_permitted => "chock askpass was not permitted to answer for that host. " ++
                "Add a secret.password rule for it to chock.zon. A host with no rule is refused, " ++
                "and so is a rule that asks, because nobody can be asked while git is waiting.",
            .no_credential_for_that_host => "chock holds no password for that host. " ++
                "The host must be the one the remote URL names, letter for letter.",
            .nobody_answered => "chock askpass reached no session, so nothing answered. " ++
                "A tool call inside the sandbox never can: the sandbox has no path to a session's socket.",
        };
    }

    /// The word this travels as on the wire.
    pub fn wireName(self: Refusal) []const u8 {
        return @tagName(self);
    }

    /// The `Refusal` that word names, or null.
    pub fn fromWireName(name: []const u8) ?Refusal {
        return std.meta.stringToEnum(Refusal, name);
    }
};

/// What one prompt came to.
pub const Answer = union(enum) {
    /// The value, borrowed from the `Grants` that answered.
    secret: []const u8,
    refused: Refusal,
};

/// The broker's own decision about one prompt: the policy table, the spawn
/// chain the act belongs to, and the credentials.
///
/// The three parts of the policy key that are not the action are here for the
/// same reason `chock-broker/network.zig` holds them: one question is asked of
/// the table, and the caller does not assemble a key.
pub const Asker = struct {
    grants: Grants = .{},
    table: *const table.Table,
    /// Every agent kind from the root of the spawn tree down to the agent this
    /// act belongs to, root first. See `Table.evaluateChain`.
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8 = policy_tool,

    /// Answer one prompt. Allocates nothing and asks nobody: see this file's
    /// own top comment.
    pub fn answer(self: Asker, prompt_text: []const u8) Answer {
        const prompt = readPrompt(prompt_text) orelse return .{ .refused = .prompt_not_read };
        if (prompt.want == .username) return .{ .refused = .prompt_wants_a_user_name };

        // **The policy first, and the credential second.** See this file's own
        // top comment: a refusal that depended on which credentials are held
        // would report which credentials are held.
        var buffer: [max_action_bytes]u8 = undefined;
        const action = actionInto(&buffer, prompt.host) orelse
            return .{ .refused = .prompt_not_read };

        const decision = self.table.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, null);
        if (decision != .allow) return .{ .refused = .host_not_permitted };

        const value = self.grants.find(prompt.host) orelse
            return .{ .refused = .no_credential_for_that_host };
        return .{ .secret = value };
    }
};

/// What the client sends: the one argument `git` gave it.
pub const Ask = struct {
    prompt: []const u8,
};

/// What the broker sends back. Exactly one field is set.
pub const Reply = struct {
    secret: ?[]const u8 = null,
    refused: ?[]const u8 = null,
};

/// The line a client sends, with its newline. Owned by the caller.
pub fn askLine(gpa: std.mem.Allocator, prompt: []const u8) std.mem.Allocator.Error![]u8 {
    const body = try std.json.Stringify.valueAlloc(gpa, Ask{ .prompt = prompt }, .{});
    defer gpa.free(body);
    return std.fmt.allocPrint(gpa, "{s}\n", .{body});
}

/// The line the broker sends back, with its newline. Owned by the caller.
///
/// **The caller wipes it.** A value in a heap buffer that is freed and not
/// overwritten stays in the allocator's memory until something else reuses
/// that memory. `Endpoint.step` wipes what this makes; a caller that builds a
/// line itself does the same.
pub fn replyLine(gpa: std.mem.Allocator, answer: Answer) std.mem.Allocator.Error![]u8 {
    const reply: Reply = switch (answer) {
        .secret => |value| .{ .secret = value },
        .refused => |refusal| .{ .refused = refusal.wireName() },
    };
    const body = try std.json.Stringify.valueAlloc(gpa, reply, .{});
    defer {
        wipe(body);
        gpa.free(body);
    }
    return std.fmt.allocPrint(gpa, "{s}\n", .{body});
}

/// Overwrite bytes that held a credential.
pub fn wipe(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

pub const AppendError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

/// Record that a prompt was asked, and what it said.
///
/// **There is no answer in scope here and there must never be one.** The
/// signature takes no `Grants` and no `Answer`, so this function could not
/// write a value into the log if it wanted to. `event.PromptPassword` says the
/// same in its own comment, and the comptime block at the end of this file
/// fails the build if that record grows a field an answer could sit in.
///
/// The prompt itself is bytes `git` composed out of a remote URL, so it is cut
/// to `max_prompt_bytes` before it is written: a log line is read back by
/// every client attached to the session.
///
/// `locked` is `anytype` for the same reason `Broker.request` takes it that
/// way: `chock_proto.storage.Locked` is not `pub`.
pub fn appendPrompt(
    gpa: std.mem.Allocator,
    io: std.Io,
    locked: anytype,
    correlation_id: []const u8,
    prompt: []const u8,
    time_ms: i64,
) AppendError!u64 {
    const kept = prompt[0..@min(prompt.len, max_prompt_bytes)];
    return locked.append(gpa, io, .{ .prompt_password = .{
        .correlation_id = correlation_id,
        .prompt = kept,
    } }, time_ms);
}

/// `chock_proto.storage.Locked` is not `pub`, so no file outside that one can
/// name it. This reaches the same type through the return type of
/// `Storage.lock`, which is public. The same route `chock-broker/socket.zig`
/// takes, for the same reason.
const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

/// The listening end of one session's askpass socket.
///
/// **One peer at a time, and the peer is closed when it has been answered.**
/// An askpass exchange is one prompt and one answer, and `git` starts a fresh
/// helper for every prompt, so there is nothing for a peer to do after it has
/// been answered. The approval socket keeps four peers because a person may
/// attach a phone and a terminal at once; nobody attaches to this one.
///
/// This holds no credential. `step` takes the `Asker` as an argument, so a
/// value is in scope for the length of one call and never for the length of a
/// session. The comptime block at the end of this file says so to the
/// compiler.
pub const Endpoint = struct {
    server: std.Io.net.Server,
    /// Borrowed from the caller, for `close` to remove.
    socket_path: []const u8,
    /// The uid this process runs as. Any other peer is closed at once.
    owner_uid: std.posix.uid_t,
    /// How many prompts were answered with a value.
    answered: usize = 0,
    /// How many prompts were refused. Counted apart from `answered`, so a
    /// caller can say a prompt arrived and got nothing, which is not the same
    /// fact as no prompt arriving.
    refused: usize = 0,
    /// How many peers were closed because they were somebody else.
    strangers: usize = 0,
    /// Why the first stranger was refused, for the caller to report.
    diagnostic: ?Diagnostic = null,

    pub const OpenError = socket.Endpoint.OpenError;
    pub const StepError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

    /// Make the control directory, remove any socket a crash left there, and
    /// listen. `path` is the socket itself, and its parent directory is made
    /// `0o700` by `socket.ensureDir`, which is the gate.
    pub fn open(io: std.Io, path: []const u8, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try socket.addressFor(path, diag);

        const parent = std.fs.path.dirname(path) orelse return error.SocketUnavailable;
        try socket.ensureDir(io, parent, diag);

        // A file left by a process that is gone would wedge that session id
        // forever, and the directory it sits in is one this user alone can
        // enter, so nothing else could have put it there.
        std.Io.Dir.deleteFileAbsolute(io, path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                _ = diagnostic.note(diag, .{ .socket_not_removed = .{ .path = path, .err = err } });
                return error.SocketUnavailable;
            },
        };

        const server = address.listen(io, .{ .kernel_backlog = 2 }) catch |err| {
            _ = diagnostic.note(diag, .{ .socket_not_opened = .{ .path = path, .err = err } });
            return error.SocketUnavailable;
        };

        return .{
            .server = server,
            .socket_path = path,
            .owner_uid = std.posix.system.getuid(),
        };
    }

    /// Stop listening, and remove the socket file.
    pub fn close(self: *Endpoint, io: std.Io) void {
        self.server.deinit(io);
        // A session whose directory has already gone is not a fault worth
        // reporting: the file is scratch, and the next `open` removes a stale
        // one anyway.
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

    /// One look. Takes at most one waiting client, reads its prompt for at
    /// most the budget, answers it, and closes it. True when a prompt was
    /// answered or refused.
    ///
    /// `locked` is where the `prompt.password` record goes, or null for a
    /// caller that holds no log.
    ///
    /// **A peer that connects and says nothing costs one budget and is then
    /// dropped.** It is not kept across looks: a client that has nothing to
    /// say is not answering a prompt, and holding the slot for it would keep
    /// the next `git` out.
    pub fn step(
        self: *Endpoint,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: ?*Locked,
        asker: Asker,
        budget_ms: u64,
    ) StepError!bool {
        const timeout = boundedTimeout(budget_ms);
        if (!socket.readable(self.server.socket.handle, timeout)) return false;

        const stream = self.server.accept(io) catch return false;
        var still_open = true;
        defer if (still_open) stream.close(io);

        const uid = socket.peerUid(stream.socket.handle) orelse {
            // The kernel would not say who this is, so it cannot be given a
            // credential.
            self.strangers += 1;
            return false;
        };
        if (uid != self.owner_uid) {
            self.strangers += 1;
            _ = diagnostic.note(&self.diagnostic, .{ .client_uid_refused = .{
                .uid = uid,
                .owner_uid = self.owner_uid,
            } });
            return false;
        }

        var buffer: [max_frame_bytes]u8 = undefined;
        const line = readLine(stream.socket.handle, &buffer, timeout) orelse return false;

        const answer = self.decide(gpa, io, locked, asker, line) catch |err| {
            // A log that cannot be written is a fault this call cannot
            // recover from, and it must not be a fault that hands out a
            // credential anyway.
            stream.close(io);
            still_open = false;
            return err;
        };

        switch (answer) {
            .secret => self.answered += 1,
            .refused => self.refused += 1,
        }

        const reply = try replyLine(gpa, answer);
        defer {
            wipe(reply);
            gpa.free(reply);
        }
        _ = socket.writeAll(stream.socket.handle, reply);
        return true;
    }

    /// Parse one frame, record the prompt, and decide. Its own function so
    /// `step` has one place a credential can enter it.
    fn decide(
        self: *Endpoint,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: ?*Locked,
        asker: Asker,
        line: []const u8,
    ) StepError!Answer {
        var parsed = std.json.parseFromSlice(Ask, gpa, line, .{
            .ignore_unknown_fields = true,
        }) catch return .{ .refused = .prompt_not_read };
        defer parsed.deinit();

        if (locked) |handle| {
            var id_buffer: [32]u8 = undefined;
            const correlation = std.fmt.bufPrint(
                &id_buffer,
                "askpass-{d}",
                .{self.answered + self.refused + 1},
            ) catch "askpass";
            _ = try appendPrompt(
                gpa,
                io,
                handle,
                correlation,
                parsed.value.prompt,
                std.Io.Timestamp.now(io, .real).toMilliseconds(),
            );
        }

        return asker.answer(parsed.value.prompt);
    }
};

/// Read one line from `handle`, up to the size of `buffer`. Null when nothing
/// whole arrived within the timeout, or when the peer went away.
///
/// **Bounded on both axes**, because the peer is a program `git` started and
/// this process is holding a session while it waits: a full buffer with no
/// line break in it is not a prompt, and a peer that keeps the socket open
/// without writing gets one timeout and no more.
fn readLine(handle: std.posix.fd_t, buffer: []u8, timeout_ms: i32) ?[]const u8 {
    var filled: usize = 0;
    while (filled < buffer.len) {
        if (!socket.readable(handle, timeout_ms)) return null;
        const read = std.posix.read(handle, buffer[filled..]) catch return null;
        if (read == 0) return null;
        filled += read;
        if (std.mem.indexOfScalar(u8, buffer[0..filled], '\n')) |end| return buffer[0..end];
    }
    return null;
}

/// A millisecond budget as the `i32` `poll` takes, with no wrap.
fn boundedTimeout(budget_ms: u64) i32 {
    if (budget_ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(budget_ms);
}

// A grant is keyed by a host and has no name, because a name is what a
// `{{secret:name}}` handle spells. See this file's own top comment. This
// fails the build if one appears.
comptime {
    for (@typeInfo(Grant).@"struct".fields) |field| {
        if (std.mem.indexOf(u8, field.name, "name") != null) {
            @compileError("a git credential must have no name for a handle to spell: " ++ field.name);
        }
    }
}

// The record of a prompt holds the prompt and never the answer. This fails the
// build if `event.PromptPassword` grows a field an answer could sit in, which
// is the shape the mistake would take.
comptime {
    const forbidden = [_][]const u8{ "secret", "password", "answer", "value", "credential", "token" };
    for (@typeInfo(event.PromptPassword).@"struct".fields) |field| {
        for (forbidden) |bad| {
            if (std.mem.indexOf(u8, field.name, bad) != null) {
                @compileError("the record of a prompt must not hold the answer: " ++ field.name);
            }
        }
    }
}

// The endpoint holds no credential: `step` takes the `Asker` as an argument,
// so a value is in scope for one call and never for a session. An endpoint
// that held one would be a long lived object with a password in it, which is
// the thing this whole design is arranged to avoid.
comptime {
    for (@typeInfo(Endpoint).@"struct".fields) |field| {
        if (field.type == Grants or field.type == Grant or field.type == Asker) {
            @compileError("the askpass endpoint must hold no credential: " ++ field.name);
        }
    }
}

const testing = std.testing;

const the_password = "ghp_9f2c4a7b1d3e5a6b7c8d";

/// A table that permits one host and nothing else.
const one_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.com.example.git", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// A table that asks about every host, which is the policy table's own safe
/// default written out.
const ask_every_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.*", .decision = .ask },
    \\        },
    \\    },
    \\}
;

fn testGrants() Grants {
    return .{ .entries = &.{
        .{ .host = "git.example.com", .secret = the_password },
    } };
}

fn askerOver(policy: *const table.Table) Asker {
    return .{
        .grants = testGrants(),
        .table = policy,
        .chain = &.{"coder"},
        .agent_kind = "coder",
        .model = "main",
    };
}

test "the two prompts git writes are read, and the host is the one the URL names" {
    // The ordinary case first, measured against a real git: `git credential
    // fill` writes exactly these strings in the C locale.
    const password = readPrompt("Password for 'https://ross@git.example.com': ").?;
    try testing.expectEqual(Want.password, password.want);
    try testing.expectEqualStrings("git.example.com", password.host);

    const username = readPrompt("Username for 'https://git.example.com': ").?;
    try testing.expectEqual(Want.username, username.want);
    try testing.expectEqualStrings("git.example.com", username.host);

    // A port and a path are both cut off, and neither changes the host.
    try testing.expectEqualStrings(
        "git.example.com",
        readPrompt("Password for 'https://ross@git.example.com:8443/team/project.git': ").?.host,
    );
    // A host name is not case sensitive.
    try testing.expectEqualStrings(
        "Git.Example.COM",
        readPrompt("Password for 'https://Git.Example.COM': ").?.host,
    );
}

test "a crafted prompt cannot name one host and be read as another" {
    // The attack this parser is written against. Every one of these is a
    // string an agent can put in a remote URL, which is a file in its own
    // workspace, so every one of them reaches this function.
    //
    // Mutation check: swap the two cuts in `hostOf`, so the user information
    // is stripped before the path, and the first case below reads
    // `git.example.com` and this test fails.
    const crafted = [_]struct { prompt: []const u8, host: ?[]const u8 }{
        // The `@` is in the path, so the authority is the evil host.
        .{
            .prompt = "Password for 'https://evil.test/x@git.example.com': ",
            .host = "evil.test",
        },
        // A real user information field, and the host is still what follows
        // the last `@`.
        .{
            .prompt = "Password for 'https://git.example.com@evil.test/': ",
            .host = "evil.test",
        },
        // A query and a fragment end the authority too.
        .{ .prompt = "Password for 'https://evil.test?x=@git.example.com': ", .host = "evil.test" },
        .{ .prompt = "Password for 'https://evil.test#@git.example.com': ", .host = "evil.test" },
        // A second quoted run later in the text is not the one that is read.
        .{
            .prompt = "Password for 'https://evil.test' or 'https://git.example.com': ",
            .host = "evil.test",
        },
        // Bytes that are not a host name at all.
        .{ .prompt = "Password for 'https://git.example.com*': ", .host = null },
        .{ .prompt = "Password for 'https://[::1]': ", .host = null },
        .{ .prompt = "Password for 'https://': ", .host = null },
        .{ .prompt = "Password for 'https://.example.com': ", .host = null },
        // A scheme this file does not read.
        .{ .prompt = "Password for 'file:///etc/shadow': ", .host = null },
        .{ .prompt = "Password for 'ssh://git.example.com': ", .host = null },
        // Not a prompt at all.
        .{ .prompt = "Enter passphrase for key '/home/ross/.ssh/id_ed25519': ", .host = null },
        .{ .prompt = "", .host = null },
        .{ .prompt = "Password for git.example.com: ", .host = null },
        .{ .prompt = "Password for 'https://git.example.com", .host = null },
        // A prefix that only looks like the right one.
        .{ .prompt = "  Password for 'https://git.example.com': ", .host = null },
    };

    for (crafted) |case| {
        const read = readPrompt(case.prompt);
        if (case.host) |want| {
            try testing.expectEqualStrings(want, read.?.host);
        } else {
            try testing.expectEqual(@as(?Prompt, null), read);
        }
    }

    // And a prompt longer than the bound is refused whatever it holds.
    var long: [max_prompt_bytes + 1]u8 = @splat('x');
    try testing.expectEqual(@as(?Prompt, null), readPrompt(&long));
}

test "the action name reverses the labels, so a class rule cannot be reached by the wrong host" {
    // The same reversal `chock-broker/network.zig` argues for, and the reason
    // is the same: `secret.password.com.example.*` must cover every host under
    // `example.com` and must cover nothing else.
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "secret.password.com.example.git",
        actionInto(&buffer, "git.example.com").?,
    );
    // Lowercased, because a policy key is case sensitive and a host name is
    // not.
    try testing.expectEqualStrings(
        "secret.password.com.example.git",
        actionInto(&buffer, "Git.Example.COM").?,
    );

    // The one that matters. A host built to look like the permitted one does
    // not land under the permitted prefix.
    const evil = actionInto(&buffer, "git.example.com.evil.test").?;
    try testing.expect(!std.mem.startsWith(u8, evil, "secret.password.com.example."));
    try testing.expectEqualStrings("secret.password.test.evil.com.example.git", evil);

    // Bytes that are not a host name build no action at all.
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, ""));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, "git.example.com/x"));

    // And the class rule really does cover the permitted host and not the
    // crafted one, read through the policy language itself rather than by
    // eye.
    try testing.expect(table.patternMatches(
        "secret.password.com.example.*",
        actionInto(&buffer, "git.example.com").?,
    ));
    try testing.expect(!table.patternMatches(
        "secret.password.com.example.*",
        actionInto(&buffer, "git.example.com.evil.test").?,
    ));
}

test "a host the policy permits gets the credential, and every other answer is a refusal" {
    // The four gates, one at a time, over a real policy table.
    //
    // Mutation check: change `if (decision != .allow)` in `Asker.answer` to
    // `if (decision == .deny)` and the `ask` case below stops being a
    // refusal, so this test fails.
    const gpa = testing.allocator;

    const permitting = try table.Table.parse(gpa, one_host, null);
    defer table.Table.destroy(gpa, permitting);
    const asker = askerOver(permitting);

    const answer = asker.answer("Password for 'https://ross@git.example.com': ");
    try testing.expect(answer == .secret);
    try testing.expectEqualStrings(the_password, answer.secret);

    // Gate 1: a prompt this file does not read.
    try testing.expectEqual(
        Answer{ .refused = .prompt_not_read },
        asker.answer("Enter passphrase for key '/home/ross/.ssh/id_ed25519': "),
    );
    // Gate 2: a user name is never answered, whatever the policy says.
    try testing.expectEqual(
        Answer{ .refused = .prompt_wants_a_user_name },
        asker.answer("Username for 'https://git.example.com': "),
    );
    // Gate 3: a host with no rule. The table's own safe default is `ask`, and
    // `ask` is a refusal here.
    try testing.expectEqual(
        Answer{ .refused = .host_not_permitted },
        asker.answer("Password for 'https://ross@evil.test': "),
    );
    // Gate 4: the policy permits it and no grant names it.
    const no_grants = Asker{
        .table = permitting,
        .chain = &.{"coder"},
        .agent_kind = "coder",
        .model = "main",
    };
    try testing.expectEqual(
        Answer{ .refused = .no_credential_for_that_host },
        no_grants.answer("Password for 'https://ross@git.example.com': "),
    );

    // A table that asks about everything answers nothing, because nobody can
    // be asked while git waits. This is the case the approval rule decides,
    // and it decides it as a refusal.
    const asking = try table.Table.parse(gpa, ask_every_host, null);
    defer table.Table.destroy(gpa, asking);
    try testing.expectEqual(
        Answer{ .refused = .host_not_permitted },
        askerOver(asking).answer("Password for 'https://ross@git.example.com': "),
    );

    // And an empty table, which is a project that said nothing at all.
    const empty = try table.Table.parse(gpa, ".{ .policy = .{ .rules = .{} } }", null);
    defer table.Table.destroy(gpa, empty);
    try testing.expectEqual(
        Answer{ .refused = .host_not_permitted },
        askerOver(empty).answer("Password for 'https://ross@git.example.com': "),
    );
}

test "a grant is found by an exact host and never by a suffix" {
    // A suffix match here would be a second policy language, and it would be
    // the one with no reversal, so `git.example.com.evil.test` would end with
    // the permitted name.
    const grants = testGrants();
    try testing.expectEqualStrings(the_password, grants.find("git.example.com").?);
    try testing.expectEqualStrings(the_password, grants.find("GIT.EXAMPLE.COM").?);
    try testing.expectEqual(@as(?[]const u8, null), grants.find("evil.git.example.com"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find("git.example.com.evil.test"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find("example.com"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find(""));
}

test "a grant reaches redaction without ever becoming a name" {
    // Redaction scans a tool result for known values. A grant has to be in
    // that scan, and it must not gain a name to get there: see this file's own
    // top comment on `{{secret:name}}`.
    //
    // Mutation check: return `secrets.Redactor.initValues(gpa, &.{})` from
    // `Grants.redactor` and the first expectation below fails.
    const gpa = testing.allocator;

    var redactor = try testGrants().redactor(gpa);
    defer redactor.deinit(gpa);

    try redactor.push(gpa, "remote: rejected, token " ++ the_password ++ " is expired\n");
    const clean = try redactor.finish(gpa);
    defer gpa.free(clean);

    try testing.expectEqualStrings(
        "remote: rejected, token " ++ secrets.redacted_marker ++ " is expired\n",
        clean,
    );

    // And the handle route finds nothing, because there is no name to spell.
    // A `Store` built from the same session holds provider credentials alone.
    const store = secrets.Store{ .entries = &.{.{ .name = "aiand", .value = "sk-live-1" }} };
    try testing.expectEqual(@as(?[]const u8, null), store.get("git.example.com"));
    try testing.expectError(
        error.UnknownSecret,
        secrets.resolve(store, gpa, "TOKEN={{secret:git.example.com}}", null),
    );
}

test "one frame carries a prompt with a line break in it, and one carries a value" {
    // Why the framing is JSON and not the plain words the handover socket
    // uses: a prompt is bytes git composed and a value is bytes a person
    // chose, and either may hold a line break that would end the frame early.
    const gpa = testing.allocator;

    const awkward = "Password for 'https://ross@git.example.com':\n and more ";
    const ask = try askLine(gpa, awkward);
    defer gpa.free(ask);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, ask, "\n"));
    try testing.expect(std.mem.endsWith(u8, ask, "\n"));

    var parsed = try std.json.parseFromSlice(Ask, gpa, ask[0 .. ask.len - 1], .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(awkward, parsed.value.prompt);

    const reply = try replyLine(gpa, .{ .secret = "a\nb" });
    defer gpa.free(reply);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, reply, "\n"));
    var back = try std.json.parseFromSlice(Reply, gpa, reply[0 .. reply.len - 1], .{});
    defer back.deinit();
    try testing.expectEqualStrings("a\nb", back.value.secret.?);
    try testing.expectEqual(@as(?[]const u8, null), back.value.refused);

    // A refusal travels as a word, and the word round trips.
    const no = try replyLine(gpa, .{ .refused = .host_not_permitted });
    defer gpa.free(no);
    var refused = try std.json.parseFromSlice(Reply, gpa, no[0 .. no.len - 1], .{});
    defer refused.deinit();
    try testing.expectEqual(@as(?[]const u8, null), refused.value.secret);
    try testing.expectEqual(Refusal.host_not_permitted, Refusal.fromWireName(refused.value.refused.?).?);
    try testing.expectEqual(@as(?Refusal, null), Refusal.fromWireName("no_such_refusal"));
}

test "the log records that a prompt was asked and never what was answered" {
    // A credential never enters the log, and this is the fault that rule
    // exists for: `chockd` serves the session log to every attached client, so
    // a value that reaches it has already been given away.
    //
    // Mutation check: add `.prompt = the_password` to the append in
    // `appendPrompt` and the second expectation below fails on the log's own
    // bytes.
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01ASKPASS");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const prompt = "Password for 'https://ross@git.example.com': ";
    _ = try appendPrompt(gpa, io, &locked, "askpass-1", prompt, 1_700_000_000_000);

    // The fact is in the log, so a person can see that Chock was asked.
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "git.example.com") != null);
    // The answer is not, in any line and in any field.
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, the_password) == null);

    // A prompt longer than the bound is cut rather than written whole.
    var long: [max_prompt_bytes * 2]u8 = @splat('y');
    _ = try appendPrompt(gpa, io, &locked, "askpass-2", &long, 1_700_000_000_001);

    var replay = try store.replay(gpa, io, 0);
    defer replay.deinit();
    var seen: usize = 0;
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        if (parsed.value.event != .prompt_password) continue;
        seen += 1;
        try testing.expect(parsed.value.event.prompt_password.prompt.len <= max_prompt_bytes);
    }
    try testing.expectEqual(@as(usize, 2), seen);
}

test "a prompt over a real socket is answered, and one for another host is not" {
    // The transport, over a real unix socket in a temporary directory, with a
    // real policy table and a real log. No git here: `test/broker/askpass.zig`
    // is what proves a real git can drive it.
    //
    // Mutation check: drop the `if (decision != .allow)` line from
    // `Asker.answer` and the second half of this test hands out the
    // credential for `evil.test`.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try chock_proto.log.absoluteDirPath(io, &path_buffer, tmp.dir);
    const path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, socket_name });
    defer gpa.free(path);

    var endpoint = try Endpoint.open(io, path, null);
    defer endpoint.close(io);

    var backing = try chock_proto.storage.Memory.init(gpa, "01ASKPASS");
    const store = backing.storage();
    defer store.close(io);
    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const permitting = try table.Table.parse(gpa, one_host, null);
    defer table.Table.destroy(gpa, permitting);
    const asker = askerOver(permitting);

    const address = try socket.addressFor(path, null);

    // The permitted host.
    {
        const client = try address.connect(io);
        defer client.close(io);

        const line = try askLine(gpa, "Password for 'https://ross@git.example.com': ");
        defer gpa.free(line);
        try testing.expect(socket.writeAll(client.socket.handle, line));

        try testing.expect(try endpoint.step(gpa, io, &locked, asker, 1000));
        try testing.expectEqual(@as(usize, 1), endpoint.answered);

        var buffer: [max_frame_bytes]u8 = undefined;
        const said = readLine(client.socket.handle, &buffer, 1000).?;
        var parsed = try std.json.parseFromSlice(Reply, gpa, said, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings(the_password, parsed.value.secret.?);
    }

    // A host nobody permitted.
    {
        const client = try address.connect(io);
        defer client.close(io);

        const line = try askLine(gpa, "Password for 'https://ross@evil.test': ");
        defer gpa.free(line);
        try testing.expect(socket.writeAll(client.socket.handle, line));

        try testing.expect(try endpoint.step(gpa, io, &locked, asker, 1000));
        try testing.expectEqual(@as(usize, 1), endpoint.answered);
        try testing.expectEqual(@as(usize, 1), endpoint.refused);

        var buffer: [max_frame_bytes]u8 = undefined;
        const said = readLine(client.socket.handle, &buffer, 1000).?;
        try testing.expect(std.mem.indexOf(u8, said, the_password) == null);
        var parsed = try std.json.parseFromSlice(Reply, gpa, said, .{});
        defer parsed.deinit();
        try testing.expectEqual(@as(?[]const u8, null), parsed.value.secret);
        try testing.expectEqualStrings("host_not_permitted", parsed.value.refused.?);
    }

    // Both prompts are in the log, and the value is in none of it.
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, backing.bytes.items, "prompt.password"));
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, the_password) == null);

    // A look with nobody connected answers nothing and does not spin.
    try testing.expect(!try endpoint.step(gpa, io, &locked, asker, 0));

    // A peer that connects and says nothing is dropped after one budget,
    // rather than keeping the next git out.
    {
        const silent = try address.connect(io);
        defer silent.close(io);
        try testing.expect(!try endpoint.step(gpa, io, &locked, asker, 1));
    }
    try testing.expectEqual(@as(usize, 1), endpoint.answered);
    try testing.expectEqual(@as(usize, 1), endpoint.refused);
}

test "every refusal names what to do instead, and none of them is a bare no" {
    // The rule `git_shim.networkRefusal` keeps, measured: a model, and a
    // person, told plainly what is wrong and what works instead act on it,
    // and a message that only says no leaves them with the question they
    // started with.
    for (std.enums.values(Refusal)) |refusal| {
        const text = refusal.text();
        try testing.expect(text.len > 40);
        try testing.expect(std.mem.indexOf(u8, text, "chock") != null);
        // A sentence about what does work, which every one of them has.
        try testing.expect(std.mem.indexOf(u8, text, ".") != null);
        // And the word travels, so a client can name the same refusal back.
        try testing.expectEqual(refusal, Refusal.fromWireName(refusal.wireName()).?);
    }

    // The two a reader is most likely to hit name the fix by name.
    try testing.expect(std.mem.indexOf(u8, Refusal.host_not_permitted.text(), "secret.password") != null);
    try testing.expect(std.mem.indexOf(u8, Refusal.prompt_wants_a_user_name.text(), "https://you@") != null);
    try testing.expect(std.mem.indexOf(u8, Refusal.prompt_not_read.text(), "LC_ALL=C") != null);
}

test "the askpass socket binds at exactly the bound and refuses one byte more" {
    // **This socket is one a live session needs, and it was the last one still
    // binding through `std.Io.net.UnixAddress.init` alone.** `init` takes
    // anything up to `UnixAddress.max_len`, which is past the end of Darwin's
    // `sun_path`, so a session under a deep state directory ended the whole
    // process here rather than running with no askpass socket.
    //
    // Mutation check: make `socket.max_socket_path` read
    // `std.Io.net.UnixAddress.max_len` again. On Darwin the first half ends the
    // test binary inside `listen`. On Linux both halves still pass, because
    // `std` binds an unterminated path that fills the field, which is why that
    // number is pinned in `chock-proto` instead.
    const gpa = testing.allocator;
    const io = testing.io;

    var bench = try socket.BoundBench.open(gpa, io);
    defer bench.cleanup(io);

    var at_bound = try bench.pathsOfLength(socket.max_socket_path);
    defer at_bound.deinit();
    var endpoint = try Endpoint.open(io, at_bound.socket, null);
    endpoint.close(io);

    var over = try bench.pathsOfLength(socket.max_socket_path + 1);
    defer over.deinit();
    var diag: ?Diagnostic = null;
    try testing.expectError(error.PathTooLong, Endpoint.open(io, over.socket, &diag));

    // **The refusal names the path and the bound.** `Endpoint.open` used to give
    // back a bare `error.PathTooLong` with nothing in the diagnostic at all, so
    // a person whose state directory is deep read an error name and no number.
    var said_buffer: [512]u8 = undefined;
    const said = try std.fmt.bufPrint(&said_buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, said, over.socket) != null);
    var number: [8]u8 = undefined;
    try testing.expect(std.mem.indexOf(
        u8,
        said,
        try std.fmt.bufPrint(&number, "{d}", .{socket.max_socket_path}),
    ) != null);
}
