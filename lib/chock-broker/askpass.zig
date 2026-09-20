//! The password helper. `git` and `ssh` run a program to get a password, and
//! this is the half that runs beside the credentials. It prevents a mistake and
//! it does not prevent an attack: the capability layers are the boundary.

const std = @import("std");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_sandbox = @import("chock-sandbox");

const diagnostic = @import("diagnostic.zig");
const secrets = @import("secrets.zig");
const socket = @import("socket.zig");

pub const Diagnostic = diagnostic.Diagnostic;

const event = chock_proto.event;
const table = chock_policy.table;

pub const env_socket = "CHOCK_ASKPASS_SOCKET";

pub const socket_name = "p";

/// `GIT_ASKPASS` must be one executable path. Against git 2.55,
/// `GIT_ASKPASS="/path/to/chock askpass"` fails with `cannot exec`: neither git
/// nor ssh puts a shell in the way. So this name selects the command.
pub const link_name = "askpass";

pub const LinkError = error{
    NotAnAbsolutePath,
    DirectoryUnavailable,
    LinkNotRemoved,
    LinkNotMade,
};

pub fn link(io: std.Io, link_path: []const u8, exe_path: []const u8) LinkError!void {
    if (!std.fs.path.isAbsolute(exe_path)) return error.NotAnAbsolutePath;

    const parent = std.fs.path.dirname(link_path) orelse return error.DirectoryUnavailable;
    socket.ensureDir(io, parent, null) catch return error.DirectoryUnavailable;

    std.Io.Dir.deleteFileAbsolute(io, link_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return error.LinkNotRemoved,
    };
    std.Io.Dir.symLinkAbsolute(io, exe_path, link_path, .{}) catch return error.LinkNotMade;
}

pub const max_prompt_bytes: usize = 512;

pub const max_frame_bytes: usize = 4096;

pub const action_prefix = "secret.password";

pub const max_host_bytes = chock_sandbox.net_broker.max_host_bytes;

pub const max_action_bytes = action_prefix.len + 1 + max_host_bytes;

pub const policy_tool = "askpass";

/// The two prompts `git` writes when it has no credential helper, read as
/// prefixes because the rest of each one is the remote URL in quotes. `git`
/// builds both through `gettext`, so a translated `git` writes a prompt this
/// file refuses, and a caller sets `LC_ALL=C` for the `git` it starts.
const password_lead = "Password for ";
const username_lead = "Username for ";

pub const Want = enum { username, password };

pub const Prompt = struct {
    want: Want,
    host: []const u8,
};

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
    // The first closing quote, so a second quoted run cannot be the one read.
    const close = std.mem.indexOfScalarPos(u8, rest, 1, '\'') orelse return null;

    const host = hostOf(rest[1..close]) orelse return null;
    if (!chock_sandbox.net_broker.hostBytesAreUsable(host)) return null;
    return .{ .want = want, .host = host };
}

/// Cut the path off first and the user information second. The other way
/// round, `https://evil.example/x@github.com` reads as the host `github.com`.
fn hostOf(url: []const u8) ?[]const u8 {
    const scheme_end = std.mem.indexOf(u8, url, "://") orelse return null;
    const scheme = url[0..scheme_end];
    if (!std.mem.eql(u8, scheme, "http") and !std.mem.eql(u8, scheme, "https")) return null;

    const after = url[scheme_end + 3 ..];
    const authority_end = std.mem.indexOfAny(u8, after, "/?#") orelse after.len;
    var authority = after[0..authority_end];

    // The user information ends at the last `@`, because a password holds one.
    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |colon| authority = authority[0..colon];

    if (authority.len == 0) return null;
    return authority;
}

/// The labels are reversed. Without that, a class rule about one domain is
/// reachable by any host that ends with the right words in the wrong order.
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

/// There is no name field and there must never be one. A name is what a
/// `{{secret:name}}` handle spells, and an agent can put one in a child's env.
pub const Grant = struct {
    host: []const u8,
    secret: []const u8,
};

pub const Grants = struct {
    entries: []const Grant = &.{},

    /// Exact, and folded for case alone. There is no suffix match here.
    pub fn find(self: Grants, host: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.host, host)) return entry.secret;
        }
        return null;
    }

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

pub const Refusal = enum {
    prompt_not_read,
    prompt_wants_a_user_name,
    host_not_permitted,
    reviewer_cannot_answer,
    no_credential_for_that_host,
    nobody_answered,

    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .prompt_not_read => "chock askpass does not recognise this prompt, so it answered nothing. " ++
                "It reads the two prompts git writes in the C locale. Set LC_ALL=C for the git that asks.",
            .prompt_wants_a_user_name => "chock askpass answers a password and never a user name. " ++
                "Put the user in the remote URL, as in https://you@example.com/project.git.",
            .host_not_permitted => "chock askpass was not permitted to answer for that host. " ++
                "A secret.password rule in chock.zon denies it. A host with no rule at all is " ++
                "prompted for, so this is a rule somebody wrote on purpose.",
            .reviewer_cannot_answer => "chock askpass cannot answer for that host, because the " ++
                "secret.password rule for it names a reviewer agent, and a reviewer agent cannot " ++
                "type a password. Change the rule to ask or to allow, both of which prompt a person.",
            .no_credential_for_that_host => "nobody typed a password for that host, so chock has " ++
                "none to give. A person is prompted once, for the host the remote URL names, and " ++
                "the host in this prompt must be that same host letter for letter.",
            .nobody_answered => "chock askpass reached no session, so nothing answered. " ++
                "A tool call inside the sandbox never can: the sandbox has no path to a session's socket.",
        };
    }

    pub fn wireName(self: Refusal) []const u8 {
        return @tagName(self);
    }

    pub fn fromWireName(name: []const u8) ?Refusal {
        return std.meta.stringToEnum(Refusal, name);
    }
};

pub const Answer = union(enum) {
    secret: []const u8,
    refused: Refusal,
};

pub const Asker = struct {
    grants: Grants = .{},
    table: *const table.Table,
    chain: []const []const u8,
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8 = policy_tool,

    pub fn answer(self: Asker, prompt_text: []const u8) Answer {
        const prompt = readPrompt(prompt_text) orelse return .{ .refused = .prompt_not_read };
        if (prompt.want == .username) return .{ .refused = .prompt_wants_a_user_name };

        // The policy first and the credential second. A refusal that depended
        // on which credentials are held would report which are held.
        if (self.mayPrompt(prompt.host)) |refusal| return .{ .refused = refusal };

        const value = self.grants.find(prompt.host) orelse
            return .{ .refused = .no_credential_for_that_host };
        return .{ .secret = value };
    }

    /// Null means the policy lets a person be prompted. One decider, asked from
    /// two places: a second copy could drift on the meaning of `ask`.
    pub fn mayPrompt(self: Asker, host: []const u8) ?Refusal {
        var buffer: [max_action_bytes]u8 = undefined;
        const action = actionInto(&buffer, host) orelse return .prompt_not_read;

        const decision = self.table.evaluateChain(self.chain, .{
            .agent_kind = self.agent_kind,
            .model = self.model,
            .tool = self.tool,
            .action = action,
        }, null);
        return switch (decision) {
            .deny => .host_not_permitted,
            .agent_review, .agent_then_human => .reviewer_cannot_answer,
            .ask, .allow => null,
        };
    }
};

pub const Ask = struct {
    prompt: []const u8,
};

pub const Reply = struct {
    secret: ?[]const u8 = null,
    refused: ?[]const u8 = null,
};

pub fn askLine(gpa: std.mem.Allocator, prompt: []const u8) std.mem.Allocator.Error![]u8 {
    const body = try std.json.Stringify.valueAlloc(gpa, Ask{ .prompt = prompt }, .{});
    defer gpa.free(body);
    return std.fmt.allocPrint(gpa, "{s}\n", .{body});
}

/// Owned by the caller, and the caller wipes it. A freed heap buffer keeps its
/// bytes until something else reuses that memory.
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

pub fn wipe(bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
}

pub const AppendError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

/// There is no answer in scope: the signature takes no `Grants` and no
/// `Answer`, and the session log is read by every attached client.
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

/// `chock_proto.storage.Locked` is not `pub`, so this reaches it through the
/// return type of `Storage.lock`.
const Locked = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

pub const max_kept_prompts: usize = 8;

/// This holds no credential: `step` takes the `Asker` as an argument, so a
/// value is in scope for one call and not for a session.
pub const Endpoint = struct {
    server: std.Io.net.Server,
    socket_path: []const u8,
    owner_uid: std.posix.uid_t,
    answered: usize = 0,
    refused: usize = 0,
    strangers: usize = 0,
    diagnostic: ?Diagnostic = null,
    /// A caller that polls `step` from the gap in a wait may not append to the
    /// session log. That caller passes `locked` as null and reads these after.
    kept: [max_kept_prompts][max_prompt_bytes]u8 = undefined,
    kept_lens: [max_kept_prompts]usize = @splat(0),
    kept_count: usize = 0,

    pub const OpenError = socket.Endpoint.OpenError;
    pub const StepError = std.mem.Allocator.Error || chock_proto.storage.StorageError;

    /// `socket.ensureDir` makes the parent `0o700`, which is the gate.
    pub fn open(io: std.Io, path: []const u8, diag: ?*?Diagnostic) OpenError!Endpoint {
        const address = try socket.addressFor(path, diag);

        const parent = std.fs.path.dirname(path) orelse return error.SocketUnavailable;
        try socket.ensureDir(io, parent, diag);

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

    pub fn close(self: *Endpoint, io: std.Io) void {
        self.server.deinit(io);
        std.Io.Dir.deleteFileAbsolute(io, self.socket_path) catch {};
    }

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
            // A log that cannot be written must not hand out a credential.
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

        self.keep(parsed.value.prompt);

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

    fn keep(self: *Endpoint, prompt: []const u8) void {
        const at = self.kept_count;
        self.kept_count += 1;
        if (at >= max_kept_prompts) return;
        const room = @min(prompt.len, max_prompt_bytes);
        @memcpy(self.kept[at][0..room], prompt[0..room]);
        self.kept_lens[at] = room;
    }

    pub fn keptPrompt(self: *const Endpoint, index: usize) ?[]const u8 {
        if (index >= @min(self.kept_count, max_kept_prompts)) return null;
        return self.kept[index][0..self.kept_lens[index]];
    }
};

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

fn boundedTimeout(budget_ms: u64) i32 {
    if (budget_ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(budget_ms);
}

comptime {
    for (@typeInfo(Grant).@"struct".fields) |field| {
        if (std.mem.indexOf(u8, field.name, "name") != null) {
            @compileError("a git credential must have no name for a handle to spell: " ++ field.name);
        }
    }
}

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

comptime {
    for (@typeInfo(Endpoint).@"struct".fields) |field| {
        if (field.type == Grants or field.type == Grant or field.type == Asker) {
            @compileError("the askpass endpoint must hold no credential: " ++ field.name);
        }
    }
}

const testing = std.testing;

const the_password = "ghp_9f2c4a7b1d3e5a6b7c8d";

const one_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.password.com.example.git", .decision = .allow },
    \\        },
    \\    },
    \\}
;

const ask_every_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.*", .decision = .ask },
    \\        },
    \\    },
    \\}
;

const deny_every_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.*", .decision = .deny },
    \\        },
    \\    },
    \\}
;

const review_every_host: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .action = "secret.*", .decision = .agent_review },
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
    const password = readPrompt("Password for 'https://ross@git.example.com': ").?;
    try testing.expectEqual(Want.password, password.want);
    try testing.expectEqualStrings("git.example.com", password.host);

    const username = readPrompt("Username for 'https://git.example.com': ").?;
    try testing.expectEqual(Want.username, username.want);
    try testing.expectEqualStrings("git.example.com", username.host);

    try testing.expectEqualStrings(
        "git.example.com",
        readPrompt("Password for 'https://ross@git.example.com:8443/team/project.git': ").?.host,
    );
    try testing.expectEqualStrings(
        "Git.Example.COM",
        readPrompt("Password for 'https://Git.Example.COM': ").?.host,
    );
}

test "a crafted prompt cannot name one host and be read as another" {
    const crafted = [_]struct { prompt: []const u8, host: ?[]const u8 }{
        .{
            .prompt = "Password for 'https://evil.test/x@git.example.com': ",
            .host = "evil.test",
        },
        .{
            .prompt = "Password for 'https://git.example.com@evil.test/': ",
            .host = "evil.test",
        },
        .{ .prompt = "Password for 'https://evil.test?x=@git.example.com': ", .host = "evil.test" },
        .{ .prompt = "Password for 'https://evil.test#@git.example.com': ", .host = "evil.test" },
        .{
            .prompt = "Password for 'https://evil.test' or 'https://git.example.com': ",
            .host = "evil.test",
        },
        .{ .prompt = "Password for 'https://git.example.com*': ", .host = null },
        .{ .prompt = "Password for 'https://[::1]': ", .host = null },
        .{ .prompt = "Password for 'https://': ", .host = null },
        .{ .prompt = "Password for 'https://.example.com': ", .host = null },
        .{ .prompt = "Password for 'file:///etc/shadow': ", .host = null },
        .{ .prompt = "Password for 'ssh://git.example.com': ", .host = null },
        .{ .prompt = "Enter passphrase for key '/home/ross/.ssh/id_ed25519': ", .host = null },
        .{ .prompt = "", .host = null },
        .{ .prompt = "Password for git.example.com: ", .host = null },
        .{ .prompt = "Password for 'https://git.example.com", .host = null },
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

    var long: [max_prompt_bytes + 1]u8 = @splat('x');
    try testing.expectEqual(@as(?Prompt, null), readPrompt(&long));
}

test "the action name reverses the labels, so a class rule cannot be reached by the wrong host" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "secret.password.com.example.git",
        actionInto(&buffer, "git.example.com").?,
    );
    try testing.expectEqualStrings(
        "secret.password.com.example.git",
        actionInto(&buffer, "Git.Example.COM").?,
    );

    const evil = actionInto(&buffer, "git.example.com.evil.test").?;
    try testing.expect(!std.mem.startsWith(u8, evil, "secret.password.com.example."));
    try testing.expectEqualStrings("secret.password.test.evil.com.example.git", evil);

    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, ""));
    try testing.expectEqual(@as(?[]const u8, null), actionInto(&buffer, "git.example.com/x"));

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
    const gpa = testing.allocator;

    const permitting = try table.Table.parse(gpa, one_host, null);
    defer table.Table.destroy(gpa, permitting);
    const asker = askerOver(permitting);

    const answer = asker.answer("Password for 'https://ross@git.example.com': ");
    try testing.expect(answer == .secret);
    try testing.expectEqualStrings(the_password, answer.secret);

    try testing.expectEqual(
        Answer{ .refused = .prompt_not_read },
        asker.answer("Enter passphrase for key '/home/ross/.ssh/id_ed25519': "),
    );
    try testing.expectEqual(
        Answer{ .refused = .prompt_wants_a_user_name },
        asker.answer("Username for 'https://git.example.com': "),
    );
    try testing.expectEqual(
        Answer{ .refused = .no_credential_for_that_host },
        asker.answer("Password for 'https://ross@evil.test': "),
    );
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

    const asking = try table.Table.parse(gpa, ask_every_host, null);
    defer table.Table.destroy(gpa, asking);
    const asked = askerOver(asking).answer("Password for 'https://ross@git.example.com': ");
    try testing.expect(asked == .secret);
    try testing.expectEqualStrings(the_password, asked.secret);

    const empty = try table.Table.parse(gpa, ".{ .policy = .{ .rules = .{} } }", null);
    defer table.Table.destroy(gpa, empty);
    const unruled = askerOver(empty).answer("Password for 'https://ross@git.example.com': ");
    try testing.expect(unruled == .secret);

    const denying = try table.Table.parse(gpa, deny_every_host, null);
    defer table.Table.destroy(gpa, denying);
    try testing.expectEqual(
        Answer{ .refused = .host_not_permitted },
        askerOver(denying).answer("Password for 'https://ross@git.example.com': "),
    );

    const reviewed = try table.Table.parse(gpa, review_every_host, null);
    defer table.Table.destroy(gpa, reviewed);
    try testing.expectEqual(
        Answer{ .refused = .reviewer_cannot_answer },
        askerOver(reviewed).answer("Password for 'https://ross@git.example.com': "),
    );
}

test "mayPrompt is the one decider, and answer reaches the same verdict" {
    const gpa = testing.allocator;

    const cases = [_]struct { text: [:0]const u8, refusal: ?Refusal }{
        .{ .text = one_host, .refusal = null },
        .{ .text = ask_every_host, .refusal = null },
        .{ .text = deny_every_host, .refusal = .host_not_permitted },
        .{ .text = review_every_host, .refusal = .reviewer_cannot_answer },
    };
    for (cases) |case| {
        const policy = try table.Table.parse(gpa, case.text, null);
        defer table.Table.destroy(gpa, policy);
        const asker = askerOver(policy);

        try testing.expectEqual(case.refusal, asker.mayPrompt("git.example.com"));

        const answer = asker.answer("Password for 'https://ross@git.example.com': ");
        if (case.refusal) |refusal| {
            try testing.expectEqual(Answer{ .refused = refusal }, answer);
        } else {
            try testing.expect(answer == .secret);
        }
    }

    var long: [max_host_bytes + 8]u8 = @splat('a');
    const policy = try table.Table.parse(gpa, one_host, null);
    defer table.Table.destroy(gpa, policy);
    try testing.expectEqual(Refusal.prompt_not_read, askerOver(policy).mayPrompt(&long).?);
}

test "a grant is found by an exact host and never by a suffix" {
    const grants = testGrants();
    try testing.expectEqualStrings(the_password, grants.find("git.example.com").?);
    try testing.expectEqualStrings(the_password, grants.find("GIT.EXAMPLE.COM").?);
    try testing.expectEqual(@as(?[]const u8, null), grants.find("evil.git.example.com"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find("git.example.com.evil.test"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find("example.com"));
    try testing.expectEqual(@as(?[]const u8, null), grants.find(""));
}

test "a grant reaches redaction without ever becoming a name" {
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

    const store = secrets.Store{ .entries = &.{.{ .name = "aiand", .value = "sk-live-1" }} };
    try testing.expectEqual(@as(?[]const u8, null), store.get("git.example.com"));
    try testing.expectError(
        error.UnknownSecret,
        secrets.resolve(store, gpa, "TOKEN={{secret:git.example.com}}", null),
    );
}

test "one frame carries a prompt with a line break in it, and one carries a value" {
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

    const no = try replyLine(gpa, .{ .refused = .host_not_permitted });
    defer gpa.free(no);
    var refused = try std.json.parseFromSlice(Reply, gpa, no[0 .. no.len - 1], .{});
    defer refused.deinit();
    try testing.expectEqual(@as(?[]const u8, null), refused.value.secret);
    try testing.expectEqual(Refusal.host_not_permitted, Refusal.fromWireName(refused.value.refused.?).?);
    try testing.expectEqual(@as(?Refusal, null), Refusal.fromWireName("no_such_refusal"));
}

test "the log records that a prompt was asked and never what was answered" {
    const gpa = testing.allocator;
    const io = testing.io;

    var backing = try chock_proto.storage.Memory.init(gpa, "01ASKPASS");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    const prompt = "Password for 'https://ross@git.example.com': ";
    _ = try appendPrompt(gpa, io, &locked, "askpass-1", prompt, 1_700_000_000_000);

    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "prompt.password") != null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, "git.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, the_password) == null);

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
        try testing.expectEqualStrings("no_credential_for_that_host", parsed.value.refused.?);
    }

    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, backing.bytes.items, "prompt.password"));
    try testing.expect(std.mem.indexOf(u8, backing.bytes.items, the_password) == null);

    try testing.expect(!try endpoint.step(gpa, io, &locked, asker, 0));

    {
        const silent = try address.connect(io);
        defer silent.close(io);
        try testing.expect(!try endpoint.step(gpa, io, &locked, asker, 1));
    }
    try testing.expectEqual(@as(usize, 1), endpoint.answered);
    try testing.expectEqual(@as(usize, 1), endpoint.refused);
}

test "every refusal names what to do instead, and none of them is a bare no" {
    for (std.enums.values(Refusal)) |refusal| {
        const text = refusal.text();
        try testing.expect(text.len > 40);
        try testing.expect(std.mem.indexOf(u8, text, "chock") != null);
        try testing.expect(std.mem.indexOf(u8, text, ".") != null);
        try testing.expectEqual(refusal, Refusal.fromWireName(refusal.wireName()).?);
    }

    try testing.expect(std.mem.indexOf(u8, Refusal.host_not_permitted.text(), "secret.password") != null);
    try testing.expect(std.mem.indexOf(u8, Refusal.reviewer_cannot_answer.text(), "secret.password") != null);
    try testing.expect(std.mem.indexOf(u8, Refusal.prompt_wants_a_user_name.text(), "https://you@") != null);
    try testing.expect(std.mem.indexOf(u8, Refusal.prompt_not_read.text(), "LC_ALL=C") != null);
}

test "the askpass socket binds at exactly the bound and refuses one byte more" {
    // `std.Io.net.UnixAddress.init` takes anything up to `UnixAddress.max_len`,
    // which is past the end of Darwin's `sun_path`. Linux binds an unterminated
    // path that fills the field, so only Darwin ends the process in `listen`.
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
