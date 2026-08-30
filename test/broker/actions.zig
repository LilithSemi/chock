//! The broker's own rule, proved on a running system.
//!
//! **The agent never gets the privilege. Chock does the operation outside
//! the sandbox after the user approves it, and gives the agent the result.**
//!
//! Every other test of `lib/chock-broker/actions.zig` proves the first half:
//! that an approved act really happens. That half alone pins nothing, because
//! a broker that widened the sandbox on an approval would pass it too. The
//! test here does the second half as well. It lets the
//! broker land a `workspace.apply` and read a `net.fetch`, and then spawns a
//! real sandbox, built from the very same `Workspace`, and watches it fail to
//! write the object store the broker just wrote and fail to reach the address
//! the broker just read.
//!
//! An approval grants one act by the broker. It never grants a capability to
//! the agent.
//!
//! A real `Sandbox.spawn` call needs a single threaded caller, because `fork`
//! carries only the calling thread into the child, and the zig test runner is
//! not that caller. So the sandbox work goes through `escape_probe`, the same
//! program `test/workspace/escape.zig` drives, started as a fresh process.
//! See `test/workspace/escape_probe.zig`'s own top comment.
//!
//! Every test here builds its own project inside a fresh
//! `std.testing.tmpDir` and sets its own `GIT_CEILING_DIRECTORIES`: Chock's
//! own checkout is a git repository, and `tmpDir` makes every scratch
//! directory somewhere underneath it, so git's upward search would otherwise
//! walk past a fresh scratch repository and find this project's real one.

const std = @import("std");
const chock_broker = @import("chock-broker");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const chock_workspace = @import("chock-workspace");
const sandbox = @import("chock-sandbox");
const fake_provider = @import("fake_provider");

const actions = chock_broker.actions;
const Broker = chock_broker.Broker;
const Workspace = chock_workspace.Workspace;
const git = chock_workspace.git;
const event = chock_proto.event;
const testing = std.testing;

/// The file the probe's own `git-commit` flow adds and commits inside the
/// sandbox. Named by `test/workspace/escape_probe.zig`, which owns the flow.
const agent_file = "chock-object-store-test.txt";

/// `chock_proto.storage.Locked` is not `pub`. This reaches the same type
/// through the return type of `Storage.lock`, which is.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

// The scratch project, the probe drivers, and the serializers all live in
// `support.zig`, a sibling of this file inside the same module directory, so
// `test/broker/git_shim.zig` can use the same ones. See that file's own top
// comment.
const support = @import("support.zig");

const absoluteDirPath = support.absoluteDirPath;
const writeFileAbsolute = support.writeFileAbsolute;
const gitOk = support.gitOk;
const TestProject = support.TestProject;
const findGitOnPath = support.findGitOnPath;
const runProbe = support.runProbe;

/// A policy that asks about every action, so every test here goes through a
/// real question and a real answer.
const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

/// A `Broker.Waiter` that answers the one open request with `decision` the
/// first time the broker gives control away. It never sleeps.
const TestWaiter = struct {
    now_ms: i64 = 1_700_000_000_000,
    waits: usize = 0,
    gpa: std.mem.Allocator,
    store: chock_proto.storage.Storage,
    locked: *LockedHandle,
    decision: event.ApprovalDecision,
    failed: ?anyerror = null,

    fn waiter(self: *TestWaiter) Broker.Waiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Broker.Waiter.VTable{ .nowMs = nowMsFn, .wait = waitFn };

    fn nowMsFn(ptr: *anyopaque, io: std.Io) i64 {
        _ = io;
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        return self.now_ms;
    }

    fn waitFn(ptr: *anyopaque, io: std.Io, budget_ms: u64) Broker.Waiter.Wake {
        const self: *TestWaiter = @ptrCast(@alignCast(ptr));
        self.waits += 1;
        if (self.waits == 1) {
            self.answer(io) catch |err| {
                if (self.failed == null) self.failed = err;
            };
        }
        self.now_ms += @intCast(budget_ms);
        // Nothing cancels these tests. See `Broker.Waiter.Wake`.
        return .slept;
    }

    fn answer(self: *TestWaiter, io: std.Io) !void {
        var replay = try self.store.replay(self.gpa, io, 0);
        defer replay.deinit();
        var request_id: ?u64 = null;
        while (try replay.next(io)) |parsed| {
            defer parsed.deinit();
            if (parsed.value.event != .approval_request) continue;
            request_id = parsed.value.id;
        }
        const id = request_id orelse return error.NoRequestInTheLog;
        _ = try self.locked.append(self.gpa, io, .{ .approval_response = .{
            .request_id = id,
            .decision = self.decision,
            .responder = "ross",
        } }, self.now_ms);
    }
};

/// Ask for `ask` over a real in memory log, answer it with `decision`, and
/// give back what `actions.run` made of it.
fn askAndAnswer(
    gpa: std.mem.Allocator,
    io: std.Io,
    decision: event.ApprovalDecision,
    ctx: actions.Context,
    ask: actions.Ask,
) !actions.Attempt {
    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    var waiter = TestWaiter{ .gpa = gpa, .store = store, .locked = &locked, .decision = decision };

    const policy = try chock_policy.table.Table.parse(gpa, ask_every_action, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = waiter.waiter() };
    const attempt = actions.run(&broker, gpa, io, store, &locked, ctx, ask, null);
    if (waiter.failed) |err| return err;
    return attempt;
}

fn testAsk(action: actions.Action) actions.Ask {
    return .{
        .action = action,
        .reason = "the task asked for it",
        .agent_kind = "coder",
        .model_alias = "main",
        .tool = "request_action",
        .tool_call_id = "call1",
    };
}

/// A server on 127.0.0.1 that answers one request with `body` and then stops
/// serving, while keeping its listening socket open so the address stays
/// live for whatever asks next.
const one_reply_head = "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n";
const one_reply_body = "the broker read this\n";

/// A resolver that says `127.0.0.1` answers an address on the internet.
///
/// **`actions.perform` refuses the loopback interface** before it opens
/// anything: a permitted name that answered `127.0.0.1` or `169.254.169.254`
/// would turn a rule about a host on the internet into a handle on this machine
/// and on the cloud metadata service. Every server in this file listens on
/// loopback, so a test that wants a real request out has to say what the name
/// answers with. Only the lookup is faked: the socket, the bytes and the server
/// stay real.
///
/// The test below that proves the guard uses none of this. It leaves the
/// context on `actions.Resolver.system`, so `127.0.0.1` answers itself.
const loopback_on_the_internet = struct {
    const address = "93.184.216.34";
    const marker: u8 = 0;

    fn resolver() actions.Resolver {
        return .{ .ptr = @constCast(&marker), .vtable = &vtable };
    }

    const vtable = actions.Resolver.VTable{ .lookup = lookupFn };

    fn lookupFn(
        ptr: *anyopaque,
        io: std.Io,
        host: []const u8,
        into: []actions.Resolver.Address,
    ) actions.Resolver.LookupError!usize {
        _ = ptr;
        _ = io;
        if (into.len == 0) return error.TooManyAddresses;
        if (!std.mem.eql(u8, host, "127.0.0.1")) return error.NotResolved;
        into[0] = std.Io.net.IpAddress.parse(address, 0) catch return error.NotResolved;
        return 1;
    }
};

test "an approved net.fetch reads the one host it covers, and gives the agent the bytes" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const script = fake_provider.Script{
        .head = one_reply_head,
        .body = &.{.{ .bytes = one_reply_body }},
    };
    var server = try fake_provider.FakeProvider.start(gpa, io, script);
    defer server.deinit();

    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/spec.txt", .{server.port});

    const ctx = actions.Context{
        .env = &project.env,
        .resolver = loopback_on_the_internet.resolver(),
    };
    var attempt = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .net_fetch = .{
        .host = "127.0.0.1",
        .url = url,
    } }));
    server.join();
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);

    try testing.expectEqual(@as(u16, 200), attempt.done.result.net_fetch.status);
    try testing.expectEqualStrings(one_reply_body, attempt.done.result.net_fetch.body);

    // The request really went out: the server read a GET for the path the
    // approval named, which is what makes the body above an answer and not a
    // value invented in this process.
    try testing.expect(std.mem.startsWith(u8, server.captured.head, "GET /spec.txt "));
}

test "the broker runs the action, and the agent never holds the capability" {
    // The rule end to end, in three parts.
    //
    // 1. The agent works inside a real sandbox. It commits, and every object
    //    lands in the session's own scratch store, never in the project.
    // 2. The user approves two acts. The broker lands the commit in the
    //    user's own repository and reads a URL over the network. Both really
    //    happen: the ref moves, and the bytes come back.
    // 3. The sandbox is built again, from the same `Workspace`, and it still
    //    cannot write the object store the broker just wrote, and still
    //    cannot reach the address the broker just read.
    //
    // Part 3 is the part that makes this a test of the rule. A broker
    // that widened the sandbox on an approval would pass parts 1 and 2 and
    // fail here. A test that stopped after part 2 would pin nothing.
    const gpa = testing.allocator;
    const io = testing.io;

    const git_path = (try findGitOnPath(gpa, io)) orelse {
        // A skip needs no message: a test that writes to standard error and
        // passes still puts a `failed command:` line in the build log.
        return error.SkipZigTest;
    };
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(gpa, io, &project.env, project.root_path, project.scratch_path, "sess1", null);
    defer workspace.close(gpa, io, &project.env, null) catch unreachable;
    const wt = workspace.kind.worktree;

    // Content that was never committed before, so git cannot skip writing
    // the object because it already has one with this hash.
    var agent_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const agent_path = try std.fmt.bufPrintZ(&agent_path_buffer, "{s}/{s}", .{ wt.path, agent_file });
    try writeFileAbsolute(io, agent_path, "the agent wrote this inside the sandbox\n");

    var work_root_tmp = testing.tmpDir(.{});
    defer work_root_tmp.cleanup();
    const commit_term = try runProbe(gpa, &workspace, work_root_tmp, "git-commit", git_path);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_term);

    // Read the commit the sandbox made. On the host the same two variables
    // the workspace sets inside the sandbox point at the host paths.
    var session_env = try project.env.clone(gpa);
    defer session_env.deinit();
    try session_env.put("GIT_OBJECT_DIRECTORY", wt.object_store_source);
    const real_objects = try std.fs.path.join(gpa, &.{ wt.git_dir, "objects" });
    defer gpa.free(real_objects);
    try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", real_objects);
    // The sandbox writes the session's own copy of the worktree metadata
    // directory, so the session's own HEAD is there and not in the project's
    // `.git/worktrees/<id>`. `Worktree.headAfterSession` names the same
    // directory the same way. See `chock_workspace.worktree`'s own
    // `copyMetaDirectory`.
    try session_env.put("GIT_DIR", wt.worktree_meta_bind_source);

    const agent_commit = try gitOk(gpa, &session_env, wt.path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(agent_commit);

    // The project has never seen it. The agent committed and the user's own
    // repository is untouched, which is the scratch object store working.
    var not_yet = try git.run(gpa, io, &project.env, project.root_path, &.{ "cat-file", "-e", agent_commit }, null);
    defer not_yet.deinit(gpa);
    try testing.expect(not_yet.term != .exited or not_yet.term.exited != 0);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = actions.Context{
        .env = &project.env,
        .resolver = loopback_on_the_internet.resolver(),
    };
    const apply = try actions.WorkspaceApply.describing(arena, io, ctx, .{
        .repository = project.root_path,
        .scratch_object_store = wt.object_store_source,
        .ref = "refs/heads/main",
        .new_id = agent_commit,
    }, null);
    try testing.expect(apply.objects.len >= 3);

    var applied = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .workspace_apply = apply }));
    try testing.expect(applied == .done);
    defer applied.done.result.deinit(gpa);

    // The user's own repository now holds the work, read with no scratch
    // store and no alternate in the environment at all.
    const project_head = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(project_head);
    try testing.expectEqualStrings(agent_commit, project_head);
    const landed = try gitOk(gpa, &project.env, project.root_path, &.{
        "show", "refs/heads/main:" ++ agent_file,
    });
    defer gpa.free(landed);
    try testing.expectEqualStrings("the agent wrote this inside the sandbox", landed);

    // And the broker reaches the network. The server keeps its listening
    // socket open after it answers, so the address is still live when the
    // sandbox tries it below.
    const script = fake_provider.Script{
        .head = one_reply_head,
        .body = &.{.{ .bytes = one_reply_body }},
    };
    var server = try fake_provider.FakeProvider.start(gpa, io, script);
    defer server.deinit();

    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/spec.txt", .{server.port});
    var fetched = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .net_fetch = .{
        .host = "127.0.0.1",
        .url = url,
    } }));
    server.join();
    try testing.expect(fetched == .done);
    defer fetched.done.result.deinit(gpa);
    try testing.expectEqualStrings(one_reply_body, fetched.done.result.net_fetch.body);

    // The address the broker just read is still live on this machine. Without
    // this the refusal below could be a port that had simply gone away, which
    // would prove nothing about the sandbox.
    {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port);
        var stream = try address.connect(io, .{ .mode = .stream });
        stream.close(io);
    }

    var after_root_tmp = testing.tmpDir(.{});
    defer after_root_tmp.cleanup();

    // Still no route out, to the very address the broker reached a moment
    // ago, from a sandbox built out of the same Workspace the approval was
    // about. Exit 1 is the probe's own code for ENETUNREACH, the errno a
    // network namespace with no route gives. A connection that was made
    // would exit 0, and a refusal by the far end would exit 5, because that
    // would mean the packet left the sandbox.
    var address_buffer: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buffer, "127.0.0.1:{d}", .{server.port});
    const connect_term = try runProbe(gpa, &workspace, after_root_tmp, "connect", address);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, connect_term);

    // And still no write into the project's own object store, the store the
    // broker just put three objects into. Exit 1 is the probe's own code for
    // EROFS, from the read only bind mount.
    const object_store_target = try std.fs.path.join(gpa, &.{ wt.sandbox_git_root, "objects", "chock-after-approval" });
    defer gpa.free(object_store_target);
    const write_term = try runProbe(gpa, &workspace, after_root_tmp, "write", object_store_target);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, write_term);

    // The sandbox is not a deny all, before or after an approval: a write in
    // the worktree still works. Without this the two refusals above could be
    // a sandbox that had simply stopped working.
    const inside_worktree = try std.fs.path.join(gpa, &.{ wt.project_root, "chock-after-approval.txt" });
    defer gpa.free(inside_worktree);
    const allowed_term = try runProbe(gpa, &workspace, after_root_tmp, "write", inside_worktree);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, allowed_term);

    // Nothing the sandbox did after the approval reached the user's own
    // repository either: the ref is exactly where the broker put it.
    const head_at_the_end = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(head_at_the_end);
    try testing.expectEqualStrings(agent_commit, head_at_the_end);
}

/// A project that lets the agent carry its own work back without asking
/// anybody, keyed on the tool that asks for it.
///
/// **The key is the whole point of these two tables.** `request_action` is the
/// tool an agent calls, and it is also the name `chock run` carries when it
/// asks at the end of a run: see `actions.self_asked_tool`. A project that
/// writes this rule is saying that this act, asked for this way, needs nobody.
const table_allows_the_apply: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\            .{ .tool = "request_action", .action = "workspace.apply", .decision = .allow },
    \\        },
    \\    },
    \\}
;

/// The same project with the answer the other way round.
const table_denies_the_apply: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\            .{ .tool = "request_action", .action = "workspace.apply", .decision = .deny },
    \\        },
    \\    },
    \\}
;

// The tool name in the policy key and the tool name the model calls have to
// be one string, or a project writes a rule for a key nothing ever builds.
test "the tool an agent calls for an apply is the tool name the policy key carries" {
    try testing.expectEqualStrings("request_action", actions.self_asked_tool);
    try testing.expectEqualStrings(actions.self_asked_tool, testAsk(.{ .net_fetch = .{
        .host = "example.invalid",
        .url = "https://example.invalid/",
    } }).tool);
}

/// Ask for `ask` against `table`, with a waiter that answers nothing and
/// records whether it was ever given control. **A waiter with zero waits is
/// proof that nobody was asked**, which is the half of a table answer that a
/// test of the outcome alone cannot see.
fn askTheTable(
    gpa: std.mem.Allocator,
    io: std.Io,
    table: [:0]const u8,
    ctx: actions.Context,
    ask: actions.Ask,
    waits: *usize,
) !actions.Attempt {
    var backing = try chock_proto.storage.Memory.init(gpa, "01BROKER");
    const store = backing.storage();
    defer store.close(io);

    var locked = try store.lock(io);
    defer locked.unlock(io) catch {};

    // It answers nothing at all, so a table that did not decide would leave the
    // request open and the broker would refuse it for want of an answer. That
    // is a different outcome from either of the two below, so neither test can
    // pass by accident.
    var waiter = TestWaiter{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = .refused_by_user,
        .now_ms = 1_700_000_000_000,
    };
    // Answering is what `waits == 1` triggers, so this stops it answering at
    // all while still counting the turns it was given.
    waiter.waits = 1;

    const policy = try chock_policy.table.Table.parse(gpa, table, null);
    defer chock_policy.table.Table.destroy(gpa, policy);

    const broker = Broker{ .policy = policy, .waiter = waiter.waiter() };
    const attempt = actions.run(&broker, gpa, io, store, &locked, ctx, ask, null);
    waits.* = waiter.waits - 1;
    if (waiter.failed) |err| return err;
    return attempt;
}

test "an agent that asks for an apply the table allows carries its commit into the project" {
    // The route the `request_action` tool takes, end to end and against real
    // git: the agent commits in its own worktree, asks for `workspace.apply`
    // with the tool name that goes in the policy key, and the project's own
    // table answers. **The agent never answers**: the waiter here answers
    // nothing at all and is asked nothing, and the same call with the table
    // turned round carries nothing.
    const gpa = testing.allocator;
    const io = testing.io;

    const git_path = (try findGitOnPath(gpa, io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    var workspace = try Workspace.open(
        gpa,
        io,
        &project.env,
        project.root_path,
        project.scratch_path,
        "sess1",
        null,
    );
    defer workspace.close(gpa, io, &project.env, null) catch unreachable;
    const wt = workspace.kind.worktree;

    // The session's own environment, which puts every object git writes into
    // the scratch store and leaves the project's own untouched. The sandbox
    // sets the same two variables inside itself; this test is about the policy
    // route and not about the sandbox, so the commit is made on the host.
    var session_env = try project.env.clone(gpa);
    defer session_env.deinit();
    try session_env.put("GIT_OBJECT_DIRECTORY", wt.object_store_source);
    const real_objects = try std.fs.path.join(gpa, &.{ wt.git_dir, "objects" });
    defer gpa.free(real_objects);
    try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", real_objects);

    const written = try std.fs.path.join(gpa, &.{ wt.path, agent_file });
    defer gpa.free(written);
    try writeFileAbsolute(io, written, "the agent asked for this to be carried back\n");

    const added = try gitOk(gpa, &session_env, wt.path, &.{ "add", agent_file });
    gpa.free(added);
    const committed = try gitOk(gpa, &session_env, wt.path, &.{
        "-c",     "user.email=agent@example.invalid",
        "-c",     "user.name=agent",
        "commit", "--quiet",
        "-m",     "the agent's own commit",
    });
    gpa.free(committed);
    const agent_commit = try gitOk(gpa, &session_env, wt.path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(agent_commit);

    // Nothing of it is in the user's repository yet.
    var not_yet = try git.run(gpa, io, &project.env, project.root_path, &.{
        "cat-file", "-e", agent_commit,
    }, null);
    defer not_yet.deinit(gpa);
    try testing.expect(not_yet.term != .exited or not_yet.term.exited != 0);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = actions.Context{ .env = &project.env };
    // The ref an agent's apply lands on: a ref of the session's own, never a
    // branch of the user's. `src/run.zig`'s `applyRef` builds the same name for
    // both callers, so an agent that asks reaches the same place the harness
    // would have reached at the end of the run.
    const ref = "refs/chock/sess1";

    // Turned down first, so the "it landed" half below cannot be a repository
    // that already held the work.
    {
        const apply = try actions.WorkspaceApply.describing(arena, io, ctx, .{
            .repository = project.root_path,
            .scratch_object_store = wt.object_store_source,
            .ref = ref,
            .new_id = agent_commit,
        }, null);
        var waits: usize = 0;
        const refused = try askTheTable(
            gpa,
            io,
            table_denies_the_apply,
            ctx,
            testAsk(.{ .workspace_apply = apply }),
            &waits,
        );
        try testing.expect(refused == .refused);
        // **Nobody was asked.** The table decided, and a table that decides
        // spends nobody's attention.
        try testing.expectEqual(@as(usize, 0), waits);

        var no_ref = try git.run(gpa, io, &project.env, project.root_path, &.{
            "rev-parse", "--verify", ref,
        }, null);
        defer no_ref.deinit(gpa);
        try testing.expect(no_ref.term != .exited or no_ref.term.exited != 0);
    }

    {
        const apply = try actions.WorkspaceApply.describing(arena, io, ctx, .{
            .repository = project.root_path,
            .scratch_object_store = wt.object_store_source,
            .ref = ref,
            .new_id = agent_commit,
        }, null);
        // The description is what a person reads, and it has to say what would
        // be applied or the approval is theatre. The commit is named and the
        // file it adds is in the diff.
        try testing.expect(apply.objects.len >= 3);
        try testing.expect(std.mem.indexOf(u8, apply.diff, agent_file) != null);

        var waits: usize = 0;
        var landed = try askTheTable(
            gpa,
            io,
            table_allows_the_apply,
            ctx,
            testAsk(.{ .workspace_apply = apply }),
            &waits,
        );
        try testing.expect(landed == .done);
        defer landed.done.result.deinit(gpa);
        try testing.expectEqual(@as(usize, 0), waits);
    }

    // The work is in the user's own repository, read with no scratch store and
    // no alternate in the environment at all.
    const at_ref = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", ref });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(agent_commit, at_ref);

    // **And no branch of the user's moved.** An agent that asks gains nothing
    // an agent that waits would not have had, and parking the work on a ref of
    // the session's own is the whole of that.
    var head_after = try git.run(gpa, io, &project.env, project.root_path, &.{
        "rev-parse", "--verify", "refs/heads/main",
    }, null);
    defer head_after.deinit(gpa);
    if (head_after.term == .exited and head_after.term.exited == 0) {
        try testing.expect(!std.mem.eql(u8, agent_commit, std.mem.trimEnd(u8, head_after.stdout, "\n")));
    }
}

test "an approved net.fetch whose host answers this machine reads nothing" {
    // **The guard covers `actions.perform` itself**, and not only the fetch
    // tool a layer above it. This is the privileged act: it is what opens a
    // socket, so it is where the address a name answered with is checked.
    //
    // The user approved the act, so nothing above this refuses. The address is
    // what refuses, and it does so after the lookup and before anything opens.
    //
    // **No fake resolver here.** The context is left on
    // `actions.Resolver.system`, so `127.0.0.1` answers `127.0.0.1`, the same
    // as it would in a real run.
    //
    // Mutation check: delete the `addressIsReachable` loop in `performNetFetch`
    // and this test fails, because the fetch succeeds and the server serves the
    // page.
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var project = try TestProject.init(gpa, tmp);
    defer project.deinit();

    const script = fake_provider.Script{
        .head = one_reply_head,
        .body = &.{.{ .bytes = one_reply_body }},
    };
    var server = try fake_provider.FakeProvider.start(gpa, io, script);
    defer server.deinit();

    var url_buffer: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buffer, "http://127.0.0.1:{d}/spec.txt", .{server.port});

    const ctx = actions.Context{ .env = &project.env };
    try testing.expectError(error.AddressNotPermitted, askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{
        .net_fetch = .{ .host = "127.0.0.1", .url = url },
    })));

    // The server is still waiting for its one connection, so it is released
    // with a connection that says nothing. A head it cannot read leaves
    // `captured` empty, which is what `FakeProvider` documents.
    {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port);
        var stream = try address.connect(io, .{ .mode = .stream });
        stream.close(io);
    }
    server.join();

    // **Zero requests.** A refusal that opened the connection and then threw
    // the answer away would pass every check above.
    try testing.expectEqual(@as(usize, 0), server.captured.head.len);
}

// ---------------------------------------------------------------------------
// How an approved apply lands: `ref`, `merge`, `rebase` and `squash`.
//
// **Every one of these runs against real git.** The thing under test is what
// happens to a real repository with a real working tree in it, and a fake git
// would pass whatever these tests said it should. See
// `lib/chock-broker/integrate.zig` for the design they pin: the result is built
// in the session's own object store, and the only write to the project is one
// fast forward.
// ---------------------------------------------------------------------------

/// A project, a worktree session on it, and one commit that session made,
/// which is the state every test below starts from.
const Landing = chock_policy.apply.Landing;

const Carried = struct {
    project: TestProject,
    workspace: Workspace,
    session_env: std.process.Environ.Map,
    /// The commit the session made. It is in the scratch store and the project
    /// has never seen it.
    commit: []u8,

    /// A session that wrote `contents` into `path` inside its worktree and
    /// committed it.
    fn init(
        gpa: std.mem.Allocator,
        tmp: testing.TmpDir,
        path: []const u8,
        contents: []const u8,
    ) !Carried {
        const io = testing.io;
        var project = try TestProject.init(gpa, tmp);
        errdefer project.deinit();

        var workspace = try Workspace.open(
            gpa,
            io,
            &project.env,
            project.root_path,
            project.scratch_path,
            "sess1",
            null,
        );
        errdefer workspace.close(gpa, io, &project.env, null) catch unreachable;
        const wt = workspace.kind.worktree;

        // Every object git writes goes into the scratch store, and the
        // project's own store is only read. The sandbox sets the same two
        // variables inside itself.
        var session_env = try project.env.clone(gpa);
        errdefer session_env.deinit();
        try session_env.put("GIT_OBJECT_DIRECTORY", wt.object_store_source);
        const real_objects = try std.fs.path.join(gpa, &.{ wt.git_dir, "objects" });
        defer gpa.free(real_objects);
        try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", real_objects);

        const written = try std.fs.path.join(gpa, &.{ wt.path, path });
        defer gpa.free(written);
        try writeFileAbsolute(io, written, contents);

        gpa.free(try gitOk(gpa, &session_env, wt.path, &.{ "add", path }));
        gpa.free(try gitOk(gpa, &session_env, wt.path, &.{
            "-c",     "user.email=agent@example.invalid",
            "-c",     "user.name=agent",
            "commit", "--quiet",
            "-m",     "the agent's own commit",
        }));

        return .{
            .project = project,
            .workspace = workspace,
            .session_env = session_env,
            .commit = try gitOk(gpa, &session_env, wt.path, &.{ "rev-parse", "HEAD" }),
        };
    }

    fn deinit(self: *Carried, gpa: std.mem.Allocator) void {
        gpa.free(self.commit);
        self.session_env.deinit();
        self.workspace.close(gpa, testing.io, &self.project.env, null) catch unreachable;
        self.project.deinit();
    }

    fn tree(self: *const Carried) chock_workspace.worktree.Worktree {
        return self.workspace.kind.worktree;
    }

    /// One more commit on the project's own branch, so the two histories have
    /// really diverged and a merge is a merge rather than a fast forward.
    fn commitOnMain(self: *Carried, gpa: std.mem.Allocator, path: []const u8, contents: []const u8) !void {
        const written = try std.fs.path.join(gpa, &.{ self.project.root_path, path });
        defer gpa.free(written);
        try writeFileAbsolute(testing.io, written, contents);
        gpa.free(try gitOk(gpa, &self.project.env, self.project.root_path, &.{ "add", path }));
        gpa.free(try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "commit", "--quiet", "-m", "the user's own commit",
        }));
    }

    /// Describe an apply of this session's commit, in `landing`.
    fn describing(
        self: *const Carried,
        arena: std.mem.Allocator,
        landing: Landing,
    ) !actions.WorkspaceApply {
        return actions.WorkspaceApply.describing(arena, testing.io, .{ .env = &self.project.env }, .{
            .repository = self.project.root_path,
            .scratch_object_store = self.tree().object_store_source,
            .ref = apply_ref,
            .new_id = self.commit,
            .landing = landing,
        }, null);
    }

    /// What `git` says about the project right now: the branch, where it is,
    /// what `HEAD` is, and everything the working tree holds that the branch
    /// does not. **Everything a "the repository is exactly as it was" claim has
    /// to compare.** The caller frees it.
    fn snapshot(self: *const Carried, gpa: std.mem.Allocator) ![]u8 {
        const branch = try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "symbolic-ref", "--quiet", "HEAD",
        });
        defer gpa.free(branch);
        const head = try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "rev-parse", "HEAD",
        });
        defer gpa.free(head);
        const status = try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "status", "--porcelain",
        });
        defer gpa.free(status);
        // The reflog of the branch, so a move and a move back would still be
        // seen as a change. A merge that happened and was undone is not "the
        // repository is exactly as it was".
        const reflog = try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "reflog", "show", "--format=%H", "HEAD",
        });
        defer gpa.free(reflog);
        return std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}", .{ branch, head, status, reflog });
    }

    /// What the file at `path` holds in the project's own working tree.
    fn worktreeFile(self: *const Carried, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
        const full = try std.fs.path.join(gpa, &.{ self.project.root_path, path });
        defer gpa.free(full);
        return std.Io.Dir.cwd().readFileAlloc(testing.io, full, gpa, .limited(1 << 16));
    }
};

/// The ref an apply parks the work at. `src/run.zig`'s `applyRef` builds the
/// same shape out of the session id.
const apply_ref = "refs/chock/sess1";

/// The file the session writes in every test below.
const carried_file = "carried.txt";

/// Run one described apply through a table that allows it, so the test is
/// about what the act does and not about who answered.
fn applying(gpa: std.mem.Allocator, carried: *const Carried, apply: actions.WorkspaceApply) !actions.Attempt {
    var waits: usize = 0;
    return askTheTable(
        gpa,
        testing.io,
        table_allows_the_apply,
        .{ .env = &carried.project.env },
        testAsk(.{ .workspace_apply = apply }),
        &waits,
    );
}

test "a project that says nothing parks the work and moves no branch" {
    // **The default, proved against real git.** This is what every session did
    // before modes existed, and the whole feature is only safe if a project
    // that has never heard of it behaves exactly as it did.
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
    defer carried.deinit(gpa);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // `describing` with no `landing` at all: the field has a default, and the
    // default is what a caller that has not heard of modes gets.
    const apply = try actions.WorkspaceApply.describing(
        arena_state.allocator(),
        testing.io,
        .{ .env = &carried.project.env },
        .{
            .repository = carried.project.root_path,
            .scratch_object_store = carried.tree().object_store_source,
            .ref = apply_ref,
            .new_id = carried.commit,
        },
        null,
    );
    try testing.expect(apply.integration == .park);
    try testing.expectEqual(
        chock_broker.integrate.Reason.not_asked_for,
        apply.integration.park.why,
    );

    const before = try carried.snapshot(gpa);
    defer gpa.free(before);

    var attempt = try applying(gpa, &carried, apply);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expect(attempt.done.result.workspace_apply.integration == .park);

    // The work is at the ref, and the repository is otherwise untouched.
    const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
        "rev-parse", apply_ref,
    });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(carried.commit, at_ref);

    const after = try carried.snapshot(gpa);
    defer gpa.free(after);
    try testing.expectEqualStrings(before, after);
}

test "merge, rebase and squash each land the work on the branch the way they say" {
    // One project per mode, each with a branch that has really moved on, so a
    // merge is a merge and a rebase is a replay rather than a fast forward.
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    for ([_]Landing{ .merge, .rebase, .squash }) |landing| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
        defer carried.deinit(gpa);

        // The user has committed since the session started, to a different
        // file, so the two histories diverge and neither mode can be a plain
        // fast forward.
        try carried.commitOnMain(gpa, "user.txt", "the user wrote this\n");
        const before_main = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "refs/heads/main",
        });
        defer gpa.free(before_main);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const apply = try carried.describing(arena_state.allocator(), landing);

        // The plan says which branch moves and where to, before anybody is
        // asked, and the commit it moves to is one of the objects the person
        // reads in the list.
        try testing.expect(apply.integration == .move);
        const planned = apply.integration.move;
        try testing.expectEqualStrings("refs/heads/main", planned.branch);
        try testing.expectEqualStrings(before_main, planned.at);
        var listed = false;
        for (apply.objects) |id| {
            if (std.mem.eql(u8, id, planned.to)) listed = true;
        }
        try testing.expect(listed);

        var attempt = try applying(gpa, &carried, apply);
        try testing.expect(attempt == .done);
        defer attempt.done.result.deinit(gpa);

        const outcome = attempt.done.result.workspace_apply.integration;
        try testing.expect(outcome == .moved);
        try testing.expectEqual(landing, outcome.moved.landing);
        try testing.expectEqualStrings("refs/heads/main", outcome.moved.branch);
        try testing.expectEqualStrings(before_main, outcome.moved.from);

        // The branch really moved, and it moved to the commit the person was
        // told about.
        const after_main = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "refs/heads/main",
        });
        defer gpa.free(after_main);
        try testing.expectEqualStrings(planned.to, after_main);

        // **And the working tree is at it.** A branch that moved under a
        // working tree that did not is exactly the large reverse diff this
        // whole design exists to avoid.
        const status = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "status", "--porcelain",
        });
        defer gpa.free(status);
        try testing.expectEqualStrings("", status);

        const in_tree = try carried.worktreeFile(gpa, carried_file);
        defer gpa.free(in_tree);
        try testing.expectEqualStrings("the session wrote this\n", in_tree);
        const user_file = try carried.worktreeFile(gpa, "user.txt");
        defer gpa.free(user_file);
        try testing.expectEqualStrings("the user wrote this\n", user_file);

        // The shape each mode promises, read off the history itself.
        const parents = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-list", "--parents", "-n", "1", "HEAD",
        });
        defer gpa.free(parents);
        var fields = std.mem.tokenizeScalar(u8, parents, ' ');
        _ = fields.next();
        var parent_count: usize = 0;
        while (fields.next()) |_| parent_count += 1;
        switch (landing) {
            // A merge names both sides, so git can still see where the work
            // came from.
            .merge => try testing.expectEqual(@as(usize, 2), parent_count),
            // A rebase and a squash both leave a straight line.
            .rebase, .squash => try testing.expectEqual(@as(usize, 1), parent_count),
            .ref => unreachable,
        }

        // The work is at the ref as well, in every mode. That is the thing a
        // person can always fall back on.
        const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", apply_ref,
        });
        defer gpa.free(at_ref);
        try testing.expectEqualStrings(carried.commit, at_ref);
    }
}

test "a dirty working tree parks the work, and the repository is untouched" {
    // **The decision this pins: fall back to the ref, do not refuse the whole
    // apply.** Refusing would throw the session's work away, which is the one
    // thing an apply exists to stop. Parking is what the mode `ref` does, so
    // the fallback is a behaviour the project already has a `git merge` for.
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
    defer carried.deinit(gpa);

    // A tracked file the user has edited and not committed.
    const dirty = try std.fs.path.join(gpa, &.{ carried.project.root_path, "tracked.txt" });
    defer gpa.free(dirty);
    try writeFileAbsolute(testing.io, dirty, "the user is in the middle of something\n");

    const before = try carried.snapshot(gpa);
    defer gpa.free(before);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const apply = try carried.describing(arena_state.allocator(), .merge);

    // **Known before anybody is asked**, and the prompt says so. A person is
    // never asked to approve a merge that was already known not to happen.
    try testing.expect(apply.integration == .park);
    try testing.expectEqual(chock_broker.integrate.Reason.dirty_tree, apply.integration.park.why);
    try testing.expectEqual(Landing.merge, apply.integration.park.wanted);

    var attempt = try applying(gpa, &carried, apply);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expect(attempt.done.result.workspace_apply.integration == .park);

    // The work landed at the ref, which is the whole of what happened.
    const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
        "rev-parse", apply_ref,
    });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(carried.commit, at_ref);

    // And nothing else moved: not the branch, not `HEAD`, not the working
    // tree, and the user's uncommitted edit is still there.
    const after = try carried.snapshot(gpa);
    defer gpa.free(after);
    try testing.expectEqualStrings(before, after);

    const still = try carried.worktreeFile(gpa, "tracked.txt");
    defer gpa.free(still);
    try testing.expectEqualStrings("the user is in the middle of something\n", still);
}

test "an integration that would conflict leaves the repository exactly as it was" {
    // **The property the whole design exists for.** A merge that stopped on a
    // conflict would leave `MERGE_HEAD`, a half written index and a working
    // tree full of markers. Nothing here runs a merge in the project at all, so
    // there is nothing to abort and nothing to clean up.
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    for ([_]Landing{ .merge, .rebase, .squash }) |landing| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        // Both sides change the same file, in different ways.
        var carried = try Carried.init(gpa, tmp, "tracked.txt", "the session's line\n");
        defer carried.deinit(gpa);
        try carried.commitOnMain(gpa, "tracked.txt", "the user's line\n");

        const before = try carried.snapshot(gpa);
        defer gpa.free(before);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const apply = try carried.describing(arena_state.allocator(), landing);
        try testing.expect(apply.integration == .park);
        try testing.expectEqual(
            chock_broker.integrate.Reason.would_conflict,
            apply.integration.park.why,
        );

        var attempt = try applying(gpa, &carried, apply);
        try testing.expect(attempt == .done);
        defer attempt.done.result.deinit(gpa);

        // The repository is exactly where it was: the same branch, the same
        // commit, the same working tree, and the same reflog.
        const after = try carried.snapshot(gpa);
        defer gpa.free(after);
        try testing.expectEqualStrings(before, after);

        // And no operation was left unfinished. Asked of git rather than of
        // `.git/`, because that is where a worktree keeps them.
        for ([_][]const u8{ "MERGE_HEAD", "CHERRY_PICK_HEAD", "rebase-merge", "rebase-apply" }) |marker| {
            const path = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
                "rev-parse", "--path-format=absolute", "--git-path", marker,
            });
            defer gpa.free(path);
            try testing.expectError(
                error.FileNotFound,
                std.Io.Dir.accessAbsolute(testing.io, path, .{}),
            );
        }

        // The work is still safe at the ref, which is what a person falls back
        // to.
        const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", apply_ref,
        });
        defer gpa.free(at_ref);
        try testing.expectEqualStrings(carried.commit, at_ref);
    }
}

test "a detached head and an unfinished merge each park the work" {
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
        defer carried.deinit(gpa);

        gpa.free(try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "checkout", "--quiet", "--detach", "HEAD",
        }));

        const apply = try carried.describing(arena_state.allocator(), .merge);
        try testing.expectEqual(
            chock_broker.integrate.Reason.detached_head,
            apply.integration.park.why,
        );
    }

    {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
        defer carried.deinit(gpa);

        // A `MERGE_HEAD` where git puts it for this repository, which is what
        // a real unfinished merge leaves behind.
        const path = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD",
        });
        defer gpa.free(path);
        try writeFileAbsolute(testing.io, path, "0000000000000000000000000000000000000000\n");

        const apply = try carried.describing(arena_state.allocator(), .rebase);
        try testing.expectEqual(
            chock_broker.integrate.Reason.unfinished_operation,
            apply.integration.park.why,
        );
    }
}

test "the question a person is asked is different in every mode and names the mode" {
    // **The property the modes are only safe with.** The same "y" at the same
    // prompt now does four different things, so the prompt has to say which.
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
    defer carried.deinit(gpa);
    try carried.commitOnMain(gpa, "user.txt", "the user wrote this\n");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var seen: [4][]u8 = undefined;
    var seen_detail: [4][]u8 = undefined;
    for (std.enums.values(Landing), 0..) |landing, index| {
        const apply = try carried.describing(arena_state.allocator(), landing);
        const action = actions.Action{ .workspace_apply = apply };
        seen[index] = try action.summary(gpa);
        seen_detail[index] = try action.detail(gpa);

        // Every prompt says what happens to the branch, in words, in both the
        // one line and the whole of it.
        try testing.expect(std.mem.indexOf(u8, seen_detail[index], "your branch") != null);
        if (landing == .ref) {
            try testing.expect(std.mem.indexOf(u8, seen_detail[index], "no branch of yours moves") != null);
        } else {
            // The mode is named, and so is the branch it moves.
            try testing.expect(std.mem.indexOf(u8, seen[index], landing.wireName()) != null);
            try testing.expect(std.mem.indexOf(u8, seen[index], "refs/heads/main") != null);
            try testing.expect(std.mem.indexOf(u8, seen_detail[index], "moves it") != null);
        }
    }
    defer for (seen) |one| gpa.free(one);
    defer for (seen_detail) |one| gpa.free(one);

    // **No two of the four read the same.** A prompt that looked identical in
    // two modes that do different things is the exact failure these modes have
    // to not be.
    for (seen, 0..) |one, i| {
        for (seen[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
    for (seen_detail, 0..) |one, i| {
        for (seen_detail[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
}

test "the agent cannot name the mode, and the ask it sends carries no way to" {
    // **Two ends of one rule.** The mode comes from `chock.zon` and from the
    // `workspace.integrate` row above it, both read on the host. An `Ask` is the
    // whole of what an agent sends, and there is no member of one that a mode
    // could arrive in.
    inline for (@typeInfo(actions.Ask).@"struct".fields) |field| {
        inline for (.{ "mode", "landing", "integration", "branch" }) |name| {
            try testing.expect(!std.ascii.eqlIgnoreCase(field.name, name));
        }
    }
    // The one thing an agent does say about an apply is a reason, which is an
    // argument and not an answer.
    const ask = testAsk(.{ .net_fetch = .{ .host = "h.invalid", .url = "https://h.invalid/" } });
    try testing.expectEqualStrings("the task asked for it", ask.reason);
}
