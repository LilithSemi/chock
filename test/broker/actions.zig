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
