//! The broker's own rule on a running system. An approval grants one act by
//! the broker and never a capability to the agent, so every test spawns a real
//! sandbox afterwards and watches it still refuse what the broker just did.

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

/// Named by `test/workspace/escape_probe.zig`, which owns the flow.
const agent_file = "chock-object-store-test.txt";

/// `chock_proto.storage.Locked` is not `pub`. This reaches the same type
/// through the return type of `Storage.lock`, which is.
const LockedHandle = @typeInfo(
    @typeInfo(@TypeOf(chock_proto.storage.Storage.lock)).@"fn".return_type.?,
).error_union.payload;

// The sandbox work goes through `escape_probe`, because `Sandbox.spawn` forks and
// the zig test runner is not a single threaded caller. `support.TestProject` sets
// `GIT_CEILING_DIRECTORIES`, because `tmpDir` sits under Chock's own checkout.
const support = @import("support.zig");

const absoluteDirPath = support.absoluteDirPath;
const writeFileAbsolute = support.writeFileAbsolute;
const gitOk = support.gitOk;
const TestProject = support.TestProject;
const findGitOnPath = support.findGitOnPath;
const runProbe = support.runProbe;

const ask_every_action: [:0]const u8 =
    \\.{
    \\    .policy = .{
    \\        .rules = .{
    \\            .{ .decision = .ask },
    \\        },
    \\    },
    \\}
;

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

/// It stops serving with its listening socket open, so the address stays live.
const one_reply_head = "HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\n";
const one_reply_body = "the broker read this\n";

/// `actions.perform` refuses the loopback interface before it opens anything, so a
/// test that wants a real request out fakes the lookup. Nothing else is faked.
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

    try testing.expect(std.mem.startsWith(u8, server.captured.head, "GET /spec.txt "));
}

test "the broker runs the action, and the agent never holds the capability" {
    const gpa = testing.allocator;
    const io = testing.io;

    const git_path = (try findGitOnPath(gpa, io)) orelse {
        // A test that writes to standard error and passes still puts a `failed command:` line in the build log.
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

    // Content never committed before, so git cannot skip writing the object.
    var agent_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const agent_path = try std.fmt.bufPrintZ(&agent_path_buffer, "{s}/{s}", .{ wt.path, agent_file });
    try writeFileAbsolute(io, agent_path, "the agent wrote this inside the sandbox\n");

    var work_root_tmp = testing.tmpDir(.{});
    defer work_root_tmp.cleanup();
    const commit_term = try runProbe(gpa, &workspace, work_root_tmp, "git-commit", git_path);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, commit_term);

    var session_env = try project.env.clone(gpa);
    defer session_env.deinit();
    try session_env.put("GIT_OBJECT_DIRECTORY", wt.object_store_source);
    const real_objects = try std.fs.path.join(gpa, &.{ wt.git_dir, "objects" });
    defer gpa.free(real_objects);
    try session_env.put("GIT_ALTERNATE_OBJECT_DIRECTORIES", real_objects);
    // The sandbox writes the session's own copy of the worktree metadata
    // directory, so the session's own HEAD is there and not in the project's.
    try session_env.put("GIT_DIR", wt.worktree_meta_bind_source);

    const agent_commit = try gitOk(gpa, &session_env, wt.path, &.{ "rev-parse", "HEAD" });
    defer gpa.free(agent_commit);

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
        .wanted = .{ .none = .nobody_answered },
    }, null);
    try testing.expect(apply.objects.len >= 3);

    var applied = try askAndAnswer(gpa, io, .approved_by_user, ctx, testAsk(.{ .workspace_apply = apply }));
    try testing.expect(applied == .done);
    defer applied.done.result.deinit(gpa);

    const project_head = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(project_head);
    try testing.expectEqualStrings(agent_commit, project_head);
    const landed = try gitOk(gpa, &project.env, project.root_path, &.{
        "show", "refs/heads/main:" ++ agent_file,
    });
    defer gpa.free(landed);
    try testing.expectEqualStrings("the agent wrote this inside the sandbox", landed);

    // The server keeps its socket open, so the address is live for the sandbox below.
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

    {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port);
        var stream = try address.connect(io, .{ .mode = .stream });
        stream.close(io);
    }

    var after_root_tmp = testing.tmpDir(.{});
    defer after_root_tmp.cleanup();

    // Exit 1 is the probe's code for ENETUNREACH. A connection made exits 0, and a
    // refusal by the far end exits 5, which would mean the packet left the sandbox.
    var address_buffer: [32]u8 = undefined;
    const address = try std.fmt.bufPrint(&address_buffer, "127.0.0.1:{d}", .{server.port});
    const connect_term = try runProbe(gpa, &workspace, after_root_tmp, "connect", address);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, connect_term);

    // Exit 1 is the probe's own code for EROFS, from the read only bind mount.
    const object_store_target = try std.fs.path.join(gpa, &.{ wt.sandbox_git_root, "objects", "chock-after-approval" });
    defer gpa.free(object_store_target);
    const write_term = try runProbe(gpa, &workspace, after_root_tmp, "write", object_store_target);
    try testing.expectEqual(std.process.Child.Term{ .exited = 1 }, write_term);

    // The sandbox is not a deny all: a write in the worktree still works.
    const inside_worktree = try std.fs.path.join(gpa, &.{ wt.project_root, "chock-after-approval.txt" });
    defer gpa.free(inside_worktree);
    const allowed_term = try runProbe(gpa, &workspace, after_root_tmp, "write", inside_worktree);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, allowed_term);

    const head_at_the_end = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", "refs/heads/main" });
    defer gpa.free(head_at_the_end);
    try testing.expectEqualStrings(agent_commit, head_at_the_end);
}

/// `request_action` is the tool an agent calls and also the name `chock run`
/// carries when it asks at the end of a run: see `actions.self_asked_tool`.
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

// One string, or a project writes a rule for a key nothing ever builds.
test "the tool an agent calls for an apply is the tool name the policy key carries" {
    try testing.expectEqualStrings("request_action", actions.self_asked_tool);
    try testing.expectEqualStrings(actions.self_asked_tool, testAsk(.{ .net_fetch = .{
        .host = "example.invalid",
        .url = "https://example.invalid/",
    } }).tool);
}

/// A waiter with zero waits is proof that nobody was asked.
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

    var waiter = TestWaiter{
        .gpa = gpa,
        .store = store,
        .locked = &locked,
        .decision = .refused_by_user,
        .now_ms = 1_700_000_000_000,
    };
    // Answering is what `waits == 1` triggers, so this stops it answering at all.
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

    // This environment puts every object git writes into the scratch store.
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

    var not_yet = try git.run(gpa, io, &project.env, project.root_path, &.{
        "cat-file", "-e", agent_commit,
    }, null);
    defer not_yet.deinit(gpa);
    try testing.expect(not_yet.term != .exited or not_yet.term.exited != 0);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ctx = actions.Context{ .env = &project.env };
    // `src/run.zig`'s `applyRef` builds the same name for both callers.
    const ref = "refs/chock/sess1";

    {
        const apply = try actions.WorkspaceApply.describing(arena, io, ctx, .{
            .repository = project.root_path,
            .scratch_object_store = wt.object_store_source,
            .ref = ref,
            .new_id = agent_commit,
            // No landing: this test is about what an agent gains by asking.
            .wanted = .{ .none = .nobody_answered },
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
            // No landing: this test is about what an agent gains by asking.
            .wanted = .{ .none = .nobody_answered },
        }, null);
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

    const at_ref = try gitOk(gpa, &project.env, project.root_path, &.{ "rev-parse", ref });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(agent_commit, at_ref);

    var head_after = try git.run(gpa, io, &project.env, project.root_path, &.{
        "rev-parse", "--verify", "refs/heads/main",
    }, null);
    defer head_after.deinit(gpa);
    if (head_after.term == .exited and head_after.term.exited == 0) {
        try testing.expect(!std.mem.eql(u8, agent_commit, std.mem.trimEnd(u8, head_after.stdout, "\n")));
    }
}

test "an approved net.fetch whose host answers this machine reads nothing" {
    // No fake resolver here. The context is left on `actions.Resolver.system`, so
    // `127.0.0.1` answers `127.0.0.1`, the same as it would in a real run.
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

    // A connection that says nothing releases the server and leaves `captured` empty.
    {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", server.port);
        var stream = try address.connect(io, .{ .mode = .stream });
        stream.close(io);
    }
    server.join();

    try testing.expectEqual(@as(usize, 0), server.captured.head.len);
}

// How an approved apply lands, every mode of it against real git.

const Landing = chock_policy.apply.Landing;

const Carried = struct {
    project: TestProject,
    workspace: Workspace,
    session_env: std.process.Environ.Map,
    commit: []u8,

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

        // Every object git writes goes into the scratch store.
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

    fn describing(
        self: *const Carried,
        arena: std.mem.Allocator,
        wanted: chock_broker.integrate.Wanted,
    ) !actions.WorkspaceApply {
        return actions.WorkspaceApply.describing(arena, testing.io, .{ .env = &self.project.env }, .{
            .repository = self.project.root_path,
            .scratch_object_store = self.tree().object_store_source,
            .ref = apply_ref,
            .new_id = self.commit,
            .wanted = wanted,
        }, null);
    }

    /// The branch, `HEAD`, and the working tree. The caller frees it.
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
        // The reflog of the branch, so a move and a move back is still a change.
        const reflog = try gitOk(gpa, &self.project.env, self.project.root_path, &.{
            "reflog", "show", "--format=%H", "HEAD",
        });
        defer gpa.free(reflog);
        return std.fmt.allocPrint(gpa, "{s}\n{s}\n{s}\n{s}", .{ branch, head, status, reflog });
    }

    fn worktreeFile(self: *const Carried, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
        const full = try std.fs.path.join(gpa, &.{ self.project.root_path, path });
        defer gpa.free(full);
        return std.Io.Dir.cwd().readFileAlloc(testing.io, full, gpa, .limited(1 << 16));
    }
};

/// `src/run.zig`'s `applyRef` builds the same shape out of the session id.
const apply_ref = "refs/chock/sess1";

const carried_file = "carried.txt";

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

test "a project that says nothing merges the work onto its branch, and says so before it is asked" {
    // No mode is written here. The landing comes from `chock_policy.apply.Settings{}`,
    // so this fails if the default ever stops naming a landing at all.
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

    const settings = chock_policy.apply.Settings{};
    try testing.expectEqual(
        @as(?chock_policy.apply.Mode, settings.mode),
        chock_policy.apply.boundBy(settings.mode, .allow),
    );
    const landing = settings.mode.settled() orelse return error.TheDefaultAsksAQuestion;

    const apply = try carried.describing(arena_state.allocator(), .{ .land = landing });
    try testing.expect(apply.integration == .move);
    try testing.expectEqualStrings("refs/heads/main", apply.integration.move.branch);

    const said = try (actions.Action{ .workspace_apply = apply }).summary(gpa);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "merge it into refs/heads/main") != null);

    var attempt = try applying(gpa, &carried, apply);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    const outcome = attempt.done.result.workspace_apply.integration;
    try testing.expect(outcome == .moved);
    try testing.expectEqualStrings("refs/heads/main", outcome.moved.branch);

    const parents = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
        "rev-list", "--parents", "-n", "1", "HEAD",
    });
    defer gpa.free(parents);
    var fields = std.mem.tokenizeScalar(u8, parents, ' ');
    _ = fields.next();
    var parent_count: usize = 0;
    while (fields.next()) |_| parent_count += 1;
    try testing.expectEqual(@as(usize, 2), parent_count);

    const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
        "rev-parse", apply_ref,
    });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(carried.commit, at_ref);
}

test "a policy that refuses the row parks the work, and the repository is untouched" {
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

    const bounded = chock_policy.apply.boundBy((chock_policy.apply.Settings{}).mode, .deny);
    try testing.expectEqual(@as(?chock_policy.apply.Mode, null), bounded);

    const apply = try carried.describing(arena_state.allocator(), .{ .none = .policy_refused });
    try testing.expect(apply.integration == .park);
    try testing.expectEqual(
        chock_broker.integrate.Reason.policy_refused,
        apply.integration.park.why,
    );
    try testing.expectEqual(@as(?Landing, null), apply.integration.park.wanted);

    const said = try (actions.Action{ .workspace_apply = apply }).summary(gpa);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "No branch of yours moves") != null);
    try testing.expect(std.mem.indexOf(u8, said, "workspace.integrate") != null);

    const before = try carried.snapshot(gpa);
    defer gpa.free(before);

    var attempt = try applying(gpa, &carried, apply);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expect(attempt.done.result.workspace_apply.integration == .park);

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
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    for ([_]Landing{ .merge, .rebase, .squash }) |landing| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
        defer carried.deinit(gpa);

        try carried.commitOnMain(gpa, "user.txt", "the user wrote this\n");
        const before_main = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "refs/heads/main",
        });
        defer gpa.free(before_main);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const apply = try carried.describing(arena_state.allocator(), .{ .land = landing });

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

        const after_main = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "refs/heads/main",
        });
        defer gpa.free(after_main);
        try testing.expectEqualStrings(planned.to, after_main);

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

        const parents = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-list", "--parents", "-n", "1", "HEAD",
        });
        defer gpa.free(parents);
        var fields = std.mem.tokenizeScalar(u8, parents, ' ');
        _ = fields.next();
        var parent_count: usize = 0;
        while (fields.next()) |_| parent_count += 1;
        switch (landing) {
            .merge => try testing.expectEqual(@as(usize, 2), parent_count),
            .rebase, .squash => try testing.expectEqual(@as(usize, 1), parent_count),
        }

        const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", apply_ref,
        });
        defer gpa.free(at_ref);
        try testing.expectEqualStrings(carried.commit, at_ref);
    }
}

test "a dirty working tree parks the work, and the repository is untouched" {
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var carried = try Carried.init(gpa, tmp, carried_file, "the session wrote this\n");
    defer carried.deinit(gpa);

    const dirty = try std.fs.path.join(gpa, &.{ carried.project.root_path, "tracked.txt" });
    defer gpa.free(dirty);
    try writeFileAbsolute(testing.io, dirty, "the user is in the middle of something\n");

    const before = try carried.snapshot(gpa);
    defer gpa.free(before);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const apply = try carried.describing(arena_state.allocator(), .{ .land = .merge });

    try testing.expect(apply.integration == .park);
    try testing.expectEqual(chock_broker.integrate.Reason.dirty_tree, apply.integration.park.why);
    try testing.expectEqual(@as(?Landing, .merge), apply.integration.park.wanted);

    var attempt = try applying(gpa, &carried, apply);
    try testing.expect(attempt == .done);
    defer attempt.done.result.deinit(gpa);
    try testing.expect(attempt.done.result.workspace_apply.integration == .park);

    const at_ref = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
        "rev-parse", apply_ref,
    });
    defer gpa.free(at_ref);
    try testing.expectEqualStrings(carried.commit, at_ref);

    const after = try carried.snapshot(gpa);
    defer gpa.free(after);
    try testing.expectEqualStrings(before, after);

    const still = try carried.worktreeFile(gpa, "tracked.txt");
    defer gpa.free(still);
    try testing.expectEqualStrings("the user is in the middle of something\n", still);
}

test "an integration that would conflict leaves the repository exactly as it was" {
    const gpa = testing.allocator;
    const git_path = (try findGitOnPath(gpa, testing.io)) orelse return error.SkipZigTest;
    defer gpa.free(git_path);

    for ([_]Landing{ .merge, .rebase, .squash }) |landing| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var carried = try Carried.init(gpa, tmp, "tracked.txt", "the session's line\n");
        defer carried.deinit(gpa);
        try carried.commitOnMain(gpa, "tracked.txt", "the user's line\n");

        const before = try carried.snapshot(gpa);
        defer gpa.free(before);

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const apply = try carried.describing(arena_state.allocator(), .{ .land = landing });
        try testing.expect(apply.integration == .park);
        try testing.expectEqual(
            chock_broker.integrate.Reason.would_conflict,
            apply.integration.park.why,
        );

        var attempt = try applying(gpa, &carried, apply);
        try testing.expect(attempt == .done);
        defer attempt.done.result.deinit(gpa);

        const after = try carried.snapshot(gpa);
        defer gpa.free(after);
        try testing.expectEqualStrings(before, after);

        // Asked of git rather than of `.git/`, because that is where a worktree keeps them.
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

        const apply = try carried.describing(arena_state.allocator(), .{ .land = .merge });
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

        // A `MERGE_HEAD` where git puts it for this repository.
        const path = try gitOk(gpa, &carried.project.env, carried.project.root_path, &.{
            "rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD",
        });
        defer gpa.free(path);
        try writeFileAbsolute(testing.io, path, "0000000000000000000000000000000000000000\n");

        const apply = try carried.describing(arena_state.allocator(), .{ .land = .rebase });
        try testing.expectEqual(
            chock_broker.integrate.Reason.unfinished_operation,
            apply.integration.park.why,
        );
    }
}

test "the question a person is asked is different in every mode and names the mode" {
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

    const wanted = [_]chock_broker.integrate.Wanted{
        .{ .land = .merge },
        .{ .land = .rebase },
        .{ .land = .squash },
        .{ .none = .policy_refused },
    };
    var seen: [wanted.len][]u8 = undefined;
    var seen_detail: [wanted.len][]u8 = undefined;
    for (wanted, 0..) |one, index| {
        const apply = try carried.describing(arena_state.allocator(), one);
        const action = actions.Action{ .workspace_apply = apply };
        seen[index] = try action.summary(gpa);
        seen_detail[index] = try action.detail(gpa);

        try testing.expect(std.mem.indexOf(u8, seen_detail[index], "your branch") != null);
        if (one.landing()) |landing| {
            try testing.expect(std.mem.indexOf(u8, seen[index], landing.wireName()) != null);
            try testing.expect(std.mem.indexOf(u8, seen[index], "refs/heads/main") != null);
            try testing.expect(std.mem.indexOf(u8, seen_detail[index], "moves it") != null);
        } else {
            try testing.expect(
                std.mem.indexOf(u8, seen[index], "No branch of yours moves") != null,
            );
            try testing.expect(
                std.mem.indexOf(u8, seen_detail[index], "no branch of yours moves") != null,
            );
            try testing.expect(std.mem.indexOf(u8, seen[index], "workspace.integrate") != null);
        }
    }
    defer for (seen) |one| gpa.free(one);
    defer for (seen_detail) |one| gpa.free(one);

    for (seen, 0..) |one, i| {
        for (seen[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
    for (seen_detail, 0..) |one, i| {
        for (seen_detail[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, one, other));
    }
}

test "the agent cannot name the mode, and the ask it sends carries no way to" {
    inline for (@typeInfo(actions.Ask).@"struct".fields) |field| {
        inline for (.{ "mode", "landing", "integration", "branch" }) |name| {
            try testing.expect(!std.ascii.eqlIgnoreCase(field.name, name));
        }
    }
    const ask = testAsk(.{ .net_fetch = .{ .host = "h.invalid", .url = "https://h.invalid/" } });
    try testing.expectEqualStrings("the task asked for it", ask.reason);
}
