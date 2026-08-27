//! The acceptance test for running a plugin: the real host process, the real
//! module, the real engine, over a real pipe.
//!
//! Every other test of this feature drives a peer written by the same hand.
//! `lib/chock-core/plugin_host.zig` tests the wire against a staged reply,
//! and `lib/chock-core/plugin_engine.zig` tests the gate against an engine
//! that runs nothing. A test against a stand in is worth only what the stand in
//! is worth, which is why this file exists: **it is the one place guest code
//! really runs.**
//!
//! ## Most tests here need no sandbox, and one needs the real one
//!
//! `chock_core.helper.Helper` starts the host process with a `Sandbox.spawn`,
//! which is Linux only. Most tests here spawn the same program as an ordinary
//! child and build a `helper.Channel` over its two pipes, which is exactly what
//! that type's own doc comment says it is for: the framing, the call ABI, the
//! bounded reads and the engine are then all the production ones, on Linux and
//! on Darwin alike.
//!
//! **One test starts the host process the way a session starts it**, through
//! `helper.Helper`, `plugin_host.lockdown` and a real `Sandbox.spawn`, and
//! reaches it through `plugin.Session.dispatch`, which is what `src/run.zig`'s
//! own `PluginToolRunner` wraps. It is the one that says the wiring works
//! rather than that the pieces do, and it skips where there is no sandbox: see
//! `a tool name reaches a real plugin host in a real sandbox`.
//!
//! ## No wall clock assertion
//!
//! Nothing here measures how long anything took. The deadlines are bounds, and
//! the one test about a plugin that does not answer stages a deadline that has
//! already passed rather than waiting for one.

const std = @import("std");
const builtin = @import("builtin");

const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const core = @import("chock-plugin-core");
const paths = @import("engine_paths");
const sandbox = @import("chock-sandbox");

const helper = chock_core.helper;
const plugin = chock_core.plugin;
const plugin_host = chock_core.plugin_host;
const plugin_module = chock_core.plugin_module;

const testing = std.testing;

/// The plugin the project ships, built for `wasm32-freestanding`.
const wasm_path: []const u8 = paths.plugin_wasm_path;
/// The program a plugin host process runs, which is `chock` itself, built for
/// this machine.
///
/// **The one binary this project installs**, started under
/// `plugin_host.verb`. There is no second program to find, which is what makes
/// a plugin survive an install that copies one file: see
/// `test/plugin/one_binary.zig` and `chock_core.plugin_host.verb`.
const host_path: []const u8 = paths.chock_path;

/// One running host process and the channel that reaches it.
///
/// **A `helper.Channel` over an ordinary child's pipes.** See this file's top
/// comment for why there is no sandbox here.
const Host = struct {
    child: std.process.Child,
    channel: helper.Channel,

    /// Start the host process on `module`, with `capabilities` on argv.
    fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        module: []const u8,
        capabilities: []const []const u8,
    ) !Host {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, host_path);
        // **The verb, read from the one place it is written.** `src/main.zig`
        // dispatches on this and `src/run.zig` builds the production argv with
        // it, so a spelling of its own here would let this test pass against a
        // word the program no longer answers to.
        try argv.append(gpa, plugin_host.verb);
        try argv.append(gpa, module);
        try argv.appendSlice(gpa, capabilities);

        const child = try std.process.spawn(io, .{
            .argv = argv.items,
            .stdin = .pipe,
            .stdout = .pipe,
            // The host process writes nothing to its own standard error, and a
            // pipe nobody drains would wedge it if it ever did. The same answer
            // `helper.Helper.start` gives, for the same reason.
            .stderr = .ignore,
        });

        return .{
            .child = child,
            .channel = .{
                .to_helper = child.stdin.?,
                .from_helper = child.stdout.?,
            },
        };
    }

    /// Close the request pipe, which is how the host process is told there is
    /// nothing more to answer, and then wait for it. **The wait is the point**:
    /// a test that left the process running would leak one per test.
    fn stop(self: *Host, io: std.Io) void {
        // A test that killed the process already has nothing left to do:
        // `Child.kill` waits and gives every resource up, and `Child.wait`
        // asserts there is still a process to wait for.
        if (self.child.id == null) return;
        if (self.child.stdin) |file| {
            std.Io.File.close(file, io);
            self.child.stdin = null;
        }
        _ = self.child.wait(io) catch {};
        if (self.child.stdout) |file| {
            std.Io.File.close(file, io);
            self.child.stdout = null;
        }
    }
};

/// A deadline far enough ahead that an exchange with a program on this machine
/// reaches it only if something is genuinely stuck. Nothing asserts how long
/// anything took; this is a bound, not a measurement.
fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 60 * std.time.ns_per_s);
}

/// `haystack` holds `needle`.
fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    return sayWhatItSaid(haystack, needle);
}

/// `haystack` holds no `needle`.
fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return;
    return sayWhatItSaid(haystack, needle);
}

/// Fail, and carry both the text that was looked for and the sentence the
/// plugin host really sent into what a person reads.
///
/// **The sentence is the evidence.** A plugin host turns every failure into a
/// result, so a wrong answer above is one sentence instead of another, and a
/// bare `expect` shows neither: this test failed once with nothing on record
/// about what it read, and finding out why took reproducing it.
///
/// `expectEqualStrings` is what carries two strings out, and it is used here
/// rather than a print because **no test in this project writes to standard
/// error**: see `test/proto/lock.zig`, which holds that rule and says what a
/// broken one costs in a build log.
fn sayWhatItSaid(haystack: []const u8, needle: []const u8) !void {
    try testing.expectEqualStrings(needle, haystack);
    // Reached only when the two are equal, which `expectMissing` can still be
    // here with: the host answered the text and nothing else. That is a
    // failure, and the caller already decided so.
    return error.TestUnexpectedResult;
}

test "a plugin tool call really runs guest code and answers what the guest said" {
    // **The acceptance test of this whole feature.** `plugins/hello.zig`
    // answers `ctx.successResult("Hello, world!")`, and nothing between the
    // author's file and this assertion is a stand-in: the module is the one
    // `build.zig` builds for `wasm32-freestanding`, the process is `chock`
    // itself, which is the one binary `build.zig` installs, the engine is
    // Vulcan, and the wire is the production one.
    //
    // Mutation check: change the text in `plugins/hello.zig` and this fails.
    // Change the answer record layout in `lib/chock-plugin-core/call.zig` on
    // one side only, and this fails while every unit test still passes.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("Hello, world!", outcome.text);
    try testing.expect(!outcome.is_error);
}

test "the same process answers a second call, and is not restarted between them" {
    // A plugin host outlives one tool call: that is the whole reason it is a
    // helper and not a process per call. A second call must reach the guest
    // that is already instantiated.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const first = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    const second = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{\"anything\":true}",
    );
    try testing.expectEqualStrings("Hello, world!", first.text);
    try testing.expectEqualStrings("Hello, world!", second.text);
    // Two ids went out and two came back in step, which is what says the
    // second answer is the second call's and not the first one read twice.
    try testing.expectEqual(@as(i64, 2), protocol.last_id);
}

test "a tool index no guest bound is a result and never a crash" {
    // The host reads the tool list out of the module's own file, so it knows
    // there is one tool. An index past that must come back as an ordinary
    // failed result: a host process that exited instead would be read by the
    // harness as a plugin that crashed, which says something worse.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        7,
        "{}",
    );
    try testing.expect(outcome.is_error);
    try testing.expect(outcome.text.len != 0);

    // And the process is still there: the next call works.
    const after = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expectEqualStrings("Hello, world!", after.text);
}

test "a module that imports anything is stopped before it runs, and named" {
    // **The capability gate, against a real module and the real engine.** The
    // module below is the plugin this project ships with one import spliced
    // into it, so it is a real Chock plugin in every other way: the metadata
    // reads, the tool list is right, and the policy would price it exactly as
    // before. It still must not run, because no capability it declares
    // supplies that import and this build has no host function at all.
    //
    // **The refusal happens before instantiation**, which is the one ordering
    // that matters: a guest that has started running owns this process, so a
    // check made afterwards would be a check a guest can rewrite. See
    // `chock_core.plugin_engine`'s own top comment.
    //
    // Mutation check: let `gate` pass an uncovered import through, and this
    // test gets an engine failure or an answer instead of a sentence naming
    // `read_file`.
    const gpa = testing.allocator;
    const io = testing.io;

    const spliced = try withImport(gpa, "env", "read_file");
    defer gpa.free(spliced);

    // The spliced module is still a plugin this reader accepts. If it were
    // not, this test would be measuring a broken file and not the gate.
    var read = try plugin_module.read(gpa, spliced, null);
    defer read.deinit();
    try testing.expectEqual(@as(usize, 1), read.record().tools.len);

    const path = try writeTemporary(gpa, spliced);
    defer gpa.free(path);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    // It declares `fs.read`, which is a capability the policy table really
    // answers about. It still supplies no import in this build.
    var host = try Host.start(gpa, io, path, &.{"fs.read"});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expect(outcome.is_error);
    // The message names the import, so a person reads which host function the
    // plugin was built against.
    try expectContains(outcome.text, "read_file");
    try expectMissing(outcome.text, "Hello");
}

test "a file that is not a plugin is a sentence and not a crash" {
    // A host process that exited would be read by the harness as a plugin that
    // crashed. It has to serve and say why instead, so the model reads one
    // clear fact rather than "the plugin stopped answering".
    const gpa = testing.allocator;
    const io = testing.io;

    const path = try writeTemporary(gpa, "#!/bin/sh\necho hello\n");
    defer gpa.free(path);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    var host = try Host.start(gpa, io, path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );
    try testing.expect(outcome.is_error);
    try expectContains(outcome.text, "WebAssembly");
}

test "a plugin that has gone answers the next call at once and never waits" {
    // A guest owns the address space of the process that runs it, so a plugin
    // that dumps core is the ordinary case. Killing the process is what that
    // looks like from here, and the harness must answer rather than wait.
    //
    // Mutation check: answer `Late` on end of file in `helper.Channel.read`
    // and the session waits out a budget for a reply nobody will send.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    // One call first, so the process is really up and really answering.
    _ = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );

    host.child.kill(io);

    // The write may still succeed into a pipe the kernel has not torn down
    // yet, so the failure lands on the read. Either way it is `Gone` and never
    // a wait.
    try testing.expectError(error.Gone, protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    ));
    try testing.expect(host.channel.poisoned);
}

test "the engine runs guest code on this platform" {
    // **This test used to be a guard on a skip, and the guard worked.** Four
    // tests here skipped on aarch64 macOS, because Vulcan's `syncICache` read
    // `CTR_EL0` with `mrs`, which Linux emulates for userspace and macOS traps.
    // The host process died before one byte of guest code ran.
    //
    // Rather than trust the sentence beside the skip, this test asserted the
    // fault was still there, so it would fail the day the fault went away.
    // **It fired on 2026-08-23**, when Vulcan learned to call
    // `sys_icache_invalidate` on Darwin instead, and the skips came out.
    //
    // What is left is the positive control at the protocol level: the whole
    // wire, one call, the guest's own answer.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );

    try testing.expectEqualStrings("Hello, world!", outcome.text);
}

test "a project with no plugin starts no process at all" {
    // The cheap path, which is every project today. A `plugin.Session` that
    // admitted nothing offers nothing, holds no host, and never reaches this
    // file's own machinery: `dispatch` answers null for every name, which is
    // the caller's signal to pass the call on unchanged.
    //
    // Mutation check: make `dispatch` answer a result for an unknown name and
    // every built-in tool stops working.
    const gpa = testing.allocator;
    var session: plugin.Session = .init(gpa);
    defer session.deinit();

    try testing.expect(session.isEmpty());
    try testing.expectEqual(@as(usize, 0), session.plugins.len);
    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, testing.io, "read_file", "{}"),
    );
    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, testing.io, "hello", "{}"),
    );

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try session.appendDefinitions(gpa, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

/// A policy that allows everything and records nothing. The rules a policy
/// table really applies are pinned in `lib/chock-core/plugin.zig` and in
/// `src/run.zig`; what this file is for is the half no table can stand in for.
const AllowEverything = struct {
    fn decider(self: *AllowEverything) plugin.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = plugin.Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        _ = ptr;
        _ = tool;
        _ = action;
        return .allow;
    }
};

/// Where the two files a plugin host reaches are bound inside its own sandbox.
/// **The same two paths `src/run.zig` binds**, and the argv below is the argv it
/// builds, so this test measures the production shape and not one of its own.
const host_target = "/chock";
const module_target = "/plugin.wasm";

test "a tool name reaches a real plugin host in a real sandbox, and the guest's own answer comes back" {
    // **The acceptance test of the wiring**, and the one test in this project
    // where every part of a plugin tool call is the production one at once: the
    // policy decision out of `plugin.Session.admit`, the lockdown out of
    // `plugin_host.lockdown`, a `Sandbox.spawn` through `helper.Helper`, the
    // real host process, the real engine, and `plugin.Session.dispatch`, which
    // is what `src/run.zig`'s own `PluginToolRunner` wraps.
    //
    // What is not here is the runner wrapper itself, which is one line of
    // `src/run.zig` and is pinned by the tests in that file.
    //
    // Mutation checks. Give `lockdown` no rule at all, which is what it used to
    // answer, and the host process cannot be executed: Landlock handles the
    // execute right for every path, so `execve` on the program itself is
    // refused and this test reads "its host did not answer". Drop the module
    // rule and the host process reads no module and answers a sentence instead
    // of the guest's words.
    if (builtin.target.os.tag != .linux) {
        // `Sandbox.spawn` refuses on Darwin, so there is no plugin host process
        // there at all. Everything above this line runs on both platforms, and
        // that is the same split `lib/chock-core/mcp.zig` records for a server.
        return error.SkipZigTest;
    }
    // **A boundary that was never reached is not a boundary that held.** This
    // test needs a real sandbox to put a real host process inside, and a
    // machine that will not give one measures nothing here. Asked in a child,
    // which is the only way to ask without spending this process's own one
    // namespace: see `namespace.probeAvailability`. The CI job named "Sandbox"
    // runs this suite on a machine that can host one and fails rather than
    // skips.
    if (!sandbox.namespace.probeAvailability().available()) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const keep = arena_state.allocator();

    // The module, read on the host with no engine anywhere near it, and
    // admitted exactly as `startPlugins` admits it.
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        wasm_path,
        keep,
        .limited(plugin_module.max_module_bytes),
    );

    var session: plugin.Session = .init(gpa);
    defer session.deinit();

    var allow: AllowEverything = .{};
    var failure: ?plugin.Failure = null;
    var read = try session.load(gpa, "hello", bytes, allow.decider(), null, &failure);
    read.deinit();
    try testing.expectEqual(@as(?plugin.Failure, null), failure);

    const offer = session.find("hello").?;
    try testing.expectEqual(@as(?plugin.Refusal, null), offer.refused);

    var root = try sandboxRoot(gpa);
    defer root.cleanup(io);

    // **Absolute, and resolved rather than assumed.** A mount source and a
    // sandbox root are absolute paths or they are nothing:
    // `chock_sandbox.namespace` asserts it. The two paths this test is built
    // with are the build's own, which are relative to where the build ran.
    const host_here = try std.Io.Dir.cwd().realPathFileAlloc(io, host_path, keep);
    const module_here = try std.Io.Dir.cwd().realPathFileAlloc(io, wasm_path, keep);

    // The mount tree: the two files this process reaches, and the store, which
    // is what a build that links its host program dynamically resolves through.
    // The same three `src/run.zig` names.
    const mounts = try keep.dupe(sandbox.namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = host_here, .target = host_target, .read_only = true } },
        .{ .bind = .{ .source = module_here, .target = module_target, .read_only = true } },
    });

    const config = try plugin_host.lockdown(keep, .{
        .root = root.path(),
        .mounts = mounts,
        // Dropped by the lockdown, and here to say so: a plugin host reaches
        // what the caller states and nothing the caller's own config carried.
        // A tool call's config carries the workspace, writable, and this is
        // that rule.
        .rules = &.{
            .{ .path = "/", .access = sandbox.landlock.AccessFs.read_write },
        },
        .cwd = "/",
        .env = &.{},
        .network = .host,
    }, &.{
        .{ .path = "/nix/store", .access = sandbox.landlock.AccessFs.read_only },
        .{ .path = host_target, .access = .{ .execute = true, .read_file = true } },
        .{ .path = module_target, .access = .{ .read_file = true } },
    });
    try testing.expect(config.network == .none);
    // Three, and not four: the writable rule above is gone.
    try testing.expectEqual(@as(usize, 3), config.rules.len);

    // **The page allocator, and never the test's own.** The helper's own thread
    // is inside `Sandbox.spawn` while this thread allocates, and `fork` carries
    // only the calling thread.
    var process = helper.Helper.init(std.heap.page_allocator);
    defer process.deinit(io);

    var driver = plugin_host.Driver.init(gpa, &process, .{
        .config = config,
        // The production argv: the one binary, the hidden verb, and then the
        // module. `src/run.zig` builds this shape and appends the capabilities
        // the module's own metadata declared.
        .argv = &.{ host_target, plugin_host.verb, module_target },
    });
    defer driver.deinit();

    var loaded = [_]plugin.Loaded{.{ .name = "hello", .host = driver.host() }};
    session.plugins = &loaded;

    const outcome = (try session.dispatch(gpa, io, "hello", "{}")).?;
    defer gpa.free(outcome.text);

    // **No skip here, and none is possible.** This test runs on Linux only,
    // because it needs a real sandbox, and the engine turns a module into code
    // it can run on both platforms now.
    try testing.expect(!outcome.is_error);
    try testing.expectEqualStrings("Hello, world!", outcome.text);

    // And a name no plugin declared is still not this session's business, which
    // is what makes the runner above pass every built-in call straight through.
    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, io, "read_file", "{}"),
    );
}

/// A directory a sandbox is built inside, on the host side of it.
///
/// **Beside the build's own output**, and not `/tmp`, for the reason
/// `writeTemporary` below gives. Removing it can only happen once the process
/// that pivoted into it has exited, which `helper.Helper.deinit` waits for.
const SandboxRoot = struct {
    gpa: std.mem.Allocator,
    /// Sentinel terminated, because that is what `realPathFileAlloc` answers
    /// and a free has to give back the same bytes the allocation took.
    absolute: [:0]const u8,

    fn path(self: *const SandboxRoot) []const u8 {
        return self.absolute;
    }

    fn cleanup(self: *SandboxRoot, io: std.Io) void {
        std.Io.Dir.cwd().deleteTree(io, self.absolute) catch {};
        self.gpa.free(self.absolute);
        self.* = undefined;
    }
};

/// How many sandbox roots this run has made, so two of them in one run never
/// collide. A counter and not a clock: one run makes these, one at a time.
var roots_made: usize = 0;

fn sandboxRoot(gpa: std.mem.Allocator) !SandboxRoot {
    const directory = std.fs.path.dirname(wasm_path) orelse ".";
    var name: [64]u8 = undefined;
    // **The process id, then a counter**, for the reason `writeTemporary`
    // gives: this directory is removed at the end of the test, and a second
    // run of this same binary used to remove the one the first run had a
    // sandbox pivoted into.
    const leaf = try std.fmt.bufPrint(
        &name,
        "chock-plugin-root-{d}-{d}",
        .{ std.posix.system.getpid(), roots_made },
    );
    roots_made += 1;

    const relative = try std.fs.path.join(gpa, &.{ directory, leaf });
    defer gpa.free(relative);

    // A root left behind by a run that was killed is the ordinary case, and a
    // name this run already owns is this run's to clear: the mount tree is
    // built inside it from nothing every time.
    std.Io.Dir.cwd().deleteTree(testing.io, relative) catch {};
    try std.Io.Dir.cwd().createDir(testing.io, relative, .default_dir);

    // Absolute, because a sandbox root is an absolute path or it is nothing.
    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(testing.io, relative, gpa);
    return .{ .gpa = gpa, .absolute = absolute };
}

/// The plugin this project ships, with one function import spliced in.
///
/// An import section goes after the type section and before the function
/// section, so it is inserted where the type section ends. **A function import
/// and not a global one**, because a global import shifts the global index
/// space and `chock_core.plugin_module` resolves the metadata's address
/// through it: the file would then stop being a plugin at all, and this test
/// would be measuring a broken module rather than the gate.
///
/// The caller frees the answer.
fn withImport(gpa: std.mem.Allocator, module: []const u8, field: []const u8) ![]u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        wasm_path,
        gpa,
        .limited(plugin_module.max_module_bytes),
    );
    defer gpa.free(bytes);

    // The body: one import, naming type index 0, which every module with a
    // type section has.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.append(gpa, 1); // one import
    try body.append(gpa, @intCast(module.len));
    try body.appendSlice(gpa, module);
    try body.append(gpa, @intCast(field.len));
    try body.appendSlice(gpa, field);
    try body.append(gpa, 0); // kind: a function
    try body.append(gpa, 0); // type index 0

    const at = try afterTypeSection(bytes);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, bytes[0..at]);
    try out.append(gpa, 2); // section id: imports
    try out.append(gpa, @intCast(body.items.len));
    try out.appendSlice(gpa, body.items);
    try out.appendSlice(gpa, bytes[at..]);
    return out.toOwnedSlice(gpa);
}

/// Where the type section of `bytes` ends, which is where an import section
/// belongs. Answers just past the header when there is no type section.
fn afterTypeSection(bytes: []const u8) !usize {
    var at: usize = 8;
    while (at < bytes.len) {
        const id = bytes[at];
        var cursor = at + 1;
        const size = try readUleb(bytes, &cursor);
        const end = cursor + size;
        if (end > bytes.len) return error.MalformedModule;
        if (id == 1) return end;
        at = end;
    }
    return 8;
}

fn readUleb(bytes: []const u8, at: *usize) !u32 {
    var result: u32 = 0;
    var shift: u5 = 0;
    while (true) {
        if (at.* >= bytes.len) return error.MalformedModule;
        const byte = bytes[at.*];
        at.* += 1;
        result |= @as(u32, byte & 0x7F) << shift;
        if (byte & 0x80 == 0) break;
        shift += 7;
    }
    return result;
}

/// How many files this run has written, so two of them in one run never
/// collide.
var written: usize = 0;

/// Write `bytes` to a file beside the build's own output and answer its path.
/// The caller frees the path and removes the file.
fn writeTemporary(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    // Beside the module this build already produced, which is a directory the
    // build is already writing to. **Not `/tmp`**, which a sandboxed test run
    // may not have, and not the project tree.
    const directory = std.fs.path.dirname(wasm_path) orelse ".";
    var name: [64]u8 = undefined;
    // **The process id, and then a counter.** The counter alone used to be the
    // whole name, on the reasoning that one test binary writes these one at a
    // time and that two runs write the same bytes anyway. The second half of
    // that is true and does not help: each run **removes** the file when its
    // test ends, so a second run of this same binary took the module out from
    // under the first run's host process, which then answered "the plugin's
    // own file could not be read" and the gate went untested. Two builds of
    // this project at once is all it takes, and it was measured at 27 failures
    // in 100 with four runs at a time. The pid is what tells two runs apart;
    // the counter still tells two files of one run apart.
    const leaf = try std.fmt.bufPrint(
        &name,
        "chock-plugin-probe-{d}-{d}.wasm",
        .{ std.posix.system.getpid(), written },
    );
    written += 1;
    const path = try std.fs.path.join(gpa, &.{ directory, leaf });
    errdefer gpa.free(path);

    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = bytes });
    return path;
}

comptime {
    // Named so a reader of this file finds the ABI both sides read, and so a
    // change to it cannot land without this file being looked at.
    _ = core.call.Answer.len;
}
