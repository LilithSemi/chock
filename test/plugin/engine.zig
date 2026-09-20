//! The acceptance test for running a plugin: the real host process, the real
//! module, the real engine, over a real pipe. It is the one place guest code
//! really runs.
//!
//! Most tests here spawn the host as an ordinary child and build a
//! `helper.Channel` over its pipes, so they prove the framing, the call ABI and
//! the engine but no sandbox. One test starts it through `helper.Helper` and a
//! real `Sandbox.spawn`, and skips where there is no sandbox.
//!
//! Nothing here asserts how long anything took. The test about a plugin that
//! does not answer stages a deadline that has already passed.

const std = @import("std");
const builtin = @import("builtin");

const chock_core = @import("chock-core");
const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const core = @import("chock-plugin-core");
const paths = @import("engine_paths");
const sandbox = @import("chock-sandbox");

const helper = chock_core.helper;
const plugin = chock_core.plugin;
const plugin_host = chock_core.plugin_host;
const plugin_module = chock_core.plugin_module;

const testing = std.testing;

fn callOf(name: []const u8) chock_core.tools.ToolCall {
    return .{ .call_id = "call1", .tool = name, .arguments = "{}" };
}

const PermitAll = struct {
    var anchor: u8 = 0;

    fn arbiter() chock_core.arbiter.Arbiter {
        return .{ .ptr = &anchor, .vtable = &vtable };
    }

    const vtable = chock_core.arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *chock_core.arbiter.Locked,
        ask: chock_core.arbiter.Ask,
    ) chock_core.arbiter.Answer {
        _ = ptr;
        _ = gpa;
        _ = io;
        _ = locked;
        _ = ask;
        return .{ .permitted = true, .outcome = "allowed_by_policy" };
    }
};

const LockedLog = struct {
    backing: chock_proto.storage.Memory,
    store: chock_proto.storage.Storage = undefined,
    locked: chock_core.arbiter.Locked = undefined,

    fn init(gpa: std.mem.Allocator) !LockedLog {
        return .{ .backing = try chock_proto.storage.Memory.init(gpa, "01PLUGREAL") };
    }

    /// Separate from `init` because the handle points at the storage beside it,
    /// and a struct returned by value moves.
    fn arm(self: *LockedLog, io: std.Io) !void {
        self.store = self.backing.storage();
        self.locked = try self.store.lock(io);
    }

    fn deinit(self: *LockedLog, io: std.Io) void {
        self.locked.unlock(io) catch {};
        self.store.close(io);
    }
};

const wasm_path: []const u8 = paths.plugin_wasm_path;
/// `chock` itself, which is the one binary this project installs, started under
/// `plugin_host.verb`. There is no second program to find.
const host_path: []const u8 = paths.chock_path;

const Host = struct {
    child: std.process.Child,
    channel: helper.Channel,

    fn start(
        gpa: std.mem.Allocator,
        io: std.Io,
        module: []const u8,
        capabilities: []const []const u8,
    ) !Host {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, host_path);
        // Read from the one place it is written, so a spelling of its own here
        // could not pass against a word the program no longer answers to.
        try argv.append(gpa, plugin_host.verb);
        try argv.append(gpa, module);
        try argv.appendSlice(gpa, capabilities);

        const child = try std.process.spawn(io, .{
            .argv = argv.items,
            .stdin = .pipe,
            .stdout = .pipe,
            // A pipe nobody drains would wedge the host if it ever wrote there.
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

    /// Close the request pipe and wait, or every test leaks a process.
    fn stop(self: *Host, io: std.Io) void {
        // `Child.kill` already waited and gave every resource up, and
        // `Child.wait` asserts there is still a process to wait for.
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

fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 60 * std.time.ns_per_s);
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    return sayWhatItSaid(haystack, needle);
}

fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return;
    return sayWhatItSaid(haystack, needle);
}

/// A plugin host turns every failure into a result, so a wrong answer is one
/// sentence instead of another and a bare `expect` shows neither.
/// `expectEqualStrings` carries both strings out, and no test in this project
/// may write to standard error.
fn sayWhatItSaid(haystack: []const u8, needle: []const u8) !void {
    try testing.expectEqualStrings(needle, haystack);
    // Reached only when the two are equal, which `expectMissing` can be here
    // with. The caller already decided that is a failure.
    return error.TestUnexpectedResult;
}

test "a plugin tool call really runs guest code and answers what the guest said" {
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

test "a typed argument reaches the real guest as a value of the tool's own type" {
    // The guest body answers `args.who`, so the name below came through the
    // schema, the record and the struct field.
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
        1,
        "{\"who\":\"Ross\"}",
    );
    try testing.expectEqualStrings("Ross", outcome.text);
    try testing.expect(!outcome.is_error);

    const shouted = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        1,
        "{\"who\":\"Ross\",\"loudly\":true}",
    );
    try testing.expectEqualStrings("HELLO!", shouted.text);
}

test "the real plugin says what its tools take, read with no engine at all" {
    // The schema is in the same record as the tool's name.
    const gpa = testing.allocator;
    const io = testing.io;

    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        wasm_path,
        gpa,
        .limited(plugin_module.max_module_bytes),
    );
    defer gpa.free(bytes);

    var read = try plugin_module.read(gpa, bytes, null);
    defer read.deinit();

    const greet = read.record().tools[1];
    try testing.expectEqualStrings("greet", greet.name);
    try testing.expectEqual(@as(usize, 2), greet.parameters.len);
    try testing.expectEqualStrings("who", greet.parameters[0].name);
    try testing.expect(greet.parameters[0].required);
    try testing.expectEqual(core.Kind.string, greet.parameters[0].shape.kind);
    try testing.expect(!greet.parameters[1].required);
    try testing.expectEqual(core.Kind.boolean, greet.parameters[1].shape.kind);
}

test "the same process answers a second call, and is not restarted between them" {
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
    try testing.expectEqual(@as(i64, 2), protocol.last_id);
}

test "a tool index no guest bound is a result and never a crash" {
    // A host process that exited would read as a plugin that crashed.
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
    // The refusal must happen before instantiation. A guest that has started
    // running owns this process, so a check made afterwards is one it can
    // rewrite.
    const gpa = testing.allocator;
    const io = testing.io;

    const spliced = try withImport(gpa, "env", "read_file");
    defer gpa.free(spliced);

    // Still a plugin this reader accepts, or this tests a broken file and not
    // the gate.
    var read = try plugin_module.read(gpa, spliced, null);
    defer read.deinit();
    try testing.expectEqual(@as(usize, 2), read.record().tools.len);

    const path = try writeTemporary(gpa, spliced);
    defer gpa.free(path);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

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
    try expectContains(outcome.text, "read_file");
    try expectMissing(outcome.text, "Hello");
}

test "a file that is not a plugin is a sentence and not a crash" {
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
    // that dumps core is the ordinary case.
    const gpa = testing.allocator;
    const io = testing.io;

    var host = try Host.start(gpa, io, wasm_path, &.{});
    defer host.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = plugin_host.Protocol{ .gpa = gpa };
    defer protocol.deinit();

    _ = try protocol.call(
        arena_state.allocator(),
        io,
        &host.channel,
        generousDeadline(io),
        0,
        "{}",
    );

    host.child.kill(io);

    // The write may still succeed into a pipe the kernel has not torn down yet,
    // so the failure can land on either side. Both are `Gone` and never a wait.
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
    // A null from `dispatch` tells the caller to pass the call on unchanged.
    const gpa = testing.allocator;
    var session: plugin.Session = .init(gpa);
    defer session.deinit();

    try testing.expect(session.isEmpty());
    try testing.expectEqual(@as(usize, 0), session.plugins.len);
    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, testing.io, callOf("read_file")),
    );
    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, testing.io, callOf("hello")),
    );

    var offered: std.ArrayList(chock_core.tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try session.appendDefinitions(gpa, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

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

const host_target = "/chock";
const module_target = "/plugin.wasm";

test "a tool name reaches a real plugin host in a real sandbox, and the guest's own answer comes back" {
    // Every part is the production one except the runner wrapper, which is one
    // line of `src/run.zig` and is pinned by the tests there.
    if (builtin.target.os.tag != .linux) {
        // `Sandbox.spawn` refuses on Darwin, so there is no host process there.
        return error.SkipZigTest;
    }
    // Asked in a child, which is the only way to ask without spending this
    // process's one namespace.
    if (!sandbox.namespace.probeAvailability().available()) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const keep = arena_state.allocator();

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

    // `chock_sandbox.namespace` asserts a mount source is absolute, and the two
    // paths this test is built with are relative to where the build ran.
    const host_here = try std.Io.Dir.cwd().realPathFileAlloc(io, host_path, keep);
    const module_here = try std.Io.Dir.cwd().realPathFileAlloc(io, wasm_path, keep);

    const mounts = try keep.dupe(sandbox.namespace.Mount, &.{
        .{ .bind = .{ .source = "/nix/store", .target = "/nix/store", .read_only = true } },
        .{ .bind = .{ .source = host_here, .target = host_target, .read_only = true } },
        .{ .bind = .{ .source = module_here, .target = module_target, .read_only = true } },
    });

    const config = try plugin_host.lockdown(keep, .{
        .root = root.path(),
        .mounts = mounts,
        // A tool call's config carries the workspace writable. The lockdown must
        // drop it.
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
    // Three and not four: the writable rule above is gone.
    try testing.expectEqual(@as(usize, 3), config.rules.len);

    // The page allocator and never the test's own. The helper's thread is inside
    // `Sandbox.spawn` while this one allocates, and `fork` carries one thread.
    var process = helper.Helper.init(std.heap.page_allocator);
    defer process.deinit(io);

    var driver = plugin_host.Driver.init(gpa, &process, .{
        .config = config,
        .argv = &.{ host_target, plugin_host.verb, module_target },
    });
    defer driver.deinit();

    var loaded = [_]plugin.Loaded{.{ .name = "hello", .host = driver.host() }};
    session.plugins = &loaded;

    var log = try LockedLog.init(gpa);
    defer log.deinit(io);
    try log.arm(io);
    session.asker = .{ .arbiter = PermitAll.arbiter(), .locked = &log.locked };

    const outcome = (try session.dispatch(gpa, io, callOf("hello"))).?;
    defer gpa.free(outcome.text);

    try testing.expect(!outcome.is_error);
    try testing.expectEqualStrings("Hello, world!", outcome.text);

    try testing.expectEqual(
        @as(?plugin.Outcome, null),
        try session.dispatch(gpa, io, callOf("read_file")),
    );
}

/// A directory a sandbox is built inside. Removing it can only happen once the
/// process that pivoted into it has exited, which `helper.Helper.deinit` waits
/// for.
const SandboxRoot = struct {
    gpa: std.mem.Allocator,
    /// Sentinel terminated, because that is what `realPathFileAlloc` answers.
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

var roots_made: usize = 0;

fn sandboxRoot(gpa: std.mem.Allocator) !SandboxRoot {
    const directory = std.fs.path.dirname(wasm_path) orelse ".";
    var name: [64]u8 = undefined;
    // The process id, then a counter. Two runs of this binary at once would
    // otherwise remove the directory the other has a sandbox pivoted into.
    const leaf = try std.fmt.bufPrint(
        &name,
        "chock-plugin-root-{d}-{d}",
        .{ std.posix.system.getpid(), roots_made },
    );
    roots_made += 1;

    const relative = try std.fs.path.join(gpa, &.{ directory, leaf });
    defer gpa.free(relative);

    std.Io.Dir.cwd().deleteTree(testing.io, relative) catch {};
    try std.Io.Dir.cwd().createDir(testing.io, relative, .default_dir);

    const absolute = try std.Io.Dir.cwd().realPathFileAlloc(testing.io, relative, gpa);
    return .{ .gpa = gpa, .absolute = absolute };
}

/// The plugin this project ships, with one function import spliced in. An import
/// section goes after the type section, so it is inserted where that one ends. A
/// function import and not a global one, because a global shifts the global index
/// space that `plugin_module` resolves the metadata address through. The caller
/// frees the answer.
fn withImport(gpa: std.mem.Allocator, module: []const u8, field: []const u8) ![]u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        testing.io,
        wasm_path,
        gpa,
        .limited(plugin_module.max_module_bytes),
    );
    defer gpa.free(bytes);

    // Type index 0, which every module with a type section has.
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

var written: usize = 0;

fn writeTemporary(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    // Beside the build's own output. Not `/tmp`, which a sandboxed test run may
    // not have, and not the project tree.
    const directory = std.fs.path.dirname(wasm_path) orelse ".";
    var name: [64]u8 = undefined;
    // The process id, then a counter. Each run removes its file when the test
    // ends, so two builds at once would take the module out from under the other
    // run's host process.
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
    // Named so a change to the ABI both sides read cannot land without this file
    // being looked at.
    _ = core.call.Answer.len;
}
