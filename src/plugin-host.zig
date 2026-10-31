//! The runtime entered by one forked, sandboxed plugin process.

const std = @import("std");

const chock_core = @import("chock-core");
const palisade = @import("palisade");
const wasm = @import("vulcan-wasm");

const plugin_engine = chock_core.plugin_engine;
const plugin_module = chock_core.plugin_module;

const Vulcan = struct {
    gpa: std.mem.Allocator,
    instance: ?wasm.Instance = null,

    fn engine(self: *Vulcan) plugin_engine.Engine {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = plugin_engine.Engine.VTable{
        .instantiate = instantiateFn,
        .memory = memoryFn,
        .call0 = call0Fn,
        .call3 = call3Fn,
    };

    fn instantiateFn(
        ptr: *anyopaque,
        module: []const u8,
        addresses: []const usize,
    ) anyerror!void {
        const self: *Vulcan = @ptrCast(@alignCast(ptr));
        self.instance = try wasm.Instance.instantiate(self.gpa, module, addresses);
    }

    fn memoryFn(ptr: *anyopaque) []u8 {
        const self: *Vulcan = @ptrCast(@alignCast(ptr));
        if (self.instance) |*live| return live.memory;
        return &.{};
    }

    fn call0Fn(ptr: *anyopaque, name: []const u8) anyerror!u32 {
        const self: *Vulcan = @ptrCast(@alignCast(ptr));
        var live = &(self.instance orelse return error.NotInstantiated);
        return live.call0(u32, name);
    }

    fn call3Fn(ptr: *anyopaque, name: []const u8, a0: u32, a1: u32, a2: u32) anyerror!u32 {
        const self: *Vulcan = @ptrCast(@alignCast(ptr));
        var live = &(self.instance orelse return error.NotInstantiated);
        return live.call3(u32, u32, u32, u32, name, a0, a1, a2);
    }

    fn deinit(self: *Vulcan) void {
        if (self.instance) |*live| live.deinit();
        self.instance = null;
    }
};

pub const Process = struct {
    module: []const u8,
    capabilities: []const []const u8,

    pub fn entry(self: *Process) palisade.Sandbox.Entry {
        return .{ .ptr = self, .run = runFn };
    }

    fn runFn(ptr: *anyopaque) u8 {
        const self: *Process = @ptrCast(@alignCast(ptr));
        return run(self.module, self.capabilities) catch 1;
    }
};

/// Runs after fork in the already-confined child. It deliberately uses the
/// single-threaded I/O implementation: no thread from the parent survives a
/// fork, and the plugin wire only needs blocking stdin and stdout.
pub fn run(module_bytes: []const u8, capabilities: []const []const u8) anyerror!u8 {
    const gpa = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var io_impl: std.Io.Threaded = .init_single_threaded;
    const io = io_impl.io();

    var engine_state: Vulcan = .{ .gpa = gpa };
    defer engine_state.deinit();

    var runner: plugin_engine.Runner = .{ .engine = engine_state.engine() };

    var module: ?plugin_module.Module = null;
    defer if (module) |one| one.deinit();

    const load_failure = load(gpa, arena, module_bytes, capabilities, &runner, &module) catch |err|
        try std.fmt.allocPrint(arena, "the plugin would not load: {t}", .{err});

    const input: std.Io.File = .{
        .handle = std.posix.STDIN_FILENO,
        .flags = .{ .nonblocking = false },
    };
    const output: std.Io.File = .{
        .handle = std.posix.STDOUT_FILENO,
        .flags = .{ .nonblocking = false },
    };

    try chock_core.plugin_host.serve(
        gpa,
        io,
        input,
        output,
        if (load_failure == null) &runner else null,
        load_failure,
    );
    return 0;
}

fn load(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    bytes: []const u8,
    capabilities: []const []const u8,
    runner: *plugin_engine.Runner,
    kept: *?plugin_module.Module,
) !?[]const u8 {
    var module_refusal: ?plugin_module.Refusal = null;
    const read = plugin_module.read(gpa, bytes, &module_refusal) catch {
        if (module_refusal) |detail| {
            return try std.fmt.allocPrint(arena, "{f}", .{detail});
        }
        return try arena.dupe(u8, "the plugin's module could not be read");
    };
    kept.* = read;

    const wanted = plugin_module.readImports(gpa, bytes, null) catch
        return try arena.dupe(u8, "the plugin's imports could not be read");
    defer gpa.free(wanted);

    const gated = try arena.alloc(plugin_engine.Import, wanted.len);
    for (gated, wanted) |*slot, one| slot.* = .{ .module = one.module, .field = one.field };

    var refused: ?plugin_engine.Refused = null;
    runner.load(
        gpa,
        bytes,
        kept.*.?.record().tools,
        gated,
        capabilities,
        &refused,
    ) catch |err| {
        if (refused) |detail| return try std.fmt.allocPrint(arena, "{f}", .{detail});
        if (runner.refusal) |detail| {
            return try std.fmt.allocPrint(arena, "the plugin would not start: {f}", .{detail});
        }
        return try std.fmt.allocPrint(arena, "the plugin would not start: {t}", .{err});
    };
    return null;
}
