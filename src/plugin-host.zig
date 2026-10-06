//! `chock __plugin-host`: what one plugin runs inside.

const std = @import("std");

const chock_core = @import("chock-core");
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

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
) anyerror!u8 {
    if (args.len < 1) {
        return 2;
    }
    const module_path = args[0];
    const capabilities = args[1..];

    var engine_state: Vulcan = .{ .gpa = gpa };
    defer engine_state.deinit();

    var runner: plugin_engine.Runner = .{ .engine = engine_state.engine() };

    var module: ?plugin_module.Module = null;
    defer if (module) |one| one.deinit();

    const load_failure = load(gpa, arena, io, module_path, capabilities, &runner, &module) catch |err|
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
    io: std.Io,
    module_path: []const u8,
    capabilities: []const []const u8,
    runner: *plugin_engine.Runner,
    kept: *?plugin_module.Module,
) !?[]const u8 {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        module_path,
        arena,
        .limited(plugin_module.max_module_bytes),
    ) catch return try std.fmt.allocPrint(
        arena,
        "the plugin's own file could not be read",
        .{},
    );

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
