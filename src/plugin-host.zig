//! `chock __plugin-host`: what one plugin runs inside.
//!
//! **The whole thing is an engine, a module and a call to
//! `chock_core.plugin_host.serve`.** Every rule lives in `chock-core`: the
//! capability gate is `chock_core.plugin_engine.gate`, the bounded reads of
//! guest memory are `chock_plugin_core.call.readAnswer`, and both sides of the
//! wire are in `lib/chock-core/plugin_host.zig`. Nothing is decided here.
//!
//! ## Why this is a process and not a function in the harness
//!
//! **A running guest owns the whole address space of the process that runs
//! it.** Measured on Vulcan 2026-08-22: `memPtr` is `mem_base + addr + offset`
//! with no bounds check, and `callIndirect` loads a table slot and calls it
//! with neither a bounds check nor a signature check. A module declaring
//! sixteen pages and storing to offset 100000000 dumped core.
//!
//! So this process holds nothing worth taking: no credential, no session log,
//! no policy table, and no descriptor except the two pipes the harness gave
//! it. It runs in the sandbox `chock_core.plugin_host.lockdown` built, which
//! has no network and no path rule at all. **A guest that takes this process
//! over gets a process that can talk to the harness and do nothing else.**
//!
//! ## A process of its own, out of one binary
//!
//! This was a second program, `chock-plugin-host`, installed beside `chock`
//! and found at run time by looking in `chock`'s own directory. That is what a
//! single file install cannot survive, so `chock` re-execs itself under a
//! hidden word instead: see `chock_core.plugin_host.verb`, which holds the
//! whole argument. **The process boundary is untouched.** What runs here still
//! runs alone, in its own address space, in its own sandbox, and reaches the
//! harness through two pipes and nothing else.
//!
//! **The `main` below is not the process entry point.** `src/main.zig` is, and
//! it hands over here before it has opened a stream, read an option or looked
//! at the terminal. Two reasons, and both are load bearing: this process's
//! standard output is the wire, so nothing else may write a byte to it; and
//! the argv below is the only trusted input there is, so no general purpose
//! option parser may rewrite it first.
//!
//! ## The command line, which is the only thing that is trusted
//!
//! ```text
//! chock __plugin-host <module path> [capability ...]
//! ```
//!
//! **The capabilities arrive on argv and never on the wire.** argv is fixed
//! before this process exists, so nothing a guest does and nothing on the pipe
//! can widen what the gate allows. The harness builds that list from the
//! metadata it read out of the module's own file, before any process started:
//! see `chock_core.plugin_engine.unionOfCapabilities`.

const std = @import("std");

const chock_core = @import("chock-core");
const wasm = @import("vulcan-wasm");

const plugin_engine = chock_core.plugin_engine;
const plugin_module = chock_core.plugin_module;

/// The Vulcan backed `plugin_engine.Engine`.
///
/// **The only place in this project that names a wasm engine.** Every rule
/// about what a guest may do is on the other side of the seam, in
/// `chock-core`, which builds with no engine at all on every platform.
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

/// Serve one plugin, and return when the harness closes its end.
///
/// `args` is what came after `chock_core.plugin_host.verb` on the command
/// line: the module path, and then the capabilities. `src/main.zig` calls this
/// and passes both allocators and the `Io` it was given, so nothing here has
/// to build its own.
pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
) anyerror!u8 {
    if (args.len < 1) {
        // Nothing to serve and nobody to tell, because the harness is what
        // starts this and the harness always names a module. **An exit code
        // and no message**: this process's standard output is the wire, and a
        // sentence on it would be read as a reply.
        return 2;
    }
    const module_path = args[0];
    const capabilities = args[1..];

    var engine_state: Vulcan = .{ .gpa = gpa };
    defer engine_state.deinit();

    var runner: plugin_engine.Runner = .{ .engine = engine_state.engine() };

    // **Every failure below becomes a sentence and not an exit.** A host
    // process that exited would be read by the harness as a crash, which says
    // something different and worse than "this plugin would not load".
    const load_failure = load(gpa, arena, io, module_path, capabilities, &runner) catch |err|
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
    // `serve` returns when the harness closes its end, which is the ordinary
    // end of a session.
    return 0;
}

/// Read the module, gate it, instantiate it and bind its tools. Answers null
/// when the plugin loaded, and the sentence a person reads when it did not.
///
/// **The order is the design.** The module is read with no engine, its tool
/// count comes out of that read, the gate runs on the import list that read
/// produced, and only then is anything instantiated. See
/// `chock_core.plugin_engine`'s own top comment.
fn load(
    gpa: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: std.Io,
    module_path: []const u8,
    capabilities: []const []const u8,
    runner: *plugin_engine.Runner,
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

    // The metadata, with no engine. This is the same read the harness already
    // made before it decided to start this process, and it is made again here
    // because this process must not take the tool count from the wire.
    var module_refusal: ?plugin_module.Refusal = null;
    var read = plugin_module.read(gpa, bytes, &module_refusal) catch {
        if (module_refusal) |detail| {
            return try std.fmt.allocPrint(arena, "{f}", .{detail});
        }
        return try arena.dupe(u8, "the plugin's module could not be read");
    };
    defer read.deinit();

    const wanted = plugin_module.readImports(gpa, bytes, null) catch
        return try arena.dupe(u8, "the plugin's imports could not be read");
    defer gpa.free(wanted);

    const gated = try arena.alloc(plugin_engine.Import, wanted.len);
    for (gated, wanted) |*slot, one| slot.* = .{ .module = one.module, .field = one.field };

    var refused: ?plugin_engine.Refused = null;
    runner.load(
        gpa,
        bytes,
        read.record().tools.len,
        gated,
        capabilities,
        &refused,
    ) catch |err| {
        if (refused) |detail| return try std.fmt.allocPrint(arena, "{f}", .{detail});
        return try std.fmt.allocPrint(arena, "the plugin would not start: {t}", .{err});
    };
    return null;
}
