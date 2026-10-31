//! Test-only executable for the engine protocol tests. Production enters the
//! same runtime through `Process.entry`, without executing another program.

const std = @import("std");
const plugin_runtime = @import("plugin-runtime");
const chock_core = @import("chock-core");

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) return 2;

    const bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[1],
        arena,
        .limited(chock_core.plugin_module.max_module_bytes),
    ) catch return 2;
    return plugin_runtime.run(bytes, args[2..]);
}
