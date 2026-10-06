//! The three guest symbols: magic, metadata, and init.

const std = @import("std");
const core = @import("chock-plugin-core");
const meta = @import("metadata.zig");
const tools = @import("tools.zig");

const root = @import("root");

pub const declares_plugin = @hasDecl(root, "chock_plugin_metadata");

pub const Bound = struct {
    name: []const u8,
    call: *const fn (tools.Context) tools.Result,
};

/// The guest side of one plugin. Instantiating this emits the three
/// symbols, so a second plugin in the same binary is a duplicate symbol.
pub fn Exports(comptime declared: meta.Metadata) type {
    return struct {
        pub const record: core.Metadata = declared.lower();
        pub const blob = core.serializeComptime(record);
        pub const abi_word: u32 = @intFromEnum(core.AbiVersion.current);

        var bound: [declared.tools.len]Bound = undefined;
        var bound_count: u32 = 0;

        pub fn chockPluginInit() callconv(.c) u32 {
            inline for (declared.tools, 0..) |tool, index| {
                bound[index] = .{ .name = tool.name, .call = thunkFor(tool) };
            }
            bound_count = declared.tools.len;
            return bound_count;
        }

        pub fn boundTools() []const Bound {
            return bound[0..bound_count];
        }

        var answer: [core.call.Answer.len]u8 align(4) = @splat(0);

        pub fn chockPluginCall(index: u32, args_ptr: usize, args_len: usize) callconv(.c) usize {
            if (index >= bound_count) return core.call.no_answer;
            const entry = bound[index];

            const arguments: []const u8 = if (args_len == 0)
                &.{}
            else
                @as([*]const u8, @ptrFromInt(args_ptr))[0..args_len];

            const result = entry.call(.{ .tool = entry.name, .arguments = arguments });
            const outcome: core.call.Outcome = switch (result.outcome) {
                .success => .success,
                .failure => .failure,
            };
            core.call.writeAnswer(&answer, outcome, result.text);
            return @intFromPtr(&answer);
        }

        pub fn chockPluginArguments(len: u32) callconv(.c) usize {
            if (len > argument_bytes) return 0;
            return @intFromPtr(&argument_buffer);
        }

        pub const argument_bytes = 64 << 10;

        var argument_buffer: [argument_bytes]u8 = @splat(0);

        comptime {
            @export(&abi_word, .{ .name = core.Magic.symbol });
            @export(&blob, .{ .name = core.Metadata.symbol });
            @export(&chockPluginInit, .{ .name = core.init_symbol });
            @export(&chockPluginCall, .{ .name = core.call_symbol });
            @export(&chockPluginArguments, .{ .name = core.call.arguments_symbol });
        }
    };
}

const decode_bytes = 4 << 10;

var decode_buffer: [decode_bytes]u8 align(16) = @splat(0);

fn thunkFor(comptime tool: meta.Tool) *const fn (tools.Context) tools.Result {
    const body = comptime meta.runOf(tool);
    const Args = tool.type;
    const takes_nothing = comptime @typeInfo(Args).@"struct".fields.len == 0;

    return &struct {
        fn call(ctx: tools.Context) tools.Result {
            if (takes_nothing) return body(ctx, .{});

            var scratch: std.heap.FixedBufferAllocator = .init(&decode_buffer);
            const typed = core.args.decode(Args, ctx.arguments, scratch.allocator()) catch |err|
                return ctx.errorResult(switch (err) {
                    error.OutOfMemory => "the arguments for \"" ++ tool.name ++
                        "\" hold more entries than this plugin has room for",
                    error.MissingField => "the arguments for \"" ++ tool.name ++
                        "\" leave out a field it needs",
                    else => "the arguments for \"" ++ tool.name ++
                        "\" are not a record this plugin can read",
                });
            return body(ctx, typed);
        }
    }.call;
}

comptime {
    if (declares_plugin) _ = Exports(root.chock_plugin_metadata);
}
