//! The three guest symbols, emitted from the author's own declaration.
//!
//! ```text
//! chock_plugin_magic       u32     the ABI version this plugin was built for
//! chock_plugin_metadata    bytes   the serialised record, prefix first
//! chock_plugin_init        fn      binds the tool bodies, and returns how many
//! ```
//!
//! A host reads the first two without instantiating the module. It calls the
//! third only after it has read the metadata and decided to load the plugin,
//! which is what keeps discovery free of execution. Nothing here allocates:
//! the blob is a constant array the compiler builds.
//!
//! ## Two ways in, and why there are two
//!
//! `Exports` is the whole mechanism, and it takes the declaration as a
//! parameter. The comptime block at the end of this file is the automatic
//! path: it reads `@import("root").chock_plugin_metadata` and instantiates
//! `Exports` with it, which is what an ordinary plugin build uses.
//!
//! The automatic path needs the declaration to be in the root of the
//! compilation, and two facts about Zig decide where that is.
//!
//! - Zig analyses a declaration when something reaches it. A plugin author's
//!   file declares its metadata and calls nothing, so a binary rooted at the
//!   author's file reaches nothing and emits no symbol at all.
//!   `lib/chock-plugin-sdk/start.zig` is the root of a plugin binary for that
//!   reason, and it names both halves.
//! - The root of a `zig test` binary is the test runner, not the file under
//!   test, so the automatic path never fires in a test. That is why `Exports`
//!   takes a parameter: `test/plugin/guest.zig` instantiates it by hand,
//!   against the plugin the project ships, and drives the very symbols a real
//!   plugin carries.

const std = @import("std");
const core = @import("chock-plugin-core");
const meta = @import("metadata.zig");
const tools = @import("tools.zig");

const root = @import("root");

/// Whether the root of this compilation is a plugin. False in a test binary,
/// whose root is the test runner. See this file's top comment.
pub const declares_plugin = @hasDecl(root, "chock_plugin_metadata");

/// One tool, bound. `args` points at a value of that tool's own argument
/// type, which the generated thunk is the only thing that knows.
pub const Bound = struct {
    name: []const u8,
    call: *const fn (tools.Context, *const anyopaque) tools.Result,
};

/// The guest side of one plugin. Instantiating this emits the three symbols,
/// so one compilation may instantiate it once: a second plugin in the same
/// binary is a duplicate symbol, which is the right answer.
pub fn Exports(comptime declared: meta.Metadata) type {
    return struct {
        /// The author's record with everything guest side removed. This is
        /// what a host reads.
        pub const record: core.Metadata = declared.lower();

        /// The serialised record, built while the plugin compiles, so a
        /// plugin carries no code to produce it and no allocator to produce
        /// it with.
        pub const blob = core.serializeComptime(record);

        /// The value behind `chock_plugin_magic`. The symbol's name says this
        /// is a Chock plugin; this number says which ABI it speaks.
        pub const abi_word: u32 = @intFromEnum(core.AbiVersion.current);

        var bound: [declared.tools.len]Bound = undefined;
        var bound_count: u32 = 0;

        /// The only function of a plugin that ever runs before the host has
        /// accepted it. It binds one entry per declared tool and answers how
        /// many it bound, which the host compares against the tool count it
        /// already read out of the metadata.
        ///
        /// Calling it more than once is safe. The table it fills is built
        /// from compile time constants alone, so every call fills it the same
        /// way.
        pub fn chockPluginInit() callconv(.c) u32 {
            inline for (declared.tools, 0..) |tool, index| {
                bound[index] = .{ .name = tool.name, .call = thunkFor(tool) };
            }
            bound_count = declared.tools.len;
            return bound_count;
        }

        /// The tools bound by the last `chock_plugin_init`, and nothing
        /// before it. Empty until then, so a host that skipped the call gets
        /// no entry points rather than uninitialised ones.
        pub fn boundTools() []const Bound {
            return bound[0..bound_count];
        }

        /// Where the answer of the last call is.
        ///
        /// **One record for the whole plugin, and it is right that there is
        /// one.** A host runs one call at a time down one pipe and reads the
        /// answer before it asks anything else, so a second record would be a
        /// second thing to keep in step for no gain. A plugin has no threads:
        /// there is no second caller to race with.
        ///
        /// Aligned to four, because a host reads three `u32`s out of it.
        var answer: [core.call.Answer.len]u8 align(4) = @splat(0);

        /// Run one tool and answer where the result is. See
        /// `lib/chock-plugin-core/call.zig` for the record's own layout.
        ///
        /// `index` is the tool's position in the metadata's own tool list.
        /// **Checked here as well as by the host**, because the number arrives
        /// over a pipe and this is the side that would index the table with
        /// it. A host that has not called `chock_plugin_init` has bound
        /// nothing, so every index is out of range and this answers zero,
        /// which is the same refusal.
        ///
        /// `args_ptr` and `args_len` are the argument text the model wrote,
        /// carried through to the tool body untouched. See `Context`.
        pub fn chockPluginCall(index: u32, args_ptr: usize, args_len: usize) callconv(.c) usize {
            if (index >= bound_count) return core.call.no_answer;
            const entry = bound[index];

            // A length with no bytes behind it is the ordinary case of a tool
            // called with nothing, and `@ptrFromInt(0)` is not a pointer this
            // may build. An empty slice says the same thing and is safe.
            const arguments: []const u8 = if (args_len == 0)
                &.{}
            else
                @as([*]const u8, @ptrFromInt(args_ptr))[0..args_len];

            const result = entry.call(
                .{ .tool = entry.name, .arguments = arguments },
                &empty_arguments,
            );
            const outcome: core.call.Outcome = switch (result.outcome) {
                .success => .success,
                .failure => .failure,
            };
            core.call.writeAnswer(&answer, outcome, result.text);
            return @intFromPtr(&answer);
        }

        /// Where a host may write the argument text, and how much of it fits.
        ///
        /// **A function and not a data symbol**, unlike the metadata blob. A
        /// buffer of zeros lands in `.bss`, which has no data segment at all,
        /// and `lib/chock-core/plugin_module.zig` resolves a data symbol's
        /// address through the module's own data segments. So a host could not
        /// find this by reading the file, and it does not need to: by the time
        /// it wants to write arguments it has already decided to load the
        /// plugin, so calling a function is free.
        ///
        /// **The guest owns the bound on its own buffer.** A `len` that does
        /// not fit answers zero, and the host writes nothing. A host that knew
        /// the size would be a host that has to be kept in step with every
        /// plugin's own build.
        pub fn chockPluginArguments(len: u32) callconv(.c) usize {
            if (len > argument_bytes) return 0;
            return @intFromPtr(&argument_buffer);
        }

        /// How much argument text a plugin built with this SDK accepts.
        ///
        /// 64 kibibytes, which is one wasm page. It costs a plugin nothing on
        /// disk: a buffer of zeros is `.bss` and carries no data segment, so
        /// the module's own file does not grow by one byte for it.
        pub const argument_bytes = 64 << 10;

        var argument_buffer: [argument_bytes]u8 = @splat(0);

        /// The value a thunk casts to a tool's own argument type.
        ///
        /// **A tool's argument type is comptime checked to hold no field**,
        /// below, so every such type has exactly one value and this one byte
        /// is a valid instance of all of them. The byte exists so there is an
        /// address to hand over: a zero sized type has no storage of its own
        /// and `@ptrCast` of a null pointer is not something this may build.
        var empty_arguments: u8 = 0;

        comptime {
            // **Argument lowering is not built, so a tool that needs it must
            // not compile.** The thunk casts the host's pointer straight to
            // the tool's own argument type, and nothing turns the model's
            // argument text into a value of that type. A tool with a field
            // would therefore read whatever `empty_arguments` happens to sit
            // beside, which is a silent wrong answer rather than a failure.
            //
            // A tool body that wants the model's text today reads
            // `ctx.arguments`, which carries it whole.
            for (declared.tools) |tool| {
                if (@typeInfo(tool.type) != .@"struct" or
                    @typeInfo(tool.type).@"struct".fields.len != 0)
                {
                    @compileError("the tool \"" ++ tool.name ++ "\" declares an argument type with " ++
                        "fields, and this Chock does not lower the model's arguments into one. " ++
                        "Give the tool an argument type with no field and read ctx.arguments.");
                }
            }

            @export(&abi_word, .{ .name = core.Magic.symbol });
            @export(&blob, .{ .name = core.Metadata.symbol });
            @export(&chockPluginInit, .{ .name = core.init_symbol });
            @export(&chockPluginCall, .{ .name = core.call_symbol });
            @export(&chockPluginArguments, .{ .name = core.call.arguments_symbol });
        }
    };
}

fn thunkFor(comptime tool: meta.Tool) *const fn (tools.Context, *const anyopaque) tools.Result {
    const body = comptime meta.runOf(tool);
    return &struct {
        fn call(ctx: tools.Context, args: *const anyopaque) tools.Result {
            const typed: *const tool.type = @ptrCast(@alignCast(args));
            return body(ctx, typed.*);
        }
    }.call;
}

comptime {
    // The automatic path. Nothing below `Exports` is reached in a build whose
    // root declares no plugin, so a library or a test binary that imports the
    // SDK emits nothing.
    if (declares_plugin) _ = Exports(root.chock_plugin_metadata);
}
