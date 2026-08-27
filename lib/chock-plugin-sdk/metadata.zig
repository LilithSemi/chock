//! The author facing shape of a plugin's own declaration, and how it lowers to
//! the data only form the host reads.
//!
//! This is a superset of `chock-plugin-core`'s `Metadata`. It adds the two
//! things a compiler needs and a reader must never see: the `type` of a tool's
//! arguments, and the `run` function behind it. Both exist only while the
//! plugin compiles. `lower` drops them, and what is left is exactly what
//! travels to the host.
//!
//! Keeping the two apart is the reason the host never has to instantiate
//! anything: a `core.Metadata` holds no pointer into a guest module, so a host
//! reads it, decides, and only then runs `chock_plugin_init`.

const std = @import("std");
const core = @import("chock-plugin-core");
const tools = @import("tools.zig");

pub const LocaleField = core.LocaleField;
pub const VersionConstraint = core.VersionConstraint;

/// The signature every tool body has: the context, then the tool's own
/// arguments by value, answering a `Result`.
pub fn RunFn(comptime Args: type) type {
    return fn (tools.Context, Args) tools.Result;
}

/// One tool, as its author writes it.
pub const Tool = struct {
    name: []const u8,
    description: []const LocaleField = &.{},

    /// The action names this tool may reach for, in the language
    /// `lib/chock-policy/table.zig` uses for its `action` key. This is what
    /// puts a plugin tool on the policy table beside every built in tool. It
    /// is not decoration: an empty set is a claim that the tool changes
    /// nothing, and the host holds the plugin to it.
    capabilities: []const []const u8 = &.{},

    /// The type of the arguments `run` takes.
    type: type,

    /// The tool body. The type is opaque because a struct field's type cannot
    /// depend on the value of a sibling field, and `run`'s real signature
    /// depends on `type`. `runOf` puts the signature back on, and checks it
    /// wherever Zig lets it: see that function.
    run: *const anyopaque,

    /// The part of this that reaches the host.
    pub fn descriptor(comptime self: Tool) core.ToolDescriptor {
        return .{
            .name = self.name,
            .description = self.description,
            .capabilities = self.capabilities,
        };
    }
};

/// The author's whole declaration. `plugins/hello.zig` is one of these.
pub const Metadata = struct {
    name: []const u8,
    version: std.SemanticVersion,
    chock_version: VersionConstraint,
    author: []const u8,
    description: []const LocaleField = &.{},
    tools: []const Tool = &.{},

    /// The name the author gives the declaration, and the name of the guest
    /// symbol that carries its serialised form.
    pub const symbol = core.Metadata.symbol;

    /// Drop everything that cannot cross to a host and keep the rest. Runs
    /// while the plugin compiles, so the cost on the target is zero.
    pub fn lower(comptime self: Metadata) core.Metadata {
        const descriptors = comptime descriptors: {
            var acc: [self.tools.len]core.ToolDescriptor = undefined;
            for (self.tools, &acc) |tool, *out| out.* = tool.descriptor();
            break :descriptors acc;
        };
        return .{
            .name = self.name,
            .version = self.version,
            .chock_version = self.chock_version,
            .author = self.author,
            .description = self.description,
            .tools = &descriptors,
        };
    }
};

/// `tool.run` with its signature put back on.
///
/// The cast itself cannot be checked: an opaque pointer carries no signature.
/// What can be checked is the ordinary case. Almost every author writes
/// `.type = T` and `.run = T.run`, so when `T` publishes a `run` this refuses
/// to build unless that `run` has the right signature and is the very function
/// the literal named. An author who keeps `run` private gets no check, because
/// `@hasDecl` cannot see a private declaration from another file, and the
/// build has no way to look.
pub fn runOf(comptime tool: Tool) *const RunFn(tool.type) {
    comptime {
        const Args = tool.type;
        const info = @typeInfo(Args);
        if (info != .@"struct" and info != .@"union" and info != .@"enum" and info != .@"opaque") {
            @compileError("the tool '" ++ tool.name ++ "' declares .type = " ++
                @typeName(Args) ++ ", which cannot hold arguments");
        }
        if (@hasDecl(Args, "run")) {
            const declared = @field(Args, "run");
            if (@TypeOf(declared) != RunFn(Args)) {
                @compileError("the tool '" ++ tool.name ++ "' has a run of type " ++
                    @typeName(@TypeOf(declared)) ++ ", and a tool body must be " ++
                    @typeName(RunFn(Args)));
            }
            if (tool.run != @as(*const anyopaque, @ptrCast(&declared))) {
                @compileError("the tool '" ++ tool.name ++ "' sets .run to a function that is not " ++
                    @typeName(Args) ++ ".run");
            }
        }
        return @ptrCast(@alignCast(tool.run));
    }
}

const testing = std.testing;

const Greet = struct {
    who: []const u8 = "world",

    pub fn run(ctx: tools.Context, args: Greet) tools.Result {
        return ctx.successResult(args.who);
    }
};

const Silent = struct {
    // Private on purpose: this is the shape `runOf` cannot check, and the
    // test below pins that it still binds rather than failing the build.
    fn run(ctx: tools.Context, _: Silent) tools.Result {
        return ctx.errorResult("nothing to say");
    }
};

test "lower drops the type and the run and keeps everything else" {
    // The host must never receive a pointer into a guest module. What it does
    // receive has to be complete, capabilities included.
    const declared: Metadata = .{
        .name = "greeter",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "Somebody",
        .description = &.{.{ .locale = "en", .value = "Says hello" }},
        .tools = &.{.{
            .name = "greet",
            .description = &.{.{ .locale = "en", .value = "Greets" }},
            .capabilities = &.{"fs.read"},
            .type = Greet,
            .run = Greet.run,
        }},
    };

    const lowered = comptime declared.lower();
    try testing.expectEqual(core.Metadata, @TypeOf(lowered));
    try testing.expectEqualStrings("greeter", lowered.name);
    try testing.expectEqual(@as(usize, 1), lowered.tools.len);
    try testing.expectEqualStrings("greet", lowered.tools[0].name);
    try testing.expectEqualStrings("fs.read", lowered.tools[0].capabilities[0]);
    try testing.expectEqualStrings("Greets", lowered.tools[0].description[0].value);
    // The whole point: nothing that only exists inside the guest survived.
    try testing.expect(!@hasField(core.ToolDescriptor, "run"));
    try testing.expect(!@hasField(core.ToolDescriptor, "type"));
}

test "runOf gives back a callable body with its real signature" {
    // The erased pointer is the only thing the literal carries. If the cast
    // were wrong the call below would answer with rubbish rather than "you".
    const tool: Tool = .{ .name = "greet", .type = Greet, .run = Greet.run };
    const body = comptime runOf(tool);
    const answer = body(.{ .tool = "greet" }, .{ .who = "you" });
    try testing.expectEqual(tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("you", answer.text);
}

test "runOf binds a tool whose body is private" {
    // The case the signature check cannot reach. It must still bind, because
    // a private body is ordinary Zig and not a mistake.
    const tool: Tool = .{ .name = "silent", .type = Silent, .run = Silent.run };
    const body = comptime runOf(tool);
    const answer = body(.{ .tool = "silent" }, .{});
    try testing.expectEqual(tools.Outcome.failure, answer.outcome);
    try testing.expectEqualStrings("nothing to say", answer.text);
}

test "a lowered record serialises and parses back unchanged" {
    // The join between this file and `chock-plugin-core`. The author writes
    // one shape, the host reads another, and the two must say the same thing.
    const declared: Metadata = .{
        .name = "greeter",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{
            .min = .{ .major = 0, .minor = 1, .patch = 0 },
            .rec = .{ .major = 0, .minor = 1, .patch = 0 },
        },
        .author = "Somebody",
        .description = &.{.{ .locale = "en", .value = "Says hello" }},
        .tools = &.{.{
            .name = "greet",
            .capabilities = &.{ "fs.read", "fs.write" },
            .type = Greet,
            .run = Greet.run,
        }},
    };

    const lowered = comptime declared.lower();
    const bytes = try core.serializeAlloc(testing.allocator, lowered);
    defer testing.allocator.free(bytes);

    var parsed = try core.parse(testing.allocator, bytes, null);
    defer parsed.deinit();
    try testing.expect(lowered.eql(parsed.record));
    try testing.expectEqualStrings("fs.write", parsed.record.tools[0].capabilities[1]);
}
