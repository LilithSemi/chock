//! The author's own declaration shape, lowered to the host's data only
//! form. Adds the tool `type` and `run`, dropped by `lower`.

const std = @import("std");
const core = @import("chock-plugin-core");
const tools = @import("tools.zig");

pub const LocaleField = core.LocaleField;
pub const VersionConstraint = core.VersionConstraint;

pub fn RunFn(comptime Args: type) type {
    return fn (tools.Context, Args) tools.Result;
}

pub const Tool = struct {
    name: []const u8,
    description: []const LocaleField = &.{},

    /// Not decoration: empty means the tool changes nothing.
    capabilities: []const []const u8 = &.{},

    type: type,

    /// Opaque. `runOf` puts the signature back on.
    run: *const anyopaque,

    /// The type cannot cross. `core.schema.propertiesOf` maps what does.
    pub fn descriptor(comptime self: Tool) core.ToolDescriptor {
        return .{
            .name = self.name,
            .description = self.description,
            .capabilities = self.capabilities,
            .parameters = core.schema.propertiesOf(self.type, self.whose()),
        };
    }

    pub fn whose(comptime self: Tool) []const u8 {
        return "the tool \"" ++ self.name ++ "\"";
    }
};

pub const Metadata = struct {
    name: []const u8,
    version: std.SemanticVersion,
    chock_version: VersionConstraint,
    author: []const u8,
    description: []const LocaleField = &.{},
    tools: []const Tool = &.{},

    pub const symbol = core.Metadata.symbol;

    /// Runs while the plugin compiles.
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

/// `tool.run`'s signature put back on, checked only if public.
pub fn runOf(comptime tool: Tool) *const RunFn(tool.type) {
    comptime {
        const Args = tool.type;
        const info = @typeInfo(Args);
        if (info != .@"struct") {
            @compileError("the tool '" ++ tool.name ++ "' declares .type = " ++
                @typeName(Args) ++ ", and a tool's arguments must be a struct, because " ++
                "the model writes them as a JSON object");
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

    pub const docs = .{ .who = "Who to greet." };

    pub fn run(ctx: tools.Context, args: Greet) tools.Result {
        return ctx.successResult(args.who);
    }
};

const Silent = struct {
    // Private on purpose.
    fn run(ctx: tools.Context, _: Silent) tools.Result {
        return ctx.errorResult("nothing to say");
    }
};

test "lower drops the type and the run and keeps everything else" {
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
    try testing.expect(!@hasField(core.ToolDescriptor, "run"));
    try testing.expect(!@hasField(core.ToolDescriptor, "type"));

    try testing.expectEqual(@as(usize, 1), lowered.tools[0].parameters.len);
    try testing.expectEqualStrings("who", lowered.tools[0].parameters[0].name);
    try testing.expectEqualStrings("Who to greet.", lowered.tools[0].parameters[0].description);
    try testing.expect(lowered.tools[0].parameters[0].required);
    try testing.expectEqual(core.schema.Kind.string, lowered.tools[0].parameters[0].shape.kind);
}

test "runOf gives back a callable body with its real signature" {
    const tool: Tool = .{ .name = "greet", .type = Greet, .run = Greet.run };
    const body = comptime runOf(tool);
    const answer = body(.{ .tool = "greet" }, .{ .who = "you" });
    try testing.expectEqual(tools.Outcome.success, answer.outcome);
    try testing.expectEqualStrings("you", answer.text);
}

test "runOf binds a tool whose body is private" {
    const tool: Tool = .{ .name = "silent", .type = Silent, .run = Silent.run };
    const body = comptime runOf(tool);
    const answer = body(.{ .tool = "silent" }, .{});
    try testing.expectEqual(tools.Outcome.failure, answer.outcome);
    try testing.expectEqualStrings("nothing to say", answer.text);
}

test "a lowered record serialises and parses back unchanged" {
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
