const chock_plugin_sdk = @import("chock-plugin-sdk");

const HelloTool = struct {
    fn run(ctx: chock_plugin_sdk.tools.Context, _args: HelloTool) chock_plugin_sdk.tools.Result {
        _ = _args;
        return ctx.successResult("Hello, world!");
    }
};

/// The same greeting, to somebody named. **The arguments arrive as a value of
/// this struct**, decoded from what the model wrote before this body runs, so
/// `args.who` is a string and never something to parse.
///
/// `docs` is one sentence per field. It is what the model reads to learn what
/// the tool takes, and a field with no sentence in it fails the build.
const GreetTool = struct {
    who: []const u8,
    loudly: ?bool = null,

    pub const docs = .{
        .who = "The name to greet.",
        .loudly = "True to shout the greeting.",
    };

    fn run(ctx: chock_plugin_sdk.tools.Context, args: GreetTool) chock_plugin_sdk.tools.Result {
        if (args.loudly orelse false) return ctx.successResult("HELLO!");
        return ctx.successResult(args.who);
    }
};

pub const chock_plugin_metadata: chock_plugin_sdk.Metadata = .{
    .name = "hello",
    .version = .{ .major = 0, .minor = 1, .patch = 0 },
    .author = "Tristan Ross <tristan.ross@midstall.com>",
    .chock_version = .{
        .min = chock_plugin_sdk.version,
        .rec = chock_plugin_sdk.version,
        .max = null,
    },
    .description = &.{
        .{
            .locale = "en",
            .value = "A simple hello world plugin",
        },
    },
    .tools = &.{
        .{
            .name = "hello",
            .description = &.{
                .{
                    .locale = "en",
                    .value = "A simple hello world tool",
                },
            },
            .type = HelloTool,
            .run = HelloTool.run,
        },
        .{
            .name = "greet",
            .description = &.{
                .{
                    .locale = "en",
                    .value = "Greets somebody by name",
                },
            },
            .type = GreetTool,
            .run = GreetTool.run,
        },
    },
};
