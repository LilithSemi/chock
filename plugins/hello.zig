const chock_plugin_sdk = @import("chock-plugin-sdk");

const HelloTool = struct {
    fn run(ctx: chock_plugin_sdk.tools.Context, _args: HelloTool) chock_plugin_sdk.tools.Result {
        _ = _args;
        return ctx.successResult("Hello, world!");
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
    },
};
