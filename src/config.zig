//! `chock config`: inspect the user configuration without reading credentials.

const std = @import("std");
const chock_auth = @import("chock-auth");

const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const usage_text =
    \\Usage: chock config <operation> [options]
    \\
    \\Inspect the user configuration without reading a credential or contacting a
    \\provider. The project's chock.zon is separate and is checked before a session
    \\starts.
    \\
    \\Operations:
    \\  check    Check the configuration and report the selected defaults.
    \\  path     Print the configuration path, whether or not the file exists.
    \\
++ tty.options_text;

const Operation = enum {
    check,
    path,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    _ = exe_path;

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    var env = try environ.createMap(arena);
    defer env.deinit();

    const operation = parseOperation(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const config_dir = chock_auth.paths.configDir(arena, &env) catch |err| {
        tty.print(.err, "chock config {s}: the configuration directory is unknown: {t}\n", .{
            @tagName(operation),
            err,
        });
        return Exit.usage.code();
    };
    const path = try std.fs.path.join(arena, &.{ config_dir, chock_auth.config.file_name });

    if (operation == .path) {
        tty.out(.plain, "{s}\n", .{path});
        return Exit.finished.code();
    }

    var diag: ?chock_auth.config.Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    var loaded = chock_auth.config.load(gpa, io, config_dir, &diag) catch |err| switch (err) {
        error.NoConfigFile => {
            tty.print(.err, "chock config check: there is no configuration at {s}\n", .{path});
            return Exit.usage.code();
        },
        else => {
            if (diag) |*one| {
                tty.print(.err, "chock config check: {f}\n", .{one});
            } else {
                tty.print(.err, "chock config check: {s} could not be read: {t}\n", .{ path, err });
            }
            return Exit.usage.code();
        },
    };
    defer loaded.deinit();

    if (missingDefault(&loaded)) |name| {
        tty.print(
            .err,
            "chock config check: .defaults.provider names \"{s}\", but no provider has that name\n",
            .{name},
        );
        return Exit.usage.code();
    }

    report(path, &loaded);
    return Exit.finished.code();
}

fn missingDefault(config: *const chock_auth.config.Config) ?[]const u8 {
    const name = config.default_provider orelse return null;
    if (config.find(name) != null) return null;
    return name;
}

fn report(path: []const u8, config: *const chock_auth.config.Config) void {
    tty.out(.plain, "{s}: valid; {d} provider instance{s}", .{
        path,
        config.instances.len,
        if (config.instances.len == 1) "" else "s",
    });
    if (config.defaultInstance()) |instance| {
        tty.out(.plain, "; default provider {s}", .{instance.name});
    } else if (config.instances.len > 1) {
        tty.out(.plain, "; no default provider", .{});
    }
    if (config.default_model) |model| tty.out(.plain, "; default model {s}", .{model});
    tty.out(.plain, "\n", .{});
}

fn parseOperation(args: []const []const u8) error{ HelpWanted, BadArguments }!Operation {
    if (args.len == 1 and std.mem.eql(u8, args[0], "check")) return .check;
    if (args.len == 1 and std.mem.eql(u8, args[0], "path")) return .path;
    if (args.len == 1 and
        (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")))
    {
        return error.HelpWanted;
    }
    return error.BadArguments;
}

test "config takes the check and path operations" {
    try std.testing.expectEqual(Operation.check, try parseOperation(&.{"check"}));
    try std.testing.expectEqual(Operation.path, try parseOperation(&.{"path"}));
    try std.testing.expectError(error.BadArguments, parseOperation(&.{}));
    try std.testing.expectError(error.BadArguments, parseOperation(&.{"show"}));
    try std.testing.expectError(error.BadArguments, parseOperation(&.{ "check", "again" }));
    try std.testing.expectError(error.HelpWanted, parseOperation(&.{"--help"}));
}

test "a valid report says how its default was selected and exposes no credential" {
    const gpa = std.testing.allocator;
    var config = try chock_auth.config.parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat",
        \\           .base_url = "http://127.0.0.1:5000/v1",
        \\           .token = "never-print-this" },
        \\    },
        \\    .defaults = .{ .provider = "local", .model = "test-model" },
        \\}
    , null);
    defer config.deinit();

    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, gpa);
    defer capture.stop(std.testing.io);

    report("/config/chock/config.zon", &config);
    const output = capture.out();
    try std.testing.expect(std.mem.indexOf(u8, output, "valid; 1 provider instance") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default provider local") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default model test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "never-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "127.0.0.1") == null);
}

test "a named default must name an instance the file has" {
    const gpa = std.testing.allocator;
    var config = try chock_auth.config.parse(gpa,
        \\.{
        \\    .providers = .{ .{ .name = "work", .kind = "aiand" } },
        \\    .defaults = .{ .provider = "wrok", .model = "a-model" },
        \\}
    , null);
    defer config.deinit();

    try std.testing.expectEqualStrings("wrok", missingDefault(&config).?);
}
