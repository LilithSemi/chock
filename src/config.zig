//! `chock config`: create or inspect the user configuration without reading credentials.

const std = @import("std");
const chock_auth = @import("chock-auth");

const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const usage_text =
    \\Usage: chock config <operation> [options]
    \\
    \\Create or inspect the user configuration without reading a credential or
    \\contacting a provider. The project's chock.zon is separate and is checked
    \\before a session starts.
    \\
    \\Operations:
    \\  check    Check the configuration and report the selected defaults.
    \\  example  Print a valid starter configuration without writing it.
    \\  init     Write the starter configuration unless a file already exists.
    \\  path     Print the configuration path, whether or not the file exists.
    \\
    \\Options:
    \\  --format <kind>  For check: human (default) or json.
    \\
++ tty.options_text;

const Operation = enum {
    check,
    example,
    init,
    path,
};

pub const example_text =
    \\.{
    \\    .providers = .{
    \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1", .context_tokens = 65536 },
    \\    },
    \\    .defaults = .{ .provider = "local", .model = "glm4.7-flash:A3B" },
    \\}
    \\
;

const Format = enum {
    human,
    json,
};

const Options = struct {
    operation: Operation,
    format: Format = .human,
};

pub fn main(
    init: std.process.Init,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    const arena = init.arena.allocator();
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map.*;

    _ = exe_path;

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    if (options.operation == .example) {
        tty.out(.plain, "{s}", .{example_text});
        return Exit.finished.code();
    }

    const config_dir = chock_auth.paths.configDir(arena, &env) catch |err| {
        tty.print(.err, "chock config {s}: the configuration directory is unknown: {t}\n", .{
            @tagName(options.operation),
            err,
        });
        return Exit.usage.code();
    };
    const path = try std.fs.path.join(arena, &.{ config_dir, chock_auth.config.file_name });

    if (options.operation == .path) {
        tty.out(.plain, "{s}\n", .{path});
        return Exit.finished.code();
    }

    if (options.operation == .init) {
        std.Io.Dir.cwd().createDirPath(io, config_dir) catch |err| {
            tty.print(.err, "chock config init: {s} could not be created: {t}\n", .{ config_dir, err });
            return Exit.usage.code();
        };
        const wrote = writeStarter(io, path) catch |err| {
            tty.print(.err, "chock config init: {s} could not be written: {t}\n", .{ path, err });
            return Exit.usage.code();
        };
        if (!wrote) {
            tty.print(.err, "chock config init: {s} already exists, so nothing was written\n", .{path});
            return Exit.usage.code();
        }
        tty.out(.plain, "chock config init: wrote {s}\n", .{path});
        tty.out(.plain, "Edit its endpoint and model, then run `chock config check`.\n", .{});
        return Exit.finished.code();
    }

    var diag: ?chock_auth.config.Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    var loaded = chock_auth.config.load(gpa, io, config_dir, &diag) catch |err| switch (err) {
        error.NoConfigFile => {
            tty.print(
                .err,
                "chock config check: there is no configuration at {s}; " ++
                    "run `chock config init` to write a starter\n",
                .{path},
            );
            try reportInvalid(arena, path, options.format, .config_missing, null);
            return Exit.usage.code();
        },
        else => {
            if (diag) |*one| {
                tty.print(.err, "chock config check: {f}\n", .{one});
            } else {
                tty.print(.err, "chock config check: {s} could not be read: {t}\n", .{ path, err });
            }
            try reportInvalid(
                arena,
                path,
                options.format,
                problemForLoadError(err),
                null,
            );
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
        try reportInvalid(arena, path, options.format, .default_provider_missing, &loaded);
        return Exit.usage.code();
    }

    try report(arena, path, &loaded, options.format);
    return Exit.finished.code();
}

fn writeStarter(io: std.Io, path: []const u8) !bool {
    var file = std.Io.Dir.createFileAbsolute(io, path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return false,
        else => return err,
    };
    errdefer std.Io.Dir.deleteFileAbsolute(io, path) catch {};
    defer file.close(io);
    try file.writeStreamingAll(io, example_text);
    try file.sync(io);
    return true;
}

fn missingDefault(config: *const chock_auth.config.Config) ?[]const u8 {
    const name = config.default_provider orelse return null;
    if (config.find(name) != null) return null;
    return name;
}

const CheckReport = struct {
    schema: []const u8 = "chock.config-check",
    version: u32 = 1,
    path: []const u8,
    valid: bool = true,
    problem: ?CheckProblem = null,
    provider_instances: usize = 0,
    default_provider: ?[]const u8 = null,
    default_model: ?[]const u8 = null,
};

const CheckProblem = enum {
    config_missing,
    config_invalid,
    config_unreadable,
    default_provider_missing,
};

fn problemForLoadError(err: anyerror) CheckProblem {
    return if (err == error.ReadFailed) .config_unreadable else .config_invalid;
}

fn reportInvalid(
    arena: std.mem.Allocator,
    path: []const u8,
    format: Format,
    problem: CheckProblem,
    config: ?*const chock_auth.config.Config,
) !void {
    if (format != .json) return;
    const known = config orelse {
        try reportJson(arena, .{ .path = path, .valid = false, .problem = problem });
        return;
    };
    try reportJson(arena, .{
        .path = path,
        .valid = false,
        .problem = problem,
        .provider_instances = known.instances.len,
        .default_provider = known.default_provider,
        .default_model = known.default_model,
    });
}

fn reportJson(arena: std.mem.Allocator, value: CheckReport) !void {
    const json = try std.json.Stringify.valueAlloc(arena, value, .{});
    defer arena.free(json);
    tty.out(.plain, "{s}\n", .{json});
}

fn report(
    arena: std.mem.Allocator,
    path: []const u8,
    config: *const chock_auth.config.Config,
    format: Format,
) !void {
    if (format == .json) {
        const default_provider = if (config.defaultInstance()) |instance| instance.name else null;
        try reportJson(arena, .{
            .path = path,
            .provider_instances = config.instances.len,
            .default_provider = default_provider,
            .default_model = config.default_model,
        });
        return;
    }

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

fn parseOptions(args: []const []const u8) error{ HelpWanted, BadArguments }!Options {
    if (args.len == 1 and std.mem.eql(u8, args[0], "check")) return .{ .operation = .check };
    if (args.len == 1 and std.mem.eql(u8, args[0], "example")) return .{ .operation = .example };
    if (args.len == 1 and std.mem.eql(u8, args[0], "init")) return .{ .operation = .init };
    if (args.len == 1 and std.mem.eql(u8, args[0], "path")) return .{ .operation = .path };
    if (args.len == 2 and
        (std.mem.eql(u8, args[0], "check") or
            std.mem.eql(u8, args[0], "example") or
            std.mem.eql(u8, args[0], "init") or
            std.mem.eql(u8, args[0], "path")) and
        (std.mem.eql(u8, args[1], "--help") or std.mem.eql(u8, args[1], "-h")))
    {
        return error.HelpWanted;
    }
    if (args.len == 3 and
        std.mem.eql(u8, args[0], "check") and
        std.mem.eql(u8, args[1], "--format"))
    {
        if (std.mem.eql(u8, args[2], "human")) return .{ .operation = .check };
        if (std.mem.eql(u8, args[2], "json")) return .{ .operation = .check, .format = .json };
        return error.BadArguments;
    }
    if (args.len == 1 and
        (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")))
    {
        return error.HelpWanted;
    }
    return error.BadArguments;
}

test "config takes the check, example, init, and path operations" {
    try std.testing.expectEqual(Operation.check, (try parseOptions(&.{"check"})).operation);
    try std.testing.expectEqual(Operation.example, (try parseOptions(&.{"example"})).operation);
    try std.testing.expectEqual(Operation.init, (try parseOptions(&.{"init"})).operation);
    try std.testing.expectEqual(Operation.path, (try parseOptions(&.{"path"})).operation);
    try std.testing.expectEqual(Format.json, (try parseOptions(&.{ "check", "--format", "json" })).format);
    try std.testing.expectEqual(Format.human, (try parseOptions(&.{ "check", "--format", "human" })).format);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{}));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{"show"}));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "check", "again" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "path", "--format", "json" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "check", "--format", "yaml" }));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{ "check", "--help" }));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{ "example", "--help" }));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{ "init", "--help" }));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{ "path", "-h" }));
}

test "the starter configuration remains valid" {
    var config = try chock_auth.config.parse(std.testing.allocator, example_text, null);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 1), config.instances.len);
    try std.testing.expectEqualStrings("local", config.default_provider.?);
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

    try report(gpa, "/config/chock/config.zon", &config, .human);
    const output = capture.out();
    try std.testing.expect(std.mem.indexOf(u8, output, "valid; 1 provider instance") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default provider local") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default model test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "never-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "127.0.0.1") == null);
}

test "a JSON report is structured and exposes no credential" {
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

    try report(gpa, "/config/chock/config.zon", &config, .json);
    const output = capture.out();
    try std.testing.expect(std.mem.indexOf(u8, output, "never-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "127.0.0.1") == null);

    const parsed = try std.json.parseFromSlice(CheckReport, gpa, output, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("chock.config-check", parsed.value.schema);
    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
    try std.testing.expect(parsed.value.valid);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.provider_instances);
    try std.testing.expectEqualStrings("local", parsed.value.default_provider.?);
    try std.testing.expectEqualStrings("test-model", parsed.value.default_model.?);
}

test "an invalid JSON report is structured and has no guessed configuration" {
    const gpa = std.testing.allocator;

    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, gpa);
    defer capture.stop(std.testing.io);

    try reportInvalid(gpa, "/config/chock/config.zon", .json, .config_missing, null);

    const parsed = try std.json.parseFromSlice(CheckReport, gpa, capture.out(), .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/config/chock/config.zon", parsed.value.path);
    try std.testing.expect(!parsed.value.valid);
    try std.testing.expectEqual(CheckProblem.config_missing, parsed.value.problem.?);
    try std.testing.expectEqual(@as(usize, 0), parsed.value.provider_instances);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.value.default_provider);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.value.default_model);
}

test "an invalid JSON report keeps configuration facts that were parsed" {
    const gpa = std.testing.allocator;
    var config = try chock_auth.config.parse(gpa,
        \\.{
        \\    .providers = .{ .{ .name = "work", .kind = "aiand" } },
        \\    .defaults = .{ .provider = "wrok", .model = "a-model" },
        \\}
    , null);
    defer config.deinit();

    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, gpa);
    defer capture.stop(std.testing.io);

    try reportInvalid(gpa, "/config/chock/config.zon", .json, .default_provider_missing, &config);

    const parsed = try std.json.parseFromSlice(CheckReport, gpa, capture.out(), .{});
    defer parsed.deinit();
    try std.testing.expect(!parsed.value.valid);
    try std.testing.expectEqual(CheckProblem.default_provider_missing, parsed.value.problem.?);
    try std.testing.expectEqual(@as(usize, 1), parsed.value.provider_instances);
    try std.testing.expectEqualStrings("wrok", parsed.value.default_provider.?);
    try std.testing.expectEqualStrings("a-model", parsed.value.default_model.?);
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

test "configuration load failures have stable problem classes" {
    try std.testing.expectEqual(CheckProblem.config_unreadable, problemForLoadError(error.ReadFailed));
    try std.testing.expectEqual(CheckProblem.config_invalid, problemForLoadError(error.InvalidConfig));
    try std.testing.expectEqual(CheckProblem.config_invalid, problemForLoadError(error.ConfigTooLarge));
}
