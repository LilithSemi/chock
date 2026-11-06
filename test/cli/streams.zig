//! The two streams of the real `chock` binary, read apart. Only a real process has a real fd 1 and fd 2.
//! The last test builds a project whose provider cannot be reached, so a real session starts and ends on its own.

const std = @import("std");
const builtin = @import("builtin");
const fake_provider = @import("fake_provider");
const chock_path = @import("chock_path").chock_path;
/// Found by `build.zig`. Empty when there is none, and the one test that needs it then skips.
const git_path = @import("chock_path").git_path;
/// The one thing read from the program's own source, so this compares the binary against the manifest.
const version_line = @import("chock_main").version_line;

const testing = std.testing;

/// A ULID in Crockford base32, which is what `session.isValidId` accepts.
const session_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

const Run = struct {
    out: []u8,
    err: []u8,
    code: u8,

    fn deinit(self: *Run, gpa: std.mem.Allocator) void {
        gpa.free(self.out);
        gpa.free(self.err);
    }
};

const ModelReport = struct {
    const Provider = struct {
        const Capabilities = struct {
            text: bool,
            tools: bool,
            reasoning: bool,
            cache_accounting: bool,
            provider_search: bool,
            images: bool,
        };

        const Catalogue = struct {
            status: []const u8,
            models: []const []const u8,
            http_status: ?u16,
            reason: ?[]const u8,
        };

        name: []const u8,
        kind: []const u8,
        is_default: bool,
        default_model: ?[]const u8,
        context_tokens: ?u64,
        capabilities: Capabilities,
        catalogue: ?Catalogue,
    };

    schema: []const u8,
    version: u32,
    default_provider: ?[]const u8,
    default_model: ?[]const u8,
    probed: bool,
    providers: []const Provider,
};

/// No command here can crash, and no `Exit` member uses this code.
const did_not_exit: u8 = 255;

fn codeOf(term: std.process.Child.Term) u8 {
    return switch (term) {
        .exited => |status| status,
        else => did_not_exit,
    };
}

fn runChock(
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) !Run {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, chock_path);
    try argv.appendSlice(gpa, args);

    const result = try std.process.run(gpa, io, .{
        .argv = argv.items,
        .environ_map = env,
    });
    return .{ .out = result.stdout, .err = result.stderr, .code = codeOf(result.term) };
}

/// Passes the same open file as both descriptors, so what comes back is the order the program really wrote in.
fn runOntoOneFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    env: *const std.process.Environ.Map,
    args: []const []const u8,
) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, chock_path);
    try argv.appendSlice(gpa, args);

    var file = try dir.createFile(io, name, .{ .read = true });
    defer file.close(io);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = env,
        .stdin = .ignore,
        .stdout = .{ .file = file },
        .stderr = .{ .file = file },
    });
    _ = try child.wait(io);

    return dir.readFileAlloc(io, name, gpa, .limited(1024 * 1024));
}

/// The environment is built from nothing, so a `NO_COLOR` or `TERM` of the running user cannot decide the answer.
const Sandbox = struct {
    tmp: testing.TmpDir,
    env: std.process.Environ.Map,
    root: []u8,

    fn init(gpa: std.mem.Allocator, io: std.Io) !Sandbox {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        // The child has its own working directory, so every path is absolute.
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try tmp.dir.realPath(io, &buffer);
        const root = try gpa.dupe(u8, buffer[0..length]);
        errdefer gpa.free(root);

        var env = std.process.Environ.Map.init(gpa);
        errdefer env.deinit();
        try env.put("HOME", root);
        try env.put("XDG_DATA_HOME", root);
        try env.put("XDG_CONFIG_HOME", root);
        try env.put("XDG_CACHE_HOME", root);
        try env.put("XDG_STATE_HOME", root);
        return .{ .tmp = tmp, .env = env, .root = root };
    }

    fn deinit(self: *Sandbox, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        self.env.deinit();
        self.tmp.cleanup();
    }

    fn writeConfig(self: *const Sandbox, gpa: std.mem.Allocator, io: std.Io, contents: []const u8) !void {
        const config_dir = try std.fmt.allocPrint(gpa, "{s}/chock", .{self.root});
        defer gpa.free(config_dir);
        try std.Io.Dir.cwd().createDirPath(io, config_dir);
        const config_path = try std.fmt.allocPrint(gpa, "{s}/config.zon", .{config_dir});
        defer gpa.free(config_path);
        var file = try std.Io.Dir.createFileAbsolute(io, config_path, .{
            .permissions = .fromMode(0o600),
        });
        defer file.close(io);
        try file.writeStreamingAll(io, contents);
    }
};

/// Read back out of the program's own message, rather than a second copy of `session.projectKey`.
fn sessionDirOf(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) ![]u8 {
    var told = try runChock(gpa, io, &box.env, &.{ "plan", "--project", box.root });
    defer told.deinit(gpa);

    const open = std.mem.indexOfScalar(u8, told.err, '(') orelse return error.NoDirectoryNamed;
    const close = std.mem.indexOfScalarPos(u8, told.err, open, ')') orelse return error.NoDirectoryNamed;
    return gpa.dupe(u8, told.err[open + 1 .. close]);
}

test "a diagnostic is on standard error while standard output stays empty" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "sessions", "--project", box.root });
    defer run.deinit(gpa);

    try testing.expectEqualStrings("", run.out);
    try testing.expect(std.mem.indexOf(u8, run.err, "no sessions") != null);
    try testing.expectEqual(@as(u8, 0), run.code);
}

test "the help a person asked for is on standard output and the help after a mistyped command is on standard error" {
    const gpa = testing.allocator;
    const io = testing.io;

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    var asked = try runChock(gpa, io, &env, &.{"--help"});
    defer asked.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, asked.out, "Usage: chock <command>") != null);
    try testing.expectEqualStrings("", asked.err);
    try testing.expectEqual(@as(u8, 0), asked.code);

    var mistyped = try runChock(gpa, io, &env, &.{"nonesuch"});
    defer mistyped.deinit(gpa);
    try testing.expectEqualStrings("", mistyped.out);
    try testing.expect(std.mem.indexOf(u8, mistyped.err, "there is no command named") != null);
    try testing.expect(std.mem.indexOf(u8, mistyped.err, "Usage: chock <command>") != null);
    try testing.expectEqual(@as(u8, 1), mistyped.code);
}

test "the documented configuration starter passes the real CLI check" {
    const gpa = testing.allocator;
    const io = testing.io;
    const Report = struct {
        schema: []const u8,
        version: u32,
        path: []const u8,
        valid: bool,
        problem: ?[]const u8,
        provider_instances: usize,
        default_provider: ?[]const u8,
        default_model: ?[]const u8,
    };
    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const expected_path = try std.fmt.allocPrint(gpa, "{s}/chock/config.zon", .{box.root});
    defer gpa.free(expected_path);

    var missing = try runChock(gpa, io, &box.env, &.{ "config", "check", "--format", "json" });
    defer missing.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), missing.code);
    try testing.expect(std.mem.indexOf(u8, missing.err, "there is no configuration") != null);
    const invalid = try std.json.parseFromSlice(Report, gpa, missing.out, .{});
    defer invalid.deinit();
    try testing.expectEqualStrings("chock.config-check", invalid.value.schema);
    try testing.expectEqual(@as(u32, 1), invalid.value.version);
    try testing.expectEqualStrings(expected_path, invalid.value.path);
    try testing.expect(!invalid.value.valid);
    try testing.expectEqualStrings("config_missing", invalid.value.problem.?);

    var path = try runChock(gpa, io, &box.env, &.{ "config", "path" });
    defer path.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), path.code);
    try testing.expectEqualStrings("", path.err);
    try testing.expectEqualStrings(expected_path, std.mem.trimEnd(u8, path.out, "\n"));

    try box.env.put("XDG_CONFIG_HOME", "relative/config");
    const fallback_path = try std.fmt.allocPrint(gpa, "{s}/.config/chock/config.zon", .{box.root});
    defer gpa.free(fallback_path);
    var fallback = try runChock(gpa, io, &box.env, &.{ "config", "path" });
    defer fallback.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), fallback.code);
    try testing.expectEqualStrings("", fallback.err);
    try testing.expectEqualStrings(fallback_path, std.mem.trimEnd(u8, fallback.out, "\n"));
    try box.env.put("XDG_CONFIG_HOME", box.root);

    var no_home = std.process.Environ.Map.init(gpa);
    defer no_home.deinit();
    var unknown = try runChock(gpa, io, &no_home, &.{ "config", "path" });
    defer unknown.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), unknown.code);
    try testing.expectEqualStrings("", unknown.out);
    try testing.expect(std.mem.indexOf(u8, unknown.err, "set HOME or an absolute XDG_CONFIG_HOME") != null);

    var unknown_models = try runChock(gpa, io, &no_home, &.{"models"});
    defer unknown_models.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), unknown_models.code);
    try testing.expectEqualStrings("", unknown_models.out);
    try testing.expect(std.mem.indexOf(u8, unknown_models.err, "set HOME or an absolute XDG_CONFIG_HOME") != null);

    for ([_][]const u8{ "daemon", "serve", "acp", "detach" }) |command| {
        var unknown_state = try runChock(gpa, io, &no_home, &.{command});
        defer unknown_state.deinit(gpa);
        try testing.expectEqual(@as(u8, 1), unknown_state.code);
        try testing.expectEqualStrings("", unknown_state.out);
        try testing.expect(std.mem.indexOf(u8, unknown_state.err, "set HOME or an absolute XDG_STATE_HOME") != null);
    }

    var example = try runChock(gpa, io, &box.env, &.{ "config", "example" });
    defer example.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), example.code);
    try testing.expectEqualStrings("", example.err);

    var initialized = try runChock(gpa, io, &box.env, &.{ "config", "init" });
    defer initialized.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), initialized.code);
    try testing.expectEqualStrings("", initialized.err);
    try testing.expect(std.mem.indexOf(u8, initialized.out, expected_path) != null);
    try testing.expect(std.mem.indexOf(u8, initialized.out, "run `chock config check`") != null);
    try testing.expect(std.mem.indexOf(u8, initialized.out, "`chock models --probe`") != null);
    try testing.expect(std.mem.indexOf(u8, initialized.out, "`chock doctor`") != null);

    var probe_env = try box.env.clone(gpa);
    defer probe_env.deinit();
    _ = probe_env.swapRemove("HOME");
    _ = probe_env.swapRemove("XDG_DATA_HOME");
    var unknown_data = try runChock(gpa, io, &probe_env, &.{ "models", "--probe" });
    defer unknown_data.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), unknown_data.code);
    try testing.expectEqualStrings("", unknown_data.out);
    try testing.expect(std.mem.indexOf(u8, unknown_data.err, "set HOME or an absolute XDG_DATA_HOME") != null);

    const saved = try std.Io.Dir.readFileAlloc(.cwd(), io, expected_path, gpa, .limited(1 << 16));
    defer gpa.free(saved);
    try testing.expectEqualStrings(example.out, saved);
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        const stat = try std.Io.Dir.cwd().statFile(io, expected_path, .{});
        try testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o7777);
    }

    var refused = try runChock(gpa, io, &box.env, &.{ "config", "init" });
    defer refused.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), refused.code);
    try testing.expectEqualStrings("", refused.out);
    try testing.expect(std.mem.indexOf(u8, refused.err, "already exists") != null);

    const still_saved = try std.Io.Dir.readFileAlloc(.cwd(), io, expected_path, gpa, .limited(1 << 16));
    defer gpa.free(still_saved);
    try testing.expectEqualStrings(example.out, still_saved);

    var checked = try runChock(gpa, io, &box.env, &.{ "config", "check", "--format", "json" });
    defer checked.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), checked.code);
    try testing.expectEqualStrings("", checked.err);

    const parsed = try std.json.parseFromSlice(Report, gpa, checked.out, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings(expected_path, parsed.value.path);
    try testing.expect(parsed.value.valid);
    try testing.expectEqual(@as(usize, 1), parsed.value.provider_instances);
    try testing.expectEqualStrings("local", parsed.value.default_provider.?);
    try testing.expectEqualStrings("glm4.7-flash:A3B", parsed.value.default_model.?);

    var models = try runChock(gpa, io, &box.env, &.{ "models", "--format", "json" });
    defer models.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), models.code);
    try testing.expectEqualStrings("", models.err);
    const model_report = try std.json.parseFromSlice(ModelReport, gpa, models.out, .{});
    defer model_report.deinit();
    try testing.expectEqualStrings("chock.models", model_report.value.schema);
    try testing.expectEqual(@as(u32, 1), model_report.value.version);
    try testing.expectEqualStrings("local", model_report.value.default_provider.?);
    try testing.expectEqualStrings("glm4.7-flash:A3B", model_report.value.default_model.?);
    try testing.expect(!model_report.value.probed);
    try testing.expectEqual(@as(usize, 1), model_report.value.providers.len);
    try testing.expectEqualStrings("local", model_report.value.providers[0].name);
    try testing.expect(model_report.value.providers[0].is_default);
    try testing.expect(model_report.value.providers[0].capabilities.text);
    try testing.expect(model_report.value.providers[0].catalogue == null);
    try testing.expect(std.mem.indexOf(u8, models.out, "127.0.0.1") == null);

    var conflict = try runChock(gpa, io, &box.env, &.{
        "login", "--provider", "aiand", "--name", "local", "--password-method", "stdin",
    });
    defer conflict.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), conflict.code);
    try testing.expect(std.mem.indexOf(u8, conflict.err, "configuration declares \"local\" as kind openai-compat") != null);
    try testing.expect(std.mem.indexOf(u8, conflict.err, "nothing was given") == null);
    try testing.expect(std.mem.indexOf(u8, conflict.out, "asking") == null);

    try box.writeConfig(gpa, io,
        \\.{
        \\    .providers = .{ .{ .name = "work", .kind = "aiand" } },
        \\    .defaults = .{ .provider = "wrok", .model = "a-model" },
        \\}
    );
    var invalid_default = try runChock(gpa, io, &box.env, &.{ "config", "check", "--format", "json" });
    defer invalid_default.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), invalid_default.code);
    try testing.expect(std.mem.indexOf(u8, invalid_default.err, "wrok") != null);
    const invalid_report = try std.json.parseFromSlice(Report, gpa, invalid_default.out, .{});
    defer invalid_report.deinit();
    try testing.expect(!invalid_report.value.valid);
    try testing.expectEqualStrings("default_provider_missing", invalid_report.value.problem.?);
    try testing.expectEqualStrings("wrok", invalid_report.value.default_provider.?);
    try testing.expectEqualStrings("a-model", invalid_report.value.default_model.?);

    try box.writeConfig(gpa, io, ".{ .providers = ");
    var malformed = try runChock(gpa, io, &box.env, &.{ "config", "check", "--format", "json" });
    defer malformed.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), malformed.code);
    const malformed_report = try std.json.parseFromSlice(Report, gpa, malformed.out, .{});
    defer malformed_report.deinit();
    try testing.expect(!malformed_report.value.valid);
    try testing.expectEqualStrings("config_invalid", malformed_report.value.problem.?);

    const oversized_bytes = try gpa.alloc(u8, 256 * 1024 + 1);
    defer gpa.free(oversized_bytes);
    @memset(oversized_bytes, ' ');
    try box.writeConfig(gpa, io, oversized_bytes);
    var oversized = try runChock(gpa, io, &box.env, &.{ "config", "check", "--format", "json" });
    defer oversized.deinit(gpa);
    try testing.expectEqual(@as(u8, 1), oversized.code);
    try testing.expect(std.mem.indexOf(u8, oversized.err, "exceeds the 256 KiB configuration limit") != null);
    const oversized_report = try std.json.parseFromSlice(Report, gpa, oversized.out, .{});
    defer oversized_report.deinit();
    try testing.expect(!oversized_report.value.valid);
    try testing.expectEqualStrings("config_too_large", oversized_report.value.problem.?);
}

test "a JSON model probe stays one document and reports the sorted remote catalogue" {
    const gpa = testing.allocator;
    const io = testing.io;

    const body = "{\"object\":\"list\",\"data\":[{\"id\":\"zeta\"},{\"id\":\"alpha\"}]}";
    const head = std.fmt.comptimePrint(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{body.len},
    );
    var provider = try fake_provider.FakeProvider.start(gpa, io, .{
        .head = head,
        .body = &.{.{ .bytes = body }},
    });

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    var base_buffer: [96]u8 = undefined;
    const config = try std.fmt.allocPrint(gpa,
        \\.{{
        \\    .providers = .{{
        \\        .{{ .name = "local", .kind = "openai-compat",
        \\           .base_url = "{s}/v1", .context_tokens = 65536 }},
        \\    }},
        \\    .defaults = .{{ .provider = "local", .model = "alpha" }},
        \\}}
        \\
    , .{provider.baseUrl(&base_buffer)});
    defer gpa.free(config);
    try box.writeConfig(gpa, io, config);

    var models = try runChock(gpa, io, &box.env, &.{ "models", "--probe", "--format", "json" });
    defer models.deinit(gpa);
    provider.join();
    defer provider.deinit();

    try testing.expectEqual(@as(u8, 0), models.code);
    try testing.expectEqualStrings("", models.err);
    try testing.expect(std.mem.indexOf(u8, provider.captured.head, "GET /v1/models") != null);
    const report = try std.json.parseFromSlice(ModelReport, gpa, models.out, .{});
    defer report.deinit();
    try testing.expect(report.value.probed);
    const catalogue = report.value.providers[0].catalogue.?;
    try testing.expectEqualStrings("available", catalogue.status);
    try testing.expectEqual(@as(usize, 2), catalogue.models.len);
    try testing.expectEqualStrings("alpha", catalogue.models[0]);
    try testing.expectEqualStrings("zeta", catalogue.models[1]);
    try testing.expect(catalogue.http_status == null);
    try testing.expect(catalogue.reason == null);
}

test "a failed JSON model probe returns a document and a fault exit" {
    const gpa = testing.allocator;
    const io = testing.io;

    const loopback = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var unused = try loopback.listen(io, .{ .reuse_address = true });
    const port = unused.socket.address.getPort();
    unused.deinit(io);

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    const config = try std.fmt.allocPrint(gpa,
        \\.{{
        \\    .providers = .{{
        \\        .{{ .name = "offline", .kind = "openai-compat",
        \\           .base_url = "http://127.0.0.1:{d}/v1" }},
        \\    }},
        \\    .defaults = .{{ .provider = "offline", .model = "example" }},
        \\}}
        \\
    , .{port});
    defer gpa.free(config);
    try box.writeConfig(gpa, io, config);

    var models = try runChock(gpa, io, &box.env, &.{ "models", "--probe", "--format", "json" });
    defer models.deinit(gpa);

    try testing.expect(models.code != 0);
    try testing.expect(std.mem.indexOf(u8, models.err, "provider could not be reached") != null);
    const report = try std.json.parseFromSlice(ModelReport, gpa, models.out, .{});
    defer report.deinit();
    try testing.expect(report.value.probed);
    try testing.expectEqual(@as(usize, 1), report.value.providers.len);
    const catalogue = report.value.providers[0].catalogue.?;
    try testing.expectEqualStrings("not_reached", catalogue.status);
    try testing.expectEqual(@as(usize, 0), catalogue.models.len);
    try testing.expect(catalogue.http_status == null);
    try testing.expect(catalogue.reason != null);
    try testing.expect(catalogue.reason.?.len != 0);
}

test "an empty configuration cannot pass a provider probe" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    try box.writeConfig(gpa, io, ".{}\n");

    var models = try runChock(gpa, io, &box.env, &.{ "models", "--probe", "--format", "json" });
    defer models.deinit(gpa);

    try testing.expectEqual(@as(u8, 2), models.code);
    try testing.expect(std.mem.indexOf(u8, models.err, "no provider instance to probe") != null);
    const report = try std.json.parseFromSlice(ModelReport, gpa, models.out, .{});
    defer report.deinit();
    try testing.expect(report.value.probed);
    try testing.expectEqual(@as(usize, 0), report.value.providers.len);
    try testing.expect(report.value.default_provider == null);
}

test "a compatible provider rejection names the credential command" {
    const gpa = testing.allocator;
    const io = testing.io;

    const head = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    var provider = try fake_provider.FakeProvider.start(gpa, io, .{ .head = head });

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    var base_buffer: [96]u8 = undefined;
    const base_url = try std.fmt.allocPrint(gpa, "{s}/v1", .{provider.baseUrl(&base_buffer)});
    defer gpa.free(base_url);
    const config = try std.fmt.allocPrint(gpa,
        \\.{{
        \\    .providers = .{{
        \\        .{{ .name = "private", .kind = "openai-compat", .base_url = "{s}" }},
        \\    }},
        \\    .defaults = .{{ .provider = "private", .model = "example" }},
        \\}}
        \\
    , .{base_url});
    defer gpa.free(config);
    try box.writeConfig(gpa, io, config);

    var models = try runChock(gpa, io, &box.env, &.{ "models", "--probe" });
    defer models.deinit(gpa);
    provider.join();
    defer provider.deinit();

    try testing.expectEqual(@as(u8, 2), models.code);
    try testing.expect(std.mem.indexOf(u8, models.out, "private  (default provider)") != null);
    try testing.expect(std.mem.indexOf(u8, models.err, "status 401") != null);
    const wanted = try std.fmt.allocPrint(gpa, "chock login --provider openai-compat={s} --name private", .{base_url});
    defer gpa.free(wanted);
    try testing.expect(std.mem.indexOf(u8, models.err, wanted) != null);
}

test "a piped stream gets no escape sequence, and --color=always still paints one" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    // Both streams are pipes here, because `std.process.run` gives them pipes.
    try box.env.put("TERM", "xterm-256color");

    var piped = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer piped.deinit(gpa);
    try testing.expect(piped.err.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);

    var loud = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=always" });
    defer loud.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, loud.err, 0x1b) != null);
    try testing.expect(std.mem.indexOf(u8, loud.err, "there is no command named") != null);

    try box.env.put("CLICOLOR_FORCE", "1");
    var forced = try runChock(gpa, io, &box.env, &.{ "nonesuch", "--color=never" });
    defer forced.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, forced.err, 0x1b) == null);

    var encouraged = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer encouraged.deinit(gpa);
    try testing.expect(std.mem.indexOfScalar(u8, encouraged.err, 0x1b) != null);

    var rows = try runChock(gpa, io, &box.env, &.{ "--help", "--color=always" });
    defer rows.deinit(gpa);
    try testing.expect(rows.out.len != 0);
    try testing.expect(std.mem.indexOfScalar(u8, rows.out, 0x1b) == null);
}

test "standard output is flushed before standard error, so one file holds them in the written order" {
    // Standard output is buffered and standard error is not, so `tty.print` must call `flushOut()` first.
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // A line with no newline after it is what a crash mid write leaves.
    try std.Io.Dir.cwd().createDirPath(io, session_dir);
    const log_path = try std.fmt.allocPrint(gpa, "{s}/{s}.jsonl", .{ session_dir, session_id });
    defer gpa.free(log_path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = log_path,
        .data = "{\"chock_log\":1}\n{\"id\":0,\"at_ms\":0,\"event\":{\"session\":{\"start\"",
    });

    const both = try runOntoOneFile(
        gpa,
        io,
        box.tmp.dir,
        "one-terminal.txt",
        &box.env,
        &.{ "plan", "show", session_id, "--project", box.root },
    );
    defer gpa.free(both);

    const row = std.mem.indexOf(u8, both, "kept no task list") orelse {
        try testing.expectEqualStrings("kept no task list", both);
        return error.NoRowWritten;
    };
    const warning = std.mem.indexOf(u8, both, "ends mid write") orelse {
        try testing.expectEqualStrings("ends mid write", both);
        return error.NoWarningWritten;
    };

    try testing.expect(row < warning);

    const header = std.mem.indexOf(u8, both, session_id) orelse return error.NoHeaderWritten;
    try testing.expect(header < row);
}

test "every command still exits with the code it did, including the refusals" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    const cases = [_]struct {
        args: []const []const u8,
        want: u8,
        why: []const u8,
    }{
        .{ .args = &.{"--version"}, .want = 0, .why = "a version was asked for and given" },
        .{ .args = &.{"help"}, .want = 0, .why = "help was asked for and given" },
        .{ .args = &.{"nonesuch"}, .want = 1, .why = "there is no such command" },
        // The flag comes after the command, since `main` reads the command first.
        .{ .args = &.{ "sessions", "--color=maybe" }, .want = 1, .why = "--color took a value it does not have" },
        .{ .args = &.{"askpass"}, .want = 1, .why = "the helper takes one prompt and was given none" },
        .{ .args = &.{ "doctor", "--help" }, .want = 0, .why = "help was asked for and given" },
        .{ .args = &.{ "doctor", "list" }, .want = 1, .why = "chock doctor takes no subcommand" },
    };

    for (cases) |case| {
        var run = try runChock(gpa, io, &box.env, case.args);
        defer run.deinit(gpa);
        var wanted_buffer: [160]u8 = undefined;
        var got_buffer: [160]u8 = undefined;
        const wanted = try std.fmt.bufPrint(
            &wanted_buffer,
            "chock {s} exits {d}, because {s}",
            .{ case.args[0], case.want, case.why },
        );
        const got = try std.fmt.bufPrint(
            &got_buffer,
            "chock {s} exits {d}, because {s}",
            .{ case.args[0], run.code, case.why },
        );
        try testing.expectEqualStrings(wanted, got);
    }

    var did_nothing = try runChock(gpa, io, &box.env, &.{ "cache", "clear", "--project", box.root });
    defer did_nothing.deinit(gpa);
    try testing.expect(did_nothing.code != 0);
    try testing.expectEqualStrings("", did_nothing.out);
}

/// Spelled here rather than imported, so this file holds nothing of the built binary's own source.
const alt_screen_on = "\x1b[?1049h";

const Project = struct {
    path: []u8,

    /// Port 1 on the loopback address, below the range an unprivileged program can bind.
    const dead_provider = "http://127.0.0.1:1/v1";

    fn make(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox) !Project {
        return makeWithProvider(gpa, io, box, dead_provider);
    }

    fn makeWithProvider(gpa: std.mem.Allocator, io: std.Io, box: *Sandbox, provider_url: []const u8) !Project {
        // `Sandbox` builds its environment from nothing, so the workspace builder would find no `git`.
        try box.env.put("PATH", std.fs.path.dirname(git_path) orelse "/usr/bin");

        // Readable by nobody else, which `chock-auth` insists on for a token.
        const config = try std.fmt.allocPrint(gpa,
            \\.{{
            \\    .providers = .{{
            \\        .{{ .name = "dead", .kind = "openai-compat", .base_url = "{s}",
            \\           .context_tokens = 65536, .token = "sk-not-a-real-key" }},
            \\    }},
            \\    .defaults = .{{ .provider = "dead", .model = "no-such-model" }},
            \\}}
            \\
        , .{provider_url});
        defer gpa.free(config);
        try box.writeConfig(gpa, io, config);

        const path = try std.fmt.allocPrint(gpa, "{s}/project", .{box.root});
        errdefer gpa.free(path);
        try std.Io.Dir.cwd().createDirPath(io, path);
        const readme = try std.fmt.allocPrint(gpa, "{s}/README.md", .{path});
        defer gpa.free(readme);
        try std.Io.Dir.cwd().writeFile(io, .{
            .sub_path = readme,
            .data = "a project with one commit\n",
        });

        // The identity is on the command line, so no git configuration is read.
        try git(gpa, io, git_path, &box.env, path, &.{ "init", "--quiet", "." });
        try git(gpa, io, git_path, &box.env, path, &.{ "add", "-A" });
        try git(gpa, io, git_path, &box.env, path, &.{
            "-c",     "user.email=test@example.invalid",
            "-c",     "user.name=test",
            "commit", "--quiet",
            "-m",     "one",
        });
        return .{ .path = path };
    }

    fn deinit(self: *Project, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
    }

    fn git(
        gpa: std.mem.Allocator,
        io: std.Io,
        program: []const u8,
        env: *const std.process.Environ.Map,
        cwd: []const u8,
        args: []const []const u8,
    ) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.append(gpa, program);
        try argv.appendSlice(gpa, args);
        const result = std.process.run(gpa, io, .{
            .argv = argv.items,
            .environ_map = env,
            .cwd = .{ .path = cwd },
        }) catch |err| {
            try testing.expectEqualStrings(args[0], @errorName(err));
            return err;
        };
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        if (codeOf(result.term) != 0) {
            try testing.expectEqualStrings("a git subcommand that exits zero", args[0]);
            return error.GitFailed;
        }
    }
};

test "chock run never takes the alternate screen, whatever the colour flags say" {
    // The session builds a git worktree, so a machine with no `git` skips rather than reports success.
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    try box.env.put("TERM", "xterm-256color");

    var project = try Project.make(gpa, io, &box);
    defer project.deinit(gpa);

    for ([_][]const []const u8{
        &.{ "run", "--project", project.path, "--", "fix", "the", "parser" },
        &.{ "run", "--color=always", "--project", project.path, "--", "fix", "the", "parser" },
    }) |args| {
        var one = try runChock(gpa, io, &box.env, args);
        defer one.deinit(gpa);

        try testing.expect(std.mem.indexOf(u8, one.out, "chock: session ended") != null);

        try testing.expect(std.mem.indexOf(u8, one.out, alt_screen_on) == null);
        try testing.expect(std.mem.indexOf(u8, one.err, alt_screen_on) == null);
    }
}

test "chock run JSON mode writes one result object and keeps diagnostics on standard error" {
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    var project = try Project.make(gpa, io, &box);
    defer project.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{
        "run", "--output", "json", "--project", project.path, "--", "fix", "the", "parser",
    });
    defer run.deinit(gpa);

    try testing.expect(run.out.len != 0);
    try testing.expect(run.out[run.out.len - 1] == '\n');
    try testing.expect(std.mem.count(u8, run.out, "\n") == 1);
    try testing.expect(std.mem.indexOf(u8, run.out, "chock:") == null);
    try testing.expect(std.mem.indexOf(u8, run.err, "model no-such-model via dead") != null);

    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, run.out, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try testing.expectEqualStrings("chock.run-result", object.get("schema").?.string);
    try testing.expectEqual(@as(i64, 1), object.get("version").?.integer);
    try testing.expectEqual(@as(i64, run.code), object.get("exit_code").?.integer);
    try testing.expect(object.get("session_id").? == .string);
    try testing.expect(object.get("audit_log").? == .string);
    try testing.expect(object.get("usage").? == .object);
    try testing.expect(object.get("workspace").? == .object);

    var streamed = try runChock(gpa, io, &box.env, &.{
        "run", "--output", "jsonl", "--project", project.path, "--", "fix", "the", "parser",
    });
    defer streamed.deinit(gpa);
    try testing.expect(streamed.out[streamed.out.len - 1] == '\n');

    var saw_event = false;
    var saw_result = false;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, streamed.out, "\n"), '\n');
    while (lines.next()) |line| {
        const item = try std.json.parseFromSlice(std.json.Value, gpa, line, .{});
        defer item.deinit();
        const schema = item.value.object.get("schema").?.string;
        if (std.mem.eql(u8, schema, "chock.run-event")) {
            try testing.expect(!saw_result);
            saw_event = true;
            try testing.expect(item.value.object.get("event_id").? == .integer);
            try testing.expect(item.value.object.get("event").? == .object);
        } else {
            try testing.expectEqualStrings("chock.run-result", schema);
            saw_result = true;
        }
    }
    try testing.expect(saw_event);
    try testing.expect(saw_result);
}

test "eval records once and replays after its provider is gone" {
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    const response_head =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: text/event-stream\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Connection: close\r\n\r\n";
    const content = fake_provider.httpChunk(
        "data: {\"choices\":[{\"index\":0,\"finish_reason\":null,\"delta\":{\"content\":\"Done.\"}}]}\n\n",
    );
    const stopped = fake_provider.httpChunk(
        "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\",\"delta\":{}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n",
    );
    const done = fake_provider.httpChunk("data: [DONE]\n\n");
    var provider = try fake_provider.FakeProvider.start(gpa, io, .{
        .head = response_head,
        .body = &.{
            .{ .bytes = content },
            .{ .bytes = stopped },
            .{ .bytes = done },
            .{ .bytes = fake_provider.last_chunk },
        },
    });

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    var base_url_buffer: [96]u8 = undefined;
    var url_buffer: [128]u8 = undefined;
    const provider_url = try std.fmt.bufPrint(&url_buffer, "{s}/v1", .{provider.baseUrl(&base_url_buffer)});
    var project = try Project.makeWithProvider(gpa, io, &box, provider_url);
    defer project.deinit(gpa);

    const spec_path = try std.fmt.allocPrint(gpa, "{s}/case.zon", .{box.root});
    defer gpa.free(spec_path);
    const capture_path = try std.fmt.allocPrint(gpa, "{s}/capture.json", .{box.root});
    defer gpa.free(capture_path);
    const recorded_report = try std.fmt.allocPrint(gpa, "{s}/recorded.json", .{box.root});
    defer gpa.free(recorded_report);
    const replayed_report = try std.fmt.allocPrint(gpa, "{s}/replayed.json", .{box.root});
    defer gpa.free(replayed_report);
    const trajectory_path = try std.fmt.allocPrint(gpa, "{s}/trajectory.json", .{box.root});
    defer gpa.free(trajectory_path);
    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = spec_path,
        .data =
        \\.{
        \\    .schema = "chock.eval",
        \\    .version = 1,
        \\    .name = "real replay",
        \\    .task = "Answer briefly.",
        \\    .provider = "dead",
        \\    .model = "no-such-model",
        \\    .expect = .{ .end_reason = "finished", .max_turns = 1 },
        \\}
        \\
        ,
    });

    var recorded = try runChock(gpa, io, &box.env, &.{
        "eval",          "run",        spec_path,  "--project",     project.path,
        "--capture",     capture_path, "--report", recorded_report, "--trajectory",
        trajectory_path, "--format",   "json",
    });
    defer recorded.deinit(gpa);
    provider.join();
    try testing.expect(provider.captured.body.len != 0);
    provider.deinit();
    try testing.expectEqual(@as(u8, 0), recorded.code);

    const capture = try std.Io.Dir.cwd().readFileAlloc(io, capture_path, gpa, .limited(1024 * 1024));
    defer gpa.free(capture);
    try testing.expect(std.mem.indexOf(u8, capture, "chock.eval-fixture") != null);
    try testing.expect(std.mem.indexOf(u8, capture, "sk-not-a-real-key") == null);

    var replayed = try runChock(gpa, io, &box.env, &.{
        "eval",      "replay",     spec_path,  "--project",     project.path,
        "--capture", capture_path, "--report", replayed_report, "--format",
        "json",
    });
    defer replayed.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), replayed.code);

    var compared = try runChock(gpa, io, &box.env, &.{
        "eval", "compare", recorded_report, replayed_report, "--format", "json",
    });
    defer compared.deinit(gpa);
    try testing.expectEqual(@as(u8, 0), compared.code);
    try testing.expect(std.mem.indexOf(u8, compared.out, "\"passed\":true") != null);

    const trajectory = try std.Io.Dir.cwd().readFileAlloc(io, trajectory_path, gpa, .limited(2 * 1024 * 1024));
    defer gpa.free(trajectory);
    try testing.expect(std.mem.indexOf(u8, trajectory, "chock.rl-trajectory") != null);
    try testing.expect(std.mem.indexOf(u8, trajectory, "\"trainable\":false") != null);
}

/// Three files rather than pipes, since `std.process.RunOptions` has no way to give a child its standard input.
fn runChockOnStdin(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    env: *const std.process.Environ.Map,
    cwd: []const u8,
    message: []const u8,
    args: []const []const u8,
) !Run {
    // Absolute, because the child starts somewhere else, and `chock_path` is relative to the suite's own directory.
    var suite_dir = try std.Io.Dir.cwd().openDir(io, ".", .{});
    defer suite_dir.close(io);
    var here: [std.fs.max_path_bytes]u8 = undefined;
    const length = try suite_dir.realPath(io, &here);
    const program = try std.fs.path.resolve(gpa, &.{ here[0..length], chock_path });
    defer gpa.free(program);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, program);
    try argv.appendSlice(gpa, args);

    try dir.writeFile(io, .{ .sub_path = "message.txt", .data = message });
    const message_file = try dir.openFile(io, "message.txt", .{});
    defer message_file.close(io);
    var out_file = try dir.createFile(io, "stdout.txt", .{ .read = true });
    defer out_file.close(io);
    var err_file = try dir.createFile(io, "stderr.txt", .{ .read = true });
    defer err_file.close(io);

    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = env,
        .cwd = .{ .path = cwd },
        .stdin = .{ .file = message_file },
        .stdout = .{ .file = out_file },
        .stderr = .{ .file = err_file },
    }) catch |err| {
        try testing.expectEqualStrings(program, @errorName(err));
        return err;
    };
    const term = try child.wait(io);

    const out = try dir.readFileAlloc(io, "stdout.txt", gpa, .limited(1024 * 1024));
    errdefer gpa.free(out);
    const err = try dir.readFileAlloc(io, "stderr.txt", gpa, .limited(1024 * 1024));
    return .{ .out = out, .err = err, .code = codeOf(term) };
}

test "a message on standard input runs a session with no display and no escape byte" {
    if (git_path.len == 0) return error.SkipZigTest;

    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);
    try box.env.put("TERM", "xterm-256color");

    var project = try Project.make(gpa, io, &box);
    defer project.deinit(gpa);

    // No arguments, because bare `chock` is the command, so the project is named by the working directory.
    var piped = try runChockOnStdin(
        gpa,
        io,
        box.tmp.dir,
        &box.env,
        project.path,
        "fix the parser\n",
        &.{},
    );
    defer piped.deinit(gpa);

    try testing.expect(std.mem.indexOf(u8, piped.out, "chock: session ended") != null);
    try testing.expect(std.mem.indexOf(u8, piped.err, "Usage: chock <command>") == null);

    try testing.expect(std.mem.indexOfScalar(u8, piped.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, piped.err, 0x1b) == null);

    const header = "model no-such-model via dead";
    try testing.expect(std.mem.indexOf(u8, piped.err, header) != null);
    try testing.expect(std.mem.indexOf(u8, piped.out, header) == null);
}

/// Read rather than listed, so this tracks `chock run` instead of holding a second copy of its options.
fn optionsRunAdvertises(gpa: std.mem.Allocator, text: []const u8) ![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(gpa);

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const body = std.mem.trimStart(u8, line, " ");
        // Indented, so a prose sentence opening with a dash is not an entry.
        if (body.len == line.len) continue;
        if (!std.mem.startsWith(u8, body, "--")) continue;

        var end: usize = 0;
        while (end < body.len and body[end] != '=' and body[end] != ' ') end += 1;
        try found.append(gpa, body[0..end]);
    }
    return found.toOwnedSlice(gpa);
}

test "every option chock run advertises is an option on bare chock, and not a missing command" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var help = try runChock(gpa, io, &box.env, &.{ "run", "--help" });
    defer help.deinit(gpa);
    const options = try optionsRunAdvertises(gpa, help.out);
    defer gpa.free(options);

    try testing.expect(options.len >= 5);

    for (options) |option| {
        var bare = try runChock(gpa, io, &box.env, &.{option});
        defer bare.deinit(gpa);
        var wanted: [96]u8 = undefined;
        var got: [96]u8 = undefined;
        const said_no_command = std.mem.indexOf(u8, bare.err, "there is no command named") != null;
        try testing.expectEqualStrings(
            try std.fmt.bufPrint(&wanted, "chock {s} is an option", .{option}),
            try std.fmt.bufPrint(&got, "chock {s} is {s}", .{
                option,
                if (said_no_command) "read as a command name" else "an option",
            }),
        );
    }
}

test "an option nobody knows gets the same answer from bare chock as from chock run" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var bare = try runChock(gpa, io, &box.env, &.{"--no-such-option"});
    defer bare.deinit(gpa);
    var through_run = try runChock(gpa, io, &box.env, &.{ "run", "--no-such-option" });
    defer through_run.deinit(gpa);

    try testing.expectEqualStrings(through_run.err, bare.err);
    try testing.expectEqual(through_run.code, bare.code);
    try testing.expect(std.mem.indexOf(u8, bare.err, "--no-such-option") != null);
    try testing.expect(std.mem.indexOf(u8, bare.err, "there is no command named") == null);
}

test "the two words chock answers itself still open with a dash and are still not options" {
    // `--help` and `--version` are `src/main.zig`'s own, so the rule has to let them through.
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var helped = try runChock(gpa, io, &box.env, &.{"--help"});
    defer helped.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, helped.out, "Usage: chock <command>") != null);
    try testing.expectEqual(@as(u8, 0), helped.code);

    var versioned = try runChock(gpa, io, &box.env, &.{"--version"});
    defer versioned.deinit(gpa);
    try testing.expectEqualStrings(version_line ++ "\n", versioned.out);
    try testing.expectEqualStrings("", versioned.err);
    try testing.expectEqual(@as(u8, 0), versioned.code);

    var missing = try runChock(gpa, io, &box.env, &.{"nonesuch"});
    defer missing.deinit(gpa);
    try testing.expect(std.mem.indexOf(u8, missing.err, "there is no command named") != null);
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) return;
    return sayWhatItSaid(haystack, needle);
}

fn expectMissing(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) return;
    return sayWhatItSaid(haystack, needle);
}

/// `expectEqualStrings` prints both sides, so the report a real process wrote lands inside the failure.
fn sayWhatItSaid(haystack: []const u8, needle: []const u8) !void {
    try testing.expectEqualStrings(needle, haystack);
    return error.TestUnexpectedResult;
}

const doctor_refusal = "a session cannot start here";

const doctor_first_run_heading = "Before a first run";

const doctor_layers_heading = "Sandbox layers";

/// The names differ by platform, since a user namespace, Landlock and seccomp are Linux calls macOS has none of.
const doctor_layer_names: []const []const u8 = switch (builtin.os.tag) {
    .macos => &.{
        "seatbelt",
        "network",
        "signal reach",
        "ipc",
        "rlimit floor",
        "memory ceiling",
        "mapped memory",
        "process count",
        "disk cap tmpfs",
        "syscall filter",
        "process list",
        "workspace mount",
        "tool call",
    },
    else => &.{
        "user namespace",
        "mount namespace",
        "pid namespace",
        "ipc namespace",
        "net namespace",
        "landlock",
        "seccomp",
        "write^execute",
        "pidfd",
        "cgroup v2",
        "overlayfs",
        "disk cap tmpfs",
    },
};

const doctor_absent_layer_names: []const []const u8 = switch (builtin.os.tag) {
    .macos => &.{ "seatbelt", "rlimit floor", "signal reach" },
    else => &.{ "landlock", "seccomp", "write^execute" },
};

test "chock doctor refuses a machine that cannot run a session, with a code a script can read" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    // 2 is `Exit.faulted`: a first run cannot work here.
    try testing.expectEqual(@as(u8, 2), run.code);
    try testing.expect(run.code != 0);
    try testing.expect(run.code != 1);

    try testing.expectEqualStrings(version_line, std.mem.sliceTo(run.out, '\n'));

    try expectContains(run.out, doctor_first_run_heading);
    try expectContains(run.out, "credential");
    try expectContains(run.out, "workspace space");

    try expectContains(run.err, doctor_refusal);
    try expectMissing(run.out, doctor_refusal);

    try testing.expect(std.mem.indexOfScalar(u8, run.out, 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, run.err, 0x1b) == null);

    const counted = std.mem.count(u8, run.out, "BLOCKED");
    try testing.expect(counted >= 1);

    // The word appears in no sentence, so counting it counts the column.
    const marker = "Rows that stop a first run: ";
    const at = std.mem.indexOf(u8, run.err, marker).? + marker.len;
    const footer = try std.fmt.parseInt(usize, std.mem.sliceTo(run.err[at..], ' '), 10);
    try testing.expectEqual(footer, counted);
}

test "chock doctor JSON is one versioned report with the same verdict" {
    const gpa = testing.allocator;
    const io = testing.io;
    const Report = struct {
        const Row = struct {
            section: []const u8,
            name: []const u8,
            status: []const u8,
            means: ?[]const u8,
            why: ?[]const u8,
            fix: ?[]const u8,
        };

        schema: []const u8,
        version: u32,
        project: []const u8,
        verdict: []const u8,
        can_start: bool,
        sandbox_driver: []const u8,
        not_on_rows: usize,
        blocking_rows: usize,
        driver_refusal: ?[]const u8,
        rows: []const Row,
    };

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root, "--format", "json" });
    defer run.deinit(gpa);

    const parsed = try std.json.parseFromSlice(Report, gpa, run.out, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("chock.doctor", parsed.value.schema);
    try testing.expectEqual(@as(u32, 1), parsed.value.version);
    try testing.expectEqualStrings(box.root, parsed.value.project);
    try testing.expectEqualStrings("blocked", parsed.value.verdict);
    try testing.expect(!parsed.value.can_start);
    try testing.expectEqual(@as(u8, 2), run.code);
    try expectContains(run.err, doctor_refusal);
    try testing.expect(parsed.value.rows.len != 0);

    var not_on: usize = 0;
    var blocking: usize = 0;
    var saw_sandbox = false;
    var saw_first_run = false;
    for (parsed.value.rows) |row| {
        if (!std.mem.eql(u8, row.status, "ok")) not_on += 1;
        if (std.mem.eql(u8, row.status, "blocked")) blocking += 1;
        saw_sandbox = saw_sandbox or std.mem.eql(u8, row.section, "sandbox");
        saw_first_run = saw_first_run or std.mem.eql(u8, row.section, "first_run");
    }
    try testing.expectEqual(parsed.value.not_on_rows, not_on);
    try testing.expectEqual(parsed.value.blocking_rows, blocking);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, run.out, "\n"));
    try testing.expect(saw_first_run);
    if (std.mem.eql(u8, parsed.value.sandbox_driver, "none")) {
        try testing.expect(parsed.value.driver_refusal != null);
        try testing.expect(!saw_sandbox);
    } else {
        try testing.expect(parsed.value.driver_refusal == null);
        try testing.expect(saw_sandbox);
    }
}

test "chock doctor prints a column of layers or the one sentence about the driver, never both" {
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    const has_layers = std.mem.indexOf(u8, run.out, doctor_layers_heading) != null;
    const refuses_outright = std.mem.indexOf(u8, run.err, "applies no layer") != null;
    try testing.expect(has_layers != refuses_outright);

    if (has_layers) {
        for (doctor_layer_names) |name| {
            try expectContains(run.out, name);
        }
    } else {
        try expectContains(run.err, "Sandbox.spawn refuses");
        try expectContains(run.err, "permanent");
        // This host's own names: a Linux name on a Mac would be absent anyway.
        for (doctor_absent_layer_names) |name| {
            try expectMissing(run.out, name);
        }
    }
}

test "chock doctor leaves nothing of its own behind" {
    // The kernel makes the overlay's own `work/work` with mode 0, which stops a plain `deleteTree` halfway.
    const gpa = testing.allocator;
    const io = testing.io;

    var box = try Sandbox.init(gpa, io);
    defer box.deinit(gpa);

    var run = try runChock(gpa, io, &box.env, &.{ "doctor", "--project", box.root });
    defer run.deinit(gpa);

    const session_dir = try sessionDirOf(gpa, io, &box);
    defer gpa.free(session_dir);

    // The probe tree carries the running process's id, so this test cannot name it.
    var opened = try std.Io.Dir.openDirAbsolute(io, session_dir, .{ .iterate = true });
    defer opened.close(io);
    var it = opened.iterate();
    while (try it.next(io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "doctor.probe")) continue;
        try testing.expectEqualStrings("", entry.name);
    }
}
