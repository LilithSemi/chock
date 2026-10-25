//! `chock models`: the configured provider/model choices and what their
//! adapters can faithfully carry. The default is offline; `--probe` opts into
//! credential lookup and provider catalogue requests.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_provider = @import("chock-provider");

const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const usage_text =
    \\Usage: chock models [--provider <name>] [options]
    \\
    \\Lists configured provider instances, the configured default model and context
    \\limit, and the features Chock's adapter can carry. It reads no credential and
    \\does not contact a provider. A listed feature is therefore a local guarantee,
    \\not a claim that every model behind an endpoint implements it.
    \\
    \\Options:
    \\  --provider <name>  Show one configured provider instance.
    \\  --probe             Read credentials and query provider model catalogues.
    \\
++ tty.options_text;

const Options = struct {
    provider: ?[]const u8 = null,
    probe: bool = false,
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

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    const config_dir = chock_auth.paths.configDir(arena, &env) catch |err| {
        tty.print(.err, "chock models: the configuration directory is unknown: {t}\n", .{err});
        return Exit.usage.code();
    };

    var diag: ?chock_auth.config.Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    var config = chock_auth.config.load(gpa, io, config_dir, &diag) catch |err| switch (err) {
        error.NoConfigFile => {
            tty.print(.err, "chock models: there is no configuration at {s}/{s}\n", .{
                config_dir, chock_auth.config.file_name,
            });
            return Exit.usage.code();
        },
        else => {
            if (diag) |*one| {
                tty.print(.err, "chock models: the configuration could not be read: {f}\n", .{one});
            } else {
                tty.print(.err, "chock models: the configuration could not be read: {t}\n", .{err});
            }
            return Exit.usage.code();
        },
    };
    defer config.deinit();

    const data_dir = if (options.probe)
        chock_auth.paths.dataDir(arena, &env) catch |err| {
            tty.print(.err, "chock models: the credential directory is unknown: {t}\n", .{err});
            return Exit.usage.code();
        }
    else
        "";
    var driver = chock_auth.store.Driver{
        .data_dir = data_dir,
        .store = config.credential_store,
        .env = &env,
    };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };

    if (options.provider) |name| {
        const instance = config.find(name) orelse {
            tty.print(.err, "chock models: the configuration names no provider called \"{s}\"\n", .{name});
            return Exit.usage.code();
        };
        describe(instance, &config);
        if (!options.probe) return Exit.finished.code();
        return if (try probe(gpa, io, config_dir, store, instance))
            Exit.finished.code()
        else
            Exit.faulted.code();
    }

    if (config.instances.len == 0) {
        tty.out(.plain, "chock models: config.zon names no provider instances.\n", .{});
        return Exit.finished.code();
    }

    var probe_failed = false;
    for (config.instances, 0..) |instance, index| {
        if (index != 0) tty.out(.plain, "\n", .{});
        describe(instance, &config);
        if (options.probe and !try probe(gpa, io, config_dir, store, instance)) probe_failed = true;
    }
    return if (probe_failed) Exit.faulted.code() else Exit.finished.code();
}

fn probe(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    store: chock_auth.store.Store,
    instance: chock_auth.config.Instance,
) !bool {
    var openai_lock: ?chock_auth.lock.Held = null;
    defer if (openai_lock) |*held| held.release(io);
    if (instance.kind == .openai) {
        var store_diag: ?chock_auth.store.Diagnostic = null;
        defer if (store_diag) |*one| one.deinit(gpa);
        chock_auth.store.ensureDir(io, store.data_dir, &store_diag) catch |err| {
            if (store_diag) |*one| {
                tty.print(.err, "  catalogue: the OpenAI renewal lock could not be prepared: {f}\n", .{one});
            } else {
                tty.print(.err, "  catalogue: the OpenAI renewal lock could not be prepared: {t}\n", .{err});
            }
            return false;
        };
        openai_lock = switch (chock_auth.lock.take(io, store.data_dir, "openai-refresh.lock", .{
            .wait_ns = 30 * std.time.ns_per_s,
        })) {
            .held => |held| held,
            .busy => {
                tty.print(.err, "  catalogue: another process is renewing the OpenAI login; try again\n", .{});
                return false;
            },
            .unusable => |err| {
                tty.print(.err, "  catalogue: the OpenAI renewal lock could not be used: {t}\n", .{err});
                return false;
            },
        };
    }

    var lookup_diag: ?chock_auth.lookup.Diagnostic = null;
    defer if (lookup_diag) |*one| one.deinit(gpa);
    var credential = chock_auth.lookup.resolve(
        gpa,
        io,
        instance,
        config_dir,
        store,
        &lookup_diag,
    ) catch |err| {
        if (lookup_diag) |*one| {
            tty.print(.err, "  catalogue: credential lookup failed: {f}\n", .{one});
        } else {
            tty.print(.err, "  catalogue: credential lookup failed: {t}\n", .{err});
        }
        return false;
    };
    defer credential.deinit();

    if (chock_auth.lookup.credentialIsMissing(instance, credential.source)) {
        tty.print(.err, "  catalogue: no credential; run `chock login --provider {s} --name {s}`\n", .{
            instance.kind.wireName(), instance.name,
        });
        return false;
    }

    var openai_credential: ?std.json.Parsed(chock_auth.openai_oauth.Credential) = null;
    defer if (openai_credential) |*parsed| parsed.deinit();
    var renewed_set: ?chock_auth.openai_oauth.TokenSet = null;
    defer if (renewed_set) |*held| held.deinit();
    var token: []const u8 = credential.token;
    if (instance.kind == .openai and credential.token.len != 0) {
        openai_credential = chock_auth.openai_oauth.Credential.parse(gpa, credential.token) catch {
            tty.print(.err, "  catalogue: the OpenAI credential is not a web login; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
            return false;
        };
        var current = openai_credential.?.value;
        if (!current.hasInferenceScope()) {
            tty.print(.err, "  catalogue: the OpenAI login did not grant ChatGPT plan use; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
            return false;
        }
        const now = @divTrunc(std.Io.Timestamp.now(io, .real).toMilliseconds(), 1000);
        if (current.expires_at <= now + 300) {
            if (credential.source != .login_store) {
                tty.print(.err, "  catalogue: the OpenAI login needs renewal but is not in the login store; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
                return false;
            }
            renewed_set = chock_auth.openai_oauth.refresh(
                gpa,
                io,
                current.client_id,
                current.refresh_token,
            ) catch |err| {
                tty.print(.err, "  catalogue: the OpenAI login could not be renewed ({t})\n", .{err});
                return false;
            };
            const renewed = renewed_set.?.value;
            current = .{
                .email = current.email,
                .issuer = current.issuer,
                .subject = current.subject,
                .client_id = current.client_id,
                .ext_agent_host_id = current.ext_agent_host_id,
                .id_token = renewed.id_token,
                .access_token = renewed.access_token,
                .refresh_token = renewed.refresh_token,
                .token_type = renewed.token_type,
                .expires_at = now + renewed.expires_in,
                .earliest_refresh_at = renewed.earliest_refresh_at,
                .scope = renewed.scope,
            };
            const serialized = try current.serialize(gpa);
            defer {
                std.crypto.secureZero(u8, serialized);
                gpa.free(serialized);
            }
            var refresh_diag: ?chock_auth.store.Diagnostic = null;
            defer if (refresh_diag) |*one| one.deinit(gpa);
            store.put(gpa, io, .{
                .name = instance.name,
                .kind = .openai,
                .base_url = instance.base_url,
                .token = serialized,
                .stored_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
            }, &refresh_diag) catch |err| {
                if (refresh_diag) |*one| {
                    tty.print(.err, "  catalogue: the renewed OpenAI login could not be stored: {f}\n", .{one});
                } else {
                    tty.print(.err, "  catalogue: the renewed OpenAI login could not be stored: {t}\n", .{err});
                }
                return false;
            };
        }
        token = current.access_token;
    }

    var outcome = try chock_auth.check.credential(gpa, io, instance.kind, instance.base_url, token);
    defer outcome.deinit(gpa);
    switch (outcome) {
        .ok => |ok| {
            const models = ok.models orelse {
                tty.print(.warn, "  catalogue: the provider answered, but its model list has an unknown shape\n", .{});
                return false;
            };
            tty.out(.plain, "  catalogue: {d} model{s}\n", .{ models.len, if (models.len == 1) "" else "s" });
            for (models) |model| tty.out(.plain, "    {s}\n", .{model});
            return true;
        },
        .rejected => |rejected| {
            tty.print(.err, "  catalogue: provider refused the request with status {d}\n", .{@backingInt(rejected.status)});
            return false;
        },
        .not_reached => |reason| {
            tty.print(.err, "  catalogue: provider could not be reached ({s})\n", .{reason});
            return false;
        },
    }
}

fn describe(instance: chock_auth.config.Instance, config: *const chock_auth.config.Config) void {
    const is_default = if (config.defaultInstance()) |chosen|
        std.mem.eql(u8, chosen.name, instance.name)
    else
        false;
    const adapter = adapterFor(instance.kind);
    const features = adapter.features();

    tty.out(.plain, "{s}{s}\n", .{ instance.name, if (is_default) "  (default provider)" else "" });
    tty.out(.plain, "  kind: {s}\n", .{instance.kind.wireName()});
    tty.out(.plain, "  default model: {s}\n", .{
        if (is_default) config.default_model orelse "not configured" else "not configured for this provider",
    });
    if (instance.context_tokens) |tokens| {
        tty.out(.plain, "  context limit: {d} tokens\n", .{tokens});
    } else {
        tty.out(.plain, "  context limit: not configured (compact after a provider refusal)\n", .{});
    }
    tty.out(.plain, "  capabilities: text", .{});
    if (features.tool_calls) tty.out(.plain, ", tools", .{});
    if (features.reasoning) tty.out(.plain, ", reasoning", .{});
    if (features.cache_accounting) tty.out(.plain, ", cache accounting", .{});
    if (features.image_results and instance.capabilities.images) tty.out(.plain, ", images", .{});
    tty.out(.plain, "\n", .{});
    if (features.image_results and !instance.capabilities.images) {
        tty.out(.dim, "  images: adapter support is present; enable it in this instance's capabilities\n", .{});
    }
    if (!features.provider_search) {
        tty.out(.dim, "  provider search: unavailable (web search uses Chock's policy-controlled tool)\n", .{});
    }
}

fn adapterFor(kind: chock_auth.config.Kind) chock_provider.Client.Adapter {
    return switch (kind) {
        .anthropic => .anthropic,
        .openai => .openai_responses,
        .aiand, .openai_compat => .openai_compatible,
    };
}

fn parseOptions(args: []const []const u8) error{ HelpWanted, BadArguments }!Options {
    var options = Options{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];
        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;
        if (std.mem.eql(u8, argument, "--provider")) {
            index += 1;
            if (index >= args.len or options.provider != null or args[index].len == 0) return error.BadArguments;
            options.provider = args[index];
            continue;
        }
        if (std.mem.eql(u8, argument, "--probe")) {
            if (options.probe) return error.BadArguments;
            options.probe = true;
            continue;
        }
        return error.BadArguments;
    }
    return options;
}

test "model options select at most one provider" {
    try std.testing.expect((try parseOptions(&.{})).provider == null);
    try std.testing.expectEqualStrings("local", (try parseOptions(&.{ "--provider", "local" })).provider.?);
    try std.testing.expect((try parseOptions(&.{"--probe"})).probe);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{"--provider"}));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "a", "--provider", "b" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--probe", "--probe" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{"local"}));
    try std.testing.expectError(error.HelpWanted, parseOptions(&.{"--help"}));
}

test "provider kinds select the adapter Chock actually runs" {
    try std.testing.expectEqual(chock_provider.Client.Adapter.anthropic, adapterFor(.anthropic));
    try std.testing.expectEqual(chock_provider.Client.Adapter.openai_responses, adapterFor(.openai));
    try std.testing.expectEqual(chock_provider.Client.Adapter.openai_compatible, adapterFor(.aiand));
    try std.testing.expectEqual(chock_provider.Client.Adapter.openai_compatible, adapterFor(.openai_compat));
}

test "a model description reports effective features without credential material" {
    const gpa = std.testing.allocator;
    var config = try chock_auth.config.parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat",
        \\           .base_url = "http://127.0.0.1:5000/v1",
        \\           .token = "never-print-this",
        \\           .context_tokens = 65536,
        \\           .capabilities = .{ .images = true } },
        \\    },
        \\    .defaults = .{ .provider = "local", .model = "test-model" },
        \\}
    , null);
    defer config.deinit();

    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, gpa);
    defer capture.stop(std.testing.io);

    describe(config.instances[0], &config);
    const output = capture.out();
    try std.testing.expect(std.mem.indexOf(u8, output, "test-model") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "65536 tokens") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "tools") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "images") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "never-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "127.0.0.1") == null);
}
