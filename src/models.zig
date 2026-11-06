//! `chock models`: the configured provider/model choices and what their
//! adapters can faithfully carry. The default is offline; `--probe` opts into
//! credential lookup and provider catalogue requests.

const std = @import("std");
const chock_auth = @import("chock-auth");
const oauth = @import("oauth-core");
const oauth_openai = @import("oauth-openai");
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
    \\  --format <kind>     human (default) or json.
    \\
++ tty.options_text;

const Format = enum {
    human,
    json,
};

const Options = struct {
    provider: ?[]const u8 = null,
    probe: bool = false,
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
            tty.print(.err, "chock models: there is no configuration at {s}/{s}; " ++
                "run `chock config init` to write a starter\n", .{
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

    const selected = if (options.provider) |name|
        config.find(name) orelse {
            tty.print(.err, "chock models: the configuration names no provider called \"{s}\"\n", .{name});
            return Exit.usage.code();
        }
    else
        null;

    if (options.format == .json and !options.probe) {
        try reportJson(arena, &config, selected, null);
        return Exit.finished.code();
    }

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

    if (options.format == .json) {
        const count: usize = if (selected == null) config.instances.len else 1;
        const catalogues = try arena.alloc(CatalogueReport, count);
        var probe_failed = false;
        if (selected) |instance| {
            catalogues[0] = try probe(arena, gpa, io, config_dir, store, instance, .json);
            probe_failed = !catalogues[0].available();
        } else {
            for (config.instances, catalogues) |instance, *catalogue| {
                catalogue.* = try probe(arena, gpa, io, config_dir, store, instance, .json);
                if (!catalogue.available()) probe_failed = true;
            }
        }
        try reportJson(arena, &config, selected, catalogues);
        return if (probe_failed) Exit.faulted.code() else Exit.finished.code();
    }

    if (selected) |instance| {
        describe(instance, &config);
        if (!options.probe) return Exit.finished.code();
        return if ((try probe(arena, gpa, io, config_dir, store, instance, .human)).available())
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
        if (options.probe and !(try probe(arena, gpa, io, config_dir, store, instance, .human)).available()) {
            probe_failed = true;
        }
    }
    return if (probe_failed) Exit.faulted.code() else Exit.finished.code();
}

const CapabilityReport = struct {
    text: bool = true,
    tools: bool,
    reasoning: bool,
    cache_accounting: bool,
    provider_search: bool,
    images: bool,
};

const ProviderReport = struct {
    name: []const u8,
    kind: []const u8,
    is_default: bool,
    default_model: ?[]const u8,
    context_tokens: ?u64,
    capabilities: CapabilityReport,
    catalogue: ?CatalogueReport,
};

const ModelsReport = struct {
    schema: []const u8 = "chock.models",
    version: u32 = 1,
    default_provider: ?[]const u8,
    default_model: ?[]const u8,
    probed: bool,
    providers: []const ProviderReport,
};

const CatalogueStatus = enum {
    available,
    unknown_shape,
    renewal_lock_failed,
    renewal_busy,
    credential_lookup_failed,
    credential_missing,
    credential_invalid,
    scope_missing,
    renewal_unavailable,
    renewal_failed,
    credential_store_failed,
    rejected,
    not_reached,
};

const CatalogueReport = struct {
    status: CatalogueStatus,
    models: []const []const u8 = &.{},
    http_status: ?u16 = null,
    reason: ?[]const u8 = null,

    fn available(self: CatalogueReport) bool {
        return self.status == .available;
    }
};

fn reportJson(
    arena: std.mem.Allocator,
    config: *const chock_auth.config.Config,
    selected: ?chock_auth.config.Instance,
    catalogues: ?[]const CatalogueReport,
) !void {
    const count: usize = if (selected == null) config.instances.len else 1;
    if (catalogues) |provided| std.debug.assert(provided.len == count);
    const providers = try arena.alloc(ProviderReport, count);
    defer arena.free(providers);
    if (selected) |instance| {
        providers[0] = providerReport(instance, config, if (catalogues) |all| all[0] else null);
    } else {
        for (config.instances, providers, 0..) |instance, *report, index| {
            report.* = providerReport(instance, config, if (catalogues) |all| all[index] else null);
        }
    }
    const encoded = try std.json.Stringify.valueAlloc(arena, ModelsReport{
        .default_provider = config.default_provider,
        .default_model = config.default_model,
        .probed = catalogues != null,
        .providers = providers,
    }, .{});
    defer arena.free(encoded);
    tty.out(.plain, "{s}\n", .{encoded});
}

fn providerReport(
    instance: chock_auth.config.Instance,
    config: *const chock_auth.config.Config,
    catalogue: ?CatalogueReport,
) ProviderReport {
    const is_default = isDefault(instance, config);
    const features = adapterFor(instance.kind).features();
    return .{
        .name = instance.name,
        .kind = instance.kind.wireName(),
        .is_default = is_default,
        .default_model = if (is_default) config.default_model else null,
        .context_tokens = instance.context_tokens,
        .capabilities = .{
            .tools = features.tool_calls,
            .reasoning = features.reasoning,
            .cache_accounting = features.cache_accounting,
            .provider_search = features.provider_search,
            .images = features.image_results and instance.capabilities.images,
        },
        .catalogue = catalogue,
    };
}

fn probe(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    store: chock_auth.store.Store,
    instance: chock_auth.config.Instance,
    format: Format,
) !CatalogueReport {
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
            return .{ .status = .renewal_lock_failed };
        };
        openai_lock = switch (chock_auth.lock.take(io, store.data_dir, "openai-refresh.lock", .{
            .wait_ns = 30 * std.time.ns_per_s,
        })) {
            .held => |held| held,
            .busy => {
                tty.print(.err, "  catalogue: another process is renewing the OpenAI login; try again\n", .{});
                return .{ .status = .renewal_busy };
            },
            .unusable => |err| {
                tty.print(.err, "  catalogue: the OpenAI renewal lock could not be used: {t}\n", .{err});
                return .{ .status = .renewal_lock_failed };
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
        return .{ .status = .credential_lookup_failed };
    };
    defer credential.deinit();

    if (chock_auth.lookup.credentialIsMissing(instance, credential.source)) {
        tty.print(.err, "  catalogue: no credential; run `chock login --provider {s} --name {s}`\n", .{
            instance.kind.wireName(), instance.name,
        });
        return .{ .status = .credential_missing };
    }

    var openai_credential: ?std.json.Parsed(chock_auth.openai_oauth.Credential) = null;
    defer if (openai_credential) |*parsed| parsed.deinit();
    var renewed_set: ?oauth.TokenSet = null;
    defer if (renewed_set) |*held| held.deinit();
    var token: []const u8 = credential.token;
    if (instance.kind == .openai and credential.token.len != 0) {
        openai_credential = chock_auth.openai_oauth.Credential.parse(gpa, credential.token) catch {
            tty.print(.err, "  catalogue: the OpenAI credential is not a web login; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
            return .{ .status = .credential_invalid };
        };
        var current = openai_credential.?.value;
        if (!current.hasInferenceScope()) {
            tty.print(.err, "  catalogue: the OpenAI login did not grant ChatGPT plan use; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
            return .{ .status = .scope_missing };
        }
        const now = @divTrunc(std.Io.Timestamp.now(io, .real).toMilliseconds(), 1000);
        if (current.expires_at <= now + 300) {
            if (credential.source != .login_store) {
                tty.print(.err, "  catalogue: the OpenAI login needs renewal but is not in the login store; run `chock login --provider openai --name {s} --replace`\n", .{instance.name});
                return .{ .status = .renewal_unavailable };
            }
            var zurl_transport: oauth.ZurlTransport = .init(io);
            renewed_set = oauth.refresh(gpa, .{
                .transport = zurl_transport.transport(),
                .endpoints = oauth_openai.endpoints,
                .client = .{ .id = current.client_id },
                .extra = oauth_openai.token_extra,
            }, current.refresh_token) catch |err| {
                tty.print(.err, "  catalogue: the OpenAI login could not be renewed ({t})\n", .{err});
                return .{ .status = .renewal_failed };
            };
            const renewed = renewed_set.?.value();
            var extension_arena: std.heap.ArenaAllocator = .init(gpa);
            defer extension_arena.deinit();
            const extension = renewed_set.?.extension(extension_arena.allocator(), oauth_openai.Extension) catch
                oauth_openai.Extension{};
            current = current.renewed(.{
                .access_token = renewed.access_token,
                .token_type = renewed.token_type,
                .expires_at = now + (renewed.expires_in orelse 3600),
                .id_token = renewed.id_token,
                .refresh_token = renewed.refresh_token,
                .scope = renewed.scope,
                .earliest_refresh_at = extension.earliest_refresh_at,
            });
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
                return .{ .status = .credential_store_failed };
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
                return .{ .status = .unknown_shape };
            };
            if (format == .human) {
                tty.out(.plain, "  catalogue: {d} model{s}\n", .{ models.len, if (models.len == 1) "" else "s" });
                for (models) |model| tty.out(.plain, "    {s}\n", .{model});
                return .{ .status = .available };
            }
            const copied = try arena.alloc([]const u8, models.len);
            for (models, copied) |model, *destination| destination.* = try arena.dupe(u8, model);
            return .{ .status = .available, .models = copied };
        },
        .rejected => |rejected| {
            const status = @backingInt(rejected.status);
            tty.print(.err, "  catalogue: provider refused the request with status {d}\n", .{status});
            if (instance.kind == .openai_compat and
                (rejected.status == .unauthorized or rejected.status == .forbidden))
            {
                tty.print(
                    .err,
                    "  catalogue: store its credential with `chock login --provider openai-compat={s} --name {s}`\n",
                    .{ instance.base_url, instance.name },
                );
            }
            return .{
                .status = .rejected,
                .http_status = @intCast(status),
            };
        },
        .not_reached => |reason| {
            tty.print(.err, "  catalogue: provider could not be reached ({s})\n", .{reason});
            return .{
                .status = .not_reached,
                .reason = if (format == .json) try arena.dupe(u8, reason) else null,
            };
        },
    }
}

fn describe(instance: chock_auth.config.Instance, config: *const chock_auth.config.Config) void {
    const is_default = isDefault(instance, config);
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
    if (features.provider_search) tty.out(.plain, ", provider search", .{});
    if (features.image_results and instance.capabilities.images) tty.out(.plain, ", images", .{});
    tty.out(.plain, "\n", .{});
    if (features.image_results and !instance.capabilities.images) {
        tty.out(.dim, "  images: adapter support is present; enable it in this instance's capabilities\n", .{});
    }
    if (!features.provider_search) {
        tty.out(.dim, "  provider search: unavailable (web search uses Chock's policy-controlled tool)\n", .{});
    }
}

fn isDefault(instance: chock_auth.config.Instance, config: *const chock_auth.config.Config) bool {
    const chosen = config.defaultInstance() orelse return false;
    return std.mem.eql(u8, chosen.name, instance.name);
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
    var format_set = false;
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
        if (std.mem.eql(u8, argument, "--format")) {
            index += 1;
            if (index >= args.len or format_set) return error.BadArguments;
            format_set = true;
            if (std.mem.eql(u8, args[index], "human")) continue;
            if (std.mem.eql(u8, args[index], "json")) {
                options.format = .json;
                continue;
            }
            return error.BadArguments;
        }
        return error.BadArguments;
    }
    return options;
}

test "model options select at most one provider" {
    try std.testing.expect((try parseOptions(&.{})).provider == null);
    try std.testing.expectEqualStrings("local", (try parseOptions(&.{ "--provider", "local" })).provider.?);
    try std.testing.expect((try parseOptions(&.{"--probe"})).probe);
    try std.testing.expectEqual(Format.json, (try parseOptions(&.{ "--format", "json" })).format);
    try std.testing.expectEqual(Format.json, (try parseOptions(&.{ "--provider", "local", "--format", "json" })).format);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{"--provider"}));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "a", "--provider", "b" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--probe", "--probe" }));
    try std.testing.expect((try parseOptions(&.{ "--format", "json", "--probe" })).probe);
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--format", "yaml" }));
    try std.testing.expectError(error.BadArguments, parseOptions(&.{ "--format", "human", "--format", "json" }));
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

test "the JSON model report is structured and contains no connection or credential material" {
    const gpa = std.testing.allocator;
    var config = try chock_auth.config.parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat",
        \\           .base_url = "http://127.0.0.1:5000/v1",
        \\           .token = "never-print-this",
        \\           .context_tokens = 65536,
        \\           .capabilities = .{ .images = true } },
        \\        .{ .name = "work", .kind = "openai" },
        \\    },
        \\    .defaults = .{ .provider = "local", .model = "test-model" },
        \\}
    , null);
    defer config.deinit();

    var capture: tty.Capture = undefined;
    capture.start(std.testing.io, gpa);
    defer capture.stop(std.testing.io);

    try reportJson(gpa, &config, null, null);
    const output = capture.out();
    const parsed = try std.json.parseFromSlice(ModelsReport, gpa, output, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("chock.models", parsed.value.schema);
    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
    try std.testing.expectEqualStrings("local", parsed.value.default_provider.?);
    try std.testing.expectEqualStrings("test-model", parsed.value.default_model.?);
    try std.testing.expect(!parsed.value.probed);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.providers.len);
    try std.testing.expectEqualStrings("local", parsed.value.providers[0].name);
    try std.testing.expectEqualStrings("openai-compat", parsed.value.providers[0].kind);
    try std.testing.expect(parsed.value.providers[0].is_default);
    try std.testing.expectEqual(@as(?u64, 65536), parsed.value.providers[0].context_tokens);
    try std.testing.expect(parsed.value.providers[0].capabilities.text);
    try std.testing.expect(parsed.value.providers[0].capabilities.images);
    try std.testing.expect(parsed.value.providers[0].catalogue == null);
    try std.testing.expect(!parsed.value.providers[0].capabilities.provider_search);
    try std.testing.expect(parsed.value.providers[1].capabilities.provider_search);
    try std.testing.expect(std.mem.indexOf(u8, output, "never-print-this") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "127.0.0.1") == null);
}
