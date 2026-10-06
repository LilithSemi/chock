//! `chock login`: put one credential in the store.

const std = @import("std");
const chock_auth = @import("chock-auth");
const chock_policy = @import("chock-policy");

const Exit = @import("main.zig").Exit;
const tty = @import("tty.zig");

const usage_text =
    \\Usage: chock login --provider <kind>[=<url>] [options]
    \\       chock login --search <name> [options]
    \\       chock login --tool-secret <name> [options]
    \\
    \\Kinds: anthropic, aiand, openai-compat=<url>
    \\
    \\Options:
    \\  --search <name>            Store the key of a web search engine under this name,
    \\                             which is the name your config.zon gives as .credential.
    \\  --tool-secret <name>       Store a secret a tool call may be given under this name,
    \\                             which is the name your chock.zon secrets block gives.
    \\  --name <name>              Name this instance. Omitted, the kind is the name.
    \\  --replace                  Replace a credential of this name without asking.
    \\                             A second instance of one kind needs a name of its own.
    \\  --password-method <method> Where the credential comes from:
    \\                               prompt      a hidden prompt (the default at a terminal)
    \\                               stdin       one line of standard input (the default otherwise)
    \\                               file=<path> read it from a file
    \\
++ tty.options_text ++
    \\
    \\There is no option that takes the credential itself. A command line is visible
    \\to every other user through ps and it lands in the shell history.
    \\
;

const max_credential_bytes: usize = 64 * 1024;

const forbidden_value_options = [_][]const u8{
    "--password", "--token", "--key", "--api-key", "--secret", "-p", "-w",
};

const Method = union(enum) {
    prompt,
    stdin,
    file: []const u8,
};

const Options = struct {
    provider: []const u8 = "",
    search: ?[]const u8 = null,
    secret: ?[]const u8 = null,
    name: ?[]const u8 = null,
    method: ?Method = null,
    replace: bool = false,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    _ = exe_path;

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => return Exit.usage.code(),
    };

    var env = try environ.createMap(arena);

    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();

    const config_dir = chock_auth.paths.configDir(arena, &env) catch |err| {
        tty.print(.err, "chock login: the configuration directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };
    const data_dir = chock_auth.paths.dataDir(arena, &env) catch |err| {
        tty.print(.err, "chock login: the data directory is unknown: {s}\n", .{@errorName(err)});
        return Exit.usage.code();
    };

    const credential_store = chock_auth.config.credentialStore(arena, io, config_dir);
    const driver = chock_auth.store.Driver{
        .data_dir = data_dir,
        .store = credential_store,
        .env = &env,
    };
    const store = chock_auth.store.Store{ .data_dir = data_dir, .secrets = driver.secrets() };

    if (options.search) |search_name| {
        return searchLogin(gpa, io, driver.secrets(), data_dir, search_name, options);
    }

    if (options.secret) |secret_name| {
        return secretLogin(gpa, io, store, data_dir, secret_name, options);
    }

    const kind_and_url = splitProvider(options.provider) catch return Exit.usage.code();
    const name = options.name orelse kind_and_url.kind.wireName();
    const name_was_given = options.name != null;

    // Holds no lock here: a lock held across a person answering a prompt would hold it for minutes, and every other login would time out.
    const method = options.method orelse defaultMethod(io);

    var replacing = options.replace;
    if (!name_was_given and !options.replace) {
        var store_diag: ?chock_auth.store.Diagnostic = null;
        defer if (store_diag) |*d| d.deinit(gpa);
        const existing = store.get(gpa, io, name, &store_diag) catch |err| {
            if (store_diag) |*d| {
                tty.print(.err, "chock login: the credential store could not be read: {f}\n", .{d});
            } else {
                tty.print(.err, "chock login: the credential store could not be read: {s}\n", .{@errorName(err)});
            }
            return Exit.usage.code();
        };
        if (existing) |found| {
            var stored = found;
            defer stored.deinit();

            if (method != .prompt) {
                reportNameTaken(name, stored.kind, options.provider);
                return Exit.usage.code();
            }
            replacing = askReplace(io, name, stored.kind) catch return Exit.usage.code();
            if (!replacing) {
                tty.print(.plain, "chock login: nothing was changed.\n", .{});
                return Exit.refused.code();
            }
        }
    }
    const credential = readCredential(gpa, io, method, name) catch |err| switch (err) {
        error.Reported => return Exit.usage.code(),
        else => |e| return e,
    };
    defer {
        std.crypto.secureZero(u8, credential);
        gpa.free(credential);
    }
    if (credential.len == 0) {
        tty.print(.warn, "chock login: nothing was given, so nothing was stored.\n", .{});
        return Exit.usage.code();
    }

    const loaded = loadConfig(arena, io, config_dir);
    const target = checkTarget(kind_and_url, loaded.find(name)) catch {
        const declared = loaded.find(name).?;
        tty.print(
            .warn,
            "chock login: the configuration declares \"{s}\" as kind {s}, and this command says {s}. " ++
                "Nothing was stored.\n",
            .{ name, declared.kind.wireName(), kind_and_url.kind.wireName() },
        );
        return Exit.usage.code();
    };

    tty.print(.plain, "chock login: asking {s} whether this credential works...\n", .{target.base_url});
    var outcome = try chock_auth.check.credential(gpa, io, target.kind, target.base_url, credential);
    defer outcome.deinit(gpa);
    switch (outcome) {
        .ok => |ok| {
            if (ok.model_count) |count| {
                tty.print(
                    .plain,
                    "chock login: {s} at {s} answered and listed {d} models.\n",
                    .{ target.kind.wireName(), target.base_url, count },
                );
            } else {
                tty.print(
                    .plain,
                    "chock login: {s} at {s} answered and accepted the credential.\n",
                    .{ target.kind.wireName(), target.base_url },
                );
            }
        },
        .rejected => |rejected| {
            tty.print(
                .warn,
                "chock login: {s} refused this credential with status {d}: {s}\n" ++
                    "Nothing was stored.\n",
                .{ target.base_url, @intFromEnum(rejected.status), std.mem.trim(u8, rejected.body, " \t\r\n") },
            );
            return Exit.usage.code();
        },
        .not_reached => |reason| {
            tty.print(
                .warn,
                "chock login: {s} could not be reached ({s}), so this credential was not checked. " ++
                    "Nothing was stored.\n",
                .{ target.base_url, reason },
            );
            return Exit.usage.code();
        },
    }

    var put_diag: ?chock_auth.store.Diagnostic = null;
    defer if (put_diag) |*d| d.deinit(gpa);
    store.put(gpa, io, .{
        .name = name,
        .kind = target.kind,
        .base_url = target.base_url,
        .token = credential,
        .stored_ms = std.Io.Timestamp.now(io, .real).toMilliseconds(),
        // The true check: the store makes it with the index locked, so a login that started during another one's prompt is refused here.
        .replace_existing = name_was_given or replacing,
    }, &put_diag) catch |err| {
        if (put_diag) |*d| {
            if (std.meta.activeTag(d.*) == .name_already_stored) {
                reportNameTaken(name, d.name_already_stored.kind, options.provider);
                return Exit.usage.code();
            }
            tty.print(.err, "chock login: the credential could not be stored: {f}\n", .{d});
        } else {
            tty.print(.err, "chock login: the credential could not be stored: {s}\n", .{@errorName(err)});
        }
        return Exit.usage.code();
    };
    tty.print(.plain, "chock login: stored the credential for \"{s}\".\n", .{name});

    reportConfiguration(arena, config_dir, name, target, loaded);
    return Exit.finished.code();
}

fn searchLogin(
    gpa: std.mem.Allocator,
    io: std.Io,
    secrets: chock_auth.store.Secrets,
    data_dir: []const u8,
    name: []const u8,
    options: Options,
) !u8 {
    var diag: ?chock_auth.store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    chock_auth.store.ensureDir(io, data_dir, &diag) catch |err| {
        reportStoreFault("the credential store could not be made", &diag, err);
        return Exit.usage.code();
    };

    const method = options.method orelse defaultMethod(io);

    if (!options.replace) {
        const existing = chock_auth.search.load(gpa, io, secrets, name, &diag) catch |err| {
            reportStoreFault("the credential store could not be read", &diag, err);
            return Exit.usage.code();
        };
        if (existing) |held| {
            defer {
                std.crypto.secureZero(u8, held);
                gpa.free(held);
            }
            tty.print(
                .warn,
                "chock login: there is already a key stored for the search credential \"{s}\".\n",
                .{name},
            );
            if (method != .prompt) {
                tty.print(
                    .warn,
                    "This run has nobody to ask. Say it was meant:\n\n" ++
                        "  chock login --search {s} --replace\n",
                    .{name},
                );
                return Exit.usage.code();
            }
            if (!(confirmReplace(io) catch return Exit.usage.code())) {
                tty.print(.plain, "chock login: nothing was changed.\n", .{});
                return Exit.refused.code();
            }
        }
    }

    const credential = readCredential(gpa, io, method, name) catch |err| switch (err) {
        error.Reported => return Exit.usage.code(),
        else => |e| return e,
    };
    defer {
        std.crypto.secureZero(u8, credential);
        gpa.free(credential);
    }
    if (credential.len == 0) {
        tty.print(.warn, "chock login: nothing was given, so nothing was stored.\n", .{});
        return Exit.usage.code();
    }

    chock_auth.search.save(gpa, io, secrets, name, credential, &diag) catch |err| {
        reportStoreFault("the key could not be stored", &diag, err);
        return Exit.usage.code();
    };

    tty.print(
        .plain,
        "chock login: stored the key for the search credential \"{s}\". It was not checked " ++
            "against the engine.\n",
        .{name},
    );
    tty.print(
        .plain,
        "\nThe search block of your config.zon reads it under that name:\n\n" ++
            "  .search = .{{ .kind = \"api\", .provider = \"brave\", " ++
            ".base_url = \"https://api.search.brave.com\", .credential = \"{s}\" }}\n",
        .{name},
    );
    return Exit.finished.code();
}

fn secretLogin(
    gpa: std.mem.Allocator,
    io: std.Io,
    store: chock_auth.store.Store,
    data_dir: []const u8,
    name: []const u8,
    options: Options,
) !u8 {
    var diag: ?chock_auth.store.Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    chock_auth.store.ensureDir(io, data_dir, &diag) catch |err| {
        reportStoreFault("the credential store could not be made", &diag, err);
        return Exit.usage.code();
    };

    const instance = store.get(gpa, io, name, &diag) catch |err| {
        tty.print(
            .err,
            "chock login: whether \"{s}\" is already a provider instance could not be read, so " ++
                "the secret was not stored. A tool secret and a provider instance share one set " ++
                "of names, and writing over an instance would take a session's model credential " ++
                "away. The fault was: {t}\n",
            .{ name, err },
        );
        if (diag) |*d| tty.print(.err, "chock login: {f}\n", .{d});
        return Exit.usage.code();
    };
    if (instance) |held| {
        var taken = held;
        defer taken.deinit();
        tty.print(
            .err,
            "chock login: \"{s}\" already names a provider instance of kind {s}, and a secret " ++
                "granted to a tool shares the same set of names. Pick another name for the " ++
                "secret, and name that one in the secrets block of your chock.zon.\n",
            .{ name, taken.kind },
        );
        return Exit.usage.code();
    }

    const method = options.method orelse defaultMethod(io);

    if (!options.replace) {
        const existing = store.secrets.get(gpa, io, name, &diag) catch |err| {
            reportStoreFault("the credential store could not be read", &diag, err);
            return Exit.usage.code();
        };
        if (existing) |value| {
            defer {
                std.crypto.secureZero(u8, value);
                gpa.free(value);
            }
            tty.print(
                .warn,
                "chock login: there is already a secret stored under \"{s}\".\n",
                .{name},
            );
            if (method != .prompt) {
                tty.print(
                    .warn,
                    "This run has nobody to ask. Say it was meant:\n\n" ++
                        "  chock login --tool-secret {s} --replace\n",
                    .{name},
                );
                return Exit.usage.code();
            }
            if (!(confirmReplace(io) catch return Exit.usage.code())) {
                tty.print(.plain, "chock login: nothing was changed.\n", .{});
                return Exit.refused.code();
            }
        }
    }

    const credential = readCredential(gpa, io, method, name) catch |err| switch (err) {
        error.Reported => return Exit.usage.code(),
        else => |e| return e,
    };
    defer {
        std.crypto.secureZero(u8, credential);
        gpa.free(credential);
    }
    if (credential.len == 0) {
        tty.print(.warn, "chock login: nothing was given, so nothing was stored.\n", .{});
        return Exit.usage.code();
    }

    store.secrets.put(gpa, io, name, credential, &diag) catch |err| {
        reportStoreFault("the secret could not be stored", &diag, err);
        return Exit.usage.code();
    };

    tty.print(
        .plain,
        "chock login: stored the secret \"{s}\". No agent is ever shown it.\n",
        .{name},
    );
    tty.print(
        .plain,
        "\nThe secrets block of your project's chock.zon says which tool may be given it:\n\n" ++
            "  .secrets = .{{\n" ++
            "      .{{ .name = \"{s}\", .to = \"exec.path.gh\" }},\n" ++
            "  }}\n" ++
            "\nUsing it is asked about as secret.use.{s}, so a policy rule can make it a " ++
            "standing permission or a question every time.\n",
        .{ name, name },
    );
    return Exit.finished.code();
}

fn reportStoreFault(
    what: []const u8,
    diag: *?chock_auth.store.Diagnostic,
    err: anyerror,
) void {
    if (diag.*) |*d| {
        tty.print(.err, "chock login: {s}: {f}\n", .{ what, d });
    } else {
        tty.print(.err, "chock login: {s}: {s}\n", .{ what, @errorName(err) });
    }
}

fn reportNameTaken(name: []const u8, stored_kind: []const u8, provider: []const u8) void {
    tty.print(
        .warn,
        "chock login: there is already a credential named \"{s}\", stored as kind {s}, " ++
            "and this run has nobody to ask. Say which was meant:\n\n" ++
            "  chock login --provider {s} --replace\n" ++
            "  chock login --provider {s} --name <a name of your own>\n",
        .{ name, stored_kind, provider, provider },
    );
}

fn askReplace(io: std.Io, name: []const u8, stored_kind: []const u8) error{Reported}!bool {
    tty.print(
        .warn,
        "chock login: there is already a credential named \"{s}\", stored as kind {s}.\n",
        .{ name, stored_kind },
    );
    return confirmReplace(io);
}

fn confirmReplace(io: std.Io) error{Reported}!bool {
    tty.print(.plain, "Replace it? [y/N] ", .{});
    tty.flushOut();

    var buffer: [64]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => return false,
        else => {
            tty.print(.err, "chock login: the answer could not be read: {s}\n", .{@errorName(err)});
            return error.Reported;
        },
    };
    const answer = std.mem.trim(u8, line, " \t\r");
    return std.ascii.eqlIgnoreCase(answer, "y") or std.ascii.eqlIgnoreCase(answer, "yes");
}

const LoadedConfig = union(enum) {
    absent,
    unreadable: ?chock_auth.config.Diagnostic,
    loaded: chock_auth.config.Config,

    fn find(self: *const LoadedConfig, name: []const u8) ?chock_auth.config.Instance {
        return switch (self.*) {
            .absent, .unreadable => null,
            .loaded => |*config| config.find(name),
        };
    }
};

fn loadConfig(arena: std.mem.Allocator, io: std.Io, config_dir: []const u8) LoadedConfig {
    var diag: ?chock_auth.config.Diagnostic = null;
    const config = chock_auth.config.load(arena, io, config_dir, &diag) catch |err| switch (err) {
        error.NoConfigFile => return .absent,
        else => return .{ .unreadable = diag },
    };
    return .{ .loaded = config };
}

fn checkTarget(
    from_command_line: KindAndUrl,
    declared: ?chock_auth.config.Instance,
) error{KindConflict}!KindAndUrl {
    const instance = declared orelse return from_command_line;
    if (instance.kind != from_command_line.kind) return error.KindConflict;
    if (from_command_line.url_was_given) return from_command_line;
    return .{ .kind = instance.kind, .base_url = instance.base_url, .url_was_given = false };
}

fn reportConfiguration(
    arena: std.mem.Allocator,
    config_dir: []const u8,
    name: []const u8,
    kind_and_url: KindAndUrl,
    loaded: LoadedConfig,
) void {
    const config_path = std.fs.path.join(arena, &.{ config_dir, chock_auth.config.file_name }) catch return;

    switch (loaded) {
        .absent => printConfigurationHint(config_path, name, kind_and_url, true),
        .unreadable => |diag| {
            if (diag) |*d| {
                tty.print(
                    .warn,
                    "chock login: {f}, so whether {s} declares \"{s}\" is unknown.\n",
                    .{ d, config_path, name },
                );
            } else {
                tty.print(
                    .warn,
                    "chock login: {s} could not be read, so whether it declares \"{s}\" is unknown.\n",
                    .{ config_path, name },
                );
            }
        },
        .loaded => |config| {
            if (config.find(name) != null) return;
            printConfigurationHint(config_path, name, kind_and_url, false);
        },
    }
}

fn printConfigurationHint(
    config_path: []const u8,
    name: []const u8,
    kind_and_url: KindAndUrl,
    whole_file: bool,
) void {
    const url_field = if (std.mem.eql(u8, kind_and_url.base_url, kind_and_url.kind.defaultBaseUrl()))
        ""
    else
        kind_and_url.base_url;

    tty.print(
        .warn,
        "\nchock login: {s} does not declare a provider named \"{s}\" yet. " ++
            "Chock never writes that file, so add this to it{s}:\n\n",
        .{ config_path, name, if (whole_file) " (the file does not exist yet)" else "" },
    );
    if (whole_file) tty.print(.warn, "  .{{\n      .providers = .{{\n", .{});
    if (url_field.len == 0) {
        tty.print(
            .warn,
            "  {s}.{{ .name = \"{s}\", .kind = \"{s}\" }},\n",
            .{ if (whole_file) "        " else "", name, kind_and_url.kind.wireName() },
        );
    } else {
        tty.print(
            .warn,
            "  {s}.{{ .name = \"{s}\", .kind = \"{s}\", .base_url = \"{s}\" }},\n",
            .{ if (whole_file) "        " else "", name, kind_and_url.kind.wireName(), url_field },
        );
    }
    if (whole_file) tty.print(.warn, "      }},\n  }}\n", .{});
    tty.print(
        .warn,
        "\nThe credential is already in the store and stays there. " ++
            "The configuration names the instance and holds no secret.\n",
        .{},
    );
}

const KindAndUrl = struct {
    kind: chock_auth.config.Kind,
    base_url: []const u8,
    url_was_given: bool = false,
};

fn splitProvider(text: []const u8) error{BadArguments}!KindAndUrl {
    if (text.len == 0) {
        tty.print(.err, "chock login: --provider is needed.\n\n", .{});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    const separator = std.mem.indexOfScalar(u8, text, '=');
    const kind_text = if (separator) |at| text[0..at] else text;
    const url_text = if (separator) |at| text[at + 1 ..] else "";

    const kind = chock_auth.config.Kind.fromWireName(kind_text) orelse {
        tty.print(
            .err,
            "chock login: \"{s}\" is not a provider kind Chock knows. The kinds are: {s}\n",
            .{ kind_text, chock_auth.config.Kind.all_wire_names },
        );
        return error.BadArguments;
    };

    if (url_text.len != 0) return .{ .kind = kind, .base_url = url_text, .url_was_given = true };

    const fallback = kind.defaultBaseUrl();
    if (fallback.len == 0) {
        tty.print(
            .err,
            "chock login: the kind {s} has no address of its own, so it needs one: " ++
                "--provider {s}=https://example.com/v1\n",
            .{ kind.wireName(), kind.wireName() },
        );
        return error.BadArguments;
    }
    return .{ .kind = kind, .base_url = fallback };
}

fn defaultMethod(io: std.Io) Method {
    const is_terminal = std.Io.File.stdin().isTty(io) catch false;
    return if (is_terminal) .prompt else .stdin;
}

const ReadError = error{Reported} || std.mem.Allocator.Error;

fn readCredential(
    gpa: std.mem.Allocator,
    io: std.Io,
    method: Method,
    name: []const u8,
) ReadError![]u8 {
    switch (method) {
        .prompt => return readPrompt(gpa, io, name),
        .stdin => return readLine(gpa, io),
        .file => |path| {
            var mode_fault: ?chock_auth.paths.Diagnostic = null;
            chock_auth.paths.requirePrivate(io, path, &mode_fault) catch {
                if (mode_fault) |fault| tty.print(.err, "chock login: {f}\n", .{fault});
                return error.Reported;
            };
            const source = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_credential_bytes)) catch |err| {
                tty.print(.err, "chock login: {s} could not be read: {s}\n", .{ path, @errorName(err) });
                return error.Reported;
            };
            defer {
                std.crypto.secureZero(u8, source);
                gpa.free(source);
            }
            return gpa.dupe(u8, std.mem.trim(u8, source, " \t\r\n"));
        },
    }
}

fn readPrompt(gpa: std.mem.Allocator, io: std.Io, name: []const u8) ReadError![]u8 {
    const fd = std.posix.STDIN_FILENO;
    const original = std.posix.tcgetattr(fd) catch |err| {
        tty.print(
            .err,
            "chock login: standard input is not a terminal ({s}), so there is nothing to prompt. " ++
                "Use --password-method stdin.\n",
            .{@errorName(err)},
        );
        return error.Reported;
    };

    var quiet = original;
    quiet.lflag.ECHO = false;
    std.posix.tcsetattr(fd, .FLUSH, quiet) catch |err| {
        tty.print(.err, "chock login: the terminal would not stop echoing ({s}), so nothing was read. " ++
            "A credential must not be shown on screen.\n", .{@errorName(err)});
        return error.Reported;
    };
    defer {
        std.posix.tcsetattr(fd, .FLUSH, original) catch {};
        std.Io.File.stdout().writeStreamingAll(io, "\n") catch {};
    }

    var prompt_buffer: [256]u8 = undefined;
    const prompt = std.fmt.bufPrint(&prompt_buffer, "Credential for {s}: ", .{name}) catch "Credential: ";
    std.Io.File.stdout().writeStreamingAll(io, prompt) catch {};

    return readLine(gpa, io);
}

fn readLine(gpa: std.mem.Allocator, io: std.Io) ReadError![]u8 {
    var buffer: [4096]u8 = undefined;
    var reader = std.Io.File.stdin().readerStreaming(io, &buffer);
    const line = reader.interface.takeDelimiterExclusive('\n') catch |err| switch (err) {
        error.EndOfStream => {
            const rest = reader.interface.buffered();
            if (rest.len == 0) {
                tty.print(.err, "chock login: nothing was given on standard input.\n", .{});
                return error.Reported;
            }
            return gpa.dupe(u8, std.mem.trim(u8, rest, " \t\r"));
        },
        else => {
            tty.print(.err, "chock login: standard input could not be read: {s}\n", .{@errorName(err)});
            return error.Reported;
        },
    };
    return gpa.dupe(u8, std.mem.trim(u8, line, " \t\r"));
}

const ParseError = error{ HelpWanted, BadArguments };

fn parseOptions(args: []const []const u8) ParseError!Options {
    var options = Options{};

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const argument = args[index];

        if (std.mem.eql(u8, argument, "--help") or std.mem.eql(u8, argument, "-h")) return error.HelpWanted;

        for (forbidden_value_options) |forbidden| {
            const matches = std.mem.eql(u8, argument, forbidden) or
                (std.mem.startsWith(u8, argument, forbidden) and
                    argument.len > forbidden.len and argument[forbidden.len] == '=');
            if (!matches) continue;
            tty.print(
                .err,
                "chock login: there is no {s} option, and there will not be one. " ++
                    "A command line is visible to every other user on this machine through ps, " ++
                    "and it lands in your shell history. Pipe the credential in instead:\n\n" ++
                    "  printf '%s' \"$SECRET\" | chock login --provider <kind> --password-method stdin\n" ++
                    "\nTo store a secret a tool call may be given, --tool-secret takes its name " ++
                    "and never its value.\n",
                .{forbidden},
            );
            return error.BadArguments;
        }

        const split = std.mem.indexOfScalar(u8, argument, '=');
        const name = if (split) |at| argument[0..at] else argument;
        const inline_value: ?[]const u8 = if (split) |at| argument[at + 1 ..] else null;

        if (std.mem.eql(u8, argument, "--provider") or std.mem.eql(u8, name, "--provider")) {
            if (std.mem.eql(u8, argument, "--provider")) {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock login: --provider needs a value.\n\n{s}", .{usage_text});
                    return error.BadArguments;
                }
                options.provider = args[index];
            } else {
                options.provider = inline_value.?;
            }
            continue;
        }

        if (std.mem.eql(u8, name, "--search")) {
            options.search = inline_value orelse next: {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock login: --search needs a value.\n\n{s}", .{usage_text});
                    return error.BadArguments;
                }
                break :next args[index];
            };
            continue;
        }

        if (std.mem.eql(u8, name, "--tool-secret")) {
            options.secret = inline_value orelse next: {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock login: --tool-secret needs a value.\n\n{s}", .{usage_text});
                    return error.BadArguments;
                }
                break :next args[index];
            };
            continue;
        }

        if (std.mem.eql(u8, name, "--replace")) {
            options.replace = true;
            continue;
        }

        if (std.mem.eql(u8, name, "--name")) {
            options.name = inline_value orelse next: {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock login: --name needs a value.\n\n{s}", .{usage_text});
                    return error.BadArguments;
                }
                break :next args[index];
            };
            if (options.name.?.len == 0) {
                tty.print(.err, "chock login: --name cannot be empty.\n", .{});
                return error.BadArguments;
            }
            continue;
        }

        if (std.mem.eql(u8, name, "--password-method")) {
            const text = inline_value orelse next: {
                index += 1;
                if (index >= args.len) {
                    tty.print(.err, "chock login: --password-method needs a value.\n\n{s}", .{usage_text});
                    return error.BadArguments;
                }
                break :next args[index];
            };
            options.method = try parseMethod(text);
            continue;
        }

        tty.print(.err, "chock login: there is no option named {s}.\n\n", .{name});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }

    {
        var named: usize = 0;
        if (options.provider.len != 0) named += 1;
        if (options.search != null) named += 1;
        if (options.secret != null) named += 1;
        if (named > 1) {
            tty.print(
                .err,
                "chock login: --provider, --search and --tool-secret store different things, so one " ++
                    "command does one of them. Run it again for the next.\n",
                .{},
            );
            return error.BadArguments;
        }
    }
    if (options.secret) |secret_name| {
        if (options.name != null) {
            tty.print(
                .err,
                "chock login: --tool-secret already names the secret, so --name says nothing more. " ++
                    "Drop it.\n",
                .{},
            );
            return error.BadArguments;
        }
        if (!chock_policy.secrets.nameIsWellFormed(secret_name)) {
            tty.print(
                .err,
                "chock login: \"{s}\" cannot name a secret. A name holds letters, digits and " ++
                    "underscore, because a project asks about it as secret.use.<name>.\n",
                .{secret_name},
            );
            return error.BadArguments;
        }
        return options;
    }
    if (options.search) |search_name| {
        if (options.name != null) {
            tty.print(
                .err,
                "chock login: --search already names the credential, so --name says nothing " ++
                    "more. Drop it.\n",
                .{},
            );
            return error.BadArguments;
        }
        if (!chock_auth.search.nameIsAcceptable(search_name)) {
            tty.print(
                .err,
                "chock login: \"{s}\" cannot name a search credential. A name holds letters, " ++
                    "digits, and any of - _ . and nothing else.\n",
                .{search_name},
            );
            return error.BadArguments;
        }
        return options;
    }
    if (options.provider.len == 0) {
        tty.print(.err, "chock login: --provider, --search or --tool-secret is needed.\n\n", .{});
        tty.print(.err, "{s}", .{usage_text});
        return error.BadArguments;
    }
    return options;
}

fn parseMethod(text: []const u8) ParseError!Method {
    if (std.mem.eql(u8, text, "prompt")) return .prompt;
    if (std.mem.eql(u8, text, "stdin")) return .stdin;
    if (std.mem.startsWith(u8, text, "file=")) {
        const path = text["file=".len..];
        if (path.len == 0) {
            tty.print(.err, "chock login: --password-method file= needs a path.\n", .{});
            return error.BadArguments;
        }
        return .{ .file = path };
    }
    tty.print(
        .err,
        "chock login: \"{s}\" is not a password method. The methods are: prompt, stdin, file=<path>.\n",
        .{text},
    );
    return error.BadArguments;
}

const testing = std.testing;

test "a kind with an address of its own gets it, and one without needs a URL" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    const aiand = try splitProvider("aiand");
    try testing.expectEqual(chock_auth.config.Kind.aiand, aiand.kind);
    try testing.expectEqualStrings(chock_auth.config.Kind.aiand.defaultBaseUrl(), aiand.base_url);

    const local = try splitProvider("openai-compat=http://127.0.0.1:5000/v1");
    try testing.expectEqual(chock_auth.config.Kind.openai_compat, local.kind);
    try testing.expectEqualStrings("http://127.0.0.1:5000/v1", local.base_url);

    said.clear();
    try testing.expectError(error.BadArguments, splitProvider("openai-compat"));
    try testing.expect(std.mem.indexOf(u8, said.err(), "openai-compat=") != null);

    said.clear();
    try testing.expectError(error.BadArguments, splitProvider("openai"));
    for ([_][]const u8{ "anthropic", "aiand", "openai-compat" }) |kind| {
        try testing.expect(std.mem.indexOf(u8, said.err(), kind) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, splitProvider(""));
    try testing.expect(said.err().len != 0);
    try testing.expectEqualStrings("", said.out());

    const mirror = try splitProvider("aiand=https://mirror.example.invalid/v1");
    try testing.expectEqualStrings("https://mirror.example.invalid/v1", mirror.base_url);
}

fn declaredInstance(kind: chock_auth.config.Kind, base_url: []const u8) chock_auth.config.Instance {
    return .{
        .name = "local",
        .kind = kind,
        .base_url = base_url,
        .credential = .absent,
        .context_tokens = null,
        .capabilities = .{},
    };
}

test "the check goes to the instance's own address, not to its kind's default" {
    const from_command_line = try splitProvider("anthropic");
    try testing.expectEqualStrings("https://api.anthropic.com/v1", from_command_line.base_url);

    const target = try checkTarget(
        from_command_line,
        declaredInstance(.anthropic, "http://127.0.0.1:9099/v1"),
    );
    try testing.expectEqualStrings("http://127.0.0.1:9099/v1", target.base_url);
    try testing.expectEqual(chock_auth.config.Kind.anthropic, target.kind);
}

test "an address on the command line wins over the one the configuration declares" {
    const from_command_line = try splitProvider("anthropic=https://mirror.example.invalid/v1");
    const target = try checkTarget(
        from_command_line,
        declaredInstance(.anthropic, "http://127.0.0.1:9099/v1"),
    );
    try testing.expectEqualStrings("https://mirror.example.invalid/v1", target.base_url);
}

test "a name the configuration does not declare keeps its kind's own address" {
    const from_command_line = try splitProvider("aiand");
    const target = try checkTarget(from_command_line, null);
    try testing.expectEqualStrings(chock_auth.config.Kind.aiand.defaultBaseUrl(), target.base_url);
    try testing.expectEqual(chock_auth.config.Kind.aiand, target.kind);
}

test "a configuration that declares this name as another kind is refused, not resolved" {
    const from_command_line = try splitProvider("anthropic");
    try testing.expectError(
        error.KindConflict,
        checkTarget(from_command_line, declaredInstance(.aiand, "https://api.aiand.com/v1")),
    );
    const with_url = try splitProvider("anthropic=http://127.0.0.1:9099/v1");
    try testing.expectError(
        error.KindConflict,
        checkTarget(with_url, declaredInstance(.openai_compat, "http://127.0.0.1:9099/v1")),
    );
}

test "there is no option that takes the credential, and each one is refused by name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    for (forbidden_value_options) |forbidden| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "aiand", forbidden, "sk-x" }));
        try testing.expect(std.mem.indexOf(u8, said.err(), forbidden) != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "ps") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "--password-method stdin") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "sk-x") == null);
    }
    for ([_][]const u8{ "--token=sk-x", "--password=sk-x" }) |spelled| {
        said.clear();
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "aiand", spelled }));
        try testing.expect(std.mem.indexOf(u8, said.err(), "ps") != null);
        try testing.expect(std.mem.indexOf(u8, said.err(), "sk-x") == null);
    }
    try testing.expectEqualStrings("", said.out());
}

test "the password method parses in both spellings, and an unknown one is refused" {
    {
        const options = try parseOptions(&.{ "--provider", "aiand", "--password-method", "stdin" });
        try testing.expectEqual(std.meta.activeTag(options.method.?), .stdin);
    }
    {
        const options = try parseOptions(&.{ "--provider", "aiand", "--password-method=prompt" });
        try testing.expectEqual(std.meta.activeTag(options.method.?), .prompt);
    }
    {
        const options = try parseOptions(&.{ "--provider", "aiand", "--password-method=file=/run/secrets/x" });
        try testing.expectEqualStrings("/run/secrets/x", options.method.?.file);
    }
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "aiand", "--password-method", "argv" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "argv") != null);
    for ([_][]const u8{ "prompt", "stdin", "file=" }) |method| {
        try testing.expect(std.mem.indexOf(u8, said.err(), method) != null);
    }

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "aiand", "--password-method=file=" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "path") != null);
    try testing.expectEqualStrings("", said.out());
}

test "the provider takes its own value even when that value carries an equals sign" {
    const options = try parseOptions(&.{"--provider=openai-compat=http://127.0.0.1:5000/v1"});
    try testing.expectEqualStrings("openai-compat=http://127.0.0.1:5000/v1", options.provider);
    const split = try splitProvider(options.provider);
    try testing.expectEqualStrings("http://127.0.0.1:5000/v1", split.base_url);
}

test "an instance with no name takes the kind, and --name names one of its own" {
    {
        const options = try parseOptions(&.{ "--provider", "aiand" });
        try testing.expect(options.name == null);
    }
    {
        const options = try parseOptions(&.{ "--provider", "aiand", "--name", "work" });
        try testing.expectEqualStrings("work", options.name.?);
    }
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(&.{ "--provider", "aiand", "--name", "" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "empty") != null);

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{"--name"}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--name") != null);

    said.clear();
    try testing.expectError(error.BadArguments, parseOptions(&.{}));
    try testing.expect(std.mem.indexOf(u8, said.err(), "--provider, --search or --tool-secret is needed") != null);
    try testing.expectEqualStrings("", said.out());
}

test "--replace is a flag, and a login with neither it nor --name asks for itself" {
    {
        const options = try parseOptions(&.{ "--provider", "aiand", "--replace" });
        try testing.expect(options.replace);
        try testing.expect(options.name == null);
    }
    {
        const options = try parseOptions(&.{ "--provider", "aiand" });
        try testing.expect(!options.replace);
    }
}

test "a run with nobody to ask names both ways of meaning it" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    reportNameTaken("aiand", "aiand", "aiand");

    try testing.expect(std.mem.indexOf(u8, said.err(), "--replace") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--name") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "nobody to ask") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "A name is needed") == null);
}

test "--search names the credential and takes the place of --provider" {
    {
        const options = try parseOptions(&.{ "--search", "brave" });
        try testing.expectEqualStrings("brave", options.search.?);
        try testing.expectEqualStrings("", options.provider);
    }
    {
        const options = try parseOptions(&.{"--search=brave"});
        try testing.expectEqualStrings("brave", options.search.?);
    }
}

test "--provider and --search together are refused, and so is neither" {
    {
        var said: tty.Capture = undefined;
        said.start(testing.io, testing.allocator);
        defer said.stop(testing.io);
        try testing.expectError(
            error.BadArguments,
            parseOptions(&.{ "--provider", "aiand", "--search", "brave" }),
        );
        try testing.expect(std.mem.indexOf(u8, said.err(), "Run it again") != null);
    }
    {
        var said: tty.Capture = undefined;
        said.start(testing.io, testing.allocator);
        defer said.stop(testing.io);
        try testing.expectError(error.BadArguments, parseOptions(&.{}));
        try testing.expect(std.mem.indexOf(u8, said.err(), "--search") != null);
    }
}

test "--name says nothing next to --search, so it is refused rather than ignored" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "--search", "brave", "--name", "work" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "--name") != null);
}

test "a search name the credential store cannot hold is refused at the command line" {
    for ([_][]const u8{ "", "with space", "has:colon", "has/slash" }) |bad| {
        var said: tty.Capture = undefined;
        said.start(testing.io, testing.allocator);
        defer said.stop(testing.io);
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--search", bad }));
    }

    for ([_][]const u8{ "brave", "work-key", "my_key.2" }) |good| {
        const options = try parseOptions(&.{ "--search", good });
        try testing.expectEqualStrings(good, options.search.?);
    }
}

test "--tool-secret names what a project may grant, and stands beside neither other kind" {
    {
        const options = try parseOptions(&.{ "--tool-secret", "GITHUB_TOKEN" });
        try testing.expectEqualStrings("GITHUB_TOKEN", options.secret.?);
        try testing.expectEqualStrings("", options.provider);
        try testing.expectEqual(@as(?[]const u8, null), options.search);
    }
    {
        const options = try parseOptions(&.{"--tool-secret=GITHUB_TOKEN"});
        try testing.expectEqualStrings("GITHUB_TOKEN", options.secret.?);
    }

    for ([_][]const []const u8{
        &.{ "--tool-secret", "A", "--provider", "aiand" },
        &.{ "--tool-secret", "A", "--search", "brave" },
    }) |both| {
        var said: tty.Capture = undefined;
        said.start(testing.io, testing.allocator);
        defer said.stop(testing.io);
        try testing.expectError(error.BadArguments, parseOptions(both));
        try testing.expect(std.mem.indexOf(u8, said.err(), "Run it again") != null);
    }
}

test "a secret name a project could not write is refused at the command line" {
    for ([_][]const u8{ "", "has.dot", "has:colon", "with space", "has-dash" }) |bad| {
        var said: tty.Capture = undefined;
        said.start(testing.io, testing.allocator);
        defer said.stop(testing.io);
        try testing.expectError(error.BadArguments, parseOptions(&.{ "--tool-secret", bad }));
        try testing.expect(!chock_policy.secrets.nameIsWellFormed(bad));
    }

    for ([_][]const u8{ "GITHUB_TOKEN", "openai_key", "k3" }) |good| {
        const options = try parseOptions(&.{ "--tool-secret", good });
        try testing.expectEqualStrings(good, options.secret.?);
        try testing.expect(chock_policy.secrets.nameIsWellFormed(good));
    }
}

test "--name says nothing next to --tool-secret either" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(
        error.BadArguments,
        parseOptions(&.{ "--tool-secret", "GITHUB_TOKEN", "--name", "work" }),
    );
    try testing.expect(std.mem.indexOf(u8, said.err(), "--name") != null);
}

// --secret takes a value on the command line, which ps shows to every other user, so --tool-secret's name must not be reached by it.
test "--secret still refuses, and now says which option takes a name" {
    var said: tty.Capture = undefined;
    said.start(testing.io, testing.allocator);
    defer said.stop(testing.io);

    try testing.expectError(error.BadArguments, parseOptions(&.{ "--secret", "a-real-value" }));
    try testing.expect(std.mem.indexOf(u8, said.err(), "there is no --secret option") != null);
    try testing.expect(std.mem.indexOf(u8, said.err(), "--tool-secret takes its name") != null);
}
