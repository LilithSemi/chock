//! The configuration file, and the separate token file beside it. Both live

const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");

pub const file_name = "config.zon";

pub const token_file_name = "tokens.zon";

pub const max_file_bytes: usize = 256 * 1024;

pub const Kind = enum {
    anthropic,
    aiand,
    openai_compat,

    pub fn wireName(self: Kind) []const u8 {
        return switch (self) {
            .anthropic => "anthropic",
            .aiand => "aiand",
            .openai_compat => "openai-compat",
        };
    }

    pub fn fromWireName(text: []const u8) ?Kind {
        inline for (@typeInfo(Kind).@"enum".fields) |field| {
            const kind: Kind = @enumFromInt(field.value);
            if (std.mem.eql(u8, kind.wireName(), text)) return kind;
        }
        return null;
    }

    pub const all_wire_names = "anthropic, aiand, openai-compat";

    pub fn defaultBaseUrl(self: Kind) []const u8 {
        return switch (self) {
            .anthropic => "https://api.anthropic.com/v1",
            .aiand => "https://api.aiand.com/v1",
            .openai_compat => "",
        };
    }

    pub fn hostedEndpointNeedsCredential(self: Kind) bool {
        return switch (self) {
            .anthropic, .aiand => true,
            .openai_compat => false,
        };
    }
};

pub const Capabilities = struct {
    images: bool = false,
};

const FileInstance = struct {
    name: ?[]const u8 = null,
    kind: []const u8,
    base_url: ?[]const u8 = null,
    token: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    context_tokens: ?u64 = null,
    capabilities: ?Capabilities = null,
};

const FileDefaults = struct {
    provider: ?[]const u8 = null,
    model: ?[]const u8 = null,
};

const FileCredentials = struct {
    store: ?[]const u8 = null,
};

pub const CredentialStore = enum {
    file,
    secret_service,
    keychain,
    secretspec,

    pub fn default() CredentialStore {
        return switch (builtin.os.tag) {
            .macos => .keychain,
            else => .secret_service,
        };
    }

    pub fn availableHere(self: CredentialStore) bool {
        if (self == .secretspec) return true;
        return switch (builtin.os.tag) {
            .macos => self == .keychain,
            else => self != .keychain,
        };
    }

    pub fn hereText() []const u8 {
        return switch (builtin.os.tag) {
            .macos => "keychain or secretspec",
            else => "file, secret_service, or secretspec",
        };
    }
};

pub const Instance = struct {
    name: []const u8,
    kind: Kind,
    base_url: []const u8,
    credential: Credential,
    context_tokens: ?u64,
    capabilities: Capabilities,
};

pub const Credential = union(enum) {
    absent,
    token: []const u8,
    token_file: []const u8,
};

pub const TokenEntry = struct {
    name: []const u8,
    token: []const u8,
};

pub const ParseError = std.mem.Allocator.Error || error{
    InvalidConfig,
    UnknownProviderKind,
    DuplicateInstanceName,
    TwoCredentialSpellings,
    EmptyField,
    NoBaseUrl,
};

pub const LoadError = ParseError || error{
    NoConfigFile,
    ConfigTooLarge,
    ReadFailed,
};

pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: BlockNotValid,
    not_a_struct_literal,
    token_file_not_valid: std.zon.parse.Diagnostics,
    token_file_readable_by_others: ReadableByOthers,
    empty_default: []const u8,
    unknown_provider_kind: []const u8,
    empty_provider_name,
    two_credential_spellings: []const u8,
    empty_provider_field: EmptyProviderField,
    no_base_url: NoBaseUrl,
    duplicate_instance_name: DuplicateInstanceName,
    read_failed: ReadFailed,
    unknown_credential_store: UnknownCredentialStore,
    credential_store_not_here: CredentialStoreNotHere,

    pub const BlockNotValid = struct {
        field: []const u8,
        zon: std.zon.parse.Diagnostics,
    };

    pub const EmptyProviderField = struct {
        name: []const u8,
        field: []const u8,
    };

    pub const NoBaseUrl = struct {
        name: []const u8,
        kind: []const u8,
    };

    pub const DuplicateInstanceName = struct {
        name: []const u8,
        shared_kind: ?[]const u8,
    };

    pub const UnknownCredentialStore = struct {
        spelled: []const u8,
    };

    pub const CredentialStoreNotHere = struct {
        store: CredentialStore,
    };

    pub const ReadFailed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const ReadableByOthers = struct {
        path: []const u8,
        mode: u32,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .token_file_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            .block_not_valid => |*block| block.zon.deinit(gpa),
            .unknown_provider_kind, .two_credential_spellings => |name| gpa.free(name),
            .empty_provider_field => |field| gpa.free(field.name),
            .no_base_url => |names| gpa.free(names.name),
            .duplicate_instance_name => |names| gpa.free(names.name),
            .read_failed => |failure| gpa.free(failure.path),
            .token_file_readable_by_others => |failure| gpa.free(failure.path),
            .unknown_credential_store => |named| gpa.free(named.spelled),
            .not_a_struct_literal, .empty_provider_name, .empty_default, .credential_store_not_here => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*block| try writer.print(
                "{s}: .{s} is not valid:\n{f}",
                .{ file_name, block.field, &block.zon },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .token_file_not_valid => |*zon_diag| try writer.print(
                "{s}: the token file is not valid:\n{f}",
                .{ token_file_name, zon_diag },
            ),
            .empty_default => |field| try writer.print(
                "{s}: .defaults.{s} holds nothing. Leave the field out instead.",
                .{ file_name, field },
            ),
            .unknown_provider_kind => |kind| try writer.print(
                "{s}: the provider kind \"{s}\" is not one Chock knows. The kinds are: {s}",
                .{ file_name, kind, Kind.all_wire_names },
            ),
            .empty_provider_name => try writer.print(
                "{s}: a provider names itself \"\". Leave .name out to take the kind as the name.",
                .{file_name},
            ),
            .two_credential_spellings => |name| try writer.print(
                "{s}: the provider {s} gives both .token and .token_file, so which one to read is not decided. " ++
                    "Name one of them.",
                .{ file_name, name },
            ),
            .empty_provider_field => |field| try writer.print(
                "{s}: the provider {s} gives .{s} = \"\".{s}",
                .{ file_name, field.name, field.field, emptyFieldAdvice(field.field) },
            ),
            .no_base_url => |names| try writer.print(
                "{s}: the provider {s} is of kind {s}, which has no address of its own, so it needs " ++
                    ".base_url.",
                .{ file_name, names.name, names.kind },
            ),
            .duplicate_instance_name => |names| {
                if (names.shared_kind) |kind| {
                    try writer.print(
                        "{s}: two providers of kind {s} are both named {s}. Give each one its own .name.",
                        .{ file_name, kind, names.name },
                    );
                } else {
                    try writer.print(
                        "{s}: two providers are both named {s}. A name selects one provider, so each " ++
                            "one needs its own.",
                        .{ file_name, names.name },
                    );
                }
            },
            .unknown_credential_store => |named| try writer.print(
                "the credentials block names the store \"{s}\", and this reader knows file, " ++
                    "secret_service, keychain, and secretspec",
                .{named.spelled},
            ),
            .credential_store_not_here => |named| try writer.print(
                "the credentials block names the {s} store, which this platform does not have. " ++
                    "It has {s}.",
                .{ @tagName(named.store), CredentialStore.hereText() },
            ),
            .read_failed => |failure| try writer.print(
                "reading {s} failed: {s}",
                .{ failure.path, @errorName(failure.err) },
            ),
            .token_file_readable_by_others => |failure| try writer.print(
                "the credential file {s} has mode {o:0>4}, and a credential must be readable by its owner only. " ++
                    "Run: chmod 600 {s}",
                .{ failure.path, failure.mode, failure.path },
            ),
        }
    }
};

fn emptyFieldAdvice(field: []const u8) []const u8 {
    if (std.mem.eql(u8, field, "token")) {
        return " Leave the field out: absence already means look the credential up, " ++
            "and send none if there is none.";
    }
    if (std.mem.eql(u8, field, "token_file")) return " Leave the field out instead.";
    return "";
}

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

pub const Config = struct {
    gpa: std.mem.Allocator,
    providers: []const FileInstance,
    credential_store: CredentialStore,
    defaults: FileDefaults,
    instances: []Instance,
    default_provider: ?[]const u8,
    default_model: ?[]const u8,

    pub fn deinit(self: *Config) void {
        self.gpa.free(self.instances);
        std.zon.parse.free(self.gpa, self.providers);
        std.zon.parse.free(self.gpa, self.defaults);
        self.* = undefined;
    }

    pub fn find(self: *const Config, name: []const u8) ?Instance {
        for (self.instances) |instance| {
            if (std.mem.eql(u8, instance.name, name)) return instance;
        }
        return null;
    }

    pub fn defaultInstance(self: *const Config) ?Instance {
        if (self.default_provider) |name| return self.find(name);
        if (self.instances.len == 1) return self.instances[0];
        return null;
    }
};

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Config {
    // Each top level block is parsed on its own and strictly: a typo in a field name inside a provider must not quietly become a different instance. A top level field this build does not know is ignored instead, because a later milestone writes more into this same file, and std.zon.parse's own ignore_unknown_fields is one setting for the whole tree and cannot tell the two cases apart.
    const providers = try parseBlock([]const FileInstance, gpa, source, "providers", diag) orelse &.{};
    errdefer std.zon.parse.free(gpa, providers);
    const defaults = try parseBlock(FileDefaults, gpa, source, "defaults", diag) orelse FileDefaults{};
    errdefer std.zon.parse.free(gpa, defaults);

    const credentials = try parseBlock(FileCredentials, gpa, source, "credentials", diag) orelse
        FileCredentials{};
    defer std.zon.parse.free(gpa, credentials);
    const credential_store = try readCredentialStore(gpa, credentials, diag);

    const instances = try gpa.alloc(Instance, providers.len);
    errdefer gpa.free(instances);

    for (providers, instances) |entry, *slot| slot.* = try checkInstance(gpa, entry, diag);
    try refuseDuplicateNames(gpa, instances, diag);

    if (defaults.provider) |name| {
        if (name.len == 0) {
            _ = note(diag, .{ .empty_default = "provider" });
            return error.EmptyField;
        }
    }
    if (defaults.model) |model| {
        if (model.len == 0) {
            _ = note(diag, .{ .empty_default = "model" });
            return error.EmptyField;
        }
    }

    return .{
        .gpa = gpa,
        .providers = providers,
        .defaults = defaults,
        .instances = instances,
        .credential_store = credential_store,
        .default_provider = defaults.provider,
        .default_model = defaults.model,
    };
}

pub fn credentialStore(gpa: std.mem.Allocator, io: std.Io, config_dir: []const u8) CredentialStore {
    var loaded = load(gpa, io, config_dir, null) catch return CredentialStore.default();
    defer loaded.deinit();
    return loaded.credential_store;
}

fn readCredentialStore(
    gpa: std.mem.Allocator,
    block: FileCredentials,
    diag: ?*?Diagnostic,
) ParseError!CredentialStore {
    const spelled = block.store orelse return CredentialStore.default();

    const named = std.meta.stringToEnum(CredentialStore, spelled) orelse {
        const copy = try gpa.dupe(u8, spelled);
        if (!note(diag, .{ .unknown_credential_store = .{ .spelled = copy } })) gpa.free(copy);
        return error.InvalidConfig;
    };
    if (!named.availableHere()) {
        _ = note(diag, .{ .credential_store_not_here = .{ .store = named } });
        return error.InvalidConfig;
    }
    return named;
}

fn parseBlock(
    comptime T: type,
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    field_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?T {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidConfig;
    }

    const node = try findField(zoir, field_name, diag) orelse return null;

    var diagnostics: std.zon.parse.Diagnostics = .{};
    ast_owned = false;
    zoir_owned = false;
    var diagnostics_owned = true;
    defer if (diagnostics_owned) diagnostics.deinit(gpa);

    return std.zon.parse.fromZoirNodeAlloc(T, gpa, ast, zoir, node, &diagnostics, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = .{ .field = field_name, .zon = diagnostics } })) {
                diagnostics_owned = false;
            }
            return error.InvalidConfig;
        },
    };
}

fn findField(
    zoir: std.zig.Zoir,
    field_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), field_name)) return fields.vals.at(@intCast(index));
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidConfig;
        },
    }
}

fn checkInstance(gpa: std.mem.Allocator, entry: FileInstance, diag: ?*?Diagnostic) ParseError!Instance {
    const kind = Kind.fromWireName(entry.kind) orelse {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .unknown_provider_kind = try gpa.dupe(u8, entry.kind) });
        }
        return error.UnknownProviderKind;
    };

    const name = name: {
        const given = entry.name orelse break :name kind.wireName();
        if (given.len == 0) {
            _ = note(diag, .empty_provider_name);
            return error.EmptyField;
        }
        break :name given;
    };

    if (entry.token != null and entry.token_file != null) {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .two_credential_spellings = try gpa.dupe(u8, name) });
        }
        return error.TwoCredentialSpellings;
    }

    const credential: Credential = credential: {
        if (entry.token) |token| {
            if (token.len == 0) {
                try noteEmptyProviderField(gpa, diag, name, "token");
                return error.EmptyField;
            }
            break :credential .{ .token = token };
        }
        if (entry.token_file) |path| {
            if (path.len == 0) {
                try noteEmptyProviderField(gpa, diag, name, "token_file");
                return error.EmptyField;
            }
            break :credential .{ .token_file = path };
        }
        break :credential .absent;
    };

    const base_url = base: {
        const given = entry.base_url orelse break :base kind.defaultBaseUrl();
        if (given.len == 0) {
            try noteEmptyProviderField(gpa, diag, name, "base_url");
            return error.EmptyField;
        }
        break :base given;
    };
    if (base_url.len == 0) {
        if (wantsDiagnostic(diag)) {
            _ = note(diag, .{ .no_base_url = .{
                .name = try gpa.dupe(u8, name),
                .kind = kind.wireName(),
            } });
        }
        return error.NoBaseUrl;
    }

    return .{
        .name = name,
        .kind = kind,
        .base_url = base_url,
        .credential = credential,
        .context_tokens = entry.context_tokens,
        .capabilities = entry.capabilities orelse .{},
    };
}

fn refuseDuplicateNames(
    gpa: std.mem.Allocator,
    instances: []const Instance,
    diag: ?*?Diagnostic,
) ParseError!void {
    for (instances, 0..) |instance, index| {
        for (instances[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, instance.name, other.name)) continue;
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .duplicate_instance_name = .{
                    .name = try gpa.dupe(u8, instance.name),
                    .shared_kind = if (instance.kind == other.kind)
                        instance.kind.wireName()
                    else
                        null,
                } });
            }
            return error.DuplicateInstanceName;
        }
    }
}

fn noteEmptyProviderField(
    gpa: std.mem.Allocator,
    diag: ?*?Diagnostic,
    name: []const u8,
    comptime field: []const u8,
) std.mem.Allocator.Error!void {
    if (!wantsDiagnostic(diag)) return;
    _ = note(diag, .{ .empty_provider_field = .{
        .name = try gpa.dupe(u8, name),
        .field = field,
    } });
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Config {
    const path = try std.fs.path.join(gpa, &.{ config_dir, file_name });
    defer gpa.free(path);
    const source = try readWholeFile(gpa, io, path, diag);
    defer gpa.free(source);
    return parse(gpa, source, diag);
}

pub const Tokens = struct {
    gpa: std.mem.Allocator,
    entries: []const TokenEntry,

    pub fn deinit(self: *Tokens) void {
        std.zon.parse.free(self.gpa, self.entries);
        self.* = undefined;
    }

    pub fn find(self: *const Tokens, name: []const u8) ?[]const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.token;
        }
        return null;
    }
};

pub fn loadTokens(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Tokens {
    const path = try std.fs.path.join(gpa, &.{ config_dir, token_file_name });
    defer gpa.free(path);

    // The mode rule covers every source, including a file Chock never wrote itself: a token file anyone else can read is a leaked credential however it got there.
    var mode_fault: ?paths.Diagnostic = null;
    paths.requirePrivate(io, path, &mode_fault) catch |err| switch (err) {
        error.CredentialFileMissing => {},
        error.StatFailed => {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .read_failed = .{
                    .path = try gpa.dupe(u8, path),
                    .err = mode_fault.?.stat_failed.err,
                } });
            }
            return error.ReadFailed;
        },
        error.CredentialFileIsReadable => {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .token_file_readable_by_others = .{
                    .path = try gpa.dupe(u8, path),
                    .mode = mode_fault.?.readable_by_others.mode,
                } });
            }
            return error.InvalidConfig;
        },
    };

    const source = try readWholeFile(gpa, io, path, diag);
    defer gpa.free(source);

    var diagnostics: std.zon.parse.Diagnostics = .{};
    var diagnostics_owned = true;
    defer if (diagnostics_owned) diagnostics.deinit(gpa);
    const entries = std.zon.parse.fromSliceAlloc([]const TokenEntry, gpa, source, &diagnostics, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .token_file_not_valid = diagnostics })) diagnostics_owned = false;
            return error.InvalidConfig;
        },
    };
    return .{ .gpa = gpa, .entries = entries };
}

fn readWholeFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diag: ?*?Diagnostic,
) LoadError![:0]u8 {
    return std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.ConfigTooLarge,
        error.FileNotFound, error.NotDir => return error.NoConfigFile,
        else => {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .read_failed = .{
                    .path = try gpa.dupe(u8, path),
                    .err = err,
                } });
            }
            return error.ReadFailed;
        },
    };
}

const testing = std.testing;

test "an instance with no name takes its kind as the name, and a named one keeps its own" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .name = "personal", .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expectEqual(@as(usize, 2), config.instances.len);
    try testing.expectEqualStrings("aiand", config.instances[0].name);
    try testing.expectEqualStrings("personal", config.instances[1].name);
    try testing.expectEqual(Kind.aiand, config.instances[0].kind);
    try testing.expectEqual(Kind.aiand, config.instances[1].kind);
    try testing.expectEqualStrings("personal", config.find("personal").?.name);
    try testing.expect(config.find("work") == null);
}

test "a second instance of a kind with no name is refused, never silently replacing the first" {
    const gpa = testing.allocator;
    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .kind = "aiand" },
        \\    },
        \\}
    , null));

    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand" },
        \\        .{ .name = "work", .kind = "anthropic" },
        \\    },
        \\}
    , null));
}

test "both credential spellings parse, and an instance with neither says absent" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
        \\        .{ .name = "work", .kind = "aiand", .token_file = "/run/secrets/aiand" },
        \\        .{ .name = "personal", .kind = "aiand", .token = "sk-written-in-place" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expectEqual(Credential.absent, std.meta.activeTag(config.find("local").?.credential));
    try testing.expectEqualStrings("/run/secrets/aiand", config.find("work").?.credential.token_file);
    try testing.expectEqualStrings("sk-written-in-place", config.find("personal").?.credential.token);
}

test "an instance that gives both spellings is refused rather than one of them guessed" {
    const gpa = testing.allocator;
    try testing.expectError(error.TwoCredentialSpellings, parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand", .token = "sk-one", .token_file = "/run/secrets/two" },
        \\    },
        \\}
    , null));
}

test "a field that is present and holds nothing is refused, because absence already has a meaning" {
    const gpa = testing.allocator;
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .token = "" } } }
    , null));
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .token_file = "" } } }
    , null));
    try testing.expectError(error.EmptyField, parse(gpa,
        \\.{ .providers = .{ .{ .name = "", .kind = "aiand" } } }
    , null));
}

test "a kind Chock does not know is refused, and a kind with no address of its own needs one" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , null));
    try testing.expectError(error.NoBaseUrl, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai-compat" } } }
    , null));

    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .kind = "aiand" },
        \\        .{ .name = "mirror", .kind = "aiand", .base_url = "https://mirror.example.invalid/v1" },
        \\    },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqualStrings(Kind.aiand.defaultBaseUrl(), config.find("aiand").?.base_url);
    try testing.expectEqualStrings("https://mirror.example.invalid/v1", config.find("mirror").?.base_url);
}

test "an instance can say how many tokens its model holds, and one that says nothing reads null" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1", .context_tokens = 65536 },
        \\        .{ .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqual(@as(?u64, 65536), config.find("local").?.context_tokens);
    try testing.expect(config.find("aiand").?.context_tokens == null);
}

test "a field name with a typo inside a provider is refused, and a whole section from a newer Chock is not" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .tokn = "sk-typo" } } }
    , null));

    var config = try parse(gpa,
        \\.{
        \\    .providers = .{ .{ .kind = "aiand" } },
        \\    .roster = .{ .main = "aiand" },
        \\}
    , null);
    defer config.deinit();
    try testing.expectEqual(@as(usize, 1), config.instances.len);
}

test "the default instance is the one the file names, or the only one, and never a guess between two" {
    const gpa = testing.allocator;
    {
        var config = try parse(gpa,
            \\.{ .providers = .{ .{ .kind = "aiand" } } }
        , null);
        defer config.deinit();
        try testing.expectEqualStrings("aiand", config.defaultInstance().?.name);
    }
    {
        var config = try parse(gpa,
            \\.{
            \\    .providers = .{ .{ .kind = "aiand" }, .{ .name = "personal", .kind = "aiand" } },
            \\}
        , null);
        defer config.deinit();
        try testing.expect(config.defaultInstance() == null);
    }
    {
        var config = try parse(gpa,
            \\.{
            \\    .providers = .{ .{ .kind = "aiand" }, .{ .name = "personal", .kind = "aiand" } },
            \\    .defaults = .{ .provider = "personal", .model = "a-model" },
            \\}
        , null);
        defer config.deinit();
        try testing.expectEqualStrings("personal", config.defaultInstance().?.name);
        try testing.expectEqualStrings("a-model", config.default_model.?);
    }
}

test "the separate token file is read, and one that others can read is refused" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, "{s}/{s}", .{ dir, token_file_name });

    {
        var file = try std.Io.Dir.createFileAbsolute(testing.io, path, .{ .truncate = true });
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io,
            \\.{
            \\    .{ .name = "work", .token = "sk-from-the-token-file" },
            \\}
        );
        try file.setPermissions(testing.io, .fromMode(0o600));
    }

    {
        var tokens = try loadTokens(gpa, testing.io, dir, null);
        defer tokens.deinit();
        try testing.expectEqualStrings("sk-from-the-token-file", tokens.find("work").?);
        try testing.expect(tokens.find("personal") == null);
    }

    {
        var file = try std.Io.Dir.openFileAbsolute(testing.io, path, .{});
        defer file.close(testing.io);
        try file.setPermissions(testing.io, .fromMode(0o644));
    }
    try testing.expectError(error.InvalidConfig, loadTokens(gpa, testing.io, dir, null));
}

test "a missing configuration file and a missing token file are both reported, never taken as empty" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buffer);
    const dir = dir_buffer[0..dir_len];

    try testing.expectError(error.NoConfigFile, load(gpa, testing.io, dir, null));
    try testing.expectError(error.NoConfigFile, loadTokens(gpa, testing.io, dir, null));
}

test "an instance says what it can do, and an instance that says nothing gets no capability" {
    const gpa = testing.allocator;
    var config = try parse(gpa,
        \\.{
        \\    .providers = .{
        \\        .{ .name = "work", .kind = "aiand", .capabilities = .{ .images = true } },
        \\        .{ .name = "personal", .kind = "aiand" },
        \\    },
        \\}
    , null);
    defer config.deinit();

    try testing.expect(config.find("work").?.capabilities.images);
    try testing.expect(!config.find("personal").?.capabilities.images);
}

test "a capability this build has never heard of is refused, never taken as a yes" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .capabilities = .{ .telepathy = true } } } }
    , null));
}

test "the provider a refused entry names reaches the caller, and no longer only a terminal" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , &diag));
    try testing.expectEqualStrings("openai", diag.?.unknown_provider_kind);

    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "config.zon: the provider kind \"openai\" is not one Chock knows. " ++
            "The kinds are: anthropic, aiand, openai-compat",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a name in a refused entry is a copy, because the providers block is released" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.DuplicateInstanceName, parse(gpa,
        \\.{ .providers = .{
        \\    .{ .name = "work", .kind = "aiand" },
        \\    .{ .name = "work", .kind = "anthropic" },
        \\} }
    , &diag));
    try testing.expectEqualStrings("work", diag.?.duplicate_instance_name.name);
    try testing.expectEqual(@as(?[]const u8, null), diag.?.duplicate_instance_name.shared_kind);

    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "config.zon: two providers are both named work. " ++
            "A name selects one provider, so each one needs its own.",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a typo inside a provider names its block, its line and its column" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidConfig, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "aiand", .tokn = "sk-typo" } } }
    , &diag));

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.startsWith(u8, line, "config.zon: .providers is not valid:\n"));
    try testing.expect(std.mem.indexOf(u8, line, "1:41: error:") != null);
    try testing.expect(std.mem.indexOf(u8, line, "tokn") != null);
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    const gpa = testing.allocator;
    try testing.expectError(error.UnknownProviderKind, parse(gpa,
        \\.{ .providers = .{ .{ .kind = "openai" } } }
    , null));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .not_a_struct_literal));
    try testing.expect(!note(&diag, .empty_provider_name));
    try testing.expectEqual(Diagnostic.not_a_struct_literal, diag.?);

    try testing.expect(!note(null, .not_a_struct_literal));
    try testing.expect(!wantsDiagnostic(null));
    try testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .empty_provider_name,
        .{ .empty_default = "provider" },
        .{ .empty_default = "model" },
        .{ .unknown_provider_kind = "openai" },
        .{ .two_credential_spellings = "work" },
        .{ .empty_provider_field = .{ .name = "work", .field = "token" } },
        .{ .empty_provider_field = .{ .name = "work", .field = "token_file" } },
        .{ .empty_provider_field = .{ .name = "work", .field = "base_url" } },
        .{ .no_base_url = .{ .name = "work", .kind = "openai-compat" } },
        .{ .duplicate_instance_name = .{ .name = "work", .shared_kind = null } },
        .{ .duplicate_instance_name = .{ .name = "work", .shared_kind = "aiand" } },
        .{ .read_failed = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .token_file_readable_by_others = .{ .path = "/x", .mode = 0o644 } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "the credentials block names where a credential is kept" {
    const gpa = testing.allocator;

    var named = try parse(gpa, ".{ .credentials = .{ .store = \"secretspec\" } }", null);
    defer named.deinit();
    try testing.expectEqual(CredentialStore.secretspec, named.credential_store);

    var silent = try parse(gpa, ".{}", null);
    defer silent.deinit();
    try testing.expectEqual(CredentialStore.default(), silent.credential_store);
    try testing.expect(silent.credential_store != .secretspec);
}

test "a store this reader does not know is refused, and the message lists them all" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidConfig,
        parse(gpa, ".{ .credentials = .{ .store = \"kwallet\" } }", &diag),
    );
    try testing.expectEqualStrings("kwallet", diag.?.unknown_credential_store.spelled);

    const text = try std.fmt.allocPrint(gpa, "{f}", .{diag.?});
    defer gpa.free(text);
    inline for (@typeInfo(CredentialStore).@"enum".fields) |field| {
        try testing.expect(std.mem.indexOf(u8, text, field.name) != null);
    }
}

test "a store this platform does not have is refused when the file is read" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const absent = if (builtin.os.tag == .macos) "secret_service" else "keychain";
    const source = ".{ .credentials = .{ .store = \"" ++ absent ++ "\" } }";

    try testing.expectError(error.InvalidConfig, parse(gpa, source, &diag));
    try testing.expect(diag.? == .credential_store_not_here);

    const text = try std.fmt.allocPrint(gpa, "{f}", .{diag.?});
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, CredentialStore.hereText()) != null);
}

test "every store this platform has is one this platform accepts" {
    inline for (@typeInfo(CredentialStore).@"enum".fields) |field| {
        const one: CredentialStore = @enumFromInt(field.value);
        const listed = std.mem.indexOf(u8, CredentialStore.hereText(), field.name) != null;
        try testing.expectEqual(one.availableHere(), listed);
    }
    try testing.expect(CredentialStore.default().availableHere());
}
