//! The `search` block of the operator's own `config.zon`: the web search
//! engine an agent may call. A search engine is the user's own
//! infrastructure, the same way a model provider is, so this block is read
//! from the operator's file and never from a project's own `chock.zon`.

const std = @import("std");
const limits_mod = @import("limits.zig");

pub const block_name = "search";

pub const Kind = enum {
    self_hosted,
    api,
    scrape,
};

/// Which keyed search vendor an `api` engine talks to. Each one has its own
/// request shape and its own reply shape, so the kind alone does not say
/// enough to read a reply.
pub const Provider = enum {
    brave,
    kagi,
};

/// Every member is optional, so "no search block" is told apart from a block
/// that names its own fields.
pub const Search = struct {
    kind: ?Kind = null,
    provider: ?Provider = null,
    base_url: ?[]const u8 = null,
    credential: ?[]const u8 = null,

    pub fn deinit(self: *Search, gpa: std.mem.Allocator) void {
        if (self.base_url) |value| gpa.free(value);
        if (self.credential) |value| gpa.free(value);
        self.* = undefined;
    }
};

/// Supplied by the org bundle. Absent `kinds` permits every kind; absent
/// `base_url` leaves the choice to the user. Neither field ever widens what
/// the user already chose, only narrows it.
pub const Ceiling = struct {
    kinds: ?[]const Kind = null,
    base_url: ?[]const u8 = null,
};

pub const BaseUrlError = error{
    NotAUrl,
    NoHost,
    SchemeNotAllowed,
    InsecureNotLoopback,
};

pub fn reasonText(reason: BaseUrlError) []const u8 {
    return switch (reason) {
        error.NotAUrl => "does not parse as a URL",
        error.NoHost => "names no host",
        error.SchemeNotAllowed => "must use https, and only a loopback host may use http",
        error.InsecureNotLoopback => "uses http on a host that is not loopback, so the request would leave the machine in the clear",
    };
}

fn hostText(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw => |text| text,
        .percent_encoded => |text| text,
    };
}

/// The whole 127.0.0.0/8 block loops back, not only 127.0.0.1, so a prefix
/// check is enough without a full address parse.
fn isLoopbackHost(host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.mem.eql(u8, host, "::1")) return true;
    return std.mem.startsWith(u8, host, "127.");
}

fn checkBaseUrl(text: []const u8) BaseUrlError!void {
    const uri = std.Uri.parse(text) catch return error.NotAUrl;
    const is_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    const is_http = std.ascii.eqlIgnoreCase(uri.scheme, "http");
    if (!is_https and !is_http) return error.SchemeNotAllowed;
    const host = uri.host orelse return error.NoHost;
    if (is_https) return;
    if (!isLoopbackHost(hostText(host))) return error.InsecureNotLoopback;
}

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Fault = union(enum) {
        file_not_zon: std.zon.parse.Diagnostics,
        not_a_struct_literal,
        unknown_field: []const u8,
        inline_secret: []const u8,
        kind_not_a_string,
        kind_unknown: []const u8,
        kind_missing,
        provider_not_a_string,
        provider_unknown: []const u8,
        provider_missing,
        provider_not_for_kind: Kind,
        base_url_not_a_string,
        base_url_invalid: InvalidBaseUrl,
        base_url_missing,
        credential_not_a_string,
        credential_empty,
        credential_missing,
        kind_not_permitted: Kind,
        base_url_not_permitted: BaseUrlMismatch,
        file_too_large: usize,
        read_failed: anyerror,
    };

    pub const InvalidBaseUrl = struct {
        text: []const u8,
        reason: BaseUrlError,
    };

    /// Borrowed from the caller's own `Search` and `Ceiling`, and not owned
    /// by the diagnostic.
    pub const BaseUrlMismatch = struct {
        text: []const u8,
        required: []const u8,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| zon_diag.deinit(gpa),
            .unknown_field, .inline_secret, .kind_unknown, .provider_unknown => |name| gpa.free(name),
            .base_url_invalid => |invalid| gpa.free(invalid.text),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ self.source, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .unknown_field => |field| try writer.print(
                "{s}: the search block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .inline_secret => |field| try writer.print(
                "{s}: the search block names a {s} field. A credential value must never be " ++
                    "written here. It belongs in the credential store, and chock login --search puts it there.",
                .{ self.source, field },
            ),
            .kind_not_a_string => try writer.print(
                "{s}: the search block's kind field must be a string",
                .{self.source},
            ),
            .kind_unknown => |text| try writer.print(
                "{s}: the search block's kind field holds \"{s}\", and this reader knows " ++
                    "self_hosted, api, or scrape",
                .{ self.source, text },
            ),
            .kind_missing => try writer.print(
                "{s}: the search block names no kind, and one of self_hosted, api, or scrape is required",
                .{self.source},
            ),
            .provider_not_a_string => try writer.print(
                "{s}: the search block's provider field must be a string",
                .{self.source},
            ),
            .provider_unknown => |text| try writer.print(
                "{s}: the search block's provider field holds \"{s}\", and this reader knows brave or kagi",
                .{ self.source, text },
            ),
            .provider_missing => try writer.print(
                "{s}: the search block's kind is api, and a provider naming the vendor is required",
                .{self.source},
            ),
            .provider_not_for_kind => |kind| try writer.print(
                "{s}: the search block names a provider, and provider applies to the api kind only, not {s}",
                .{ self.source, @tagName(kind) },
            ),
            .base_url_not_a_string => try writer.print(
                "{s}: the search block's base_url field must be a string",
                .{self.source},
            ),
            .base_url_invalid => |invalid| try writer.print(
                "{s}: the search block's base_url field holds \"{s}\", which {s}",
                .{ self.source, invalid.text, reasonText(invalid.reason) },
            ),
            .base_url_missing => try writer.print(
                "{s}: the search block names no base_url, and one is required",
                .{self.source},
            ),
            .credential_not_a_string => try writer.print(
                "{s}: the search block's credential field must be a string",
                .{self.source},
            ),
            .credential_empty => try writer.print(
                "{s}: the search block's credential field is empty, and a credential store name cannot be",
                .{self.source},
            ),
            .credential_missing => try writer.print(
                "{s}: the search block's kind is api, and a credential is required. It names an " ++
                    "entry in the credential store, and chock login --search <name> puts one there.",
                .{self.source},
            ),
            .kind_not_permitted => |kind| try writer.print(
                "{s}: the org policy bundle does not permit the search kind {s}",
                .{ self.source, @tagName(kind) },
            ),
            .base_url_not_permitted => |mismatch| try writer.print(
                "{s}: the org policy bundle requires the search base_url {s}, and this one is {s}",
                .{ self.source, mismatch.required, mismatch.text },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ self.source, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ self.source, err },
            ),
        }
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidSearch,
};

pub const LoadError = ParseError || error{
    SearchFileTooLarge,
    ReadFailed,
};

pub const CeilingError = error{
    KindNotPermitted,
    BaseUrlNotPermitted,
};

fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Search {
    return parseFrom(gpa, source, limits_mod.operator_file_name, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Search {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, source_name, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidSearch;
    }

    const node = try findSearchNode(zoir, source_name, diag) orelse return .{};
    return parseFields(gpa, zoir, node, source_name, diag);
}

fn findSearchNode(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidSearch;
        },
    }
}

const forbidden_secret_fields = [_][]const u8{ "key", "token", "api_key", "secret" };

fn isForbiddenSecretField(name: []const u8) bool {
    for (forbidden_secret_fields) |bad| {
        if (std.mem.eql(u8, bad, name)) return true;
    }
    return false;
}

fn parseFields(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Search {
    var search = Search{};
    errdefer search.deinit(gpa);
    switch (node.get(zoir)) {
        .empty_literal => {},
        .struct_literal => |fields| {
            for (fields.names, 0..) |name_id, index| {
                const name = name_id.get(zoir);
                const value_node = fields.vals.at(@intCast(index));
                if (isForbiddenSecretField(name)) {
                    _ = note(diag, source_name, .{ .inline_secret = try gpa.dupe(u8, name) });
                    return error.InvalidSearch;
                } else if (std.mem.eql(u8, name, "kind")) {
                    search.kind = try readKind(gpa, zoir, value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "provider")) {
                    search.provider = try readProvider(gpa, zoir, value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "base_url")) {
                    search.base_url = try readBaseUrl(gpa, zoir, value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "credential")) {
                    search.credential = try readCredential(gpa, zoir, value_node, source_name, diag);
                } else {
                    _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, name) });
                    return error.InvalidSearch;
                }
            }
        },
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidSearch;
        },
    }

    // The block being present at all commits it to naming a real engine.
    if (search.kind == null) {
        _ = note(diag, source_name, .kind_missing);
        return error.InvalidSearch;
    }
    if (search.base_url == null) {
        _ = note(diag, source_name, .base_url_missing);
        return error.InvalidSearch;
    }

    const kind = search.kind.?;
    // A keyed engine with no key cannot work, so the provider and the
    // credential are required now, not on the agent's first search.
    if (kind == .api) {
        if (search.provider == null) {
            _ = note(diag, source_name, .provider_missing);
            return error.InvalidSearch;
        }
        if (search.credential == null) {
            _ = note(diag, source_name, .credential_missing);
            return error.InvalidSearch;
        }
    } else if (search.provider != null) {
        _ = note(diag, source_name, .{ .provider_not_for_kind = kind });
        return error.InvalidSearch;
    }
    return search;
}

fn readKind(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Kind {
    const text = switch (node.get(zoir)) {
        .string_literal => |text| text,
        else => {
            _ = note(diag, source_name, .kind_not_a_string);
            return error.InvalidSearch;
        },
    };
    return std.meta.stringToEnum(Kind, text) orelse {
        _ = note(diag, source_name, .{ .kind_unknown = try gpa.dupe(u8, text) });
        return error.InvalidSearch;
    };
}

fn readProvider(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Provider {
    const text = switch (node.get(zoir)) {
        .string_literal => |text| text,
        else => {
            _ = note(diag, source_name, .provider_not_a_string);
            return error.InvalidSearch;
        },
    };
    return std.meta.stringToEnum(Provider, text) orelse {
        _ = note(diag, source_name, .{ .provider_unknown = try gpa.dupe(u8, text) });
        return error.InvalidSearch;
    };
}

fn readBaseUrl(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    const text = switch (node.get(zoir)) {
        .string_literal => |text| text,
        else => {
            _ = note(diag, source_name, .base_url_not_a_string);
            return error.InvalidSearch;
        },
    };
    checkBaseUrl(text) catch |err| {
        const owned_text = try gpa.dupe(u8, text);
        if (!note(diag, source_name, .{ .base_url_invalid = .{ .text = owned_text, .reason = err } })) {
            gpa.free(owned_text);
        }
        return error.InvalidSearch;
    };
    return gpa.dupe(u8, text);
}

fn readCredential(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    const text = switch (node.get(zoir)) {
        .string_literal => |text| text,
        else => {
            _ = note(diag, source_name, .credential_not_a_string);
            return error.InvalidSearch;
        },
    };
    if (text.len == 0) {
        _ = note(diag, source_name, .credential_empty);
        return error.InvalidSearch;
    }
    return gpa.dupe(u8, text);
}

/// There is no project-level loader: `chock.zon` never carries a `search`
/// block, so the operator's `config.zon` is the only file this reads.
pub fn loadOperator(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Search {
    const path = try std.fs.path.join(gpa, &.{ config_dir, limits_mod.operator_file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(limits_mod.max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return .{},
        error.StreamTooLong => {
            _ = note(diag, limits_mod.operator_file_name, .{ .file_too_large = limits_mod.max_file_bytes });
            return error.SearchFileTooLarge;
        },
        else => {
            _ = note(diag, limits_mod.operator_file_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

fn containsKind(allowed: []const Kind, kind: Kind) bool {
    for (allowed) |one| {
        if (one == kind) return true;
    }
    return false;
}

/// The single configured layer, held to the org ceiling. There is no project
/// layer to fold in: see `loadOperator`.
pub fn foldLayers(operator: Search, ceiling: ?Ceiling, diag: ?*?Diagnostic) CeilingError!Search {
    return underCeiling(operator, ceiling, diag);
}

/// A refusal, and never a silent narrowing: `kind` and `base_url` are
/// categorical, not a quantity a ceiling can clamp down to. A user config
/// that names a kind or url the ceiling excludes is refused outright.
pub fn underCeiling(resolved: Search, ceiling: ?Ceiling, diag: ?*?Diagnostic) CeilingError!Search {
    const bound = ceiling orelse return resolved;
    if (resolved.kind) |kind| {
        if (bound.kinds) |allowed| {
            if (!containsKind(allowed, kind)) {
                _ = note(diag, limits_mod.operator_file_name, .{ .kind_not_permitted = kind });
                return error.KindNotPermitted;
            }
        }
    }
    if (resolved.base_url) |actual| {
        if (bound.base_url) |required| {
            if (!std.mem.eql(u8, actual, required)) {
                _ = note(diag, limits_mod.operator_file_name, .{
                    .base_url_not_permitted = .{ .text = actual, .required = required },
                });
                return error.BaseUrlNotPermitted;
            }
        }
    }
    return resolved;
}

const testing = std.testing;

test "a file with no search block is not an error, and nothing is configured" {
    const gpa = testing.allocator;

    var none = try parse(gpa, ".{}", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(?Kind, null), none.kind);

    var other_block = try parse(gpa, ".{ .policy = .{} }", null);
    defer other_block.deinit(gpa);
    try testing.expectEqual(@as(?Kind, null), other_block.kind);
}

test "each of the three kinds parses" {
    const gpa = testing.allocator;

    var self_hosted = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org" } }
    , null);
    defer self_hosted.deinit(gpa);
    try testing.expectEqual(Kind.self_hosted, self_hosted.kind.?);

    var api = try parse(gpa,
        \\.{ .search = .{ .kind = "api", .base_url = "https://search.example.com", .provider = "brave", .credential = "brave" } }
    , null);
    defer api.deinit(gpa);
    try testing.expectEqual(Kind.api, api.kind.?);

    var scrape = try parse(gpa,
        \\.{ .search = .{ .kind = "scrape", .base_url = "https://example.net" } }
    , null);
    defer scrape.deinit(gpa);
    try testing.expectEqual(Kind.scrape, scrape.kind.?);
}

test "an unknown kind is refused, naming the three this reader knows" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "carrier_pigeon", .base_url = "https://example.org" } }
        , &diag),
    );
    try testing.expectEqualStrings("carrier_pigeon", diag.?.fault.kind_unknown);
}

test "kind and base_url are both required once the block is present" {
    const gpa = testing.allocator;

    var no_kind: ?Diagnostic = null;
    defer if (no_kind) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa, ".{ .search = .{ .base_url = \"https://example.org\" } }", &no_kind),
    );
    try testing.expect(no_kind.?.fault == .kind_missing);

    var no_url: ?Diagnostic = null;
    defer if (no_url) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa, ".{ .search = .{ .kind = \"api\" } }", &no_url),
    );
    try testing.expect(no_url.?.fault == .base_url_missing);
}

test "a plain http base url is refused, and an http loopback one is allowed" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "self_hosted", .base_url = "http://searx.example.org" } }
        , &diag),
    );
    try testing.expectEqual(BaseUrlError.InsecureNotLoopback, diag.?.fault.base_url_invalid.reason);

    var loopback = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "http://127.0.0.1:8080" } }
    , null);
    defer loopback.deinit(gpa);
    try testing.expectEqualStrings("http://127.0.0.1:8080", loopback.base_url.?);

    var named_loopback = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "http://localhost:8080" } }
    , null);
    defer named_loopback.deinit(gpa);
    try testing.expectEqualStrings("http://localhost:8080", named_loopback.base_url.?);
}

test "a key, token, api_key, or secret field is refused by name, not read as an unknown field" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .key = "sk-live-secret" } }
        , &diag),
    );
    try testing.expectEqualStrings("key", diag.?.fault.inline_secret);

    var typo: ?Diagnostic = null;
    defer if (typo) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .engine = "brave" } }
        , &typo),
    );
    try testing.expectEqualStrings("engine", typo.?.fault.unknown_field);
}

test "credential names an entry in the store, and an empty name is refused" {
    const gpa = testing.allocator;

    var named = try parse(gpa,
        \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "brave", .credential = "brave" } }
    , null);
    defer named.deinit(gpa);
    try testing.expectEqualStrings("brave", named.credential.?);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .credential = "" } }
        , &diag),
    );
    try testing.expect(diag.?.fault == .credential_empty);
}

test "the search block comes off the operator's config.zon, and a missing file names nothing" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root_len = try tmp.dir.realPath(testing.io, &path_buffer);
    const root = path_buffer[0..root_len];

    var missing = try loadOperator(gpa, testing.io, root, null);
    defer missing.deinit(gpa);
    try testing.expectEqual(@as(?Kind, null), missing.kind);

    {
        var file = try tmp.dir.createFile(testing.io, limits_mod.operator_file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(
            testing.io,
            \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org" } }
            ,
        );
    }

    var written = try loadOperator(gpa, testing.io, root, null);
    defer written.deinit(gpa);
    try testing.expectEqual(Kind.self_hosted, written.kind.?);
}

test "an org ceiling forbidding scrape beats a user config that asks for it" {
    const gpa = testing.allocator;

    var wanted = try parse(gpa,
        \\.{ .search = .{ .kind = "scrape", .base_url = "https://example.org" } }
    , null);
    defer wanted.deinit(gpa);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    const ceiling = Ceiling{ .kinds = &.{ .self_hosted, .api } };
    try testing.expectError(
        error.KindNotPermitted,
        foldLayers(wanted, ceiling, &diag),
    );
    try testing.expectEqual(Kind.scrape, diag.?.fault.kind_not_permitted);

    var allowed = try parse(gpa,
        \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "brave", .credential = "brave" } }
    , null);
    defer allowed.deinit(gpa);
    const held = try foldLayers(allowed, ceiling, null);
    try testing.expectEqual(Kind.api, held.kind.?);
}

test "an org ceiling naming an exact base_url refuses any other one" {
    const gpa = testing.allocator;

    var mismatched = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://other.example.org" } }
    , null);
    defer mismatched.deinit(gpa);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    const ceiling = Ceiling{ .base_url = "https://search.example.org" };
    try testing.expectError(
        error.BaseUrlNotPermitted,
        foldLayers(mismatched, ceiling, &diag),
    );
    try testing.expectEqualStrings("https://other.example.org", diag.?.fault.base_url_not_permitted.text);

    var matched = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://search.example.org" } }
    , null);
    defer matched.deinit(gpa);
    const held = try foldLayers(matched, ceiling, null);
    try testing.expectEqualStrings("https://search.example.org", held.base_url.?);
}

test "a ceiling this build was given nothing for changes nothing" {
    const gpa = testing.allocator;

    var search = try parse(gpa,
        \\.{ .search = .{ .kind = "scrape", .base_url = "https://example.org" } }
    , null);
    defer search.deinit(gpa);

    const held = try foldLayers(search, null, null);
    try testing.expectEqual(Kind.scrape, held.kind.?);
}

test "kind api with a provider and a credential parses, and provider reads back" {
    const gpa = testing.allocator;

    var search = try parse(gpa,
        \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "brave", .credential = "brave" } }
    , null);
    defer search.deinit(gpa);
    try testing.expectEqual(Provider.brave, search.provider.?);
}

test "an unknown provider is refused, and the diagnostic carries the text the user wrote" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "yahoo", .credential = "yahoo" } }
        , &diag),
    );
    try testing.expectEqualStrings("yahoo", diag.?.fault.provider_unknown);
}

test "kind api requires both a provider and a credential" {
    const gpa = testing.allocator;

    var no_provider: ?Diagnostic = null;
    defer if (no_provider) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org" } }
        , &no_provider),
    );
    try testing.expect(no_provider.?.fault == .provider_missing);

    var no_credential: ?Diagnostic = null;
    defer if (no_credential) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "brave" } }
        , &no_credential),
    );
    try testing.expect(no_credential.?.fault == .credential_missing);
}

test "self_hosted and scrape must not name a provider" {
    const gpa = testing.allocator;

    var self_hosted: ?Diagnostic = null;
    defer if (self_hosted) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org", .provider = "brave" } }
        , &self_hosted),
    );
    try testing.expectEqual(Kind.self_hosted, self_hosted.?.fault.provider_not_for_kind);

    var scrape: ?Diagnostic = null;
    defer if (scrape) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "scrape", .base_url = "https://example.net", .provider = "brave" } }
        , &scrape),
    );
    try testing.expectEqual(Kind.scrape, scrape.?.fault.provider_not_for_kind);
}

test "the provider_unknown message names both vendors this reader knows" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidSearch,
        parse(gpa,
            \\.{ .search = .{ .kind = "api", .base_url = "https://example.org", .provider = "yahoo", .credential = "yahoo" } }
        , &diag),
    );
    const text = try std.fmt.allocPrint(gpa, "{f}", .{diag.?});
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "brave") != null);
    try testing.expect(std.mem.indexOf(u8, text, "kagi") != null);
}

test "a self_hosted block with no provider still parses" {
    const gpa = testing.allocator;

    var search = try parse(gpa,
        \\.{ .search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org" } }
    , null);
    defer search.deinit(gpa);
    try testing.expectEqual(@as(?Provider, null), search.provider);
}
