//! OAuth 2.1 for remote MCP servers. The login command owns the browser and
//! loopback callback; this module owns discovery, registration, PKCE values,
//! token exchange, and the credential stored at rest.

const std = @import("std");
const openai_oauth = @import("openai_oauth.zig");

pub const max_response_bytes: usize = 1024 * 1024;

pub const ProtectedResource = struct {
    resource: []const u8,
    authorization_servers: []const []const u8,
    scopes_supported: []const []const u8 = &.{},
};

pub const AuthorizationServer = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    registration_endpoint: ?[]const u8 = null,
    code_challenge_methods_supported: []const []const u8 = &.{},
};

pub const ClientRegistration = struct {
    client_id: []const u8,
    token_endpoint_auth_method: []const u8 = "none",
};

pub const TokenResponse = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_in: i64 = 3600,
    refresh_token: []const u8 = "",
    scope: []const u8 = "",
};

pub const TokenSet = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    value: TokenResponse,

    pub fn deinit(self: *TokenSet) void {
        std.crypto.secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const Credential = struct {
    kind: []const u8 = kind_value,
    version: u32 = 1,
    resource: []const u8,
    issuer: []const u8,
    client_id: []const u8,
    token_endpoint: []const u8,
    access_token: []const u8,
    refresh_token: []const u8 = "",
    token_type: []const u8,
    expires_at: i64,
    scope: []const u8 = "",

    pub const kind_value = "mcp_oauth";

    pub fn serialize(self: Credential, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{});
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Credential) {
        const parsed = try std.json.parseFromSlice(Credential, allocator, bytes, .{ .ignore_unknown_fields = false });
        errdefer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.kind, kind_value)) return error.NotMcpOAuthCredential;
        return parsed;
    }
};

pub const Discovery = struct {
    resource_metadata_url: []const u8,
    resource: ProtectedResource,
    authorization: AuthorizationServer,
};

pub fn discover(allocator: std.mem.Allocator, io: std.Io, resource_url: []const u8) !Discovery {
    try requireHttps(resource_url);
    const metadata_url = try challengeMetadataUrl(allocator, io, resource_url);
    errdefer allocator.free(metadata_url);
    try requireHttps(metadata_url);

    const resource_bytes = try fetchBytes(allocator, io, metadata_url, .GET, null, null);
    defer allocator.free(resource_bytes);
    const resource = try std.json.parseFromSliceLeaky(ProtectedResource, allocator, resource_bytes, .{
        .ignore_unknown_fields = true,
    });
    if (!std.mem.eql(u8, resource.resource, resource_url)) return error.ResourceMetadataMismatch;
    if (resource.authorization_servers.len == 0) return error.NoAuthorizationServer;
    const issuer = resource.authorization_servers[0];
    try requireHttps(issuer);

    const metadata_endpoint = try authorizationMetadataUrl(allocator, issuer);
    defer allocator.free(metadata_endpoint);
    const authorization_bytes = try fetchBytes(allocator, io, metadata_endpoint, .GET, null, null);
    defer allocator.free(authorization_bytes);
    const authorization = try std.json.parseFromSliceLeaky(AuthorizationServer, allocator, authorization_bytes, .{
        .ignore_unknown_fields = true,
    });
    if (!std.mem.eql(u8, authorization.issuer, issuer)) return error.IssuerMetadataMismatch;
    try requireHttps(authorization.authorization_endpoint);
    try requireHttps(authorization.token_endpoint);
    if (!holds(authorization.code_challenge_methods_supported, "S256")) return error.PkceS256Unsupported;
    return .{
        .resource_metadata_url = metadata_url,
        .resource = resource,
        .authorization = authorization,
    };
}

pub fn register(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    callback: []const u8,
) !ClientRegistration {
    try requireHttps(endpoint);
    const body = try std.json.Stringify.valueAlloc(allocator, .{
        .client_name = "Chock",
        .redirect_uris = &.{callback},
        .token_endpoint_auth_method = "none",
        .grant_types = &.{ "authorization_code", "refresh_token" },
        .response_types = &.{"code"},
    }, .{});
    defer allocator.free(body);
    const bytes = try fetchBytes(allocator, io, endpoint, .POST, body, "application/json");
    defer allocator.free(bytes);
    const registration = try std.json.parseFromSliceLeaky(ClientRegistration, allocator, bytes, .{
        .ignore_unknown_fields = true,
    });
    if (registration.client_id.len == 0 or
        !std.mem.eql(u8, registration.token_endpoint_auth_method, "none")) return error.ConfidentialClientUnsupported;
    return registration;
}

pub fn authorizationUrl(
    allocator: std.mem.Allocator,
    endpoint: []const u8,
    resource: []const u8,
    callback: []const u8,
    client_id: []const u8,
    scope: []const u8,
    attempt: *const openai_oauth.Attempt,
) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, endpoint);
    try out.append(allocator, if (std.mem.indexOfScalar(u8, endpoint, '?') == null) '?' else '&');
    try openai_oauth.addQuery(allocator, &out, "response_type", "code", false);
    try openai_oauth.addQuery(allocator, &out, "client_id", client_id, true);
    try openai_oauth.addQuery(allocator, &out, "redirect_uri", callback, true);
    try openai_oauth.addQuery(allocator, &out, "resource", resource, true);
    if (scope.len != 0) try openai_oauth.addQuery(allocator, &out, "scope", scope, true);
    try openai_oauth.addQuery(allocator, &out, "state", &attempt.state, true);
    try openai_oauth.addQuery(allocator, &out, "code_challenge_method", "S256", true);
    try openai_oauth.addQuery(allocator, &out, "code_challenge", &attempt.challenge, true);
    return out.toOwnedSlice(allocator);
}

pub fn exchangeCode(
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: []const u8,
    resource: []const u8,
    code: []const u8,
    client_id: []const u8,
    verifier: []const u8,
    callback: []const u8,
) !TokenSet {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try openai_oauth.addQuery(allocator, &body, "grant_type", "authorization_code", false);
    try openai_oauth.addQuery(allocator, &body, "client_id", client_id, true);
    try openai_oauth.addQuery(allocator, &body, "code", code, true);
    try openai_oauth.addQuery(allocator, &body, "code_verifier", verifier, true);
    try openai_oauth.addQuery(allocator, &body, "redirect_uri", callback, true);
    try openai_oauth.addQuery(allocator, &body, "resource", resource, true);
    return tokenRequest(allocator, io, endpoint, body.items);
}

pub fn refresh(
    allocator: std.mem.Allocator,
    io: std.Io,
    credential: Credential,
) !TokenSet {
    if (credential.refresh_token.len == 0) return error.NoRefreshToken;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try openai_oauth.addQuery(allocator, &body, "grant_type", "refresh_token", false);
    try openai_oauth.addQuery(allocator, &body, "client_id", credential.client_id, true);
    try openai_oauth.addQuery(allocator, &body, "refresh_token", credential.refresh_token, true);
    try openai_oauth.addQuery(allocator, &body, "resource", credential.resource, true);
    return tokenRequest(allocator, io, credential.token_endpoint, body.items);
}

fn tokenRequest(allocator: std.mem.Allocator, io: std.Io, endpoint: []const u8, body: []const u8) !TokenSet {
    try requireHttps(endpoint);
    const bytes = try fetchBytes(allocator, io, endpoint, .POST, body, "application/x-www-form-urlencoded");
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{
        .allocator = allocator,
        .bytes = bytes,
        .value = try std.json.parseFromSliceLeaky(TokenResponse, allocator, bytes, .{
            .ignore_unknown_fields = true,
        }),
    };
}

pub fn scopes(allocator: std.mem.Allocator, values: []const []const u8) std.mem.Allocator.Error![]u8 {
    return std.mem.join(allocator, " ", values);
}

fn holds(values: []const []const u8, wanted: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, wanted)) return true;
    return false;
}

fn requireHttps(url: []const u8) !void {
    const uri = try std.Uri.parse(url);
    if (!std.mem.eql(u8, uri.scheme, "https") or uri.host == null or uri.fragment != null or
        uri.user != null or uri.password != null) return error.UrlNotSafe;
}

fn authorizationMetadataUrl(allocator: std.mem.Allocator, issuer: []const u8) ![]u8 {
    try requireHttps(issuer);
    const rest = issuer["https://".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..slash];
    var path = rest[slash..];
    while (path.len != 0 and path[path.len - 1] == '/') path = path[0 .. path.len - 1];
    return std.fmt.allocPrint(allocator, "https://{s}/.well-known/oauth-authorization-server{s}", .{
        authority, path,
    });
}

fn challengeMetadataUrl(allocator: std.mem.Allocator, io: std.Io, resource_url: []const u8) ![]u8 {
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const uri = try std.Uri.parse(resource_url);
    var request = try http.request(.POST, uri, .{
        .keep_alive = false,
        .redirect_behavior = .not_allowed,
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .accept_encoding = .{ .override = "identity" },
        },
        .extra_headers = &.{.{ .name = "MCP-Protocol-Version", .value = "2025-06-18" }},
    });
    defer request.deinit();
    const initialize =
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"chock","version":"1"}}}
    ;
    const body = try allocator.dupe(u8, initialize);
    defer allocator.free(body);
    try request.sendBodyComplete(body);
    var head_buffer: [8 * 1024]u8 = undefined;
    var response = try request.receiveHead(&head_buffer);
    if (response.head.status != .unauthorized) return error.AuthorizationChallengeMissing;
    var headers = response.head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) continue;
        if (resourceMetadataIn(header.value)) |url| return allocator.dupe(u8, url);
    }
    return error.ResourceMetadataMissing;
}

fn resourceMetadataIn(header: []const u8) ?[]const u8 {
    const marker = "resource_metadata=";
    const at = std.mem.indexOf(u8, header, marker) orelse return null;
    var value = header[at + marker.len ..];
    value = std.mem.trimStart(u8, value, " \t");
    if (value.len == 0) return null;
    if (value[0] == '"') {
        const end = std.mem.indexOfScalar(u8, value[1..], '"') orelse return null;
        return value[1 .. 1 + end];
    }
    const end = std.mem.indexOfAny(u8, value, " ,\t") orelse value.len;
    return value[0..end];
}

fn fetchBytes(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    method: std.http.Method,
    payload: ?[]const u8,
    content_type: ?[]const u8,
) ![]u8 {
    try requireHttps(url);
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const storage = try allocator.alloc(u8, max_response_bytes + 1);
    defer allocator.free(storage);
    var out = std.Io.Writer.fixed(storage);
    const result = try http.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .redirect_behavior = .not_allowed,
        .headers = .{
            .content_type = if (content_type) |value| .{ .override = value } else .omit,
            .accept_encoding = .{ .override = "identity" },
        },
        .response_writer = &out,
    });
    if (result.status.class() != .success) return error.AuthorizationServerRefused;
    return allocator.dupe(u8, out.buffered());
}

test "the challenge parser finds only the protected resource metadata parameter" {
    try std.testing.expectEqualStrings(
        "https://mcp.example/.well-known/oauth-protected-resource",
        resourceMetadataIn("Bearer realm=\"mcp\", resource_metadata=\"https://mcp.example/.well-known/oauth-protected-resource\"").?,
    );
    try std.testing.expect(resourceMetadataIn("Bearer realm=\"mcp\"") == null);
}

test "authorization carries state PKCE callback and the exact resource" {
    const attempt = openai_oauth.Attempt{
        .state = "sssssssssssssssssssssssssssssssssssssssssss".*,
        .nonce = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn".*,
        .verifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv".*,
        .challenge = "ccccccccccccccccccccccccccccccccccccccccccc".*,
    };
    const url = try authorizationUrl(std.testing.allocator, "https://auth.example/authorize", "https://mcp.example/mcp", "http://127.0.0.1:1234/auth/callback", "client", "read write", &attempt);
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "resource=https%3A%2F%2Fmcp.example%2Fmcp") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=read%20write") != null);
}

test "an MCP credential is distinguished from an ordinary bearer secret" {
    const before = Credential{
        .resource = "https://mcp.example/mcp",
        .issuer = "https://auth.example",
        .client_id = "client",
        .token_endpoint = "https://auth.example/token",
        .access_token = "access",
        .refresh_token = "refresh",
        .token_type = "Bearer",
        .expires_at = 42,
    };
    const bytes = try before.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var parsed = try Credential.parse(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("https://mcp.example/mcp", parsed.value.resource);
    const other =
        \\{"kind":"other","resource":"r","issuer":"i","client_id":"c","token_endpoint":"t","access_token":"a","token_type":"Bearer","expires_at":1}
    ;
    try std.testing.expectError(error.NotMcpOAuthCredential, Credential.parse(std.testing.allocator, other));
}
