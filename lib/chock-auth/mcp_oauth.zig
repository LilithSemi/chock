//! The credential a remote MCP server's OAuth login leaves at rest.
//! `oauth-mcp` owns discovery and registration. This file is the shape on
//! disk, the strict read of it, and the renewal written back into it.

const std = @import("std");

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

    /// The stored credential with a renewed token set written into it. The
    /// resource, the issuer and the client stay as they are.
    pub fn renewed(self: Credential, token: Renewed) Credential {
        return .{
            .resource = self.resource,
            .issuer = self.issuer,
            .client_id = self.client_id,
            .token_endpoint = self.token_endpoint,
            .access_token = token.access_token,
            .refresh_token = token.refresh_token orelse self.refresh_token,
            .token_type = token.token_type,
            .expires_at = token.expires_at,
            .scope = token.scope orelse self.scope,
        };
    }
};

/// What a token response gives. A field the server left out keeps the value
/// the credential already holds.
pub const Renewed = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_at: i64,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

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

test "a renewal keeps the resource and what the server did not send" {
    const stored = Credential{
        .resource = "https://mcp.example/mcp",
        .issuer = "https://auth.example",
        .client_id = "client",
        .token_endpoint = "https://auth.example/token",
        .access_token = "old-access",
        .refresh_token = "old-refresh",
        .token_type = "Bearer",
        .expires_at = 10,
        .scope = "read",
    };
    const quiet = stored.renewed(.{ .access_token = "new-access", .token_type = "Bearer", .expires_at = 20 });
    try std.testing.expectEqualStrings("old-refresh", quiet.refresh_token);
    try std.testing.expectEqualStrings("read", quiet.scope);
    try std.testing.expectEqualStrings("https://mcp.example/mcp", quiet.resource);
    try std.testing.expectEqualStrings(Credential.kind_value, quiet.kind);
}
