//! The OpenAI web-login credential Chock keeps at rest. `oauth-openai` owns
//! the protocol. This file is the shape on disk, the strict read of it, and
//! the one place a renewed token set is written into a stored credential.

const std = @import("std");

pub const Credential = struct {
    version: u32 = 1,
    email: []const u8,
    issuer: []const u8,
    subject: []const u8,
    client_id: []const u8,
    ext_agent_host_id: []const u8,
    id_token: []const u8,
    access_token: []const u8,
    refresh_token: []const u8,
    token_type: []const u8,
    expires_at: i64,
    earliest_refresh_at: ?i64 = null,
    scope: []const u8,

    pub fn serialize(self: Credential, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{ .emit_null_optional_fields = false });
    }

    pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Credential) {
        return std.json.parseFromSlice(Credential, allocator, bytes, .{ .ignore_unknown_fields = false });
    }

    pub fn hasInferenceScope(self: Credential) bool {
        var it = std.mem.tokenizeScalar(u8, self.scope, ' ');
        while (it.next()) |one| if (std.mem.eql(u8, one, "chatgpt.tokens.use.direct")) return true;
        return false;
    }

    /// The stored credential with a renewed token set written into it. The
    /// identity, the client and the host stay as they are.
    pub fn renewed(self: Credential, token: Renewed) Credential {
        return .{
            .email = self.email,
            .issuer = self.issuer,
            .subject = self.subject,
            .client_id = self.client_id,
            .ext_agent_host_id = self.ext_agent_host_id,
            .id_token = token.id_token orelse self.id_token,
            .access_token = token.access_token,
            .refresh_token = token.refresh_token orelse self.refresh_token,
            .token_type = token.token_type,
            .expires_at = token.expires_at,
            .earliest_refresh_at = token.earliest_refresh_at,
            .scope = token.scope orelse self.scope,
        };
    }
};

/// What a token response gives. A field the server left out keeps the value
/// the credential already holds, so an optional here is absence and not empty.
pub const Renewed = struct {
    access_token: []const u8,
    token_type: []const u8,
    expires_at: i64,
    id_token: ?[]const u8 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    earliest_refresh_at: ?i64 = null,
};

test "credential round trips without losing refresh data" {
    const before = Credential{
        .email = "person@example.com",
        .issuer = "https://auth.openai.com",
        .subject = "subject",
        .client_id = "oaiapp_test",
        .ext_agent_host_id = "urn:uuid:test",
        .id_token = "header.payload.signature",
        .access_token = "access",
        .refresh_token = "refresh",
        .token_type = "Bearer",
        .expires_at = 42,
        .scope = "openid chatgpt.tokens.use.direct",
    };
    const bytes = try before.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var parsed = try Credential.parse(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("refresh", parsed.value.refresh_token);
    try std.testing.expect(parsed.value.hasInferenceScope());
    try std.testing.expect(!Credential.hasInferenceScope(.{
        .email = "",
        .issuer = "",
        .subject = "",
        .client_id = "",
        .ext_agent_host_id = "",
        .id_token = "",
        .access_token = "",
        .refresh_token = "",
        .token_type = "",
        .expires_at = 0,
        .scope = "openid email",
    }));
}

test "a renewal keeps what the server did not send" {
    const stored = Credential{
        .email = "person@example.com",
        .issuer = "https://auth.openai.com",
        .subject = "subject",
        .client_id = "oaiapp_test",
        .ext_agent_host_id = "urn:uuid:test",
        .id_token = "old.id.token",
        .access_token = "old-access",
        .refresh_token = "old-refresh",
        .token_type = "Bearer",
        .expires_at = 10,
        .scope = "openid chatgpt.tokens.use.direct",
    };
    const quiet = stored.renewed(.{ .access_token = "new-access", .token_type = "Bearer", .expires_at = 20 });
    try std.testing.expectEqualStrings("old-refresh", quiet.refresh_token);
    try std.testing.expectEqualStrings("old.id.token", quiet.id_token);
    try std.testing.expectEqualStrings(stored.scope, quiet.scope);
    try std.testing.expectEqualStrings("oaiapp_test", quiet.client_id);
    try std.testing.expectEqual(@as(i64, 20), quiet.expires_at);

    const rotated = stored.renewed(.{
        .access_token = "new-access",
        .token_type = "Bearer",
        .expires_at = 20,
        .refresh_token = "new-refresh",
        .earliest_refresh_at = 15,
    });
    try std.testing.expectEqualStrings("new-refresh", rotated.refresh_token);
    try std.testing.expectEqual(@as(?i64, 15), rotated.earliest_refresh_at);
}
