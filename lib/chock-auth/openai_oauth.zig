//! OAuth for an open-source OpenAI client. This module builds and checks the
//! protocol values. The command owns the browser and the loopback socket.

const std = @import("std");

pub const authorize_endpoint = "https://auth.openai.com/api/accounts/authorize";
pub const token_endpoint = "https://auth.openai.com/api/accounts/oauth/token";
pub const jwks_endpoint = "https://auth.openai.com/.well-known/jwks.json";
pub const issuer = "https://auth.openai.com";
pub const resource = "https://api.openai.com/v1";
pub const scopes = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
pub const initial_client_id = "dynamic_agent_client";

pub const Attempt = struct {
    state: [43]u8,
    nonce: [43]u8,
    verifier: [86]u8,
    challenge: [43]u8,

    pub fn init(io: std.Io) Attempt {
        var state_raw: [32]u8 = undefined;
        var nonce_raw: [32]u8 = undefined;
        var verifier_raw: [64]u8 = undefined;
        io.random(&state_raw);
        io.random(&nonce_raw);
        io.random(&verifier_raw);

        var self: Attempt = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.state, &state_raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.nonce, &nonce_raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&self.verifier, &verifier_raw);
        pkceChallenge(&self.challenge, &self.verifier);
        return self;
    }
};

fn pkceChallenge(out: *[43]u8, verifier: []const u8) void {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha256.hash(verifier, &digest, .{});
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &digest);
}

pub const Registration = struct {
    client_id: []const u8 = initial_client_id,
    host_id: []const u8,
    id_token_hint: ?[]const u8 = null,
    login_hint: ?[]const u8 = null,

    pub fn isInitial(self: Registration) bool {
        return std.mem.eql(u8, self.client_id, initial_client_id);
    }
};

pub fn authorizationUrl(
    allocator: std.mem.Allocator,
    callback: []const u8,
    attempt: *const Attempt,
    registration: Registration,
) std.mem.Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, authorize_endpoint);
    try out.append(allocator, '?');
    try addQuery(allocator, &out, "client_id", registration.client_id, false);
    if (registration.isInitial()) try addQuery(allocator, &out, "agent_name_hint", "Chock", true);
    try addQuery(allocator, &out, "ext_agent_host_id", registration.host_id, true);
    if (registration.id_token_hint) |value| try addQuery(allocator, &out, "id_token_hint", value, true);
    if (registration.login_hint) |value| try addQuery(allocator, &out, "login_hint", value, true);
    try addQuery(allocator, &out, "response_type", "code", true);
    try addQuery(allocator, &out, "redirect_uri", callback, true);
    try addQuery(allocator, &out, "scope", scopes, true);
    try addQuery(allocator, &out, "resource", resource, true);
    try addQuery(allocator, &out, "state", &attempt.state, true);
    try addQuery(allocator, &out, "nonce", &attempt.nonce, true);
    try addQuery(allocator, &out, "code_challenge_method", "S256", true);
    try addQuery(allocator, &out, "code_challenge", &attempt.challenge, true);
    return out.toOwnedSlice(allocator);
}

pub fn addQuery(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    value: []const u8,
    separator: bool,
) std.mem.Allocator.Error!void {
    if (separator) try out.append(allocator, '&');
    try out.appendSlice(allocator, name);
    try out.append(allocator, '=');
    for (value) |byte| {
        if (isUnreserved(byte)) {
            try out.append(allocator, byte);
        } else {
            const hex = "0123456789ABCDEF";
            try out.appendSlice(allocator, &.{ '%', hex[byte >> 4], hex[byte & 0x0f] });
        }
    }
}

fn isUnreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

pub const Callback = struct {
    code: []const u8,
    state: []const u8,
    client_id: ?[]const u8,
    scope: ?[]const u8,
};

pub const CallbackError = error{
    WrongPath,
    MissingCode,
    MissingState,
    StateMismatch,
    AuthorizationRefused,
    BadEncoding,
};

pub fn parseCallback(allocator: std.mem.Allocator, target: []const u8, expected_state: []const u8) (CallbackError || std.mem.Allocator.Error)!Callback {
    const query_at = std.mem.indexOfScalar(u8, target, '?') orelse return error.MissingCode;
    if (!std.mem.eql(u8, target[0..query_at], "/auth/callback")) return error.WrongPath;

    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var client_id: ?[]const u8 = null;
    var scope: ?[]const u8 = null;
    var refused = false;
    errdefer {
        if (code) |value| allocator.free(value);
        if (state) |value| allocator.free(value);
        if (client_id) |value| allocator.free(value);
        if (scope) |value| allocator.free(value);
    }
    var pairs = std.mem.splitScalar(u8, target[query_at + 1 ..], '&');
    while (pairs.next()) |pair| {
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const name = pair[0..equals];
        const decoded = try decode(allocator, pair[equals + 1 ..]);
        if (std.mem.eql(u8, name, "code")) {
            if (code) |old| allocator.free(old);
            code = decoded;
        } else if (std.mem.eql(u8, name, "state")) {
            if (state) |old| allocator.free(old);
            state = decoded;
        } else if (std.mem.eql(u8, name, "client_id")) {
            if (client_id) |old| allocator.free(old);
            client_id = decoded;
        } else if (std.mem.eql(u8, name, "scope")) {
            if (scope) |old| allocator.free(old);
            scope = decoded;
        } else {
            if (std.mem.eql(u8, name, "error") and std.mem.eql(u8, decoded, "access_denied")) refused = true;
            allocator.free(decoded);
        }
    }
    const got_state = state orelse return error.MissingState;
    if (got_state.len != expected_state.len or expected_state.len != 43 or
        !std.crypto.timing_safe.eql([43]u8, expected_state[0..43].*, got_state[0..43].*)) return error.StateMismatch;
    if (refused) return error.AuthorizationRefused;
    return .{
        .code = code orelse return error.MissingCode,
        .state = got_state,
        .client_id = client_id,
        .scope = scope,
    };
}

fn decode(allocator: std.mem.Allocator, value: []const u8) (CallbackError || std.mem.Allocator.Error)![]u8 {
    const copy = try allocator.dupe(u8, value);
    errdefer allocator.free(copy);
    for (copy) |*byte| if (byte.* == '+') {
        byte.* = ' ';
    };
    var at: usize = 0;
    while (at < copy.len) : (at += 1) {
        if (copy[at] != '%') continue;
        if (at + 2 >= copy.len or std.fmt.charToDigit(copy[at + 1], 16) catch null == null or std.fmt.charToDigit(copy[at + 2], 16) catch null == null) return error.BadEncoding;
    }
    const decoded = std.Uri.percentDecodeInPlace(copy);
    const result = try allocator.dupe(u8, decoded);
    allocator.free(copy);
    return result;
}

pub const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    id_token: []const u8,
    token_type: []const u8,
    expires_in: i64,
    scope: []const u8,
    earliest_refresh_at: ?i64 = null,
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

pub const HttpError = error{
    AuthorizationServerRefused,
    AuthorizationResponseTooLarge,
};

pub fn exchangeCode(
    allocator: std.mem.Allocator,
    io: std.Io,
    code: []const u8,
    client_id: []const u8,
    verifier: []const u8,
    callback: []const u8,
) !TokenSet {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try addQuery(allocator, &body, "grant_type", "authorization_code", false);
    try addQuery(allocator, &body, "client_id", client_id, true);
    try addQuery(allocator, &body, "code", code, true);
    try addQuery(allocator, &body, "code_verifier", verifier, true);
    try addQuery(allocator, &body, "redirect_uri", callback, true);
    try addQuery(allocator, &body, "resource", resource, true);
    const bytes = try fetchBytes(allocator, io, token_endpoint, .POST, body.items, "application/x-www-form-urlencoded");
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{
        .allocator = allocator,
        .bytes = bytes,
        .value = try std.json.parseFromSliceLeaky(TokenResponse, allocator, bytes, .{ .ignore_unknown_fields = true }),
    };
}

pub fn refresh(
    allocator: std.mem.Allocator,
    io: std.Io,
    client_id: []const u8,
    refresh_token: []const u8,
) !TokenSet {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try addQuery(allocator, &body, "grant_type", "refresh_token", false);
    try addQuery(allocator, &body, "client_id", client_id, true);
    try addQuery(allocator, &body, "refresh_token", refresh_token, true);
    try addQuery(allocator, &body, "resource", resource, true);
    const bytes = try fetchBytes(allocator, io, token_endpoint, .POST, body.items, "application/x-www-form-urlencoded");
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{
        .allocator = allocator,
        .bytes = bytes,
        .value = try std.json.parseFromSliceLeaky(TokenResponse, allocator, bytes, .{ .ignore_unknown_fields = true }),
    };
}

pub fn fetchJwks(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    return fetchBytes(allocator, io, jwks_endpoint, .GET, null, null);
}

const max_authorization_response_bytes = 1024 * 1024;

fn fetchBytes(
    allocator: std.mem.Allocator,
    io: std.Io,
    url: []const u8,
    method: std.http.Method,
    payload: ?[]const u8,
    content_type: ?[]const u8,
) ![]u8 {
    var http: std.http.Client = .{ .allocator = allocator, .io = io };
    defer http.deinit();
    const storage = try allocator.alloc(u8, max_authorization_response_bytes + 1);
    defer allocator.free(storage);
    var out = std.Io.Writer.fixed(storage);
    const result = http.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .payload = payload,
        .redirect_behavior = .not_allowed,
        .headers = .{
            .content_type = if (content_type) |value| .{ .override = value } else .omit,
            .accept_encoding = .{ .override = "identity" },
        },
        .response_writer = &out,
    }) catch |err| switch (err) {
        error.WriteFailed => return error.AuthorizationResponseTooLarge,
        else => |other| return other,
    };
    if (result.status.class() != .success) return error.AuthorizationServerRefused;
    if (out.buffered().len > max_authorization_response_bytes) return error.AuthorizationResponseTooLarge;
    return allocator.dupe(u8, out.buffered());
}

pub const Identity = struct {
    subject: []const u8,
    email: []const u8,
};

pub const VerifyError = error{
    MalformedIdToken,
    UnsupportedAlgorithm,
    SigningKeyNotFound,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    WrongNonce,
    TokenExpired,
    TokenIssuedInFuture,
};

const JwtHeader = struct {
    alg: []const u8,
    kid: []const u8,
};

const JwtClaims = struct {
    iss: []const u8,
    // OIDC permits a single audience string or an array of audience strings.
    aud: std.json.Value,
    sub: []const u8,
    email: []const u8 = "",
    nonce: []const u8,
    exp: i64,
    iat: i64,
};

const Jwks = struct {
    keys: []const Jwk,
};

const Jwk = struct {
    kty: []const u8,
    kid: []const u8,
    alg: []const u8,
    n: []const u8,
    e: []const u8,
};

pub fn verifyIdToken(
    allocator: std.mem.Allocator,
    token: []const u8,
    jwks_bytes: []const u8,
    client_id: []const u8,
    nonce: []const u8,
    now_seconds: i64,
) (VerifyError || std.mem.Allocator.Error || std.json.ParseError(std.json.Scanner))!Identity {
    const first = std.mem.indexOfScalar(u8, token, '.') orelse return error.MalformedIdToken;
    const second_relative = std.mem.indexOfScalar(u8, token[first + 1 ..], '.') orelse return error.MalformedIdToken;
    const second = first + 1 + second_relative;
    if (std.mem.indexOfScalar(u8, token[second + 1 ..], '.') != null) return error.MalformedIdToken;

    const header_bytes = try decodeBase64(allocator, token[0..first]);
    defer allocator.free(header_bytes);
    const claims_bytes = try decodeBase64(allocator, token[first + 1 .. second]);
    defer allocator.free(claims_bytes);
    const signature = try decodeBase64(allocator, token[second + 1 ..]);
    defer allocator.free(signature);

    var header = std.json.parseFromSlice(JwtHeader, allocator, header_bytes, .{ .ignore_unknown_fields = true }) catch return error.MalformedIdToken;
    defer header.deinit();
    if (!std.mem.eql(u8, header.value.alg, "RS256")) return error.UnsupportedAlgorithm;

    var keys = try std.json.parseFromSlice(Jwks, allocator, jwks_bytes, .{ .ignore_unknown_fields = true });
    defer keys.deinit();
    const key = for (keys.value.keys) |candidate| {
        if (std.mem.eql(u8, candidate.kid, header.value.kid) and
            std.mem.eql(u8, candidate.kty, "RSA") and
            std.mem.eql(u8, candidate.alg, "RS256")) break candidate;
    } else return error.SigningKeyNotFound;

    const modulus = try decodeBase64(allocator, key.n);
    defer allocator.free(modulus);
    const exponent = try decodeBase64(allocator, key.e);
    defer allocator.free(exponent);
    const public_key = std.crypto.Certificate.rsa.PublicKey.fromBytes(exponent, modulus) catch return error.BadSignature;
    const signed = token[0..second];
    switch (signature.len) {
        256 => std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(256, &signature[0..256].*, signed, public_key, std.crypto.hash.sha2.Sha256) catch return error.BadSignature,
        384 => std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(384, &signature[0..384].*, signed, public_key, std.crypto.hash.sha2.Sha256) catch return error.BadSignature,
        512 => std.crypto.Certificate.rsa.PKCS1v1_5Signature.verify(512, &signature[0..512].*, signed, public_key, std.crypto.hash.sha2.Sha256) catch return error.BadSignature,
        else => return error.BadSignature,
    }

    var claims = std.json.parseFromSlice(JwtClaims, allocator, claims_bytes, .{ .ignore_unknown_fields = true }) catch return error.MalformedIdToken;
    defer claims.deinit();
    if (!std.mem.eql(u8, claims.value.iss, issuer)) return error.WrongIssuer;
    if (!audienceIncludes(claims.value.aud, client_id)) return error.WrongAudience;
    if (!std.mem.eql(u8, claims.value.nonce, nonce)) return error.WrongNonce;
    if (claims.value.exp <= now_seconds) return error.TokenExpired;
    if (claims.value.iat > now_seconds + 60) return error.TokenIssuedInFuture;
    const subject = try allocator.dupe(u8, claims.value.sub);
    errdefer allocator.free(subject);
    return .{
        .subject = subject,
        .email = try allocator.dupe(u8, claims.value.email),
    };
}

fn audienceIncludes(audience: std.json.Value, expected: []const u8) bool {
    return switch (audience) {
        .string => |one| std.mem.eql(u8, one, expected),
        .array => |many| for (many.items) |one| {
            if (one == .string and std.mem.eql(u8, one.string, expected)) break true;
        } else false,
        else => false,
    };
}

fn decodeBase64(allocator: std.mem.Allocator, text: []const u8) (VerifyError || std.mem.Allocator.Error)![]u8 {
    const size = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text) catch return error.MalformedIdToken;
    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);
    std.base64.url_safe_no_pad.Decoder.decode(bytes, text) catch return error.MalformedIdToken;
    return bytes;
}

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
};

pub fn hostId(allocator: std.mem.Allocator, io: std.Io) std.mem.Allocator.Error![]u8 {
    var raw: [16]u8 = undefined;
    io.random(&raw);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    return std.fmt.allocPrint(allocator, "urn:uuid:{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
        raw[0], raw[1], raw[2],  raw[3],  raw[4],  raw[5],  raw[6],  raw[7],
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    });
}

test "authorization request carries PKCE and an exact encoded callback" {
    const attempt = Attempt{
        .state = "sssssssssssssssssssssssssssssssssssssssssss".*,
        .nonce = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn".*,
        .verifier = "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv".*,
        .challenge = "ccccccccccccccccccccccccccccccccccccccccccc".*,
    };
    const url = try authorizationUrl(std.testing.allocator, "http://127.0.0.1:1455/auth/callback", &attempt, .{ .host_id = "urn:uuid:host" });
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "client_id=dynamic_agent_client") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A1455%2Fauth%2Fcallback") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
}

test "PKCE challenge matches RFC 7636" {
    var challenge: [43]u8 = undefined;
    pkceChallenge(&challenge, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", &challenge);
}

test "callback validates state and decodes its issued client" {
    const state = "sssssssssssssssssssssssssssssssssssssssssss";
    const callback = try parseCallback(std.testing.allocator, "/auth/callback?code=one%2Btwo&state=sssssssssssssssssssssssssssssssssssssssssss&client_id=oaiapp_test&scope=openid+email", state);
    defer {
        std.testing.allocator.free(callback.code);
        std.testing.allocator.free(callback.state);
        std.testing.allocator.free(callback.client_id.?);
        std.testing.allocator.free(callback.scope.?);
    }
    try std.testing.expectEqualStrings("one+two", callback.code);
    try std.testing.expectEqualStrings("oaiapp_test", callback.client_id.?);
    try std.testing.expectEqualStrings("openid email", callback.scope.?);
    try std.testing.expectError(error.StateMismatch, parseCallback(std.testing.allocator, "/auth/callback?code=x&state=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", state));
}

test "credential round trips without losing refresh data" {
    const before = Credential{
        .email = "person@example.com",
        .issuer = issuer,
        .subject = "subject",
        .client_id = "oaiapp_test",
        .ext_agent_host_id = "urn:uuid:test",
        .id_token = "header.payload.signature",
        .access_token = "access",
        .refresh_token = "refresh",
        .token_type = "Bearer",
        .expires_at = 42,
        .scope = scopes,
    };
    const bytes = try before.serialize(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var parsed = try Credential.parse(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("refresh", parsed.value.refresh_token);
    try std.testing.expect(parsed.value.hasInferenceScope());
}

test "ID token audience accepts both OIDC encodings" {
    try std.testing.expect(audienceIncludes(.{ .string = "oaiapp_test" }, "oaiapp_test"));

    var values: std.json.Array = .init(std.testing.allocator);
    defer values.deinit();
    try values.append(.{ .string = "another_client" });
    try values.append(.{ .string = "oaiapp_test" });
    try std.testing.expect(audienceIncludes(.{ .array = values }, "oaiapp_test"));
    try std.testing.expect(!audienceIncludes(.{ .array = values }, "missing_client"));
}
