//! Persistent multi-user state owned by `chock daemon`.
//!
//! Session transcripts remain Chock logs: they are ordered, hash chained, and
//! already replayable. SQL holds the facts a log cannot own by itself: external
//! identities, who may enter a session, and which machine currently executes
//! it.

const std = @import("std");
const oauth = @import("oauth-core");
const quarry = @import("quarry");

pub const Provider = enum {
    kanidm,
    authentik,
    authelia,
};

pub const Oidc = struct {
    provider: Provider,
    issuer: []const u8,
    client_id: []const u8,
    /// Optional confidential-client credential. Kept server-side and never
    /// included in the authorization URL or persisted in Quarry.
    client_secret: ?[]const u8 = null,
    /// Authentik commonly publishes application-specific metadata at a path
    /// not derived from `issuer`. Null uses standard OIDC discovery for every
    /// provider, including Authentik installations configured that way.
    discovery_url: ?[]const u8 = null,

    pub fn validate(self: Oidc) error{InvalidOidcConfiguration}!void {
        if (self.issuer.len == 0 or self.client_id.len == 0)
            return error.InvalidOidcConfiguration;
        if (!isIssuerUrl(self.issuer)) return error.InvalidOidcConfiguration;
        if (self.discovery_url) |url| {
            if (!isHttpsUrl(url)) return error.InvalidOidcConfiguration;
        }
    }

    pub fn discover(
        self: Oidc,
        arena: std.mem.Allocator,
        transport: oauth.Transport,
    ) (oauth.oidc.DiscoverError || error{InvalidOidcConfiguration})!oauth.oidc.Metadata {
        try self.validate();
        if (self.discovery_url) |url|
            return oauth.oidc.discoverAt(arena, transport, url, self.issuer);
        return oauth.oidc.discover(arena, transport, self.issuer);
    }
};

fn isHttpsUrl(value: []const u8) bool {
    const uri = std.Uri.parse(value) catch return false;
    return std.mem.eql(u8, uri.scheme, "https") and uri.host != null and
        !uri.host.?.isEmpty() and uri.user == null and uri.password == null and
        uri.fragment == null and isValidUrlHost(uri.host.?);
}

fn isValidUrlHost(component: std.Uri.Component) bool {
    var buffer: [std.Io.net.HostName.max_len]u8 = undefined;
    const host = component.toRaw(&buffer) catch return false;
    if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') {
        return switch (std.Io.net.Ip6Address.Unresolved.parse(host[1 .. host.len - 1])) {
            .success => |address| address.interface_name == null and !std.mem.allEqual(u8, &address.bytes, 0),
            else => false,
        };
    }
    if (std.Io.net.Ip4Address.parse(host, 0)) |address| {
        if (std.mem.allEqual(u8, &address.bytes, 0)) return false;
    } else |_| {}
    std.Io.net.HostName.validate(host) catch return false;
    return true;
}

fn isIssuerUrl(value: []const u8) bool {
    const uri = std.Uri.parse(value) catch return false;
    return uri.query == null and isHttpsUrl(value);
}

/// Validate a configured public web base URL before it becomes an OAuth
/// redirect target. A path prefix is allowed, but query/fragment/user-info are
/// not; cleartext HTTP is restricted to exact loopback hosts.
pub fn isSecureWebBaseUrl(value: []const u8) bool {
    return isWebBaseUrl(value, false);
}

/// Validate the browser-facing URL for `chock serve`. Cleartext HTTP is
/// normally loopback-only; an explicit operator opt-in may permit a valid
/// non-loopback HTTP host when TLS is terminated outside Chock.
pub fn isWebBaseUrl(value: []const u8, allow_http: bool) bool {
    const uri = std.Uri.parse(value) catch return false;
    if (uri.query != null or uri.fragment != null or uri.user != null or
        uri.password != null or uri.host == null or uri.host.?.isEmpty())
        return false;
    if (std.mem.eql(u8, uri.scheme, "https")) return isValidUrlHost(uri.host.?);
    if (allow_http and std.mem.eql(u8, uri.scheme, "http")) return isValidUrlHost(uri.host.?);
    return isLoopbackHttp(value);
}

fn isLoopbackHttp(value: []const u8) bool {
    const uri = std.Uri.parse(value) catch return false;
    if (!std.mem.eql(u8, uri.scheme, "http") or uri.user != null or
        uri.password != null or uri.host == null or uri.fragment != null)
        return false;
    return switch (uri.host.?) {
        .percent_encoded => |host| std.mem.eql(u8, host, "localhost") or
            std.mem.eql(u8, host, "127.0.0.1") or std.mem.eql(u8, host, "[::1]"),
        .raw => false,
    };
}

/// Start the reusable authorization-code flow shared by Kanidm, Authentik,
/// and Authelia. Public clients use PKCE; confidential deployments may also
/// present a server-side client secret at token exchange.
pub fn oidcAuthorizationUrl(
    config: Oidc,
    arena: std.mem.Allocator,
    metadata: oauth.oidc.Metadata,
    attempt: *const oauth.Attempt,
    redirect_uri: []const u8,
) (oauth.UrlError || std.mem.Allocator.Error || error{InvalidOidcConfiguration})![]u8 {
    try config.validate();
    if (!std.mem.eql(u8, metadata.issuer, config.issuer) or redirect_uri.len == 0)
        return error.InvalidOidcConfiguration;
    if (metadata.code_challenge_methods_supported.len != 0 and
        !contains(metadata.code_challenge_methods_supported, "S256"))
        return error.InvalidOidcConfiguration;
    return oauth.authorizeUrl(arena, metadata.authorization_endpoint, .{ .id = config.client_id }, attempt, .{
        .redirect_uri = redirect_uri,
        .scope = "openid profile email",
        .send_nonce = true,
    });
}

/// Exchange an OAuth callback after `parseCallback` has checked the same
/// attempt's state. The returned token set remains owned by the caller.
pub fn oidcExchangeCode(
    config: Oidc,
    gpa: std.mem.Allocator,
    transport: oauth.Transport,
    metadata: oauth.oidc.Metadata,
    code: []const u8,
    attempt: *const oauth.Attempt,
    redirect_uri: []const u8,
) (oauth.TokenError || error{InvalidOidcConfiguration})!oauth.TokenSet {
    try config.validate();
    if (!std.mem.eql(u8, metadata.issuer, config.issuer) or redirect_uri.len == 0)
        return error.InvalidOidcConfiguration;
    const call: oauth.Call = .{
        .transport = transport,
        .endpoints = metadata.endpoints(),
        .client = .{
            .id = config.client_id,
            .auth = if (config.client_secret) |secret| .{ .secret_basic = secret } else .none,
        },
    };
    return oauth.exchangeCode(gpa, call, code, &attempt.verifier, redirect_uri);
}

/// Verify an ID token with this configured issuer, client audience, and the
/// nonce paired with the authorization attempt.
pub fn verifyOidcIdToken(
    config: Oidc,
    arena: std.mem.Allocator,
    transport: oauth.Transport,
    metadata: oauth.oidc.Metadata,
    token: []const u8,
    attempt: *const oauth.Attempt,
    now_seconds: i64,
) (oauth.oidc.DiscoverError || oauth.oidc.VerifyError || error{InvalidOidcConfiguration})!oauth.oidc.Verified {
    try config.validate();
    if (!std.mem.eql(u8, metadata.issuer, config.issuer)) return error.InvalidOidcConfiguration;
    const jwks = try oauth.oidc.fetchJwks(arena, transport, metadata.jwks_uri);
    return oauth.oidc.verifyIdToken(arena, token, jwks, .{
        .issuer = config.issuer,
        .client_id = config.client_id,
        .nonce = &attempt.nonce,
        .now = now_seconds,
    });
}

fn contains(values: []const []const u8, wanted: []const u8) bool {
    for (values) |value| if (std.mem.eql(u8, value, wanted)) return true;
    return false;
}

pub const SessionPlacement = enum { client, daemon };
pub const SessionHostLease = struct { generation: u64, expires_ms: i64 };
pub const MemberRole = enum { owner, editor, viewer };
pub const TeamRole = enum { owner, manager, member };
pub const ProviderScope = enum { instance, user, team };
pub const PrincipalKind = enum { everyone, identity, team };
pub const Effect = enum { allow, deny };

pub const Capability = enum {
    team_manage,
    project_view,
    project_manage,
    session_view,
    session_prompt,
    session_approve,
    session_share,
    provider_use,
    provider_manage,
};

pub const Rule = struct {
    resource_kind: []const u8,
    resource_id: []const u8,
    principal_kind: PrincipalKind,
    principal_id: []const u8 = "",
    capability: Capability,
    effect: Effect,
};

pub const AclRecord = struct {
    id: [36]u8,
    rule: Rule,
};

pub const Actor = struct {
    identity_id: []const u8,
    team_ids: []const []const u8 = &.{},
    instance_admin: bool = false,
};

/// Durable account row produced only after the caller has verified an OIDC
/// ID token. IDs are random UUIDs; the issuer and subject remain the unique
/// external key and are never reconstructed from an email address.
pub const Identity = struct {
    id: [36]u8,
    instance_role: []const u8,
};

pub const LocalAccount = struct {
    username: []const u8,
    password: []const u8,
};

fn validLocalUsername(username: []const u8) bool {
    if (username.len < 3 or username.len > 64) return false;
    for (username) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.')) return false;
    }
    return true;
}

fn localUsernameLower(
    gpa: std.mem.Allocator,
    username: []const u8,
) (std.mem.Allocator.Error || error{InvalidLocalAccount})![]u8 {
    const trimmed = std.mem.trim(u8, username, " \t\r\n");
    if (!validLocalUsername(trimmed)) return error.InvalidLocalAccount;
    const normalized = try gpa.alloc(u8, trimmed.len);
    for (trimmed, 0..) |byte, index| normalized[index] = std.ascii.toLower(byte);
    return normalized;
}

fn dummyPasswordDerivation(gpa: std.mem.Allocator, io: std.Io, password: []const u8) void {
    const salt = "chock-login-dummy-salt";
    var digest: [32]u8 = undefined;
    std.crypto.pwhash.argon2.kdf(
        gpa,
        &digest,
        password,
        salt,
        .owasp_2id,
        .argon2id,
        io,
    ) catch {};
    std.crypto.secureZero(u8, &digest);
}

pub const LoginSession = struct {
    /// Opaque bearer for an HttpOnly cookie. The database stores only its hash.
    token: [43]u8,
    expires_ms: i64,
};

pub const SessionIdentity = struct {
    id: [36]u8,
    instance_role: []const u8,
    /// Non-empty only for a bearer restricted to this one client-hosted
    /// session. Kept inline so resolving a credential adds no owned slice.
    worker_session: [128]u8 = undefined,
    worker_session_len: u8 = 0,

    pub fn workerScope(self: *const SessionIdentity) ?[]const u8 {
        if (self.worker_session_len == 0) return null;
        return self.worker_session[0..self.worker_session_len];
    }
};

fn validWorkerSessionId(value: []const u8) bool {
    if (value.len != 26) return false;
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for (value) |character| if (std.mem.indexOfScalar(u8, alphabet, character) == null) return false;
    return true;
}

pub const Project = struct {
    id: [36]u8,
    name: []const u8,
    root: []const u8,
    source_kind: []const u8,
    source_locator: []const u8,
    status: []const u8,
};

pub const SessionMember = struct {
    identity_id: []const u8,
    role: MemberRole,
};

pub const SessionPerson = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    role: ?MemberRole = null,
};

pub const SessionPresence = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    last_seen_ms: i64,
};

pub const session_presence_ttl_ms: i64 = 60_000;

pub const Team = struct {
    id: [36]u8,
    name: []const u8,
    role: TeamRole,
};

/// Invitation metadata is safe to list: it contains no bearer or token digest.
pub const TeamInvitation = struct {
    id: [36]u8,
    role: TeamRole,
    created_ms: i64,
    expires_ms: i64,
    revoked: bool,
    redeemed: bool,
    expired: bool,
};

pub const CreatedTeamInvitation = struct {
    id: [36]u8,
    token: [43]u8,
    expires_ms: i64,
};

pub const TeamPerson = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    role: ?TeamRole = null,
};

pub const DirectoryPerson = struct {
    identity_id: []const u8,
    display_name: []const u8 = "",
    email: []const u8 = "",
    instance_role: []const u8,
    local_account: bool = false,
    local_account_disabled: bool = false,
};

pub const InstanceTeamExport = struct {
    id: []const u8,
    name: []const u8,
    created_by_identity_id: []const u8,
    created_ms: i64,
};

pub const InstanceTeamMemberExport = struct {
    team_id: []const u8,
    identity_id: []const u8,
    role: []const u8,
    added_ms: i64,
};

/// Invitation export includes lifecycle metadata only, never the invitation
/// bearer or its stored digest.
pub const InstanceInvitationExport = struct {
    id: []const u8,
    team_id: []const u8,
    role: []const u8,
    created_by_identity_id: []const u8,
    created_ms: i64,
    expires_ms: i64,
    revoked_ms: ?i64,
    redeemed_by_identity_id: ?[]const u8,
    redeemed_ms: ?i64,
};

pub const InstanceSessionMemberExport = struct {
    session_id: []const u8,
    identity_id: []const u8,
    role: []const u8,
    added_by_identity_id: []const u8,
    added_ms: i64,
};

pub const InstanceAclExport = struct {
    id: []const u8,
    resource_kind: []const u8,
    resource_id: []const u8,
    principal_kind: []const u8,
    principal_id: ?[]const u8,
    capability: []const u8,
    effect: []const u8,
    created_by_identity_id: []const u8,
    created_ms: i64,
};

pub const InstanceAccessExport = struct {
    teams: []const InstanceTeamExport,
    team_members: []const InstanceTeamMemberExport,
    invitations: []const InstanceInvitationExport,
    session_members: []const InstanceSessionMemberExport,
    acl_rules: []const InstanceAclExport,
};

/// A provider record contains non-secret configuration and a reference to a
/// separately managed credential. Credential material never enters Quarry.
pub const LlmProvider = struct {
    id: [36]u8,
    name: []const u8,
    provider_kind: []const u8,
    scope_kind: ProviderScope,
    scope_id: ?[]const u8,
    configuration: []const u8,
    has_credential: bool,
    is_default: bool,
    created_ms: i64,
};

/// ACLs are deny by default. A matching deny beats every matching allow;
/// instance administrators are the only bypass and are assigned explicitly.
pub fn authorized(
    actor: Actor,
    rules: []const Rule,
    resource_kind: []const u8,
    resource_id: []const u8,
    capability: Capability,
) bool {
    if (actor.instance_admin) return true;
    var allowed = false;
    for (rules) |rule| {
        if (!std.mem.eql(u8, rule.resource_kind, resource_kind) or
            !std.mem.eql(u8, rule.resource_id, resource_id) or
            rule.capability != capability or
            !matchesPrincipal(rule, actor)) continue;
        if (rule.effect == .deny) return false;
        allowed = true;
    }
    return allowed;
}

fn matchesPrincipal(rule: Rule, actor: Actor) bool {
    return switch (rule.principal_kind) {
        .everyone => true,
        .identity => std.mem.eql(u8, rule.principal_id, actor.identity_id),
        .team => for (actor.team_ids) |team_id| {
            if (std.mem.eql(u8, rule.principal_id, team_id)) break true;
        } else false,
    };
}

fn aclManageCapability(resource_kind: []const u8) ?Capability {
    if (std.mem.eql(u8, resource_kind, "team")) return .team_manage;
    if (std.mem.eql(u8, resource_kind, "project")) return .project_manage;
    if (std.mem.eql(u8, resource_kind, "session")) return .session_share;
    if (std.mem.eql(u8, resource_kind, "provider")) return .provider_manage;
    return null;
}

fn validCapabilityForResource(resource_kind: []const u8, capability: Capability) bool {
    if (std.mem.eql(u8, resource_kind, "team")) return capability == .team_manage;
    if (std.mem.eql(u8, resource_kind, "project")) return capability == .project_view or capability == .project_manage or capability == .session_view or capability == .session_prompt or capability == .session_approve or capability == .session_share;
    if (std.mem.eql(u8, resource_kind, "session")) return capability == .session_view or capability == .session_prompt or capability == .session_approve or capability == .session_share;
    if (std.mem.eql(u8, resource_kind, "provider")) return capability == .provider_use or capability == .provider_manage;
    return false;
}

fn validProviderKind(value: []const u8) bool {
    return std.mem.eql(u8, value, "anthropic") or std.mem.eql(u8, value, "aiand") or
        std.mem.eql(u8, value, "openai") or std.mem.eql(u8, value, "openai-compat");
}

fn validCredentialRef(value: []const u8) bool {
    if (std.mem.startsWith(u8, value, "secret://")) return isUuid(value[9..]);
    if (!std.mem.startsWith(u8, value, "env://")) return false;
    const name = value[6..];
    if (name.len == 0 or name.len > 128 or
        !(std.ascii.isAlphabetic(name[0]) or name[0] == '_')) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

fn configurationHasNoSecrets(value: std.json.Value) bool {
    return switch (value) {
        .object => |object| blk: {
            var iterator = object.iterator();
            while (iterator.next()) |entry| {
                if (secretLikeConfigKey(entry.key_ptr.*) or !configurationHasNoSecrets(entry.value_ptr.*))
                    break :blk false;
            }
            break :blk true;
        },
        .array => |array| blk: {
            for (array.items) |child| if (!configurationHasNoSecrets(child)) break :blk false;
            break :blk true;
        },
        else => true,
    };
}

fn secretLikeConfigKey(key: []const u8) bool {
    var lowered: [128]u8 = undefined;
    if (key.len > lowered.len) return true;
    for (key, 0..) |byte, index| lowered[index] = std.ascii.toLower(byte);
    const normalized = lowered[0..key.len];
    for ([_][]const u8{ "api_key", "apikey", "secret", "password", "token", "credential", "authorization" }) |needle| {
        if (std.mem.indexOf(u8, normalized, needle) != null) return true;
    }
    return false;
}

fn roleGrants(role: MemberRole, capability: Capability) bool {
    return switch (role) {
        .owner => capability == .session_view or capability == .session_prompt or
            capability == .session_approve or capability == .session_share,
        .editor => capability == .session_view or capability == .session_prompt or
            capability == .session_approve,
        .viewer => capability == .session_view,
    };
}

/// The database belongs to the daemon process and closes after its connection
/// threads have stopped. Keeping Quarry behind this type prevents command code
/// from depending on a particular SQL driver.
pub const Database = struct {
    gpa: std.mem.Allocator,
    pool: *quarry.Pool,
    text_type: quarry.TypeId,
    int_type: quarry.TypeId,

    pub const LocalSetupState = enum { available, local, configured_elsewhere };

    /// Report whether first-run service configuration is still available.
    /// Existing OIDC identities also close local setup, preventing a mixed
    /// authentication mode from being enabled by a later request.
    pub fn localSetupState(self: *Database) (quarry.Error || error{UnexpectedResult})!LocalSetupState {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        var cursor = try connection.exec(
            "SELECT (SELECT auth_mode FROM service_config WHERE id = 1), EXISTS (SELECT 1 FROM identities LIMIT 1)",
            null,
        );
        defer cursor.finish() catch {};
        const row = (try cursor.next()) orelse return error.UnexpectedResult;
        if (row.get(0)) |auth_mode| {
            if (std.mem.eql(u8, auth_mode, "local")) return .local;
            return .configured_elsewhere;
        }
        const has_identity = row.get(1) orelse return error.UnexpectedResult;
        return if (std.mem.eql(u8, has_identity, "t") or std.mem.eql(u8, has_identity, "1"))
            .configured_elsewhere
        else
            .available;
    }

    pub fn open(
        gpa: std.mem.Allocator,
        io: std.Io,
        url: []const u8,
        environ: *const std.process.Environ.Map,
        now_ms: i64,
    ) (quarry.Error || error{UnsupportedDatabaseScheme})!Database {
        const parameter_types = databaseParameterTypes(url) orelse return error.UnsupportedDatabaseScheme;
        const pool = try quarry.Pool.init(gpa, io, url, .{ .environ = environ }, .{
            .min = 1,
            .max = 10,
            .idle_timeout_ms = 5 * std.time.ms_per_min,
            .acquire_timeout_ms = 5 * std.time.ms_per_s,
        });
        errdefer pool.deinit();
        const connection = try pool.acquire();
        defer pool.release(connection);
        if (std.mem.startsWith(u8, url, "sqlite:")) {
            // Quarry's embedded SQLite image keeps sqlite_schema on page 1.
            // Chock's normalized multi-user schema exceeds a 4 KiB catalog
            // page, so select an 8 KiB page size before the first migration.
            var page_size = try connection.exec("PRAGMA page_size = 8192", null);
            try page_size.finish();
        }
        try initialize(connection, now_ms);
        return .{
            .gpa = gpa,
            .pool = pool,
            .text_type = parameter_types.text,
            .int_type = parameter_types.int,
        };
    }

    pub fn close(self: *Database) void {
        self.pool.deinit();
        self.* = undefined;
    }

    pub fn ping(self: *Database) quarry.Error!void {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        return connection.ping();
    }

    /// Resolve a verified OIDC identity into this daemon's local identity.
    /// Profile changes update attributes but cannot change local roles. Only
    /// an explicitly configured OIDC subject can bootstrap or regain admin.
    pub fn resolveIdentity(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        issuer: []const u8,
        verified: oauth.oidc.Verified,
        display_name: ?[]const u8,
        instance_admin: bool,
        now_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidIdentity, UnexpectedResult })!Identity {
        if (issuer.len == 0 or verified.subject.len == 0) return error.InvalidIdentity;

        var id = try randomUuid(io);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);

        const type_ids = [_]quarry.TypeId{
            self.text_type,
            self.text_type,
            self.text_type,
            self.text_type,
            self.text_type,
            self.int_type,
        };
        const statement = try connection.prepare(
            "INSERT INTO identities (id, issuer, subject, email, display_name, instance_role, created_ms) " ++
                "VALUES ($1, $2, $3, $4, $5, 'member', $6) " ++
                "ON CONFLICT (issuer, subject) DO UPDATE SET " ++
                "email = excluded.email, display_name = excluded.display_name " ++
                "RETURNING id, instance_role",
            &type_ids,
            null,
        );
        var timestamp: [24]u8 = undefined;
        const timestamp_text = std.fmt.bufPrint(&timestamp, "{d}", .{now_ms}) catch unreachable;
        const params = [_]quarry.Param{
            textParam(self.text_type, id[0..]),
            textParam(self.text_type, issuer),
            textParam(self.text_type, verified.subject),
            nullableTextParam(self.text_type, verified.email),
            nullableTextParam(self.text_type, display_name),
            .{ .type_id = self.int_type, .format = .text, .bytes = timestamp_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        const row = (try cursor.next()) orelse return error.UnexpectedResult;
        const stored_id = row.get(0) orelse return error.UnexpectedResult;
        const stored_role = try gpa.dupe(u8, row.get(1) orelse return error.UnexpectedResult);
        errdefer gpa.free(stored_role);
        if (stored_id.len != id.len or !isUuid(stored_id)) return error.UnexpectedResult;
        @memcpy(&id, stored_id);
        try cursor.finish();
        if (instance_admin) {
            const admin_types = [_]quarry.TypeId{self.text_type};
            const promote = try connection.prepare(
                "UPDATE identities SET instance_role = 'instance_admin' WHERE id = $1",
                &admin_types,
                null,
            );
            const promote_params = [_]quarry.Param{textParam(self.text_type, &id)};
            var promote_cursor = try connection.execute(promote, &promote_params, null);
            try promote_cursor.finish();
            const admin_role = try gpa.dupe(u8, "instance_admin");
            gpa.free(stored_role);
            return .{ .id = id, .instance_role = admin_role };
        }
        return .{ .id = id, .instance_role = stored_role };
    }

    /// Atomically create the first service-managed account and select local
    /// authentication. This operation is deliberately first-run-only: later
    /// accounts must be created through an authenticated administrative flow.
    /// Passwords are encoded as PHC Argon2id strings before they enter SQL.
    pub fn createInitialLocalAdmin(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        username_input: []const u8,
        password: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || std.crypto.pwhash.Error || std.mem.Allocator.Error || error{ InvalidLocalAccount, AlreadyInitialized, UnexpectedResult })!Identity {
        const username = try localUsernameLower(gpa, username_input);
        defer gpa.free(username);
        if (password.len < 12 or password.len > 1024) return error.InvalidLocalAccount;

        var encoded_hash: [256]u8 = undefined;
        const password_hash = try std.crypto.pwhash.argon2.strHash(password, .{
            .allocator = gpa,
            .params = .owasp_2id,
        }, &encoded_hash, io);
        const id = try randomUuid(io);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        var configured = try connection.exec("SELECT id FROM service_config WHERE id = 1", null);
        const already_configured = (try configured.next()) != null;
        try configured.finish();
        var identities = try connection.exec("SELECT id FROM identities LIMIT 1", null);
        const has_identity = (try identities.next()) != null;
        try identities.finish();
        if (already_configured or has_identity) return error.AlreadyInitialized;

        // The singleton insert is the race fence: two simultaneous setup
        // requests cannot both commit an initial administrator.
        var config_insert = try connection.exec("INSERT INTO service_config (id, auth_mode) VALUES (1, 'local')", null);
        try config_insert.finish();

        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const identity_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.int_type };
        const identity_statement = try connection.prepare(
            "INSERT INTO identities (id, issuer, subject, email, display_name, instance_role, created_ms) " ++
                "VALUES ($1, 'urn:chock:local-account', $1, NULL, $2, 'instance_admin', $3)",
            &identity_types,
            null,
        );
        const identity_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, username),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        try identity_cursor.finish();

        const account_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.int_type };
        const account_statement = try connection.prepare(
            "INSERT INTO local_auth_users (identity_id, username, password_hash, created_ms) VALUES ($1, $2, $3, $4)",
            &account_types,
            null,
        );
        const account_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, username),
            textParam(self.text_type, password_hash),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var account_cursor = try connection.execute(account_statement, &account_params, null);
        try account_cursor.finish();
        try connection.commit();
        return .{ .id = id, .instance_role = try gpa.dupe(u8, "instance_admin") };
    }

    /// Authenticate a local account. Unknown usernames perform a dummy
    /// Argon2id derivation so account existence is not exposed by an instant
    /// response. A null result covers unknown, disabled, and wrong-password
    /// accounts alike.
    pub fn authenticateLocalAccount(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        username_input: []const u8,
        password: []const u8,
    ) (quarry.Error || std.mem.Allocator.Error || error{UnexpectedResult})!?Identity {
        const username = localUsernameLower(gpa, username_input) catch {
            dummyPasswordDerivation(gpa, io, password);
            return null;
        };
        defer gpa.free(username);
        if (password.len > 1024) {
            dummyPasswordDerivation(gpa, io, "oversized-password");
            return null;
        }

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT i.id, i.instance_role, a.password_hash, a.disabled_ms " ++
                "FROM local_auth_users a JOIN identities i ON i.id = a.identity_id WHERE a.username = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, username)};
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        const row = (try cursor.next()) orelse {
            dummyPasswordDerivation(gpa, io, password);
            return null;
        };
        const stored_id = row.get(0) orelse return error.UnexpectedResult;
        const stored_role = row.get(1) orelse return error.UnexpectedResult;
        const encoded_hash = row.get(2) orelse return error.UnexpectedResult;
        if (row.get(3) != null) {
            dummyPasswordDerivation(gpa, io, password);
            return null;
        }
        if (password.len < 1) {
            dummyPasswordDerivation(gpa, io, password);
            return null;
        }
        std.crypto.pwhash.argon2.strVerify(encoded_hash, password, .{ .allocator = gpa }, io) catch return null;
        if (!isUuid(stored_id)) return error.UnexpectedResult;
        var id: [36]u8 = undefined;
        @memcpy(&id, stored_id);
        return .{ .id = id, .instance_role = try gpa.dupe(u8, stored_role) };
    }

    /// Create a member account managed by the service. Only an instance
    /// administrator may do this, and the service must already have selected
    /// local authentication during first-run setup.
    pub fn createLocalAccount(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        actor_identity_id: []const u8,
        username_input: []const u8,
        password: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || std.crypto.pwhash.Error || error{ InvalidLocalAccount, NotInstanceAdmin, LocalAuthDisabled, AccountAlreadyExists, UnexpectedResult })![36]u8 {
        if (!isUuid(actor_identity_id)) return error.NotInstanceAdmin;
        if (password.len < 12 or password.len > 1024) return error.InvalidLocalAccount;
        const username = try localUsernameLower(gpa, username_input);
        defer gpa.free(username);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const actor_types = [_]quarry.TypeId{self.text_type};
        const actor_statement = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &actor_types,
            null,
        );
        const actor_params = [_]quarry.Param{textParam(self.text_type, actor_identity_id)};
        var actor_cursor = try connection.execute(actor_statement, &actor_params, null);
        const actor_row = (try actor_cursor.next()) orelse {
            try actor_cursor.finish();
            return error.NotInstanceAdmin;
        };
        const role = actor_row.get(0) orelse return error.UnexpectedResult;
        const is_admin = std.mem.eql(u8, role, "instance_admin");
        try actor_cursor.finish();
        if (!is_admin) return error.NotInstanceAdmin;

        var config = try connection.exec("SELECT auth_mode FROM service_config WHERE id = 1", null);
        const mode_row = (try config.next()) orelse {
            try config.finish();
            return error.LocalAuthDisabled;
        };
        const mode = mode_row.get(0) orelse return error.UnexpectedResult;
        const is_local = std.mem.eql(u8, mode, "local");
        try config.finish();
        if (!is_local) return error.LocalAuthDisabled;

        const username_types = [_]quarry.TypeId{self.text_type};
        const username_statement = try connection.prepare(
            "SELECT identity_id FROM local_auth_users WHERE username = $1",
            &username_types,
            null,
        );
        const username_params = [_]quarry.Param{textParam(self.text_type, username)};
        var username_cursor = try connection.execute(username_statement, &username_params, null);
        const username_exists = (try username_cursor.next()) != null;
        try username_cursor.finish();
        if (username_exists) return error.AccountAlreadyExists;

        var encoded_hash: [256]u8 = undefined;
        const password_hash = try std.crypto.pwhash.argon2.strHash(password, .{
            .allocator = gpa,
            .params = .owasp_2id,
        }, &encoded_hash, io);
        const id = try randomUuid(io);

        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const identity_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.int_type };
        const identity_statement = try connection.prepare(
            "INSERT INTO identities (id, issuer, subject, email, display_name, instance_role, created_ms) " ++
                "VALUES ($1, 'urn:chock:local-account', $1, NULL, $2, 'member', $3)",
            &identity_types,
            null,
        );
        const identity_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, username),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        try identity_cursor.finish();

        const account_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.int_type };
        const account_statement = try connection.prepare(
            "INSERT INTO local_auth_users (identity_id, username, password_hash, created_ms) VALUES ($1, $2, $3, $4)",
            &account_types,
            null,
        );
        const account_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, username),
            textParam(self.text_type, password_hash),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var account_cursor = try connection.execute(account_statement, &account_params, null);
        try account_cursor.finish();
        try connection.commit();
        return id;
    }

    /// Replace a local account's password. This is an administrator recovery
    /// operation: changing the password and revoking every existing login
    /// credential happen in the same transaction.
    pub fn resetLocalAccountPassword(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        actor_identity_id: []const u8,
        target_identity_id: []const u8,
        password: []const u8,
    ) (quarry.Error || std.crypto.pwhash.Error || error{ InvalidLocalAccount, NotInstanceAdmin, LocalAuthDisabled, UnexpectedResult })!void {
        if (!isUuid(actor_identity_id) or !isUuid(target_identity_id) or password.len < 12 or password.len > 1024)
            return error.InvalidLocalAccount;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const actor_types = [_]quarry.TypeId{self.text_type};
        const actor_statement = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &actor_types,
            null,
        );
        const actor_params = [_]quarry.Param{textParam(self.text_type, actor_identity_id)};
        var actor_cursor = try connection.execute(actor_statement, &actor_params, null);
        const actor_row = (try actor_cursor.next()) orelse {
            try actor_cursor.finish();
            return error.NotInstanceAdmin;
        };
        const role = actor_row.get(0) orelse return error.UnexpectedResult;
        const is_admin = std.mem.eql(u8, role, "instance_admin");
        try actor_cursor.finish();
        if (!is_admin) return error.NotInstanceAdmin;

        var config = try connection.exec("SELECT auth_mode FROM service_config WHERE id = 1", null);
        const mode_row = (try config.next()) orelse {
            try config.finish();
            return error.LocalAuthDisabled;
        };
        const mode = mode_row.get(0) orelse return error.UnexpectedResult;
        const is_local = std.mem.eql(u8, mode, "local");
        try config.finish();
        if (!is_local) return error.LocalAuthDisabled;

        const target_types = [_]quarry.TypeId{self.text_type};
        const target_statement = try connection.prepare(
            "SELECT identity_id FROM local_auth_users WHERE identity_id = $1",
            &target_types,
            null,
        );
        const target_params = [_]quarry.Param{textParam(self.text_type, target_identity_id)};
        var target_cursor = try connection.execute(target_statement, &target_params, null);
        const target_row = (try target_cursor.next()) orelse {
            try target_cursor.finish();
            return error.InvalidLocalAccount;
        };
        _ = target_row.get(0) orelse return error.UnexpectedResult;
        try target_cursor.finish();

        var encoded_hash: [256]u8 = undefined;
        const password_hash = try std.crypto.pwhash.argon2.strHash(password, .{
            .allocator = gpa,
            .params = .owasp_2id,
        }, &encoded_hash, io);
        const update_statement = try connection.prepare(
            "UPDATE local_auth_users SET password_hash = $1 WHERE identity_id = $2",
            &.{ self.text_type, self.text_type },
            null,
        );
        const update_params = [_]quarry.Param{
            textParam(self.text_type, password_hash),
            textParam(self.text_type, target_identity_id),
        };
        var update_cursor = try connection.execute(update_statement, &update_params, null);
        try update_cursor.finish();

        const revoke_statement = try connection.prepare(
            "DELETE FROM auth_sessions WHERE identity_id = $1",
            &target_types,
            null,
        );
        var revoke_cursor = try connection.execute(revoke_statement, &target_params, null);
        try revoke_cursor.finish();
        try connection.commit();
    }

    /// Change the signed-in account's own password. The active browser
    /// session is retained, while every other browser or worker credential is
    /// revoked in the same transaction. A compare-and-swap update prevents
    /// two simultaneous password changes from both succeeding with the same
    /// old password.
    pub fn changeLocalAccountPassword(
        self: *Database,
        gpa: std.mem.Allocator,
        io: std.Io,
        identity_id: []const u8,
        session_token: []const u8,
        current_password: []const u8,
        new_password: []const u8,
        now_ms: i64,
    ) (quarry.Error || std.crypto.pwhash.Error || error{ InvalidLocalAccount, InvalidCurrentPassword, InvalidSessionToken, LocalAuthDisabled, UnexpectedResult })!void {
        if (!isUuid(identity_id) or !validSessionToken(session_token) or
            current_password.len == 0 or current_password.len > 1024 or
            new_password.len < 12 or new_password.len > 1024)
            return error.InvalidLocalAccount;

        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(session_token, &digest, .{});
        const session_hash = hexDigest(digest);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        var config = try connection.exec("SELECT auth_mode FROM service_config WHERE id = 1", null);
        const mode_row = (try config.next()) orelse {
            try config.finish();
            return error.LocalAuthDisabled;
        };
        const mode = mode_row.get(0) orelse return error.UnexpectedResult;
        const is_local = std.mem.eql(u8, mode, "local");
        try config.finish();
        if (!is_local) return error.LocalAuthDisabled;

        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const active_session = try connection.prepare(
            "SELECT token_hash FROM auth_sessions WHERE token_hash = $1 AND identity_id = $2 " ++
                "AND expires_ms > $3 AND revoked_ms IS NULL AND worker_session_id IS NULL",
            &.{ self.text_type, self.text_type, self.int_type },
            null,
        );
        const active_params = [_]quarry.Param{
            textParam(self.text_type, &session_hash),
            textParam(self.text_type, identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var active_cursor = try connection.execute(active_session, &active_params, null);
        const active = (try active_cursor.next()) != null;
        try active_cursor.finish();
        if (!active) return error.InvalidSessionToken;

        const account_query = try connection.prepare(
            "SELECT password_hash, disabled_ms FROM local_auth_users WHERE identity_id = $1",
            &.{self.text_type},
            null,
        );
        const account_params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var account_cursor = try connection.execute(account_query, &account_params, null);
        const account_row = (try account_cursor.next()) orelse {
            try account_cursor.finish();
            return error.LocalAuthDisabled;
        };
        const old_hash = account_row.get(0) orelse return error.UnexpectedResult;
        const disabled = account_row.get(1) != null;
        const kept_old_hash = try self.gpa.dupe(u8, old_hash);
        try account_cursor.finish();
        defer self.gpa.free(kept_old_hash);
        if (disabled) return error.LocalAuthDisabled;
        std.crypto.pwhash.argon2.strVerify(kept_old_hash, current_password, .{ .allocator = gpa }, io) catch
            return error.InvalidCurrentPassword;

        var encoded_hash: [256]u8 = undefined;
        const new_hash = try std.crypto.pwhash.argon2.strHash(new_password, .{
            .allocator = gpa,
            .params = .owasp_2id,
        }, &encoded_hash, io);
        const update = try connection.prepare(
            "UPDATE local_auth_users SET password_hash = $1 WHERE identity_id = $2 AND password_hash = $3",
            &.{ self.text_type, self.text_type, self.text_type },
            null,
        );
        const update_params = [_]quarry.Param{
            textParam(self.text_type, new_hash),
            textParam(self.text_type, identity_id),
            textParam(self.text_type, kept_old_hash),
        };
        var update_cursor = try connection.execute(update, &update_params, null);
        try update_cursor.finish();
        if ((update_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidCurrentPassword;

        const revoke = try connection.prepare(
            "DELETE FROM auth_sessions WHERE identity_id = $1 AND token_hash <> $2",
            &.{ self.text_type, self.text_type },
            null,
        );
        const revoke_params = [_]quarry.Param{
            textParam(self.text_type, identity_id),
            textParam(self.text_type, &session_hash),
        };
        var revoke_cursor = try connection.execute(revoke, &revoke_params, null);
        try revoke_cursor.finish();
        try connection.commit();
    }

    /// Disable or re-enable a local account without deleting its identity or
    /// collaboration history. Disabling revokes all active credentials and
    /// cannot remove the final enabled local instance administrator.
    pub fn setLocalAccountDisabled(
        self: *Database,
        actor_identity_id: []const u8,
        target_identity_id: []const u8,
        disabled: bool,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidLocalAccount, NotInstanceAdmin, LocalAuthDisabled, LastLocalAdministrator, UnexpectedResult })!void {
        if (!isUuid(actor_identity_id) or !isUuid(target_identity_id)) return error.InvalidLocalAccount;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const actor_types = [_]quarry.TypeId{self.text_type};
        const actor_statement = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &actor_types,
            null,
        );
        const actor_params = [_]quarry.Param{textParam(self.text_type, actor_identity_id)};
        var actor_cursor = try connection.execute(actor_statement, &actor_params, null);
        const actor_row = (try actor_cursor.next()) orelse {
            try actor_cursor.finish();
            return error.NotInstanceAdmin;
        };
        const actor_role = actor_row.get(0) orelse return error.UnexpectedResult;
        const is_admin = std.mem.eql(u8, actor_role, "instance_admin");
        try actor_cursor.finish();
        if (!is_admin) return error.NotInstanceAdmin;

        var config = try connection.exec("SELECT auth_mode FROM service_config WHERE id = 1", null);
        const mode_row = (try config.next()) orelse {
            try config.finish();
            return error.LocalAuthDisabled;
        };
        const mode = mode_row.get(0) orelse return error.UnexpectedResult;
        const is_local = std.mem.eql(u8, mode, "local");
        try config.finish();
        if (!is_local) return error.LocalAuthDisabled;

        // Serialize status changes through the single service-config row so
        // two concurrent administrator requests cannot both disable the last
        // active local administrator based on a stale count.
        var service_lock = try connection.exec("UPDATE service_config SET auth_mode = auth_mode WHERE id = 1", null);
        try service_lock.finish();

        const target_types = [_]quarry.TypeId{self.text_type};
        const target_statement = try connection.prepare(
            "SELECT i.instance_role, a.disabled_ms FROM identities i " ++
                "JOIN local_auth_users a ON a.identity_id = i.id WHERE i.id = $1",
            &target_types,
            null,
        );
        const target_params = [_]quarry.Param{textParam(self.text_type, target_identity_id)};
        var target_cursor = try connection.execute(target_statement, &target_params, null);
        const target_row = (try target_cursor.next()) orelse {
            try target_cursor.finish();
            return error.InvalidLocalAccount;
        };
        const target_role = target_row.get(0) orelse return error.UnexpectedResult;
        const target_is_admin = std.mem.eql(u8, target_role, "instance_admin");
        const was_disabled = target_row.get(1) != null;
        try target_cursor.finish();

        if (disabled and !was_disabled and target_is_admin) {
            const remaining_admins = try connection.prepare(
                "SELECT COUNT(*) FROM identities i JOIN local_auth_users a ON a.identity_id = i.id " ++
                    "WHERE i.instance_role = 'instance_admin' AND a.disabled_ms IS NULL AND i.id <> $1",
                &target_types,
                null,
            );
            var admins_cursor = try connection.execute(remaining_admins, &target_params, null);
            const admins_row = (try admins_cursor.next()) orelse return error.UnexpectedResult;
            const admins_count = integerColumn(admins_row, 0) orelse return error.UnexpectedResult;
            try admins_cursor.finish();
            if (admins_count == 0) return error.LastLocalAdministrator;
        }

        var timestamp_buffer: [24]u8 = undefined;
        const timestamp = std.fmt.bufPrint(&timestamp_buffer, "{d}", .{now_ms}) catch unreachable;
        if (disabled) {
            const update = try connection.prepare(
                "UPDATE local_auth_users SET disabled_ms = $1 WHERE identity_id = $2",
                &.{ self.int_type, self.text_type },
                null,
            );
            const params = [_]quarry.Param{
                .{ .type_id = self.int_type, .format = .text, .bytes = timestamp },
                textParam(self.text_type, target_identity_id),
            };
            var cursor = try connection.execute(update, &params, null);
            try cursor.finish();

            const revoke = try connection.prepare("DELETE FROM auth_sessions WHERE identity_id = $1", &target_types, null);
            var revoke_cursor = try connection.execute(revoke, &target_params, null);
            try revoke_cursor.finish();
        } else {
            const update = try connection.prepare(
                "UPDATE local_auth_users SET disabled_ms = NULL WHERE identity_id = $1",
                &target_types,
                null,
            );
            var cursor = try connection.execute(update, &target_params, null);
            try cursor.finish();
        }
        try connection.commit();
    }

    /// Create a team with its creator as owner. The owner-only role check is
    /// kept in SQL-backed membership state rather than inferred from email or
    /// provider groups.
    pub fn createTeam(
        self: *Database,
        io: std.Io,
        owner_identity_id: []const u8,
        name_input: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidTeam, UnexpectedResult })![36]u8 {
        const name = std.mem.trim(u8, name_input, " \t\r\n");
        if (!isUuid(owner_identity_id) or name.len == 0 or name.len > 96)
            return error.InvalidTeam;
        const id = try randomUuid(io);
        const acl_id = aclRuleId(.{
            .resource_kind = "team",
            .resource_id = &id,
            .principal_kind = .identity,
            .principal_id = owner_identity_id,
            .capability = .team_manage,
            .effect = .allow,
        });
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const team_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.int_type };
        const team_statement = try connection.prepare(
            "INSERT INTO teams (id, name, created_by_identity_id, created_ms) " ++
                "SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM identities WHERE id = $3)",
            &team_types,
            null,
        );
        const team_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, name),
            textParam(self.text_type, owner_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var team_cursor = try connection.execute(team_statement, &team_params, null);
        try team_cursor.finish();
        if ((team_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidTeam;

        const member_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.int_type };
        const member_statement = try connection.prepare(
            "INSERT INTO team_members (team_id, identity_id, role, added_ms) VALUES ($1, $2, 'owner', $3)",
            &member_types,
            null,
        );
        const member_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, owner_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var member_cursor = try connection.execute(member_statement, &member_params, null);
        try member_cursor.finish();

        const acl_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type, self.int_type,
        };
        const acl_statement = try connection.prepare(
            "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
                "VALUES ($1, 'team', $2, 'identity', $3, 'team_manage', 'allow', $4, $5)",
            &acl_types,
            null,
        );
        const acl_params = [_]quarry.Param{
            textParam(self.text_type, &acl_id),
            textParam(self.text_type, &id),
            textParam(self.text_type, owner_identity_id),
            textParam(self.text_type, owner_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var acl_cursor = try connection.execute(acl_statement, &acl_params, null);
        try acl_cursor.finish();
        try connection.commit();
        return id;
    }

    /// Create an unbound, single-use invitation. The bearer is returned once;
    /// only its SHA-256 digest is kept in Quarry. Redemption always requires a
    /// currently authenticated OIDC identity.
    pub fn createTeamInvitation(
        self: *Database,
        io: std.Io,
        actor_identity_id: []const u8,
        team_id: []const u8,
        role: TeamRole,
        created_ms: i64,
        expires_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidInvitation, NotTeamOwner, UnexpectedResult })!CreatedTeamInvitation {
        const lifetime_ms = std.math.sub(i64, expires_ms, created_ms) catch return error.InvalidInvitation;
        // Invitations are currently member-only. Granting manager through an
        // unbound bearer would let anyone who obtains the token elevate their
        // team role; manager invitations need an explicit identity-binding
        // policy before they can be enabled.
        if (!isUuid(actor_identity_id) or !isUuid(team_id) or role != .member or
            lifetime_ms <= 0 or lifetime_ms > 7 * 24 * 60 * 60 * 1000)
            return error.InvalidInvitation;

        var token: [43]u8 = undefined;
        var raw: [32]u8 = undefined;
        try io.randomSecure(&raw);
        defer std.crypto.secureZero(u8, &raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &raw);
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(&token, &digest, .{});
        const token_hash = hexDigest(digest);
        const id = try randomUuid(io);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};
        try requireTeamOwner(connection, self.text_type, actor_identity_id, team_id);

        const types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.text_type, self.int_type,  self.int_type,
        };
        const statement = try connection.prepare(
            "INSERT INTO team_invitations (id, token_hash, team_id, role, created_by_identity_id, created_ms, expires_ms) " ++
                "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &types,
            null,
        );
        var created_buffer: [24]u8 = undefined;
        var expires_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const expires_text = std.fmt.bufPrint(&expires_buffer, "{d}", .{expires_ms}) catch unreachable;
        const params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, &token_hash),
            textParam(self.text_type, team_id),
            textParam(self.text_type, @tagName(role)),
            textParam(self.text_type, actor_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
            .{ .type_id = self.int_type, .format = .text, .bytes = expires_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        if ((cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidInvitation;
        try connection.commit();
        return .{ .id = id, .token = token, .expires_ms = expires_ms };
    }

    /// Redeem the bearer and add the authenticated identity in one transaction.
    /// Conditional consumption makes concurrent redemptions single-winner.
    pub fn redeemTeamInvitation(
        self: *Database,
        token: []const u8,
        identity_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidInvitation, InvitationUnavailable, UnexpectedResult })!void {
        if (!validSessionToken(token) or !isUuid(identity_id)) return error.InvalidInvitation;
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        const token_hash = hexDigest(digest);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const select_types = [_]quarry.TypeId{self.text_type};
        const select_statement = try connection.prepare(
            "SELECT team_id, role, expires_ms FROM team_invitations " ++
                "WHERE token_hash = $1 AND revoked_ms IS NULL AND redeemed_ms IS NULL",
            &select_types,
            null,
        );
        const select_params = [_]quarry.Param{textParam(self.text_type, &token_hash)};
        var select_cursor = try connection.execute(select_statement, &select_params, null);
        const row = (try select_cursor.next()) orelse {
            try select_cursor.finish();
            return error.InvitationUnavailable;
        };
        const stored_team_id = row.get(0) orelse {
            try select_cursor.finish();
            return error.UnexpectedResult;
        };
        if (!isUuid(stored_team_id)) {
            try select_cursor.finish();
            return error.UnexpectedResult;
        }
        var team_id: [36]u8 = undefined;
        @memcpy(&team_id, stored_team_id);
        const role_text = row.get(1) orelse {
            try select_cursor.finish();
            return error.UnexpectedResult;
        };
        const role = std.meta.stringToEnum(TeamRole, role_text) orelse {
            try select_cursor.finish();
            return error.UnexpectedResult;
        };
        const expires_ms = integerColumn(row, 2) orelse {
            try select_cursor.finish();
            return error.UnexpectedResult;
        };
        try select_cursor.finish();
        if (expires_ms <= now_ms or role == .owner) return error.InvitationUnavailable;

        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const update_types = [_]quarry.TypeId{ self.text_type, self.int_type, self.text_type, self.int_type };
        const update_statement = try connection.prepare(
            "UPDATE team_invitations SET redeemed_by_identity_id = $1, redeemed_ms = $2 " ++
                "WHERE token_hash = $3 AND revoked_ms IS NULL AND redeemed_ms IS NULL AND expires_ms > $4",
            &update_types,
            null,
        );
        const update_params = [_]quarry.Param{
            textParam(self.text_type, identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            textParam(self.text_type, &token_hash),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var update_cursor = try connection.execute(update_statement, &update_params, null);
        try update_cursor.finish();
        if ((update_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvitationUnavailable;

        const insert_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.int_type };
        const insert_statement = try connection.prepare(
            "INSERT INTO team_members (team_id, identity_id, role, added_ms) VALUES ($1, $2, $3, $4) " ++
                "ON CONFLICT (team_id, identity_id) DO NOTHING",
            &insert_types,
            null,
        );
        const insert_params = [_]quarry.Param{
            textParam(self.text_type, &team_id),
            textParam(self.text_type, identity_id),
            textParam(self.text_type, @tagName(role)),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var insert_cursor = try connection.execute(insert_statement, &insert_params, null);
        try insert_cursor.finish();
        try connection.commit();
    }

    pub fn listTeamInvitations(
        self: *Database,
        arena: std.mem.Allocator,
        team_id: []const u8,
        actor_identity_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidInvitation, NotTeamOwner, UnexpectedResult })![]const TeamInvitation {
        if (!isUuid(team_id) or !isUuid(actor_identity_id)) return error.InvalidInvitation;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try requireTeamOwner(connection, self.text_type, actor_identity_id, team_id);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT id, role, created_ms, expires_ms, revoked_ms, redeemed_ms FROM team_invitations " ++
                "WHERE team_id = $1 AND created_by_identity_id = $2 ORDER BY created_ms DESC, id",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, actor_identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var invitations: std.ArrayList(TeamInvitation) = .empty;
        while (try cursor.next()) |row| {
            const id_text = row.get(0) orelse return error.UnexpectedResult;
            const role_text = row.get(1) orelse return error.UnexpectedResult;
            const role = std.meta.stringToEnum(TeamRole, role_text) orelse return error.UnexpectedResult;
            const created_ms = integerColumn(row, 2) orelse return error.UnexpectedResult;
            const expires_ms = integerColumn(row, 3) orelse return error.UnexpectedResult;
            if (!isUuid(id_text)) return error.UnexpectedResult;
            var id: [36]u8 = undefined;
            @memcpy(&id, id_text);
            try invitations.append(arena, .{
                .id = id,
                .role = role,
                .created_ms = created_ms,
                .expires_ms = expires_ms,
                .revoked = row.get(4) != null,
                .redeemed = row.get(5) != null,
                .expired = expires_ms <= now_ms,
            });
        }
        try cursor.finish();
        return invitations.items;
    }

    pub fn revokeTeamInvitation(
        self: *Database,
        actor_identity_id: []const u8,
        team_id: []const u8,
        invitation_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidInvitation, NotTeamOwner, UnexpectedResult })!void {
        if (!isUuid(team_id) or !isUuid(invitation_id) or !isUuid(actor_identity_id)) return error.InvalidInvitation;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try requireTeamOwner(connection, self.text_type, actor_identity_id, team_id);
        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const types = [_]quarry.TypeId{ self.int_type, self.text_type, self.text_type, self.text_type };
        const statement = try connection.prepare(
            "UPDATE team_invitations SET revoked_ms = $1 WHERE id = $2 AND team_id = $3 " ++
                "AND created_by_identity_id = $4 AND revoked_ms IS NULL AND redeemed_ms IS NULL",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            textParam(self.text_type, invitation_id),
            textParam(self.text_type, team_id),
            textParam(self.text_type, actor_identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        if ((cursor.rowsAffected() orelse return error.UnexpectedResult) != 1) return error.InvalidInvitation;
    }

    /// Register a provider at instance, user, or team scope. The credential is
    /// represented only by an opaque `secret://<UUID>` or `env://NAME` handle;
    /// resolving it belongs to the daemon's trusted credential boundary.
    pub fn createLlmProvider(
        self: *Database,
        io: std.Io,
        actor_identity_id: []const u8,
        name_input: []const u8,
        provider_kind: []const u8,
        scope_kind: ProviderScope,
        scope_id_input: []const u8,
        configuration: []const u8,
        credential_ref: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidProvider, UnexpectedResult })![36]u8 {
        const name = std.mem.trim(u8, name_input, " \t\r\n");
        if (!isUuid(actor_identity_id) or name.len == 0 or name.len > 96 or
            !validProviderKind(provider_kind) or configuration.len == 0 or configuration.len > 16 * 1024 or
            !validCredentialRef(credential_ref)) return error.InvalidProvider;
        var config_arena = std.heap.ArenaAllocator.init(self.gpa);
        defer config_arena.deinit();
        const parsed_config = std.json.parseFromSliceLeaky(std.json.Value, config_arena.allocator(), configuration, .{}) catch
            return error.InvalidProvider;
        if (parsed_config != .object or !configurationHasNoSecrets(parsed_config)) return error.InvalidProvider;

        const scope_id: ?[]const u8 = switch (scope_kind) {
            .instance => if (scope_id_input.len == 0) null else return error.InvalidProvider,
            .user => if (std.mem.eql(u8, scope_id_input, actor_identity_id)) scope_id_input else return error.InvalidProvider,
            .team => if (isUuid(scope_id_input)) scope_id_input else return error.InvalidProvider,
        };
        if (scope_kind == .instance) {
            if (!try self.isInstanceAdmin(actor_identity_id)) return error.InvalidProvider;
        } else if (scope_kind == .team and !try self.canManageTeam(scope_id.?, actor_identity_id)) {
            return error.InvalidProvider;
        }

        const id = try randomUuid(io);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};
        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.int_type,
        };
        const insert = try connection.prepare(
            "INSERT INTO llm_providers (id, name, provider_kind, scope_kind, scope_id, configuration, credential_ref, created_by_identity_id, created_ms) " ++
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, name),
            textParam(self.text_type, provider_kind),
            textParam(self.text_type, @tagName(scope_kind)),
            nullableTextParam(self.text_type, scope_id),
            textParam(self.text_type, configuration),
            textParam(self.text_type, credential_ref),
            textParam(self.text_type, actor_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var cursor = try connection.execute(insert, &params, null);
        try cursor.finish();

        const manager_rule: Rule = .{
            .resource_kind = "provider",
            .resource_id = &id,
            .principal_kind = .identity,
            .principal_id = actor_identity_id,
            .capability = .provider_manage,
            .effect = .allow,
        };
        const use_rule: Rule = .{
            .resource_kind = "provider",
            .resource_id = &id,
            .principal_kind = if (scope_kind == .team) .team else .identity,
            .principal_id = if (scope_kind == .team) scope_id.? else actor_identity_id,
            .capability = .provider_use,
            .effect = .allow,
        };
        const acl_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type,
            self.text_type, self.text_type, self.text_type,
            self.int_type,
        };
        const acl_insert = try connection.prepare(
            "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
                "VALUES ($1, 'provider', $2, $3, $4, $5, 'allow', $6, $7)",
            &acl_types,
            null,
        );
        for ([_]Rule{ manager_rule, use_rule }) |rule| {
            const rule_id = aclRuleId(rule);
            const acl_params = [_]quarry.Param{
                textParam(self.text_type, &rule_id),
                textParam(self.text_type, &id),
                textParam(self.text_type, @tagName(rule.principal_kind)),
                textParam(self.text_type, rule.principal_id),
                textParam(self.text_type, @tagName(rule.capability)),
                textParam(self.text_type, actor_identity_id),
                .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
            };
            var acl_cursor = try connection.execute(acl_insert, &acl_params, null);
            try acl_cursor.finish();
        }
        try connection.commit();
        return id;
    }

    /// List only providers the identity is authorized to use or manage. No
    /// credential material is returned, only its opaque reference.
    pub fn listLlmProviders(
        self: *Database,
        arena: std.mem.Allocator,
        identity_id: []const u8,
    ) (quarry.Error || error{ UnexpectedResult, InvalidAclState })![]const LlmProvider {
        if (!isUuid(identity_id)) return &.{};
        const connection = try self.pool.acquire();
        var connection_held = true;
        defer if (connection_held) self.pool.release(connection);
        const statement = try connection.prepare(
            "SELECT id, name, provider_kind, scope_kind, scope_id, configuration, CAST(created_ms AS TEXT) " ++
                "FROM llm_providers ORDER BY scope_kind, scope_id, name, id",
            &.{},
            null,
        );
        var cursor = try connection.execute(statement, &.{}, null);
        var all: std.ArrayList(LlmProvider) = .empty;
        while (try cursor.next()) |row| {
            const id_text = row.get(0) orelse return error.UnexpectedResult;
            if (!isUuid(id_text)) return error.UnexpectedResult;
            var id: [36]u8 = undefined;
            @memcpy(&id, id_text);
            try all.append(arena, .{
                .id = id,
                .name = try arena.dupe(u8, row.get(1) orelse return error.UnexpectedResult),
                .provider_kind = try arena.dupe(u8, row.get(2) orelse return error.UnexpectedResult),
                .scope_kind = std.meta.stringToEnum(ProviderScope, row.get(3) orelse return error.UnexpectedResult) orelse return error.UnexpectedResult,
                .scope_id = if (row.get(4)) |value| try arena.dupe(u8, value) else null,
                .configuration = try arena.dupe(u8, row.get(5) orelse return error.UnexpectedResult),
                .has_credential = true,
                .is_default = false,
                .created_ms = integerColumn(row, 6) orelse return error.UnexpectedResult,
            });
        }
        try cursor.finish();
        self.pool.release(connection);
        connection_held = false;
        for (all.items, 0..) |*provider, index| {
            provider.is_default = true;
            for (all.items, 0..) |other, other_index| {
                if (index == other_index or provider.scope_kind != other.scope_kind or
                    !std.mem.eql(u8, provider.scope_id orelse "", other.scope_id orelse "")) continue;
                if (other.created_ms > provider.created_ms or
                    (other.created_ms == provider.created_ms and std.mem.order(u8, &other.id, &provider.id) == .gt))
                {
                    provider.is_default = false;
                    break;
                }
            }
        }
        var visible: std.ArrayList(LlmProvider) = .empty;
        for (all.items) |provider| {
            if (try self.authorize(identity_id, "provider", &provider.id, .provider_use) or
                try self.authorize(identity_id, "provider", &provider.id, .provider_manage))
                try visible.append(arena, provider);
        }
        return visible.items;
    }

    pub fn defaultLlmProvider(
        self: *Database,
        arena: std.mem.Allocator,
        identity_id: []const u8,
    ) (quarry.Error || error{ UnexpectedResult, InvalidAclState })!?LlmProvider {
        const providers = try self.listLlmProviders(arena, identity_id);
        var selected: ?LlmProvider = null;
        for (providers) |provider| {
            if (!provider.is_default) continue;
            const rank: u8 = switch (provider.scope_kind) {
                .user => 0,
                .team => 1,
                .instance => 2,
            };
            const selected_rank: u8 = if (selected) |current| switch (current.scope_kind) {
                .user => 0,
                .team => 1,
                .instance => 2,
            } else 255;
            if (rank < selected_rank or
                (rank == selected_rank and rank == 1 and std.mem.order(u8, provider.scope_id orelse "", selected.?.scope_id orelse "") == .lt))
                selected = provider;
        }
        return selected;
    }

    /// Resolve a provider's credential reference only after the caller has
    /// selected an authorized provider. Public provider listings never expose it.
    pub fn llmProviderCredentialRef(
        self: *Database,
        arena: std.mem.Allocator,
        provider_id: []const u8,
    ) (quarry.Error || error{ InvalidProvider, UnexpectedResult })![]const u8 {
        if (!isUuid(provider_id)) return error.InvalidProvider;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT credential_ref FROM llm_providers WHERE id = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, provider_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse return error.InvalidProvider;
        const reference = try arena.dupe(u8, row.get(0) orelse return error.UnexpectedResult);
        if (try cursor.next() != null) return error.UnexpectedResult;
        try cursor.finish();
        return reference;
    }

    pub fn removeLlmProvider(
        self: *Database,
        actor_identity_id: []const u8,
        provider_id: []const u8,
    ) (quarry.Error || error{ InvalidProvider, InvalidAclState, NotProviderManager, UnexpectedResult })!bool {
        if (!isUuid(provider_id)) return error.InvalidProvider;
        if (!try self.authorize(actor_identity_id, "provider", provider_id, .provider_manage)) return error.NotProviderManager;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};
        const types = [_]quarry.TypeId{self.text_type};
        const delete_rules = try connection.prepare("DELETE FROM acl_rules WHERE resource_kind = 'provider' AND resource_id = $1", &types, null);
        const params = [_]quarry.Param{textParam(self.text_type, provider_id)};
        var rules_cursor = try connection.execute(delete_rules, &params, null);
        try rules_cursor.finish();
        const delete_provider = try connection.prepare("DELETE FROM llm_providers WHERE id = $1", &types, null);
        var provider_cursor = try connection.execute(delete_provider, &params, null);
        try provider_cursor.finish();
        const removed = (provider_cursor.rowsAffected() orelse return error.UnexpectedResult) == 1;
        try connection.commit();
        return removed;
    }

    fn isInstanceAdmin(self: *Database, identity_id: []const u8) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare("SELECT instance_role FROM identities WHERE id = $1", &.{self.text_type}, null);
        const params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return false;
        };
        const role = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const admin = std.mem.eql(u8, role, "instance_admin");
        try cursor.finish();
        return admin;
    }

    /// Export authorization and sharing metadata only for an explicit
    /// instance administrator. Bearers, token hashes, and live host leases are
    /// intentionally absent from this backup representation.
    pub fn exportInstanceAccess(
        self: *Database,
        arena: std.mem.Allocator,
        actor_identity_id: []const u8,
    ) (quarry.Error || std.mem.Allocator.Error || error{ InvalidIdentity, NotInstanceAdmin, UnexpectedResult })![]const u8 {
        if (!isUuid(actor_identity_id)) return error.InvalidIdentity;
        if (!try self.isInstanceAdmin(actor_identity_id)) return error.NotInstanceAdmin;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.repeatable_read);
        errdefer connection.rollback() catch {};

        var teams: std.ArrayList(InstanceTeamExport) = .empty;
        var team_cursor = try connection.exec(
            "SELECT id, name, created_by_identity_id, created_ms FROM teams ORDER BY created_ms, id",
            null,
        );
        defer team_cursor.finish() catch {};
        while (try team_cursor.next()) |row| {
            const id = row.get(0) orelse return error.UnexpectedResult;
            const creator = row.get(2) orelse return error.UnexpectedResult;
            if (!isUuid(id) or !isUuid(creator)) return error.UnexpectedResult;
            try teams.append(arena, .{
                .id = try arena.dupe(u8, id),
                .name = try arena.dupe(u8, row.get(1) orelse return error.UnexpectedResult),
                .created_by_identity_id = try arena.dupe(u8, creator),
                .created_ms = integerColumn(row, 3) orelse return error.UnexpectedResult,
            });
        }
        try team_cursor.finish();

        var team_members: std.ArrayList(InstanceTeamMemberExport) = .empty;
        var member_cursor = try connection.exec(
            "SELECT team_id, identity_id, role, added_ms FROM team_members ORDER BY team_id, identity_id",
            null,
        );
        defer member_cursor.finish() catch {};
        while (try member_cursor.next()) |row| {
            const team_id = row.get(0) orelse return error.UnexpectedResult;
            const identity_id = row.get(1) orelse return error.UnexpectedResult;
            const role = row.get(2) orelse return error.UnexpectedResult;
            if (!isUuid(team_id) or !isUuid(identity_id) or std.meta.stringToEnum(TeamRole, role) == null)
                return error.UnexpectedResult;
            try team_members.append(arena, .{
                .team_id = try arena.dupe(u8, team_id),
                .identity_id = try arena.dupe(u8, identity_id),
                .role = try arena.dupe(u8, role),
                .added_ms = integerColumn(row, 3) orelse return error.UnexpectedResult,
            });
        }
        try member_cursor.finish();

        var invitations: std.ArrayList(InstanceInvitationExport) = .empty;
        var invitation_cursor = try connection.exec(
            "SELECT id, team_id, role, created_by_identity_id, created_ms, expires_ms, revoked_ms, " ++
                "redeemed_by_identity_id, redeemed_ms FROM team_invitations ORDER BY created_ms, id",
            null,
        );
        defer invitation_cursor.finish() catch {};
        while (try invitation_cursor.next()) |row| {
            const id = row.get(0) orelse return error.UnexpectedResult;
            const team_id = row.get(1) orelse return error.UnexpectedResult;
            const role = row.get(2) orelse return error.UnexpectedResult;
            const creator = row.get(3) orelse return error.UnexpectedResult;
            const redeemer = if (row.get(7)) |value| try arena.dupe(u8, value) else null;
            if (!isUuid(id) or !isUuid(team_id) or !isUuid(creator) or
                (redeemer != null and !isUuid(redeemer.?)) or std.meta.stringToEnum(TeamRole, role) == null)
                return error.UnexpectedResult;
            try invitations.append(arena, .{
                .id = try arena.dupe(u8, id),
                .team_id = try arena.dupe(u8, team_id),
                .role = try arena.dupe(u8, role),
                .created_by_identity_id = try arena.dupe(u8, creator),
                .created_ms = integerColumn(row, 4) orelse return error.UnexpectedResult,
                .expires_ms = integerColumn(row, 5) orelse return error.UnexpectedResult,
                .revoked_ms = if (row.get(6) != null) integerColumn(row, 6) orelse return error.UnexpectedResult else null,
                .redeemed_by_identity_id = redeemer,
                .redeemed_ms = if (row.get(8) != null) integerColumn(row, 8) orelse return error.UnexpectedResult else null,
            });
        }
        try invitation_cursor.finish();

        var session_members: std.ArrayList(InstanceSessionMemberExport) = .empty;
        var session_member_cursor = try connection.exec(
            "SELECT session_id, identity_id, role, added_by_identity_id, added_ms FROM session_members " ++
                "ORDER BY session_id, identity_id",
            null,
        );
        defer session_member_cursor.finish() catch {};
        while (try session_member_cursor.next()) |row| {
            const session_id = row.get(0) orelse return error.UnexpectedResult;
            const identity_id = row.get(1) orelse return error.UnexpectedResult;
            const role = row.get(2) orelse return error.UnexpectedResult;
            const added_by = row.get(3) orelse return error.UnexpectedResult;
            if (!validWorkerSessionId(session_id) or !isUuid(identity_id) or !isUuid(added_by) or
                std.meta.stringToEnum(MemberRole, role) == null) return error.UnexpectedResult;
            try session_members.append(arena, .{
                .session_id = try arena.dupe(u8, session_id),
                .identity_id = try arena.dupe(u8, identity_id),
                .role = try arena.dupe(u8, role),
                .added_by_identity_id = try arena.dupe(u8, added_by),
                .added_ms = integerColumn(row, 4) orelse return error.UnexpectedResult,
            });
        }
        try session_member_cursor.finish();

        var acl_rules: std.ArrayList(InstanceAclExport) = .empty;
        var acl_cursor = try connection.exec(
            "SELECT id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, " ++
                "created_by_identity_id, created_ms FROM acl_rules ORDER BY resource_kind, resource_id, id",
            null,
        );
        defer acl_cursor.finish() catch {};
        while (try acl_cursor.next()) |row| {
            const id = row.get(0) orelse return error.UnexpectedResult;
            const kind = row.get(1) orelse return error.UnexpectedResult;
            const resource_id = row.get(2) orelse return error.UnexpectedResult;
            const principal_kind = row.get(3) orelse return error.UnexpectedResult;
            const principal_id = if (row.get(4)) |value| try arena.dupe(u8, value) else null;
            const capability = row.get(5) orelse return error.UnexpectedResult;
            const effect = row.get(6) orelse return error.UnexpectedResult;
            const creator = row.get(7) orelse return error.UnexpectedResult;
            if (!isUuid(id) or !isUuid(creator) or aclManageCapability(kind) == null or resource_id.len == 0 or
                std.meta.stringToEnum(PrincipalKind, principal_kind) == null or
                std.meta.stringToEnum(Capability, capability) == null or std.meta.stringToEnum(Effect, effect) == null or
                (std.mem.eql(u8, principal_kind, "identity") or std.mem.eql(u8, principal_kind, "team")) and
                    (principal_id == null or !isUuid(principal_id.?)) or
                std.mem.eql(u8, principal_kind, "everyone") and principal_id != null)
                return error.UnexpectedResult;
            try acl_rules.append(arena, .{
                .id = try arena.dupe(u8, id),
                .resource_kind = try arena.dupe(u8, kind),
                .resource_id = try arena.dupe(u8, resource_id),
                .principal_kind = try arena.dupe(u8, principal_kind),
                .principal_id = principal_id,
                .capability = try arena.dupe(u8, capability),
                .effect = try arena.dupe(u8, effect),
                .created_by_identity_id = try arena.dupe(u8, creator),
                .created_ms = integerColumn(row, 8) orelse return error.UnexpectedResult,
            });
        }
        try acl_cursor.finish();

        const json = try std.json.Stringify.valueAlloc(arena, InstanceAccessExport{
            .teams = teams.items,
            .team_members = team_members.items,
            .invitations = invitations.items,
            .session_members = session_members.items,
            .acl_rules = acl_rules.items,
        }, .{});
        try connection.commit();
        return json;
    }

    /// The instance directory is deliberately administrator-only because it
    /// contains profile email addresses from the configured identity server.
    pub fn listPeople(
        self: *Database,
        arena: std.mem.Allocator,
        actor_identity_id: []const u8,
    ) (quarry.Error || error{ InvalidIdentity, NotInstanceAdmin, UnexpectedResult })![]const DirectoryPerson {
        if (!isUuid(actor_identity_id)) return error.InvalidIdentity;
        if (!try self.isInstanceAdmin(actor_identity_id)) return error.NotInstanceAdmin;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "SELECT id, display_name, email, instance_role, " ++
                "CASE WHEN EXISTS (SELECT 1 FROM local_auth_users a WHERE a.identity_id = identities.id) " ++
                "THEN 1 ELSE 0 END, " ++
                "CASE WHEN EXISTS (SELECT 1 FROM local_auth_users a WHERE a.identity_id = identities.id AND a.disabled_ms IS NOT NULL) " ++
                "THEN 1 ELSE 0 END " ++
                "FROM identities ORDER BY display_name, id",
            &.{},
            null,
        );
        var cursor = try connection.execute(statement, &.{}, null);
        defer cursor.finish() catch {};
        var people: std.ArrayList(DirectoryPerson) = .empty;
        while (try cursor.next()) |row| {
            const id = row.get(0) orelse return error.UnexpectedResult;
            const role = row.get(3) orelse return error.UnexpectedResult;
            const local_account = integerColumn(row, 4) orelse return error.UnexpectedResult;
            const local_account_disabled = integerColumn(row, 5) orelse return error.UnexpectedResult;
            if (!isUuid(id) or (!std.mem.eql(u8, role, "member") and !std.mem.eql(u8, role, "instance_admin")))
                return error.UnexpectedResult;
            try people.append(arena, .{
                .identity_id = try arena.dupe(u8, id),
                .display_name = try arena.dupe(u8, row.get(1) orelse ""),
                .email = try arena.dupe(u8, row.get(2) orelse ""),
                .instance_role = try arena.dupe(u8, role),
                .local_account = local_account != 0,
                .local_account_disabled = local_account_disabled != 0,
            });
        }
        try cursor.finish();
        return people.items;
    }

    /// Change an identity's instance-wide role. Serialize demotions through
    /// the service configuration row so concurrent administrators cannot
    /// remove the final administrator based on the same stale count.
    pub fn setInstanceAdmin(
        self: *Database,
        actor_identity_id: []const u8,
        target_identity_id: []const u8,
        make_admin: bool,
    ) (quarry.Error || error{ InvalidIdentity, NotInstanceAdmin, LastInstanceAdministrator, UnexpectedResult })!void {
        if (!isUuid(actor_identity_id) or !isUuid(target_identity_id)) return error.InvalidIdentity;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        // Take the service-wide role lock before checking the actor, so a
        // request that waited behind another demotion cannot act on a stale
        // administrator role.
        var service_lock = try connection.exec("UPDATE service_config SET auth_mode = auth_mode WHERE id = 1", null);
        try service_lock.finish();

        const identity_types = [_]quarry.TypeId{self.text_type};
        const actor_query = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &identity_types,
            null,
        );
        const actor_params = [_]quarry.Param{textParam(self.text_type, actor_identity_id)};
        var actor_cursor = try connection.execute(actor_query, &actor_params, null);
        const actor_row = (try actor_cursor.next()) orelse {
            try actor_cursor.finish();
            return error.NotInstanceAdmin;
        };
        const actor_role = actor_row.get(0) orelse return error.UnexpectedResult;
        const actor_is_admin = std.mem.eql(u8, actor_role, "instance_admin");
        try actor_cursor.finish();
        if (!actor_is_admin) return error.NotInstanceAdmin;

        const target_query = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &identity_types,
            null,
        );
        const target_params = [_]quarry.Param{textParam(self.text_type, target_identity_id)};
        var target_cursor = try connection.execute(target_query, &target_params, null);
        const target_row = (try target_cursor.next()) orelse {
            try target_cursor.finish();
            return error.InvalidIdentity;
        };
        const target_role = target_row.get(0) orelse return error.UnexpectedResult;
        const target_is_admin = std.mem.eql(u8, target_role, "instance_admin");
        try target_cursor.finish();

        if (target_is_admin and !make_admin) {
            const count_query = try connection.prepare(
                "SELECT COUNT(*) FROM identities WHERE instance_role = 'instance_admin' AND id <> $1",
                &identity_types,
                null,
            );
            var count_cursor = try connection.execute(count_query, &target_params, null);
            const count_row = (try count_cursor.next()) orelse return error.UnexpectedResult;
            const remaining = integerColumn(count_row, 0) orelse return error.UnexpectedResult;
            try count_cursor.finish();
            if (remaining == 0) return error.LastInstanceAdministrator;
        }

        const role: []const u8 = if (make_admin) "instance_admin" else "member";
        const update = try connection.prepare(
            "UPDATE identities SET instance_role = $1 WHERE id = $2",
            &.{ self.text_type, self.text_type },
            null,
        );
        const update_params = [_]quarry.Param{
            textParam(self.text_type, role),
            textParam(self.text_type, target_identity_id),
        };
        var update_cursor = try connection.execute(update, &update_params, null);
        try update_cursor.finish();
        try connection.commit();
    }

    fn canManageTeam(self: *Database, team_id: []const u8, identity_id: []const u8) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "SELECT role FROM team_members WHERE team_id = $1 AND identity_id = $2",
            &.{ self.text_type, self.text_type },
            null,
        );
        const params = [_]quarry.Param{ textParam(self.text_type, team_id), textParam(self.text_type, identity_id) };
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return false;
        };
        const role = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const manages = std.mem.eql(u8, role, "owner") or std.mem.eql(u8, role, "manager");
        try cursor.finish();
        return manages;
    }

    pub fn listTeams(
        self: *Database,
        arena: std.mem.Allocator,
        identity_id: []const u8,
    ) (quarry.Error || error{ InvalidTeam, UnexpectedResult })![]const Team {
        if (!isUuid(identity_id)) return error.InvalidTeam;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT t.id, t.name, tm.role FROM teams t JOIN team_members tm ON tm.team_id = t.id " ++
                "WHERE tm.identity_id = $1 ORDER BY t.name, t.id",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var teams: std.ArrayList(Team) = .empty;
        while (try cursor.next()) |row| {
            const id_text = row.get(0) orelse return error.UnexpectedResult;
            const name = row.get(1) orelse return error.UnexpectedResult;
            const role_text = row.get(2) orelse return error.UnexpectedResult;
            if (!isUuid(id_text)) return error.UnexpectedResult;
            const role = std.meta.stringToEnum(TeamRole, role_text) orelse return error.UnexpectedResult;
            var id: [36]u8 = undefined;
            @memcpy(&id, id_text);
            try teams.append(arena, .{ .id = id, .name = try arena.dupe(u8, name), .role = role });
        }
        try cursor.finish();
        return teams.items;
    }

    pub fn setTeamMember(
        self: *Database,
        team_id: []const u8,
        actor_identity_id: []const u8,
        identity_id: []const u8,
        role: TeamRole,
        added_ms: i64,
    ) (quarry.Error || error{ InvalidTeam, NotTeamOwner, UnexpectedResult })!void {
        if (!isUuid(team_id) or !isUuid(actor_identity_id) or !isUuid(identity_id) or role == .owner)
            return error.InvalidTeam;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const owner_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM team_members WHERE team_id = $1 AND identity_id = $2",
            &owner_types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotTeamOwner;
        };
        const owner_role = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const is_owner = std.mem.eql(u8, owner_role, "owner");
        try owner_cursor.finish();
        if (!is_owner) return error.NotTeamOwner;

        const identity_types = [_]quarry.TypeId{self.text_type};
        const identity_statement = try connection.prepare("SELECT id FROM identities WHERE id = $1", &identity_types, null);
        const identity_params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        if ((try identity_cursor.next()) == null) {
            try identity_cursor.finish();
            return error.InvalidTeam;
        }
        try identity_cursor.finish();

        var added_buffer: [24]u8 = undefined;
        const added_text = std.fmt.bufPrint(&added_buffer, "{d}", .{added_ms}) catch unreachable;
        const member_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.int_type,
        };
        const member_statement = try connection.prepare(
            "INSERT INTO team_members (team_id, identity_id, role, added_ms) VALUES ($1, $2, $3, $4) " ++
                "ON CONFLICT (team_id, identity_id) DO UPDATE SET role = $3, added_ms = $4 " ++
                "WHERE team_members.role <> 'owner'",
            &member_types,
            null,
        );
        const member_params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, identity_id),
            textParam(self.text_type, @tagName(role)),
            .{ .type_id = self.int_type, .format = .text, .bytes = added_text },
        };
        var member_cursor = try connection.execute(member_statement, &member_params, null);
        try member_cursor.finish();
        if ((member_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidTeam;
        try connection.commit();
    }

    /// Remove a non-owner's team membership. Team-derived access disappears,
    /// while independent identity ACL rules remain untouched.
    pub fn removeTeamMember(
        self: *Database,
        team_id: []const u8,
        actor_identity_id: []const u8,
        identity_id: []const u8,
    ) (quarry.Error || error{ InvalidTeam, NotTeamOwner, UnexpectedResult })!void {
        if (!isUuid(team_id) or !isUuid(actor_identity_id) or !isUuid(identity_id)) return error.InvalidTeam;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM team_members WHERE team_id = $1 AND identity_id = $2",
            &types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotTeamOwner;
        };
        const owner_role = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const is_owner = std.mem.eql(u8, owner_role, "owner");
        try owner_cursor.finish();
        if (!is_owner) return error.NotTeamOwner;

        const remove_statement = try connection.prepare(
            "DELETE FROM team_members WHERE team_id = $1 AND identity_id = $2 AND role <> 'owner'",
            &types,
            null,
        );
        const remove_params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, identity_id),
        };
        var removed = try connection.execute(remove_statement, &remove_params, null);
        try removed.finish();
        try connection.commit();
    }

    pub fn listTeamPeople(
        self: *Database,
        arena: std.mem.Allocator,
        team_id: []const u8,
        actor_identity_id: []const u8,
    ) (quarry.Error || error{ InvalidTeam, NotTeamOwner, UnexpectedResult })![]const TeamPerson {
        if (!isUuid(team_id) or !isUuid(actor_identity_id)) return error.InvalidTeam;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const owner_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM team_members WHERE team_id = $1 AND identity_id = $2",
            &owner_types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, team_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotTeamOwner;
        };
        const role_text = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const is_owner = std.mem.eql(u8, role_text, "owner");
        try owner_cursor.finish();
        if (!is_owner) return error.NotTeamOwner;

        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT i.id, i.display_name, i.email, tm.role FROM identities i " ++
                "LEFT JOIN team_members tm ON tm.identity_id = i.id AND tm.team_id = $1 " ++
                "ORDER BY i.display_name, i.id",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, team_id)};
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var people: std.ArrayList(TeamPerson) = .empty;
        while (try cursor.next()) |row| {
            const id = row.get(0) orelse return error.UnexpectedResult;
            const role_text_opt = row.get(3);
            const role = if (role_text_opt) |text|
                std.meta.stringToEnum(TeamRole, text) orelse return error.UnexpectedResult
            else
                null;
            try people.append(arena, .{
                .identity_id = try arena.dupe(u8, id),
                .display_name = try arena.dupe(u8, row.get(1) orelse ""),
                .email = try arena.dupe(u8, row.get(2) orelse ""),
                .role = role,
            });
        }
        try cursor.finish();
        return people.items;
    }

    /// Evaluate the persisted ACL set for a resource. Team membership is read
    /// from daemon state, not accepted from an untrusted request. A principal
    /// with an unknown identity is always denied.
    pub fn authorize(
        self: *Database,
        identity_id: []const u8,
        resource_kind: []const u8,
        resource_id: []const u8,
        capability: Capability,
    ) (quarry.Error || error{InvalidAclState})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);

        const text_type = self.text_type;
        const identity_types = [_]quarry.TypeId{text_type};
        const identity_statement = try connection.prepare(
            "SELECT instance_role FROM identities WHERE id = $1",
            &identity_types,
            null,
        );
        const identity_params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        const identity_row = (try identity_cursor.next()) orelse {
            try identity_cursor.finish();
            return false;
        };
        const role = identity_row.get(0) orelse {
            try identity_cursor.finish();
            return error.InvalidAclState;
        };
        const is_admin = std.mem.eql(u8, role, "instance_admin");
        try identity_cursor.finish();
        if (is_admin) return true;

        const types = [_]quarry.TypeId{ text_type, text_type, text_type, text_type, text_type };
        const statement = try connection.prepare(
            "SELECT effect FROM acl_rules WHERE resource_kind = $1 AND (resource_id = $2 OR resource_id = '*') " ++
                "AND capability = $3 AND principal_kind = 'everyone' " ++
                "UNION ALL SELECT effect FROM acl_rules WHERE resource_kind = $1 " ++
                "AND (resource_id = $2 OR resource_id = '*') AND capability = $3 AND principal_kind = 'identity' " ++
                "AND principal_id = $4 UNION ALL SELECT ar.effect FROM acl_rules ar " ++
                "JOIN team_members tm ON tm.team_id = ar.principal_id " ++
                "WHERE ar.resource_kind = $1 AND (ar.resource_id = $2 OR ar.resource_id = '*') " ++
                "AND ar.capability = $3 AND ar.principal_kind = 'team' " ++
                "AND tm.identity_id = $5",
            &types,
            null,
        );
        const parameters = [_]quarry.Param{
            textParam(self.text_type, resource_kind),
            textParam(self.text_type, resource_id),
            textParam(self.text_type, @tagName(capability)),
            textParam(self.text_type, identity_id),
            textParam(self.text_type, identity_id),
        };
        var cursor = try connection.execute(statement, &parameters, null);
        var allowed = false;
        while (try cursor.next()) |row| {
            const effect = row.get(0) orelse {
                try cursor.finish();
                return error.InvalidAclState;
            };
            if (std.mem.eql(u8, effect, "deny")) {
                try cursor.finish();
                return false;
            }
            if (std.mem.eql(u8, effect, "allow")) {
                allowed = true;
            } else {
                try cursor.finish();
                return error.InvalidAclState;
            }
        }
        try cursor.finish();
        return allowed;
    }

    /// Return the ACL rows for one resource only to a principal that can
    /// administer that resource. A listing is itself privileged state.
    pub fn listAclRules(
        self: *Database,
        arena: std.mem.Allocator,
        actor_identity_id: []const u8,
        resource_kind: []const u8,
        resource_id: []const u8,
    ) (quarry.Error || error{ InvalidAclRule, InvalidAclState, NotAclManager, UnexpectedResult })![]const AclRecord {
        const manage = aclManageCapability(resource_kind) orelse return error.InvalidAclRule;
        if (!try self.authorize(actor_identity_id, resource_kind, resource_id, manage))
            return error.NotAclManager;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT id, principal_kind, principal_id, capability, effect FROM acl_rules " ++
                "WHERE resource_kind = $1 AND resource_id = $2 ORDER BY principal_kind, principal_id, capability",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, resource_kind),
            textParam(self.text_type, resource_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var rows: std.ArrayList(AclRecord) = .empty;
        while (try cursor.next()) |row| {
            const id_text = row.get(0) orelse return error.UnexpectedResult;
            const principal_kind_text = row.get(1) orelse return error.UnexpectedResult;
            const principal_id = row.get(2) orelse "";
            const capability_text = row.get(3) orelse return error.UnexpectedResult;
            const effect_text = row.get(4) orelse return error.UnexpectedResult;
            if (!isUuid(id_text)) return error.UnexpectedResult;
            var id: [36]u8 = undefined;
            @memcpy(&id, id_text);
            try rows.append(arena, .{ .id = id, .rule = .{
                .resource_kind = try arena.dupe(u8, resource_kind),
                .resource_id = try arena.dupe(u8, resource_id),
                .principal_kind = std.meta.stringToEnum(PrincipalKind, principal_kind_text) orelse return error.UnexpectedResult,
                .principal_id = try arena.dupe(u8, principal_id),
                .capability = std.meta.stringToEnum(Capability, capability_text) orelse return error.UnexpectedResult,
                .effect = std.meta.stringToEnum(Effect, effect_text) orelse return error.UnexpectedResult,
            } });
        }
        try cursor.finish();
        return rows.items;
    }

    /// Replace the one rule for a resource/principal/capability tuple. The
    /// caller must already manage the resource; arbitrary identity UUIDs and
    /// provider group claims are never accepted as principals.
    pub fn setAclRule(
        self: *Database,
        actor_identity_id: []const u8,
        rule: Rule,
        created_ms: i64,
    ) (quarry.Error || error{ InvalidAclRule, InvalidAclState, NotAclManager, UnexpectedResult })![36]u8 {
        const manage = aclManageCapability(rule.resource_kind) orelse return error.InvalidAclRule;
        if (rule.resource_id.len == 0 or rule.resource_id.len > 128 or
            !validCapabilityForResource(rule.resource_kind, rule.capability)) return error.InvalidAclRule;
        if (rule.principal_kind == .everyone) {
            if (rule.principal_id.len != 0) return error.InvalidAclRule;
        } else if (!isUuid(rule.principal_id)) return error.InvalidAclRule;
        if (!try self.authorize(actor_identity_id, rule.resource_kind, rule.resource_id, manage))
            return error.NotAclManager;
        if (!try self.aclResourceExists(rule.resource_kind, rule.resource_id) or
            !try self.aclPrincipalExists(rule.principal_kind, rule.principal_id)) return error.InvalidAclRule;

        const id = aclRuleId(rule);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};
        const remove_old = try connection.prepare(
            "DELETE FROM acl_rules WHERE resource_kind = $1 AND resource_id = $2 AND principal_kind = $3 " ++
                "AND COALESCE(principal_id, '') = $4 AND capability = $5 AND id <> $6",
            &.{ self.text_type, self.text_type, self.text_type, self.text_type, self.text_type, self.text_type },
            null,
        );
        const key_params = [_]quarry.Param{
            textParam(self.text_type, rule.resource_kind),
            textParam(self.text_type, rule.resource_id),
            textParam(self.text_type, @tagName(rule.principal_kind)),
            textParam(self.text_type, rule.principal_id),
            textParam(self.text_type, @tagName(rule.capability)),
            textParam(self.text_type, &id),
        };
        var remove_cursor = try connection.execute(remove_old, &key_params, null);
        try remove_cursor.finish();

        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const insert_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.int_type,
        };
        const insert = try connection.prepare(
            "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) " ++
                "ON CONFLICT (id) DO UPDATE SET effect = excluded.effect, " ++
                "created_by_identity_id = excluded.created_by_identity_id, created_ms = excluded.created_ms",
            &insert_types,
            null,
        );
        const insert_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, rule.resource_kind),
            textParam(self.text_type, rule.resource_id),
            textParam(self.text_type, @tagName(rule.principal_kind)),
            if (rule.principal_kind == .everyone) .{ .type_id = self.text_type, .format = .text, .bytes = null } else textParam(self.text_type, rule.principal_id),
            textParam(self.text_type, @tagName(rule.capability)),
            textParam(self.text_type, @tagName(rule.effect)),
            textParam(self.text_type, actor_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var insert_cursor = try connection.execute(insert, &insert_params, null);
        try insert_cursor.finish();
        try connection.commit();
        return id;
    }

    pub fn removeAclRule(
        self: *Database,
        actor_identity_id: []const u8,
        rule_id: []const u8,
    ) (quarry.Error || error{ InvalidAclRule, InvalidAclState, NotAclManager, UnexpectedResult })!bool {
        if (!isUuid(rule_id)) return error.InvalidAclRule;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT resource_kind, resource_id, capability FROM acl_rules WHERE id = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, rule_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return false;
        };
        const kind = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const resource_id = row.get(1) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const capability_text = row.get(2) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const manage = aclManageCapability(kind) orelse {
            try cursor.finish();
            return error.InvalidAclRule;
        };
        const copied_kind = try self.gpa.dupe(u8, kind);
        defer self.gpa.free(copied_kind);
        const copied_resource = try self.gpa.dupe(u8, resource_id);
        defer self.gpa.free(copied_resource);
        _ = std.meta.stringToEnum(Capability, capability_text) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        try cursor.finish();
        if (!try self.authorize(actor_identity_id, copied_kind, copied_resource, manage)) return error.NotAclManager;
        const deletion = try connection.prepare("DELETE FROM acl_rules WHERE id = $1", &types, null);
        var deleted = try connection.execute(deletion, &params, null);
        try deleted.finish();
        return (deleted.rowsAffected() orelse return error.UnexpectedResult) == 1;
    }

    fn aclResourceExists(self: *Database, resource_kind: []const u8, resource_id: []const u8) (quarry.Error || error{UnexpectedResult})!bool {
        if (std.mem.eql(u8, resource_id, "*") and std.mem.eql(u8, resource_kind, "provider")) return true;
        const table = if (std.mem.eql(u8, resource_kind, "project")) "daemon_projects" else if (std.mem.eql(u8, resource_kind, "team")) "teams" else if (std.mem.eql(u8, resource_kind, "session")) "daemon_sessions" else if (std.mem.eql(u8, resource_kind, "provider")) "llm_providers" else return false;
        const sql = try std.fmt.allocPrint(self.gpa, "SELECT id FROM {s} WHERE id = $1", .{table});
        defer self.gpa.free(sql);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(sql, &[_]quarry.TypeId{self.text_type}, null);
        const params = [_]quarry.Param{textParam(self.text_type, resource_id)};
        var cursor = try connection.execute(statement, &params, null);
        const found = (try cursor.next()) != null;
        try cursor.finish();
        return found;
    }

    fn aclPrincipalExists(self: *Database, kind: PrincipalKind, principal_id: []const u8) (quarry.Error || error{UnexpectedResult})!bool {
        if (kind == .everyone) return principal_id.len == 0;
        if (!isUuid(principal_id)) return false;
        const table = if (kind == .identity) "identities" else "teams";
        const sql = try std.fmt.allocPrint(self.gpa, "SELECT id FROM {s} WHERE id = $1", .{table});
        defer self.gpa.free(sql);
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(sql, &[_]quarry.TypeId{self.text_type}, null);
        const params = [_]quarry.Param{textParam(self.text_type, principal_id)};
        var cursor = try connection.execute(statement, &params, null);
        const found = (try cursor.next()) != null;
        try cursor.finish();
        return found;
    }

    /// Create an opaque browser session. The bearer is returned once and only
    /// its SHA-256 digest is persisted.
    pub fn createLoginSession(
        self: *Database,
        io: std.Io,
        identity_id: []const u8,
        now_ms: i64,
        expires_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidSessionLifetime, UnknownIdentity, UnexpectedResult })!LoginSession {
        return self.createLoginSessionForScope(io, identity_id, null, now_ms, expires_ms);
    }

    /// Create a bearer restricted to one registered client-hosted session.
    /// The raw token is returned once; only its digest and scope are stored.
    pub fn createWorkerLoginSession(
        self: *Database,
        io: std.Io,
        identity_id: []const u8,
        session_id: []const u8,
        now_ms: i64,
        expires_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidSessionLifetime, UnknownIdentity, UnexpectedResult, InvalidWorkerSession })!LoginSession {
        if (!validWorkerSessionId(session_id)) return error.InvalidWorkerSession;
        return self.createLoginSessionForScope(io, identity_id, session_id, now_ms, expires_ms);
    }

    fn createLoginSessionForScope(
        self: *Database,
        io: std.Io,
        identity_id: []const u8,
        worker_session_id: ?[]const u8,
        now_ms: i64,
        expires_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{ InvalidSessionLifetime, UnknownIdentity, UnexpectedResult })!LoginSession {
        if (expires_ms <= now_ms) return error.InvalidSessionLifetime;
        var token: [43]u8 = undefined;
        var raw: [32]u8 = undefined;
        try io.randomSecure(&raw);
        defer std.crypto.secureZero(u8, &raw);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &raw);
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(&token, &digest, .{});
        const hash = hexDigest(digest);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type, self.int_type, self.int_type, self.text_type };
        const statement = try connection.prepare(
            "INSERT INTO auth_sessions (token_hash, identity_id, created_ms, expires_ms, worker_session_id) " ++
                "SELECT $1, $2, $3, $4, $5 WHERE EXISTS (SELECT 1 FROM identities WHERE id = $2)",
            &types,
            null,
        );
        var now_buffer: [24]u8 = undefined;
        var expires_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const expires_text = std.fmt.bufPrint(&expires_buffer, "{d}", .{expires_ms}) catch unreachable;
        const params = [_]quarry.Param{
            textParam(self.text_type, &hash),
            textParam(self.text_type, identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            .{ .type_id = self.int_type, .format = .text, .bytes = expires_text },
            if (worker_session_id) |scope| textParam(self.text_type, scope) else .{ .type_id = self.text_type, .format = .text, .bytes = null },
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        const inserted = cursor.rowsAffected() orelse return error.UnexpectedResult;
        if (inserted != 1) return error.UnknownIdentity;
        return .{ .token = token, .expires_ms = expires_ms };
    }

    /// Resolve an untrusted cookie into local identity state. Expired,
    /// revoked, malformed, and unknown tokens are indistinguishable.
    pub fn resolveLoginSession(
        self: *Database,
        gpa: std.mem.Allocator,
        token: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidSessionToken, UnexpectedResult })!?SessionIdentity {
        if (!validSessionToken(token)) return null;
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        const hash = hexDigest(digest);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.int_type };
        const statement = try connection.prepare(
            "SELECT i.id, i.instance_role, s.worker_session_id FROM auth_sessions s " ++
                "JOIN identities i ON i.id = s.identity_id " ++
                "WHERE s.token_hash = $1 AND s.expires_ms > $2 AND s.revoked_ms IS NULL",
            &types,
            null,
        );
        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const params = [_]quarry.Param{
            textParam(self.text_type, &hash),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return null;
        };
        const id = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const role = row.get(1) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const worker_session = row.get(2);
        if (id.len != 36 or !isUuid(id)) {
            try cursor.finish();
            return error.UnexpectedResult;
        }
        var copied_id: [36]u8 = undefined;
        @memcpy(&copied_id, id);
        var copied_worker_session: [128]u8 = undefined;
        var copied_worker_session_len: u8 = 0;
        if (worker_session) |scope| {
            if (!validWorkerSessionId(scope) or scope.len > copied_worker_session.len) {
                try cursor.finish();
                return error.UnexpectedResult;
            }
            @memcpy(copied_worker_session[0..scope.len], scope);
            copied_worker_session_len = @intCast(scope.len);
        }
        const copied_role = try gpa.dupe(u8, role);
        errdefer gpa.free(copied_role);
        try cursor.finish();
        return .{
            .id = copied_id,
            .instance_role = copied_role,
            .worker_session = copied_worker_session,
            .worker_session_len = copied_worker_session_len,
        };
    }

    pub fn revokeLoginSession(
        self: *Database,
        token: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{InvalidSessionToken})!void {
        if (!validSessionToken(token)) return error.InvalidSessionToken;
        var digest: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &digest);
        std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
        const hash = hexDigest(digest);

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.int_type, self.text_type };
        const statement = try connection.prepare(
            "UPDATE auth_sessions SET revoked_ms = $1 WHERE token_hash = $2 AND revoked_ms IS NULL",
            &types,
            null,
        );
        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const params = [_]quarry.Param{
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            textParam(self.text_type, &hash),
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
    }

    /// Revoke all still-live browser and worker credentials for one identity.
    /// The identity and all collaboration history remain intact for audit and
    /// ownership; this is intended for OIDC offboarding after the auth server
    /// has disabled the account.
    pub fn revokeIdentitySessions(
        self: *Database,
        actor_identity_id: []const u8,
        target_identity_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidIdentity, NotInstanceAdmin, UnknownIdentity, UnexpectedResult })!u64 {
        if (!isUuid(actor_identity_id) or !isUuid(target_identity_id)) return error.InvalidIdentity;
        if (!try self.isInstanceAdmin(actor_identity_id)) return error.NotInstanceAdmin;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const identity_statement = try connection.prepare("SELECT id FROM identities WHERE id = $1", &.{self.text_type}, null);
        const identity_params = [_]quarry.Param{textParam(self.text_type, target_identity_id)};
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        if ((try identity_cursor.next()) == null) {
            try identity_cursor.finish();
            return error.UnknownIdentity;
        }
        try identity_cursor.finish();

        var now_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const update_types = [_]quarry.TypeId{ self.int_type, self.text_type, self.int_type };
        const update = try connection.prepare(
            "UPDATE auth_sessions SET revoked_ms = $1 WHERE identity_id = $2 AND revoked_ms IS NULL AND expires_ms > $3",
            &update_types,
            null,
        );
        const update_params = [_]quarry.Param{
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            textParam(self.text_type, target_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var cursor = try connection.execute(update, &update_params, null);
        try cursor.finish();
        const count = cursor.rowsAffected() orelse return error.UnexpectedResult;
        try connection.commit();
        return count;
    }

    /// Resolve the cookie and evaluate its ACL in one daemon-owned operation.
    /// A null result means the login session is invalid or expired.
    pub fn authorizeLoginSession(
        self: *Database,
        gpa: std.mem.Allocator,
        token: []const u8,
        now_ms: i64,
        resource_kind: []const u8,
        resource_id: []const u8,
        capability: Capability,
    ) (quarry.Error || error{ InvalidSessionToken, UnexpectedResult, InvalidAclState })!?bool {
        const session = try self.resolveLoginSession(gpa, token, now_ms) orelse return null;
        defer gpa.free(session.instance_role);
        if (std.mem.eql(u8, session.instance_role, "instance_admin")) return true;
        if (std.mem.eql(u8, resource_kind, "session"))
            return try self.authorizeSession(&session.id, resource_id, capability);
        // A wildcard names every project and no directory, so it reaches the rules as it
        // stands. Only a real root is exchanged for the project it belongs to.
        if (std.mem.eql(u8, resource_kind, "project") and !isUuid(resource_id) and
            !std.mem.eql(u8, resource_id, "*"))
        {
            const project_id = try self.projectIdForRoot(resource_id) orelse return false;
            return try self.authorize(&session.id, "project", &project_id, capability);
        }
        return try self.authorize(&session.id, resource_kind, resource_id, capability);
    }

    /// Session membership grants the role's baseline capabilities. Explicit
    /// session ACL rules can add access, and any matching deny still wins.
    pub fn authorizeSession(
        self: *Database,
        identity_id: []const u8,
        session_id: []const u8,
        capability: Capability,
    ) (quarry.Error || error{ InvalidAclState, UnexpectedResult })!bool {
        const connection = try self.pool.acquire();
        var acquired = true;
        defer if (acquired) self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT role FROM session_members WHERE session_id = $1 AND identity_id = $2",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        var member_role: ?MemberRole = null;
        if (try cursor.next()) |row| {
            const role_text = row.get(0) orelse {
                try cursor.finish();
                return error.InvalidAclState;
            };
            member_role = std.meta.stringToEnum(MemberRole, role_text) orelse {
                try cursor.finish();
                return error.InvalidAclState;
            };
        }
        try cursor.finish();
        self.pool.release(connection);
        acquired = false;

        if (try self.isInstanceAdministrator(identity_id)) return true;
        const project_id = try self.sessionProjectId(session_id) orelse return false;
        if (try self.hasSessionDeny(identity_id, session_id, capability)) return false;
        if (try self.hasSessionProjectDeny(identity_id, session_id, capability)) return false;
        if (try self.authorize(identity_id, "session", session_id, capability)) return true;
        if (try self.authorize(identity_id, "project", &project_id, capability)) return true;
        return if (member_role) |role| roleGrants(role, capability) else false;
    }

    fn sessionProjectId(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!?[36]u8 {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT project_id FROM daemon_sessions WHERE id = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return null;
        };
        const project_id = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        if (project_id.len != 36) {
            try cursor.finish();
            return error.UnexpectedResult;
        }
        const copy: [36]u8 = project_id[0..36].*;
        try cursor.finish();
        return copy;
    }

    fn isInstanceAdministrator(
        self: *Database,
        identity_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT id FROM identities WHERE id = $1 AND instance_role = 'instance_admin'",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var cursor = try connection.execute(statement, &params, null);
        const found = (try cursor.next()) != null;
        try cursor.finish();
        return found;
    }

    /// Project ACL denies constrain sessions inside that project too. Session
    /// membership and a session-level allow may grant a capability, but neither
    /// can override a matching deny at the containing project boundary.
    fn hasSessionProjectDeny(
        self: *Database,
        identity_id: []const u8,
        session_id: []const u8,
        capability: Capability,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT ar.id FROM acl_rules ar JOIN daemon_sessions ds ON ds.id = $1 " ++
                "WHERE ar.resource_kind = 'project' AND (ar.resource_id = ds.project_id OR ar.resource_id = '*') " ++
                "AND ar.capability = $2 AND ar.effect = 'deny' AND (ar.principal_kind = 'everyone' " ++
                "OR (ar.principal_kind = 'identity' AND ar.principal_id = $3) " ++
                "OR (ar.principal_kind = 'team' AND EXISTS (SELECT 1 FROM team_members tm " ++
                "WHERE tm.team_id = ar.principal_id AND tm.identity_id = $3)))",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, @tagName(capability)),
            textParam(self.text_type, identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        const denied = (try cursor.next()) != null;
        try cursor.finish();
        return denied;
    }

    fn hasSessionDeny(
        self: *Database,
        identity_id: []const u8,
        session_id: []const u8,
        capability: Capability,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT id FROM acl_rules WHERE resource_kind = 'session' AND (resource_id = $1 OR resource_id = '*') " ++
                "AND capability = $2 AND principal_kind = 'everyone' AND effect = 'deny' " ++
                "UNION ALL SELECT id FROM acl_rules WHERE resource_kind = 'session' AND (resource_id = $1 OR resource_id = '*') " ++
                "AND capability = $2 AND principal_kind = 'identity' AND principal_id = $3 AND effect = 'deny' " ++
                "UNION ALL SELECT ar.id FROM acl_rules ar JOIN team_members tm ON tm.team_id = ar.principal_id " ++
                "WHERE ar.resource_kind = 'session' AND (ar.resource_id = $1 OR ar.resource_id = '*') AND ar.capability = $2 " ++
                "AND ar.principal_kind = 'team' AND tm.identity_id = $3 AND ar.effect = 'deny'",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, @tagName(capability)),
            textParam(self.text_type, identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        const denied = (try cursor.next()) != null;
        try cursor.finish();
        return denied;
    }

    /// Register an existing local directory under a daemon-owned UUID. The
    /// caller verifies and canonicalizes the directory before reaching here.
    /// The creator receives project access but no rights to unrelated projects.
    pub fn registerLocalProject(
        self: *Database,
        io: std.Io,
        owner_identity_id: []const u8,
        name: []const u8,
        root: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{InvalidProject})![36]u8 {
        return self.registerProjectSource(io, owner_identity_id, name, "local", root, root, created_ms);
    }

    fn registerProjectSource(
        self: *Database,
        io: std.Io,
        owner_identity_id: []const u8,
        name: []const u8,
        source_kind: []const u8,
        source_locator: []const u8,
        execution_root: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{InvalidProject})![36]u8 {
        if (!isUuid(owner_identity_id) or name.len == 0 or name.len > 128 or
            (!std.mem.eql(u8, source_kind, "local") and !std.mem.eql(u8, source_kind, "git")) or
            source_locator.len == 0 or source_locator.len > 2048 or
            !std.fs.path.isAbsolute(execution_root) or execution_root.len == 0) return error.InvalidProject;
        var id = try randomUuid(io);
        var acl_ids: [6][36]u8 = undefined;
        const capabilities = .{ .project_view, .project_manage, .session_view, .session_prompt, .session_approve, .session_share };
        inline for (capabilities, 0..) |capability, index| {
            acl_ids[index] = aclRuleId(.{
                .resource_kind = "project",
                .resource_id = &id,
                .principal_kind = .identity,
                .principal_id = owner_identity_id,
                .capability = capability,
                .effect = .allow,
            });
        }
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const project_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type, self.text_type, self.text_type, self.int_type,
        };
        const project_insert = try connection.prepare(
            "INSERT INTO daemon_projects (id, owner_identity_id, name, source_kind, source_locator, execution_root, status, created_ms) " ++
                "VALUES ($1, $2, $3, $4, $5, $6, 'ready', $7)",
            &project_types,
            null,
        );
        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const project_params = [_]quarry.Param{
            textParam(self.text_type, &id),
            textParam(self.text_type, owner_identity_id),
            textParam(self.text_type, name),
            textParam(self.text_type, source_kind),
            textParam(self.text_type, source_locator),
            textParam(self.text_type, execution_root),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var project_cursor = try connection.execute(project_insert, &project_params, null);
        try project_cursor.finish();

        const acl_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type,
            self.text_type, self.int_type,
        };
        const acl_insert = try connection.prepare(
            "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
                "VALUES ($1, 'project', $2, 'identity', $3, $4, 'allow', $5, $6)",
            &acl_types,
            null,
        );
        inline for (capabilities, 0..) |capability, index| {
            const acl_params = [_]quarry.Param{
                textParam(self.text_type, &acl_ids[index]),
                textParam(self.text_type, &id),
                textParam(self.text_type, owner_identity_id),
                textParam(self.text_type, @tagName(capability)),
                textParam(self.text_type, owner_identity_id),
                .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
            };
            var acl_cursor = try connection.execute(acl_insert, &acl_params, null);
            try acl_cursor.finish();
        }
        try connection.commit();
        return id;
    }

    pub fn registerGitProject(
        self: *Database,
        io: std.Io,
        owner_identity_id: []const u8,
        name: []const u8,
        repository_url: []const u8,
        execution_root: []const u8,
        created_ms: i64,
    ) (quarry.Error || std.Io.RandomSecureError || error{InvalidProject})![36]u8 {
        if (repository_url.len == 0 or repository_url.len > 2048 or
            !std.fs.path.isAbsolute(execution_root)) return error.InvalidProject;
        return self.registerProjectSource(io, owner_identity_id, name, "git", repository_url, execution_root, created_ms);
    }

    pub fn listProjects(
        self: *Database,
        arena: std.mem.Allocator,
    ) (quarry.Error || error{UnexpectedResult})![]const Project {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "SELECT id, name, execution_root, source_kind, source_locator, status FROM daemon_projects ORDER BY created_ms, id",
            &.{},
            null,
        );
        var cursor = try connection.execute(statement, &.{}, null);
        defer cursor.finish() catch {};
        var projects: std.ArrayList(Project) = .empty;
        while (try cursor.next()) |row| {
            const id_text = row.get(0) orelse return error.UnexpectedResult;
            const name = row.get(1) orelse return error.UnexpectedResult;
            const root = row.get(2) orelse return error.UnexpectedResult;
            const source_kind = row.get(3) orelse return error.UnexpectedResult;
            const source_locator = row.get(4) orelse return error.UnexpectedResult;
            const status = row.get(5) orelse return error.UnexpectedResult;
            if (!isUuid(id_text)) return error.UnexpectedResult;
            var id: [36]u8 = undefined;
            @memcpy(&id, id_text);
            try projects.append(arena, .{
                .id = id,
                .name = try arena.dupe(u8, name),
                .root = try arena.dupe(u8, root),
                .source_kind = try arena.dupe(u8, source_kind),
                .source_locator = try arena.dupe(u8, source_locator),
                .status = try arena.dupe(u8, status),
            });
        }
        try cursor.finish();
        return projects.items;
    }

    /// Reversibly archive or restore a project. Archiving leaves workspace
    /// files, sessions, and ACL history untouched; it only prevents new
    /// service-managed sessions from being created from that project.
    pub fn setProjectArchived(
        self: *Database,
        actor_identity_id: []const u8,
        project_id: []const u8,
        archived: bool,
    ) (quarry.Error || error{ InvalidProject, InvalidAclState, NotProjectManager, UnexpectedResult })!void {
        if (!isUuid(project_id)) return error.InvalidProject;
        if (!try self.authorize(actor_identity_id, "project", project_id, .project_manage))
            return error.NotProjectManager;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "UPDATE daemon_projects SET status = $1 WHERE id = $2 AND status IN ('ready', 'archived')",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, if (archived) "archived" else "ready"),
            textParam(self.text_type, project_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        if ((cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidProject;
    }

    /// Only registered projects in the ready state accept new service-managed
    /// sessions. Existing transcripts and sessions remain available after
    /// their project is archived.
    pub fn projectAcceptsNewSessions(
        self: *Database,
        execution_root: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "SELECT status FROM daemon_projects WHERE execution_root = $1",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, execution_root)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return false;
        };
        const status = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const ready = std.mem.eql(u8, status, "ready");
        try cursor.finish();
        return ready;
    }

    /// Persist the daemon's session-to-project mapping and its creator's owner
    /// membership. The transcript keeps its existing session identifier; the
    /// project relationship always uses the daemon's UUID.
    pub fn registerSession(
        self: *Database,
        owner_identity_id: []const u8,
        project_root: []const u8,
        session_id: []const u8,
        placement: SessionPlacement,
        created_ms: i64,
    ) (quarry.Error || error{ InvalidSession, UnexpectedResult })!void {
        var stage: []const u8 = "input validation";
        self.registerSessionInner(owner_identity_id, project_root, session_id, placement, created_ms, &stage) catch |err| {
            if (err == error.ServerError)
                std.log.err("session registration failed during {s}", .{stage});
            return err;
        };
    }

    fn registerSessionInner(
        self: *Database,
        owner_identity_id: []const u8,
        project_root: []const u8,
        session_id: []const u8,
        placement: SessionPlacement,
        created_ms: i64,
        stage: *[]const u8,
    ) (quarry.Error || error{ InvalidSession, UnexpectedResult })!void {
        if (!isUuid(owner_identity_id) or
            session_id.len == 0 or session_id.len > 128) return error.InvalidSession;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        stage.* = "begin";
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        // Serialize session registration with archive/restore updates. The
        // matched no-op update acquires the project row's write lock on
        // PostgreSQL and the database write lock on SQLite, keeping the
        // status check and session insert in one ordering boundary.
        stage.* = "project gate";
        const project_gate = try connection.prepare(
            "UPDATE daemon_projects SET status = 'ready' WHERE execution_root = $1 AND status = 'ready'",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        const project_gate_params = [_]quarry.Param{textParam(self.text_type, project_root)};
        var project_gate_cursor = try connection.execute(project_gate, &project_gate_params, null);
        try project_gate_cursor.finish();
        if ((project_gate_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidSession;

        var created_buffer: [24]u8 = undefined;
        const created_text = std.fmt.bufPrint(&created_buffer, "{d}", .{created_ms}) catch unreachable;
        const session_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type, self.int_type,
        };
        stage.* = "session row insert";
        const session_insert = try connection.prepare(
            "INSERT INTO daemon_sessions (id, owner_identity_id, placement, project_id, created_ms) " ++
                "SELECT $1, $2, $3, id, $5 FROM daemon_projects " ++
                "WHERE execution_root = $4 AND status = 'ready'",
            &session_types,
            null,
        );
        const session_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, owner_identity_id),
            textParam(self.text_type, @tagName(placement)),
            textParam(self.text_type, project_root),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var session_cursor = try connection.execute(session_insert, &session_params, null);
        try session_cursor.finish();
        if ((session_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.InvalidSession;

        const member_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.int_type,
        };
        stage.* = "owner membership insert";
        const member_insert = try connection.prepare(
            "INSERT INTO session_members (session_id, identity_id, role, added_by_identity_id, added_ms) " ++
                "VALUES ($1, $2, 'owner', $3, $4)",
            &member_types,
            null,
        );
        const member_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, owner_identity_id),
            textParam(self.text_type, owner_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = created_text },
        };
        var member_cursor = try connection.execute(member_insert, &member_params, null);
        try member_cursor.finish();
        stage.* = "commit";
        try connection.commit();
    }

    /// Compensate a failed filesystem session creation. This removes only the
    /// registry row and dependent access state created for that session; it
    /// never touches transcript files.
    pub fn unregisterSession(
        self: *Database,
        owner_identity_id: []const u8,
        session_id: []const u8,
    ) (quarry.Error || error{ InvalidSession, UnexpectedResult })!bool {
        if (!isUuid(owner_identity_id) or session_id.len == 0 or session_id.len > 128)
            return error.InvalidSession;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const check_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const check = try connection.prepare(
            "SELECT id FROM daemon_sessions WHERE id = $1 AND owner_identity_id = $2",
            &check_types,
            null,
        );
        const check_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, owner_identity_id),
        };
        var check_cursor = try connection.execute(check, &check_params, null);
        const found = (try check_cursor.next()) != null;
        try check_cursor.finish();
        if (!found) {
            try connection.commit();
            return false;
        }

        const child_types = [_]quarry.TypeId{self.text_type};
        for ([_][]const u8{
            "DELETE FROM session_hosts WHERE session_id = $1",
            "DELETE FROM session_members WHERE session_id = $1",
            "DELETE FROM acl_rules WHERE resource_kind = 'session' AND resource_id = $1",
        }) |sql| {
            const child = try connection.prepare(sql, &child_types, null);
            const child_params = [_]quarry.Param{textParam(self.text_type, session_id)};
            var child_cursor = try connection.execute(child, &child_params, null);
            try child_cursor.finish();
        }
        const delete = try connection.prepare(
            "DELETE FROM daemon_sessions WHERE id = $1 AND owner_identity_id = $2",
            &check_types,
            null,
        );
        var delete_cursor = try connection.execute(delete, &check_params, null);
        try delete_cursor.finish();
        const removed = (delete_cursor.rowsAffected() orelse return error.UnexpectedResult) == 1;
        try connection.commit();
        return removed;
    }

    /// Verify the caller's project locator is the project bound to a registered
    /// session. The session ID alone is not a project authorization boundary.
    pub fn sessionBelongsToProject(
        self: *Database,
        session_id: []const u8,
        project_root: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const project_id = try self.projectIdForRoot(project_root) orelse return false;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT id FROM daemon_sessions WHERE id = $1 AND project_id = $2",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, &project_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        const found = (try cursor.next()) != null;
        try cursor.finish();
        return found;
    }

    /// Return the execution placement recorded when this session was created.
    /// Callers must not infer placement from the currently connected host.
    pub fn sessionPlacement(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!?SessionPlacement {
        if (session_id.len == 0 or session_id.len > 128) return null;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT placement FROM daemon_sessions WHERE id = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return null;
        };
        const text = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const placement = if (std.mem.eql(u8, text, "client_busy"))
            SessionPlacement.client
        else
            std.meta.stringToEnum(SessionPlacement, text) orelse {
                try cursor.finish();
                return error.UnexpectedResult;
            };
        try cursor.finish();
        return placement;
    }

    /// Only the owner of a client-placed session may provision a worker
    /// credential for it. Membership can grant collaboration, not execution
    /// host ownership.
    pub fn isClientSessionOwner(
        self: *Database,
        session_id: []const u8,
        identity_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        if (!validWorkerSessionId(session_id) or !isUuid(identity_id)) return false;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const statement = try connection.prepare(
            "SELECT id FROM daemon_sessions WHERE id = $1 AND owner_identity_id = $2 AND placement IN ('client', 'client_busy')",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        const found = (try cursor.next()) != null;
        try cursor.finish();
        return found;
    }

    /// Admit one client-hosted turn at a time. This keeps a prompt appended
    /// while its worker is running from being ordered ahead of that turn's
    /// assistant output in the canonical event log.
    pub fn beginClientTurn(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        if (session_id.len == 0 or session_id.len > 128) return false;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "UPDATE daemon_sessions SET placement = 'client_busy' WHERE id = $1 AND placement = 'client'",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        return (cursor.rowsAffected() orelse return error.UnexpectedResult) == 1;
    }

    /// The worker calls this only after its terminal turn event is durably
    /// appended. A worker restart can continue the busy turn from the log.
    pub fn finishClientTurn(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        if (session_id.len == 0 or session_id.len > 128) return false;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const statement = try connection.prepare(
            "UPDATE daemon_sessions SET placement = 'client' WHERE id = $1 AND placement = 'client_busy'",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        return (cursor.rowsAffected() orelse return error.UnexpectedResult) == 1;
    }

    /// Complete a client turn and fence every request carrying the generation
    /// that ran it. A host may claim the next generation after it observes the
    /// terminal event, but delayed writes from the completed turn cannot land
    /// after a later prompt opens a new busy window.
    pub fn finishClientTurnAndFenceHost(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};
        const types = [_]quarry.TypeId{self.text_type};
        const finish_statement = try connection.prepare(
            "UPDATE daemon_sessions SET placement = 'client' WHERE id = $1 AND placement = 'client_busy'",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var finish_cursor = try connection.execute(finish_statement, &params, null);
        try finish_cursor.finish();
        if ((finish_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1) {
            try connection.commit();
            return false;
        }
        const fence_statement = try connection.prepare(
            "UPDATE session_hosts SET lease_generation = lease_generation + 1 WHERE session_id = $1 AND placement = 'client'",
            &types,
            null,
        );
        var fence_cursor = try connection.execute(fence_statement, &params, null);
        try fence_cursor.finish();
        if ((fence_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.UnexpectedResult;
        try connection.commit();
        return true;
    }

    /// Check the serialization marker while holding the session log lock.
    /// Worker event ingress uses this immediately before appending so a
    /// terminal event can close the turn before another event acquires the log.
    pub fn clientTurnActive(
        self: *Database,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT id FROM daemon_sessions WHERE id = $1 AND placement = 'client_busy'",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        const active = (try cursor.next()) != null;
        try cursor.finish();
        return active;
    }

    /// Resolve the daemon-side execution root only after the session UUID has
    /// been looked up through its registered project relationship.
    pub fn projectRootForSession(
        self: *Database,
        arena: std.mem.Allocator,
        session_id: []const u8,
    ) (quarry.Error || error{UnexpectedResult})!?[]const u8 {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT p.execution_root FROM daemon_sessions ds JOIN daemon_projects p ON p.id = ds.project_id WHERE ds.id = $1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return null;
        };
        const root = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        const copy = try arena.dupe(u8, root);
        try cursor.finish();
        return copy;
    }

    /// Assign the single executor for a registered session. Only its owner
    /// may assign a host. An active lease cannot be stolen; an expired lease
    /// is taken over with a strictly larger generation.
    pub fn claimSessionHost(
        self: *Database,
        session_id: []const u8,
        actor_identity_id: []const u8,
        placement: SessionPlacement,
        host_id: []const u8,
        now_ms: i64,
        lease_ms: i64,
    ) (quarry.Error || error{ InvalidHostLease, NotSessionOwner, SessionLeaseHeld, UnexpectedResult })!SessionHostLease {
        if (session_id.len == 0 or session_id.len > 128 or !isUuid(actor_identity_id) or
            !isUuid(host_id) or lease_ms <= 0 or lease_ms > 5 * 60 * std.time.ms_per_min)
            return error.InvalidHostLease;
        const expires_ms = std.math.add(i64, now_ms, lease_ms) catch return error.InvalidHostLease;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const pair_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM session_members WHERE session_id = $1 AND identity_id = $2",
            &pair_types,
            null,
        );
        const pair_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &pair_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotSessionOwner;
        };
        const role = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const is_owner = std.mem.eql(u8, role, "owner");
        try owner_cursor.finish();
        if (!is_owner) return error.NotSessionOwner;

        const session_statement = try connection.prepare(
            "SELECT placement FROM daemon_sessions WHERE id = $1",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        const session_params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var session_cursor = try connection.execute(session_statement, &session_params, null);
        const session_row = (try session_cursor.next()) orelse {
            try session_cursor.finish();
            return error.InvalidHostLease;
        };
        const session_placement = session_row.get(0) orelse {
            try session_cursor.finish();
            return error.UnexpectedResult;
        };
        const placement_matches = std.mem.eql(u8, session_placement, @tagName(placement)) or
            (placement == .client and std.mem.eql(u8, session_placement, "client_busy"));
        try session_cursor.finish();
        if (!placement_matches) return error.InvalidHostLease;

        var generation: u64 = 1;
        const host_statement = try connection.prepare(
            "SELECT placement, host_id, CAST(lease_generation AS TEXT), CAST(lease_expires_ms AS TEXT) " ++
                "FROM session_hosts WHERE session_id = $1",
            &[_]quarry.TypeId{self.text_type},
            null,
        );
        var host_cursor = try connection.execute(host_statement, &session_params, null);
        if (try host_cursor.next()) |host_row| {
            const had_placement = host_row.get(0) orelse {
                try host_cursor.finish();
                return error.UnexpectedResult;
            };
            const host_placement_matches = std.mem.eql(u8, had_placement, @tagName(placement));
            const had_host = host_row.get(1) orelse {
                try host_cursor.finish();
                return error.UnexpectedResult;
            };
            const same_host = std.mem.eql(u8, had_host, host_id);
            const generation_text = host_row.get(2) orelse {
                try host_cursor.finish();
                return error.UnexpectedResult;
            };
            const had_generation = std.fmt.parseInt(u64, generation_text, 10) catch {
                try host_cursor.finish();
                return error.UnexpectedResult;
            };
            const expiration = if (host_row.get(3)) |text|
                std.fmt.parseInt(i64, text, 10) catch {
                    try host_cursor.finish();
                    return error.UnexpectedResult;
                }
            else
                0;
            if (!host_placement_matches) {
                try host_cursor.finish();
                return error.InvalidHostLease;
            }
            if (expiration > now_ms and !same_host) {
                try host_cursor.finish();
                return error.SessionLeaseHeld;
            }
            generation = if (expiration > now_ms) had_generation else std.math.add(u64, had_generation, 1) catch {
                try host_cursor.finish();
                return error.InvalidHostLease;
            };
        }
        try host_cursor.finish();

        var expires_buffer: [24]u8 = undefined;
        var generation_buffer: [24]u8 = undefined;
        var now_buffer: [24]u8 = undefined;
        const expires_text = std.fmt.bufPrint(&expires_buffer, "{d}", .{expires_ms}) catch unreachable;
        const generation_text = std.fmt.bufPrint(&generation_buffer, "{d}", .{generation}) catch unreachable;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const upsert_types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.int_type, self.int_type, self.int_type };
        const upsert = try connection.prepare(
            "INSERT INTO session_hosts (session_id, placement, host_id, lease_generation, lease_expires_ms) " ++
                "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_id) DO UPDATE SET " ++
                "placement = $2, host_id = $3, lease_generation = $4, lease_expires_ms = $5 " ++
                "WHERE session_hosts.host_id = $3 OR session_hosts.lease_expires_ms <= $6",
            &upsert_types,
            null,
        );
        const upsert_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, @tagName(placement)),
            textParam(self.text_type, host_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = generation_text },
            .{ .type_id = self.int_type, .format = .text, .bytes = expires_text },
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var upsert_cursor = try connection.execute(upsert, &upsert_params, null);
        try upsert_cursor.finish();
        if ((upsert_cursor.rowsAffected() orelse return error.UnexpectedResult) != 1)
            return error.SessionLeaseHeld;
        try connection.commit();
        return .{ .generation = generation, .expires_ms = expires_ms };
    }

    /// Release only the lease still held by this host generation. A stale host
    /// cannot release a replacement's lease.
    pub fn releaseSessionHost(
        self: *Database,
        session_id: []const u8,
        actor_identity_id: []const u8,
        host_id: []const u8,
        generation: u64,
        now_ms: i64,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        if (session_id.len == 0 or session_id.len > 128 or !isUuid(actor_identity_id) or !isUuid(host_id)) return false;
        var now_buffer: [24]u8 = undefined;
        var generation_buffer: [24]u8 = undefined;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const generation_text = std.fmt.bufPrint(&generation_buffer, "{d}", .{generation}) catch unreachable;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.int_type, self.text_type, self.text_type, self.int_type, self.text_type };
        const statement = try connection.prepare(
            "UPDATE session_hosts SET lease_expires_ms = $1 WHERE session_id = $2 AND host_id = $3 " ++
                "AND lease_generation = $4 AND lease_expires_ms > $1 AND EXISTS (" ++
                "SELECT 1 FROM session_members WHERE session_id = $2 AND identity_id = $5 AND role = 'owner')",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
            textParam(self.text_type, session_id),
            textParam(self.text_type, host_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = generation_text },
            textParam(self.text_type, actor_identity_id),
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
        return (cursor.rowsAffected() orelse return error.UnexpectedResult) == 1;
    }

    /// Check the fencing token on every worker request. A claimed UUID alone
    /// is not proof of ownership: replacement workers carry a larger
    /// generation, and expired generations stop authorizing writes.
    pub fn sessionHostMatches(
        self: *Database,
        session_id: []const u8,
        actor_identity_id: []const u8,
        placement: SessionPlacement,
        host_id: []const u8,
        generation: u64,
        now_ms: i64,
    ) (quarry.Error || error{UnexpectedResult})!bool {
        if (session_id.len == 0 or session_id.len > 128 or
            !isUuid(actor_identity_id) or !isUuid(host_id) or generation == 0) return false;
        var generation_buffer: [24]u8 = undefined;
        var now_buffer: [24]u8 = undefined;
        const generation_text = std.fmt.bufPrint(&generation_buffer, "{d}", .{generation}) catch unreachable;
        const now_text = std.fmt.bufPrint(&now_buffer, "{d}", .{now_ms}) catch unreachable;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type, self.text_type, self.text_type, self.int_type, self.int_type };
        const statement = try connection.prepare(
            "SELECT sh.session_id FROM session_hosts sh " ++
                "JOIN daemon_sessions ds ON ds.id = sh.session_id " ++
                "JOIN session_members sm ON sm.session_id = sh.session_id " ++
                "WHERE sh.session_id = $1 AND sm.identity_id = $2 AND sm.role = 'owner' " ++
                "AND sh.placement = $3 AND (ds.placement = $3 OR (ds.placement = 'client_busy' AND $3 = 'client')) AND sh.host_id = $4 " ++
                "AND sh.lease_generation = $5 AND sh.lease_expires_ms > $6",
            &types,
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, actor_identity_id),
            textParam(self.text_type, @tagName(placement)),
            textParam(self.text_type, host_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = generation_text },
            .{ .type_id = self.int_type, .format = .text, .bytes = now_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        const matched = (try cursor.next()) != null;
        try cursor.finish();
        return matched;
    }

    /// Share a registered session with another authenticated identity. Only
    /// an owner can add or change a member; an existing owner cannot be
    /// replaced or downgraded by this operation.
    pub fn setSessionMember(
        self: *Database,
        session_id: []const u8,
        actor_identity_id: []const u8,
        identity_id: []const u8,
        role: MemberRole,
        added_ms: i64,
    ) (quarry.Error || error{ InvalidSession, NotSessionOwner, UnexpectedResult })!void {
        if (session_id.len == 0 or session_id.len > 128 or
            !isUuid(actor_identity_id) or !isUuid(identity_id) or role == .owner)
            return error.InvalidSession;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const owner_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM session_members WHERE session_id = $1 AND identity_id = $2",
            &owner_types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotSessionOwner;
        };
        const actor_role = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const actor_is_owner = std.mem.eql(u8, actor_role, "owner");
        try owner_cursor.finish();
        if (!actor_is_owner) return error.NotSessionOwner;

        const identity_types = [_]quarry.TypeId{self.text_type};
        const identity_statement = try connection.prepare(
            "SELECT id FROM identities WHERE id = $1",
            &identity_types,
            null,
        );
        const identity_params = [_]quarry.Param{textParam(self.text_type, identity_id)};
        var identity_cursor = try connection.execute(identity_statement, &identity_params, null);
        if ((try identity_cursor.next()) == null) {
            try identity_cursor.finish();
            return error.InvalidSession;
        }
        try identity_cursor.finish();

        const member_types = [_]quarry.TypeId{
            self.text_type, self.text_type, self.text_type, self.text_type, self.int_type,
        };
        const member_statement = try connection.prepare(
            "INSERT INTO session_members (session_id, identity_id, role, added_by_identity_id, added_ms) " ++
                "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (session_id, identity_id) DO UPDATE SET " ++
                "role = $3, added_by_identity_id = $4, added_ms = $5 " ++
                "WHERE session_members.role <> 'owner'",
            &member_types,
            null,
        );
        var added_buffer: [24]u8 = undefined;
        const added_text = std.fmt.bufPrint(&added_buffer, "{d}", .{added_ms}) catch unreachable;
        const member_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, identity_id),
            textParam(self.text_type, @tagName(role)),
            textParam(self.text_type, actor_identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = added_text },
        };
        var member_cursor = try connection.execute(member_statement, &member_params, null);
        try member_cursor.finish();
        const affected = member_cursor.rowsAffected() orelse return error.UnexpectedResult;
        if (affected != 1) return error.InvalidSession;
        try connection.commit();
    }

    /// Revoke a session role without changing independent ACL rules. The
    /// owner membership is immutable, and only an owner may remove members.
    pub fn removeSessionMember(
        self: *Database,
        session_id: []const u8,
        actor_identity_id: []const u8,
        identity_id: []const u8,
    ) (quarry.Error || error{ InvalidSession, NotSessionOwner, UnexpectedResult })!void {
        if (session_id.len == 0 or session_id.len > 128 or
            !isUuid(actor_identity_id) or !isUuid(identity_id)) return error.InvalidSession;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        try connection.begin(.read_committed);
        errdefer connection.rollback() catch {};

        const owner_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM session_members WHERE session_id = $1 AND identity_id = $2",
            &owner_types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotSessionOwner;
        };
        const actor_role = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const actor_is_owner = std.mem.eql(u8, actor_role, "owner");
        try owner_cursor.finish();
        if (!actor_is_owner) return error.NotSessionOwner;

        const remove_statement = try connection.prepare(
            "DELETE FROM session_members WHERE session_id = $1 AND identity_id = $2 AND role <> 'owner'",
            &owner_types,
            null,
        );
        const remove_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, identity_id),
        };
        var removed = try connection.execute(remove_statement, &remove_params, null);
        try removed.finish();
        try connection.commit();
    }

    pub fn listSessionMembers(
        self: *Database,
        arena: std.mem.Allocator,
        session_id: []const u8,
    ) (quarry.Error || error{ InvalidSession, UnexpectedResult })![]const SessionMember {
        if (session_id.len == 0 or session_id.len > 128) return error.InvalidSession;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT identity_id, role FROM session_members WHERE session_id = $1 ORDER BY added_ms, identity_id",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var members: std.ArrayList(SessionMember) = .empty;
        while (try cursor.next()) |row| {
            const identity_id = row.get(0) orelse return error.UnexpectedResult;
            const role_text = row.get(1) orelse return error.UnexpectedResult;
            const role = std.meta.stringToEnum(MemberRole, role_text) orelse return error.UnexpectedResult;
            try members.append(arena, .{ .identity_id = try arena.dupe(u8, identity_id), .role = role });
        }
        try cursor.finish();
        return members.items;
    }

    /// Return the people directory only to a session owner. It includes the
    /// current role (if any) so a UI can offer add/change actions without
    /// exposing the daemon-wide identity directory to unrelated users.
    pub fn listSessionPeople(
        self: *Database,
        arena: std.mem.Allocator,
        session_id: []const u8,
        actor_identity_id: []const u8,
    ) (quarry.Error || error{ InvalidSession, NotSessionOwner, UnexpectedResult })![]const SessionPerson {
        if (session_id.len == 0 or session_id.len > 128 or !isUuid(actor_identity_id))
            return error.InvalidSession;
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const owner_types = [_]quarry.TypeId{ self.text_type, self.text_type };
        const owner_statement = try connection.prepare(
            "SELECT role FROM session_members WHERE session_id = $1 AND identity_id = $2",
            &owner_types,
            null,
        );
        const owner_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, actor_identity_id),
        };
        var owner_cursor = try connection.execute(owner_statement, &owner_params, null);
        const owner_row = (try owner_cursor.next()) orelse {
            try owner_cursor.finish();
            return error.NotSessionOwner;
        };
        const role_text = owner_row.get(0) orelse {
            try owner_cursor.finish();
            return error.UnexpectedResult;
        };
        const is_owner = std.mem.eql(u8, role_text, "owner");
        try owner_cursor.finish();
        if (!is_owner) return error.NotSessionOwner;

        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT i.id, i.display_name, i.email, sm.role FROM identities i " ++
                "LEFT JOIN session_members sm ON sm.identity_id = i.id AND sm.session_id = $1 " ++
                "ORDER BY i.display_name, i.id",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, session_id)};
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var people: std.ArrayList(SessionPerson) = .empty;
        while (try cursor.next()) |row| {
            const identity_id = row.get(0) orelse return error.UnexpectedResult;
            const role_text_opt = row.get(3);
            const role = if (role_text_opt) |text|
                std.meta.stringToEnum(MemberRole, text) orelse return error.UnexpectedResult
            else
                null;
            try people.append(arena, .{
                .identity_id = try arena.dupe(u8, identity_id),
                .display_name = try arena.dupe(u8, row.get(1) orelse ""),
                .email = try arena.dupe(u8, row.get(2) orelse ""),
                .role = role,
            });
        }
        try cursor.finish();
        return people.items;
    }

    /// Refresh a viewer's short-lived presence lease. Presence is ephemeral
    /// coordination metadata, not part of the durable transcript or audit log.
    pub fn touchSessionPresence(
        self: *Database,
        session_id: []const u8,
        identity_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidAclState, InvalidSession, NotSessionViewer, UnexpectedResult })!void {
        if (session_id.len == 0 or session_id.len > 128 or !isUuid(identity_id)) return error.InvalidSession;
        if (!try self.authorizeSession(identity_id, session_id, .session_view)) return error.NotSessionViewer;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{ self.text_type, self.text_type, self.int_type };
        const statement = try connection.prepare(
            "INSERT INTO session_presence (session_id, identity_id, last_seen_ms) VALUES ($1, $2, $3) " ++
                "ON CONFLICT (session_id, identity_id) DO UPDATE SET last_seen_ms = excluded.last_seen_ms",
            &types,
            null,
        );
        var timestamp: [24]u8 = undefined;
        const timestamp_text = std.fmt.bufPrint(&timestamp, "{d}", .{now_ms}) catch unreachable;
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            textParam(self.text_type, identity_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = timestamp_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        try cursor.finish();
    }

    /// List active collaborators only to people who can view the session. A
    /// lazy prune bounds stale rows without turning presence into retained
    /// history.
    pub fn listSessionPresence(
        self: *Database,
        arena: std.mem.Allocator,
        session_id: []const u8,
        actor_identity_id: []const u8,
        now_ms: i64,
    ) (quarry.Error || error{ InvalidAclState, InvalidSession, NotSessionViewer, UnexpectedResult })![]const SessionPresence {
        if (session_id.len == 0 or session_id.len > 128 or !isUuid(actor_identity_id)) return error.InvalidSession;
        if (!try self.authorizeSession(actor_identity_id, session_id, .session_view)) return error.NotSessionViewer;
        const cutoff = if (now_ms < std.math.minInt(i64) + session_presence_ttl_ms)
            std.math.minInt(i64)
        else
            now_ms - session_presence_ttl_ms;

        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const delete = try connection.prepare(
            "DELETE FROM session_presence WHERE session_id = $1 AND last_seen_ms <= $2",
            &.{ self.text_type, self.int_type },
            null,
        );
        var cutoff_buffer: [24]u8 = undefined;
        const cutoff_text = std.fmt.bufPrint(&cutoff_buffer, "{d}", .{cutoff}) catch unreachable;
        const delete_params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = cutoff_text },
        };
        var delete_cursor = try connection.execute(delete, &delete_params, null);
        try delete_cursor.finish();

        const statement = try connection.prepare(
            "SELECT p.identity_id, i.display_name, p.last_seen_ms FROM session_presence p " ++
                "JOIN identities i ON i.id = p.identity_id WHERE p.session_id = $1 AND p.last_seen_ms > $2 " ++
                "ORDER BY i.display_name, p.identity_id",
            &.{ self.text_type, self.int_type },
            null,
        );
        const params = [_]quarry.Param{
            textParam(self.text_type, session_id),
            .{ .type_id = self.int_type, .format = .text, .bytes = cutoff_text },
        };
        var cursor = try connection.execute(statement, &params, null);
        defer cursor.finish() catch {};
        var people: std.ArrayList(SessionPresence) = .empty;
        while (try cursor.next()) |row| {
            try people.append(arena, .{
                .identity_id = try arena.dupe(u8, row.get(0) orelse return error.UnexpectedResult),
                .display_name = try arena.dupe(u8, row.get(1) orelse ""),
                .last_seen_ms = integerColumn(row, 2) orelse return error.UnexpectedResult,
            });
        }
        try cursor.finish();
        return people.items;
    }

    fn projectIdForRoot(self: *Database, root: []const u8) (quarry.Error || error{UnexpectedResult})!?[36]u8 {
        const connection = try self.pool.acquire();
        defer self.pool.release(connection);
        const types = [_]quarry.TypeId{self.text_type};
        const statement = try connection.prepare(
            "SELECT id FROM daemon_projects WHERE execution_root = $1 ORDER BY id LIMIT 1",
            &types,
            null,
        );
        const params = [_]quarry.Param{textParam(self.text_type, root)};
        var cursor = try connection.execute(statement, &params, null);
        const row = (try cursor.next()) orelse {
            try cursor.finish();
            return null;
        };
        const id_text = row.get(0) orelse {
            try cursor.finish();
            return error.UnexpectedResult;
        };
        if (!isUuid(id_text)) {
            try cursor.finish();
            return error.UnexpectedResult;
        }
        var id: [36]u8 = undefined;
        @memcpy(&id, id_text);
        try cursor.finish();
        return id;
    }
};

fn textParam(type_id: quarry.TypeId, bytes: []const u8) quarry.Param {
    return .{ .type_id = type_id, .format = .text, .bytes = bytes };
}

/// Quarry preserves each driver's row format. Integers from embedded SQLite
/// and PostgreSQL binary results are signed big-endian bytes, 8 bytes for
/// int8 and 4 or 2 for an int4 or int2 expression such as a bare CASE.
/// Text-protocol drivers return decimal digits.
fn integerColumn(row: quarry.Row, index: usize) ?i64 {
    const bytes = row.get(index) orelse return null;
    if (row.formats[index] == .binary) return switch (bytes.len) {
        8 => std.mem.readInt(i64, bytes[0..8], .big),
        4 => std.mem.readInt(i32, bytes[0..4], .big),
        2 => std.mem.readInt(i16, bytes[0..2], .big),
        else => null,
    };
    return std.fmt.parseInt(i64, bytes, 10) catch null;
}

test "database integer decoding accepts binary and text Quarry rows" {
    var binary_value: [8]u8 = undefined;
    std.mem.writeInt(i64, &binary_value, -42, .big);
    const binary_columns = [_]?[]const u8{&binary_value};
    const binary_types = [_]quarry.TypeId{quarry.sqlite.type_id.integer};
    const binary_formats = [_]quarry.Format{.binary};
    const binary_row: quarry.Row = .{
        .columns = &binary_columns,
        .types = &binary_types,
        .formats = &binary_formats,
    };
    try std.testing.expectEqual(@as(?i64, -42), integerColumn(binary_row, 0));

    const text_columns = [_]?[]const u8{"100"};
    const text_types = [_]quarry.TypeId{quarry.postgres.oid.int8};
    const text_formats = [_]quarry.Format{.text};
    const text_row: quarry.Row = .{
        .columns = &text_columns,
        .types = &text_types,
        .formats = &text_formats,
    };
    try std.testing.expectEqual(@as(?i64, 100), integerColumn(text_row, 0));
}

test "database integer decoding accepts a four byte PostgreSQL int4" {
    var one: [4]u8 = undefined;
    std.mem.writeInt(i32, &one, 1, .big);
    var negative: [4]u8 = undefined;
    std.mem.writeInt(i32, &negative, -7, .big);
    const columns = [_]?[]const u8{ &one, &negative, "abc" };
    const types = [_]quarry.TypeId{ quarry.postgres.oid.integer, quarry.postgres.oid.integer, quarry.postgres.oid.integer };
    const formats = [_]quarry.Format{ .binary, .binary, .binary };
    const row: quarry.Row = .{ .columns = &columns, .types = &types, .formats = &formats };
    try std.testing.expectEqual(@as(?i64, 1), integerColumn(row, 0));
    try std.testing.expectEqual(@as(?i64, -7), integerColumn(row, 1));
    try std.testing.expectEqual(@as(?i64, null), integerColumn(row, 2));
}

fn requireTeamOwner(
    connection: *quarry.Connection,
    text_type: quarry.TypeId,
    actor_identity_id: []const u8,
    team_id: []const u8,
) (quarry.Error || error{ NotTeamOwner, UnexpectedResult })!void {
    const types = [_]quarry.TypeId{ text_type, text_type };
    const statement = try connection.prepare(
        "SELECT role FROM team_members WHERE team_id = $1 AND identity_id = $2",
        &types,
        null,
    );
    const params = [_]quarry.Param{
        textParam(text_type, team_id),
        textParam(text_type, actor_identity_id),
    };
    var cursor = try connection.execute(statement, &params, null);
    const row = (try cursor.next()) orelse {
        try cursor.finish();
        return error.NotTeamOwner;
    };
    const role = row.get(0) orelse {
        try cursor.finish();
        return error.UnexpectedResult;
    };
    const owner = std.mem.eql(u8, role, "owner");
    try cursor.finish();
    if (!owner) return error.NotTeamOwner;
}

fn nullableTextParam(type_id: quarry.TypeId, bytes: ?[]const u8) quarry.Param {
    return .{ .type_id = type_id, .format = .text, .bytes = bytes };
}

const ParameterTypes = struct { text: quarry.TypeId, int: quarry.TypeId };

fn databaseParameterTypes(url: []const u8) ?ParameterTypes {
    if (std.mem.startsWith(u8, url, "sqlite:")) return .{ .text = quarry.sqlite.type_id.text, .int = quarry.sqlite.type_id.integer };
    if (std.mem.startsWith(u8, url, "postgres:") or std.mem.startsWith(u8, url, "postgresql:"))
        return .{ .text = quarry.postgres.oid.text, .int = quarry.postgres.oid.int8 };
    return null;
}

fn randomUuid(io: std.Io) std.Io.RandomSecureError![36]u8 {
    var raw: [16]u8 = undefined;
    try io.randomSecure(&raw);
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    return uuidText(raw);
}

/// A stable RFC 9562 version-8 UUID names an ACL slot, so replacing a rule is
/// one primary-key upsert even when two database connections race.
fn aclRuleId(rule: Rule) [36]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for ([_][]const u8{
        rule.resource_kind,
        rule.resource_id,
        @tagName(rule.principal_kind),
        rule.principal_id,
        @tagName(rule.capability),
    }) |part| {
        hasher.update(part);
        hasher.update(&.{0});
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var bytes: [16]u8 = digest[0..16].*;
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return uuidText(bytes);
}

fn uuidText(raw: [16]u8) [36]u8 {
    const hex = "0123456789abcdef";
    var result: [36]u8 = undefined;
    var at: usize = 0;
    for (raw, 0..) |byte, index| {
        if (index == 4 or index == 6 or index == 8 or index == 10) {
            result[at] = '-';
            at += 1;
        }
        result[at] = hex[byte >> 4];
        result[at + 1] = hex[byte & 0x0f];
        at += 2;
    }
    return result;
}

pub fn isUuid(value: []const u8) bool {
    if (value.len != 36) return false;
    for (value, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return false;
        } else if (!std.ascii.isHex(byte)) return false;
    }
    return true;
}

fn validSessionToken(value: []const u8) bool {
    if (value.len != 43) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return false;
    }
    return true;
}

fn hexDigest(digest: [32]u8) [64]u8 {
    const hex = "0123456789abcdef";
    var result: [64]u8 = undefined;
    for (digest, 0..) |byte, index| {
        result[index * 2] = hex[byte >> 4];
        result[index * 2 + 1] = hex[byte & 0x0f];
    }
    return result;
}

/// The base schema is intentionally portable across SQLite and PostgreSQL. A
/// personal daemon defaults to an embedded SQLite URL; a hosted deployment can
/// use PostgreSQL without changing repository code or its parameter binding.
pub const schema_v1 = [_][]const u8{
    \\CREATE TABLE IF NOT EXISTS chock_schema (
    \\  version BIGINT NOT NULL PRIMARY KEY,
    \\  applied_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS identities (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  issuer TEXT NOT NULL,
    \\  subject TEXT NOT NULL,
    \\  email TEXT,
    \\  display_name TEXT,
    \\  instance_role TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL,
    \\  UNIQUE (issuer, subject)
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS auth_sessions (
    \\  token_hash TEXT NOT NULL PRIMARY KEY,
    \\  identity_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL,
    \\  expires_ms BIGINT NOT NULL,
    \\  revoked_ms BIGINT
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS service_config (
    \\  id BIGINT NOT NULL PRIMARY KEY,
    \\  auth_mode TEXT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS local_auth_users (
    \\  identity_id TEXT NOT NULL PRIMARY KEY,
    \\  username TEXT NOT NULL UNIQUE,
    \\  password_hash TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL,
    \\  disabled_ms BIGINT
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS teams (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  name TEXT NOT NULL,
    \\  created_by_identity_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS team_members (
    \\  team_id TEXT NOT NULL,
    \\  identity_id TEXT NOT NULL,
    \\  role TEXT NOT NULL,
    \\  added_ms BIGINT NOT NULL,
    \\  PRIMARY KEY (team_id, identity_id)
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS team_invitations (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  token_hash TEXT NOT NULL UNIQUE,
    \\  team_id TEXT NOT NULL,
    \\  role TEXT NOT NULL,
    \\  created_by_identity_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL,
    \\  expires_ms BIGINT NOT NULL,
    \\  revoked_ms BIGINT,
    \\  redeemed_by_identity_id TEXT,
    \\  redeemed_ms BIGINT
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS daemon_projects (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  owner_identity_id TEXT NOT NULL,
    \\  name TEXT NOT NULL,
    \\  source_kind TEXT NOT NULL,
    \\  source_locator TEXT NOT NULL,
    \\  status TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE UNIQUE INDEX IF NOT EXISTS daemon_projects_locator
    \\  ON daemon_projects(source_kind, source_locator)
    ,
    \\CREATE TABLE IF NOT EXISTS llm_providers (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  name TEXT NOT NULL,
    \\  provider_kind TEXT NOT NULL,
    \\  scope_kind TEXT NOT NULL,
    \\  scope_id TEXT,
    \\  configuration TEXT NOT NULL,
    \\  credential_ref TEXT NOT NULL,
    \\  created_by_identity_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS acl_rules (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  resource_kind TEXT NOT NULL,
    \\  resource_id TEXT NOT NULL,
    \\  principal_kind TEXT NOT NULL,
    \\  principal_id TEXT,
    \\  capability TEXT NOT NULL,
    \\  effect TEXT NOT NULL,
    \\  created_by_identity_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS daemon_sessions (
    \\  id TEXT NOT NULL PRIMARY KEY,
    \\  owner_identity_id TEXT NOT NULL,
    \\  placement TEXT NOT NULL,
    \\  project_id TEXT NOT NULL,
    \\  created_ms BIGINT NOT NULL
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS session_members (
    \\  session_id TEXT NOT NULL,
    \\  identity_id TEXT NOT NULL,
    \\  role TEXT NOT NULL,
    \\  added_by_identity_id TEXT NOT NULL,
    \\  added_ms BIGINT NOT NULL,
    \\  PRIMARY KEY (session_id, identity_id)
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS session_presence (
    \\  session_id TEXT NOT NULL,
    \\  identity_id TEXT NOT NULL,
    \\  last_seen_ms BIGINT NOT NULL,
    \\  PRIMARY KEY (session_id, identity_id)
    \\)
    ,
    \\CREATE TABLE IF NOT EXISTS session_hosts (
    \\  session_id TEXT NOT NULL PRIMARY KEY,
    \\  placement TEXT NOT NULL,
    \\  host_id TEXT NOT NULL,
    \\  lease_generation BIGINT NOT NULL,
    \\  lease_expires_ms BIGINT
    \\)
    ,
    \\CREATE INDEX IF NOT EXISTS session_members_identity
    \\  ON session_members(identity_id, session_id)
    ,
    \\CREATE INDEX IF NOT EXISTS session_presence_expiry
    \\  ON session_presence(last_seen_ms)
    ,
    \\CREATE INDEX IF NOT EXISTS team_members_identity
    \\  ON team_members(identity_id, team_id)
    ,
    \\CREATE INDEX IF NOT EXISTS llm_providers_scope
    \\  ON llm_providers(scope_kind, scope_id)
    ,
    \\CREATE INDEX IF NOT EXISTS acl_rules_resource
    \\  ON acl_rules(resource_kind, resource_id, capability)
    ,
};

pub fn initialize(conn: *quarry.Connection, applied_ms: i64) quarry.Error!void {
    try conn.begin(.read_committed);
    errdefer conn.rollback() catch {};
    for (schema_v1) |statement| {
        var cursor = try conn.exec(statement, null);
        try cursor.finish();
    }
    var version_cursor = try conn.exec("SELECT version FROM chock_schema WHERE version = 2", null);
    const migration_needed = (try version_cursor.next()) == null;
    try version_cursor.finish();
    if (migration_needed) {
        var alter = try conn.exec("ALTER TABLE daemon_projects ADD COLUMN execution_root TEXT NOT NULL DEFAULT ''", null);
        try alter.finish();
        var backfill = try conn.exec("UPDATE daemon_projects SET execution_root = source_locator WHERE execution_root = ''", null);
        try backfill.finish();
        var applied_v2_buffer: [256]u8 = undefined;
        const insert_v2_sql = std.fmt.bufPrint(
            &applied_v2_buffer,
            "INSERT INTO chock_schema(version, applied_ms) SELECT 2, {d} WHERE NOT EXISTS (SELECT 1 FROM chock_schema WHERE version = 2)",
            .{applied_ms},
        ) catch unreachable;
        var insert_v2 = try conn.exec(insert_v2_sql, null);
        try insert_v2.finish();
    }
    var worker_scope_cursor = try conn.exec("SELECT version FROM chock_schema WHERE version = 3", null);
    const worker_scope_migration_needed = (try worker_scope_cursor.next()) == null;
    try worker_scope_cursor.finish();
    if (worker_scope_migration_needed) {
        var alter_sessions = try conn.exec("ALTER TABLE auth_sessions ADD COLUMN worker_session_id TEXT", null);
        try alter_sessions.finish();
        var applied_v3_buffer: [256]u8 = undefined;
        const insert_v3_sql = std.fmt.bufPrint(
            &applied_v3_buffer,
            "INSERT INTO chock_schema(version, applied_ms) SELECT 3, {d} WHERE NOT EXISTS (SELECT 1 FROM chock_schema WHERE version = 3)",
            .{applied_ms},
        ) catch unreachable;
        var insert_v3 = try conn.exec(insert_v3_sql, null);
        try insert_v3.finish();
    }
    var invitation_cursor = try conn.exec("SELECT version FROM chock_schema WHERE version = 4", null);
    const invitation_migration_needed = (try invitation_cursor.next()) == null;
    try invitation_cursor.finish();
    if (invitation_migration_needed) {
        var applied_v4_buffer: [256]u8 = undefined;
        const insert_v4_sql = std.fmt.bufPrint(
            &applied_v4_buffer,
            "INSERT INTO chock_schema(version, applied_ms) SELECT 4, {d} WHERE NOT EXISTS (SELECT 1 FROM chock_schema WHERE version = 4)",
            .{applied_ms},
        ) catch unreachable;
        var insert_v4 = try conn.exec(insert_v4_sql, null);
        try insert_v4.finish();
    }
    var local_accounts_cursor = try conn.exec("SELECT version FROM chock_schema WHERE version = 5", null);
    const local_accounts_migration_needed = (try local_accounts_cursor.next()) == null;
    try local_accounts_cursor.finish();
    if (local_accounts_migration_needed) {
        var applied_v5_buffer: [256]u8 = undefined;
        const insert_v5_sql = std.fmt.bufPrint(
            &applied_v5_buffer,
            "INSERT INTO chock_schema(version, applied_ms) SELECT 5, {d} WHERE NOT EXISTS (SELECT 1 FROM chock_schema WHERE version = 5)",
            .{applied_ms},
        ) catch unreachable;
        var insert_v5 = try conn.exec(insert_v5_sql, null);
        try insert_v5.finish();
    }
    // Type identifiers belong to a driver (a PostgreSQL OID is not a SQLite
    // type number), while this one migration value is generated here and is
    // not input. Formatting it keeps the DDL driver-neutral without putting a
    // caller-controlled value into SQL.
    var insert_buffer: [256]u8 = undefined;
    const insert_sql = std.fmt.bufPrint(
        &insert_buffer,
        "INSERT INTO chock_schema(version, applied_ms) " ++
            "SELECT 1, {d} WHERE NOT EXISTS (SELECT 1 FROM chock_schema WHERE version = 1)",
        .{applied_ms},
    ) catch unreachable;
    var cursor = try conn.exec(insert_sql, null);
    try cursor.finish();
    try conn.commit();
}

test "OIDC issuer and discovery configuration requires safe HTTPS URLs" {
    try (Oidc{ .provider = .kanidm, .issuer = "https://id.example", .client_id = "chock" }).validate();
    try std.testing.expectError(error.InvalidOidcConfiguration, (Oidc{
        .provider = .authentik,
        .issuer = "http://id.example",
        .client_id = "chock",
    }).validate());
    for ([_][]const u8{
        "http://localhost:9091",
        "http://[::1]:9091",
        "http://localhost.attacker.example",
        "http://127.0.0.1.attacker.example",
        "http://localhost@attacker.example",
        "https://user@id.example",
        "https://",
        "https://bad_host.example",
        "https://id..example",
        "https://id.example?tenant=one",
        "https://id.example#fragment",
    }) |issuer| {
        try std.testing.expectError(error.InvalidOidcConfiguration, (Oidc{
            .provider = .kanidm,
            .issuer = issuer,
            .client_id = "chock",
        }).validate());
    }
    try std.testing.expectError(error.InvalidOidcConfiguration, (Oidc{
        .provider = .authentik,
        .issuer = "https://id.example",
        .client_id = "chock",
        .discovery_url = "http://localhost:9091/.well-known/openid-configuration",
    }).validate());
}

test "Authentik application discovery stays bound to the configured issuer" {
    const config: Oidc = .{
        .provider = .authentik,
        .issuer = "https://auth.example/application/o/chock/",
        .client_id = "chock-client",
        .discovery_url = "https://auth.example/application/o/chock/.well-known/openid-configuration",
    };
    const metadata_json =
        \\{"issuer":"https://auth.example/application/o/chock/","authorization_endpoint":"https://auth.example/application/o/authorize/",
        \\"token_endpoint":"https://auth.example/application/o/token/","jwks_uri":"https://auth.example/application/o/chock/jwks/",
        \\"code_challenge_methods_supported":["S256"]}
    ;
    const other_issuer_metadata =
        \\{"issuer":"https://auth.example/application/o/other/","authorization_endpoint":"https://auth.example/application/o/authorize/",
        \\"token_endpoint":"https://auth.example/application/o/token/","jwks_uri":"https://auth.example/application/o/chock/jwks/",
        \\"code_challenge_methods_supported":["S256"]}
    ;
    var fake = oauth.testing.FakeTransport.init(std.testing.allocator, &.{
        .{ .body = metadata_json },
        .{ .body = other_issuer_metadata },
    });
    defer fake.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const metadata = try config.discover(arena.allocator(), fake.transport());
    try std.testing.expectEqualStrings(config.issuer, metadata.issuer);
    try std.testing.expectEqualStrings(config.discovery_url.?, fake.sent.items[0].url);
    try std.testing.expectEqualStrings("S256", metadata.code_challenge_methods_supported[0]);
    try std.testing.expectError(error.IssuerMismatch, config.discover(arena.allocator(), fake.transport()));
}

test "external web base URLs are safe OAuth redirect targets" {
    try std.testing.expect(isSecureWebBaseUrl("https://chock.example"));
    try std.testing.expect(isSecureWebBaseUrl("https://chock.example/service/"));
    try std.testing.expect(isSecureWebBaseUrl("http://localhost:7374"));
    try std.testing.expect(isSecureWebBaseUrl("http://[::1]:7374"));
    for ([_][]const u8{
        "https://",
        "https://0.0.0.0:7474",
        "https://[::]:7474",
        "https://user@chock.example",
        "https://chock.example?redirect=http://evil.example",
        "https://chock.example/#fragment",
        "http://127.0.0.1.attacker.example",
        "http://chock.example",
        "http://localhost@attacker.example",
    }) |value| try std.testing.expect(!isSecureWebBaseUrl(value));
    try std.testing.expect(isWebBaseUrl("http://chock.example", true));
    try std.testing.expect(isWebBaseUrl("http://192.0.2.10:7374/chock", true));
    try std.testing.expect(!isWebBaseUrl("http://0.0.0.0:7374", true));
    try std.testing.expect(!isWebBaseUrl("http://[::]:7374", true));
    try std.testing.expect(!isWebBaseUrl("http://user@chock.example", true));
}

test "OIDC authorization URLs use PKCE, nonce, and provider metadata" {
    const config: Oidc = .{ .provider = .kanidm, .issuer = "https://id.example", .client_id = "chock", .client_secret = "s3cret" };
    const metadata: oauth.oidc.Metadata = .{
        .issuer = config.issuer,
        .authorization_endpoint = "https://id.example/authorize",
        .token_endpoint = "https://id.example/token",
        .jwks_uri = "https://id.example/jwks",
        .code_challenge_methods_supported = &.{"S256"},
    };
    var attempt = oauth.Attempt.init(std.testing.io);
    defer attempt.wipe();
    const url = try oidcAuthorizationUrl(config, std.testing.allocator, metadata, &attempt, "https://chock.example/auth/callback");
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.indexOf(u8, url, "response_type=code") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "&nonce=") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=openid%20profile%20email") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "s3cret") == null);

    const wrong_issuer = metadata;
    var bad_attempt = oauth.Attempt.init(std.testing.io);
    defer bad_attempt.wipe();
    try std.testing.expectError(error.InvalidOidcConfiguration, oidcAuthorizationUrl(config, std.testing.allocator, .{
        .issuer = "https://other.example",
        .authorization_endpoint = wrong_issuer.authorization_endpoint,
        .token_endpoint = wrong_issuer.token_endpoint,
        .jwks_uri = wrong_issuer.jwks_uri,
    }, &bad_attempt, "https://chock.example/auth/callback"));
}

test "OIDC exchange and ID-token verification route through oauth transport" {
    const config: Oidc = .{ .provider = .authelia, .issuer = "https://id.example", .client_id = "chock", .client_secret = "s3cret" };
    const metadata: oauth.oidc.Metadata = .{
        .issuer = config.issuer,
        .authorization_endpoint = "https://id.example/authorize",
        .token_endpoint = "https://id.example/token",
        .jwks_uri = "https://id.example/jwks",
    };
    var attempt = oauth.Attempt.init(std.testing.io);
    defer attempt.wipe();

    var exchange_transport = oauth.testing.FakeTransport.init(std.testing.allocator, &.{.{ .status = 500 }});
    defer exchange_transport.deinit();
    try std.testing.expectError(error.ServerRefused, oidcExchangeCode(
        config,
        std.testing.allocator,
        exchange_transport.transport(),
        metadata,
        "authorization-code",
        &attempt,
        "https://chock.example/auth/callback",
    ));
    try std.testing.expectEqualStrings("https://id.example/token", exchange_transport.sent.items[0].url);
    try std.testing.expectEqualStrings("Basic Y2hvY2s6czNjcmV0", exchange_transport.sent.items[0].header("authorization").?);
    try std.testing.expect(std.mem.indexOf(u8, exchange_transport.sent.items[0].body.?, "s3cret") == null);

    var key_transport = oauth.testing.FakeTransport.init(std.testing.allocator, &.{.{ .body = "not-jwks" }});
    defer key_transport.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.MalformedToken, verifyOidcIdToken(
        config,
        arena.allocator(),
        key_transport.transport(),
        metadata,
        "id-token",
        &attempt,
        1,
    ));
    try std.testing.expectEqualStrings("https://id.example/jwks", key_transport.sent.items[0].url);
}

test "daemon schema initializes idempotently in embedded SQLite" {
    var server = try quarry.sqlite.testing.Server.start(std.testing.allocator, std.testing.io, .{});
    defer server.deinit();
    var conn = try quarry.open(std.testing.allocator, std.testing.io, server.url, .{});
    defer conn.close();
    var page_size = try conn.exec("PRAGMA page_size = 8192", null);
    try page_size.finish();
    try initialize(conn, 42);
    try initialize(conn, 43);
    var cursor = try conn.exec("SELECT version, applied_ms FROM chock_schema ORDER BY version", null);
    const v1 = (try cursor.next()).?;
    try std.testing.expectEqual(@as(i64, 1), std.mem.readInt(i64, v1.get(0).?[0..8], .big));
    const v2 = (try cursor.next()).?;
    try std.testing.expectEqual(@as(i64, 2), std.mem.readInt(i64, v2.get(0).?[0..8], .big));
    const v3 = (try cursor.next()).?;
    try std.testing.expectEqual(@as(i64, 3), std.mem.readInt(i64, v3.get(0).?[0..8], .big));
    const v4 = (try cursor.next()).?;
    try std.testing.expectEqual(@as(i64, 4), std.mem.readInt(i64, v4.get(0).?[0..8], .big));
    const v5 = (try cursor.next()).?;
    try std.testing.expectEqual(@as(i64, 5), std.mem.readInt(i64, v5.get(0).?[0..8], .big));
    try std.testing.expect((try cursor.next()) == null);
    try cursor.finish();
}

test "schema migration preserves existing project roots as execution roots" {
    const gpa = std.testing.allocator;
    var server = try quarry.sqlite.testing.Server.start(gpa, std.testing.io, .{});
    defer server.deinit();
    var conn = try quarry.open(gpa, std.testing.io, server.url, .{});
    defer conn.close();
    var schema_cursor = try conn.exec(
        "CREATE TABLE chock_schema (version BIGINT NOT NULL PRIMARY KEY, applied_ms BIGINT NOT NULL)",
        null,
    );
    try schema_cursor.finish();
    var projects_cursor = try conn.exec(
        "CREATE TABLE daemon_projects (id TEXT NOT NULL PRIMARY KEY, owner_identity_id TEXT NOT NULL, name TEXT NOT NULL, source_kind TEXT NOT NULL, source_locator TEXT NOT NULL, status TEXT NOT NULL, created_ms BIGINT NOT NULL)",
        null,
    );
    try projects_cursor.finish();
    var version_cursor = try conn.exec("INSERT INTO chock_schema(version, applied_ms) VALUES (1, 10)", null);
    try version_cursor.finish();
    var old_project = try conn.exec(
        "INSERT INTO daemon_projects (id, owner_identity_id, name, source_kind, source_locator, status, created_ms) " ++
            "VALUES ('00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002', 'Old', 'local', '/old/project', 'ready', 9)",
        null,
    );
    try old_project.finish();

    var page_size = try conn.exec("PRAGMA page_size = 8192", null);
    try page_size.finish();
    try initialize(conn, 20);
    var migrated = try conn.exec(
        "SELECT execution_root FROM daemon_projects WHERE id = '00000000-0000-4000-8000-000000000001'",
        null,
    );
    const row = (try migrated.next()).?;
    try std.testing.expectEqualStrings("/old/project", row.get(0).?);
    try migrated.finish();
}

test "verified identity resolution uses UUIDs and preserves local roles" {
    const gpa = std.testing.allocator;
    var server = try quarry.sqlite.testing.Server.start(gpa, std.testing.io, .{});
    defer server.deinit();
    var environ = std.process.Environ.Map.init(gpa);
    defer environ.deinit();
    var database = try Database.open(gpa, std.testing.io, server.url, &environ, 1);
    defer database.close();
    const pool = database.pool;

    const first = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-1",
        .email = "old@example.test",
        .payload = "{}",
    }, "Old", false, 2);
    defer gpa.free(first.instance_role);
    try std.testing.expect(isUuid(&first.id));
    try std.testing.expectEqualStrings("member", first.instance_role);

    const second = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-1",
        .email = "new@example.test",
        .payload = "{}",
    }, "New", false, 3);
    defer gpa.free(second.instance_role);
    try std.testing.expectEqualStrings(&first.id, &second.id);
    try std.testing.expectEqualStrings("member", second.instance_role);

    const git_project_id = try database.registerGitProject(
        std.testing.io,
        &first.id,
        "Source-backed",
        "https://code.example/team/repository.git",
        "/daemon/projects/01JQ",
        3,
    );
    var project_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer project_arena_state.deinit();
    const listed_projects = try database.listProjects(project_arena_state.allocator());
    try std.testing.expectEqual(@as(usize, 1), listed_projects.len);
    try std.testing.expectEqualStrings(&git_project_id, &listed_projects[0].id);
    try std.testing.expectEqualStrings("/daemon/projects/01JQ", listed_projects[0].root);
    try std.testing.expectEqualStrings("git", listed_projects[0].source_kind);
    try std.testing.expectEqualStrings("https://code.example/team/repository.git", listed_projects[0].source_locator);
    try std.testing.expect(try database.projectAcceptsNewSessions("/daemon/projects/01JQ"));
    try database.registerSession(&first.id, "/daemon/projects/01JQ", "archive-retained-session", .daemon, 3);
    try database.setProjectArchived(&first.id, &git_project_id, true);
    try std.testing.expect(!try database.projectAcceptsNewSessions("/daemon/projects/01JQ"));
    try std.testing.expect(try database.authorizeSession(&first.id, "archive-retained-session", .session_view));
    try std.testing.expectError(error.InvalidSession, database.registerSession(
        &first.id,
        "/daemon/projects/01JQ",
        "archived-session",
        .daemon,
        4,
    ));
    const archived_projects = try database.listProjects(project_arena_state.allocator());
    try std.testing.expectEqualStrings("archived", archived_projects[0].status);
    try database.setProjectArchived(&first.id, &git_project_id, false);
    try std.testing.expect(try database.projectAcceptsNewSessions("/daemon/projects/01JQ"));

    const shared = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-2",
        .email = "shared@example.test",
        .payload = "{}",
    }, "Shared", false, 4);
    defer gpa.free(shared.instance_role);
    try std.testing.expectError(error.NotProjectManager, database.setProjectArchived(&shared.id, &git_project_id, true));
    const invited_identity = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-3",
        .email = "invited@example.test",
        .payload = "{}",
    }, "Invited", false, 4);
    defer gpa.free(invited_identity.instance_role);
    const outside_identity = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-4",
        .email = "outside@example.test",
        .payload = "{}",
    }, "Outside", false, 4);
    defer gpa.free(outside_identity.instance_role);
    const team_id = try database.createTeam(std.testing.io, &second.id, "Reviewers", 5);
    try std.testing.expect(isUuid(&team_id));
    var team_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer team_arena_state.deinit();
    const team_arena = team_arena_state.allocator();
    const owner_teams = try database.listTeams(team_arena, &second.id);
    if (owner_teams.len != 1) return error.OwnerTeamListingCountMismatch;
    try std.testing.expectEqualStrings("Reviewers", owner_teams[0].name);
    try std.testing.expectEqual(TeamRole.owner, owner_teams[0].role);
    try database.setTeamMember(&team_id, &second.id, &shared.id, .member, 6);
    try std.testing.expectError(error.InvalidInvitation, database.createTeamInvitation(
        std.testing.io,
        &second.id,
        &team_id,
        .manager,
        7,
        100,
    ));
    const invitation = try database.createTeamInvitation(
        std.testing.io,
        &second.id,
        &team_id,
        .member,
        7,
        100,
    );
    try std.testing.expectEqual(@as(usize, 43), invitation.token.len);
    const invitation_connection = try pool.acquire();
    var invitation_cursor = try invitation_connection.exec(
        "SELECT team_id, role, expires_ms FROM team_invitations",
        null,
    );
    const invitation_row = (try invitation_cursor.next()).?;
    try std.testing.expectEqualStrings(&team_id, invitation_row.get(0).?);
    try std.testing.expectEqualStrings("member", invitation_row.get(1).?);
    try std.testing.expectEqual(@as(i64, 100), integerColumn(invitation_row, 2).?);
    try invitation_cursor.finish();
    pool.release(invitation_connection);
    try database.redeemTeamInvitation(&invitation.token, &invited_identity.id, 8);
    try std.testing.expectError(
        error.InvitationUnavailable,
        database.redeemTeamInvitation(&invitation.token, &shared.id, 9),
    );
    var invited_teams_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer invited_teams_arena_state.deinit();
    const invited_teams = try database.listTeams(invited_teams_arena_state.allocator(), &invited_identity.id);
    if (invited_teams.len != 1) return error.InvitedTeamListingCountMismatch;
    try std.testing.expectEqual(TeamRole.member, invited_teams[0].role);

    const revoked_invitation = try database.createTeamInvitation(
        std.testing.io,
        &second.id,
        &team_id,
        .member,
        10,
        100,
    );
    try database.revokeTeamInvitation(&second.id, &team_id, &revoked_invitation.id, 11);
    try std.testing.expectError(
        error.InvitationUnavailable,
        database.redeemTeamInvitation(&revoked_invitation.token, &first.id, 12),
    );
    const user_provider_id = try database.createLlmProvider(
        std.testing.io,
        &second.id,
        "Personal",
        "openai",
        .user,
        &second.id,
        "{\"base_url\":\"https://api.openai.com/v1\"}",
        "secret://00000000-0000-4000-8000-000000000123",
        6,
    );
    try std.testing.expect(isUuid(&user_provider_id));
    try std.testing.expectError(error.InvalidProvider, database.createLlmProvider(
        std.testing.io,
        &second.id,
        "Leaky",
        "openai",
        .user,
        &second.id,
        "{\"base_url\":\"https://api.openai.com/v1\"}",
        "sk-live-plaintext-is-not-a-reference",
        6,
    ));
    try std.testing.expectError(error.InvalidProvider, database.createLlmProvider(
        std.testing.io,
        &second.id,
        "Leaky config",
        "openai",
        .user,
        &second.id,
        "{\"base_url\":\"https://api.openai.com/v1\",\"api_key\":\"sk-live-plaintext\"}",
        "env://CHOCK_PROVIDER_KEY",
        6,
    ));
    const team_provider_id = try database.createLlmProvider(
        std.testing.io,
        &second.id,
        "Shared team provider",
        "anthropic",
        .team,
        &team_id,
        "{\"base_url\":\"https://api.anthropic.com/v1\"}",
        "env://CHOCK_TEAM_ANTHROPIC_KEY",
        7,
    );
    var provider_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer provider_arena_state.deinit();
    const shared_providers = database.listLlmProviders(provider_arena_state.allocator(), &shared.id) catch return error.ProviderListingFailed;
    if (shared_providers.len != 1) return error.SharedProviderListingCountMismatch;
    try std.testing.expectEqualStrings(&team_provider_id, &shared_providers[0].id);
    try std.testing.expect(shared_providers[0].has_credential);
    try std.testing.expect(shared_providers[0].is_default);
    const shared_default = (database.defaultLlmProvider(provider_arena_state.allocator(), &shared.id) catch return error.SharedProviderDefaultFailed).?;
    try std.testing.expectEqualStrings(&team_provider_id, &shared_default.id);
    const owner_default = (database.defaultLlmProvider(provider_arena_state.allocator(), &second.id) catch return error.OwnerProviderDefaultFailed).?;
    try std.testing.expectEqualStrings(&user_provider_id, &owner_default.id);
    try std.testing.expectError(error.NotProviderManager, database.removeLlmProvider(&shared.id, &team_provider_id));
    try std.testing.expect(database.removeLlmProvider(&second.id, &team_provider_id) catch return error.TeamProviderRemovalFailed);
    const team_people = database.listTeamPeople(team_arena, &team_id, &second.id) catch return error.TeamPeopleListingFailed;
    try std.testing.expectEqual(@as(usize, 4), team_people.len);
    var saw_shared_team_person = false;
    var saw_outside_team_person = false;
    for (team_people) |person| {
        if (std.mem.eql(u8, person.identity_id, &shared.id)) {
            saw_shared_team_person = true;
            try std.testing.expectEqual(TeamRole.member, person.role.?);
        }
        if (std.mem.eql(u8, person.identity_id, &outside_identity.id)) {
            saw_outside_team_person = true;
            try std.testing.expect(person.role == null);
        }
    }
    try std.testing.expect(saw_shared_team_person);
    try std.testing.expect(saw_outside_team_person);
    try std.testing.expectEqual(TeamRole.member, (try database.listTeams(team_arena, &shared.id))[0].role);
    try std.testing.expectError(error.NotTeamOwner, database.setTeamMember(&team_id, &shared.id, &first.id, .member, 7));
    try std.testing.expectError(error.NotTeamOwner, database.removeTeamMember(&team_id, &shared.id, &second.id));
    try database.removeTeamMember(&team_id, &second.id, &shared.id);
    try database.removeTeamMember(&team_id, &second.id, &second.id);
    try std.testing.expectEqual(@as(usize, 0), (try database.listTeams(team_arena, &shared.id)).len);
    try database.setTeamMember(&team_id, &second.id, &shared.id, .member, 8);
    try std.testing.expectError(error.NotTeamOwner, database.listTeamPeople(team_arena, &team_id, &shared.id));

    const project_id = "00000000-0000-4000-8000-000000000001";
    const project_connection = try pool.acquire();
    var project_cursor = try project_connection.exec(
        "INSERT INTO daemon_projects (id, owner_identity_id, name, source_kind, source_locator, execution_root, status, created_ms) " ++
            "VALUES ('00000000-0000-4000-8000-000000000001', '" ++
            "00000000-0000-4000-8000-000000000001', 'Example', 'local', '/example', '/example', 'ready', 4)",
        null,
    );
    try project_cursor.finish();
    pool.release(project_connection);
    try database.registerSession(&second.id, "/example", "01JQSESSION0000000000000000", .daemon, 5);
    try database.registerSession(&second.id, "/example", "01JQSESSION0000000000000001", .client, 5);
    try database.registerSession(&second.id, "/example", "01JQ0000000000000000000002", .client, 5);
    try database.registerSession(&second.id, "/example", "01JQSESSION0000000000000003", .daemon, 5);
    try std.testing.expect(try database.unregisterSession(&second.id, "01JQSESSION0000000000000003"));
    try std.testing.expect(!(try database.unregisterSession(&second.id, "01JQSESSION0000000000000003")));
    try std.testing.expect(try database.sessionPlacement("01JQSESSION0000000000000003") == null);
    try database.registerSession(&second.id, "/example", "01JQSESSION0000000000000003", .daemon, 6);
    try std.testing.expectEqual(@as(?SessionPlacement, .daemon), try database.sessionPlacement("01JQSESSION0000000000000003"));
    try std.testing.expectEqual(@as(?SessionPlacement, .daemon), try database.sessionPlacement("01JQSESSION0000000000000000"));
    try std.testing.expectEqual(@as(?SessionPlacement, .client), try database.sessionPlacement("01JQSESSION0000000000000001"));
    try std.testing.expect(try database.isClientSessionOwner("01JQ0000000000000000000002", &second.id));
    try std.testing.expect(!try database.isClientSessionOwner("01JQ0000000000000000000002", &shared.id));
    try std.testing.expect(!try database.isClientSessionOwner("01JQSESSION0000000000000001", &second.id));
    try std.testing.expect(try database.beginClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(try database.clientTurnActive("01JQ0000000000000000000002"));
    try std.testing.expect(!try database.beginClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(try database.finishClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(!try database.clientTurnActive("01JQ0000000000000000000002"));
    try std.testing.expect(!try database.finishClientTurn("01JQ0000000000000000000002"));
    const client_first_lease = try database.claimSessionHost(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000010",
        100,
        1000,
    );
    try std.testing.expect(try database.beginClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(try database.clientTurnActive("01JQ0000000000000000000002"));
    const client_takeover_lease = try database.claimSessionHost(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000011",
        client_first_lease.expires_ms,
        1000,
    );
    try std.testing.expectEqual(client_first_lease.generation + 1, client_takeover_lease.generation);
    try std.testing.expect(!try database.sessionHostMatches(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000010",
        client_first_lease.generation,
        client_first_lease.expires_ms,
    ));
    try std.testing.expect(try database.sessionHostMatches(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000011",
        client_takeover_lease.generation,
        client_first_lease.expires_ms,
    ));
    try std.testing.expect(!try database.beginClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(try database.finishClientTurnAndFenceHost("01JQ0000000000000000000002"));
    try std.testing.expect(!try database.clientTurnActive("01JQ0000000000000000000002"));
    try std.testing.expect(!try database.sessionHostMatches(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000011",
        client_takeover_lease.generation,
        client_takeover_lease.expires_ms - 1,
    ));
    const next_client_lease = try database.claimSessionHost(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000011",
        1200,
        1000,
    );
    try std.testing.expectEqual(client_takeover_lease.generation + 1, next_client_lease.generation);
    try std.testing.expect(try database.sessionHostMatches(
        "01JQ0000000000000000000002",
        &second.id,
        .client,
        "00000000-0000-4000-8000-000000000011",
        next_client_lease.generation,
        1201,
    ));
    try std.testing.expect(try database.beginClientTurn("01JQ0000000000000000000002"));
    try std.testing.expect(try database.finishClientTurn("01JQ0000000000000000000002"));
    try std.testing.expectEqual(@as(?SessionPlacement, null), try database.sessionPlacement("01MISSING"));
    try std.testing.expect(try database.sessionBelongsToProject("01JQSESSION0000000000000000", "/example"));
    try std.testing.expect(!try database.sessionBelongsToProject("01JQSESSION0000000000000000", "/elsewhere"));
    const first_host = "00000000-0000-4000-8000-000000000010";
    const second_host = "00000000-0000-4000-8000-000000000011";
    const third_host = "00000000-0000-4000-8000-000000000012";
    const first_lease = try database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        first_host,
        100,
        1000,
    );
    try std.testing.expectEqual(@as(u64, 1), first_lease.generation);
    try std.testing.expectEqual(@as(i64, 1100), first_lease.expires_ms);
    try std.testing.expect(try database.sessionHostMatches(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        first_host,
        first_lease.generation,
        101,
    ));
    try std.testing.expect(!try database.sessionHostMatches(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        second_host,
        first_lease.generation,
        101,
    ));
    try std.testing.expect(!try database.sessionHostMatches(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        first_host,
        first_lease.generation,
        first_lease.expires_ms,
    ));
    try std.testing.expect(!try database.releaseSessionHost(
        "01JQSESSION0000000000000000",
        &shared.id,
        first_host,
        first_lease.generation,
        150,
    ));
    try std.testing.expectError(error.SessionLeaseHeld, database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        second_host,
        200,
        1000,
    ));
    const renewed_lease = try database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        first_host,
        300,
        1000,
    );
    try std.testing.expectEqual(first_lease.generation, renewed_lease.generation);
    try std.testing.expect(!try database.releaseSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        first_host,
        2,
        400,
    ));
    try std.testing.expect(try database.releaseSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        first_host,
        first_lease.generation,
        400,
    ));
    const takeover_lease = try database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        second_host,
        400,
        1000,
    );
    try std.testing.expectEqual(@as(u64, 2), takeover_lease.generation);
    try std.testing.expect(!try database.releaseSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        first_host,
        first_lease.generation,
        500,
    ));
    const expired_takeover = try database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .daemon,
        third_host,
        takeover_lease.expires_ms,
        1000,
    );
    try std.testing.expectEqual(@as(u64, 3), expired_takeover.generation);
    try std.testing.expectError(error.InvalidHostLease, database.claimSessionHost(
        "01JQSESSION0000000000000000",
        &second.id,
        .client,
        first_host,
        500,
        1000,
    ));
    var member_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer member_arena_state.deinit();
    const member_arena = member_arena_state.allocator();
    var members = try database.listSessionMembers(member_arena, "01JQSESSION0000000000000000");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings(&second.id, members[0].identity_id);
    try std.testing.expectEqual(MemberRole.owner, members[0].role);
    try database.setSessionMember("01JQSESSION0000000000000000", &second.id, &shared.id, .editor, 6);
    members = try database.listSessionMembers(member_arena, "01JQSESSION0000000000000000");
    try std.testing.expectEqual(@as(usize, 2), members.len);
    const people = try database.listSessionPeople(member_arena, "01JQSESSION0000000000000000", &second.id);
    try std.testing.expectEqual(@as(usize, 4), people.len);
    var saw_shared_person = false;
    var saw_outside_person = false;
    for (people) |person| {
        if (std.mem.eql(u8, person.identity_id, &shared.id)) {
            saw_shared_person = true;
            try std.testing.expectEqualStrings("Shared", person.display_name);
            try std.testing.expectEqualStrings("shared@example.test", person.email);
            try std.testing.expectEqual(MemberRole.editor, person.role.?);
        }
        if (std.mem.eql(u8, person.identity_id, &outside_identity.id)) {
            saw_outside_person = true;
            try std.testing.expect(person.role == null);
        }
    }
    try std.testing.expect(saw_shared_person);
    try std.testing.expect(saw_outside_person);
    try std.testing.expectError(error.NotSessionOwner, database.listSessionPeople(
        member_arena,
        "01JQSESSION0000000000000000",
        &shared.id,
    ));
    try std.testing.expectError(error.NotSessionOwner, database.setSessionMember(
        "01JQSESSION0000000000000000",
        &shared.id,
        &first.id,
        .viewer,
        7,
    ));
    try std.testing.expectError(error.NotSessionOwner, database.removeSessionMember(
        "01JQSESSION0000000000000000",
        &shared.id,
        &second.id,
    ));
    const retained_acl_connection = try pool.acquire();
    const retained_acl_sql = try std.fmt.allocPrint(
        gpa,
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('session-member-removal-acl', 'session', '01JQSESSION0000000000000000', 'identity', '{s}', 'session_prompt', 'allow', 'test', 8)",
        .{&shared.id},
    );
    defer gpa.free(retained_acl_sql);
    var retained_acl_cursor = try retained_acl_connection.exec(retained_acl_sql, null);
    try retained_acl_cursor.finish();
    pool.release(retained_acl_connection);
    try database.removeSessionMember("01JQSESSION0000000000000000", &second.id, &shared.id);
    try database.removeSessionMember("01JQSESSION0000000000000000", &second.id, &second.id);
    members = try database.listSessionMembers(member_arena, "01JQSESSION0000000000000000");
    try std.testing.expectEqual(@as(usize, 1), members.len);
    try std.testing.expectEqualStrings(&second.id, members[0].identity_id);
    try std.testing.expect(try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_prompt));
    const clear_retained_acl_connection = try pool.acquire();
    var clear_retained_acl_cursor = try clear_retained_acl_connection.exec(
        "DELETE FROM acl_rules WHERE id = 'session-member-removal-acl'",
        null,
    );
    try clear_retained_acl_cursor.finish();
    pool.release(clear_retained_acl_connection);
    try std.testing.expect(!try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_prompt));
    try database.setSessionMember("01JQSESSION0000000000000000", &second.id, &shared.id, .editor, 8);

    const acl_project_id = try database.registerLocalProject(std.testing.io, &first.id, "ACL test", "/acl-test", 8);
    const acl_row_id = try database.setAclRule(&first.id, .{
        .resource_kind = "project",
        .resource_id = &acl_project_id,
        .principal_kind = .identity,
        .principal_id = &shared.id,
        .capability = .project_view,
        .effect = .allow,
    }, 9);
    try std.testing.expect(try database.authorize(&shared.id, "project", &acl_project_id, .project_view));
    const acl_rows = try database.listAclRules(member_arena, &first.id, "project", &acl_project_id);
    var found_acl = false;
    for (acl_rows) |acl_row| {
        if (!std.mem.eql(u8, &acl_row.id, &acl_row_id)) continue;
        found_acl = true;
        try std.testing.expectEqual(PrincipalKind.identity, acl_row.rule.principal_kind);
        try std.testing.expectEqual(Effect.allow, acl_row.rule.effect);
        try std.testing.expectEqualStrings(&shared.id, acl_row.rule.principal_id);
    }
    try std.testing.expect(found_acl);
    try std.testing.expectError(error.NotAclManager, database.removeAclRule(&shared.id, &acl_row_id));
    const deny_row_id = try database.setAclRule(&first.id, .{
        .resource_kind = "project",
        .resource_id = &acl_project_id,
        .principal_kind = .identity,
        .principal_id = &shared.id,
        .capability = .project_view,
        .effect = .deny,
    }, 10);
    try std.testing.expect(!try database.authorize(&shared.id, "project", &acl_project_id, .project_view));
    try std.testing.expectEqualStrings(&acl_row_id, &deny_row_id);
    try std.testing.expect(try database.removeAclRule(&first.id, &deny_row_id));
    try std.testing.expect(!try database.authorize(&shared.id, "project", &acl_project_id, .project_view));

    try std.testing.expect(try database.authorizeSession(&second.id, "01JQSESSION0000000000000000", .session_share));
    try std.testing.expect(try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_prompt));
    try std.testing.expect(!try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_share));
    try database.touchSessionPresence("01JQSESSION0000000000000000", &shared.id, 100_000);
    try database.touchSessionPresence("01JQSESSION0000000000000000", &second.id, 150_000);
    var presence = try database.listSessionPresence(
        member_arena,
        "01JQSESSION0000000000000000",
        &shared.id,
        160_000,
    );
    try std.testing.expectEqual(@as(usize, 1), presence.len);
    try std.testing.expectEqualStrings(&second.id, presence[0].identity_id);
    try std.testing.expectEqualStrings("New", presence[0].display_name);
    try database.touchSessionPresence("01JQSESSION0000000000000000", &shared.id, 160_000);
    presence = try database.listSessionPresence(
        member_arena,
        "01JQSESSION0000000000000000",
        &shared.id,
        170_000,
    );
    try std.testing.expectEqual(@as(usize, 2), presence.len);
    try std.testing.expectError(error.NotSessionViewer, database.touchSessionPresence(
        "01JQSESSION0000000000000000",
        &outside_identity.id,
        170_000,
    ));
    presence = try database.listSessionPresence(
        member_arena,
        "01JQSESSION0000000000000000",
        &shared.id,
        220_001,
    );
    try std.testing.expectEqual(@as(usize, 0), presence.len);
    const project_session_deny_connection = try pool.acquire();
    const project_session_deny_sql = try std.fmt.allocPrint(
        gpa,
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('project-session-deny', 'project', '{s}', 'identity', '{s}', 'session_prompt', 'deny', 'test', 8), " ++
            "('session-prompt-allow', 'session', '01JQSESSION0000000000000000', 'identity', '{s}', 'session_prompt', 'allow', 'test', 8), " ++
            "('project-session-view-allow', 'project', '{s}', 'everyone', NULL, 'session_view', 'allow', 'test', 8)",
        .{ project_id, &shared.id, &shared.id, project_id },
    );
    defer gpa.free(project_session_deny_sql);
    var project_session_deny_cursor = try project_session_deny_connection.exec(
        project_session_deny_sql,
        null,
    );
    try project_session_deny_cursor.finish();
    pool.release(project_session_deny_connection);
    try std.testing.expect(!try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_prompt));
    try std.testing.expect(try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_view));
    try std.testing.expect(try database.authorizeSession(&first.id, "01JQSESSION0000000000000000", .session_view));
    const session_deny_connection = try pool.acquire();
    var session_deny_cursor = try session_deny_connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('session-deny', 'session', '01JQSESSION0000000000000000', 'everyone', NULL, 'session_view', 'deny', 'test', 8)",
        null,
    );
    try session_deny_cursor.finish();
    pool.release(session_deny_connection);
    try std.testing.expect(!try database.authorize(&second.id, "session", "01JQSESSION0000000000000000", .session_view));
    try std.testing.expect(try database.hasSessionDeny(&second.id, "01JQSESSION0000000000000000", .session_view));
    try std.testing.expect(!try database.authorizeSession(&second.id, "01JQSESSION0000000000000000", .session_view));

    const wildcard_session_deny_connection = try pool.acquire();
    var wildcard_session_deny_cursor = try wildcard_session_deny_connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('session-deny-wildcard', 'session', '*', 'everyone', NULL, 'session_approve', 'deny', 'test', 8)",
        null,
    );
    try wildcard_session_deny_cursor.finish();
    pool.release(wildcard_session_deny_connection);
    try std.testing.expect(!try database.authorize(&shared.id, "session", "01JQSESSION0000000000000000", .session_approve));
    try std.testing.expect(try database.hasSessionDeny(&shared.id, "01JQSESSION0000000000000000", .session_approve));
    try std.testing.expect(!try database.authorizeSession(&shared.id, "01JQSESSION0000000000000000", .session_approve));
    const clear_wildcard_session_deny_connection = try pool.acquire();
    var clear_wildcard_session_deny_cursor = try clear_wildcard_session_deny_connection.exec(
        "DELETE FROM acl_rules WHERE id = 'session-deny-wildcard'",
        null,
    );
    try clear_wildcard_session_deny_cursor.finish();
    pool.release(clear_wildcard_session_deny_connection);

    const login = try database.createLoginSession(std.testing.io, &second.id, 10, 100);
    try std.testing.expect(validSessionToken(&login.token));
    try std.testing.expectEqual(@as(?bool, true), try database.authorizeLoginSession(
        gpa,
        &login.token,
        11,
        "session",
        "01JQSESSION0000000000000000",
        .session_share,
    ));
    const current_session = (try database.resolveLoginSession(gpa, &login.token, 11)).?;
    defer gpa.free(current_session.instance_role);
    try std.testing.expectEqualStrings(&second.id, &current_session.id);
    try std.testing.expectEqualStrings("member", current_session.instance_role);
    try std.testing.expect(current_session.workerScope() == null);
    try std.testing.expect((try database.resolveLoginSession(gpa, &login.token, 100)) == null);
    const worker_login = try database.createWorkerLoginSession(
        std.testing.io,
        &second.id,
        "01JQ0000000000000000000000",
        15,
        90,
    );
    const worker_session = (try database.resolveLoginSession(gpa, &worker_login.token, 16)).?;
    defer gpa.free(worker_session.instance_role);
    try std.testing.expectEqualStrings("01JQ0000000000000000000000", worker_session.workerScope().?);
    try std.testing.expectError(error.InvalidWorkerSession, database.createWorkerLoginSession(
        std.testing.io,
        &second.id,
        "not-a-session",
        15,
        90,
    ));
    const second_browser_login = try database.createLoginSession(std.testing.io, &second.id, 16, 100);
    try database.revokeLoginSession(&login.token, 12);
    try std.testing.expect((try database.resolveLoginSession(gpa, &login.token, 13)) == null);
    try std.testing.expectError(error.UnknownIdentity, database.createLoginSession(std.testing.io, "00000000-0000-4000-8000-000000000099", 14, 100));

    try std.testing.expect(!try database.authorize(&second.id, "project", project_id, .project_view));
    const acl_connection = try pool.acquire();
    var allow_cursor = try acl_connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('acl-allow', 'project', '00000000-0000-4000-8000-000000000001', 'everyone', NULL, 'project_view', 'allow', 'test', 4)",
        null,
    );
    try allow_cursor.finish();
    pool.release(acl_connection);
    const check_connection = try pool.acquire();
    var check_cursor = try check_connection.exec("SELECT effect FROM acl_rules", null);
    try std.testing.expect((try check_cursor.next()) != null);
    try check_cursor.finish();
    pool.release(check_connection);
    try std.testing.expect(try database.authorize(&second.id, "project", project_id, .project_view));
    const acl_login = try database.createLoginSession(std.testing.io, &second.id, 10, 100);
    try std.testing.expectEqual(@as(?bool, true), try database.authorizeLoginSession(
        gpa,
        &acl_login.token,
        11,
        "project",
        project_id,
        .project_view,
    ));

    const deny_connection = try pool.acquire();
    var deny_cursor = try deny_connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('acl-deny', 'project', '00000000-0000-4000-8000-000000000001', 'everyone', NULL, 'project_view', 'deny', 'test', 5)",
        null,
    );
    try deny_cursor.finish();
    pool.release(deny_connection);
    try std.testing.expect(!try database.authorize(&second.id, "project", project_id, .project_view));
    try std.testing.expectEqual(@as(?bool, false), try database.authorizeLoginSession(
        gpa,
        &acl_login.token,
        11,
        "project",
        project_id,
        .project_view,
    ));
    try database.revokeLoginSession(&acl_login.token, 12);
    try std.testing.expectEqual(@as(?bool, null), try database.authorizeLoginSession(
        gpa,
        &acl_login.token,
        13,
        "project",
        project_id,
        .project_view,
    ));

    const membership_connection = try pool.acquire();
    const membership_sql = try std.fmt.allocPrint(
        gpa,
        "INSERT INTO teams (id, name, created_by_identity_id, created_ms) " ++
            "VALUES ('00000000-0000-4000-8000-000000000001', 'Reviewers', '{s}', 6); " ++
            "INSERT INTO team_members (team_id, identity_id, role, added_ms) " ++
            "VALUES ('00000000-0000-4000-8000-000000000001', '{s}', 'member', 6); " ++
            "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('acl-team', 'project', 'project-2', 'team', '00000000-0000-4000-8000-000000000001', 'project_view', 'allow', '{s}', 6)",
        .{ &second.id, &second.id, &second.id },
    );
    defer gpa.free(membership_sql);
    var membership_cursor = try membership_connection.exec(membership_sql, null);
    try membership_cursor.finish();
    pool.release(membership_connection);
    try std.testing.expect(try database.authorize(&second.id, "project", "project-2", .project_view));

    const wildcard_connection = try pool.acquire();
    var wildcard_cursor = try wildcard_connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('acl-wildcard', 'project', '*', 'everyone', NULL, 'project_view', 'allow', 'test', 7)",
        null,
    );
    try wildcard_cursor.finish();
    pool.release(wildcard_connection);
    try std.testing.expect(try database.authorize(&second.id, "project", "project-3", .project_view));

    const promoted = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-1",
        .email = "new@example.test",
        .payload = "{}",
    }, "New", true, 8);
    defer gpa.free(promoted.instance_role);
    try std.testing.expectEqualStrings(&first.id, &promoted.id);
    try std.testing.expectEqualStrings("instance_admin", promoted.instance_role);
    var people_arena = std.heap.ArenaAllocator.init(gpa);
    defer people_arena.deinit();
    const directory = try database.listPeople(people_arena.allocator(), &first.id);
    try std.testing.expect(directory.len >= 1);
    var found_first = false;
    for (directory) |person| {
        if (!std.mem.eql(u8, person.identity_id, &first.id)) continue;
        found_first = true;
        try std.testing.expectEqualStrings("New", person.display_name);
        try std.testing.expectEqualStrings("new@example.test", person.email);
        try std.testing.expectEqualStrings("instance_admin", person.instance_role);
    }
    try std.testing.expect(found_first);
    const role_config_connection = try pool.acquire();
    var role_config_cursor = try role_config_connection.exec(
        "INSERT INTO service_config (id, auth_mode) VALUES (1, 'oidc')",
        null,
    );
    try role_config_cursor.finish();
    pool.release(role_config_connection);
    try database.setInstanceAdmin(&first.id, &shared.id, true);
    const promoted_second = try database.resolveIdentity(
        gpa,
        std.testing.io,
        "https://id.example",
        .{ .subject = "person-2", .email = "shared@example.test", .payload = "{}" },
        "Shared",
        false,
        10,
    );
    defer gpa.free(promoted_second.instance_role);
    try std.testing.expectEqualStrings("instance_admin", promoted_second.instance_role);
    try database.setInstanceAdmin(&first.id, &shared.id, false);
    try std.testing.expectError(error.NotInstanceAdmin, database.setInstanceAdmin(&shared.id, &outside_identity.id, true));
    try std.testing.expectError(error.LastInstanceAdministrator, database.setInstanceAdmin(&first.id, &first.id, false));
    try std.testing.expectError(error.NotInstanceAdmin, database.setInstanceAdmin(&outside_identity.id, &outside_identity.id, true));
    try std.testing.expectError(error.NotInstanceAdmin, database.listPeople(people_arena.allocator(), &outside_identity.id));
    const still_admin = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "person-1",
        .email = "new@example.test",
        .payload = "{}",
    }, "New", false, 9);
    defer gpa.free(still_admin.instance_role);
    try std.testing.expectEqualStrings("instance_admin", still_admin.instance_role);

    try std.testing.expectError(error.NotInstanceAdmin, database.revokeIdentitySessions(&outside_identity.id, &second.id, 17));
    try std.testing.expectEqual(@as(u64, 2), try database.revokeIdentitySessions(&first.id, &second.id, 17));
    try std.testing.expect((try database.resolveLoginSession(gpa, &worker_login.token, 18)) == null);
    try std.testing.expect((try database.resolveLoginSession(gpa, &second_browser_login.token, 18)) == null);
    try std.testing.expectError(error.UnknownIdentity, database.revokeIdentitySessions(
        &first.id,
        "00000000-0000-4000-8000-000000000099",
        18,
    ));

    try std.testing.expectError(error.InvalidIdentity, database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "",
        .email = null,
        .payload = "{}",
    }, null, false, 4));
}

test "first local administrator uses Argon2id and setup is one-time" {
    const gpa = std.testing.allocator;
    var server = try quarry.sqlite.testing.Server.start(gpa, std.testing.io, .{});
    defer server.deinit();
    var environ = std.process.Environ.Map.init(gpa);
    defer environ.deinit();
    var database = try Database.open(gpa, std.testing.io, server.url, &environ, 1);
    defer database.close();

    const created = try database.createInitialLocalAdmin(
        gpa,
        std.testing.io,
        "  Admin.User  ",
        "correct horse battery staple",
        2,
    );
    defer gpa.free(created.instance_role);
    try std.testing.expect(isUuid(&created.id));
    try std.testing.expectEqualStrings("instance_admin", created.instance_role);

    const authenticated = (try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "ADMIN.USER",
        "correct horse battery staple",
    )).?;
    defer gpa.free(authenticated.instance_role);
    try std.testing.expectEqual(created.id, authenticated.id);
    try std.testing.expectEqualStrings("instance_admin", authenticated.instance_role);

    const member_id = try database.createLocalAccount(
        gpa,
        std.testing.io,
        &created.id,
        "team.member",
        "member password one",
        3,
    );
    try std.testing.expect(isUuid(&member_id));
    var local_directory_arena = std.heap.ArenaAllocator.init(gpa);
    defer local_directory_arena.deinit();
    const local_directory = try database.listPeople(local_directory_arena.allocator(), &created.id);
    var found_local_member = false;
    for (local_directory) |person| {
        if (std.mem.eql(u8, person.identity_id, &member_id)) {
            found_local_member = true;
            try std.testing.expect(person.local_account);
        }
    }
    try std.testing.expect(found_local_member);
    try std.testing.expectError(error.AccountAlreadyExists, database.createLocalAccount(
        gpa,
        std.testing.io,
        &created.id,
        "TEAM.MEMBER",
        "another member password",
        4,
    ));
    const member = (try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "member password one",
    )).?;
    defer gpa.free(member.instance_role);
    try std.testing.expectEqual(member_id, member.id);
    try std.testing.expectEqualStrings("member", member.instance_role);
    const member_login = try database.createLoginSession(std.testing.io, &member_id, 6, 1000);
    try database.resetLocalAccountPassword(
        gpa,
        std.testing.io,
        &created.id,
        &member_id,
        "temporary password two",
    );
    try std.testing.expect((try database.resolveLoginSession(gpa, &member_login.token, 7)) == null);
    try std.testing.expect((try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "member password one",
    )) == null);
    const reset_member = (try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "temporary password two",
    )).?;
    defer gpa.free(reset_member.instance_role);
    try std.testing.expectEqual(member_id, reset_member.id);
    const member_login_after_reset = try database.createLoginSession(std.testing.io, &member_id, 8, 1000);
    const member_login_other_device = try database.createLoginSession(std.testing.io, &member_id, 8, 1000);
    try database.changeLocalAccountPassword(
        gpa,
        std.testing.io,
        &member_id,
        &member_login_after_reset.token,
        "temporary password two",
        "member password three",
        9,
    );
    const still_signed_in = (try database.resolveLoginSession(gpa, &member_login_after_reset.token, 10)).?;
    defer gpa.free(still_signed_in.instance_role);
    try std.testing.expect((try database.resolveLoginSession(gpa, &member_login_other_device.token, 10)) == null);
    try std.testing.expectError(error.InvalidCurrentPassword, database.changeLocalAccountPassword(
        gpa,
        std.testing.io,
        &member_id,
        &member_login_after_reset.token,
        "temporary password two",
        "member password four",
        10,
    ));
    try std.testing.expect((try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "temporary password two",
    )) == null);
    const changed_member = (try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "member password three",
    )).?;
    defer gpa.free(changed_member.instance_role);
    try std.testing.expectEqual(member_id, changed_member.id);
    try database.setLocalAccountDisabled(&created.id, &member_id, true, 9);
    try std.testing.expect((try database.resolveLoginSession(gpa, &member_login_after_reset.token, 10)) == null);
    try std.testing.expect((try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "temporary password two",
    )) == null);
    const disabled_directory = try database.listPeople(local_directory_arena.allocator(), &created.id);
    for (disabled_directory) |person| if (std.mem.eql(u8, person.identity_id, &member_id)) {
        try std.testing.expect(person.local_account_disabled);
    };
    try std.testing.expectError(error.LastLocalAdministrator, database.setLocalAccountDisabled(
        &created.id,
        &created.id,
        true,
        10,
    ));
    try database.setLocalAccountDisabled(&created.id, &member_id, false, 11);
    const reenabled_member = (try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "team.member",
        "member password three",
    )).?;
    defer gpa.free(reenabled_member.instance_role);
    try std.testing.expectEqual(member_id, reenabled_member.id);

    try std.testing.expectError(error.NotInstanceAdmin, database.createLocalAccount(
        gpa,
        std.testing.io,
        &member_id,
        "not.allowed",
        "another valid password",
        5,
    ));
    try std.testing.expectError(error.NotInstanceAdmin, database.resetLocalAccountPassword(
        gpa,
        std.testing.io,
        &member_id,
        &created.id,
        "another temporary password",
    ));
    try std.testing.expectError(error.NotInstanceAdmin, database.setLocalAccountDisabled(
        &member_id,
        &member_id,
        true,
        12,
    ));

    try std.testing.expect((try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "admin.user",
        "not the password",
    )) == null);
    try std.testing.expect((try database.authenticateLocalAccount(
        gpa,
        std.testing.io,
        "missing-user",
        "not the password",
    )) == null);
    try std.testing.expectError(error.AlreadyInitialized, database.createInitialLocalAdmin(
        gpa,
        std.testing.io,
        "second.admin",
        "another correct password",
        3,
    ));
}

test "instance access export includes shared ACL state without invitation bearers" {
    var server = try quarry.sqlite.testing.Server.start(std.testing.allocator, std.testing.io, .{});
    defer server.deinit();
    var environ = std.process.Environ.Map.init(std.testing.allocator);
    defer environ.deinit();
    var database = try Database.open(std.testing.allocator, std.testing.io, server.url, &environ, 1);
    defer database.close();

    const admin = try database.resolveIdentity(std.testing.allocator, std.testing.io, "https://id.example", .{
        .subject = "admin",
        .email = "admin@example.test",
        .payload = "{}",
    }, "Admin", true, 10);
    defer std.testing.allocator.free(admin.instance_role);
    const member = try database.resolveIdentity(std.testing.allocator, std.testing.io, "https://id.example", .{
        .subject = "member",
        .email = "member@example.test",
        .payload = "{}",
    }, "Member", false, 11);
    defer std.testing.allocator.free(member.instance_role);

    const team = try database.createTeam(std.testing.io, &admin.id, "Reviewers", 12);
    try database.setTeamMember(&team, &admin.id, &member.id, .member, 13);
    const invitation = try database.createTeamInvitation(std.testing.io, &admin.id, &team, .member, 14, 60_014);
    const project = try database.registerLocalProject(std.testing.io, &admin.id, "Project", "/tmp/chock-export", 15);
    const session = "01JQ0000000000000000000000";
    try database.registerSession(&admin.id, "/tmp/chock-export", session, .client, 16);
    try database.setSessionMember(session, &admin.id, &member.id, .viewer, 17);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const access_json = try database.exportInstanceAccess(arena.allocator(), &admin.id);
    for ([_][]const u8{
        "\"teams\":[",
        "\"team_members\":[",
        "\"invitations\":[",
        "\"session_members\":[",
        "\"acl_rules\":[",
        &team,
        &project,
        session,
    }) |expected| try std.testing.expect(std.mem.indexOf(u8, access_json, expected) != null);
    try std.testing.expect(std.mem.indexOf(u8, access_json, &invitation.token) == null);
    try std.testing.expect(std.mem.indexOf(u8, access_json, "token_hash") == null);
    try std.testing.expectError(error.NotInstanceAdmin, database.exportInstanceAccess(arena.allocator(), &member.id));
}

test "Database owns a ready connection" {
    var server = try quarry.sqlite.testing.Server.start(std.testing.allocator, std.testing.io, .{});
    defer server.deinit();
    var env = std.process.Environ.Map.init(std.testing.allocator);
    defer env.deinit();
    var database = try Database.open(std.testing.allocator, std.testing.io, server.url, &env, 42);
    defer database.close();
    try database.ping();
}

// Quarry's isolated PostgreSQL server makes this test self-contained when
// native PostgreSQL tools are installed, and it skips otherwise.
test "PostgreSQL persists identities teams shared sessions and revocation" {
    const gpa = std.testing.allocator;
    var server = quarry.postgres.testing.Server.start(gpa, std.testing.io, .{}) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest,
        else => return err,
    };
    defer server.deinit();
    var environ = std.process.Environ.Map.init(gpa);
    defer environ.deinit();
    const database_url = server.url;
    var database = try Database.open(gpa, std.testing.io, database_url, &environ, 1);
    defer database.close();
    const now_ms = std.Io.Timestamp.now(std.testing.io, .real).toMilliseconds();
    const issuer = try std.fmt.allocPrint(gpa, "https://id.example/postgres-test-{d}", .{now_ms});
    defer gpa.free(issuer);
    const admin = try database.resolveIdentity(gpa, std.testing.io, issuer, .{
        .subject = "admin",
        .email = "admin@example.test",
        .payload = "{}",
    }, "Admin", true, now_ms);
    defer gpa.free(admin.instance_role);
    const member = try database.resolveIdentity(gpa, std.testing.io, issuer, .{
        .subject = "member",
        .email = "member@example.test",
        .payload = "{}",
    }, "Member", false, now_ms + 1);
    defer gpa.free(member.instance_role);

    const team_id = try database.createTeam(std.testing.io, &admin.id, "PostgreSQL team", now_ms + 2);
    try database.setTeamMember(&team_id, &admin.id, &member.id, .member, now_ms + 3);
    var people_arena = std.heap.ArenaAllocator.init(gpa);
    defer people_arena.deinit();
    const people = try database.listTeamPeople(people_arena.allocator(), &team_id, &admin.id);
    try std.testing.expectEqual(@as(usize, 2), people.len);
    const directory = try database.listPeople(people_arena.allocator(), &admin.id);
    try std.testing.expectEqual(@as(usize, 2), directory.len);

    const root = try std.fmt.allocPrint(gpa, "/tmp/chock-postgres-{d}", .{now_ms});
    defer gpa.free(root);
    _ = try database.registerLocalProject(std.testing.io, &admin.id, "PostgreSQL project", root, now_ms + 4);
    var session_buffer: [32]u8 = undefined;
    const session_id = try std.fmt.bufPrint(&session_buffer, "pg{d}", .{now_ms});
    try database.registerSession(&admin.id, root, session_id, .client, now_ms + 5);
    try database.setSessionMember(session_id, &admin.id, &member.id, .viewer, now_ms + 6);
    try std.testing.expect(try database.authorizeSession(&member.id, session_id, .session_view));
    try std.testing.expect(!try database.authorizeSession(&member.id, session_id, .session_prompt));

    const login = try database.createLoginSession(std.testing.io, &member.id, now_ms + 7, now_ms + 60_007);
    const resolved = (try database.resolveLoginSession(gpa, &login.token, now_ms + 8)).?;
    defer gpa.free(resolved.instance_role);
    try std.testing.expectEqualStrings(&member.id, &resolved.id);
    try database.revokeLoginSession(&login.token, now_ms + 9);
    try std.testing.expect((try database.resolveLoginSession(gpa, &login.token, now_ms + 10)) == null);
}

test "a wildcard project is not a directory, and an administrator is never denied one" {
    const gpa = std.testing.allocator;
    var server = try quarry.sqlite.testing.Server.start(gpa, std.testing.io, .{});
    defer server.deinit();
    var environ = std.process.Environ.Map.init(gpa);
    defer environ.deinit();
    var database = try Database.open(gpa, std.testing.io, server.url, &environ, 1);
    defer database.close();

    const admin = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "admin",
        .email = "admin@example.test",
        .payload = "{}",
    }, "Admin", true, 1);
    defer gpa.free(admin.instance_role);
    const member = try database.resolveIdentity(gpa, std.testing.io, "https://id.example", .{
        .subject = "member",
        .email = "member@example.test",
        .payload = "{}",
    }, "Member", false, 2);
    defer gpa.free(member.instance_role);
    const admin_login = try database.createLoginSession(std.testing.io, &admin.id, 3, 1000);
    const member_login = try database.createLoginSession(std.testing.io, &member.id, 3, 1000);

    // The first page a browser asks for names every project and no directory, and the
    // directory this was started for can name no project at all.
    try std.testing.expectEqual(@as(?bool, true), try database.authorizeLoginSession(
        gpa,
        &admin_login.token,
        4,
        "project",
        "*",
        .project_view,
    ));
    try std.testing.expectEqual(@as(?bool, true), try database.authorizeLoginSession(
        gpa,
        &admin_login.token,
        4,
        "project",
        "/home/nobody/work",
        .project_view,
    ));
    try std.testing.expectEqual(@as(?bool, false), try database.authorizeLoginSession(
        gpa,
        &member_login.token,
        4,
        "project",
        "*",
        .project_view,
    ));

    const connection = try database.pool.acquire();
    var cursor = try connection.exec(
        "INSERT INTO acl_rules (id, resource_kind, resource_id, principal_kind, principal_id, capability, effect, created_by_identity_id, created_ms) " ++
            "VALUES ('every-project-view', 'project', '*', 'everyone', NULL, 'project_view', 'allow', 'test', 5)",
        null,
    );
    try cursor.finish();
    database.pool.release(connection);
    try std.testing.expectEqual(@as(?bool, true), try database.authorizeLoginSession(
        gpa,
        &member_login.token,
        6,
        "project",
        "*",
        .project_view,
    ));
}

test "ACL is deny by default and a matching deny wins" {
    const actor: Actor = .{ .identity_id = "person-1", .team_ids = &.{"team-1"} };
    try std.testing.expect(!authorized(actor, &.{}, "provider", "provider-1", .provider_use));
    try std.testing.expect(authorized(actor, &.{.{
        .resource_kind = "provider",
        .resource_id = "provider-1",
        .principal_kind = .team,
        .principal_id = "team-1",
        .capability = .provider_use,
        .effect = .allow,
    }}, "provider", "provider-1", .provider_use));
    try std.testing.expect(!authorized(actor, &.{
        .{
            .resource_kind = "provider",
            .resource_id = "provider-1",
            .principal_kind = .everyone,
            .capability = .provider_use,
            .effect = .allow,
        },
        .{
            .resource_kind = "provider",
            .resource_id = "provider-1",
            .principal_kind = .identity,
            .principal_id = "person-1",
            .capability = .provider_use,
            .effect = .deny,
        },
    }, "provider", "provider-1", .provider_use));
    try std.testing.expect(authorized(.{ .identity_id = "admin", .instance_admin = true }, &.{}, "provider", "provider-1", .provider_manage));
}

test {
    std.testing.refAllDecls(@This());
}
