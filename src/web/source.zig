//! A `chock-ui` source that reaches `chock serve` over HTTP.
//!
//! The browser half of the seam. Every call goes through phantom's own HTTP
//! client, which the page answers with its `fetch`, so this needs no wire format
//! of its own. Not `std.http.Client`: that does not compile for
//! wasm32-freestanding on Zig 0.17.

const std = @import("std");
const phantom = @import("phantom");
const chock_ui = @import("chock-ui");
const chock_proto = @import("chock-proto");
const event = chock_proto.event;
const control = chock_proto.control;

const ui_source = chock_ui.source;
const Source = ui_source.Source;

/// Browser callers pass the current host without a scheme so Phantom can bind
/// the request to the page's origin. Native mobile callers may persist an
/// explicit HTTP or HTTPS scheme, which must survive instead of becoming the
/// malformed `http://https://…` URL.
fn requestUrl(arena: std.mem.Allocator, origin: []const u8, target: []const u8) ![]const u8 {
    if (std.mem.startsWith(u8, origin, "https://") or std.mem.startsWith(u8, origin, "http://"))
        return std.fmt.allocPrint(arena, "{s}{s}", .{ origin, target });
    return std.fmt.allocPrint(arena, "http://{s}{s}", .{ origin, target });
}

/// The most one reply may be. A session list or a page of lines past this is a
/// daemon answering something other than what was asked.
const max_reply_bytes: usize = 8 * 1024 * 1024;

/// Reaches the `chock serve` that served this page.
pub const Web = struct {
    gpa: std.mem.Allocator,
    /// The owner, and never a copy of its `io`.
    ///
    /// **`BuildOwner.io` starts as `std.Io.failing` and is replaced with the
    /// browser's during init.** A copy taken before that is a vtable whose every
    /// read fails, which reaches a screen as a dead daemon and sends a reader
    /// looking at the network.
    owner: *phantom.BuildOwner,
    /// The origin the page came from, so a request goes back where it came from
    /// and nowhere else.
    origin: []const u8,
    /// Why the last call refused. Owned, replaced on each failure.
    said: ?[]u8 = null,
    /// The session whose questions `asks` reports. Null until a screen picks
    /// one, and then nothing is waiting because nothing is being looked at.
    watching: ?[]const u8 = null,
    /// The directory of the project that session is in, so a request names it.
    /// Serve is started for one project and a browser lists across them all.
    watching_project: []u8 = &.{},
    /// Room for the event stream's `&project=`, which is built without an arena.
    /// `std.fs.max_path_bytes` is not a number on wasm32-freestanding, so the
    /// longest path Linux takes is written out here.
    project_query: [4096 + 16]u8 = undefined,

    pub const AclRule = struct {
        resource_kind: []const u8,
        resource_id: []const u8,
        principal_kind: []const u8,
        principal_id: []const u8,
        capability: []const u8,
        effect: []const u8,
    };

    pub const AuthStatus = struct { mode: []const u8, setup: bool };
    pub const LocalCredentials = struct { username: []const u8, password: []const u8 };
    pub const LocalPasswordChange = struct {
        current_password: []const u8,
        new_password: []const u8,
    };
    pub const OidcConfiguration = struct {
        provider: []const u8,
        issuer: []const u8,
        discovery_url: ?[]const u8 = null,
        client_id: []const u8,
        client_secret: ?[]const u8 = null,
        admin_subject: []const u8,
    };

    /// Read the service's first-run/authentication mode without exposing any
    /// identity-provider credentials or account data.
    pub fn authStatus(self: *Web, arena: std.mem.Allocator) ui_source.Error!AuthStatus {
        const said = try self.get(arena, "/api/auth/status");
        const found = std.json.parseFromSliceLeaky(AuthStatus, arena, said, .{}) catch {
            self.note("the service authentication status could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn localSetup(self: *Web, arena: std.mem.Allocator, credentials: LocalCredentials) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, credentials, .{}) catch return error.OutOfMemory;
        const headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-chock-phantom-auth", .value = "true" },
        };
        _ = try self.sendMethod(arena, "/api/setup/local", .POST, payload, &headers);
    }

    pub fn localLogin(self: *Web, arena: std.mem.Allocator, credentials: LocalCredentials) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, credentials, .{}) catch return error.OutOfMemory;
        const headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/json" },
            .{ .name = "x-chock-phantom-auth", .value = "true" },
        };
        _ = try self.sendMethod(arena, "/api/auth/local", .POST, payload, &headers);
    }

    pub fn changeLocalPassword(self: *Web, arena: std.mem.Allocator, change: LocalPasswordChange) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, change, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/auth/password", payload);
    }

    pub fn oidcSetup(self: *Web, arena: std.mem.Allocator, configuration: OidcConfiguration) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, configuration, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/setup/oidc", payload);
    }

    pub const WorkerCredential = struct {
        token: []const u8,
        expires_ms: i64,
    };

    pub const CreatedTeamInvitation = struct { id: []const u8, token: []const u8, expires_ms: i64 };
    pub const TeamInvitationRow = struct {
        id: []const u8,
        role: []const u8,
        created_ms: i64,
        expires_ms: i64,
        revoked: bool,
        redeemed: bool,
        expired: bool,
    };

    /// Mint a session-scoped worker bearer. The response is intentionally not
    /// cached by this source; callers should display it once and discard it.
    pub fn createWorkerCredential(
        self: *Web,
        arena: std.mem.Allocator,
        session: []const u8,
    ) ui_source.Error!WorkerCredential {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .session = session }, .{}) catch
            return error.OutOfMemory;
        const said = try self.post(arena, "/api/worker/token", payload);
        const found = std.json.parseFromSliceLeaky(WorkerCredential, arena, said, .{}) catch {
            self.note("the daemon's worker credential response could not be read");
            return error.Refused;
        };
        if (found.token.len != 43 or found.expires_ms <= 0) {
            self.note("the daemon returned an invalid worker credential");
            return error.Refused;
        }
        self.clear();
        return found;
    }

    /// Revoke a worker bearer using the only authority it carries: itself.
    pub fn revokeWorkerCredential(self: *Web, arena: std.mem.Allocator, token: []const u8) ui_source.Error!void {
        const value = std.fmt.allocPrint(arena, "Bearer {s}", .{token}) catch return error.OutOfMemory;
        defer std.crypto.secureZero(u8, value);
        const headers = [_]std.http.Header{.{ .name = "authorization", .value = value }};
        _ = try self.sendMethod(arena, "/api/worker/revoke", .POST, "", &headers);
        self.clear();
    }
    pub const AclRecord = struct { id: []const u8, rule: AclRule };
    pub const ProviderRow = struct {
        id: []const u8,
        name: []const u8,
        provider_kind: []const u8,
        scope_kind: []const u8,
        scope_id: ?[]const u8 = null,
        configuration: []const u8,
        has_credential: bool,
    };

    pub fn init(gpa: std.mem.Allocator, owner: *phantom.BuildOwner, origin: []const u8) Web {
        return .{ .gpa = gpa, .owner = owner, .origin = origin };
    }

    /// Whether this can reach anything at all. A page that does not know its own
    /// host would build `http:///api/sessions`, which a browser reads as a local
    /// file and refuses, and the refusal arrives looking like a dead daemon.
    fn reachable(self: *Web) bool {
        if (self.origin.len != 0) return true;
        self.note("the page did not say which host it is on");
        return false;
    }

    pub fn deinit(self: *Web) void {
        if (self.said) |one| self.gpa.free(one);
        self.said = null;
        self.gpa.free(self.watching_project);
        self.watching_project = &.{};
    }

    /// Create in a registered project selected from the Projects screen. The
    /// project root is URL-encoded and independently checked by the gateway's
    /// project ACL before it reaches the daemon.
    pub fn createInProject(
        self: *Web,
        arena: std.mem.Allocator,
        placement: ui_source.Placement,
        project_root: []const u8,
    ) ui_source.Error![]const u8 {
        const target = std.fmt.allocPrint(arena, "/api/create?placement={s}&project={f}", .{
            @tagName(placement),
            std.fmt.alt(@as(std.Uri.Component, .{ .raw = project_root }), .formatEscaped),
        }) catch return error.OutOfMemory;
        const response = std.mem.trim(u8, try self.post(arena, target, ""), " \t\r\n");
        const end = std.mem.indexOfAny(u8, response, "\t\r\n") orelse response.len;
        if (end == 0) {
            self.note("the daemon returned no session identifier");
            return error.Refused;
        }
        self.clear();
        return response[0..end];
    }

    /// Attach a session created by the local `chock` daemon to a registered
    /// service project, making its transcript available to ACL and sharing.
    pub fn registerExistingSession(
        self: *Web,
        arena: std.mem.Allocator,
        project_root: []const u8,
        session_id: []const u8,
    ) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/session/register?project={f}", .{
            std.fmt.alt(@as(std.Uri.Component, .{ .raw = project_root }), .formatEscaped),
        }) catch return error.OutOfMemory;
        const payload = std.json.Stringify.valueAlloc(arena, .{ .session = session_id }, .{}) catch
            return error.OutOfMemory;
        _ = try self.post(arena, target, payload);
        self.clear();
    }

    /// Follow one session, and look up which project it is in.
    ///
    /// The id alone does not say: the daemon finds a session under its project's
    /// own directory, so every later request has to name that project.
    pub fn watch(self: *Web, session: []const u8) void {
        self.watching = session;
        self.gpa.free(self.watching_project);
        self.watching_project = &.{};

        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();

        const found = sessions(self, room.allocator()) catch return;
        for (found) |one| {
            if (!std.mem.eql(u8, one.id, session)) continue;
            self.watching_project = self.gpa.dupe(u8, one.project_root) catch &.{};
            return;
        }
    }

    /// The same, into a buffer the caller owns, for an event stream URL built
    /// without an arena.
    pub fn eventsProject(self: *Web) []const u8 {
        if (self.watching_project.len == 0) return "";
        return std.fmt.bufPrint(&self.project_query, "&project={f}", .{std.fmt.alt(
            @as(std.Uri.Component, .{ .raw = self.watching_project }),
            .formatEscaped,
        )}) catch "";
    }

    /// The project needed to authorize an address-bar session route.
    pub fn locationProject(self: *Web) []const u8 {
        if (self.watching_project.len == 0) return "";
        return std.fmt.bufPrint(&self.project_query, "?project={f}", .{std.fmt.alt(
            @as(std.Uri.Component, .{ .raw = self.watching_project }),
            .formatEscaped,
        )}) catch "";
    }

    /// `&project=...` for a request about the session being followed, or nothing
    /// when serve's own project is the right one.
    fn namedProject(self: *Web, arena: std.mem.Allocator) []const u8 {
        if (self.watching_project.len == 0) return "";
        return std.fmt.allocPrint(arena, "&project={f}", .{std.fmt.alt(
            @as(std.Uri.Component, .{ .raw = self.watching_project }),
            .formatEscaped,
        )}) catch "";
    }

    pub fn source(self: *Web) Source {
        return .{ .ptr = self, .vtable = &vtable, .name = "daemon" };
    }

    pub fn projects(self: *Web, arena: std.mem.Allocator) ui_source.Error![]const control.ProjectRow {
        const said = try self.get(arena, "/api/projects");
        const found = std.json.parseFromSliceLeaky([]const control.ProjectRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's project list could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn people(self: *Web, arena: std.mem.Allocator) ui_source.Error![]const control.PersonRow {
        const said = try self.get(arena, "/api/people");
        const found = std.json.parseFromSliceLeaky([]const control.PersonRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's people directory could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn revokePersonSessions(self: *Web, arena: std.mem.Allocator, identity_id: []const u8) ui_source.Error!u64 {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .identity_id = identity_id }, .{}) catch
            return error.OutOfMemory;
        const said = try self.post(arena, "/api/people", payload);
        const Reply = struct { revoked: u64 };
        const found = std.json.parseFromSliceLeaky(Reply, arena, said, .{}) catch {
            self.note("the daemon's credential revocation result could not be read");
            return error.Refused;
        };
        self.clear();
        return found.revoked;
    }

    pub fn createLocalAccount(
        self: *Web,
        arena: std.mem.Allocator,
        username: []const u8,
        password: []const u8,
    ) ui_source.Error![]const u8 {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .action = "create_local",
            .username = username,
            .password = password,
        }, .{}) catch return error.OutOfMemory;
        const said = try self.post(arena, "/api/people", payload);
        const Reply = struct { identity_id: []const u8 };
        const found = std.json.parseFromSliceLeaky(Reply, arena, said, .{}) catch {
            self.note("the new local account result could not be read");
            return error.Refused;
        };
        if (found.identity_id.len != 36) {
            self.note("the new local account identifier was malformed");
            return error.Refused;
        }
        self.clear();
        return found.identity_id;
    }

    pub fn resetLocalAccountPassword(
        self: *Web,
        arena: std.mem.Allocator,
        identity_id: []const u8,
        password: []const u8,
    ) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .action = "reset_local_password",
            .identity_id = identity_id,
            .password = password,
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/people", payload);
        self.clear();
    }

    pub fn setLocalAccountEnabled(
        self: *Web,
        arena: std.mem.Allocator,
        identity_id: []const u8,
        enabled: bool,
    ) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .action = "set_local_account_enabled",
            .identity_id = identity_id,
            .enabled = enabled,
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/people", payload);
        self.clear();
    }

    pub fn setInstanceRole(
        self: *Web,
        arena: std.mem.Allocator,
        identity_id: []const u8,
        instance_admin: bool,
    ) ui_source.Error!void {
        const role: []const u8 = if (instance_admin) "instance_admin" else "member";
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .action = "set_instance_role",
            .identity_id = identity_id,
            .role = role,
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/people", payload);
        self.clear();
    }

    pub fn createProject(
        self: *Web,
        arena: std.mem.Allocator,
        name: []const u8,
        root: []const u8,
    ) ui_source.Error!control.ProjectRow {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .name = name, .root = root }, .{}) catch
            return error.OutOfMemory;
        const said = try self.post(arena, "/api/projects", payload);
        const found = std.json.parseFromSliceLeaky(control.ProjectRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's project response could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn createGitProject(
        self: *Web,
        arena: std.mem.Allocator,
        name: []const u8,
        repository_url: []const u8,
    ) ui_source.Error!control.ProjectRow {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .name = name, .repository_url = repository_url }, .{}) catch
            return error.OutOfMemory;
        const said = try self.post(arena, "/api/projects", payload);
        const found = std.json.parseFromSliceLeaky(control.ProjectRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's project response could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn setProjectArchived(
        self: *Web,
        arena: std.mem.Allocator,
        project_id: []const u8,
        archived: bool,
    ) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .action = "set_status",
            .project_id = project_id,
            .status = if (archived) "archived" else "ready",
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/projects", payload);
        self.clear();
    }

    pub fn cancelSession(self: *Web, arena: std.mem.Allocator, session: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/cancel?session={s}{s}", .{ session, self.namedProject(arena) }) catch
            return error.OutOfMemory;
        _ = try self.post(arena, target, "");
    }

    pub fn answerAgentQuestion(
        self: *Web,
        arena: std.mem.Allocator,
        session: []const u8,
        request: u64,
        answer_text: []const u8,
    ) ui_source.Error!void {
        const target = std.fmt.allocPrint(
            arena,
            "/api/agent-answer?session={s}&request={d}{s}",
            .{ session, request, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        _ = try self.post(arena, target, answer_text);
    }

    pub fn teams(self: *Web, arena: std.mem.Allocator) ui_source.Error![]const control.TeamRow {
        const said = try self.get(arena, "/api/teams");
        const found = std.json.parseFromSliceLeaky([]const control.TeamRow, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's team list could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn createTeam(self: *Web, arena: std.mem.Allocator, name: []const u8) ui_source.Error!control.TeamRow {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .name = name }, .{}) catch return error.OutOfMemory;
        const said = try self.post(arena, "/api/teams", payload);
        const found = std.json.parseFromSliceLeaky(control.TeamRow, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's team response could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn teamPeople(self: *Web, arena: std.mem.Allocator, team: []const u8) ui_source.Error![]const control.TeamPersonRow {
        const target = std.fmt.allocPrint(arena, "/api/team-members?team={s}", .{team}) catch return error.OutOfMemory;
        const said = try self.get(arena, target);
        const found = std.json.parseFromSliceLeaky([]const control.TeamPersonRow, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's team membership could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn setTeamMember(self: *Web, arena: std.mem.Allocator, team: []const u8, identity_id: []const u8, role: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/team-members?team={s}", .{team}) catch return error.OutOfMemory;
        const payload = std.json.Stringify.valueAlloc(arena, .{ .identity_id = identity_id, .role = role }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, target, payload);
    }

    pub fn teamInvitations(self: *Web, arena: std.mem.Allocator, team: []const u8) ui_source.Error![]const TeamInvitationRow {
        const target = std.fmt.allocPrint(arena, "/api/team-invites?team={s}", .{team}) catch return error.OutOfMemory;
        const said = try self.get(arena, target);
        const found = std.json.parseFromSliceLeaky([]const TeamInvitationRow, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's team invitations could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn createTeamInvitation(self: *Web, arena: std.mem.Allocator, team: []const u8, role: []const u8) ui_source.Error!CreatedTeamInvitation {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .action = "create", .team = team, .role = role }, .{}) catch return error.OutOfMemory;
        const said = try self.post(arena, "/api/team-invites", payload);
        const found = std.json.parseFromSliceLeaky(CreatedTeamInvitation, arena, said, .{}) catch {
            self.note("the daemon's invitation response could not be read");
            return error.Refused;
        };
        if (found.id.len != 36 or found.token.len != 43 or found.expires_ms <= 0) {
            self.note("the daemon returned an invalid invitation");
            return error.Refused;
        }
        self.clear();
        return found;
    }

    pub fn redeemTeamInvitation(self: *Web, arena: std.mem.Allocator, token: []const u8) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, .{ .action = "redeem", .token = token }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/team-invites", payload);
    }

    pub fn revokeTeamInvitation(self: *Web, arena: std.mem.Allocator, team: []const u8, invitation: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/team-invites?team={s}&invitation={s}", .{ team, invitation }) catch return error.OutOfMemory;
        _ = try self.sendMethod(arena, target, .DELETE, "", &.{});
    }

    pub fn aclRules(self: *Web, arena: std.mem.Allocator, resource_kind: []const u8, resource_id: []const u8) ui_source.Error![]const AclRecord {
        const target = std.fmt.allocPrint(arena, "/api/acl-rules?resource_kind={s}&resource_id={s}", .{ resource_kind, resource_id }) catch return error.OutOfMemory;
        const said = try self.get(arena, target);
        const found = std.json.parseFromSliceLeaky([]const AclRecord, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's ACL rules could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn setAclRule(self: *Web, arena: std.mem.Allocator, resource_kind: []const u8, resource_id: []const u8, principal_kind: []const u8, principal_id: []const u8, capability: []const u8, effect: []const u8) ui_source.Error!void {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .resource_kind = resource_kind,
            .resource_id = resource_id,
            .principal_kind = principal_kind,
            .principal_id = principal_id,
            .capability = capability,
            .effect = effect,
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, "/api/acl-rules", payload);
    }

    pub fn removeAclRule(self: *Web, arena: std.mem.Allocator, rule_id: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/acl-rules?rule_id={s}", .{rule_id}) catch return error.OutOfMemory;
        _ = try self.sendMethod(arena, target, .DELETE, "", &.{});
    }

    pub fn providers(self: *Web, arena: std.mem.Allocator) ui_source.Error![]const ProviderRow {
        const said = try self.get(arena, "/api/providers");
        const found = std.json.parseFromSliceLeaky([]const ProviderRow, arena, said, .{ .ignore_unknown_fields = true }) catch {
            self.note("the daemon's providers could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn createProvider(self: *Web, arena: std.mem.Allocator, name: []const u8, provider_kind: []const u8, scope_kind: []const u8, scope_id: []const u8, configuration: []const u8, credential_ref: []const u8) ui_source.Error![]const u8 {
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .name = name,
            .provider_kind = provider_kind,
            .scope_kind = scope_kind,
            .scope_id = scope_id,
            .configuration = configuration,
            .credential_ref = credential_ref,
        }, .{}) catch return error.OutOfMemory;
        const response = try self.post(arena, "/api/providers", payload);
        const Result = struct { id: []const u8 };
        const parsed = std.json.parseFromSliceLeaky(Result, arena, response, .{}) catch {
            self.note("the daemon's provider response could not be read");
            return error.Refused;
        };
        self.clear();
        return parsed.id;
    }

    pub fn removeProvider(self: *Web, arena: std.mem.Allocator, provider_id: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/providers?provider_id={s}", .{provider_id}) catch return error.OutOfMemory;
        _ = try self.sendMethod(arena, target, .DELETE, "", &.{});
    }

    pub fn sessionPeople(
        self: *Web,
        arena: std.mem.Allocator,
        session: []const u8,
    ) ui_source.Error![]const control.SessionPersonRow {
        const target = std.fmt.allocPrint(arena, "/api/session-members?session={s}", .{session}) catch
            return error.OutOfMemory;
        const said = try self.get(arena, target);
        const found = std.json.parseFromSliceLeaky([]const control.SessionPersonRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's session people list could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn touchSessionPresence(self: *Web, arena: std.mem.Allocator, session: []const u8) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/session-presence?session={s}", .{session}) catch
            return error.OutOfMemory;
        _ = try self.post(arena, target, "");
    }

    pub fn sessionPresence(
        self: *Web,
        arena: std.mem.Allocator,
        session: []const u8,
    ) ui_source.Error![]const control.SessionPresenceRow {
        const target = std.fmt.allocPrint(arena, "/api/session-presence?session={s}", .{session}) catch
            return error.OutOfMemory;
        const said = try self.get(arena, target);
        const found = std.json.parseFromSliceLeaky([]const control.SessionPresenceRow, arena, said, .{
            .ignore_unknown_fields = true,
        }) catch {
            self.note("the daemon's session presence could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    pub fn shareSession(
        self: *Web,
        arena: std.mem.Allocator,
        session: []const u8,
        identity_id: []const u8,
        role: []const u8,
    ) ui_source.Error!void {
        const target = std.fmt.allocPrint(arena, "/api/session-members?session={s}", .{session}) catch
            return error.OutOfMemory;
        const payload = std.json.Stringify.valueAlloc(arena, .{
            .identity_id = identity_id,
            .role = role,
        }, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, target, payload);
    }

    const vtable: Source.VTable = .{
        .sessions = sessions,
        .create = create,
        .createPlaced = createPlaced,
        .events = events,
        .asks = asks,
        .prompt = prompt,
        .fork = fork,
        .review = review,
        .select = select,
        .undoSelection = undoSelection,
        .answer = answer,
        .whyLast = whyLast,
    };

    fn note(self: *Web, said: []const u8) void {
        if (self.said) |one| self.gpa.free(one);
        self.said = self.gpa.dupe(u8, said) catch null;
    }

    /// One request, with the body as an owned slice. The caller frees it.
    fn get(self: *Web, arena: std.mem.Allocator, target: []const u8) ui_source.Error![]u8 {
        if (!self.reachable()) return error.Unreachable;
        // A scheme so the client can parse it. Which scheme the browser really
        // uses is the page's own, resolved on the far side of `fetch`: see
        // phantom's `web_net.requestUrl`.
        const url = requestUrl(arena, self.origin, target) catch return error.OutOfMemory;

        var body: std.Io.Writer.Allocating = .init(arena);
        const reply = self.owner.http().fetch(.{
            .url = url,
            .response_writer = &body.writer,
        }) catch |err| {
            // The URL and the error together, because "no answer" cannot be told
            // apart from a wrong host, a wrong port, or a refused request, and
            // none of those are visible from inside the page.
            var room: [512]u8 = undefined;
            self.note(std.fmt.bufPrint(&room, "{t} asking {s}", .{ err, url }) catch
                "the daemon did not answer");
            return error.Unreachable;
        };

        if (reply.status != .ok and reply.status != .created) {
            const detail = std.mem.trim(u8, body.written(), " \t\r\n");
            var room: [512]u8 = undefined;
            self.note(if (detail.len != 0)
                std.fmt.bufPrint(&room, "{d} from {s}: {s}", .{
                    @backingInt(reply.status),
                    target,
                    detail[0..@min(detail.len, 400)],
                }) catch detail
            else
                std.fmt.bufPrint(&room, "{d} from {s}", .{
                    @backingInt(reply.status), target,
                }) catch (reply.status.phrase() orelse "the daemon refused"));
            return error.Refused;
        }
        if (body.written().len > max_reply_bytes) {
            self.note("the daemon said more than this page reads");
            return error.Refused;
        }
        return body.toOwnedSlice() catch error.OutOfMemory;
    }

    fn sessions(ptr: *anyopaque, arena: std.mem.Allocator) ui_source.Error![]const ui_source.Session {
        const self: *Web = @ptrCast(@alignCast(ptr));
        // Every project, so the picker can group them. A browser is not inside
        // one project the way a terminal is.
        const said = try self.get(arena, "/api/sessions?all=1");

        const parsed = std.json.parseFromSliceLeaky(
            std.json.Value,
            arena,
            said,
            .{ .allocate = .alloc_always },
        ) catch {
            self.note("the daemon's session list could not be read");
            return error.Refused;
        };

        const list = switch (parsed) {
            .array => |one| one,
            else => {
                self.note("the daemon answered something other than a session list");
                return error.Refused;
            },
        };

        var out: std.ArrayList(ui_source.Session) = .empty;
        for (list.items) |item| {
            const object = switch (item) {
                .object => |one| one,
                else => continue,
            };
            out.append(arena, .{
                .id = stringAt(object, "id") orelse continue,
                .started_ms = @intCast(@max(integerAt(object, "started_ms") orelse 0, 0)),
                .forked_from = stringAt(object, "forked_from") orelse "",
                .forked_at = @intCast(@max(integerAt(object, "forked_at") orelse 0, 0)),
                .model = stringAt(object, "model") orelse "",
                .title = stringAt(object, "title") orelse "",
                .project = stringAt(object, "project") orelse "",
                .project_root = stringAt(object, "project_root") orelse "",
                // A row with no `live` reads as unknown, which is what the
                // daemon means by it.
                .live = ui_source.Session.Live.fromWire(stringAt(object, "live") orelse ""),
                .turns = @intCast(@max(integerAt(object, "turns") orelse 0, 0)),
            }) catch return error.OutOfMemory;
        }
        self.clear();
        return out.items;
    }

    /// Create in the project `chock serve` was started for. Session lists may
    /// span projects, but a bare New action has that one unambiguous home.
    fn create(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
    ) ui_source.Error![]const u8 {
        return createPlaced(ptr, arena, .daemon);
    }

    fn createPlaced(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        placement: ui_source.Placement,
    ) ui_source.Error![]const u8 {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const target = std.fmt.allocPrint(arena, "/api/create?placement={s}", .{@tagName(placement)}) catch
            return error.OutOfMemory;
        const response = std.mem.trim(u8, try self.post(arena, target, ""), " \t\r\n");
        const end = std.mem.indexOfAny(u8, response, "\t\r\n") orelse response.len;
        if (end == 0) {
            self.note("the daemon returned no session identifier");
            return error.Refused;
        }
        return response[0..end];
    }

    /// Reads `/api/lines`, which answers once and closes.
    ///
    /// Not `/api/events`: that holds a stream open, and phantom's web backend
    /// reads one whole response per request. See `src/serve.zig`'s own note.
    fn events(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        session: []const u8,
        after: u64,
    ) ui_source.Error![]const ui_source.Entry {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const said = try self.get(arena, std.fmt.allocPrint(
            arena,
            "/api/lines?session={s}&after={d}{s}",
            .{ session, after, self.namedProject(arena) },
        ) catch return error.OutOfMemory);
        return self.envelopesIn(arena, said);
    }

    /// The envelopes in one reply, as the interface draws them.
    fn envelopesIn(
        self: *Web,
        arena: std.mem.Allocator,
        said: []const u8,
    ) ui_source.Error![]const ui_source.Entry {
        const found = entriesIn(arena, said) orelse {
            self.note("the daemon's events could not be read");
            return error.Refused;
        };
        self.clear();
        return found;
    }

    /// The questions still waiting, worked out from the events themselves.
    ///
    /// The daemon has no verb for "what is pending", so this reads the session's
    /// events and keeps every `approval_request` that no later
    /// `approval_response` names. An `ApprovalRequest` carries no id of its own:
    /// the envelope's id is what a response cites.
    fn asks(ptr: *anyopaque, arena: std.mem.Allocator) ui_source.Error![]const ui_source.Ask {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const session = self.watching orelse {
            // Nothing is being watched, so nothing is waiting on an answer.
            self.clear();
            return &.{};
        };

        const said = try self.get(arena, std.fmt.allocPrint(
            arena,
            "/api/lines?session={s}&after=0{s}",
            .{ session, self.namedProject(arena) },
        ) catch return error.OutOfMemory);
        const entries = try self.envelopesIn(arena, said);

        var waiting: std.ArrayList(ui_source.Ask) = .empty;
        var answered: std.ArrayList(u64) = .empty;

        for (entries) |one| switch (one.ev) {
            .approval_request => |asked| waiting.append(arena, .{
                .session = session,
                .request = one.at,
                .action = asked.action,
                .summary = asked.summary,
                .detail = asked.detail,
                .reason = asked.reason,
                .timeout_at_ms = asked.timeout_at_ms,
            }) catch return error.OutOfMemory,
            // Zero names no request, which is the table answering alone, so it
            // retires nothing.
            .approval_response => |given| if (given.request_id != 0)
                answered.append(arena, given.request_id) catch return error.OutOfMemory,
            else => {},
        };

        var out: std.ArrayList(ui_source.Ask) = .empty;
        for (waiting.items) |one| {
            if (std.mem.indexOfScalar(u64, answered.items, one.request) != null) continue;
            out.append(arena, one) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// POST `/api/prompt`, the message in the body because a prompt is as long
    /// as a person wants and a URL is not.
    fn prompt(ptr: *anyopaque, session: []const u8, message: []const u8) ui_source.Error!void {
        const self: *Web = @ptrCast(@alignCast(ptr));

        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();
        const arena = room.allocator();

        const target = std.fmt.allocPrint(
            arena,
            "/api/prompt?session={s}{s}",
            .{ session, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        _ = try self.post(arena, target, message);
    }

    fn fork(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        session: []const u8,
        at: ?u64,
    ) ui_source.Error![]const u8 {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const at_query = if (at) |offset|
            std.fmt.allocPrint(arena, "&at={d}", .{offset}) catch return error.OutOfMemory
        else
            "";
        const target = std.fmt.allocPrint(
            arena,
            "/api/fork?session={s}{s}{s}",
            .{ session, at_query, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        const response = std.mem.trim(u8, try self.post(arena, target, ""), " \t\r\n");
        const end = std.mem.indexOfAny(u8, response, "\t\r\n") orelse response.len;
        if (end == 0) {
            self.note("the daemon returned no child session identifier");
            return error.Refused;
        }
        return response[0..end];
    }

    fn review(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        session: []const u8,
    ) ui_source.Error!ui_source.Review {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const target = std.fmt.allocPrint(
            arena,
            "/api/workspace/review?session={s}{s}",
            .{ session, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        const said = try self.get(arena, target);
        const parsed = std.json.parseFromSliceLeaky(
            []ui_source.Review,
            arena,
            said,
            .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
        ) catch {
            self.note("the workspace review could not be read");
            return error.Refused;
        };
        if (parsed.len != 1) {
            self.note("the daemon returned no workspace review");
            return error.Refused;
        }
        self.clear();
        return parsed[0];
    }

    fn select(ptr: *anyopaque, session: []const u8, selection: ui_source.Selection) ui_source.Error!void {
        const self: *Web = @ptrCast(@alignCast(ptr));
        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();
        const arena = room.allocator();
        const target = std.fmt.allocPrint(
            arena,
            "/api/workspace/select?session={s}{s}",
            .{ session, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        const payload = std.json.Stringify.valueAlloc(arena, selection, .{}) catch return error.OutOfMemory;
        _ = try self.post(arena, target, payload);
    }

    fn undoSelection(ptr: *anyopaque, session: []const u8) ui_source.Error!void {
        const self: *Web = @ptrCast(@alignCast(ptr));
        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();
        const arena = room.allocator();
        const target = std.fmt.allocPrint(
            arena,
            "/api/workspace/undo?session={s}{s}",
            .{ session, self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        _ = try self.post(arena, target, "");
    }

    fn answer(
        ptr: *anyopaque,
        session: []const u8,
        request: u64,
        decision: ui_source.Decision,
    ) ui_source.Error!void {
        const self: *Web = @ptrCast(@alignCast(ptr));

        var room = std.heap.ArenaAllocator.init(self.gpa);
        defer room.deinit();
        const arena = room.allocator();

        const target = std.fmt.allocPrint(
            arena,
            "/api/answer?session={s}&request={d}&decision={s}{s}",
            .{ session, request, @tagName(decision), self.namedProject(arena) },
        ) catch return error.OutOfMemory;
        _ = try self.post(arena, target, "");
    }

    /// Ask for something that changes a session, and say plainly when it did not
    /// happen.
    ///
    /// A POST and not a GET: a decision and a message both change what a session
    /// does, and anything that prefetches a link would drive a GET that did.
    fn post(
        self: *Web,
        arena: std.mem.Allocator,
        target: []const u8,
        payload: []const u8,
    ) ui_source.Error![]const u8 {
        return self.sendMethod(arena, target, .POST, payload, &.{});
    }

    fn sendMethod(
        self: *Web,
        arena: std.mem.Allocator,
        target: []const u8,
        method: std.http.Method,
        payload: []const u8,
        extra_headers: []const std.http.Header,
    ) ui_source.Error![]const u8 {
        if (!self.reachable()) return error.Unreachable;
        const url = requestUrl(arena, self.origin, target) catch return error.OutOfMemory;

        var body: std.Io.Writer.Allocating = .init(arena);
        const reply = self.owner.http().fetch(.{
            .url = url,
            .method = method,
            // Keep an empty POST body present. On native std.http this emits a
            // zero content length; treating it as null leaves a body-bearing
            // method underspecified and can trip the Android client assertion.
            .payload = payload,
            .extra_headers = extra_headers,
            .response_writer = &body.writer,
        }) catch |err| {
            // The error and the address together. Without them a refused
            // request, a wrong host and a daemon that is not there all read the
            // same from inside the page, and none of the three is visible here.
            var room: [512]u8 = undefined;
            self.note(std.fmt.bufPrint(&room, "{t} asking {s}", .{ err, url }) catch
                "the daemon did not answer");
            return error.Unreachable;
        };

        if (reply.status != .ok) {
            // The daemon's own words, which say which of its rules refused. The
            // status phrase only ever says "Conflict".
            const said = std.mem.trim(u8, body.written(), " \t\r\n");
            var room: [512]u8 = undefined;
            self.note(if (said.len != 0)
                std.fmt.bufPrint(&room, "{d} from {s}: {s}", .{
                    @backingInt(reply.status),
                    target,
                    said[0..@min(said.len, 400)],
                }) catch said
            else
                std.fmt.bufPrint(&room, "{d} from {s}", .{
                    @backingInt(reply.status), target,
                }) catch (reply.status.phrase() orelse "the daemon refused"));
            return error.Refused;
        }
        self.clear();
        return body.written();
    }

    pub fn whyLast(ptr: *anyopaque) ?[]const u8 {
        const self: *Web = @ptrCast(@alignCast(ptr));
        return self.said;
    }

    pub fn lastError(self: *const Web) ?[]const u8 {
        return self.said;
    }

    fn clear(self: *Web) void {
        if (self.said) |one| self.gpa.free(one);
        self.said = null;
    }
};

fn stringAt(object: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const got = object.get(name) orelse return null;
    return switch (got) {
        .string => |one| one,
        else => null,
    };
}

fn integerAt(object: std.json.ObjectMap, name: []const u8) ?i64 {
    const got = object.get(name) orelse return null;
    return switch (got) {
        .integer => |one| one,
        else => null,
    };
}

/// The entries in one reply, or null when it is not a list of envelopes.
///
/// Parsed into `event.Envelope` and not read field by field. The log's own type
/// is what the interface already knows how to draw, and a reader here that
/// picked out a name and a line of text would be a second renderer drifting
/// from the first.
fn entriesIn(arena: std.mem.Allocator, said: []const u8) ?[]const ui_source.Entry {
    const parsed = std.json.parseFromSliceLeaky(
        []event.Envelope,
        arena,
        said,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
    ) catch return null;

    const out = arena.alloc(ui_source.Entry, parsed.len) catch return null;
    for (parsed, out) |envelope, *one| {
        one.* = .{ .at = envelope.id, .time_ms = envelope.time_ms, .ev = envelope.event };
    }
    return out;
}

const testing = std.testing;

test "native server URLs preserve HTTPS while browser hosts get a placeholder scheme" {
    const arena = testing.allocator;
    const secure = try requestUrl(arena, "https://daemon.example:7374", "/api/projects");
    defer arena.free(secure);
    try testing.expectEqualStrings("https://daemon.example:7374/api/projects", secure);

    const local = try requestUrl(arena, "192.168.1.20:7374", "/api/projects");
    defer arena.free(local);
    try testing.expectEqualStrings("http://192.168.1.20:7374/api/projects", local);
}

test "a reply is read as the events the log holds, not as words about them" {
    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();
    const arena = room.allocator();

    const said =
        \\[{"id":4096,"session":"01JQ","time_ms":1700000000000,"event":
        \\{"message":{"role":"assistant","content":[{"text":"the parser is fixed"}]}}},
        \\{"id":4200,"session":"01JQ","time_ms":1700000001000,"event":
        \\{"tool.call":{"call_id":"c1","tool":"fs.read","arguments":"{\"path\":\"src/main.zig\"}"}}}]
    ;

    const found = entriesIn(arena, said) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 2), found.len);

    // The event itself, so the interface draws it the way a terminal does.
    try testing.expectEqual(@as(u64, 4096), found[0].at);
    try testing.expectEqual(@as(i64, 1700000000000), found[0].time_ms);
    try testing.expectEqualStrings("the parser is fixed", found[0].ev.message.content[0].text);

    try testing.expectEqual(@as(u64, 4200), found[1].at);
    try testing.expectEqualStrings("fs.read", found[1].ev.tool_call.tool);
}

test "a reply that is not a list of envelopes is refused rather than half read" {
    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();

    try testing.expectEqual(
        @as(?[]const ui_source.Entry, null),
        entriesIn(room.allocator(), "{\"error\":\"no such session\"}"),
    );
}

test "a field this build does not know does not throw the whole event away" {
    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();
    const arena = room.allocator();

    const said =
        \\[{"id":1,"session":"01JQ","time_ms":5,"invented_field":true,
        \\"event":{"message":{"role":"user","content":[{"text":"hello"}]}}}]
    ;
    const found = entriesIn(arena, said) orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("hello", found[0].ev.message.content[0].text);
}

test "a cross-project request escapes every query delimiter in its path" {
    var web = Web{
        .gpa = testing.allocator,
        .owner = undefined,
        .origin = "",
        .watching_project = try testing.allocator.dupe(u8, "/work/a & b/%23#one?two"),
    };
    defer web.deinit();

    var room = std.heap.ArenaAllocator.init(testing.allocator);
    defer room.deinit();
    const expected = "&project=%2Fwork%2Fa%20%26%20b%2F%2523%23one%3Ftwo";
    try testing.expectEqualStrings(expected, web.namedProject(room.allocator()));
    try testing.expectEqualStrings(expected, web.eventsProject());
}
