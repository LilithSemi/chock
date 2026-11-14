//! The page a person uses: the interface the terminal and the window draw, fed
//! from `chock serve`.
//!
//! The app-owned routes share `chock-ui`'s responsive navigation scaffold;
//! sessions use the same `Ui` and event replay as a native run. This file wires
//! the shell, route state, daemon source, and live event stream together.
//!
//! Stateful, because the interface outlives a frame and only a `State` can ask
//! for the next one.

const std = @import("std");
const phantom = @import("phantom");
const chock_ui = @import("chock-ui");
const chock_proto = @import("chock-proto");
const event = chock_proto.event;

const web_source = @import("source.zig");
const web_host = @import("host.zig");

/// A scroll view at least as tall as the viewport, so the card inside it can be
/// centred while taller content still scrolls.
fn fillViewport(view: phantom.ScrollView) phantom.ScrollView {
    var filled = view;
    filled.fill_viewport = true;
    return filled;
}

pub const App = struct {
    /// Empty in a browser, where the page's own host is the API host. Native
    /// clients name the `chock serve` host explicitly (without a scheme).
    api_host: []const u8 = "",
    /// Browsers have EventSource. Native clients follow the same log through
    /// the bounded `/api/lines` endpoint instead.
    poll_events: bool = false,

    pub fn widget(self: *const App) phantom.Widget {
        return phantom.stateful.statefulWidget(App, self);
    }

    pub const State = struct {
        const Destination = enum { sessions, projects, teams, people, providers };

        base: phantom.StateBase = .{},
        reaching: ?web_source.Web = null,
        from_host: ?web_host.Web = null,
        ui: ?*chock_ui.Ui = null,
        auth_status: ?web_source.Web.AuthStatus = null,
        auth_status_mode: ?[]u8 = null,
        auth_status_loaded: bool = false,
        auth_failed: bool = false,
        auth_oidc_configured: bool = false,
        setup_oidc_mode: bool = false,
        auth_message: []const u8 = "",
        auth_username: phantom.TextFieldController = .{},
        auth_password: phantom.TextFieldController = .{},
        account_current_password: phantom.TextFieldController = .{},
        account_new_password: phantom.TextFieldController = .{},
        account_confirm_password: phantom.TextFieldController = .{},
        account_message: []const u8 = "",
        account_failed: bool = false,
        account_status_loaded: bool = false,
        account_status_mode: ?[]u8 = null,
        oidc_provider: phantom.TextFieldController = .{},
        oidc_issuer: phantom.TextFieldController = .{},
        oidc_discovery_url: phantom.TextFieldController = .{},
        oidc_client_id: phantom.TextFieldController = .{},
        oidc_client_secret: phantom.TextFieldController = .{},
        oidc_admin_subject: phantom.TextFieldController = .{},
        /// The session being read, owned, because the row it came from is
        /// rebuilt every frame.
        opened: ?[]u8 = null,
        /// The stream carrying that session's events, closed when another
        /// session is opened.
        stream: ?phantom.EventSource = null,
        poll: ?phantom.Scheduler.Handle = null,
        presence_poll: ?phantom.Scheduler.Handle = null,
        presence_json: ?[]u8 = null,
        presence_failed: bool = false,
        api_host: []const u8 = "",
        poll_events: bool = false,
        poll_failed: bool = false,
        projects_open: bool = false,
        projects_loaded: bool = false,
        projects_failed: bool = false,
        project_rows: []chock_proto.control.ProjectRow = &.{},
        project_name: phantom.TextFieldController = .{},
        project_root: phantom.TextFieldController = .{},
        project_repository_url: phantom.TextFieldController = .{},
        project_import_root: phantom.TextFieldController = .{},
        project_import_session: phantom.TextFieldController = .{},
        project_message: []const u8 = "",
        project_acl_open: bool = false,
        selected_project: ?[]u8 = null,
        project_acl_json: ?[]u8 = null,
        project_acl_loaded: bool = false,
        project_acl_failed: bool = false,
        project_acl_message: []const u8 = "",
        teams_open: bool = false,
        teams_loaded: bool = false,
        teams_failed: bool = false,
        team_rows: []chock_proto.control.TeamRow = &.{},
        team_actions: []TeamAction = &.{},
        team_name: phantom.TextFieldController = .{},
        team_invite_token_input: phantom.TextFieldController = .{},
        selected_team: ?[]u8 = null,
        team_people_loaded: bool = false,
        team_people_failed: bool = false,
        team_people: []chock_proto.control.TeamPersonRow = &.{},
        team_person_actions: []TeamPersonAction = &.{},
        team_invites_json: ?[]u8 = null,
        team_invites_loaded: bool = false,
        team_invites_failed: bool = false,
        created_team_invite_token: ?[]u8 = null,
        team_acl_json: ?[]u8 = null,
        team_acl_loaded: bool = false,
        team_acl_failed: bool = false,
        acl_principal_kind: phantom.TextFieldController = .{},
        acl_principal_id: phantom.TextFieldController = .{},
        acl_effect: phantom.TextFieldController = .{},
        acl_capability: phantom.TextFieldController = .{},
        team_message: []const u8 = "",
        people_open: bool = false,
        people_loaded: bool = false,
        people_failed: bool = false,
        people_json: ?[]u8 = null,
        people_actions: []PersonAction = &.{},
        people_message: []const u8 = "",
        local_accounts_enabled: bool = false,
        local_account_username: phantom.TextFieldController = .{},
        local_account_password: phantom.TextFieldController = .{},
        providers_open: bool = false,
        providers_loaded: bool = false,
        providers_failed: bool = false,
        providers_json: ?[]u8 = null,
        providers_message: []const u8 = "",
        provider_name: phantom.TextFieldController = .{},
        provider_kind: phantom.TextFieldController = .{},
        provider_scope: phantom.TextFieldController = .{},
        provider_scope_id: phantom.TextFieldController = .{},
        provider_configuration: phantom.TextFieldController = .{},
        provider_credential_ref: phantom.TextFieldController = .{},
        provider_acl_open: bool = false,
        selected_provider: ?[]u8 = null,
        provider_acl_json: ?[]u8 = null,
        provider_acl_loaded: bool = false,
        provider_acl_failed: bool = false,
        provider_acl_message: []const u8 = "",
        share_open: bool = false,
        pending_question_id: ?u64 = null,
        share_people_loaded: bool = false,
        share_people_failed: bool = false,
        share_people: []chock_proto.control.SessionPersonRow = &.{},
        share_actions: []ShareAction = &.{},
        share_message: []const u8 = "",
        session_acl_json: ?[]u8 = null,
        session_acl_loaded: bool = false,
        session_acl_failed: bool = false,
        session_acl_message: []const u8 = "",
        worker_credential: ?[]u8 = null,
        worker_credential_expires_ms: i64 = 0,
        /// The offset of the newest event drawn.
        ///
        /// A browser reopens a dropped stream by itself and the daemon starts
        /// again from the top, so without this the whole transcript appears a
        /// second time after any hiccup.
        seen: u64 = 0,

        var origin_buffer: [512]u8 = undefined;
        var location_buffer: [512]u8 = undefined;

        /// What the address bar says when a session is open. Under phantom's
        /// default strategy this lands in the fragment, so the daemon never sees
        /// it and a reload comes back to the same session.
        const session_path = "/s/";

        const ShareAction = struct {
            state: *State,
            person_index: usize,
            role: []const u8,
        };

        const TeamAction = struct { state: *State, team_id: []const u8 };
        const PersonAction = struct {
            state: *State,
            identity_id: []const u8,
            instance_admin: bool = false,
            local_account: bool = false,
            local_account_disabled: bool = false,
            password: phantom.TextFieldController = .{},
        };
        const ProjectAclAction = struct { state: *State, project_id: []const u8 };
        const ProjectStatusAction = struct { state: *State, project_id: []const u8, archive: bool };
        const ProjectLaunchAction = struct {
            state: *State,
            project_root: []const u8,
            placement: chock_ui.source.Placement,
        };
        const ProviderAction = struct { state: *State, provider_id: []const u8 };
        const TeamPersonAction = struct { state: *State, team_id: []const u8, identity_id: []const u8 };
        const TeamInviteAction = struct { state: *State, team_id: []const u8, invitation_id: []const u8 };
        const AclRemoveAction = struct { state: *State, rule_id: []const u8 };

        pub fn initState(self: *State, config: *const App) !void {
            self.api_host = config.api_host;
            self.poll_events = config.poll_events;
        }

        pub fn didUpdateWidget(self: *State, config: *const App) !void {
            self.api_host = config.api_host;
            self.poll_events = config.poll_events;
        }

        pub fn dispose(self: *State) void {
            const gpa = self.base.element.owner.gpa;
            self.closeStream();
            if (self.ui) |one| one.deinit();
            if (self.opened) |one| gpa.free(one);
            self.clearSharePeople();
            self.clearSessionAcl();
            self.clearProjectRows();
            self.clearWorkerCredential();
            self.clearTeams();
            self.clearTeamInvites();
            self.clearCreatedTeamInvite();
            self.clearTeamAcl();
            self.clearProjectAcl();
            self.clearPeople();
            if (self.selected_project) |project_id| gpa.free(project_id);
            self.clearProviders();
            self.clearProviderAcl();
            if (self.selected_provider) |provider_id| gpa.free(provider_id);
            if (self.selected_team) |team_id| gpa.free(team_id);
            if (self.reaching) |*one| one.deinit();
            if (self.auth_status_mode) |mode| gpa.free(mode);
            if (self.account_status_mode) |mode| gpa.free(mode);
        }

        pub fn build(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const ui = self.interface() orelse
                return ctx.new(phantom.Text{ .text = "out of memory" }).widget();

            if (self.isAccountSettingsPath()) return self.accountSettingsView(ctx);

            // Authentication and first-run setup are entry pages, not views in
            // the signed-in application shell. Keep them focused and avoid
            // constructing project/session navigation before authentication.
            if (self.authEntryPath()) |path| {
                return self.authEntryView(ctx, std.mem.eql(u8, path, "/setup"));
            }

            return chock_ui.Ui.rootWithBody(ctx, ui, .{
                .ctx = self,
                .build = buildApplicationBody,
            });
        }

        fn buildApplicationBody(ptr: ?*anyopaque, ctx: *phantom.BuildContext) phantom.Widget {
            const self: *State = @ptrCast(@alignCast(ptr.?));
            const body = self.buildRoute(ctx) catch ctx.new(phantom.Text{
                .text = "The application view could not be built.",
                .color = phantom.ColorScheme.tokyoNight().red,
            }).widget();
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{
                    .text = "Chock",
                    .size = 20,
                    .color = phantom.ColorScheme.tokyoNight().fg,
                }).widget() })).widget(),
                ctx.new(phantom.Button{
                    .id = "account-settings",
                    .variant = .secondary,
                    .on_tap = onOpenAccountSettings,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Account settings" }).widget(),
                }).widget(),
            }) })).widget()) catch {};
            if (self.opened != null) children.append(ctx.arena, self.presenceStrip(ctx)) catch {};
            children.append(ctx.arena, ctx.new(phantom.Expanded(.{ .child = body })).widget()) catch {};
            return ctx.new(phantom.Column(.{ .children = children.items })).widget();
        }

        fn presenceStrip(self: *State, ctx: *phantom.BuildContext) phantom.Widget {
            const colors = phantom.ColorScheme.tokyoNight();
            var summary: []const u8 = if (self.presence_failed)
                "Collaborator presence is temporarily unavailable."
            else
                "Checking who is here…";
            if (self.presence_json) |json| {
                const rows = std.json.parseFromSliceLeaky([]const chock_proto.control.SessionPresenceRow, ctx.arena, json, .{
                    .ignore_unknown_fields = true,
                }) catch &.{};
                if (rows.len == 0) {
                    summary = "No collaborators are online.";
                } else {
                    var names: std.ArrayList([]const u8) = .empty;
                    for (rows) |row| {
                        const label = if (row.display_name.len != 0)
                            row.display_name
                        else
                            row.identity_id[0..@min(row.identity_id.len, 8)];
                        names.append(ctx.arena, label) catch continue;
                    }
                    const joined = std.mem.join(ctx.arena, ", ", names.items) catch "";
                    summary = std.fmt.allocPrint(ctx.arena, "Here now: {s}", .{joined}) catch "Collaborators are online.";
                }
            }
            return ctx.new(phantom.Padding{
                .insets = .{ .top = 4, .bottom = 8 },
                .child = ctx.new(phantom.Text{
                    .text = summary,
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget();
        }

        fn isAccountSettingsPath(self: *State) bool {
            const said = self.base.element.owner.platform.readLocation(&location_buffer) orelse return false;
            const path = said[0 .. std.mem.indexOfScalar(u8, said, '?') orelse said.len];
            return std.mem.eql(u8, path, "/account");
        }

        fn accountSettingsView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const colors = phantom.ColorScheme.tokyoNight();
            var mode: ?web_source.Web.AuthStatus = null;
            if (!self.account_status_loaded) {
                self.account_status_loaded = true;
                if (self.reaching) |*reaching| {
                    const status = reaching.authStatus(ctx.arena) catch blk: {
                        self.account_failed = true;
                        self.account_message = reaching.lastError() orelse "The service account settings could not be loaded.";
                        break :blk null;
                    };
                    if (status) |found| {
                        self.account_status_mode = self.base.gpa().dupe(u8, found.mode) catch null;
                        if (self.account_status_mode == null) {
                            self.account_failed = true;
                            self.account_message = "The service account settings could not be retained.";
                        } else {
                            self.account_failed = false;
                            self.account_message = "";
                        }
                    }
                }
            }
            if (self.account_status_mode) |account_mode|
                mode = .{ .mode = account_mode, .setup = false };
            var children: std.ArrayList(phantom.Widget) = .empty;
            try children.append(ctx.arena, ctx.new(phantom.Text{
                .text = "Account settings",
                .size = 30,
                .color = colors.fg,
            }).widget());
            try children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 16 },
                .child = ctx.new(phantom.Text{
                    .text = "Manage the credentials for your Chock service account.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget());
            if (self.account_message.len != 0) {
                try children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = self.account_message,
                    .wrap = true,
                    .color = if (self.account_failed) colors.red else colors.green,
                }).widget());
            }
            if (mode) |status| {
                if (std.mem.eql(u8, status.mode, "local")) {
                    inline for (.{
                        .{ "chock-account-current-password", "Current password", &self.account_current_password },
                        .{ "chock-account-new-password", "New password (12 or more characters)", &self.account_new_password },
                        .{ "chock-account-confirm-password", "Confirm new password", &self.account_confirm_password },
                    }) |field| {
                        try children.append(ctx.arena, ctx.new(phantom.Padding{
                            .insets = .{ .bottom = 10 },
                            .child = ctx.new(phantom.TextField{
                                .id = field[0],
                                .placeholder = field[1],
                                .controller = field[2],
                                .obscure = true,
                                .ctx = self,
                            }).widget(),
                        }).widget());
                    }
                    try children.append(ctx.arena, ctx.new(phantom.Text{
                        .text = "Changing your password keeps this device signed in and signs out your other active sessions.",
                        .wrap = true,
                        .color = colors.fg_muted,
                    }).widget());
                    try children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .top = 12, .bottom = 12 },
                        .child = ctx.new(phantom.Button{
                            .id = "change-account-password",
                            .variant = .primary,
                            .on_tap = onChangeLocalPassword,
                            .ctx = self,
                            .child = ctx.new(phantom.Text{ .text = "Change password" }).widget(),
                        }).widget(),
                    }).widget());
                } else if (std.mem.eql(u8, status.mode, "oidc")) {
                    try children.append(ctx.arena, ctx.new(phantom.Text{
                        .text = "Your password and recovery options are managed by the configured identity provider.",
                        .wrap = true,
                        .color = colors.fg_muted,
                    }).widget());
                } else {
                    try children.append(ctx.arena, ctx.new(phantom.Text{
                        .text = "This Chock installation does not use service-managed accounts.",
                        .wrap = true,
                        .color = colors.fg_muted,
                    }).widget());
                }
            } else if (self.account_message.len == 0) {
                try children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "The service account settings could not be loaded.",
                    .wrap = true,
                    .color = colors.red,
                }).widget());
            }
            try children.append(ctx.arena, ctx.new(phantom.Button{
                .variant = .secondary,
                .on_tap = onReturnFromAccountSettings,
                .ctx = self,
                .child = ctx.new(phantom.Text{ .text = "Back to Chock" }).widget(),
            }).widget());
            return ctx.new(phantom.Padding{
                .insets = .all(24),
                .child = ctx.new(phantom.Center(.{ .child = ctx.new(phantom.SizedBox{
                    .width = 480,
                    .child = ctx.new(phantom.Column(.{ .children = children.items })).widget(),
                }).widget() })).widget(),
            }).widget();
        }

        fn buildRoute(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const ui = self.interface() orelse
                return ctx.new(phantom.Text{ .text = "out of memory" }).widget();

            // The service entry routes are pages of this same Phantom app,
            // not a second HTML implementation. The server redirects an
            // authenticated browser to `/`, while first-run and signed-out
            // browsers arrive here and build their forms as Phantom widgets.
            if (self.authEntryPath()) |path| {
                return self.authEntryView(ctx, std.mem.eql(u8, path, "/setup"));
            }

            self.followCreate(ctx.arena, ui);
            self.followPick(ui);
            self.followSubmit(ctx.arena, ui);
            if (ui.takeSessionsRequest()) {
                self.selectDestination(.sessions);
            }
            if (ui.takeProjectsRequest()) {
                self.selectDestination(.projects);
                self.projects_loaded = false;
                self.project_message = "";
            }
            if (ui.takeTeamsRequest()) {
                self.selectDestination(.teams);
                self.teams_loaded = false;
                self.team_message = "";
            }
            if (ui.takePeopleRequest()) {
                self.selectDestination(.people);
                self.people_loaded = false;
                self.people_message = "";
            }
            if (ui.takeProvidersRequest()) {
                self.selectDestination(.providers);
                self.providers_loaded = false;
                self.providers_message = "";
            }
            if (self.providers_open) return self.providersView(ctx);
            if (self.projects_open) return self.projectsView(ctx);
            if (self.teams_open) return self.teamsView(ctx);
            if (self.people_open) return self.peopleView(ctx);
            if (ui.takeShareRequest() and self.opened != null) {
                self.share_open = true;
                self.share_people_loaded = false;
                self.share_message = "";
            }
            if (self.share_open) return self.shareView(ctx);
            return chock_ui.Ui.rootOf(ctx, ui);
        }

        fn authEntryPath(self: *State) ?[]const u8 {
            const said = self.base.element.owner.platform.readLocation(&location_buffer) orelse return null;
            const path = said[0 .. std.mem.indexOfScalar(u8, said, '?') orelse said.len];
            if (std.mem.eql(u8, path, "/setup") or std.mem.eql(u8, path, "/auth/login")) return path;
            return null;
        }

        fn keepAuthStatus(self: *State, status: web_source.Web.AuthStatus) error{OutOfMemory}!void {
            const kept = try self.base.gpa().dupe(u8, status.mode);
            if (self.auth_status_mode) |old| self.base.gpa().free(old);
            self.auth_status_mode = kept;
            self.auth_status = .{ .mode = kept, .setup = status.setup };
        }

        fn authEntryView(self: *State, ctx: *phantom.BuildContext, setup_route: bool) anyerror!phantom.Widget {
            if (!self.auth_status_loaded) {
                self.auth_status_loaded = true;
                const status = self.reaching.?.authStatus(ctx.arena) catch blk: {
                    self.auth_failed = true;
                    self.auth_message = self.reaching.?.lastError() orelse "The service could not be reached.";
                    break :blk null;
                };
                if (status) |found| self.keepAuthStatus(found) catch {
                    self.auth_failed = true;
                    self.auth_message = "The service authentication status could not be retained.";
                };
            }
            const colors = phantom.ColorScheme.tokyoNight();
            var children: std.ArrayList(phantom.Widget) = .empty;
            const setup = self.auth_status != null and self.auth_status.?.setup;
            children.append(ctx.arena, ctx.new(phantom.Text{
                .text = if (setup)
                    "Set up Chock service"
                else if (self.auth_status != null and std.mem.eql(u8, self.auth_status.?.mode, "single-user"))
                    "Sign-in is not configured"
                else
                    "Sign in to Chock",
                .size = 32,
                .color = colors.fg,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 20 },
                .child = ctx.new(phantom.Text{
                    .text = if (setup)
                        "Choose how people will sign in. You can use Chock-managed accounts or connect an OpenID Connect provider."
                    else
                        "Sign in with your Chock service account.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget()) catch {};

            if (setup) {
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .bottom = 16 },
                    .child = ctx.new(phantom.Column(.{ .children = ctx.newSlice(phantom.Widget, &.{
                        ctx.new(phantom.Button{
                            .variant = if (self.setup_oidc_mode) .secondary else .primary,
                            .padding = .symmetric(16, 10),
                            .on_tap = onSetupLocalMode,
                            .ctx = self,
                            .child = ctx.new(phantom.Text{ .text = "Use Chock-managed accounts" }).widget(),
                        }).widget(),
                        ctx.new(phantom.Padding{
                            .insets = .{ .top = 8 },
                            .child = ctx.new(phantom.Button{
                                .variant = if (self.setup_oidc_mode) .primary else .secondary,
                                .padding = .symmetric(16, 10),
                                .on_tap = onSetupOidcMode,
                                .ctx = self,
                                .child = ctx.new(phantom.Text{ .text = "Connect an identity provider" }).widget(),
                            }).widget(),
                        }).widget(),
                    }) })).widget(),
                }).widget()) catch {};
            }

            if (self.auth_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = self.auth_message,
                    .wrap = true,
                    .color = colors.red,
                }).widget()) catch {};
            } else if (self.auth_oidc_configured) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "The identity provider configuration was accepted. Continue to sign in with the provider.",
                    .wrap = true,
                    .color = colors.green,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 12 },
                    .child = ctx.new(phantom.Button{
                        .variant = .primary,
                        .padding = .symmetric(16, 10),
                        .on_tap = onContinueToIdentityProvider,
                        .ctx = self,
                        .child = ctx.new(phantom.Text{ .text = "Continue to identity provider" }).widget(),
                    }).widget(),
                }).widget()) catch {};
            } else if (self.auth_status != null and std.mem.eql(u8, self.auth_status.?.mode, "single-user")) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "This daemon serves its owner directly and does not use service accounts.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Button{
                    .variant = .primary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onContinueToDaemon,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Continue" }).widget(),
                }).widget()) catch {};
            } else if (setup_route and !setup) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "Initial setup has already been completed. Continue to sign in.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Button{
                    .variant = .primary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onContinueToSignIn,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Continue to sign in" }).widget(),
                }).widget()) catch {};
            } else if (!setup_route and setup) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "The service needs its first administrator before anyone can sign in.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Button{
                    .variant = .primary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onGoToSetup,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Set up service" }).widget(),
                }).widget()) catch {};
            } else if (setup and !self.setup_oidc_mode) {
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 8 },
                    .child = ctx.new(phantom.Text{ .text = "Create your administrator account", .size = 22, .color = colors.fg }).widget(),
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{
                    .id = "chock-initial-admin-username",
                    .placeholder = "Administrator username",
                    .controller = &self.auth_username,
                    .ctx = self,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{
                    .id = "chock-initial-admin-password",
                    .placeholder = "Password (at least 12 characters)",
                    .obscure = true,
                    .controller = &self.auth_password,
                    .ctx = self,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 18 },
                    .child = ctx.new(phantom.Button{
                        .variant = .primary,
                        .padding = .symmetric(16, 10),
                        .on_tap = onServiceLocalSetup,
                        .ctx = self,
                        .child = ctx.new(phantom.Text{ .text = "Create administrator" }).widget(),
                    }).widget(),
                }).widget()) catch {};
            } else if (setup and self.setup_oidc_mode) {
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 8 },
                    .child = ctx.new(phantom.Text{ .text = "Connect an identity provider", .size = 22, .color = colors.fg }).widget(),
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "Supported providers: Kanidm, Authentik, and Authelia. Configure the public service URL before enabling OIDC.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget()) catch {};
                inline for (.{
                    .{ "chock-oidc-provider", "Provider (kanidm, authentik, or authelia)", &self.oidc_provider },
                    .{ "chock-oidc-issuer", "Issuer URL", &self.oidc_issuer },
                    .{ "chock-oidc-discovery", "Discovery URL (optional)", &self.oidc_discovery_url },
                    .{ "chock-oidc-client-id", "Client ID", &self.oidc_client_id },
                    .{ "chock-oidc-client-secret", "Client secret (if required)", &self.oidc_client_secret },
                    .{ "chock-oidc-admin-subject", "Initial administrator subject (sub)", &self.oidc_admin_subject },
                }) |field| {
                    children.append(ctx.arena, ctx.new(phantom.TextField{
                        .id = field[0],
                        .placeholder = field[1],
                        .text = if (std.mem.eql(u8, field[0], "chock-oidc-provider")) "kanidm" else "",
                        .controller = field[2],
                        .ctx = self,
                        .obscure = std.mem.eql(u8, field[0], "chock-oidc-client-secret"),
                    }).widget()) catch {};
                }
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 18 },
                    .child = ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(16, 10),
                        .on_tap = onServiceOidcSetup,
                        .ctx = self,
                        .child = ctx.new(phantom.Text{ .text = "Validate and enable OIDC" }).widget(),
                    }).widget(),
                }).widget()) catch {};
            } else if (self.auth_status != null and std.mem.eql(u8, self.auth_status.?.mode, "local")) {
                children.append(ctx.arena, ctx.new(phantom.TextField{
                    .id = "chock-login-username",
                    .placeholder = "Username",
                    .controller = &self.auth_username,
                    .ctx = self,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{
                    .id = "chock-login-password",
                    .placeholder = "Password",
                    .obscure = true,
                    .controller = &self.auth_password,
                    .ctx = self,
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 12 },
                    .child = ctx.new(phantom.Button{
                        .variant = .primary,
                        .padding = .symmetric(16, 10),
                        .on_tap = onServiceLocalLogin,
                        .ctx = self,
                        .child = ctx.new(phantom.Text{ .text = "Sign in" }).widget(),
                    }).widget(),
                }).widget()) catch {};
            } else if (self.auth_status != null and std.mem.eql(u8, self.auth_status.?.mode, "oidc")) {
                children.append(ctx.arena, ctx.new(phantom.Button{
                    .variant = .primary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onContinueToIdentityProvider,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Continue with identity provider" }).widget(),
                }).widget()) catch {};
            }
            if (self.auth_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 8 },
                .child = ctx.new(phantom.Text{
                    .text = self.auth_message,
                    .wrap = true,
                    .color = if (self.auth_failed) colors.red else colors.green,
                }).widget(),
            }).widget()) catch {};
            return ctx.new(phantom.Align{
                .alignment = .top_center,
                .child = ctx.new(fillViewport(.{
                    .child = ctx.new(phantom.Align{
                        .alignment = .center,
                        .child = ctx.new(phantom.SizedBox{
                            .width = 560,
                            .child = ctx.new(phantom.DecoratedBox{
                                .color = colors.bg_medium,
                                .border_color = colors.fg_dim,
                                .border_width = 1,
                                .radius = 12,
                                .child = ctx.new(phantom.Padding{
                                    .insets = .symmetric(24, 28),
                                    .child = ctx.new(phantom.Column(.{ .children = children.items })).widget(),
                                }).widget(),
                            }).widget(),
                        }).widget(),
                    }).widget(),
                })).widget(),
            }).widget();
        }

        fn onSetupLocalMode(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.setup_oidc_mode = false;
            self.auth_message = "";
            repaint(self);
        }

        fn onSetupOidcMode(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.setup_oidc_mode = true;
            self.auth_message = "";
            repaint(self);
        }

        fn onGoToSetup(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            // This is a document-level entry route. Navigate through the web
            // host so the browser loads the setup endpoint even if the
            // current app shell cannot rebuild its route after history changes.
            self.openAuthPage("/setup");
        }

        fn onOpenAccountSettings(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.account_failed = false;
            self.account_message = "";
            self.account_status_loaded = false;
            if (self.account_status_mode) |old| self.base.gpa().free(old);
            self.account_status_mode = null;
            self.openAuthPage("/account");
        }

        fn onReturnFromAccountSettings(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.openAuthPage("/");
        }

        fn onChangeLocalPassword(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            if (!std.mem.eql(u8, self.account_new_password.text(), self.account_confirm_password.text())) {
                self.account_failed = true;
                self.account_message = "The new password and confirmation do not match.";
                repaint(self);
                return;
            }
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.changeLocalPassword(room.allocator(), .{
                .current_password = self.account_current_password.text(),
                .new_password = self.account_new_password.text(),
            }) catch {
                self.account_failed = true;
                self.account_message = self.reaching.?.lastError() orelse "The password could not be changed.";
                self.account_current_password.setText("") catch {};
                repaint(self);
                return;
            };
            self.account_failed = false;
            self.account_message = "Password changed. Other active devices have been signed out.";
            self.account_current_password.setText("") catch {};
            self.account_new_password.setText("") catch {};
            self.account_confirm_password.setText("") catch {};
            repaint(self);
        }

        fn onContinueToIdentityProvider(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.openAuthPage("/auth/login");
        }

        fn onContinueToSignIn(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.openAuthPage("/auth/login");
        }

        fn onContinueToDaemon(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.openAuthPage("/");
        }

        fn openAuthPage(self: *State, path: []const u8) void {
            if (self.base.element.owner.platform.openUrl(path, .same_tab)) return;
            self.auth_failed = true;
            self.auth_message = "This page could not open the requested sign-in screen.";
            repaint(self);
        }

        fn authFailureMessage(self: *State, fallback: []const u8) []const u8 {
            const reason = self.reaching.?.lastError() orelse return fallback;
            if (std.mem.indexOf(u8, reason, "request origin is not allowed") != null) {
                return "This browser address does not match chock serve's --external-url. Restart chock serve with the public URL you opened in this browser; keep --host as the bind address.";
            }
            return reason;
        }

        fn submitLocalAuth(self: *State, setup: bool) void {
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const credentials = web_source.Web.LocalCredentials{
                .username = self.auth_username.text(),
                .password = self.auth_password.text(),
            };
            if (setup)
                self.reaching.?.localSetup(room.allocator(), credentials) catch {
                    self.auth_failed = true;
                    self.auth_message = self.authFailureMessage("Administrator setup was refused.");
                    self.auth_password.setText("") catch {};
                    repaint(self);
                    return;
                }
            else
                self.reaching.?.localLogin(room.allocator(), credentials) catch {
                    self.auth_failed = true;
                    self.auth_message = self.authFailureMessage("Sign-in was refused.");
                    self.auth_password.setText("") catch {};
                    repaint(self);
                    return;
                };
            self.auth_failed = false;
            self.auth_message = "Signed in. Opening Chock…";
            self.auth_password.setText("") catch {};
            self.selectDestination(.projects);
            self.projects_loaded = false;
            self.base.element.owner.platform.writeLocation("/", .replace);
            repaint(self);
        }

        fn onServiceLocalSetup(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.submitLocalAuth(true);
        }

        fn onServiceLocalLogin(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.submitLocalAuth(false);
        }

        fn onServiceOidcSetup(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.oidcSetup(room.allocator(), .{
                .provider = self.oidc_provider.text(),
                .issuer = self.oidc_issuer.text(),
                .discovery_url = if (self.oidc_discovery_url.text().len == 0) null else self.oidc_discovery_url.text(),
                .client_id = self.oidc_client_id.text(),
                .client_secret = if (self.oidc_client_secret.text().len == 0) null else self.oidc_client_secret.text(),
                .admin_subject = self.oidc_admin_subject.text(),
            }) catch {
                self.auth_failed = true;
                self.auth_message = self.authFailureMessage("OpenID Connect configuration was refused.");
                self.oidc_client_secret.setText("") catch {};
                repaint(self);
                return;
            };
            self.auth_failed = false;
            self.auth_oidc_configured = true;
            self.auth_message = "Identity provider configuration accepted.";
            self.oidc_client_secret.setText("") catch {};
            repaint(self);
        }

        fn selectDestination(self: *State, destination: Destination) void {
            if (self.share_open) self.clearWorkerCredential();
            self.projects_open = destination == .projects;
            self.teams_open = destination == .teams;
            self.people_open = destination == .people;
            self.providers_open = destination == .providers;
            self.share_open = false;
        }

        fn peopleView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.people_loaded) self.loadPeople(ctx.arena);
            const colors = phantom.ColorScheme.tokyoNight();
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(12, 8),
                    .on_tap = onPeopleBack,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Sessions" }).widget(),
                }).widget(),
                ctx.new(phantom.Padding{
                    .insets = .{ .left = 12 },
                    .child = ctx.new(phantom.Text{ .text = "People", .size = 28, .color = colors.fg }).widget(),
                }).widget(),
            }) })).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 12 },
                .child = ctx.new(phantom.Text{
                    .text = "People who can use this service. Access is controlled by teams and ACL rules.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget()) catch {};
            if (self.people_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{
                .text = self.people_message,
                .wrap = true,
                .color = if (self.people_failed) colors.red else colors.green,
            }).widget()) catch {};
            if (self.people_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "The directory is available to instance administrators only.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget()) catch {};
            } else if (self.people_json) |json| {
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 4, .bottom = 12 },
                    .child = ctx.new(phantom.Link{
                        .url = "/api/export/instance",
                        .child = ctx.new(phantom.Button{
                            .variant = .secondary,
                            .padding = .symmetric(12, 8),
                            .child = ctx.new(phantom.Text{ .text = "Export instance data" }).widget(),
                        }).widget(),
                    }).widget(),
                }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .bottom = 12 },
                    .child = ctx.new(phantom.Text{
                        .text = "Downloads people and provider configuration, project metadata, complete session transcripts, teams, memberships, invitations, session sharing, and ACL rules. Session metadata may include daemon project paths. Workspace files, repository source URLs, invitation tokens, and provider credentials are excluded.",
                        .wrap = true,
                        .color = colors.fg_muted,
                    }).widget(),
                }).widget()) catch {};
                const people = std.json.parseFromSliceLeaky([]const chock_proto.control.PersonRow, ctx.arena, json, .{
                    .ignore_unknown_fields = true,
                }) catch &.{};
                if (self.local_accounts_enabled) {
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .top = 8, .bottom = 8 },
                        .child = ctx.new(phantom.Text{ .text = "Create local account", .size = 20, .color = colors.fg }).widget(),
                    }).widget()) catch {};
                    children.append(ctx.arena, ctx.new(phantom.TextField{
                        .id = "chock-local-account-username",
                        .placeholder = "Username",
                        .controller = &self.local_account_username,
                        .ctx = self,
                    }).widget()) catch {};
                    children.append(ctx.arena, ctx.new(phantom.TextField{
                        .id = "chock-local-account-password",
                        .placeholder = "Temporary password (at least 12 characters)",
                        .obscure = true,
                        .controller = &self.local_account_password,
                        .ctx = self,
                    }).widget()) catch {};
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .top = 8, .bottom = 16 },
                        .child = ctx.new(phantom.Button{
                            .variant = .primary,
                            .padding = .symmetric(14, 8),
                            .on_tap = onCreateLocalAccount,
                            .ctx = self,
                            .child = ctx.new(phantom.Text{ .text = "Create account" }).widget(),
                        }).widget(),
                    }).widget()) catch {};
                }
                if (people.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "No one has signed in yet.",
                    .color = colors.fg_muted,
                }).widget()) catch {};
                for (people, 0..) |person, index| {
                    const label = if (person.display_name.len == 0)
                        person.identity_id
                    else if (person.email.len == 0)
                        person.display_name
                    else
                        try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}", .{ person.display_name, person.email });
                    const detail = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s}", .{ label, person.instance_role, person.identity_id });
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .top = 6, .bottom = 6 },
                        .child = ctx.new(phantom.Text{ .text = detail, .wrap = true, .color = colors.fg }).widget(),
                    }).widget()) catch {};
                    if (index < self.people_actions.len) children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .bottom = 8 },
                        .child = ctx.new(phantom.Button{
                            .variant = .secondary,
                            .padding = .symmetric(10, 6),
                            .on_tap = onRevokePersonSessions,
                            .ctx = &self.people_actions[index],
                            .child = ctx.new(phantom.Text{ .text = "Revoke active sessions" }).widget(),
                        }).widget(),
                    }).widget()) catch {};
                    if (index < self.people_actions.len) children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .bottom = 8 },
                        .child = ctx.new(phantom.Button{
                            .variant = .secondary,
                            .padding = .symmetric(10, 6),
                            .on_tap = onSetInstanceAdmin,
                            .ctx = &self.people_actions[index],
                            .child = ctx.new(phantom.Text{
                                .text = if (std.mem.eql(u8, person.instance_role, "instance_admin"))
                                    "Remove instance administrator"
                                else
                                    "Grant instance administrator",
                            }).widget(),
                        }).widget(),
                    }).widget()) catch {};
                    if (index < self.people_actions.len and person.local_account) {
                        const action = &self.people_actions[index];
                        children.append(ctx.arena, ctx.new(phantom.Text{
                            .text = if (person.local_account_disabled) "Local account · disabled" else "Local account · enabled",
                            .color = if (person.local_account_disabled) colors.red else colors.fg_muted,
                        }).widget()) catch {};
                        children.append(ctx.arena, ctx.new(phantom.Padding{
                            .insets = .{ .top = 4, .bottom = 6 },
                            .child = ctx.new(phantom.Button{
                                .variant = .secondary,
                                .padding = .symmetric(10, 6),
                                .on_tap = onSetLocalAccountEnabled,
                                .ctx = action,
                                .child = ctx.new(phantom.Text{
                                    .text = if (person.local_account_disabled) "Re-enable local account" else "Disable local account",
                                }).widget(),
                            }).widget(),
                        }).widget()) catch {};
                        children.append(ctx.arena, ctx.new(phantom.TextField{
                            .id = try std.fmt.allocPrint(ctx.arena, "chock-reset-local-password-{s}", .{person.identity_id}),
                            .placeholder = "Set temporary password (at least 12 characters)",
                            .obscure = true,
                            .controller = &action.password,
                            .ctx = action,
                        }).widget()) catch {};
                        children.append(ctx.arena, ctx.new(phantom.Padding{
                            .insets = .{ .bottom = 12 },
                            .child = ctx.new(phantom.Button{
                                .variant = .secondary,
                                .padding = .symmetric(10, 6),
                                .on_tap = onResetLocalPassword,
                                .ctx = action,
                                .child = ctx.new(phantom.Text{ .text = "Reset local password" }).widget(),
                            }).widget(),
                        }).widget()) catch {};
                    }
                }
            }
            return ctx.new(phantom.Padding{
                .insets = .all(24),
                .child = ctx.new(phantom.ScrollView{
                    .child = ctx.new(phantom.Column(.{ .children = children.items })).widget(),
                }).widget(),
            }).widget();
        }

        fn loadPeople(self: *State, arena: std.mem.Allocator) void {
            self.clearPeople();
            const people = self.reaching.?.people(arena) catch {
                self.people_failed = true;
                self.people_loaded = true;
                self.people_message = self.reaching.?.lastError() orelse "The people directory could not be loaded.";
                return;
            };
            self.people_json = std.json.Stringify.valueAlloc(self.base.gpa(), people, .{}) catch {
                self.people_failed = true;
                self.people_loaded = true;
                return;
            };
            self.local_accounts_enabled = false;
            for (people) |person| self.local_accounts_enabled = self.local_accounts_enabled or person.local_account;
            const gpa = self.base.gpa();
            self.people_actions = gpa.alloc(PersonAction, people.len) catch &.{};
            for (people, self.people_actions) |person, *action| {
                action.* = .{
                    .state = self,
                    .identity_id = gpa.dupe(u8, person.identity_id) catch "",
                    .instance_admin = std.mem.eql(u8, person.instance_role, "instance_admin"),
                    .local_account = person.local_account,
                    .local_account_disabled = person.local_account_disabled,
                };
            }
            self.people_failed = false;
            self.people_loaded = true;
        }

        fn clearPeople(self: *State) void {
            const gpa = self.base.gpa();
            if (self.people_json) |json| gpa.free(json);
            for (self.people_actions) |*action| {
                action.password.setText("") catch {};
                if (action.identity_id.len != 0) gpa.free(action.identity_id);
            }
            if (self.people_actions.len != 0) gpa.free(self.people_actions);
            self.people_actions = &.{};
            self.people_json = null;
        }

        fn teamsView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.teams_loaded) self.loadTeams(ctx.arena);
            if (self.selected_team != null and !self.team_people_loaded) self.loadTeamPeople(ctx.arena);
            if (self.selected_team != null and !self.team_invites_loaded) self.loadTeamInvites(ctx.arena);
            if (self.selected_team != null and !self.team_acl_loaded) self.loadTeamAcl(ctx.arena);
            const colors = phantom.ColorScheme.tokyoNight();
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onTeamsBack, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Sessions" }).widget() }).widget(),
                ctx.new(phantom.Padding{ .insets = .{ .left = 12 }, .child = ctx.new(phantom.Text{ .text = "Teams", .size = 28, .color = colors.fg }).widget() }).widget(),
                ctx.new(phantom.Padding{ .insets = .{ .left = 12 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onProvidersOpen, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Providers" }).widget() }).widget() }).widget(),
            }) })).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8, .bottom = 12 }, .child = ctx.new(phantom.Text{ .text = "Teams organize people for shared access. Team and identity UUIDs are stable IDs; names are for display.", .wrap = true, .color = colors.fg_muted }).widget() }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{ .id = "chock-team-invite-token", .placeholder = "Invitation token to join a team", .controller = &self.team_invite_token_input, .ctx = self }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 6 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(14, 8), .on_tap = onRedeemTeamInvite, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Redeem team invitation" }).widget() }).widget() }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{ .id = "chock-team-name", .placeholder = "Team name", .controller = &self.team_name, .ctx = self }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(16, 10), .on_tap = onCreateTeam, .ctx = self, .child = ctx.new(phantom.Text{ .text = "New team" }).widget() }).widget() }).widget()) catch {};
            if (self.team_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = self.team_message, .wrap = true, .color = if (self.teams_failed or self.team_people_failed or self.team_acl_failed) colors.red else colors.green }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 20, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = "Your teams", .size = 20, .color = colors.fg }).widget() }).widget()) catch {};
            if (self.team_rows.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = if (self.teams_failed) "Teams could not be loaded." else "No teams yet.", .color = if (self.teams_failed) colors.red else colors.fg_muted }).widget()) catch {};
            for (self.team_rows, 0..) |team, index| {
                const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s}", .{ team.name, team.role, team.id });
                const action = &self.team_actions[index];
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 4, .bottom = 4 }, .child = ctx.new(phantom.Button{ .variant = if (self.selected_team != null and std.mem.eql(u8, self.selected_team.?, team.id)) .primary else .secondary, .padding = .symmetric(12, 8), .on_tap = onSelectTeam, .ctx = action, .child = ctx.new(phantom.Text{ .text = label, .wrap = true }).widget() }).widget() }).widget()) catch {};
            }
            if (self.selected_team) |team_id| {
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 20, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = "Team members", .size = 20, .color = colors.fg }).widget() }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Invitations grant a team role only after the recipient signs in with this daemon's configured identity provider. Join links are bearer invitations: anyone who gets the token can redeem it before expiry.", .wrap = true, .color = colors.fg_muted }).widget()) catch {};
                if (self.team_people_failed) {
                    children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Only a team owner can view or change membership.", .color = colors.red }).widget()) catch {};
                } else {
                    for (self.team_people, 0..) |person, person_index| {
                        const label = if (person.display_name.len == 0) person.identity_id else if (person.email.len == 0) person.display_name else try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}", .{ person.display_name, person.email });
                        const detail = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}", .{ label, person.role orelse "Not a member" });
                        children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 4, .bottom = 4 }, .child = ctx.new(phantom.Text{ .text = detail, .wrap = true, .color = colors.fg }).widget() }).widget()) catch {};
                        if (person.role == null) {
                            const action = &self.team_person_actions[person_index];
                            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .bottom = 8 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onAddListedTeamPerson, .ctx = action, .child = ctx.new(phantom.Text{ .text = "Add to team" }).widget() }).widget() }).widget()) catch {};
                        } else if (!std.mem.eql(u8, person.role.?, "owner")) {
                            const action = &self.team_person_actions[person_index];
                            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .bottom = 8 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onRemoveTeamPerson, .ctx = action, .child = ctx.new(phantom.Text{ .text = "Remove from team" }).widget() }).widget() }).widget()) catch {};
                        }
                    }
                }
                if (self.currentTeamIsOwner()) {
                    children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 14, .bottom = 6 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onCreateTeamInvite, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Create 7-day member invitation" }).widget() }).widget() }).widget()) catch {};
                    if (self.created_team_invite_token) |invite_token| {
                        const invite_label = try std.fmt.allocPrint(ctx.arena, "Copy this one-time invitation token now: {s}", .{invite_token});
                        children.append(ctx.arena, ctx.new(phantom.Text{ .text = invite_label, .wrap = true, .color = colors.green }).widget()) catch {};
                        children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 4, .bottom = 8 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(10, 6), .on_tap = onHideTeamInvite, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Hide invitation token" }).widget() }).widget() }).widget()) catch {};
                    }
                    if (self.team_invites_failed) {
                        children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Team invitations could not be loaded.", .color = colors.red }).widget()) catch {};
                    } else if (self.team_invites_json) |json| {
                        const invitations = std.json.parseFromSliceLeaky([]const web_source.Web.TeamInvitationRow, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                        for (invitations) |invitation| {
                            const status = if (invitation.redeemed) "redeemed" else if (invitation.revoked) "revoked" else if (invitation.expired) "expired" else "pending";
                            const label = try std.fmt.allocPrint(ctx.arena, "{s} invite  ·  {s}  ·  expires {d}", .{ invitation.role, status, invitation.expires_ms });
                            const row_children = if (!invitation.redeemed and !invitation.revoked and !invitation.expired) blk: {
                                const action = ctx.new(TeamInviteAction{ .state = self, .team_id = team_id, .invitation_id = invitation.id });
                                break :blk ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                                    ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                                    ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onRevokeTeamInvite, .ctx = action, .child = ctx.new(phantom.Text{ .text = "Revoke" }).widget() }).widget(),
                                }) })).widget();
                            } else ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg_muted }).widget();
                            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 4, .bottom = 4 }, .child = row_children }).widget()) catch {};
                        }
                    }
                }
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 20, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = "Team access rules", .size = 20, .color = colors.fg }).widget() }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Grant or deny team management to an identity or another team. Enter UUIDs for identity/team principals; everyone uses a blank ID.", .wrap = true, .color = colors.fg_muted }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = "chock-acl-principal-kind", .placeholder = "identity, team, or everyone", .controller = &self.acl_principal_kind, .ctx = self }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = "chock-acl-principal-id", .placeholder = "Principal UUID (blank for everyone)", .controller = &self.acl_principal_id, .ctx = self }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = "chock-acl-effect", .placeholder = "allow or deny", .controller = &self.acl_effect, .ctx = self }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onSetTeamAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Save team rule" }).widget() }).widget() }).widget()) catch {};
                if (self.team_acl_failed) {
                    children.append(ctx.arena, ctx.new(phantom.Text{ .text = "ACL rules could not be loaded. You may not manage this team.", .color = colors.red }).widget()) catch {};
                } else if (self.team_acl_json) |json| {
                    const rules = std.json.parseFromSliceLeaky([]const web_source.Web.AclRecord, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                    if (rules.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = "No explicit team rules.", .color = colors.fg_muted }).widget()) catch {};
                    for (rules) |row| {
                        const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s} {s}  ·  {s}", .{ row.rule.capability, row.rule.effect, row.rule.principal_kind, row.rule.principal_id, row.id });
                        const rule_action = ctx.new(AclRemoveAction{ .state = self, .rule_id = row.id });
                        const row_children = ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                            ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                            ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onRemoveTeamAcl, .ctx = rule_action, .child = ctx.new(phantom.Text{ .text = "Remove" }).widget() }).widget(),
                        }) })).widget();
                        children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 4, .bottom = 4 }, .child = row_children }).widget()) catch {};
                    }
                }
            }
            return ctx.new(phantom.Padding{ .insets = .all(24), .child = ctx.new(phantom.ScrollView{ .child = ctx.new(phantom.Column(.{ .children = children.items })).widget() }).widget() }).widget();
        }

        fn loadTeams(self: *State, arena: std.mem.Allocator) void {
            self.clearTeams();
            const fetched = self.reaching.?.teams(arena) catch {
                self.teams_failed = true;
                self.teams_loaded = true;
                self.team_message = self.reaching.?.lastError() orelse "Teams could not be loaded.";
                return;
            };
            const gpa = self.base.gpa();
            self.team_rows = gpa.alloc(chock_proto.control.TeamRow, fetched.len) catch {
                self.teams_failed = true;
                self.teams_loaded = true;
                return;
            };
            @memset(self.team_rows, .{ .id = "", .name = "", .role = "" });
            self.team_actions = gpa.alloc(TeamAction, fetched.len) catch {
                self.clearTeams();
                self.teams_failed = true;
                self.teams_loaded = true;
                return;
            };
            for (fetched, self.team_rows, self.team_actions) |row, *copy, *action| {
                const id = gpa.dupe(u8, row.id) catch {
                    self.clearTeams();
                    self.teams_failed = true;
                    self.teams_loaded = true;
                    return;
                };
                const name = gpa.dupe(u8, row.name) catch {
                    gpa.free(id);
                    self.clearTeams();
                    self.teams_failed = true;
                    self.teams_loaded = true;
                    return;
                };
                const role = gpa.dupe(u8, row.role) catch {
                    gpa.free(id);
                    gpa.free(name);
                    self.clearTeams();
                    self.teams_failed = true;
                    self.teams_loaded = true;
                    return;
                };
                copy.* = .{ .id = id, .name = name, .role = role };
                action.* = .{ .state = self, .team_id = copy.id };
            }
            self.teams_failed = false;
            self.teams_loaded = true;
        }

        fn loadTeamPeople(self: *State, arena: std.mem.Allocator) void {
            self.clearTeamPeople();
            const people = self.reaching.?.teamPeople(arena, self.selected_team.?) catch {
                self.team_people_failed = true;
                self.team_people_loaded = true;
                self.team_message = self.reaching.?.lastError() orelse "Team members could not be loaded.";
                return;
            };
            const gpa = self.base.gpa();
            self.team_people = gpa.alloc(chock_proto.control.TeamPersonRow, people.len) catch {
                self.team_people_failed = true;
                self.team_people_loaded = true;
                return;
            };
            @memset(self.team_people, .{ .identity_id = "", .display_name = "", .email = "", .role = null });
            self.team_person_actions = gpa.alloc(TeamPersonAction, people.len) catch {
                self.team_people_failed = true;
                self.team_people_loaded = true;
                return;
            };
            for (people, self.team_people, self.team_person_actions) |person, *copy, *action| {
                const identity_id = gpa.dupe(u8, person.identity_id) catch {
                    self.clearTeamPeople();
                    self.team_people_failed = true;
                    self.team_people_loaded = true;
                    return;
                };
                const display_name = gpa.dupe(u8, person.display_name) catch {
                    gpa.free(identity_id);
                    self.clearTeamPeople();
                    self.team_people_failed = true;
                    self.team_people_loaded = true;
                    return;
                };
                const email = gpa.dupe(u8, person.email) catch {
                    gpa.free(identity_id);
                    gpa.free(display_name);
                    self.clearTeamPeople();
                    self.team_people_failed = true;
                    self.team_people_loaded = true;
                    return;
                };
                const role = if (person.role) |value| gpa.dupe(u8, value) catch {
                    gpa.free(identity_id);
                    gpa.free(display_name);
                    gpa.free(email);
                    self.clearTeamPeople();
                    self.team_people_failed = true;
                    self.team_people_loaded = true;
                    return;
                } else null;
                copy.* = .{ .identity_id = identity_id, .display_name = display_name, .email = email, .role = role };
                action.* = .{ .state = self, .team_id = self.selected_team.?, .identity_id = copy.identity_id };
            }
            self.team_people_failed = false;
            self.team_people_loaded = true;
        }

        fn loadTeamAcl(self: *State, arena: std.mem.Allocator) void {
            self.clearTeamAcl();
            const rows = self.reaching.?.aclRules(arena, "team", self.selected_team.?) catch {
                self.team_acl_failed = true;
                self.team_acl_loaded = true;
                return;
            };
            self.team_acl_json = std.json.Stringify.valueAlloc(self.base.gpa(), rows, .{}) catch {
                self.team_acl_failed = true;
                self.team_acl_loaded = true;
                return;
            };
            self.team_acl_failed = false;
            self.team_acl_loaded = true;
        }

        fn loadTeamInvites(self: *State, arena: std.mem.Allocator) void {
            self.clearTeamInvites();
            const rows = self.reaching.?.teamInvitations(arena, self.selected_team.?) catch {
                self.team_invites_failed = true;
                self.team_invites_loaded = true;
                return;
            };
            self.team_invites_json = std.json.Stringify.valueAlloc(self.base.gpa(), rows, .{}) catch {
                self.team_invites_failed = true;
                self.team_invites_loaded = true;
                return;
            };
            self.team_invites_failed = false;
            self.team_invites_loaded = true;
        }

        fn currentTeamIsOwner(self: *State) bool {
            const selected = self.selected_team orelse return false;
            for (self.team_rows) |team| {
                if (std.mem.eql(u8, team.id, selected)) return std.mem.eql(u8, team.role, "owner");
            }
            return false;
        }

        fn clearTeamAcl(self: *State) void {
            if (self.team_acl_json) |json| self.base.gpa().free(json);
            self.team_acl_json = null;
        }

        fn clearTeamInvites(self: *State) void {
            if (self.team_invites_json) |json| self.base.gpa().free(json);
            self.team_invites_json = null;
        }

        fn clearCreatedTeamInvite(self: *State) void {
            if (self.created_team_invite_token) |token| {
                std.crypto.secureZero(u8, token);
                self.base.gpa().free(token);
            }
            self.created_team_invite_token = null;
        }

        fn clearTeamPeople(self: *State) void {
            const gpa = self.base.gpa();
            for (self.team_people) |person| {
                if (person.identity_id.len != 0) gpa.free(person.identity_id);
                if (person.display_name.len != 0) gpa.free(person.display_name);
                if (person.email.len != 0) gpa.free(person.email);
                if (person.role) |role| gpa.free(role);
            }
            if (self.team_people.len != 0) gpa.free(self.team_people);
            if (self.team_person_actions.len != 0) gpa.free(self.team_person_actions);
            self.team_people = &.{};
            self.team_person_actions = &.{};
        }

        fn clearTeams(self: *State) void {
            const gpa = self.base.gpa();
            self.clearTeamPeople();
            for (self.team_rows) |team| {
                if (team.id.len != 0) gpa.free(team.id);
                if (team.name.len != 0) gpa.free(team.name);
                if (team.role.len != 0) gpa.free(team.role);
            }
            if (self.team_rows.len != 0) gpa.free(self.team_rows);
            if (self.team_actions.len != 0) gpa.free(self.team_actions);
            self.team_rows = &.{};
            self.team_actions = &.{};
        }

        fn onTeamsBack(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.teams_open = false;
            self.clearCreatedTeamInvite();
            if (self.ui) |ui| ui.showSessions();
            repaint(self);
        }

        fn onPeopleBack(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.people_open = false;
            self.people_loaded = false;
            self.clearPeople();
            if (self.ui) |ui| ui.showSessions();
            repaint(self);
        }

        fn onRevokePersonSessions(ptr: *anyopaque) void {
            const action: *PersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var temp = std.heap.ArenaAllocator.init(self.base.gpa());
            defer temp.deinit();
            const revoked = self.reaching.?.revokePersonSessions(temp.allocator(), action.identity_id) catch {
                self.people_message = self.reaching.?.lastError() orelse "Credentials could not be revoked.";
                repaint(self);
                return;
            };
            self.people_message = std.fmt.allocPrint(self.base.gpa(), "Revoked {d} active credentials. Account disabling is a separate action.", .{revoked}) catch "Active credentials revoked.";
            repaint(self);
        }

        fn onResetLocalPassword(ptr: *anyopaque) void {
            const action: *PersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const password = action.password.text();
            if (password.len < 12 or password.len > 1024) {
                self.people_message = "Choose a temporary password between 12 and 1024 characters.";
                repaint(self);
                return;
            }
            var temp = std.heap.ArenaAllocator.init(self.base.gpa());
            defer temp.deinit();
            self.reaching.?.resetLocalAccountPassword(temp.allocator(), action.identity_id, password) catch {
                action.password.setText("") catch {};
                self.people_message = self.reaching.?.lastError() orelse "The local password could not be reset.";
                self.people_failed = true;
                repaint(self);
                return;
            };
            action.password.setText("") catch {};
            self.people_message = "Password reset; the account owner must sign in again with the temporary password.";
            repaint(self);
        }

        fn onSetLocalAccountEnabled(ptr: *anyopaque) void {
            const action: *PersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const enabled = action.local_account_disabled;
            var temp = std.heap.ArenaAllocator.init(self.base.gpa());
            defer temp.deinit();
            self.reaching.?.setLocalAccountEnabled(temp.allocator(), action.identity_id, enabled) catch {
                self.people_message = self.reaching.?.lastError() orelse "The local account status could not be changed.";
                self.people_failed = true;
                repaint(self);
                return;
            };
            self.people_message = if (enabled)
                "Local account re-enabled. Its owner must sign in again; previous credentials remain revoked."
            else
                "Local account disabled and all active credentials revoked. Its identity and history were retained.";
            self.people_loaded = false;
            repaint(self);
        }

        fn onSetInstanceAdmin(ptr: *anyopaque) void {
            const action: *PersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const promote = !action.instance_admin;
            var temp = std.heap.ArenaAllocator.init(self.base.gpa());
            defer temp.deinit();
            self.reaching.?.setInstanceRole(temp.allocator(), action.identity_id, promote) catch {
                self.people_message = self.reaching.?.lastError() orelse "The instance role could not be changed.";
                self.people_failed = true;
                repaint(self);
                return;
            };
            self.people_message = if (promote)
                "Instance administrator granted. This role can manage accounts, access, and service-wide data; keep at least one trusted administrator."
            else
                "Instance administrator removed. The identity and its history were retained.";
            self.people_loaded = false;
            repaint(self);
        }

        fn onCreateLocalAccount(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const username = self.local_account_username.text();
            const password = self.local_account_password.text();
            self.local_account_password.setText("") catch {};
            if (std.mem.trim(u8, username, " \t\r\n").len == 0 or password.len == 0) {
                self.people_message = "Enter a username and a temporary password.";
                repaint(self);
                return;
            }
            var temp = std.heap.ArenaAllocator.init(self.base.gpa());
            defer temp.deinit();
            const identity = self.reaching.?.createLocalAccount(temp.allocator(), username, password) catch {
                self.people_message = self.reaching.?.lastError() orelse "The local account could not be created.";
                repaint(self);
                return;
            };
            self.local_account_username.setText("") catch {};
            self.people_message = std.fmt.allocPrint(self.base.gpa(), "Local account created ({s}). Add it to teams or ACL rules to grant access.", .{identity}) catch "Local account created.";
            self.people_loaded = false;
            self.loadPeople(temp.allocator());
            repaint(self);
        }

        fn providersView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.providers_loaded) self.loadProviders(ctx.arena);
            if (self.provider_acl_open) return self.providerAclView(ctx);
            const colors = phantom.ColorScheme.tokyoNight();
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onProvidersBack, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Back to Teams" }).widget() }).widget(),
                ctx.new(phantom.Padding{ .insets = .{ .left = 12 }, .child = ctx.new(phantom.Text{ .text = "LLM Providers", .size = 28, .color = colors.fg }).widget() }).widget(),
            }) })).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Provider records are scoped to a user, team, or instance. Enter only an opaque secret://UUID or env://NAME reference; never paste an API key here.", .wrap = true, .color = colors.fg_muted }).widget()) catch {};
            inline for (.{
                .{ "chock-provider-name", "Name", &self.provider_name },
                .{ "chock-provider-kind", "anthropic, aiand, openai, or openai-compat", &self.provider_kind },
                .{ "chock-provider-scope", "user, team, or instance", &self.provider_scope },
                .{ "chock-provider-scope-id", "Team UUID (blank for your user scope or instance)", &self.provider_scope_id },
                .{ "chock-provider-config", "Non-secret JSON with model, e.g. {\"model\":\"your-model-id\",\"base_url\":\"https://api.openai.com/v1\"}", &self.provider_configuration },
                .{ "chock-provider-credential-ref", "secret://UUID or env://NAME", &self.provider_credential_ref },
            }) |field| {
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = field[0], .placeholder = field[1], .controller = field[2], .ctx = self }).widget()) catch {};
            }
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onProviderCreate, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Add provider" }).widget() }).widget() }).widget()) catch {};
            if (self.providers_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = self.providers_message, .wrap = true, .color = if (self.providers_failed) colors.red else colors.green }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 20, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = "Providers you can use or manage", .size = 20, .color = colors.fg }).widget() }).widget()) catch {};
            if (self.providers_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Provider list could not be loaded.", .color = colors.red }).widget()) catch {};
            } else if (self.providers_json) |json| {
                const providers = std.json.parseFromSliceLeaky([]const web_source.Web.ProviderRow, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                if (providers.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = "No providers are available yet.", .color = colors.fg_muted }).widget()) catch {};
                for (providers) |provider| {
                    const scope = if (provider.scope_id) |id| try std.fmt.allocPrint(ctx.arena, "{s} · {s}", .{ provider.scope_kind, id }) else provider.scope_kind;
                    const label = try std.fmt.allocPrint(ctx.arena, "{s} · {s} · {s} · credential {s}", .{ provider.name, provider.provider_kind, scope, if (provider.has_credential) "configured" else "missing" });
                    const action = ctx.new(ProviderAction{ .state = self, .provider_id = provider.id });
                    children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                        ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                        ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onOpenProviderAcl, .ctx = action, .child = ctx.new(phantom.Text{ .text = "Access" }).widget() }).widget(),
                        ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onProviderRemove, .ctx = action, .child = ctx.new(phantom.Text{ .text = "Remove" }).widget() }).widget(),
                    }) })).widget()) catch {};
                }
            }
            return ctx.new(phantom.Padding{ .insets = .all(24), .child = ctx.new(phantom.ScrollView{ .child = ctx.new(phantom.Column(.{ .children = children.items })).widget() }).widget() }).widget();
        }

        fn providerAclView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.provider_acl_loaded) self.loadProviderAcl(ctx.arena);
            const colors = phantom.ColorScheme.tokyoNight();
            const provider_id = self.selected_provider orelse "";
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onCloseProviderAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Back to Providers" }).widget() }).widget(),
                ctx.new(phantom.Padding{ .insets = .{ .left = 12 }, .child = ctx.new(phantom.Text{ .text = "Provider access rules", .size = 28, .color = colors.fg }).widget() }).widget(),
            }) })).widget()) catch {};
            const intro = try std.fmt.allocPrint(ctx.arena, "Rules for provider {s}. Use provider_use to allow a person or team to select it; provider_manage controls configuration changes.", .{provider_id});
            children.append(ctx.arena, ctx.new(phantom.Text{ .text = intro, .wrap = true, .color = colors.fg_muted }).widget()) catch {};
            inline for (.{
                .{ "chock-provider-acl-principal-kind", "identity, team, or everyone", &self.acl_principal_kind },
                .{ "chock-provider-acl-principal-id", "Principal UUID (blank for everyone)", &self.acl_principal_id },
                .{ "chock-provider-acl-capability", "provider_use or provider_manage", &self.acl_capability },
                .{ "chock-provider-acl-effect", "allow or deny", &self.acl_effect },
            }) |field| {
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = field[0], .placeholder = field[1], .controller = field[2], .ctx = self }).widget()) catch {};
            }
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8, .bottom = 12 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onSetProviderAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Save provider rule" }).widget() }).widget() }).widget()) catch {};
            if (self.provider_acl_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = self.provider_acl_message, .wrap = true, .color = if (self.provider_acl_failed) colors.red else colors.green }).widget()) catch {};
            if (self.provider_acl_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Provider rules could not be loaded or changed. You may not manage this provider.", .wrap = true, .color = colors.red }).widget()) catch {};
            } else if (self.provider_acl_json) |json| {
                const rules = std.json.parseFromSliceLeaky([]const web_source.Web.AclRecord, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                if (rules.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = "No explicit provider rules.", .color = colors.fg_muted }).widget()) catch {};
                for (rules) |row| {
                    const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s} {s}", .{ row.rule.capability, row.rule.effect, row.rule.principal_kind, row.rule.principal_id });
                    const remove_action = ctx.new(AclRemoveAction{ .state = self, .rule_id = row.id });
                    children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                        ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                        ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onRemoveProviderAcl, .ctx = remove_action, .child = ctx.new(phantom.Text{ .text = "Remove" }).widget() }).widget(),
                    }) })).widget()) catch {};
                }
            }
            return ctx.new(phantom.Padding{ .insets = .all(24), .child = ctx.new(phantom.ScrollView{ .child = ctx.new(phantom.Column(.{ .children = children.items })).widget() }).widget() }).widget();
        }

        fn loadProviderAcl(self: *State, arena: std.mem.Allocator) void {
            self.clearProviderAcl();
            const provider_id = self.selected_provider orelse return;
            const rules = self.reaching.?.aclRules(arena, "provider", provider_id) catch {
                self.provider_acl_failed = true;
                self.provider_acl_loaded = true;
                return;
            };
            self.provider_acl_json = std.json.Stringify.valueAlloc(self.base.gpa(), rules, .{}) catch {
                self.provider_acl_failed = true;
                self.provider_acl_loaded = true;
                return;
            };
            self.provider_acl_failed = false;
            self.provider_acl_loaded = true;
        }

        fn clearProviderAcl(self: *State) void {
            if (self.provider_acl_json) |json| self.base.gpa().free(json);
            self.provider_acl_json = null;
        }

        fn onOpenProviderAcl(ptr: *anyopaque) void {
            const action: *ProviderAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            if (self.selected_provider) |old| self.base.gpa().free(old);
            self.selected_provider = self.base.gpa().dupe(u8, action.provider_id) catch null;
            self.clearProviderAcl();
            self.provider_acl_open = self.selected_provider != null;
            self.provider_acl_loaded = false;
            self.provider_acl_failed = false;
            self.provider_acl_message = "";
            repaint(self);
        }

        fn onCloseProviderAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.provider_acl_open = false;
            self.provider_acl_loaded = false;
            self.provider_acl_failed = false;
            self.provider_acl_message = "";
            self.clearProviderAcl();
            repaint(self);
        }

        fn onSetProviderAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const provider_id = self.selected_provider orelse return;
            const kind = std.mem.trim(u8, self.acl_principal_kind.text(), " \t\r\n");
            const principal_id = std.mem.trim(u8, self.acl_principal_id.text(), " \t\r\n");
            const capability = std.mem.trim(u8, self.acl_capability.text(), " \t\r\n");
            const effect = std.mem.trim(u8, self.acl_effect.text(), " \t\r\n");
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setAclRule(room.allocator(), "provider", provider_id, kind, principal_id, capability, effect) catch {
                self.provider_acl_failed = true;
                self.provider_acl_message = "The provider rule could not be saved; check the UUIDs, capability, and effect.";
                repaint(self);
                return;
            };
            self.provider_acl_failed = false;
            self.provider_acl_loaded = false;
            self.provider_acl_message = "Provider access rule saved.";
            self.acl_principal_id.setText("") catch {};
            repaint(self);
        }

        fn onRemoveProviderAcl(ptr: *anyopaque) void {
            const action: *AclRemoveAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.removeAclRule(room.allocator(), action.rule_id) catch {
                self.provider_acl_failed = true;
                self.provider_acl_message = "The provider rule could not be removed; you may not manage this provider.";
                repaint(self);
                return;
            };
            self.provider_acl_failed = false;
            self.provider_acl_loaded = false;
            self.provider_acl_message = "Provider access rule removed.";
            repaint(self);
        }

        fn loadProviders(self: *State, arena: std.mem.Allocator) void {
            self.clearProviders();
            const rows = self.reaching.?.providers(arena) catch {
                self.providers_failed = true;
                self.providers_loaded = true;
                self.providers_message = self.reaching.?.lastError() orelse "Provider list could not be loaded.";
                return;
            };
            self.providers_json = std.json.Stringify.valueAlloc(self.base.gpa(), rows, .{}) catch {
                self.providers_failed = true;
                self.providers_loaded = true;
                return;
            };
            self.providers_failed = false;
            self.providers_loaded = true;
        }

        fn clearProviders(self: *State) void {
            if (self.providers_json) |json| self.base.gpa().free(json);
            self.providers_json = null;
        }

        fn onProvidersOpen(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.providers_open = true;
            self.providers_loaded = false;
            self.providers_message = "";
            repaint(self);
        }

        fn onProvidersBack(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.providers_open = false;
            self.provider_acl_open = false;
            self.providers_loaded = false;
            repaint(self);
        }

        fn onProviderCreate(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            _ = self.reaching.?.createProvider(
                room.allocator(),
                self.provider_name.text(),
                self.provider_kind.text(),
                self.provider_scope.text(),
                self.provider_scope_id.text(),
                self.provider_configuration.text(),
                self.provider_credential_ref.text(),
            ) catch {
                self.providers_failed = true;
                self.providers_message = self.reaching.?.lastError() orelse "Provider could not be created.";
                repaint(self);
                return;
            };
            self.providers_failed = false;
            self.providers_message = "Provider created.";
            self.providers_loaded = false;
            self.provider_name.setText("") catch {};
            repaint(self);
        }

        fn onProviderRemove(ptr: *anyopaque) void {
            const action: *ProviderAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.removeProvider(room.allocator(), action.provider_id) catch {
                self.providers_failed = true;
                self.providers_message = self.reaching.?.lastError() orelse "Provider could not be removed.";
                repaint(self);
                return;
            };
            self.providers_failed = false;
            self.providers_message = "Provider removed.";
            self.providers_loaded = false;
            repaint(self);
        }

        fn onSelectTeam(ptr: *anyopaque) void {
            const action: *TeamAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const gpa = self.base.gpa();
            if (self.selected_team) |old| gpa.free(old);
            self.selected_team = gpa.dupe(u8, action.team_id) catch null;
            self.clearTeamPeople();
            self.clearTeamAcl();
            self.clearTeamInvites();
            self.clearCreatedTeamInvite();
            self.team_people_loaded = false;
            self.team_people_failed = false;
            self.team_acl_loaded = false;
            self.team_acl_failed = false;
            self.team_invites_loaded = false;
            self.team_invites_failed = false;
            repaint(self);
        }

        fn onCreateTeamInvite(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const team_id = self.selected_team orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const invite = self.reaching.?.createTeamInvitation(room.allocator(), team_id, "member") catch {
                self.team_message = self.reaching.?.lastError() orelse "The invitation could not be created.";
                repaint(self);
                return;
            };
            self.clearCreatedTeamInvite();
            self.created_team_invite_token = self.base.gpa().dupe(u8, invite.token) catch null;
            self.team_invites_loaded = false;
            self.team_message = "Invitation created. Copy its token now; it will not be shown again.";
            repaint(self);
        }

        fn onHideTeamInvite(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.clearCreatedTeamInvite();
            repaint(self);
        }

        fn onRedeemTeamInvite(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const token = std.mem.trim(u8, self.team_invite_token_input.text(), " \t\r\n");
            if (token.len == 0) return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.redeemTeamInvitation(room.allocator(), token) catch {
                self.team_message = self.reaching.?.lastError() orelse "The invitation could not be redeemed.";
                repaint(self);
                return;
            };
            self.team_invite_token_input.setText("") catch {};
            self.teams_loaded = false;
            self.team_message = "Invitation redeemed; the team is now available in your list.";
            repaint(self);
        }

        fn onRevokeTeamInvite(ptr: *anyopaque) void {
            const action: *TeamInviteAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.revokeTeamInvitation(room.allocator(), action.team_id, action.invitation_id) catch {
                self.team_message = self.reaching.?.lastError() orelse "The invitation could not be revoked.";
                repaint(self);
                return;
            };
            self.team_message = "Unused invitation revoked.";
            self.team_invites_loaded = false;
            repaint(self);
        }

        fn onCreateTeam(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            _ = self.reaching.?.createTeam(room.allocator(), self.team_name.text()) catch {
                self.teams_failed = true;
                self.team_message = self.reaching.?.lastError() orelse "The team could not be created.";
                repaint(self);
                return;
            };
            self.teams_failed = false;
            self.team_message = "Team created.";
            self.teams_loaded = false;
            self.team_name.setText("") catch {};
            repaint(self);
        }

        fn onAddListedTeamPerson(ptr: *anyopaque) void {
            const action: *TeamPersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setTeamMember(room.allocator(), action.team_id, action.identity_id, "member") catch {
                self.team_people_failed = true;
                self.team_message = self.reaching.?.lastError() orelse "Membership could not be updated.";
                repaint(self);
                return;
            };
            self.team_people_failed = false;
            self.team_message = "Team membership updated.";
            self.team_people_loaded = false;
            repaint(self);
        }

        fn onRemoveTeamPerson(ptr: *anyopaque) void {
            const action: *TeamPersonAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setTeamMember(room.allocator(), action.team_id, action.identity_id, "remove") catch {
                self.team_people_failed = true;
                self.team_message = self.reaching.?.lastError() orelse "Membership could not be removed.";
                repaint(self);
                return;
            };
            self.team_people_failed = false;
            self.team_message = "Team membership removed.";
            self.team_people_loaded = false;
            repaint(self);
        }

        fn onSetTeamAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const team_id = self.selected_team orelse return;
            const kind = std.mem.trim(u8, self.acl_principal_kind.text(), " \t\r\n");
            const principal_id = std.mem.trim(u8, self.acl_principal_id.text(), " \t\r\n");
            const effect = std.mem.trim(u8, self.acl_effect.text(), " \t\r\n");
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setAclRule(room.allocator(), "team", team_id, kind, principal_id, "team_manage", effect) catch {
                self.team_acl_failed = true;
                self.team_message = self.reaching.?.lastError() orelse "The team rule could not be saved.";
                repaint(self);
                return;
            };
            self.team_acl_failed = false;
            self.team_message = "Team access rule saved.";
            self.team_acl_loaded = false;
            self.acl_principal_id.setText("") catch {};
            repaint(self);
        }

        fn onRemoveTeamAcl(ptr: *anyopaque) void {
            const action: *AclRemoveAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.removeAclRule(room.allocator(), action.rule_id) catch {
                self.team_acl_failed = true;
                self.team_message = self.reaching.?.lastError() orelse "The team rule could not be removed.";
                repaint(self);
                return;
            };
            self.team_acl_failed = false;
            self.team_message = "Team access rule removed.";
            self.team_acl_loaded = false;
            repaint(self);
        }

        fn shareView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.share_people_loaded) self.loadSharePeople(ctx.arena);
            if (self.isShareOwner() and !self.session_acl_loaded) self.loadSessionAcl(ctx.arena);
            const colors = phantom.ColorScheme.tokyoNight();
            const session_id = self.opened orelse "";
            const export_url = try std.fmt.allocPrint(ctx.arena, "/api/export/session?session={s}", .{session_id});
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(12, 8),
                    .on_tap = onShareBack,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Back to session" }).widget(),
                }).widget(),
                ctx.new(phantom.Padding{
                    .insets = .{ .left = 12 },
                    .child = ctx.new(phantom.Text{
                        .text = "Share session",
                        .size = 28,
                        .color = colors.fg,
                    }).widget(),
                }).widget(),
                ctx.new(phantom.Link{
                    .url = export_url,
                    .child = ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(12, 8),
                        .child = ctx.new(phantom.Text{ .text = "Export transcript" }).widget(),
                    }).widget(),
                }).widget(),
                ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(12, 8),
                    .on_tap = onCancelSession,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Cancel turn" }).widget(),
                }).widget(),
            }) })).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 12 },
                .child = ctx.new(phantom.Text{
                    .text = "Choose an identity that has signed in to this daemon. Editors can prompt and approve; viewers can read.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget()) catch {};
            if (self.isShareOwner()) {
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 16, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = "Session access rules", .size = 20, .color = colors.fg }).widget() }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Explicit session grants and denies. Capabilities: session_view, session_prompt, session_approve, session_share.", .wrap = true, .color = colors.fg_muted }).widget()) catch {};
                inline for (.{
                    .{ "chock-session-acl-principal-kind", "identity, team, or everyone", &self.acl_principal_kind },
                    .{ "chock-session-acl-principal-id", "Principal UUID (blank for everyone)", &self.acl_principal_id },
                    .{ "chock-session-acl-capability", "session_view, session_prompt, session_approve, or session_share", &self.acl_capability },
                    .{ "chock-session-acl-effect", "allow or deny", &self.acl_effect },
                }) |field| children.append(ctx.arena, ctx.new(phantom.TextField{ .id = field[0], .placeholder = field[1], .controller = field[2], .ctx = self }).widget()) catch {};
                children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8, .bottom = 8 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onSetSessionAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Save session rule" }).widget() }).widget() }).widget()) catch {};
                if (self.session_acl_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = self.session_acl_message, .wrap = true, .color = if (self.session_acl_failed) colors.red else colors.green }).widget()) catch {};
                if (self.session_acl_failed) {
                    children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Session rules could not be loaded or changed. You may not manage this session.", .wrap = true, .color = colors.red }).widget()) catch {};
                } else if (self.session_acl_json) |json| {
                    const rules = std.json.parseFromSliceLeaky([]const web_source.Web.AclRecord, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                    if (rules.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = "No explicit session rules.", .color = colors.fg_muted }).widget()) catch {};
                    for (rules) |row| {
                        const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s} {s}", .{ row.rule.capability, row.rule.effect, row.rule.principal_kind, row.rule.principal_id });
                        const remove_action = ctx.new(AclRemoveAction{ .state = self, .rule_id = row.id });
                        children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                            ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                            ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onRemoveSessionAcl, .ctx = remove_action, .child = ctx.new(phantom.Text{ .text = "Remove" }).widget() }).widget(),
                        }) })).widget()) catch {};
                    }
                }
                if (self.worker_credential) |credential| {
                    const instructions = try std.fmt.allocPrint(ctx.arena, "One-time credential for a client worker, scoped to this session and expiring at {d} ms. On the machine with the project checkout, run chock worker --server <daemon-origin> --session <session-id> --project <checkout> with CHOCK_WORKER_TOKEN set to this credential. Treat it like a password; do not put it in shell history or source control.", .{self.worker_credential_expires_ms});
                    children.append(ctx.arena, ctx.new(phantom.Text{ .text = instructions, .wrap = true, .color = colors.fg_muted }).widget()) catch {};
                    children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8, .bottom = 8 }, .child = ctx.new(phantom.Text{ .text = credential, .wrap = true, .color = colors.fg }).widget() }).widget()) catch {};
                    children.append(ctx.arena, ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onClearWorkerCredential, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Hide credential" }).widget() }).widget()) catch {};
                } else {
                    children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 12, .bottom = 12 }, .child = ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onCreateWorkerCredential, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Create client-worker credential" }).widget() }).widget() }).widget()) catch {};
                }
            }
            if (self.share_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{
                .text = self.share_message,
                .wrap = true,
                .color = if (self.share_people_failed) colors.red else colors.green,
            }).widget()) catch {};
            if (self.share_people_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "People could not be loaded. Only the session owner can manage membership.",
                    .wrap = true,
                    .color = colors.red,
                }).widget()) catch {};
            } else if (self.share_people.len == 0) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = "No signed-in identities are available yet.",
                    .color = colors.fg_muted,
                }).widget()) catch {};
            }
            var action_index: usize = 0;
            for (self.share_people, 0..) |person, person_index| {
                const name = if (person.display_name.len != 0) person.display_name else person.identity_id;
                const label = if (person.email.len != 0)
                    try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s}", .{
                        name, person.email, person.role orelse "not a member",
                    })
                else
                    try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}", .{
                        name, person.role orelse "not a member",
                    });
                var row_children: std.ArrayList(phantom.Widget) = .empty;
                row_children.append(ctx.arena, ctx.new(phantom.Expanded(.{
                    .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget(),
                })).widget()) catch {};
                if (person.role == null or !std.mem.eql(u8, person.role.?, "owner")) {
                    const editor_action = &self.share_actions[action_index];
                    action_index += 1;
                    row_children.append(ctx.arena, ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(8, 6),
                        .on_tap = onShareRole,
                        .ctx = editor_action,
                        .child = ctx.new(phantom.Text{ .text = "Editor" }).widget(),
                    }).widget()) catch {};
                    const viewer_action = &self.share_actions[action_index];
                    action_index += 1;
                    row_children.append(ctx.arena, ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(8, 6),
                        .on_tap = onShareRole,
                        .ctx = viewer_action,
                        .child = ctx.new(phantom.Text{ .text = "Viewer" }).widget(),
                    }).widget()) catch {};
                    if (person.role != null) {
                        const remove_action = &self.share_actions[action_index];
                        action_index += 1;
                        row_children.append(ctx.arena, ctx.new(phantom.Button{
                            .variant = .secondary,
                            .padding = .symmetric(8, 6),
                            .on_tap = onShareRole,
                            .ctx = remove_action,
                            .child = ctx.new(phantom.Text{ .text = "Remove access" }).widget(),
                        }).widget()) catch {};
                    }
                }
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 8, .bottom = 8 },
                    .child = ctx.new(phantom.Row(.{ .children = row_children.items })).widget(),
                }).widget()) catch {};
                _ = person_index;
            }
            return ctx.new(phantom.Padding{
                .insets = .all(24),
                .child = ctx.new(phantom.ScrollView{
                    .child = ctx.new(phantom.Column(.{ .children = children.items })).widget(),
                }).widget(),
            }).widget();
        }

        fn loadSharePeople(self: *State, arena: std.mem.Allocator) void {
            const gpa = self.base.gpa();
            self.clearSharePeople();
            const session = self.opened orelse {
                self.share_people_failed = true;
                self.share_people_loaded = true;
                return;
            };
            const fetched = self.reaching.?.sessionPeople(arena, session) catch {
                self.share_people_failed = true;
                self.share_message = self.reaching.?.lastError() orelse "People could not be loaded.";
                self.share_people_loaded = true;
                return;
            };
            self.share_people = gpa.alloc(chock_proto.control.SessionPersonRow, fetched.len) catch {
                self.share_people_failed = true;
                self.share_people_loaded = true;
                return;
            };
            @memset(self.share_people, .{ .identity_id = "", .display_name = "", .email = "", .role = null });
            var action_count: usize = 0;
            for (fetched, self.share_people) |one, *copy| {
                copy.* = duplicateSessionPerson(gpa, one) catch {
                    self.share_people_failed = true;
                    self.clearSharePeople();
                    self.share_people_loaded = true;
                    return;
                };
                if (copy.role == null or !std.mem.eql(u8, copy.role.?, "owner"))
                    action_count += if (copy.role == null) 2 else 3;
            }
            self.share_actions = gpa.alloc(ShareAction, action_count) catch {
                self.share_people_failed = true;
                self.clearSharePeople();
                self.share_people_loaded = true;
                return;
            };
            var at: usize = 0;
            for (self.share_people, 0..) |person, person_index| {
                if (person.role != null and std.mem.eql(u8, person.role.?, "owner")) continue;
                self.share_actions[at] = .{ .state = self, .person_index = person_index, .role = "editor" };
                self.share_actions[at + 1] = .{ .state = self, .person_index = person_index, .role = "viewer" };
                at += 2;
                if (person.role != null) {
                    self.share_actions[at] = .{ .state = self, .person_index = person_index, .role = "remove" };
                    at += 1;
                }
            }
            self.share_people_failed = false;
            self.share_people_loaded = true;
        }

        fn duplicateSessionPerson(
            gpa: std.mem.Allocator,
            person: chock_proto.control.SessionPersonRow,
        ) std.mem.Allocator.Error!chock_proto.control.SessionPersonRow {
            const identity_id = try gpa.dupe(u8, person.identity_id);
            errdefer gpa.free(identity_id);
            const display_name = try gpa.dupe(u8, person.display_name);
            errdefer gpa.free(display_name);
            const email = try gpa.dupe(u8, person.email);
            errdefer gpa.free(email);
            const role = if (person.role) |value| try gpa.dupe(u8, value) else null;
            return .{ .identity_id = identity_id, .display_name = display_name, .email = email, .role = role };
        }

        fn clearSharePeople(self: *State) void {
            const gpa = self.base.gpa();
            for (self.share_people) |person| {
                if (person.identity_id.len != 0) gpa.free(person.identity_id);
                if (person.display_name.len != 0) gpa.free(person.display_name);
                if (person.email.len != 0) gpa.free(person.email);
                if (person.role) |role| gpa.free(role);
            }
            if (self.share_people.len != 0) gpa.free(self.share_people);
            self.share_people = &.{};
            if (self.share_actions.len != 0) gpa.free(self.share_actions);
            self.share_actions = &.{};
        }

        fn onShareBack(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.share_open = false;
            self.clearWorkerCredential();
            self.clearSessionAcl();
            self.session_acl_loaded = false;
            self.session_acl_failed = false;
            self.session_acl_message = "";
            repaint(self);
        }

        fn onCancelSession(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const session = self.opened orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.cancelSession(room.allocator(), session) catch {
                self.share_people_failed = true;
                self.share_message = self.reaching.?.lastError() orelse "The running turn could not be canceled.";
                repaint(self);
                return;
            };
            self.share_people_failed = false;
            self.share_message = "Cancellation requested. The worker will stop at its next safe point.";
            repaint(self);
        }

        fn loadSessionAcl(self: *State, arena: std.mem.Allocator) void {
            self.clearSessionAcl();
            const session = self.opened orelse return;
            const rules = self.reaching.?.aclRules(arena, "session", session) catch {
                self.session_acl_failed = true;
                self.session_acl_loaded = true;
                return;
            };
            self.session_acl_json = std.json.Stringify.valueAlloc(self.base.gpa(), rules, .{}) catch {
                self.session_acl_failed = true;
                self.session_acl_loaded = true;
                return;
            };
            self.session_acl_failed = false;
            self.session_acl_loaded = true;
        }

        fn clearSessionAcl(self: *State) void {
            if (self.session_acl_json) |json| self.base.gpa().free(json);
            self.session_acl_json = null;
        }

        fn onSetSessionAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const session = self.opened orelse return;
            const kind = std.mem.trim(u8, self.acl_principal_kind.text(), " \t\r\n");
            const principal_id = std.mem.trim(u8, self.acl_principal_id.text(), " \t\r\n");
            const capability = std.mem.trim(u8, self.acl_capability.text(), " \t\r\n");
            const effect = std.mem.trim(u8, self.acl_effect.text(), " \t\r\n");
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setAclRule(room.allocator(), "session", session, kind, principal_id, capability, effect) catch {
                self.session_acl_failed = true;
                self.session_acl_message = "The session rule could not be saved; check the UUIDs, capability, and effect.";
                repaint(self);
                return;
            };
            self.session_acl_failed = false;
            self.session_acl_loaded = false;
            self.session_acl_message = "Session access rule saved.";
            self.acl_principal_id.setText("") catch {};
            repaint(self);
        }

        fn onRemoveSessionAcl(ptr: *anyopaque) void {
            const action: *AclRemoveAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.removeAclRule(room.allocator(), action.rule_id) catch {
                self.session_acl_failed = true;
                self.session_acl_message = "The session rule could not be removed; you may not manage this session.";
                repaint(self);
                return;
            };
            self.session_acl_failed = false;
            self.session_acl_loaded = false;
            self.session_acl_message = "Session access rule removed.";
            repaint(self);
        }

        fn isShareOwner(self: *const State) bool {
            for (self.share_people) |person| {
                if (person.role) |role| if (std.mem.eql(u8, role, "owner")) return true;
            }
            return false;
        }

        fn clearWorkerCredential(self: *State) void {
            if (self.worker_credential) |credential| {
                std.crypto.secureZero(u8, credential);
                self.base.gpa().free(credential);
                self.worker_credential = null;
            }
            self.worker_credential_expires_ms = 0;
        }

        fn onClearWorkerCredential(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const credential = self.worker_credential orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.revokeWorkerCredential(room.allocator(), credential) catch {
                self.share_people_failed = true;
                self.share_message = self.reaching.?.lastError() orelse "The worker credential could not be revoked; it remains valid until expiry.";
                repaint(self);
                return;
            };
            self.clearWorkerCredential();
            self.share_message = "Worker credential revoked and cleared from this screen.";
            self.share_people_failed = false;
            repaint(self);
        }

        fn onCreateWorkerCredential(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const session = self.opened orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const issued = self.reaching.?.createWorkerCredential(room.allocator(), session) catch {
                self.share_people_failed = true;
                self.share_message = self.reaching.?.lastError() orelse "The worker credential could not be created.";
                repaint(self);
                return;
            };
            self.clearWorkerCredential();
            self.worker_credential = self.base.gpa().dupe(u8, issued.token) catch {
                self.share_message = "The worker credential was issued but could not be held for display. It will expire in 24 hours.";
                repaint(self);
                return;
            };
            self.worker_credential_expires_ms = issued.expires_ms;
            self.share_people_failed = false;
            self.share_message = "Worker credential created. It is shown once below.";
            repaint(self);
        }

        fn onShareRole(ptr: *anyopaque) void {
            const action: *ShareAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const session = self.opened orelse return;
            const identity_id = self.share_people[action.person_index].identity_id;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.shareSession(room.allocator(), session, identity_id, action.role) catch {
                self.share_people_failed = true;
                self.share_message = self.reaching.?.lastError() orelse "Membership could not be updated.";
                repaint(self);
                return;
            };
            self.share_people_failed = false;
            self.share_message = "Session membership updated.";
            self.share_people_loaded = false;
            repaint(self);
        }

        fn projectsView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.projects_loaded) {
                const fetched = self.reaching.?.projects(ctx.arena) catch {
                    self.projects_failed = true;
                    self.projects_loaded = true;
                    return self.projectsView(ctx);
                };
                self.clearProjectRows();
                self.project_rows = self.base.gpa().alloc(chock_proto.control.ProjectRow, fetched.len) catch {
                    self.projects_failed = true;
                    self.projects_loaded = true;
                    return self.projectsView(ctx);
                };
                @memset(self.project_rows, .{ .id = "", .root = "", .source_kind = "", .source_locator = "", .name = "", .status = "" });
                for (fetched, self.project_rows) |row, *owned| {
                    owned.* = duplicateProjectRow(self.base.gpa(), row) catch {
                        self.clearProjectRows();
                        self.projects_failed = true;
                        self.projects_loaded = true;
                        return self.projectsView(ctx);
                    };
                }
                self.projects_failed = false;
                self.projects_loaded = true;
            }
            if (self.project_acl_open) return self.projectAclView(ctx);

            const colors = phantom.ColorScheme.tokyoNight();
            const export_url = "/api/export/account";
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(12, 8),
                    .on_tap = onProjectsBack,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Sessions" }).widget(),
                }).widget(),
                ctx.new(phantom.Padding{
                    .insets = .{ .left = 12 },
                    .child = ctx.new(phantom.Text{
                        .text = "Projects",
                        .size = 28,
                        .color = colors.fg,
                    }).widget(),
                }).widget(),
            }) })).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 12 },
                .child = ctx.new(phantom.Link{
                    .url = export_url,
                    .child = ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(12, 8),
                        .child = ctx.new(phantom.Text{ .text = "Export accessible data" }).widget(),
                    }).widget(),
                }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8, .bottom = 12 },
                .child = ctx.new(phantom.Text{
                    .text = "Export accessible project metadata and complete session transcripts as JSON. Project files, provider credentials, and identity-provider credentials are not included.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .bottom = 12 },
                .child = ctx.new(phantom.Text{
                    .text = "Register a local directory (instance admins) or provision from an HTTPS Git host allowed by the daemon operator. Clones are stored in the daemon's managed project directory.",
                    .wrap = true,
                    .color = colors.fg_muted,
                }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Name", .color = colors.fg }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{
                .id = "chock-project-name",
                .placeholder = "Project name",
                .controller = &self.project_name,
                .ctx = self,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Directory", .color = colors.fg }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{
                .id = "chock-project-root",
                .placeholder = "/absolute/path/to/project",
                .controller = &self.project_root,
                .ctx = self,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 12 },
                .child = ctx.new(phantom.Button{
                    .variant = .primary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onRegisterProject,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "New project" }).widget(),
                }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 24, .bottom = 8 },
                .child = ctx.new(phantom.Text{ .text = "Provision from Git", .size = 20, .color = colors.fg }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{
                .id = "chock-project-repository-url",
                .placeholder = "https://code.example/team/project.git",
                .controller = &self.project_repository_url,
                .ctx = self,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8 },
                .child = ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onCloneGitProject,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Clone repository" }).widget(),
                }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 24, .bottom = 8 },
                .child = ctx.new(phantom.Text{ .text = "Import a local session", .size = 20, .color = colors.fg }).widget(),
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Text{
                .text = "For a session created by chock on this daemon, copy its ID from `chock sessions` and the registered project's exact directory. Import makes you its owner so you can share it; the session log stays in place.",
                .wrap = true,
                .color = colors.fg_muted,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{
                .id = "chock-import-session-project",
                .placeholder = "Registered project directory",
                .controller = &self.project_import_root,
                .ctx = self,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.TextField{
                .id = "chock-import-session-id",
                .placeholder = "Existing session ID",
                .controller = &self.project_import_session,
                .ctx = self,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 8 },
                .child = ctx.new(phantom.Button{
                    .variant = .secondary,
                    .padding = .symmetric(16, 10),
                    .on_tap = onImportExistingSession,
                    .ctx = self,
                    .child = ctx.new(phantom.Text{ .text = "Import existing session" }).widget(),
                }).widget(),
            }).widget()) catch {};
            if (self.project_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{
                .text = self.project_message,
                .wrap = true,
                .color = if (self.projects_failed) colors.red else colors.green,
            }).widget()) catch {};
            children.append(ctx.arena, ctx.new(phantom.Padding{
                .insets = .{ .top = 24, .bottom = 8 },
                .child = ctx.new(phantom.Text{ .text = "Registered projects", .size = 20, .color = colors.fg }).widget(),
            }).widget()) catch {};
            if (self.project_rows.len == 0) {
                children.append(ctx.arena, ctx.new(phantom.Text{
                    .text = if (self.projects_failed) "Projects could not be loaded." else "No projects registered yet.",
                    .color = if (self.projects_failed) colors.red else colors.fg_muted,
                }).widget()) catch {};
            }
            for (self.project_rows) |project| {
                const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}\n{s}  ·  {s}", .{
                    project.name, project.status, project.root, project.id,
                });
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .top = 6, .bottom = 6 },
                    .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget(),
                }).widget()) catch {};
                const acl_action = ctx.new(ProjectAclAction{ .state = self, .project_id = project.id });
                children.append(ctx.arena, ctx.new(phantom.Padding{
                    .insets = .{ .left = 12, .bottom = 8 },
                    .child = ctx.new(phantom.Button{
                        .variant = .secondary,
                        .padding = .symmetric(10, 6),
                        .on_tap = onOpenProjectAcl,
                        .ctx = acl_action,
                        .child = ctx.new(phantom.Text{ .text = "Access rules" }).widget(),
                    }).widget(),
                }).widget()) catch {};
                if (project.status.len == 0 or std.mem.eql(u8, project.status, "ready")) {
                    const daemon_launch = ctx.new(ProjectLaunchAction{
                        .state = self,
                        .project_root = project.root,
                        .placement = .daemon,
                    });
                    const client_launch = ctx.new(ProjectLaunchAction{
                        .state = self,
                        .project_root = project.root,
                        .placement = .client,
                    });
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .left = 12, .bottom = 12 },
                        .child = ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                            ctx.new(phantom.Button{
                                .variant = .primary,
                                .padding = .symmetric(12, 8),
                                .on_tap = onLaunchProjectSession,
                                .ctx = daemon_launch,
                                .child = ctx.new(phantom.Text{ .text = "New daemon session" }).widget(),
                            }).widget(),
                            ctx.new(phantom.Padding{
                                .insets = .{ .left = 8 },
                                .child = ctx.new(phantom.Button{
                                    .variant = .secondary,
                                    .padding = .symmetric(12, 8),
                                    .on_tap = onLaunchProjectSession,
                                    .ctx = client_launch,
                                    .child = ctx.new(phantom.Text{ .text = "New client session" }).widget(),
                                }).widget(),
                            }).widget(),
                        }) })).widget(),
                    }).widget()) catch {};
                } else {
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .left = 12, .bottom = 12 },
                        .child = ctx.new(phantom.Text{ .text = "Archived projects cannot start new sessions; existing sessions and files are retained.", .wrap = true, .color = colors.fg_muted }).widget(),
                    }).widget()) catch {};
                }
                if (project.can_manage) {
                    const status_action = ctx.new(ProjectStatusAction{
                        .state = self,
                        .project_id = project.id,
                        .archive = std.mem.eql(u8, project.status, "ready"),
                    });
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .left = 12, .bottom = 12 },
                        .child = ctx.new(phantom.Button{
                            .variant = .secondary,
                            .padding = .symmetric(10, 6),
                            .on_tap = onChangeProjectStatus,
                            .ctx = status_action,
                            .child = ctx.new(phantom.Text{ .text = if (std.mem.eql(u8, project.status, "ready")) "Archive project" else "Restore project" }).widget(),
                        }).widget(),
                    }).widget()) catch {};
                }
                if (project.source_kind.len != 0) {
                    const source = try std.fmt.allocPrint(ctx.arena, "Source: {s}  {s}", .{
                        project.source_kind, project.source_locator,
                    });
                    children.append(ctx.arena, ctx.new(phantom.Padding{
                        .insets = .{ .left = 12, .bottom = 8 },
                        .child = ctx.new(phantom.Text{ .text = source, .wrap = true, .color = colors.fg_muted }).widget(),
                    }).widget()) catch {};
                }
            }
            return ctx.new(phantom.Padding{
                .insets = .all(24),
                .child = ctx.new(phantom.ScrollView{
                    .child = ctx.new(phantom.Column(.{ .children = children.items })).widget(),
                }).widget(),
            }).widget();
        }

        fn projectAclView(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            if (!self.project_acl_loaded) self.loadProjectAcl(ctx.arena);
            const colors = phantom.ColorScheme.tokyoNight();
            const project_id = self.selected_project orelse "";
            var children: std.ArrayList(phantom.Widget) = .empty;
            children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(12, 8), .on_tap = onCloseProjectAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Back to Projects" }).widget() }).widget(),
                ctx.new(phantom.Padding{ .insets = .{ .left = 12 }, .child = ctx.new(phantom.Text{ .text = "Project access rules", .size = 28, .color = colors.fg }).widget() }).widget(),
            }) })).widget()) catch {};
            const intro = try std.fmt.allocPrint(ctx.arena, "Rules for project {s}. Project rules also apply to its sessions; a matching deny overrides a session role or grant.", .{project_id});
            children.append(ctx.arena, ctx.new(phantom.Text{ .text = intro, .wrap = true, .color = colors.fg_muted }).widget()) catch {};
            inline for (.{
                .{ "chock-project-acl-principal-kind", "identity, team, or everyone", &self.acl_principal_kind },
                .{ "chock-project-acl-principal-id", "Principal UUID (blank for everyone)", &self.acl_principal_id },
                .{ "chock-project-acl-capability", "Capability, e.g. project_view or session_prompt", &self.acl_capability },
                .{ "chock-project-acl-effect", "allow or deny", &self.acl_effect },
            }) |field| {
                children.append(ctx.arena, ctx.new(phantom.TextField{ .id = field[0], .placeholder = field[1], .controller = field[2], .ctx = self }).widget()) catch {};
            }
            children.append(ctx.arena, ctx.new(phantom.Padding{ .insets = .{ .top = 8, .bottom = 12 }, .child = ctx.new(phantom.Button{ .variant = .primary, .padding = .symmetric(14, 8), .on_tap = onSetProjectAcl, .ctx = self, .child = ctx.new(phantom.Text{ .text = "Save project rule" }).widget() }).widget() }).widget()) catch {};
            if (self.project_acl_message.len != 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = self.project_acl_message, .wrap = true, .color = if (self.project_acl_failed) colors.red else colors.green }).widget()) catch {};
            if (self.project_acl_failed) {
                children.append(ctx.arena, ctx.new(phantom.Text{ .text = "Project rules could not be loaded or changed. You may not manage this project.", .wrap = true, .color = colors.red }).widget()) catch {};
            } else if (self.project_acl_json) |json| {
                const rules = std.json.parseFromSliceLeaky([]const web_source.Web.AclRecord, ctx.arena, json, .{ .ignore_unknown_fields = true }) catch &.{};
                if (rules.len == 0) children.append(ctx.arena, ctx.new(phantom.Text{ .text = "No explicit project rules.", .color = colors.fg_muted }).widget()) catch {};
                for (rules) |row| {
                    const label = try std.fmt.allocPrint(ctx.arena, "{s}  ·  {s}  ·  {s} {s}", .{ row.rule.capability, row.rule.effect, row.rule.principal_kind, row.rule.principal_id });
                    const remove_action = ctx.new(AclRemoveAction{ .state = self, .rule_id = row.id });
                    children.append(ctx.arena, ctx.new(phantom.Row(.{ .children = ctx.newSlice(phantom.Widget, &.{
                        ctx.new(phantom.Expanded(.{ .child = ctx.new(phantom.Text{ .text = label, .wrap = true, .color = colors.fg }).widget() })).widget(),
                        ctx.new(phantom.Button{ .variant = .secondary, .padding = .symmetric(8, 6), .on_tap = onRemoveProjectAcl, .ctx = remove_action, .child = ctx.new(phantom.Text{ .text = "Remove" }).widget() }).widget(),
                    }) })).widget()) catch {};
                }
            }
            return ctx.new(phantom.Padding{ .insets = .all(24), .child = ctx.new(phantom.ScrollView{ .child = ctx.new(phantom.Column(.{ .children = children.items })).widget() }).widget() }).widget();
        }

        fn loadProjectAcl(self: *State, arena: std.mem.Allocator) void {
            self.clearProjectAcl();
            const project_id = self.selected_project orelse return;
            const rules = self.reaching.?.aclRules(arena, "project", project_id) catch {
                self.project_acl_failed = true;
                self.project_acl_loaded = true;
                return;
            };
            self.project_acl_json = std.json.Stringify.valueAlloc(self.base.gpa(), rules, .{}) catch {
                self.project_acl_failed = true;
                self.project_acl_loaded = true;
                return;
            };
            self.project_acl_failed = false;
            self.project_acl_loaded = true;
        }

        fn clearProjectAcl(self: *State) void {
            if (self.project_acl_json) |json| self.base.gpa().free(json);
            self.project_acl_json = null;
        }

        fn onOpenProjectAcl(ptr: *anyopaque) void {
            const action: *ProjectAclAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            if (self.selected_project) |old| self.base.gpa().free(old);
            self.selected_project = self.base.gpa().dupe(u8, action.project_id) catch null;
            self.clearProjectAcl();
            self.project_acl_open = self.selected_project != null;
            self.project_acl_loaded = false;
            self.project_acl_failed = false;
            self.project_acl_message = "";
            repaint(self);
        }

        fn onLaunchProjectSession(ptr: *anyopaque) void {
            const action: *ProjectLaunchAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            const ui = self.ui orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const id = self.reaching.?.createInProject(
                room.allocator(),
                action.placement,
                action.project_root,
            ) catch {
                ui.say(.chock, self.reaching.?.lastError() orelse "the session could not be created in this project");
                ui.endLine();
                repaint(self);
                return;
            };
            self.open(ui, id);
            self.showSessionInLocation(id);
            ui.beginInput();
        }

        fn onChangeProjectStatus(ptr: *anyopaque) void {
            const action: *ProjectStatusAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setProjectArchived(room.allocator(), action.project_id, action.archive) catch {
                self.projects_failed = true;
                self.project_message = self.reaching.?.lastError() orelse "The project status could not be changed.";
                repaint(self);
                return;
            };
            self.projects_failed = false;
            self.project_message = if (action.archive)
                "Project archived. Its files and existing sessions were retained."
            else
                "Project restored.";
            self.projects_loaded = false;
            repaint(self);
        }

        fn onCloseProjectAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.project_acl_open = false;
            self.project_acl_loaded = false;
            self.project_acl_failed = false;
            self.project_acl_message = "";
            self.clearProjectAcl();
            repaint(self);
        }

        fn onSetProjectAcl(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const project_id = self.selected_project orelse return;
            const kind = std.mem.trim(u8, self.acl_principal_kind.text(), " \t\r\n");
            const principal_id = std.mem.trim(u8, self.acl_principal_id.text(), " \t\r\n");
            const capability = std.mem.trim(u8, self.acl_capability.text(), " \t\r\n");
            const effect = std.mem.trim(u8, self.acl_effect.text(), " \t\r\n");
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.setAclRule(room.allocator(), "project", project_id, kind, principal_id, capability, effect) catch {
                self.project_acl_failed = true;
                self.project_acl_message = "The project rule could not be saved; check the UUIDs, capability, and effect.";
                repaint(self);
                return;
            };
            self.project_acl_failed = false;
            self.project_acl_loaded = false;
            self.project_acl_message = "Project access rule saved.";
            self.acl_principal_id.setText("") catch {};
            repaint(self);
        }

        fn onRemoveProjectAcl(ptr: *anyopaque) void {
            const action: *AclRemoveAction = @ptrCast(@alignCast(ptr));
            const self = action.state;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            self.reaching.?.removeAclRule(room.allocator(), action.rule_id) catch {
                self.project_acl_failed = true;
                self.project_acl_message = "The project rule could not be removed; you may not manage this project.";
                repaint(self);
                return;
            };
            self.project_acl_failed = false;
            self.project_acl_loaded = false;
            self.project_acl_message = "Project access rule removed.";
            repaint(self);
        }

        fn onProjectsBack(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            self.projects_open = false;
            self.project_acl_open = false;
            self.projects_loaded = false;
            self.clearProjectRows();
            if (self.ui) |ui| ui.showSessions();
            repaint(self);
        }

        fn duplicateProjectRow(gpa: std.mem.Allocator, row: chock_proto.control.ProjectRow) std.mem.Allocator.Error!chock_proto.control.ProjectRow {
            const id = try gpa.dupe(u8, row.id);
            errdefer gpa.free(id);
            const root = try gpa.dupe(u8, row.root);
            errdefer gpa.free(root);
            const source_kind = try gpa.dupe(u8, row.source_kind);
            errdefer gpa.free(source_kind);
            const source_locator = try gpa.dupe(u8, row.source_locator);
            errdefer gpa.free(source_locator);
            const name = try gpa.dupe(u8, row.name);
            errdefer gpa.free(name);
            const status = try gpa.dupe(u8, row.status);
            return .{ .id = id, .root = root, .source_kind = source_kind, .source_locator = source_locator, .name = name, .sessions = row.sessions, .status = status, .can_manage = row.can_manage };
        }

        fn clearProjectRows(self: *State) void {
            const gpa = self.base.gpa();
            for (self.project_rows) |row| {
                gpa.free(row.id);
                gpa.free(row.root);
                gpa.free(row.source_kind);
                gpa.free(row.source_locator);
                gpa.free(row.name);
                gpa.free(row.status);
            }
            if (self.project_rows.len != 0) gpa.free(self.project_rows);
            self.project_rows = &.{};
        }

        fn onRegisterProject(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const name = self.project_name.text();
            const root = self.project_root.text();
            var room = std.heap.ArenaAllocator.init(self.base.element.owner.gpa);
            defer room.deinit();
            _ = self.reaching.?.createProject(room.allocator(), name, root) catch {
                self.projects_failed = true;
                self.project_message = self.reaching.?.lastError() orelse "The project could not be registered.";
                repaint(self);
                return;
            };
            self.projects_failed = false;
            self.project_message = "Project registered.";
            self.projects_loaded = false;
            self.project_name.setText("") catch {};
            self.project_root.setText("") catch {};
            repaint(self);
        }

        fn onImportExistingSession(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            const project_root = std.mem.trim(u8, self.project_import_root.text(), " \t\r\n");
            const session_id = std.mem.trim(u8, self.project_import_session.text(), " \t\r\n");
            if (project_root.len == 0 or session_id.len == 0) {
                self.projects_failed = true;
                self.project_message = "Enter the registered project directory and the existing session ID.";
                repaint(self);
                return;
            }
            var room = std.heap.ArenaAllocator.init(self.base.element.owner.gpa);
            defer room.deinit();
            self.reaching.?.registerExistingSession(room.allocator(), project_root, session_id) catch {
                self.projects_failed = true;
                self.project_message = self.reaching.?.lastError() orelse "The existing session could not be imported.";
                repaint(self);
                return;
            };
            self.projects_failed = false;
            self.project_message = "Session imported. You are its owner and can now share it.";
            self.projects_loaded = false;
            self.project_import_session.setText("") catch {};
            repaint(self);
        }

        fn onCloneGitProject(ptr: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ptr));
            var room = std.heap.ArenaAllocator.init(self.base.element.owner.gpa);
            defer room.deinit();
            _ = self.reaching.?.createGitProject(
                room.allocator(),
                self.project_name.text(),
                self.project_repository_url.text(),
            ) catch {
                self.projects_failed = true;
                self.project_message = self.reaching.?.lastError() orelse "The repository could not be provisioned.";
                repaint(self);
                return;
            };
            self.projects_failed = false;
            self.project_message = "Project cloned and registered.";
            self.projects_loaded = false;
            self.project_name.setText("") catch {};
            self.project_repository_url.setText("") catch {};
            repaint(self);
        }

        /// The interface, made on the first build.
        ///
        /// Not made in `initState`: the owner's `io` is still `std.Io.failing`
        /// then, and a source built on that copy reads a dead network forever.
        fn interface(self: *State) ?*chock_ui.Ui {
            if (self.ui) |one| return one;

            const owner = self.base.element.owner;
            const origin = if (self.api_host.len != 0)
                self.api_host
            else
                owner.platform.readHost(&origin_buffer) orelse "";
            self.reaching = web_source.Web.init(owner.gpa, owner, origin);
            self.from_host = .{
                .state = self,
                .repaint = repaint,
                .reaching = &self.reaching.?,
                .io = owner.io,
            };

            const one = chock_ui.Ui.init(owner.gpa, owner.io, self.from_host.?.host()) catch
                return null;
            one.setClock(one, chock_ui.Ui.realNowMs, 0);
            self.ui = one;

            var status_room = std.heap.ArenaAllocator.init(owner.gpa);
            defer status_room.deinit();
            const fetched_status = self.reaching.?.authStatus(status_room.allocator()) catch null;
            if (fetched_status) |found| self.keepAuthStatus(found) catch {};
            self.auth_status_loaded = self.auth_status != null;
            const service_mode = if (self.auth_status) |status|
                std.mem.eql(u8, status.mode, "local") or std.mem.eql(u8, status.mode, "oidc")
            else
                false;

            // A link or a reload names the session it was looking at. With
            // nothing named, the first thing shown is the list of them, the same
            // picker a person opens in a terminal.
            // NavigationScaffold keeps this beside a wide view and in the
            // drawer on a compact one, without putting picker rows into the
            // transcript.
            if (self.authEntryPath() == null) {
                const named = self.namedSession();
                if (named) |id| self.open(one, id);
                if (service_mode and named == null) {
                    self.projects_open = true;
                } else {
                    one.showSessions();
                }
            }
            return one;
        }

        /// The session the address bar names, or null when it names none.
        fn namedSession(self: *State) ?[]const u8 {
            const said = self.base.element.owner.platform.readLocation(&location_buffer) orelse
                return null;
            if (!std.mem.startsWith(u8, said, session_path)) return null;
            const remainder = said[session_path.len..];
            const id = remainder[0 .. std.mem.indexOfScalar(u8, remainder, '?') orelse remainder.len];
            if (id.len == 0 or id.len > 64) return null;
            for (id) |one| if (!std.ascii.isAlphanumeric(one)) return null;
            return id;
        }

        /// Take up whatever the picker chose, and say so in the address bar.
        fn followPick(self: *State, ui: *chock_ui.Ui) void {
            const chosen = ui.taken orelse return;
            ui.taken = null;
            self.open(ui, chosen);

            self.showSessionInLocation(chosen);
        }

        fn showSessionInLocation(self: *State, id: []const u8) void {
            var room: [4096 + 128]u8 = undefined;
            const project = if (self.reaching) |*web| web.locationProject() else "";
            const said = std.fmt.bufPrint(&room, session_path ++ "{s}{s}", .{ id, project }) catch return;
            // A push and not a replace: the list is where the back button goes.
            self.base.element.owner.platform.writeLocation(said, .push);
        }

        fn followCreate(self: *State, arena: std.mem.Allocator, ui: *chock_ui.Ui) void {
            const placement = ui.takeNewSessionPlacement() orelse return;

            const source = self.reaching.?.source();
            const id = source.createPlaced(arena, placement) catch {
                ui.say(.chock, source.whyLast() orelse "the session was not created");
                ui.endLine();
                return;
            };
            if (id.len == 0) {
                ui.say(.chock, "the session source cannot create sessions");
                ui.endLine();
                return;
            }
            self.open(ui, id);
            self.showSessionInLocation(id);
            ui.beginInput();
        }

        /// Read one session, whether a person picked it or a link named it.
        fn open(self: *State, ui: *chock_ui.Ui, id: []const u8) void {
            const gpa = self.base.element.owner.gpa;
            self.clearWorkerCredential();
            const kept = gpa.dupe(u8, id) catch return;
            if (self.opened) |one| gpa.free(one);
            self.opened = kept;
            ui.clearTranscript();
            ui.current_session = kept;
            self.poll_failed = false;
            self.reaching.?.watch(kept);
            self.seen = 0;
            self.pending_question_id = null;
            self.listen(kept);
        }

        /// Send whatever a person typed.
        fn followSubmit(self: *State, arena: std.mem.Allocator, ui: *chock_ui.Ui) void {
            if (!ui.submitted) return;
            defer ui.beginInput();

            const session = self.opened orelse return;
            if (self.pending_question_id) |request_id| {
                const answer = std.mem.trim(u8, ui.typed.items, " \t\r\n");
                if (answer.len == 0) return;
                self.reaching.?.answerAgentQuestion(arena, session, request_id, answer) catch {
                    ui.say(.chock, self.reaching.?.source().whyLast() orelse "the answer was not sent");
                    ui.endLine();
                    return;
                };
                self.pending_question_id = null;
                return;
            }
            if (ui.takeForkRequest()) |at| {
                self.forkSession(arena, ui, session, at);
                return;
            }
            if (ui.takeReviewRequest()) |request| {
                self.workspaceReview(arena, ui, session, request);
                return;
            }
            switch (chock_ui.ui.answerFor(ui.typed.items)) {
                .nothing => {},
                .command => |command| switch (command) {
                    .fork => self.forkSession(arena, ui, session, null),
                    .review => self.workspaceReview(arena, ui, session, .open),
                    // These commands act on a loop this page is not inside.
                    else => {
                        ui.say(.chock, "that command only works where the session is running");
                        ui.endLine();
                    },
                },
                // Not drawn here: the daemon writes the message to the log and
                // the stream brings it back, so saying it now would show it
                // twice.
                .message => |words| {
                    self.reaching.?.source().prompt(session, words) catch {
                        ui.say(.chock, self.reaching.?.source().whyLast() orelse
                            "the message was not sent");
                        ui.endLine();
                    };
                },
            }
        }

        fn workspaceReview(
            self: *State,
            arena: std.mem.Allocator,
            ui: *chock_ui.Ui,
            session: []const u8,
            request: chock_ui.Ui.ReviewRequest,
        ) void {
            const source = self.reaching.?.source();
            switch (request) {
                .open => {
                    const review = source.review(arena, session) catch {
                        ui.say(.chock, source.whyLast() orelse "the workspace review could not be opened");
                        ui.endLine();
                        return;
                    };
                    ui.showReview(review);
                },
                .apply => {
                    const selection = ui.reviewSelection(arena) catch return;
                    source.select(session, selection) catch {
                        ui.say(.chock, source.whyLast() orelse "the workspace selection was not created");
                        ui.endLine();
                        return;
                    };
                    ui.say(.chock, "the selected result was created without moving your branch");
                    ui.endLine();
                },
                .undo => {
                    source.undoSelection(session) catch {
                        ui.say(.chock, source.whyLast() orelse "the selected result was not removed");
                        ui.endLine();
                        return;
                    };
                    ui.say(.chock, "the selected result was removed; your branch was not changed");
                    ui.endLine();
                },
            }
        }

        fn forkSession(
            self: *State,
            arena: std.mem.Allocator,
            ui: *chock_ui.Ui,
            session: []const u8,
            at: ?u64,
        ) void {
            const child = self.reaching.?.source().fork(arena, session, at) catch {
                ui.say(.chock, self.reaching.?.source().whyLast() orelse
                    "the session was not forked");
                ui.endLine();
                return;
            };
            self.open(ui, child);
            self.showSessionInLocation(child);
        }

        /// Follow one session's events from the start of its log.
        ///
        /// A stream and not a poll: the page has no timer of its own, so
        /// something has to push. The whole log comes first, which is what fills
        /// the transcript, and then each new event as it is written.
        fn listen(self: *State, session: []const u8) void {
            self.closeStream();
            const ui = self.ui orelse return;

            self.refreshPresence();
            self.presence_poll = self.base.scheduler().every(
                self.base.gpa(),
                15 * std.time.ns_per_s,
                self,
                presenceTick,
            ) catch null;

            if (self.poll_events) {
                self.pollOnce();
                self.poll = self.base.scheduler().every(
                    self.base.gpa(),
                    std.time.ns_per_s,
                    self,
                    pollTick,
                ) catch null;
                return;
            }

            var room: [1024]u8 = undefined;
            const url = std.fmt.bufPrint(
                &room,
                "/api/events?session={s}&after=0{s}",
                .{ session, self.reaching.?.eventsProject() },
            ) catch return;

            self.stream = self.base.element.owner.platform.openEventSource(
                url,
                &.{"refused"},
                .{ .ctx = self, .on_event = onStreamEvent },
            ) orelse {
                ui.say(.chock, "this page cannot open an event stream");
                ui.endLine();
                return;
            };
        }

        fn closeStream(self: *State) void {
            if (self.poll) |running| self.base.scheduler().cancel(running);
            self.poll = null;
            if (self.presence_poll) |running| self.base.scheduler().cancel(running);
            self.presence_poll = null;
            self.clearPresence();
            if (self.stream) |running| {
                self.stream = null;
                self.base.element.owner.platform.closeEventSource(running);
            }
        }

        fn clearPresence(self: *State) void {
            if (self.presence_json) |json| self.base.gpa().free(json);
            self.presence_json = null;
            self.presence_failed = false;
        }

        fn failPresence(self: *State) void {
            if (self.presence_json) |json| self.base.gpa().free(json);
            self.presence_json = null;
            if (!self.presence_failed) {
                self.presence_failed = true;
                repaint(self);
            }
        }

        fn refreshPresence(self: *State) void {
            const session = self.opened orelse return;
            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const arena = room.allocator();
            self.reaching.?.touchSessionPresence(arena, session) catch {
                self.failPresence();
                return;
            };
            const people = self.reaching.?.sessionPresence(arena, session) catch {
                self.failPresence();
                return;
            };
            const json = std.json.Stringify.valueAlloc(arena, people, .{}) catch {
                self.failPresence();
                return;
            };
            const kept = self.base.gpa().dupe(u8, json) catch {
                self.failPresence();
                return;
            };
            if (self.presence_json) |old| self.base.gpa().free(old);
            self.presence_json = kept;
            if (self.presence_failed) {
                self.presence_failed = false;
            }
            repaint(self);
        }

        fn presenceTick(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            self.refreshPresence();
        }

        fn pollTick(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            self.pollOnce();
        }

        /// Native hosts do not provide the browser's EventSource hook. Read
        /// only the tail that has not been drawn yet; the server closes this
        /// response, so a temporarily unreachable host cannot strand a frame.
        fn pollOnce(self: *State) void {
            const ui = self.ui orelse return;
            const session = self.opened orelse return;

            var room = std.heap.ArenaAllocator.init(self.base.gpa());
            defer room.deinit();
            const entries = self.reaching.?.source().events(
                room.allocator(),
                session,
                self.seen,
            ) catch {
                if (!self.poll_failed) {
                    ui.say(.chock, self.reaching.?.source().whyLast() orelse
                        "the daemon did not answer");
                    ui.endLine();
                    self.poll_failed = true;
                    repaint(self);
                }
                return;
            };

            self.poll_failed = false;
            for (entries) |entry| {
                if (entry.at != 0 and entry.at <= self.seen) continue;
                self.seen = entry.at;
                self.trackQuestion(entry.at, entry.ev);
                ui.replay(entry.at, entry.ev);
            }
            if (entries.len != 0) repaint(self);
        }

        fn onStreamEvent(ctx: *anyopaque, got: phantom.ServerEvent) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            const ui = self.ui orelse return;

            switch (got) {
                .open, .reconnecting => {},
                .closed => {
                    ui.say(.chock, "the daemon stopped sending events");
                    ui.endLine();
                },
                .message => |said| {
                    if (std.mem.eql(u8, said.type, "refused")) {
                        ui.say(.chock, said.data);
                        ui.endLine();
                    } else {
                        // The offset is the stream's own id: an event read back
                        // out of a log carries zero in its own `id` field.
                        self.replayOne(ui, said.data, std.fmt.parseInt(
                            u64,
                            said.last_event_id,
                            10,
                        ) catch 0);
                    }
                },
            }
            repaint(self);
        }

        /// One line of the log, drawn the way a native run draws it.
        ///
        /// The arena goes away at the end of this: the interface copies every
        /// string it keeps, so nothing here has to outlive the parse.
        fn replayOne(self: *State, ui: *chock_ui.Ui, line: []const u8, at: u64) void {
            // The first line of a log says what it is and carries no event.
            if (std.mem.eql(u8, line, chock_proto.storage.header_line)) return;

            // A browser reopens a dropped stream by itself and the daemon starts
            // again from the top, so an event already drawn is dropped.
            if (at != 0 and at <= self.seen) return;

            var room = std.heap.ArenaAllocator.init(self.base.element.owner.gpa);
            defer room.deinit();

            const envelope = std.json.parseFromSliceLeaky(
                event.Envelope,
                room.allocator(),
                line,
                .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
            ) catch {
                ui.say(.chock, "an event could not be read");
                ui.endLine();
                return;
            };
            self.seen = at;
            self.trackQuestion(at, envelope.event);
            ui.replay(at, envelope.event);
        }

        fn trackQuestion(self: *State, id: u64, ev: event.Event) void {
            switch (ev) {
                .agent_question => self.pending_question_id = id,
                .agent_answer => |answer| {
                    if (self.pending_question_id == answer.request_id) self.pending_question_id = null;
                },
                .session_end => self.pending_question_id = null,
                else => {},
            }
        }

        fn repaint(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            phantom.stateful.markNeedsBuild(self);
        }
    };
};

test "application destinations are exclusive and leave shared-session views" {
    var state: App.State = .{
        .projects_open = true,
        .teams_open = true,
        .people_open = true,
        .providers_open = true,
        .share_open = true,
    };

    state.selectDestination(.projects);
    try std.testing.expect(state.projects_open);
    try std.testing.expect(!state.teams_open);
    try std.testing.expect(!state.people_open);
    try std.testing.expect(!state.providers_open);
    try std.testing.expect(!state.share_open);

    state.selectDestination(.people);
    try std.testing.expect(!state.projects_open);
    try std.testing.expect(!state.teams_open);
    try std.testing.expect(state.people_open);
    try std.testing.expect(!state.providers_open);
    try std.testing.expect(!state.share_open);

    state.selectDestination(.sessions);
    try std.testing.expect(!state.projects_open);
    try std.testing.expect(!state.teams_open);
    try std.testing.expect(!state.people_open);
    try std.testing.expect(!state.providers_open);
    try std.testing.expect(!state.share_open);
}

test "setup mode choices keep their widget slice alive through mount" {
    var state: App.State = .{
        .auth_status = .{ .mode = "local", .setup = true },
        .auth_status_loaded = true,
    };
    var sink = phantom.FaultSink{};
    var owner = phantom.BuildOwner{ .gpa = std.testing.allocator, .sink = &sink };
    defer owner.deinit();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var bctx = phantom.BuildContext{ .arena = arena.allocator(), .owner = &owner };

    // authEntryView returns before Widget.mount consumes its tree. This is the
    // lifetime boundary that requires multi-child slices to use the frame arena.
    const root = try state.authEntryView(&bctx, true);
    const mounted = try root.mount(&bctx, null);
    defer mounted.deinit(std.testing.allocator);
    try std.testing.expect(sink.ok());
}

const AuthEntryFixture = struct {
    setup_route: bool = true,
    setup: bool = true,
    mode: []const u8 = "local",

    pub const State = struct {
        base: phantom.StateBase = .{},
        setup_route: bool = true,
        auth: App.State = .{
            .auth_status = .{ .mode = "local", .setup = true },
            .auth_status_loaded = true,
            .setup_oidc_mode = true,
        },

        pub fn initState(self: *State, fixture: *const AuthEntryFixture) !void {
            self.auth.base.element = self.base.element;
            self.setup_route = fixture.setup_route;
            self.auth.auth_status = .{ .mode = fixture.mode, .setup = fixture.setup };
        }

        pub fn build(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            return self.auth.authEntryView(ctx, self.setup_route);
        }

        pub fn dispose(self: *State) void {
            self.auth.dispose();
        }
    };

    pub fn widget(self: *const AuthEntryFixture) phantom.Widget {
        return phantom.stateful.statefulWidget(AuthEntryFixture, self);
    }
};

test "the set up service button opens the setup route in the current tab" {
    const fixture = AuthEntryFixture{ .setup_route = false };
    var mounted = try phantom.testing.mount(std.testing.allocator, fixture.widget());
    defer mounted.deinit();
    try mounted.pump();

    const NavigationSpy = struct {
        url: []const u8 = "",
        mode: ?phantom.OpenMode = null,
        fn open(ctx: *anyopaque, url: []const u8, mode: phantom.OpenMode) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.url = url;
            self.mode = mode;
            return true;
        }
    };
    var navigation = NavigationSpy{};
    mounted.owner.platform = .{ .ctx = &navigation, .open_url = NavigationSpy.open };

    const ButtonFinder = struct {
        fn find(el: *phantom.Element, ordinal: *usize) ?*phantom.Element {
            if (std.mem.eql(u8, el.type_name, @typeName(phantom.Button))) {
                if (ordinal.* == 2) return el;
                ordinal.* += 1;
            }
            if (el.child) |child| if (find(child, ordinal)) |found| return found;
            for (el.children.items) |child| if (find(child, ordinal)) |found| return found;
            return null;
        }
    };
    var ordinal: usize = 0;
    const button = ButtonFinder.find(mounted.root, &ordinal) orelse return error.FinderMatchedNothing;
    const render = button.renderObject() orelse return error.NoRenderObject;
    mounted.tapAt(.{
        .x = render.origin.x + render.size.width / 2,
        .y = render.origin.y + render.size.height / 2,
    });

    try std.testing.expectEqualStrings("/setup", navigation.url);
    try std.testing.expectEqual(phantom.OpenMode.same_tab, navigation.mode.?);
}

test "the identity-provider button performs a same-tab navigation" {
    const fixture = AuthEntryFixture{ .setup_route = false, .setup = false, .mode = "oidc" };
    var mounted = try phantom.testing.mount(std.testing.allocator, fixture.widget());
    defer mounted.deinit();
    try mounted.pump();

    const OpenSpy = struct {
        url: []const u8 = "",
        mode: ?phantom.OpenMode = null,
        fn open(ctx: *anyopaque, url: []const u8, mode: phantom.OpenMode) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.url = url;
            self.mode = mode;
            return true;
        }
    };
    var opened = OpenSpy{};
    mounted.owner.platform = .{ .ctx = &opened, .open_url = OpenSpy.open };

    const ButtonFinder = struct {
        fn find(el: *phantom.Element) ?*phantom.Element {
            if (std.mem.eql(u8, el.type_name, @typeName(phantom.Button))) return el;
            if (el.child) |child| if (find(child)) |found| return found;
            for (el.children.items) |child| if (find(child)) |found| return found;
            return null;
        }
    };
    const button = ButtonFinder.find(mounted.root) orelse return error.FinderMatchedNothing;
    const render = button.renderObject() orelse return error.NoRenderObject;
    mounted.tapAt(.{
        .x = render.origin.x + render.size.width / 2,
        .y = render.origin.y + render.size.height / 2,
    });

    try std.testing.expectEqualStrings("/auth/login", opened.url);
    try std.testing.expectEqual(phantom.OpenMode.same_tab, opened.mode.?);
}

test "tapping the setup account choice updates the auth page" {
    const fixture = AuthEntryFixture{};
    var mounted = try phantom.testing.mount(std.testing.allocator, fixture.widget());
    defer mounted.deinit();
    try mounted.pump();

    const first_button = try mounted.stateOf(phantom.testing.find.byType(AuthEntryFixture), AuthEntryFixture.State);
    try std.testing.expect(first_button.auth.setup_oidc_mode);
    const ButtonFinder = struct {
        fn find(el: *phantom.Element) ?*phantom.Element {
            if (std.mem.eql(u8, el.type_name, @typeName(phantom.Button))) return el;
            if (el.child) |child| if (find(child)) |found| return found;
            for (el.children.items) |child| if (find(child)) |found| return found;
            return null;
        }
    };
    const button_element = ButtonFinder.find(mounted.root) orelse return error.FinderMatchedNothing;
    const button_ro = button_element.renderObject() orelse return error.NoRenderObject;
    mounted.tapAt(.{
        .x = button_ro.origin.x + button_ro.size.width / 2,
        .y = button_ro.origin.y + button_ro.size.height / 2,
    });

    const rebuilt = try mounted.stateOf(phantom.testing.find.byType(AuthEntryFixture), AuthEntryFixture.State);
    try std.testing.expect(!rebuilt.auth.setup_oidc_mode);
}
