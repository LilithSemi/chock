//! Chock's Android client. The daemon and HTTP API stay on a development
//! machine; this APK contains only the shared interface and its remote wiring.

const std = @import("std");
const phantom = @import("phantom");
const app = @import("chock-remote-app");
const servers = @import("servers.zig");

pub fn root(ctx: *phantom.BuildContext) phantom.Widget {
    return ctx.new(Connection{}).widget();
}

/// Chooses the served API at runtime, so pointing a device at another machine
/// never requires rebuilding the APK.
const Connection = struct {
    pub fn widget(self: *const Connection) phantom.Widget {
        return phantom.StatefulWidget(Connection, self);
    }

    pub const State = struct {
        const ConnectionState = @This();

        base: phantom.StateBase = .{},
        field: phantom.TextFieldController = .{},
        api_host: std.ArrayList(u8) = .empty,
        saved: servers.List = .{},
        initial_host: []u8 = &.{},
        connected: bool = false,

        pub fn initState(self: *State, _: *const Connection) !void {
            var encoded: [servers.max_setting_bytes]u8 = undefined;
            const platform = self.base.element.owner.platform;
            const value = platform.readSetting(servers.setting_key, &encoded) catch |err| switch (err) {
                error.Unsupported, error.StorageFailure, error.BufferTooSmall => return,
                error.InvalidKey => return err,
            };
            if (value) |text| try self.saved.load(self.base.gpa(), text);
            if (self.saved.items.items.len != 0)
                self.initial_host = try self.base.gpa().dupe(u8, self.saved.items.items[0]);
        }

        pub fn dispose(self: *State) void {
            const gpa = self.base.gpa();
            self.api_host.deinit(gpa);
            self.saved.deinit(gpa);
            gpa.free(self.initial_host);
        }

        fn connect(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            const host = servers.normalized(self.field.text()) orelse {
                self.base.sink().report(.state_update, "enter a valid HTTP(S) server origin without a path or credentials");
                return;
            };
            self.api_host.clearRetainingCapacity();
            self.api_host.appendSlice(self.base.gpa(), host) catch {
                self.base.sink().report(.oom, "out of memory keeping the API host");
                return;
            };
            self.saved.remember(self.base.gpa(), host) catch |err| {
                self.base.sink().report(.state_update, @errorName(err));
                return;
            };
            const encoded = self.saved.encode(self.base.gpa()) catch |err| {
                self.base.sink().report(.state_update, @errorName(err));
                return;
            };
            defer self.base.gpa().free(encoded);
            self.base.element.owner.platform.writeSetting(servers.setting_key, encoded) catch |err| switch (err) {
                error.Unsupported => {},
                else => self.base.sink().report(.state_update, @errorName(err)),
            };
            self.connected = true;
            phantom.markNeedsBuild(self);
        }

        fn changeServer(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            self.connected = false;
            phantom.markNeedsBuild(self);
        }

        fn forgetServer(self: *State, server: []const u8) void {
            if (!self.saved.forget(self.base.gpa(), server)) return;
            const encoded = self.saved.encode(self.base.gpa()) catch |err| {
                self.base.sink().report(.state_update, @errorName(err));
                phantom.markNeedsBuild(self);
                return;
            };
            defer self.base.gpa().free(encoded);
            self.base.element.owner.platform.writeSetting(servers.setting_key, encoded) catch |err| switch (err) {
                error.Unsupported => {},
                else => self.base.sink().report(.state_update, @errorName(err)),
            };
            phantom.markNeedsBuild(self);
        }

        /// A stateful wrapper keeps the callback context alive after Phantom
        /// resets the build scratch arena. The server slice itself belongs to
        /// the connection state's saved list and is stable until unmount.
        const SavedServer = struct {
            owner: *ConnectionState,
            server: []const u8,

            fn widget(self: *const SavedServer) phantom.Widget {
                return phantom.StatefulWidget(SavedServer, self);
            }

            const ButtonState = struct {
                base: phantom.StateBase = .{},
                owner: *ConnectionState = undefined,
                server: []const u8 = "",

                pub fn initState(self: *ButtonState, config: *const SavedServer) !void {
                    self.owner = config.owner;
                    self.server = config.server;
                }

                pub fn didUpdateWidget(self: *ButtonState, config: *const SavedServer) !void {
                    self.owner = config.owner;
                    self.server = config.server;
                }

                fn choose(ctx: *anyopaque) void {
                    const self: *ButtonState = @ptrCast(@alignCast(ctx));
                    self.owner.field.setText(self.server) catch {
                        self.owner.base.sink().report(.oom, "out of memory selecting a saved server");
                        return;
                    };
                    connect(self.owner);
                }

                fn forget(ctx: *anyopaque) void {
                    const self: *ButtonState = @ptrCast(@alignCast(ctx));
                    self.owner.forgetServer(self.server);
                }

                pub fn build(self: *ButtonState, b: *phantom.BuildContext) !phantom.Widget {
                    const forget_id = try std.fmt.allocPrint(b.arena, "forget-{s}", .{self.server});
                    return b.new(phantom.Row(.{ .children = b.newSlice(phantom.Widget, &.{
                        b.new(phantom.Button{
                            .id = self.server,
                            .variant = .secondary,
                            .ctx = self,
                            .on_tap = choose,
                            .child = b.new(phantom.Text{ .text = self.server }).widget(),
                        }).widget(),
                        b.new(phantom.Button{
                            .id = forget_id,
                            .variant = .secondary,
                            .ctx = self,
                            .on_tap = forget,
                            .child = b.new(phantom.Text{ .text = "Forget" }).widget(),
                        }).widget(),
                    }) })).widget();
                }
            };

            pub const State = ButtonState;
        };

        fn key(ctx: *anyopaque, event: phantom.input.KeyEvent) bool {
            if (event.keysym != .enter or event.mods.shift or event.mods.alt) return false;
            connect(ctx);
            return true;
        }

        pub fn build(self: *State, b: *phantom.BuildContext) !phantom.Widget {
            if (self.connected) {
                const theme = phantom.Theme.of(b);
                const header = b.new(phantom.Row(.{ .children = b.newSlice(phantom.Widget, &.{
                    b.new(phantom.Expanded(.{ .child = b.new(phantom.Text{
                        .text = self.api_host.items,
                        .color = theme.colors.fg_muted,
                        .wrap = true,
                    }).widget() })).widget(),
                    b.new(phantom.Button{
                        .id = "change-server",
                        .variant = .secondary,
                        .ctx = self,
                        .on_tap = changeServer,
                        .child = b.new(phantom.Text{ .text = "Change server" }).widget(),
                    }).widget(),
                }) })).widget();
                return b.new(phantom.Column(.{ .children = b.newSlice(phantom.Widget, &.{
                    b.new(phantom.Padding{ .insets = .symmetric(12, 8), .child = header }).widget(),
                    b.new(phantom.Expanded(.{ .child = b.new(app.App{
                        .api_host = self.api_host.items,
                        .poll_events = true,
                    }).widget() })).widget(),
                }) })).widget();
            }

            const theme = phantom.Theme.of(b);
            const gap12 = b.new(phantom.SizedBox{
                .height = 12,
                .child = b.new(phantom.ColoredBox{ .color = .{ .a = 0 } }).widget(),
            }).widget();
            const gap20 = b.new(phantom.SizedBox{
                .height = 20,
                .child = b.new(phantom.ColoredBox{ .color = .{ .a = 0 } }).widget(),
            }).widget();
            const field = b.new(phantom.TextField{
                .id = "chock-api-host",
                .placeholder = "https://chock.example",
                .text = self.initial_host,
                .controller = &self.field,
                .on_key = key,
                .ctx = self,
            }).widget();
            const framed = b.new(phantom.DecoratedBox{
                .color = theme.colors.bg_dark,
                .radius = 8,
                .border_color = theme.colors.fg_dim,
                .border_width = 1,
                .child = b.new(phantom.Padding{
                    .insets = .symmetric(12, 10),
                    .child = field,
                }).widget(),
            }).widget();
            const button = b.new(phantom.Button{
                .id = "connect",
                .ctx = self,
                .on_tap = connect,
                .child = b.new(phantom.Text{ .text = "Connect" }).widget(),
            }).widget();
            var children: std.ArrayList(phantom.Widget) = .empty;
            try children.append(b.arena, b.new(phantom.Text{ .text = "Chock server" }).widget());
            try children.append(b.arena, gap12);
            try children.append(b.arena, b.new(phantom.Text{
                .text = "Enter a server, or reconnect to one saved on this device. Use HTTPS outside a trusted local network.",
                .color = theme.colors.fg_muted,
            }).widget());
            try children.append(b.arena, gap20);
            try children.append(b.arena, framed);
            try children.append(b.arena, gap12);
            try children.append(b.arena, button);
            if (self.saved.items.items.len != 0) {
                try children.append(b.arena, gap20);
                try children.append(b.arena, b.new(phantom.Text{ .text = "Saved servers" }).widget());
                for (self.saved.items.items) |server| {
                    try children.append(b.arena, gap12);
                    try children.append(b.arena, b.new(SavedServer{ .owner = self, .server = server }).widget());
                }
            }
            const form = b.new(phantom.SizedBox{
                .width = 480,
                .child = b.new(phantom.Column(.{
                    .children = children.items,
                })).widget(),
            }).widget();
            return b.new(phantom.Padding{
                .insets = .all(24),
                .child = b.new(phantom.Center(.{ .child = form })).widget(),
            }).widget();
        }
    };
};
