//! Chock's Android client. The daemon and HTTP API stay on a development
//! machine; this APK contains only the shared interface and its remote wiring.

const std = @import("std");
const phantom = @import("phantom");
const app = @import("chock-remote-app");

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
        base: phantom.StateBase = .{},
        field: phantom.TextFieldController = .{},
        api_host: std.ArrayList(u8) = .empty,
        connected: bool = false,

        pub fn dispose(self: *State) void {
            self.api_host.deinit(self.base.gpa());
        }

        fn connect(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            const host = std.mem.trim(u8, self.field.text(), " \t\r\n/");
            if (host.len == 0) return;
            self.api_host.clearRetainingCapacity();
            self.api_host.appendSlice(self.base.gpa(), host) catch {
                self.base.sink().report(.oom, "out of memory keeping the API host");
                return;
            };
            self.connected = true;
            phantom.markNeedsBuild(self);
        }

        fn key(ctx: *anyopaque, event: phantom.input.KeyEvent) bool {
            if (event.keysym != .enter or event.mods.shift or event.mods.alt) return false;
            connect(ctx);
            return true;
        }

        pub fn build(self: *State, b: *phantom.BuildContext) !phantom.Widget {
            if (self.connected) return b.new(app.App{
                .api_host = self.api_host.items,
                .poll_events = true,
            }).widget();

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
                .placeholder = "192.168.1.20:7374",
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
            const form = b.new(phantom.SizedBox{
                .width = 480,
                .child = b.new(phantom.Column(.{
                    .children = b.newSlice(phantom.Widget, &.{
                        b.new(phantom.Text{ .text = "Chock server" }).widget(),
                        gap12,
                        b.new(phantom.Text{
                            .text = "Enter the host and port printed by chock serve.",
                            .color = theme.colors.fg_muted,
                        }).widget(),
                        gap20,
                        framed,
                        gap12,
                        button,
                    }),
                })).widget(),
            }).widget();
            return b.new(phantom.Padding{
                .insets = .all(24),
                .child = b.new(phantom.Center(.{ .child = form })).widget(),
            }).widget();
        }
    };
};
