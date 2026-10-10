//! The browser half of `chock-ui`'s `Host`.
//!
//! A page draws its own frames, so the calls a terminal answers by blocking on
//! a key or re-reading its window size answer nothing here. What is left is the
//! clock, the repaint request, and the list of sessions a person may open.

const std = @import("std");
const phantom = @import("phantom");
const chock_ui = @import("chock-ui");

const web_source = @import("source.zig");

pub const Web = struct {
    /// The state holding the tree, so a repaint can be asked for.
    state: *anyopaque,
    /// Marks `state` as needing a build. Held as a function because the state's
    /// type lives in `app.zig` and this file must not know it.
    repaint: *const fn (state: *anyopaque) void,
    /// Where the sessions come from. The same source the page reads its
    /// transcript through.
    reaching: *web_source.Web,
    /// The page's own `Io`, whose real clock is the browser's `Date.now`.
    io: std.Io,

    pub fn host(self: *Web) chock_ui.Host {
        return .{ .ptr = self, .vtable = &vtable, .name = "browser" };
    }

    const vtable: chock_ui.Host.VTable = .{
        .flushOut = nothing,
        .writeOut = dropped,
        .scrollCount = none,
        .verbose = off,
        .colorOn = on,
        .requestStop = nothing,
        .stopRequested = off,
        .interrupt = ignored,
        .nowMs = nowMs,
        .utcOffsetMinutes = noOffset,
        .invalidate = invalidate,
        .focusLast = nothing,
        .hasFocus = on,
        .takeKeys = atKeys,
        .giveKeys = atKeys,
        // The page already has the keys: phantom's web backend hands a press
        // straight to the tree, so there is nothing to take and nothing to
        // read, and the interface still draws its key hints.
        .answersKeys = on,
        .dropKeys = nothing,
        .pumpKeys = none,
        .keysWaiting = off,
        .step = carryOn,
        .followSize = nothing,
        .finish = nothing,
        .release = nothing,
        .resumables = resumables,
    };

    fn nowMs(ptr: *anyopaque) i64 {
        const self: *Web = @ptrCast(@alignCast(ptr));
        return std.Io.Timestamp.now(self.io, .real).toMilliseconds();
    }

    fn invalidate(ptr: *anyopaque) void {
        const self: *Web = @ptrCast(@alignCast(ptr));
        self.repaint(self.state);
    }

    /// Every session the daemon knows, less the one being looked at.
    fn resumables(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        current: []const u8,
    ) ?[]const chock_ui.model.Resumable {
        const self: *Web = @ptrCast(@alignCast(ptr));
        const found = self.reaching.source().sessions(arena) catch return null;

        var offered: std.ArrayList(chock_ui.model.Resumable) = .empty;
        for (found) |one| {
            if (std.mem.eql(u8, one.id, current)) continue;
            const note = std.fmt.allocPrint(arena, "{s}  {s}", .{
                one.live.text(),
                one.model,
            }) catch one.live.text();
            const words = chock_ui.model.resumableWords(arena, one.id, one.title, note) catch one.id;
            offered.append(arena, .{
                .id = one.id,
                .words = words,
                .group = one.project,
                .refusal = refusalFor(one),
            }) catch return null;
        }
        return offered.items;
    }

    /// What stops a session being opened from a browser, in words.
    fn refusalFor(one: chock_ui.source.Session) []const u8 {
        // Two writers on one log.
        if (one.live == .live) return "it is running";
        // The daemon is told which project a session is in, and nothing wrote
        // this one down. A session started since then records it.
        if (one.project_root.len == 0) return "its project directory was never recorded";
        return "";
    }

    fn nothing(_: *anyopaque) void {}
    fn dropped(_: *anyopaque, _: []const u8) void {}
    fn none(_: *anyopaque) usize {
        return 0;
    }
    fn off(_: *anyopaque) bool {
        return false;
    }
    fn on(_: *anyopaque) bool {
        return true;
    }
    fn ignored(_: *anyopaque, _: usize) void {}
    fn atKeys(_: *anyopaque, _: chock_ui.host.When) void {}
    fn noOffset(_: *anyopaque) i32 {
        return 0;
    }
    /// The page owns the frames, so the interface never asks the loop to stop.
    fn carryOn(_: *anyopaque, _: u32) bool {
        return true;
    }
};
