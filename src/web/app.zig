//! The page a person uses: the interface the terminal and the window draw, fed
//! from `chock serve`.
//!
//! No screens of its own. The tree is `chock-ui`'s `Ui`, built by `Ui.rootOf`,
//! and this file is only the wiring: a host, a source, and a stream that turns
//! the daemon's events into the same `replay` calls a native run makes.
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

pub const App = struct {
    pub fn widget(self: *const App) phantom.Widget {
        return phantom.stateful.statefulWidget(App, self);
    }

    pub const State = struct {
        base: phantom.StateBase = .{},
        reaching: ?web_source.Web = null,
        from_host: ?web_host.Web = null,
        ui: ?*chock_ui.Ui = null,
        /// The session being read, owned, because the row it came from is
        /// rebuilt every frame.
        opened: ?[]u8 = null,
        /// The stream carrying that session's events, closed when another
        /// session is opened.
        stream: ?phantom.EventSource = null,
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

        pub fn dispose(self: *State) void {
            const gpa = self.base.element.owner.gpa;
            self.closeStream();
            if (self.ui) |one| one.deinit();
            if (self.opened) |one| gpa.free(one);
            if (self.reaching) |*one| one.deinit();
        }

        pub fn build(self: *State, ctx: *phantom.BuildContext) anyerror!phantom.Widget {
            const ui = self.interface() orelse
                return ctx.new(phantom.Text{ .text = "out of memory" }).widget();

            self.followPick(ui);
            self.followSubmit(ui);
            return chock_ui.Ui.rootOf(ctx, ui);
        }

        /// The interface, made on the first build.
        ///
        /// Not made in `initState`: the owner's `io` is still `std.Io.failing`
        /// then, and a source built on that copy reads a dead network forever.
        fn interface(self: *State) ?*chock_ui.Ui {
            if (self.ui) |one| return one;

            const owner = self.base.element.owner;
            const origin = owner.platform.readHost(&origin_buffer) orelse "";
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

            // A link or a reload names the session it was looking at. With
            // nothing named, the first thing shown is the list of them, the same
            // picker a person opens in a terminal.
            // Beside the transcript and not over it, so the list stays in view
            // while a session is read. A narrow page falls back to the picker,
            // which `toggleSessions` does by itself.
            one.toggleSessions();
            if (self.namedSession()) |id| self.open(one, id);
            return one;
        }

        /// The session the address bar names, or null when it names none.
        fn namedSession(self: *State) ?[]const u8 {
            const said = self.base.element.owner.platform.readLocation(&location_buffer) orelse
                return null;
            if (!std.mem.startsWith(u8, said, session_path)) return null;
            const id = said[session_path.len..];
            if (id.len == 0 or id.len > 64) return null;
            for (id) |one| if (!std.ascii.isAlphanumeric(one)) return null;
            return id;
        }

        /// Take up whatever the picker chose, and say so in the address bar.
        fn followPick(self: *State, ui: *chock_ui.Ui) void {
            const chosen = ui.taken orelse return;
            ui.taken = null;
            self.open(ui, chosen);

            var room: [128]u8 = undefined;
            const said = std.fmt.bufPrint(&room, session_path ++ "{s}", .{chosen}) catch return;
            // A push and not a replace: the list is where the back button goes.
            self.base.element.owner.platform.writeLocation(said, .push);
        }

        /// Read one session, whether a person picked it or a link named it.
        fn open(self: *State, ui: *chock_ui.Ui, id: []const u8) void {
            const gpa = self.base.element.owner.gpa;
            const kept = gpa.dupe(u8, id) catch return;
            if (self.opened) |one| gpa.free(one);
            self.opened = kept;
            ui.current_session = kept;
            self.reaching.?.watch(kept);
            self.seen = 0;
            self.listen(kept);
        }

        /// Send whatever a person typed.
        fn followSubmit(self: *State, ui: *chock_ui.Ui) void {
            if (!ui.submitted) return;
            defer ui.beginInput();

            const session = self.opened orelse return;
            switch (chock_ui.ui.answerFor(ui.typed.items)) {
                .nothing => {},
                // The commands act on a loop this page is not inside, so saying
                // nothing would look like the message was sent.
                .command => {
                    ui.say(.chock, "a command only works where the session is running");
                    ui.endLine();
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

        /// Follow one session's events from the start of its log.
        ///
        /// A stream and not a poll: the page has no timer of its own, so
        /// something has to push. The whole log comes first, which is what fills
        /// the transcript, and then each new event as it is written.
        fn listen(self: *State, session: []const u8) void {
            self.closeStream();
            const ui = self.ui orelse return;

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
            const running = self.stream orelse return;
            self.stream = null;
            self.base.element.owner.platform.closeEventSource(running);
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
            ui.replay(at, envelope.event);
        }

        fn repaint(ctx: *anyopaque) void {
            const self: *State = @ptrCast(@alignCast(ctx));
            phantom.stateful.markNeedsBuild(self);
        }
    };
};
