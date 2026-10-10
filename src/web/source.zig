//! A `chock-ui` source that reaches `chock serve` over HTTP.
//!
//! The browser half of the seam. Phantom gives the page an `Io` whose sockets
//! are really `fetch`, so a plain `std.http.Client` works here and the page
//! needs no wire format of its own.

const std = @import("std");
const phantom = @import("phantom");
const chock_ui = @import("chock-ui");
const event = @import("chock-proto").event;

const ui_source = chock_ui.source;
const Source = ui_source.Source;

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
        return std.fmt.bufPrint(&self.project_query, "&project={s}", .{self.watching_project}) catch "";
    }

    /// `&project=...` for a request about the session being followed, or nothing
    /// when serve's own project is the right one.
    fn namedProject(self: *Web, arena: std.mem.Allocator) []const u8 {
        if (self.watching_project.len == 0) return "";
        return std.fmt.allocPrint(arena, "&project={s}", .{self.watching_project}) catch "";
    }

    pub fn source(self: *Web) Source {
        return .{ .ptr = self, .vtable = &vtable, .name = "daemon" };
    }

    const vtable: Source.VTable = .{
        .sessions = sessions,
        .events = events,
        .asks = asks,
        .prompt = prompt,
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
        const url = std.fmt.allocPrint(arena, "http://{s}{s}", .{ self.origin, target }) catch
            return error.OutOfMemory;

        var client: std.http.Client = .{ .allocator = self.gpa, .io = self.owner.io };
        defer client.deinit();

        var body: std.Io.Writer.Allocating = .init(arena);
        const reply = client.fetch(.{
            .location = .{ .url = url },
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

        if (reply.status != .ok) {
            self.note(reply.status.phrase() orelse "the daemon refused");
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
        try self.post(arena, target, message);
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
        try self.post(arena, target, "");
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
    ) ui_source.Error!void {
        if (!self.reachable()) return error.Unreachable;
        const url = std.fmt.allocPrint(arena, "http://{s}{s}", .{ self.origin, target }) catch
            return error.OutOfMemory;

        var client: std.http.Client = .{ .allocator = self.gpa, .io = self.owner.io };
        defer client.deinit();

        var body: std.Io.Writer.Allocating = .init(arena);
        const reply = client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = if (payload.len == 0) null else payload,
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
                std.fmt.bufPrint(&room, "{s} ({d})", .{
                    said[0..@min(said.len, 400)],
                    @intFromEnum(reply.status),
                }) catch said
            else
                reply.status.phrase() orelse "the daemon refused");
            return error.Refused;
        }
        self.clear();
    }

    fn whyLast(ptr: *anyopaque) ?[]const u8 {
        const self: *Web = @ptrCast(@alignCast(ptr));
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
