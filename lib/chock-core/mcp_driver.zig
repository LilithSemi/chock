//! The production `mcp.Host`: a real MCP server, in the sandbox, over a
//! `helper.Helper`, speaking JSON-RPC on descriptors 0 and 1.
//!
//! `lib/chock-core/mcp.zig` is everything above the seam and holds every
//! decision this file only carries out: which tools may be offered, which name
//! may not be taken, what a result may carry into the context, and why the
//! tool list is read one time. Read that file first.
//!
//! ## The transport is stdio, and the other one is not built
//!
//! MCP has two transports: **stdio**, where the server is a child process on
//! two pipes, and **streamable HTTP**, where the server is a URL. This file
//! builds stdio and nothing else, and there is no half of the second one here.
//!
//! Stdio is the one that fits what Chock already has. `helper.Helper` runs a
//! long lived program inside the sandbox on exactly two pipes, and it was
//! built for a language server, an MCP server and a plugin host together. The
//! HTTP shape would need this process to hold a connection to a server the
//! sandbox has no part in, which puts the server outside every boundary this
//! project has and makes the sandbox a decoration. A project that wants a
//! remote server today runs a stdio bridge as its command.
//!
//! ## The framing is one line per message, and it is not the LSP's
//!
//! **A language server writes `Content-Length` headers. An MCP server does
//! not.** One message is one line of JSON, and a message may hold no raw
//! newline. Measured against `mcp-server-time` 2026.7.10 on 2026-08-23: every
//! reply arrived as one line ending in `\n`, with no header of any kind.
//!
//! This is written out because it is exactly the class of mistake a test
//! against a stand-in hides. A driver written from the LSP driver's own shape
//! would have sent headers, and a test server written by the same hand would
//! have read them, and the pair would have passed every test and talked to no
//! real server at all. `test/core/mcp_real_probe.zig` runs a real one for that
//! reason.
//!
//! ## What a reply is, and what only looks like one
//!
//! A server writes far more than answers. `awaitReply` walks past all of it,
//! and each rule below is a fault the LSP driver learned the hard way:
//!
//! * **A notification is not a reply.** It carries a `method` and no `id`.
//! * **A request from the server is not a reply either, even with our own
//!   id.** It carries a `method` **and** an `id`. A server that asks the
//!   client a question numbers it in its own sequence, which starts at 1, the
//!   same place this client's does. So the test for a reply is not "the id
//!   matches": it is "the id matches, and there is no `method`, and there is a
//!   `result` or an `error`". A driver that tested the id alone would read the
//!   server's first question as the answer to its own first request.
//! * **A line that is not JSON is skipped.** The framing is still in step,
//!   because the framing is the newline.
//! * **A line longer than `max_inbox_bytes` ends the server.** The sender is a
//!   third party program, so a message that never ends must not grow this
//!   process until the machine complains.
//!
const std = @import("std");

const helper = @import("helper.zig");
const mcp = @import("mcp.zig");

/// The protocol version this client states. The server answers with the one it
/// picked, and **nothing here reads that answer**, for the reason
/// `chock_core.lsp_driver.handshake` gives about capabilities: a third party
/// program must not have a second road to change what Chock does.
pub const protocol_version = "2025-06-18";

/// What this client calls itself in the handshake. Servers log it.
pub const client_name = "chock";

/// The most this driver will hold of a message that has not finished
/// arriving.
///
/// **A bound is needed because the sender is a third party program.** A server
/// that writes a line and never ends it would otherwise grow this buffer until
/// the machine complains. Four mebibytes is far above any real message:
/// `mcp.max_result_bytes` means 32 kibibytes reach the model, and a server
/// that answers a hundred times that still writes well under this.
pub const max_inbox_bytes = 4 << 20;

const read_chunk_bytes = 4096;

/// The JSON object with no fields in it.
///
/// **`.{}` is a tuple in Zig and `std.json.Stringify` writes a tuple as
/// `[]`.** So a `capabilities` written as `.{}` reaches the server as
/// `"capabilities":[]` where the protocol requires an object. That exact
/// mistake made this project's whole LSP feature fail against a real server:
/// see `chock_core.lsp_driver`'s own `empty_object`, which carries the
/// measurement.
const empty_object = struct {}{};

/// The half of this file that speaks the protocol over one `helper.Channel`.
///
/// **Separate from `Driver` so a test can drive a real server with no sandbox
/// at all.** A `helper.Channel` is two ordinary pipes, so the production
/// framing, the production JSON and the production reply walk can all be
/// pointed at a real `mcp-server-time` on this machine. That is what
/// `test/core/mcp_real_probe.zig` does, and it is worth more than any number
/// of servers written here: see this file's own top comment.
pub const Protocol = struct {
    /// The allocator `inbox` lives in. It outlives one exchange by definition.
    gpa: std.mem.Allocator,

    /// Bytes read from the server and not yet consumed. **It survives an
    /// exchange that ran out of budget**, which is the whole reason it is a
    /// field.
    inbox: std.ArrayList(u8) = .empty,

    /// Whether `initialize` and `notifications/initialized` have been through.
    ready: bool = false,

    /// The id of the last request this client sent.
    last_id: i64 = 0,

    /// The id of the `initialize` this client already put on the wire, or null
    /// before it sent one.
    ///
    /// **It is remembered so a handshake that ran out of budget is waited for
    /// again and never sent again.** `initialize` may go out one time per
    /// server: a second one is a protocol error, and a real server answers it
    /// with an error rather than a capability set, so a client that re-sent it
    /// after one slow first answer would turn a late reply into a dead server.
    /// Nothing was lost by the timeout, because the reply is still in the pipe:
    /// see `helper.Channel.read`.
    handshake_id: ?i64 = null,

    /// How many times the server said its tool list changed. See
    /// `lib/chock-core/mcp.zig` on the ratchet.
    list_changed: usize = 0,

    pub fn deinit(self: *Protocol) void {
        self.inbox.deinit(self.gpa);
        self.* = undefined;
    }

    /// Every tool the server declares, in `arena`.
    pub fn list(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error![]const mcp.Declared {
        try self.handshake(arena, io, channel, deadline);

        const reply = try self.request(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .id = self.nextId(),
            .method = "tools/list",
            .params = empty_object,
        });

        const result = objectField(reply, "result") orelse return &.{};
        const declared = result.get("tools") orelse return &.{};
        if (declared != .array) return &.{};

        var out: std.ArrayList(mcp.Declared) = .empty;
        for (declared.array.items) |item| {
            if (item != .object) continue;
            const name = item.object.get("name") orelse continue;
            if (name != .string) continue;
            const description = blk: {
                const raw = item.object.get("description") orelse break :blk "";
                if (raw != .string) break :blk "";
                break :blk raw.string;
            };
            // The protocol spells it `inputSchema`. A server that sends none,
            // or sends something a schema cannot be, gets the empty object
            // from `mcp.Session.admit`, which is where that decision lives.
            const schema = item.object.get("inputSchema") orelse std.json.Value.null;
            try out.append(arena, .{
                .name = name.string,
                .description = description,
                .schema = schema,
            });
        }
        return out.toOwnedSlice(arena);
    }

    /// Call one tool, and answer what the server said.
    pub fn call(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        name: []const u8,
        arguments: []const u8,
    ) mcp.Error!mcp.Outcome {
        try self.handshake(arena, io, channel, deadline);

        // **The model's own JSON, parsed and put back.** The arguments arrive
        // as text, and the protocol wants an object. A text that is not an
        // object at all becomes the empty object rather than a parse error the
        // server has to explain, which is what a built-in tool does with the
        // same input.
        const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, arguments, .{}) catch
            std.json.Value.null;
        const args: std.json.Value = if (parsed == .object)
            parsed
        else
            std.json.parseFromSliceLeaky(std.json.Value, arena, "{}", .{}) catch
                return error.OutOfMemory;

        const reply = try self.request(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .id = self.nextId(),
            .method = "tools/call",
            .params = .{ .name = name, .arguments = args },
        });

        // **A JSON-RPC error is a result and never a fault of this host.** The
        // server ran and said no, which is exactly what a built-in tool that
        // refuses does, and the model reads it and acts on it.
        if (objectField(reply, "error")) |failure| {
            const message = failure.get("message") orelse std.json.Value.null;
            const text = if (message == .string) message.string else "the server refused the call";
            return .{ .text = text, .is_error = true };
        }

        const result = objectField(reply, "result") orelse
            return .{ .text = "the server answered nothing", .is_error = true };

        var text: std.ArrayList(u8) = .empty;
        if (result.get("content")) |content| {
            if (content == .array) {
                for (content.array.items) |part| {
                    if (part != .object) continue;
                    const kind = part.object.get("type") orelse std.json.Value.null;
                    const kind_name = if (kind == .string) kind.string else "";
                    const body = part.object.get("text") orelse std.json.Value.null;
                    if (body == .string and std.mem.eql(u8, kind_name, "text")) {
                        if (text.items.len != 0) try text.append(arena, '\n');
                        try text.appendSlice(arena, body.string);
                        continue;
                    }
                    // **A part this build cannot show is named and not
                    // dropped.** An image or an embedded resource is a real
                    // answer, and a model told there was one can ask for
                    // something else. A model shown nothing believes the tool
                    // answered nothing.
                    if (text.items.len != 0) try text.append(arena, '\n');
                    const named = try std.fmt.allocPrint(
                        arena,
                        "[chock: the server sent a {s} part, which this build does not carry]",
                        .{if (kind_name.len != 0) kind_name else "content"},
                    );
                    try text.appendSlice(arena, named);
                }
            }
        }

        // `isError` is the tool's own answer about itself, and the protocol
        // leaves it out for a call that worked.
        const failed = blk: {
            const raw = result.get("isError") orelse break :blk false;
            if (raw != .bool) break :blk false;
            break :blk raw.bool;
        };
        return .{ .text = try text.toOwnedSlice(arena), .is_error = failed };
    }

    fn nextId(self: *Protocol) i64 {
        self.last_id += 1;
        return self.last_id;
    }

    /// `initialize`, then `notifications/initialized`. Once per server.
    ///
    /// **Nothing in the reply is read.** The server answers a protocol version
    /// and a capability set, and acting on either would be a road for a third
    /// party program to change what Chock does. `chock_core.lsp_driver` reads
    /// exactly one field and says why; this one reads none, because no field
    /// here changes the meaning of anything that comes back.
    fn handshake(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error!void {
        if (self.ready) return;

        // Sent one time, and waited for as often as it takes. See
        // `handshake_id`.
        if (self.handshake_id == null) {
            const id = self.nextId();
            try self.send(arena, io, channel, deadline, .{
                .jsonrpc = "2.0",
                .id = id,
                .method = "initialize",
                .params = .{
                    .protocolVersion = protocol_version,
                    // An object, and never `.{}`: see `empty_object`.
                    .capabilities = empty_object,
                    .clientInfo = .{ .name = client_name, .version = "1" },
                },
            });
            // Recorded after the write, so a write that failed does not leave
            // this client believing a handshake is on the wire.
            self.handshake_id = id;
        }
        _ = try self.awaitReply(arena, io, channel, deadline, self.handshake_id.?);

        try self.send(arena, io, channel, deadline, .{
            .jsonrpc = "2.0",
            .method = "notifications/initialized",
            .params = empty_object,
        });

        // Set after the notification, so a write that failed leaves this
        // client believing no handshake happened rather than a half one.
        self.ready = true;
    }

    /// Send one request and wait for the reply that answers it.
    fn request(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) mcp.Error!std.json.Value {
        try self.send(arena, io, channel, deadline, message);
        return self.awaitReply(arena, io, channel, deadline, self.last_id);
    }

    /// Write one JSON-RPC message, and the newline that ends it, in **one**
    /// `writeAll`.
    ///
    /// One call and not two, so a failure can never leave a message on the
    /// wire with no newline behind it, which would join it to the next one.
    /// `helper.Channel.writeAll` poisons the channel on a partial write for
    /// the same reason, one layer down.
    fn send(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        message: anytype,
    ) mcp.Error!void {
        _ = self;
        const body = try std.json.Stringify.valueAlloc(arena, message, .{});
        const framed = try std.fmt.allocPrint(arena, "{s}\n", .{body});
        channel.writeAll(io, framed, deadline) catch |err| return switch (err) {
            // A write that ran out of budget left half a message behind and
            // poisoned the channel, so the server is finished with even though
            // the reason was a clock. Never `Late`, which would say the
            // session can ask again.
            error.Late, error.HelperGone => error.Gone,
        };
    }

    /// Read messages until the one that answers `id` arrives.
    ///
    /// See this file's own top comment for what is walked past and why the
    /// test is not on the id alone.
    fn awaitReply(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
        id: i64,
    ) mcp.Error!std.json.Value {
        while (true) {
            const message = try self.receive(arena, io, channel, deadline);
            if (message != .object) continue;
            const object = message.object;

            if (object.get("method")) |method| {
                // A message with a method is a notification or a request the
                // server made, and neither is an answer to anything this
                // client asked. **Even when it carries this client's own id.**
                if (method == .string and
                    std.mem.eql(u8, method.string, "notifications/tools/list_changed"))
                {
                    self.list_changed += 1;
                }
                continue;
            }

            const answered = object.get("id") orelse continue;
            if (answered != .integer or answered.integer != id) continue;
            // A reply carries one of the two, and a message with neither is
            // not a reply whatever its id says.
            if (object.get("result") == null and object.get("error") == null) continue;
            return message;
        }
    }

    /// The next whole message from the server, parsed.
    ///
    /// The parsed tree lives in `arena` and so does every string in it, which
    /// is why `mcp.Session.admit` copies what it keeps: the arena is the
    /// caller's and ends with the ask.
    fn receive(
        self: *Protocol,
        arena: std.mem.Allocator,
        io: std.Io,
        channel: *helper.Channel,
        deadline: std.Io.Clock.Timestamp,
    ) mcp.Error!std.json.Value {
        while (true) {
            if (try self.takeLine(arena)) |line| {
                // An empty line carries no message. A server that writes one
                // is not broken and the framing is still in step.
                if (line.len == 0) continue;
                // A line that is not JSON is skipped for the same reason: the
                // framing is the newline, so nothing is out of step. Giving up
                // here would end a server that wrote one odd line.
                const parsed = std.json.parseFromSliceLeaky(
                    std.json.Value,
                    arena,
                    line,
                    .{},
                ) catch continue;
                return parsed;
            }

            var scratch: [read_chunk_bytes]u8 = undefined;
            const count = channel.read(io, &scratch, deadline) catch |err| return switch (err) {
                error.Late => error.Late,
                error.HelperGone => error.Gone,
            };
            if (self.inbox.items.len + count > max_inbox_bytes) {
                // A server that writes more than this without a newline is one
                // this driver cannot talk to. Poison the channel so nothing
                // tries again with a buffer that is already out of step.
                channel.poisoned = true;
                return error.Gone;
            }
            try self.inbox.appendSlice(self.gpa, scratch[0..count]);
        }
    }

    /// The first whole line in `inbox`, copied into `arena`, with that line
    /// and its newline removed. Null when no whole line has arrived.
    ///
    /// **Nothing is removed for a line that is only partly here.** A server
    /// that died mid sentence leaves an incomplete line that is never mistaken
    /// for a whole one, which is what `Content-Length` does for the LSP driver
    /// and what the newline does here.
    ///
    /// A carriage return before the newline is dropped, so a server on a
    /// platform that writes `\r\n` is read the same way.
    fn takeLine(self: *Protocol, arena: std.mem.Allocator) mcp.Error!?[]const u8 {
        const end = std.mem.indexOfScalar(u8, self.inbox.items, '\n') orelse return null;
        var body = self.inbox.items[0..end];
        if (body.len != 0 and body[body.len - 1] == '\r') body = body[0 .. body.len - 1];
        const line = try arena.dupe(u8, body);
        self.inbox.replaceRange(self.gpa, 0, end + 1, &.{}) catch unreachable;
        return line;
    }
};

/// One MCP server, from the first ask of a session to the last.
///
/// **Owned by the caller that owns the session**, beside the `helper.Helper`
/// it drives and the `mcp.Session` that reads it.
pub const Driver = struct {
    /// The allocator the protocol state lives in. It outlives one ask by
    /// definition.
    gpa: std.mem.Allocator,

    /// The helper this driver speaks to. **Not owned**: the caller starts the
    /// session, ends the session, and owns everything that lasts as long.
    process: *helper.Helper,

    /// What to start, if it is not started yet. The sandbox in it is the same
    /// one a tool call gets, plus a network broker when this project's policy
    /// said so: see `mcp.networkActionInto`.
    request: helper.Request,

    /// The protocol state, which survives an ask that ran out of budget.
    protocol: Protocol,

    /// Why the server is finished with, or null while it works. Static text:
    /// see `mcp.start_failed`.
    failure: ?[]const u8 = null,

    pub fn init(gpa: std.mem.Allocator, process: *helper.Helper, request: helper.Request) Driver {
        return .{
            .gpa = gpa,
            .process = process,
            .request = request,
            .protocol = .{ .gpa = gpa },
        };
    }

    pub fn deinit(self: *Driver) void {
        self.protocol.deinit();
        self.* = undefined;
    }

    pub fn host(self: *Driver) mcp.Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = mcp.Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) mcp.Error![]const mcp.Declared {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.list(arena, io, channel, deadline) catch |err| {
            return self.note(err);
        };
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) mcp.Error!mcp.Outcome {
        const self: *Driver = @ptrCast(@alignCast(ptr));
        const channel = try self.live(io);
        const deadline = helper.Channel.deadlineIn(io, budget_ns);
        return self.protocol.call(arena, io, channel, deadline, name, arguments) catch |err| {
            return self.note(err);
        };
    }

    /// Keep the first reason a server was finished with, and hand the error
    /// on. **The first and not the last**, the rule every diagnostic in this
    /// project follows.
    fn note(self: *Driver, err: mcp.Error) mcp.Error {
        if (err == error.Gone and self.failure == null) self.failure = mcp.start_failed;
        return err;
    }

    /// The channel, starting the server if this is the first ask.
    ///
    /// **Started on the first ask and not at session start.** A project that
    /// names a server pays for it when its tools are first listed and not
    /// before, the same rule `chock_core.lsp_driver` keeps.
    fn live(self: *Driver, io: std.Io) mcp.Error!*helper.Channel {
        if (self.failure != null) return error.Gone;
        if (!self.process.started) {
            self.process.start(io, self.request) catch {
                self.failure = mcp.start_failed;
                return error.Gone;
            };
        }
        return self.process.live() orelse {
            if (self.failure == null) self.failure = mcp.start_failed;
            return error.Gone;
        };
    }
};

/// One field of a message, when the message is an object and the field is one
/// too. Null in every other case, because the whole message comes off a wire a
/// third party program wrote.
fn objectField(message: std.json.Value, name: []const u8) ?std.json.ObjectMap {
    if (message != .object) return null;
    const field = message.object.get(name) orelse return null;
    if (field != .object) return null;
    return field.object;
}

// No test here starts a sandbox, and none reads a clock to decide anything.
// Every test drives the production `Protocol` over two ordinary pipes and
// writes the real bytes a server writes, so the framing, the JSON and the
// reply walk are the production ones and a broken serialiser fails here.
//
// **What none of these can reach is agreement with a real server.** They prove
// this file talks to a peer written by the same hand, and that class of proof
// is worthless on its own. `test/core/mcp_real_probe.zig` runs a real
// `mcp-server-time` through this same `Protocol` for that reason, and the
// newline framing at the top of this file is a fact that came from it and not
// from here.

const testing = std.testing;
const chock_io = @import("chock-io");

/// Two pipes and the four descriptors they are made of, so a test can play the
/// server by hand. The same shape `chock_core.helper`'s own tests use.
const Pair = struct {
    channel: helper.Channel,
    /// The end the server would read its requests from.
    server_reads: std.Io.File,
    /// The end the server would write its replies to.
    server_writes: std.Io.File,

    fn open() !Pair {
        const driver = chock_io.default();
        const requests = try driver.pipeCloseOnExec();
        const replies = try driver.pipeCloseOnExec();
        return .{
            .channel = .{
                .to_helper = .{ .handle = requests.write_fd, .flags = .{ .nonblocking = false } },
                .from_helper = .{ .handle = replies.read_fd, .flags = .{ .nonblocking = false } },
            },
            .server_reads = .{ .handle = requests.read_fd, .flags = .{ .nonblocking = false } },
            .server_writes = .{ .handle = replies.write_fd, .flags = .{ .nonblocking = false } },
        };
    }

    /// Put bytes in the pipe as the server would. A pipe holds what is written
    /// until it is read, so a whole conversation can be staged before the
    /// client says anything and no thread is needed.
    fn serverSays(self: *Pair, io: std.Io, bytes: []const u8) !void {
        try std.Io.File.writeStreamingAll(self.server_writes, io, bytes);
    }

    /// Everything the client has written so far, up to `buffer.len`.
    fn clientWrote(self: *Pair, io: std.Io, buffer: []u8) ![]const u8 {
        var data: [1][]u8 = .{buffer};
        const count = try std.Io.File.readStreaming(self.server_reads, io, &data);
        return buffer[0..count];
    }

    /// A test that plays a server's exit closes one end itself and puts -1 in
    /// its place. Closing it twice would be a use after free.
    fn close(self: *Pair, io: std.Io) void {
        for ([_]std.Io.File{
            self.channel.to_helper,
            self.channel.from_helper,
            self.server_reads,
            self.server_writes,
        }) |file| {
            if (file.handle < 0) continue;
            std.Io.File.close(file, io);
        }
    }
};

/// A deadline far enough ahead that an exchange between two ends of one pipe
/// in one process reaches it only if something is genuinely stuck. Nothing
/// asserts how long anything took; this is a bound, not a measurement.
fn generousDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return helper.Channel.deadlineIn(io, 30 * std.time.ns_per_s);
}

/// The reply a server gives to `initialize`, as one line.
const initialize_reply =
    \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"probe","version":"1"}}}
++ "\n";

/// One `tools/list` reply with two tools, answering id 2.
const list_reply =
    \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_current_time","description":"Get current time","inputSchema":{"type":"object","properties":{"timezone":{"type":"string"}}}},{"name":"convert_time","description":"Convert","inputSchema":{"type":"object"}}]}}
++ "\n";

test "one exchange runs over two pipes, and the framing is a newline and never a header" {
    // The floor, and the one fact a driver written from the LSP driver's own
    // shape would get wrong. **An MCP server reads one line of JSON per
    // message and no header at all**, measured against `mcp-server-time`
    // 2026.7.10 on 2026-08-23.
    //
    // Mutation check: put a `Content-Length` header in front of the body in
    // `send` and this test fails, and so does `test/core/mcp_real_probe.zig`.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqualStrings("get_current_time", declared[0].name);
    try testing.expectEqualStrings("Get current time", declared[0].description);
    try testing.expect(declared[0].schema == .object);
    try testing.expectEqualStrings("convert_time", declared[1].name);

    // What really went on the wire: three messages, one per line, and not one
    // header byte among them.
    var buffer: [4096]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expect(std.mem.indexOf(u8, wrote, "Content-Length") == null);
    var lines = std.mem.tokenizeScalar(u8, wrote, '\n');
    const first = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, first, "\"method\":\"initialize\"") != null);
    // **The capabilities are an object and not an empty array.** `.{}` is a
    // tuple in Zig and writes as `[]`, which is the mistake that made this
    // project's whole LSP feature fail against a real server.
    try testing.expect(std.mem.indexOf(u8, first, "\"capabilities\":{}") != null);
    const second = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, second, "notifications/initialized") != null);
    const third = lines.next().?;
    try testing.expect(std.mem.indexOf(u8, third, "\"method\":\"tools/list\"") != null);
    try testing.expect(lines.next() == null);
}

test "a request the server sends with the client's own id is not read as the reply" {
    // A server numbers its own requests in its own sequence, which starts at 1
    // in the same place this client's does. So a test on the id alone would
    // read the server's first question as the answer to this client's first
    // request, and the handshake would finish against a message that answered
    // nothing.
    //
    // Mutation check: drop the `method` check in `awaitReply` and `list`
    // answers an empty list here rather than the two tools.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    // A real server request, with this client's own id on it.
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}
    ++ "\n");
    try pair.serverSays(io, initialize_reply);
    // And one with the id of the `tools/list` request, before its reply.
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"method":"roots/list"}
    ++ "\n");
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqualStrings("get_current_time", declared[0].name);
}

test "a notification, an empty line, and a line that is not JSON are all walked past" {
    // A real server logs, reports progress, and asks its own questions before
    // it answers anything: measured against `zls` for the LSP driver, and the
    // same shape here. A driver that treated any of them as an error would
    // give up on the first server that says hello.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, "\n");
    try pair.serverSays(io, "this is not JSON at all\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"hello"}}
    ++ "\n");
    // A reply to an id nobody asked about.
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":99,"result":{}}
    ++ "\n");
    // A message with our id and neither a result nor an error.
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":1}
    ++ "\n");
    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
}

test "a server that says its tool list changed is counted, and nothing is added" {
    // The ratchet: narrowing is free and widening needs authorisation, and
    // there is nobody to authorise one at that moment. The tool list of a
    // session is one slice built before the first request, so a widening has
    // nowhere to land. It is counted so a caller can say so once.
    //
    // Mutation check: act on the notification and there is no code to act
    // with, which is the point: `Session` holds no way to add an offer after
    // `admit`.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}
    ++ "\n");
    try pair.serverSays(io, list_reply);

    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 2), declared.len);
    try testing.expectEqual(@as(usize, 2), protocol.list_changed);
}

test "the handshake happens one time, however many asks follow" {
    // A server told to initialize twice answers a protocol error, and an
    // `initialized` sent twice is a second handshake on a session that already
    // has one.
    //
    // Mutation check: drop the `ready` flag and this test finds two
    // `initialize` messages on the wire.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"noon"}]}}
    ++ "\n");

    const arena = arena_state.allocator();
    _ = try protocol.list(arena, io, &pair.channel, generousDeadline(io));
    const outcome = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "get_current_time",
        \\{"timezone":"UTC"}
    );
    try testing.expectEqualStrings("noon", outcome.text);
    try testing.expect(!outcome.is_error);

    var buffer: [8192]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\"method\":\"initialize\""));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "notifications/initialized"));
    // And the arguments the model sent really crossed as an object.
    try testing.expect(std.mem.indexOf(u8, wrote, "\"arguments\":{\"timezone\":\"UTC\"}") != null);
}

test "a JSON-RPC error and a tool that failed are both results, and neither ends anything" {
    // The two ways a call can go wrong that are not faults of this host. A
    // real server answers the first for a method it does not know and the
    // second for an argument it does not like: both measured against
    // `mcp-server-time` 2026.7.10.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"Invalid request parameters"}}
    ++ "\n");
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"Invalid timezone"}],"isError":true}}
    ++ "\n");

    const failed = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "a", "{}");
    try testing.expect(failed.is_error);
    try testing.expectEqualStrings("Invalid request parameters", failed.text);

    const refused = try protocol.call(arena, io, &pair.channel, generousDeadline(io), "b", "{}");
    try testing.expect(refused.is_error);
    try testing.expectEqualStrings("Invalid timezone", refused.text);
}

test "a content part this build cannot show is named and never silently dropped" {
    // A model told there was an image can ask for something else. A model
    // shown nothing believes the tool answered nothing, which is a lie about
    // what happened.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"first"},{"type":"image","data":"AAAA"},{"type":"text","text":"last"}]}}
    ++ "\n");

    const outcome = try protocol.call(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
        "a",
        "{}",
    );
    try testing.expect(std.mem.indexOf(u8, outcome.text, "first") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "image") != null);
    try testing.expect(std.mem.indexOf(u8, outcome.text, "last") != null);
    // The base64 of the image itself is not in the context, which is the whole
    // reason the part is named rather than carried.
    try testing.expect(std.mem.indexOf(u8, outcome.text, "AAAA") == null);
}

test "a server that dies mid sentence leaves no half message that reads as a whole one" {
    // The newline is what makes a partial message safe, the job
    // `Content-Length` does for the LSP driver. A driver that read the bytes
    // it had would parse half an object, or worse, half of one joined to the
    // start of the next.
    //
    // Mutation check: answer whatever is in `inbox` when the channel ends and
    // this test parses a truncated message instead of saying the server is
    // gone.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    try pair.serverSays(io, "{\"jsonrpc\":\"2.0\",\"id\":1,\"resu");
    std.Io.File.close(pair.server_writes, io);
    pair.server_writes = .{ .handle = -1, .flags = .{ .nonblocking = false } };

    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
    // And it stays gone: the channel is poisoned, so nothing asks a dead
    // process again.
    try testing.expect(pair.channel.poisoned);
    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
}

test "a reply that misses its budget is late, and the exchange can be tried again" {
    // A hostile or broken server must not wedge the session. A budget that ran
    // out is not a fault: the bytes are still in the pipe, so the channel is
    // not poisoned and the next ask picks the reply up whole.
    //
    // The deadline is already in the past, so nothing here waits for a clock:
    // `operateTimeout` sees a passed deadline and answers at once.
    //
    // Mutation check: poison the channel on `Late` in `receive` and the second
    // half of this test answers `Gone`.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
    ));
    try testing.expect(!pair.channel.poisoned);

    // The server answers after all. **The handshake is not sent again**: see
    // `handshake_id`. The staged reply below answers id 1, which is the id of
    // the `initialize` the first ask already put on the wire, so a client that
    // sent a second one would wait for id 2 and this ask would be late too.
    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io,
        \\{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"only","inputSchema":{}}]}}
    ++ "\n");
    const declared = try protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    );
    try testing.expectEqual(@as(usize, 1), declared.len);
    try testing.expectEqualStrings("only", declared[0].name);
}

test "a line that never ends is refused rather than grown until the machine complains" {
    // The sender is a third party program. A server that writes and never
    // sends a newline would otherwise grow `inbox` without a bound, and the
    // fault a person sees would be the machine and not the server.
    //
    // A thread writes, because more than a pipe's own buffer has to cross and
    // a pipe holds only about 64 KiB. Nothing here measures a duration.
    //
    // Mutation check: drop the `max_inbox_bytes` check in `receive` and this
    // test never finishes.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const Flood = struct {
        fn run(file: std.Io.File, driver: std.Io) void {
            var block: [16 << 10]u8 = @splat('x');
            var written: usize = 0;
            // A little past the bound, and a broken pipe ends the loop: the
            // reader gives up first, which is the whole point.
            while (written < max_inbox_bytes + block.len) : (written += block.len) {
                std.Io.File.writeStreamingAll(file, driver, &block) catch return;
            }
        }
    };
    const thread = try std.Thread.spawn(.{}, Flood.run, .{ pair.server_writes, io });
    defer thread.join();

    try testing.expectError(error.Gone, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        generousDeadline(io),
    ));
    try testing.expect(pair.channel.poisoned);

    // The write end is closed here so the flooding thread stops rather than
    // waiting on a pipe nobody drains.
    std.Io.File.close(pair.channel.from_helper, io);
    pair.channel.from_helper = .{ .handle = -1, .flags = .{ .nonblocking = false } };
}

test "a driver that never started answers gone, and says so once" {
    // A `Driver` whose helper cannot start must answer and never wait, and it
    // must keep the first reason. `chock_core.helper.Helper` is not restarted,
    // so neither is this.
    //
    // **This test says nothing on the terminal, and that is not an accident.**
    // The root below is a path that is not there, so the sandbox child fails
    // while it builds the mount tree, and it writes the reason with
    // `lib/chock-sandbox/linux/driver.zig`'s own `writeStderr`: between `fork`
    // and `execve` it cannot take the lock a formatted diagnostic needs.
    //
    // It goes where `Sandbox.Config.stderr_fd` says rather than to descriptor
    // 2 by number, and `helper.startWith` points that at `/dev/null`. The die
    // paths were changed to read the field for exactly this.
    const gpa = testing.allocator;
    var process = helper.Helper.init(gpa);
    defer process.deinit(testing.io);

    var driver = Driver.init(gpa, &process, .{
        .config = .{ .root = "/nowhere", .mounts = &.{}, .rules = &.{}, .cwd = "/", .env = &.{} },
        .argv = &.{"/probe"},
    });
    defer driver.deinit();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const host = driver.host();
    try testing.expectError(error.Gone, host.list(
        arena_state.allocator(),
        testing.io,
        mcp.discovery_budget_ns,
    ));
    try testing.expect(driver.failure != null);
    try testing.expectEqualStrings(mcp.start_failed, driver.failure.?);

    // And it stays gone, without touching the process again.
    try testing.expectError(error.Gone, host.call(
        arena_state.allocator(),
        testing.io,
        "anything",
        "{}",
        mcp.call_budget_ns,
    ));
}

test "an initialize that ran out of budget is waited for again and never sent twice" {
    // `initialize` may go out one time per server. A real server answers a
    // second one with an error rather than a capability set, so a client that
    // re-sent it after one slow first answer would turn a late reply into a
    // dead server for the rest of the session.
    //
    // Mutation check: build the `initialize` inside `handshake` on every pass
    // rather than once, and this test finds two of them on the wire and the
    // second ask never gets its reply.
    const gpa = testing.allocator;
    const io = testing.io;
    var pair = try Pair.open();
    defer pair.close(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var protocol = Protocol{ .gpa = gpa };
    defer protocol.deinit();

    const past = std.Io.Clock.Timestamp.now(io, .awake);
    try testing.expectError(error.Late, protocol.list(
        arena_state.allocator(),
        io,
        &pair.channel,
        past,
    ));
    try testing.expectEqual(@as(?i64, 1), protocol.handshake_id);

    try pair.serverSays(io, initialize_reply);
    try pair.serverSays(io, list_reply);
    _ = try protocol.list(arena_state.allocator(), io, &pair.channel, generousDeadline(io));

    var buffer: [8192]u8 = undefined;
    const wrote = try pair.clientWrote(io, &buffer);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, wrote, "\"method\":\"initialize\""));
}
