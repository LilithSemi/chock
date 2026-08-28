//! Server sent events, and the tool call fragments a streaming response splits
//! across many of them. A streaming chat completion is a sequence of `data:`
//! lines, one JSON chunk per line, ended by a `data: [DONE]` line. A tool call
//! inside that stream does not arrive whole. The id and the name arrive on the
//! call's first fragment. The arguments arrive as pieces of a JSON string,
//! spread across many more fragments after it, told apart from another call's
//! fragments by the call's `index`, not by the order fragments arrive in.
//!
//! `Parser` turns raw bytes, fed in whatever sizes a socket read hands over,
//! into whole `Event`s. `ToolCallAssembler` turns a stream of tool call
//! fragments, keyed by index, into whole calls. Neither type reads a byte
//! off a socket itself: something in `chockd`'s HTTP client feeds `Parser`,
//! and whichever adapter decodes a chunk's JSON body feeds
//! `ToolCallAssembler`, most likely `openai.zig`'s streaming counterpart,
//! built in a later task.
//!
//! Both types treat their input as hostile. A model provider can be
//! compromised, a proxy can sit in the way, a local server can be buggy.
//! Two fix passes cover the attacks a reviewer ran and what changed in
//! response, including every bound below and the explicit errors
//! `Parser.feed`, `ToolCallAssembler.feed`, and `applyDeltaJson` can now
//! return instead of a crash or, in the first pass, a corrupted next event.
//!
//! What a real server sends, captured from a llama.cpp server running
//! glm4.7-flash:A3B, streaming a request with one tool defined (see
//! `testdata/` for the full capture):
//!
//!     data: {"choices":[{"finish_reason":null,"index":0,"delta":{"tool_calls":
//!     [{"index":0,"id":"4FwUcjf20VWuU8oghmD8EcSfAhMhCAom","type":"function",
//!     "function":{"name":"read_file","arguments":"{"}}]}}],...}
//!
//!     data: {"choices":[{"finish_reason":null,"index":0,"delta":{"tool_calls":
//!     [{"index":0,"function":{"arguments":"\"path\":"}}]}}],...}
//!
//! Only the first fragment for a given index carries `id`, `type`, and
//! `function.name`. Every fragment after it carries only
//! `function.arguments`, one piece of the arguments string, sometimes as
//! short as a single character. The stream ends with a chunk whose
//! `finish_reason` is set and whose `delta` is empty, followed by a literal
//! `data: [DONE]` line. Plain text answers arrive the same way, as
//! `delta.content` fragments, and can share a stream with a tool call: the
//! model can say a sentence and then call a tool in the same response.
//! `reasoning_content` streams the same way, fragment by fragment, ahead of
//! `content` or `tool_calls` when the model reasons before it answers: see
//! `testdata/reasoning_content_stream.sse`, a real capture.
//!
//! **`[DONE]` is not always the last thing on the wire.** ai& appends one
//! named trailer after it, carrying what the turn actually cost:
//!
//!     event: metrics
//!     data: {"tokens":{"input":7,"output":2,"total":9,"cached":0},
//!     "cost":0.000018,"currency":"usd","ttft_ms":120,"inference_ms":850}
//!
//! That is why `Event.data` carries the `event:` name and not only the body:
//! see `Data`. Chock reads that trailer in `Client.zig`.

const std = @import("std");
const message = @import("message.zig");

/// One complete server sent event, or the literal `[DONE]` marker that ends
/// a stream. `data` owns its memory: the caller frees it with `deinit`.
pub const Event = union(enum) {
    /// One event's `data:` field, and the `event:` name it arrived under.
    data: Data,
    /// The stream's final event: a literal `data: [DONE]` line. Nothing
    /// stops a caller from calling `Parser.next` again after seeing this.
    /// It simply returns null until more bytes arrive.
    done,

    pub fn deinit(self: Event, allocator: std.mem.Allocator) void {
        switch (self) {
            .data => |data| data.deinit(allocator),
            .done => {},
        }
    }
};

/// One event's payload and the name the server gave it. Both slices are owned
/// by the `Event` that holds them, and `Event.deinit` frees them.
///
/// **The name is the only safe way to tell two payload shapes apart on one
/// stream.** ai& appends a `metrics` event, carrying the turn's real token
/// counts and its final cost, after the `[DONE]` line of an otherwise
/// ordinary chat completion stream, and its documentation says in as many
/// words not to read that event as a chat completion chunk. A reader that
/// looks only at the JSON must guess from the shape, and a guess that is
/// wrong in either direction either loses the cost or corrupts the reply.
pub const Data = struct {
    /// The `event:` field, or empty when the event carried none. Per the SSE
    /// spec this resets between events, so an unnamed event after a named one
    /// reads back as unnamed. The OpenAI compatible wire names nothing at all
    /// and so leaves this empty on every chat completion chunk.
    name: []const u8,
    /// The `data:` field, with the SSE spec's one optional leading space
    /// stripped, and with several `data:` lines of one event joined by `\n`.
    /// In practice, the JSON text of one streaming chunk.
    body: []const u8,

    pub fn deinit(self: Data, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.body);
    }
};

/// Turns raw bytes into `Event`s. Bytes arrive in whatever sizes a socket
/// read hands over: one byte, one line, or the whole response at once, and
/// `feed` produces the same events regardless. It scans for a line break
/// (`\n`, `\r\n`, or a bare `\r`, all three legal under the SSE spec) a
/// single byte at a time, no UTF-8 continuation byte (0x80-0xBF) or lead
/// byte (0xC0 and up) can equal one, so a multi byte character split across
/// two calls to `feed` reassembles correctly the moment its last byte
/// arrives: nothing here inspects a byte's meaning until the line it
/// belongs to is whole.
pub const Parser = struct {
    allocator: std.mem.Allocator,
    /// Bytes fed but not yet resolved into a complete line. Never holds more
    /// than `max_line_bytes`: see `feed`.
    line_buf: std.ArrayList(u8) = .empty,
    /// The `data:` line(s) of the event currently being assembled, joined
    /// by `\n` per the SSE spec when an event carries more than one. Never
    /// holds more than `max_pending_bytes`: see `processLine`.
    pending: std.ArrayList(u8) = .empty,
    /// The `event:` line of the event currently being assembled, empty when
    /// it carried none. Per the SSE spec a second `event:` line replaces the
    /// first rather than joining onto it, so this holds one line at most and
    /// `max_line_bytes` bounds it.
    pending_name: std.ArrayList(u8) = .empty,
    /// Whether `pending` holds at least one `data:` line for the event in
    /// progress. This is what tells a blank line that really ends an event
    /// apart from a stray blank line, for example a second one in a row,
    /// that ends nothing: without it, a stray blank line would manufacture
    /// an empty-data event no server sent.
    have_pending: bool = false,
    /// Set once `pending` has been discarded for growing past
    /// `max_pending_bytes`, and cleared again on the discarded event's own
    /// terminating blank line. While set, every line is swallowed: the
    /// discarded event's remaining `data:` lines are not a new event's,
    /// and must not restart `pending` as if they were: see `processLine`.
    /// If the peer never sends that blank line at all, this stays set
    /// until the next one arrives from wherever it comes: per SSE framing,
    /// any `data:` line fed with no blank line ahead of it belongs to
    /// whatever event is already open, so there is no way to tell "more of
    /// the discarded event" apart from "an unrelated new event" without
    /// one.
    skip_to_blank: bool = false,
    /// Fully parsed events not yet handed to the caller by `next`, from
    /// index `events_read` onward: see `next`.
    events: std.ArrayList(Event) = .empty,
    /// How many of `events.items`, from the front, `next` has already
    /// returned. `next` advances this instead of shifting the array on
    /// every call, so draining N events costs O(N), not O(N^2): see `next`.
    events_read: usize = 0,
    /// How many times `feed` has moved the unconsumed tail of `line_buf` back
    /// to the front. **One per `feed` call**, whatever that call held.
    ///
    /// This exists for one test: "feeding many small events compacts the
    /// buffer once per call, not once per line". That test used to assert on
    /// a wall clock, which measures the machine and the load on it rather
    /// than the code, and which had already been removed twice elsewhere in
    /// this project for failing on unmodified code. This counter is
    /// deterministic.
    ///
    /// **A rewrite of `feed` must keep this count truthful.** Add one for
    /// each time the buffer's remaining bytes are moved.
    compactions: usize = 0,

    /// A single buffered line cannot grow past this many bytes. 4 MiB. Every
    /// real capture this parser has read carries a `data:` line under a
    /// kilobyte. Even a whole non-streaming reply folded into one line would
    /// rarely reach a megabyte. 4 MiB gives three orders of magnitude of
    /// headroom over anything a real server sends, while still bounding the
    /// worst case far below the 91 MiB and 128 MiB a reviewer measured from
    /// an uncapped parser fed a hostile line.
    ///
    /// This bounds a line that is still growing, one `feed` call at a time,
    /// with no line break yet: see the early check in `feed`. A single
    /// complete line, break included, delivered whole in one `feed` call is
    /// bounded too, checked as each line is found: see the loop in `feed`.
    pub const max_line_bytes: usize = 4 * 1024 * 1024;
    /// `pending` cannot grow past this many bytes across the `data:` lines
    /// of one event. Twice `max_line_bytes`: generous enough for the rare
    /// multi-line `data:` event the SSE spec allows, without which a peer
    /// that never sends the blank line ending an event could otherwise grow
    /// `pending` without bound, one capped line at a time.
    pub const max_pending_bytes: usize = 2 * max_line_bytes;
    /// How many parsed events `next` can leave undrained before `feed`
    /// refuses to queue more. 200,000: comfortably above any batch a real
    /// caller drains in, since `next` is O(1) and cheap to call after every
    /// `feed`, and comfortably below the 500,000 undrained events a
    /// reviewer measured holding 22 MiB with no bound at all.
    pub const max_queued_events: usize = 200_000;

    pub const Error = std.mem.Allocator.Error || error{
        /// A buffered line grew past `max_line_bytes` without a line break
        /// arriving to end it. The unterminated line is discarded: `feed`
        /// cannot know where the real line boundary is until more bytes
        /// arrive, and holding onto more than the cap defeats the point of
        /// having one.
        LineTooLong,
        /// The `data:` line(s) of one event grew past `max_pending_bytes`
        /// before a blank line ended it. The event in progress is
        /// discarded, same reasoning as `LineTooLong`.
        EventTooLarge,
        /// `next` has not been called often enough to keep the queued event
        /// count at or under `max_queued_events`. The event that tripped
        /// this is queued regardless: nothing about it was wrong, and it
        /// reads back normally once the caller drains with `next`. This is
        /// a backpressure signal, not a data loss one.
        TooManyQueuedEvents,
    };

    pub fn init(allocator: std.mem.Allocator) Parser {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Parser) void {
        for (self.events.items[self.events_read..]) |event| event.deinit(self.allocator);
        self.events.deinit(self.allocator);
        self.pending.deinit(self.allocator);
        self.pending_name.deinit(self.allocator);
        self.line_buf.deinit(self.allocator);
    }

    /// Whether a stream fed to this parser ended cleanly or was cut short.
    pub const FinishStatus = enum {
        /// Nothing is left half-parsed: every byte fed so far resolved into
        /// a whole line, and every line into a whole event or a stray blank
        /// line. This does not by itself prove a `.done` event was seen: a
        /// server that closes its connection right after its last whole
        /// event, without ever sending `data: [DONE]`, also reports this,
        /// because nothing fed to the parser was lost. A caller that must
        /// enforce the `[DONE]` marker itself tracks whether `Parser.next`
        /// ever returned `.done`.
        complete,
        /// Bytes are still buffered that never resolved into a whole event:
        /// a line cut off mid-way with no line break yet, or a whole `data:`
        /// line whose event never got its terminating blank line. Whatever
        /// that data held is lost the moment the caller stops feeding this
        /// parser, because nothing else will ever complete it.
        truncated,
    };

    /// Call once after the source of `feed`'s bytes, typically a socket, has
    /// closed. Tells the caller whether anything fed to this parser was left
    /// unfinished, the way a stream cut off mid-response would leave its
    /// last partial event with no other way to notice.
    pub fn finish(self: *const Parser) FinishStatus {
        if (self.line_buf.items.len != 0 or self.have_pending) return .truncated;
        return .complete;
    }

    /// Find the next line break in `buf` starting at `start`, treating `\n`,
    /// `\r\n`, and a bare `\r` all as one line break, per the SSE spec.
    /// `end` is the line's length up to but not including the break. `next`
    /// is where the following line starts. Returns null when no break has
    /// arrived yet, including when `buf` ends in a `\r` whose next byte, the
    /// one that would say whether this is `\r\n` or a bare `\r`, has not
    /// arrived yet: deciding early would misread a `\r\n` split across two
    /// `feed` calls as two separate lines.
    fn findLineBreak(buf: []const u8, start: usize) ?struct { end: usize, next: usize } {
        var i = start;
        while (i < buf.len) : (i += 1) {
            switch (buf[i]) {
                '\n' => return .{ .end = i, .next = i + 1 },
                '\r' => {
                    if (i + 1 >= buf.len) return null;
                    const break_end: usize = if (buf[i + 1] == '\n') i + 2 else i + 1;
                    return .{ .end = i, .next = break_end };
                },
                else => {},
            }
        }
        return null;
    }

    /// Feed the next chunk of bytes, of any length, including zero. Parses
    /// every whole line the buffered bytes now contain. A trailing partial
    /// line waits in `line_buf` for the rest of itself to arrive in a later
    /// call.
    pub fn feed(self: *Parser, bytes: []const u8) Error!void {
        // A chunk with no line break in it can only ever extend the current
        // unterminated line. Reject before growing `line_buf` at all: a
        // chunk this large, with nothing to end a line, would otherwise
        // sit in `line_buf` until a break finally arrives. Clear what was
        // already buffered too, `pending` and `have_pending` included:
        // leaving `line_buf` in place would let a later, unrelated feed
        // silently glue itself onto this rejected line's leftovers instead
        // of starting clean, and leaving `pending` in place would let that
        // later feed's data glue onto an event this rejected line can no
        // longer complete.
        if (findLineBreak(bytes, 0) == null and self.line_buf.items.len + bytes.len > max_line_bytes) {
            self.line_buf.clearAndFree(self.allocator);
            self.dropPendingEvent();
            return error.LineTooLong;
        }
        try self.line_buf.appendSlice(self.allocator, bytes);

        // A line's bytes are consumed off the wire whether processLine
        // accepts them or not. An error from it must still let the buffer
        // compact past that line below, or the same bytes would be
        // reprocessed, mangled together with whatever is fed next, the
        // next time feed() is called.
        var start: usize = 0;
        var line_error: ?Error = null;
        while (findLineBreak(self.line_buf.items, start)) |brk| {
            // A single complete line past the cap is rejected here too,
            // not only a still-growing, unterminated one: without this
            // check, a line whose break arrives in the same feed() call as
            // the rest of it skips both of the other two LineTooLong
            // checks in this function entirely, since neither one ever
            // sees an unterminated line to catch.
            if (brk.end - start > max_line_bytes) {
                start = brk.next;
                line_error = error.LineTooLong;
                break;
            }
            const line = self.line_buf.items[start..brk.end];
            start = brk.next;
            self.processLine(line) catch |err| {
                line_error = err;
                break;
            };
        }

        // Compact once, after every complete line in this call has been
        // scanned, instead of once per line: draining the many small lines
        // one big feed can contain is O(bytes fed), not O(line count
        // squared).
        const remaining = self.line_buf.items.len - start;
        std.mem.copyForwards(u8, self.line_buf.items[0..remaining], self.line_buf.items[start..]);
        self.line_buf.shrinkRetainingCapacity(remaining);
        // See the field's own doc comment: this line is the contract that
        // count keeps.
        self.compactions += 1;

        if (line_error) |err| {
            // Whatever event was in progress cannot be trusted once a line
            // belonging to it is thrown away: clear it, so a clean event
            // fed afterward does not glue onto its leftovers. EventTooLarge
            // already clears both itself, in processLine, before returning
            // here, so this is a no-op in that case.
            if (err == error.LineTooLong) self.dropPendingEvent();
            return err;
        }

        if (self.line_buf.items.len > max_line_bytes) {
            self.line_buf.clearAndFree(self.allocator);
            self.dropPendingEvent();
            return error.LineTooLong;
        }
    }

    fn processLine(self: *Parser, line: []const u8) Error!void {
        if (self.skip_to_blank) {
            // EventTooLarge already discarded this event's pending data.
            // Everything up to its own terminating blank line is more of
            // the discarded event, not a new one: swallow it here instead
            // of letting it restart `pending` as if it were fresh input,
            // one legal-sized line at a time.
            if (line.len == 0) self.skip_to_blank = false;
            return;
        }
        if (line.len == 0) {
            if (!self.have_pending) {
                // A stray blank line ends no event, and it still ends the
                // name: per the SSE spec the event type buffer is reset on
                // every dispatch, whether anything was dispatched or not, so
                // a bare `event: ping` cannot name the event after it.
                self.pending_name.clearRetainingCapacity();
                return;
            }
            try self.finishEvent();
            return;
        }

        const colon = std.mem.indexOfScalar(u8, line, ':');
        const field = if (colon) |c| line[0..c] else line;
        // id: and retry: are not read here. An SSE comment line, for
        // example ": keep-alive", starts with ':' and so has an empty
        // field name here too: it falls through this same check, no
        // separate guard needed.
        const is_data = std.mem.eql(u8, field, "data");
        const is_name = std.mem.eql(u8, field, "event");
        if (!is_data and !is_name) return;

        var value: []const u8 = "";
        if (colon) |c| {
            value = line[c + 1 ..];
            if (value.len != 0 and value[0] == ' ') value = value[1..];
        }

        if (is_name) {
            // Replaced and never joined, unlike `data:` below: the SSE spec
            // sets the event type buffer to the field value rather than
            // appending to it, which is also what keeps this bounded by one
            // line.
            self.pending_name.clearRetainingCapacity();
            try self.pending_name.appendSlice(self.allocator, value);
            return;
        }

        // A second `data:` line in the same event joins onto the first with
        // a '\n' between them, per the SSE spec. Every real event this
        // parser has read carries exactly one, but this still does the
        // right thing with a multi-line data block.
        if (self.have_pending) try self.pending.append(self.allocator, '\n');
        try self.pending.appendSlice(self.allocator, value);
        self.have_pending = true;

        if (self.pending.items.len > max_pending_bytes) {
            self.dropPendingEvent();
            self.skip_to_blank = true;
            return error.EventTooLarge;
        }
    }

    /// Throw away the event being assembled, name and all. Called wherever a
    /// line belonging to it was refused: what is left cannot be completed,
    /// and leaving it would let the next clean event glue onto its leftovers.
    fn dropPendingEvent(self: *Parser) void {
        self.pending.clearAndFree(self.allocator);
        self.pending_name.clearAndFree(self.allocator);
        self.have_pending = false;
    }

    fn finishEvent(self: *Parser) Error!void {
        defer {
            self.pending.clearRetainingCapacity();
            self.pending_name.clearRetainingCapacity();
            self.have_pending = false;
        }
        if (std.mem.eql(u8, self.pending.items, "[DONE]")) {
            try self.events.append(self.allocator, .done);
        } else {
            const body = try self.allocator.dupe(u8, self.pending.items);
            errdefer self.allocator.free(body);
            const name = try self.allocator.dupe(u8, self.pending_name.items);
            errdefer self.allocator.free(name);
            try self.events.append(self.allocator, .{ .data = .{ .name = name, .body = body } });
        }
        // Nothing bounds how many parsed events pile up if the caller never
        // drains with `next`: a reviewer measured 500,000 undrained events
        // holding 22 MiB. The event just queued above is real and stays
        // queued either way. This only tells the caller to drain before
        // feeding more.
        if (self.events.items.len - self.events_read > max_queued_events) return error.TooManyQueuedEvents;
    }

    /// Pop the next fully parsed event, or null when none is ready yet.
    /// Ownership of the returned event passes to the caller, who must call
    /// its `deinit`.
    pub fn next(self: *Parser) ?Event {
        if (self.events_read == self.events.items.len) {
            // Everything queued has been handed out: reclaim the array
            // instead of leaving `events_read` to grow forever.
            self.events_read = 0;
            self.events.clearRetainingCapacity();
            return null;
        }
        const event = self.events.items[self.events_read];
        self.events_read += 1;
        return event;
    }
};

/// One piece of one tool call as it arrives on the wire. See its doc comment
/// in `message.zig`, where the canonical definition lives: `Client.Delta`
/// carries this same type at the public interface, so it cannot be defined
/// here, in a module an implementation other than `Client.HttpClient` has no
/// reason to import. Aliased, not copied, for the reason `message.zig`'s own
/// top comment gives: two definitions of the same shape drift the moment one
/// changes and the other does not.
pub const ToolCallFragment = message.ToolCallFragment;

/// One tool call, fully assembled from its fragments. `arguments` is the
/// concatenation of every fragment fed for this call's index, in the order
/// they were fed: it parses as JSON once the last fragment has arrived, not
/// necessarily before.
pub const ToolCall = struct {
    index: usize,
    id: []const u8,
    name: []const u8,
    arguments: []const u8,
    /// False when this index never carried an `id` and a `name`: an orphan
    /// fragment, for example an `arguments` piece whose first fragment
    /// never arrived. `id` and `name` are still empty strings in that case,
    /// not null, so a caller that only checks for null never notices.
    /// Check this field instead.
    complete: bool,
};

/// Assembles tool call fragments, keyed by `index`, into whole calls. Two
/// calls in one response are told apart by `index`, not by the order their
/// fragments arrive in: nothing about the wire shape promises one call's
/// fragments all arrive before the next call's first fragment does.
pub const ToolCallAssembler = struct {
    allocator: std.mem.Allocator,
    /// Keyed by `ToolCallFragment.index`. A hash map, not a linear scan
    /// over a list: a model chooses how many distinct indices a response
    /// carries, and a scan-per-fragment lookup is O(n) per fragment, O(n^2)
    /// to feed n distinct indices. A reviewer measured 435 ms to feed
    /// 20,000 distinct indices and 1794 ms for 40,000, four times the work
    /// for twice the input. `std.AutoArrayHashMapUnmanaged` keeps the
    /// insertion order `finished` promises while making that lookup O(1)
    /// on average.
    entries: std.AutoArrayHashMapUnmanaged(usize, Entry) = .empty,
    /// How many stored indices `entryFor` has examined over the life of this
    /// assembler. One unit for every stored index a lookup looks at, and
    /// never less than one unit per call, because a lookup always examines
    /// at least the one slot it lands on.
    ///
    /// This exists for one test: "feeding n distinct tool call indices costs
    /// work proportional to n, not to n squared". That test used to assert
    /// on a wall clock, which measures the machine and the load on it, not
    /// the code, and which failed on an idle machine for a reason no reader
    /// could act on. This counter is deterministic: it gives the same answer
    /// on every machine, at every optimize level, under any load.
    ///
    /// **A replacement for `entryFor` must keep this count truthful.** Add
    /// the number of stored indices the new lookup examines. A lookup that
    /// scans the whole table adds the size of the whole table.
    lookup_steps: usize = 0,

    const Entry = struct {
        id: std.ArrayList(u8) = .empty,
        name: std.ArrayList(u8) = .empty,
        arguments: std.ArrayList(u8) = .empty,
        has_id: bool = false,
        has_name: bool = false,
    };

    /// One index's accumulated `arguments` cannot grow past this many
    /// bytes. 16 MiB: generous enough for a tool call whose argument is a
    /// large file's contents, while still bounding the worst case a model
    /// or a corrupted stream could inflict. A reviewer measured 64 MiB of
    /// arguments fed in small fragments, individually well under any
    /// per-event cap `Parser` enforces, holding 90 MiB with no cap at all.
    pub const max_arguments_bytes: usize = 16 * 1024 * 1024;

    pub const Error = std.mem.Allocator.Error || error{
        /// A fragment's `arguments` would push this index's accumulated
        /// total past `max_arguments_bytes`. The fragment is rejected
        /// before it is appended: whatever this index held before is kept
        /// as is, not discarded, since unlike `Parser`'s caps there is no
        /// terminating line to wait out.
        ArgumentsTooLarge,
    };

    pub fn init(allocator: std.mem.Allocator) ToolCallAssembler {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ToolCallAssembler) void {
        for (self.entries.values()) |*entry| {
            entry.id.deinit(self.allocator);
            entry.name.deinit(self.allocator);
            entry.arguments.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }

    fn entryFor(self: *ToolCallAssembler, index: usize) std.mem.Allocator.Error!*Entry {
        // One step. An array hash map goes straight to the slot the hash
        // names and examines that one slot, whatever the table already
        // holds. See `lookup_steps` for the contract this line keeps.
        self.lookup_steps += 1;
        const result = try self.entries.getOrPut(self.allocator, index);
        if (!result.found_existing) result.value_ptr.* = .{};
        return result.value_ptr;
    }

    /// Feed one fragment. `fragment.id` and `fragment.name`, when set,
    /// replace whatever this index held before. `fragment.arguments`, when
    /// set, appends onto it. A fragment that only sets `arguments`, the
    /// shape every fragment after the first takes on a real stream, only
    /// touches `arguments`.
    pub fn feed(self: *ToolCallAssembler, fragment: ToolCallFragment) Error!void {
        const entry = try self.entryFor(fragment.index);
        if (fragment.id) |id| {
            entry.id.clearRetainingCapacity();
            try entry.id.appendSlice(self.allocator, id);
            entry.has_id = true;
        }
        if (fragment.name) |name| {
            entry.name.clearRetainingCapacity();
            try entry.name.appendSlice(self.allocator, name);
            entry.has_name = true;
        }
        if (fragment.arguments) |arguments| {
            if (entry.arguments.items.len + arguments.len > max_arguments_bytes) return error.ArgumentsTooLarge;
            try entry.arguments.appendSlice(self.allocator, arguments);
        }
    }

    /// The calls assembled so far, in the order their index first appeared.
    /// Every field of every returned `ToolCall`, `id`, `name`, and
    /// `arguments`, is a fresh copy, independent of this assembler's own
    /// buffers: a later call to `feed` can reallocate those buffers without
    /// invalidating anything `finished` already returned. The caller owns
    /// the slice and every copy inside it. Free both with `freeFinished`.
    pub fn finished(self: *ToolCallAssembler) std.mem.Allocator.Error![]const ToolCall {
        var out: std.ArrayList(ToolCall) = .empty;
        errdefer {
            for (out.items) |call| {
                self.allocator.free(call.id);
                self.allocator.free(call.name);
                self.allocator.free(call.arguments);
            }
            out.deinit(self.allocator);
        }
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            const entry = kv.value_ptr.*;
            const id = try self.allocator.dupe(u8, entry.id.items);
            errdefer self.allocator.free(id);
            const name = try self.allocator.dupe(u8, entry.name.items);
            errdefer self.allocator.free(name);
            const arguments = try self.allocator.dupe(u8, entry.arguments.items);
            try out.append(self.allocator, .{
                .index = kv.key_ptr.*,
                .id = id,
                .name = name,
                .arguments = arguments,
                .complete = entry.has_id and entry.has_name,
            });
        }
        return out.toOwnedSlice(self.allocator);
    }
};

/// Free everything `ToolCallAssembler.finished` returned: every call's
/// `id`, `name`, and `arguments`, then the slice itself.
pub fn freeFinished(allocator: std.mem.Allocator, calls: []const ToolCall) void {
    for (calls) |call| {
        allocator.free(call.id);
        allocator.free(call.name);
        allocator.free(call.arguments);
    }
    allocator.free(calls);
}

/// Test support only: pulls the fields this file's tests care about out of
/// one delta chunk's raw JSON text, the same way `openai.zig`'s tests read a
/// wire body back with `std.json.Value` instead of a typed struct (see
/// `parseWireRequest` there). Decoding the full streaming chunk shape into
/// typed fields for real use belongs to whichever adapter calls this
/// parser, built in a later task. This file owns framing and assembly, not
/// the chunk schema.
///
/// Every field access below is guarded rather than asserted: `json_text`
/// comes off the wire, and a malformed body is a runtime fault, never a
/// programmer error. A body whose shape this function cannot make sense of
/// returns a named error instead of an assert or a bad union field access.
/// The blast radius is the one SSE event that body belonged to, not the
/// whole stream, since `Parser` hands events over one at a time, and not
/// even a partial write into `text_out`, `reasoning_out`, or `assembler`
/// from that one event: every field is validated before anything is
/// applied, so a rejected body applies nothing at all, not even the parts
/// that came before the field that failed.
const ApplyDeltaError = error{
    /// The top level parsed, but was not a JSON object.
    BodyNotObject,
    /// No `choices` field at all.
    MissingChoices,
    /// `choices` was present but not an array.
    ChoicesNotArray,
    /// `choices` was an empty array.
    NoChoices,
    /// `choices[0]` was not an object.
    ChoiceNotObject,
    /// `choices[0]` had no `delta` field.
    MissingDelta,
    /// `delta` was present but not an object.
    DeltaNotObject,
    /// `delta.tool_calls` was present but not an array.
    ToolCallsNotArray,
    /// An entry of `tool_calls` was not an object.
    ToolCallNotObject,
    /// A `tool_calls` entry had no `index` field. Every real call, first
    /// fragment or later one, carries `index`: an entry without one cannot
    /// be attributed to any call.
    ToolCallMissingIndex,
    /// A `tool_calls` entry's `index` was not a JSON integer, for example a
    /// number too large for an `i64` to hold, which `std.json.Value` parses
    /// as `.number_string` instead of `.integer`.
    ToolCallIndexNotInteger,
    /// A `tool_calls` entry's `index` was negative. `ToolCallFragment.index`
    /// is a `usize`. A negative value has no representation to fall back to.
    ToolCallIndexNegative,
    /// A `tool_calls` entry's `function` field was present but not an
    /// object.
    ToolCallFunctionNotObject,
} || ToolCallAssembler.Error || std.json.ParseError(std.json.Scanner);

/// Reads every field this file cares about out of one delta chunk's JSON
/// body without applying any of it, so a body that fails validation partway
/// through, for example a second `tool_calls` entry with no `index`, never
/// commits the first entry's fragment or the `content` that came before it.
/// `content` and `reasoning_content` are plain slices into `parsed`'s own
/// tree. `fragments` is owned by the caller, freed whether this succeeds or
/// fails.
const ParsedDelta = struct {
    content: ?[]const u8 = null,
    reasoning_content: ?[]const u8 = null,
    fragments: std.ArrayList(ToolCallFragment) = .empty,

    fn deinit(self: *ParsedDelta, allocator: std.mem.Allocator) void {
        self.fragments.deinit(allocator);
    }
};

fn parseDelta(allocator: std.mem.Allocator, delta: std.json.ObjectMap) ApplyDeltaError!ParsedDelta {
    var out = ParsedDelta{};
    errdefer out.deinit(allocator);

    if (delta.get("content")) |content_value| {
        if (content_value == .string) out.content = content_value.string;
    }
    if (delta.get("reasoning_content")) |reasoning_value| {
        if (reasoning_value == .string) out.reasoning_content = reasoning_value.string;
    }

    if (delta.get("tool_calls")) |tool_calls_value| {
        if (tool_calls_value != .array) return error.ToolCallsNotArray;
        for (tool_calls_value.array.items) |call_value| {
            if (call_value != .object) return error.ToolCallNotObject;
            const call = call_value.object;

            const index_value = call.get("index") orelse return error.ToolCallMissingIndex;
            if (index_value != .integer) return error.ToolCallIndexNotInteger;
            if (index_value.integer < 0) return error.ToolCallIndexNegative;
            var fragment = ToolCallFragment{ .index = @intCast(index_value.integer) };

            if (call.get("id")) |id_value| {
                if (id_value == .string) fragment.id = id_value.string;
            }
            if (call.get("function")) |function_value| {
                if (function_value != .object) return error.ToolCallFunctionNotObject;
                const function = function_value.object;
                if (function.get("name")) |name_value| {
                    if (name_value == .string) fragment.name = name_value.string;
                }
                if (function.get("arguments")) |arguments_value| {
                    if (arguments_value == .string) fragment.arguments = arguments_value.string;
                }
            }
            try out.fragments.append(allocator, fragment);
        }
    }
    return out;
}

fn applyDeltaJson(
    allocator: std.mem.Allocator,
    assembler: *ToolCallAssembler,
    text_out: *std.ArrayList(u8),
    reasoning_out: *std.ArrayList(u8),
    json_text: []const u8,
) ApplyDeltaError!void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.BodyNotObject;
    const choices_value = parsed.value.object.get("choices") orelse return error.MissingChoices;
    if (choices_value != .array) return error.ChoicesNotArray;
    if (choices_value.array.items.len == 0) return error.NoChoices;

    const choice_value = choices_value.array.items[0];
    if (choice_value != .object) return error.ChoiceNotObject;
    const delta_value = choice_value.object.get("delta") orelse return error.MissingDelta;
    if (delta_value != .object) return error.DeltaNotObject;

    // Everything above and everything parseDelta checks is validated before
    // this point. Nothing has been written to text_out, reasoning_out, or
    // assembler yet: if parseDelta returns an error, the caller sees the
    // whole event rejected, not some of it silently applied first.
    var delta = try parseDelta(allocator, delta_value.object);
    defer delta.deinit(allocator);

    if (delta.content) |content| try text_out.appendSlice(allocator, content);
    if (delta.reasoning_content) |reasoning| try reasoning_out.appendSlice(allocator, reasoning);
    for (delta.fragments.items) |fragment| try assembler.feed(fragment);
}

test "a data line split across two reads produces one event" {
    const allocator = std.testing.allocator;
    // A real captured event: one streaming content delta carrying Japanese
    // text, several codepoints of it three bytes long. Fed one byte at a
    // time below, on purpose, splitting those codepoints mid character.
    const raw = @embedFile("testdata/unicode_content_event.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();

    for (raw) |byte| try parser.feed(&[_]u8{byte});

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    // raw is "data: " (6 bytes) + the JSON text + "\n\n" (2 bytes).
    try std.testing.expectEqualStrings(raw[6 .. raw.len - 2], event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "the done marker ends the stream" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try parser.feed("data: [DONE]\n\n");

    const first = parser.next() orelse return error.TestExpectedEvent;
    defer first.deinit(allocator);
    try std.testing.expect(first == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", first.data.body);

    const second = parser.next() orelse return error.TestExpectedEvent;
    try std.testing.expect(second == .done);

    try std.testing.expect(parser.next() == null);
}

test "an event's name reaches the caller, because two payload shapes share one stream" {
    // ai& appends `event: metrics` after `[DONE]`, carrying the turn's token
    // counts and its final cost, and says in as many words not to read that
    // event as a chat completion chunk. Its name is the only thing that tells
    // it apart, so the name has to survive the parser.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try parser.feed("data: [DONE]\n\n");
    try parser.feed("event: metrics\ndata: {\"cost\":0.000018}\n\n");
    try parser.feed("data: {\"choices\":[]}\n\n");

    const chunk = parser.next() orelse return error.TestExpectedEvent;
    defer chunk.deinit(allocator);
    // The OpenAI compatible wire names nothing, and an unnamed event reads
    // back as unnamed rather than as some default name a reader must know.
    try std.testing.expectEqualStrings("", chunk.data.name);

    const done = parser.next() orelse return error.TestExpectedEvent;
    try std.testing.expect(done == .done);

    const metrics = parser.next() orelse return error.TestExpectedEvent;
    defer metrics.deinit(allocator);
    try std.testing.expectEqualStrings("metrics", metrics.data.name);
    try std.testing.expectEqualStrings("{\"cost\":0.000018}", metrics.data.body);

    // The name is reset between events, per the SSE spec: without that, every
    // event after a named one would inherit a name nobody sent, and an
    // ordinary chunk would read as metrics.
    const after = parser.next() orelse return error.TestExpectedEvent;
    defer after.deinit(allocator);
    try std.testing.expectEqualStrings("", after.data.name);

    try std.testing.expect(parser.next() == null);
}

test "a named event with no data of its own dispatches nothing and names nothing after it" {
    // Per the SSE spec an event with an empty data buffer is not dispatched
    // at all, and the event type buffer still resets. A keep-alive shaped
    // like this must not manufacture an event, and must not leave its name
    // behind to be worn by the next real one.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("event: ping\n\n");
    try std.testing.expect(parser.next() == null);

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("", event.data.name);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "a tool call whose arguments arrive in five fragments assembles into one call" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    // Shaped like the real capture: the first fragment carries id, name,
    // and the opening brace. Every fragment after it carries only a piece
    // of the arguments string.
    try assembler.feed(.{ .index = 0, .id = "call_1", .name = "read_file", .arguments = "{" });
    try assembler.feed(.{ .index = 0, .arguments = "\"path\":" });
    try assembler.feed(.{ .index = 0, .arguments = "\"" });
    try assembler.feed(.{ .index = 0, .arguments = "README.md" });
    try assembler.feed(.{ .index = 0, .arguments = "\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("call_1", calls[0].id);
    try std.testing.expectEqualStrings("read_file", calls[0].name);
    try std.testing.expectEqualStrings("{\"path\":\"README.md\"}", calls[0].arguments);
    try std.testing.expect(calls[0].complete);
}

test "two tool calls in one response stay separate" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    // The second call's first fragment, and a later fragment of it, arrive
    // in between the first call's own fragments. Only `index` keeps the two
    // apart. Arrival order does not.
    try assembler.feed(.{ .index = 0, .id = "call_a", .name = "read_file", .arguments = "{\"path\":\"a" });
    try assembler.feed(.{ .index = 1, .id = "call_b", .name = "read_file", .arguments = "{\"path\":\"b" });
    try assembler.feed(.{ .index = 0, .arguments = ".zig\"}" });
    try assembler.feed(.{ .index = 1, .arguments = ".zig\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 2), calls.len);
    try std.testing.expectEqualStrings("call_a", calls[0].id);
    try std.testing.expectEqualStrings("{\"path\":\"a.zig\"}", calls[0].arguments);
    try std.testing.expectEqualStrings("call_b", calls[1].id);
    try std.testing.expectEqualStrings("{\"path\":\"b.zig\"}", calls[1].arguments);
}

test "a comment line is ignored and does not end the event in progress" {
    // Finding 5. The old version of this test put its one data: line
    // before the comment, so a mutation that made ':' end the event in
    // progress still produced that one correct event: the data was already
    // in `pending` by the time the comment arrived. Putting the comment
    // between two data: lines of the same event catches the mutation: if
    // the comment ends the event, the second data: line starts a new one
    // instead of joining the first, and two events come out instead of
    // one.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: first half\n: keep-alive\ndata: second half\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("first half\nsecond half", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "a stray blank line before any data manufactures no event" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    // The leading blank line has no data buffered yet (have_pending is
    // false) and must not become an empty-data event of its own.
    try parser.feed("\ndata: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "a trailing carriage return on a data line is stripped" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    // CRLF line endings: a server on the other side of a Windows proxy, or
    // one that just follows the SSE spec's other legal terminator.
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\n\r\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    // No trailing \r left on the data: proves the strip ran, not just that
    // parsing did not crash on \r\n input.
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
}

test "a bare carriage return with no following newline still ends a line" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    // The SSE spec allows a bare \r as a line terminator on its own, no \n
    // required. A parser that only ever looks for \n never finds a boundary
    // here and the bytes wait in line_buf forever. The trailing ": pad\n"
    // gives the second \r, the one ending the event, a byte to look ahead
    // at other than end-of-buffer: without one more byte after it, a lone
    // trailing \r is ambiguous with a \r\n split across two feed calls, and
    // finish() would correctly report .truncated instead.
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\r\r: pad\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());
}

test "two data lines in one event join with a newline between them" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    // The SSE spec joins multiple data: lines of the same event with \n.
    // Every real capture this parser has read carries exactly one data:
    // line per event, so nothing exercises this path outside a hand-built
    // test.
    try parser.feed("data: first half\ndata: second half\n\n");

    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("first half\nsecond half", event.data.body);
}

test "a later id or name fragment overwrites the one an index already held" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    // Not a shape any real capture has produced, but nothing about the wire
    // schema forbids a server correcting an id or a name mid-call, and
    // `feed`'s doc comment promises overwrite semantics for these two
    // fields.
    try assembler.feed(.{ .index = 0, .id = "first-id", .name = "first-name" });
    try assembler.feed(.{ .index = 0, .id = "second-id", .name = "second-name" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("second-id", calls[0].id);
    try std.testing.expectEqualStrings("second-name", calls[0].name);
}

test "text and a tool call in the same stream both come out whole" {
    const allocator = std.testing.allocator;
    // A real capture: the model says one sentence, then calls read_file.
    // reasoning_content events removed whole (the data: line and its
    // terminating blank line both), unlike the version of this fixture the
    // first fix pass replaced.
    const raw = @embedFile("testdata/text_and_tool_call.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    var saw_done = false;
    var offset: usize = 0;
    var chunk_size: usize = 1;
    // Awkward, uneven chunk sizes on purpose: 1, 2, 3, ... 7 bytes, then
    // back to 1. Never a whole line, never the same size twice in a row.
    while (offset < raw.len) {
        const end = @min(offset + chunk_size, raw.len);
        try parser.feed(raw[offset..end]);
        offset = end;
        chunk_size = if (chunk_size >= 7) 1 else chunk_size + 1;

        while (parser.next()) |event| {
            defer event.deinit(allocator);
            switch (event) {
                .data => |data| try applyDeltaJson(allocator, &assembler, &text, &reasoning, data.body),
                .done => saw_done = true,
            }
        }
    }

    try std.testing.expect(saw_done);
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());
    try std.testing.expectEqualStrings("I will read the file /home/ross/chock/README.md.", text.items);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqualStrings("ur9rVD4YQsXUINcxCvlse6lpXVjR1Wfi", calls[0].id);
    try std.testing.expectEqualStrings("read_file", calls[0].name);
    try std.testing.expectEqualStrings("{\"path\":\"/home/ross/chock/README.md\"}", calls[0].arguments);
    try std.testing.expect(calls[0].complete);
}

test "a real captured reasoning stream keeps reasoning_content apart from content" {
    // Finding 5: reasoning_content used to be silently dropped. Captured
    // live against glm4.7-flash:A3B, model told to think step by step
    // before answering. Not trimmed: every reasoning_content event is
    // intact, unlike the fixture this
    // parser's earlier tests used.
    const allocator = std.testing.allocator;
    const raw = @embedFile("testdata/reasoning_content_stream.sse");

    var parser = Parser.init(allocator);
    defer parser.deinit();
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try parser.feed(raw);
    var saw_done = false;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        switch (event) {
            .data => |data| try applyDeltaJson(allocator, &assembler, &text, &reasoning, data.body),
            .done => saw_done = true,
        }
    }

    try std.testing.expect(saw_done);
    // The final answer: short, and exactly what content (not
    // reasoning_content) fragments assembled into. If reasoning_content
    // fragments had leaked into text, this would be thousands of bytes
    // longer than the real answer.
    try std.testing.expectEqualStrings(
        \\Here is the step-by-step breakdown:
        \\
        \\1.  The farmer initially has 17 sheep.
        \\2.  The phrase "all but 9 die" is a mathematical way of saying that every single sheep died, except for the 9 that survived.
        \\3.  Therefore, the number of sheep remaining is the number that did not die.
        \\
        \\There are 9 sheep left.
    , text.items);
    // The reasoning, kept in its own buffer: an exact byte count pins the
    // real captured length, and the two anchors prove it is this capture's
    // reasoning, not some other text.
    try std.testing.expectEqual(@as(usize, 2500), reasoning.items.len);
    try std.testing.expect(std.mem.startsWith(u8, reasoning.items, "1.  **Analyze the Request:**"));
    try std.testing.expect(std.mem.endsWith(u8, reasoning.items, "The logic holds up."));
}

test "an orphan tool call fragment reports incomplete instead of an empty id and name" {
    // Finding 6. A fragment whose index never carried an id or a name, for
    // example the first fragment of a call was dropped by a lossy proxy,
    // used to become a ToolCall with id "" and name "", indistinguishable
    // from a real call that happened to have empty strings.
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .arguments = "{\"path\":\"orphaned.zig\"}" });

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);

    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expect(!calls[0].complete);
    try std.testing.expectEqualStrings("", calls[0].id);
    try std.testing.expectEqualStrings("", calls[0].name);
}

test "a stream cut off mid line reports truncated, not complete" {
    // Finding 6. No line break ever arrived to end this line, the way a
    // connection dropped mid-response would leave it. Before finish()
    // existed, a caller had no way to learn this partial data was lost.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"cut off partway");
    try std.testing.expectEqual(Parser.FinishStatus.truncated, parser.finish());
    try std.testing.expect(parser.next() == null);
}

test "a stream cut off after a data line but before its blank line reports truncated" {
    // Finding 6, the other half: the line itself is whole, but the blank
    // line that would end the event never arrived, so the event never
    // queued. Complete lines are not the same as complete events.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"whole line, no terminator\"}}]}\n");
    try std.testing.expectEqual(Parser.FinishStatus.truncated, parser.finish());
    try std.testing.expect(parser.next() == null);
}

test "a stream that ends right after a whole event's blank line reports complete" {
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    try std.testing.expectEqual(Parser.FinishStatus.complete, parser.finish());

    const event = parser.next() orelse return error.TestExpectedEvent;
    event.deinit(allocator);
}

test "a later feed does not invalidate strings finished already returned" {
    // Finding 2. finished()'s old doc comment promised its fields were
    // "valid until deinit", but they were slices into this assembler's own
    // ArrayLists: a later feed() that grows those lists reallocates, and
    // the old slice, and pointer, no longer point at anything live. Proven
    // here by growing well past any small buffer's starting capacity after
    // finished() has already been called once.
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.feed(.{ .index = 0, .id = "call_1", .name = "read_file", .arguments = "{\"path\":\"a" });

    const first_calls = try assembler.finished();
    defer freeFinished(allocator, first_calls);
    try std.testing.expectEqualStrings("{\"path\":\"a", first_calls[0].arguments);

    // Force reallocation of entry 0's `arguments` ArrayList well past
    // whatever capacity it started with.
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try assembler.feed(.{ .index = 0, .arguments = "0123456789" });
    }

    // The slice `finished` returned earlier must still read back correctly:
    // proof it was a copy, not a view into the buffer that just grew.
    try std.testing.expectEqualStrings("{\"path\":\"a", first_calls[0].arguments);
}

fn manySmallEvents(allocator: std.mem.Allocator, event_count: usize) std.mem.Allocator.Error!std.ArrayList(u8) {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    const one_event = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
    var i: usize = 0;
    while (i < event_count) : (i += 1) try body.appendSlice(allocator, one_event);
    return body;
}

test "feeding many small events compacts the buffer once per call, not once per line" {
    // Finding 4. The old feed() shifted the whole remaining buffer once per
    // line: O(events^2). A reviewer measured 148s to feed 160,000 events.
    //
    // **This measures the shape and not the clock.** The version of this test
    // that shipped before asserted that 40,000 events were fed inside eight
    // seconds, which reads as a performance test and is really a test of
    // whether the machine was busy. Two tests of exactly that shape have
    // already been removed from this project after failing on unmodified
    // code, and a third survived here.
    // A test that goes red because another program was running pins nothing.
    //
    // The two implementations differ in a fact that needs no timer: shifting
    // per line moves bytes once for every line in the call, so the work is
    // quadratic in the line count, while compacting once at the end moves
    // each remaining byte once whatever the line count is. `compactions`
    // counts that move. It is deterministic, the same on every machine, at
    // every optimize level, under any load.
    const allocator = std.testing.allocator;

    const small_count = 4_000;
    const large_count = 2 * small_count;

    var small = Parser.init(allocator);
    defer small.deinit();
    var small_body = try manySmallEvents(allocator, small_count);
    defer small_body.deinit(allocator);
    try small.feed(small_body.items);

    var large = Parser.init(allocator);
    defer large.deinit();
    var large_body = try manySmallEvents(allocator, large_count);
    defer large_body.deinit(allocator);
    try large.feed(large_body.items);

    // One feed call, one compaction, whatever the call held. A per line shift
    // makes this the line count, so twice the input would be twice the
    // number here and not the same number.
    try std.testing.expectEqual(@as(usize, 1), small.compactions);
    try std.testing.expectEqual(@as(usize, 1), large.compactions);

    // And the events really arrived, so this is not a counter agreeing with
    // itself over a parser that did nothing.
    var drained: usize = 0;
    while (small.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
    }
    try std.testing.expectEqual(@as(usize, small_count), drained);
}

test "handing out one queued event moves none of the ones behind it" {
    // Finding 5. The shape this guards against is a `next` reverted to
    // `orderedRemove(0)`, which moves every remaining event one place on
    // every call and so costs O(events^2) to drain a queue.
    //
    // **This measures the shape and not the clock.** The previous version of
    // this test drained 150,000 events and asserted the whole drain finished
    // inside eight seconds. That reads as a performance test and is really a
    // test of whether the machine was busy: it failed twice in three runs on
    // a loaded Apple Silicon machine, on an implementation with no
    // regression in it at all, which is a known failure mode. A test that
    // goes red because another program was running pins nothing.
    //
    // `orderedRemove(0)` and the O(1) cursor differ in a fact that needs no
    // timer: removing from the front shortens the queue on every call, and
    // moving a cursor leaves it exactly as long as it was until the last
    // event has been handed out. So this checks the queue's own length after
    // each call, which is deterministic, is the same on every machine, and
    // finishes in milliseconds.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    // Enough events for a front removal to be obvious and few enough that
    // checking after every single one is free. The old test needed 150,000
    // only because it was waiting for a stopwatch to notice.
    const event_count = 4_096;
    var body = try manySmallEvents(allocator, event_count);
    defer body.deinit(allocator);
    try parser.feed(body.items);
    try std.testing.expectEqual(@as(usize, event_count), parser.events.items.len);

    var drained: usize = 0;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
        // Nothing behind the event just handed out moved. A `next` that
        // removed from the front would have shortened this by one every
        // time, and this line is where such a change goes red.
        try std.testing.expectEqual(@as(usize, event_count), parser.events.items.len);
        // And the cursor is the only thing that advanced.
        try std.testing.expectEqual(drained, parser.events_read);
    }

    try std.testing.expectEqual(@as(usize, event_count), drained);
    // Once the last event has been handed out, `next` reclaims the array
    // rather than letting the cursor grow forever: see `next` itself.
    try std.testing.expectEqual(@as(usize, 0), parser.events.items.len);
    try std.testing.expectEqual(@as(usize, 0), parser.events_read);
}

test "a line longer than the cap is rejected, and the parser recovers after" {
    // Finding 3. A reviewer fed 64 MiB with no newline and watched the
    // parser hold 91 MiB. This proves the cap fires well before that, and
    // that the parser is usable again afterward rather than stuck holding
    // an oversized buffer.
    //
    // Finding 5: the attack size used to be derived from max_line_bytes
    // itself (the constant plus one), so this pinned only that some cap
    // fires at whatever the constant happens to equal, not that the cap
    // holds any particular, reasonable size. Raising max_line_bytes to a
    // gigabyte would have made this test's attack grow to a gigabyte right
    // alongside it and still pass. 8 MiB is fixed, not derived: it pins the
    // documented 4 MiB cap with headroom, and would stop tripping this
    // error, correctly failing the test, if max_line_bytes ever grew past
    // it.
    const attack_size = 8 * 1024 * 1024;
    comptime std.debug.assert(attack_size > Parser.max_line_bytes);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const oversized = try allocator.alloc(u8, attack_size);
    defer allocator.free(oversized);
    @memset(oversized, 'x');

    try std.testing.expectError(error.LineTooLong, parser.feed(oversized));

    // The parser recovers: a normal small event right after still works.
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "a line that crosses the cap over several feed calls, none containing a newline, still recovers" {
    // Regression: the early-reject path in feed(), added to stop a single
    // huge chunk from growing line_buf even transiently, used to return
    // LineTooLong without clearing what was already buffered. A later feed
    // call would then silently glue its bytes onto that leftover instead of
    // starting clean, corrupting the next real event instead of just
    // erroring on this one. Found by re-running the reviewer's 64 MiB
    // attack in 1 MiB pieces instead of one giant feed call.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const chunk = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var fed: usize = 0;
    var hit_cap = false;
    while (fed < 64 * 1024 * 1024) : (fed += chunk.len) {
        parser.feed(chunk) catch |err| {
            try std.testing.expectEqual(error.LineTooLong, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "an event whose data lines never get a blank line is rejected once pending is capped" {
    // Finding 3's second buffer: many data: lines, each under the line cap,
    // for one event that never gets the blank line ending it. Nothing
    // capped `pending` before this fix, so a peer that never sends that
    // blank line could grow it without bound, one legal-sized line at a
    // time.
    //
    // Finding 5's fixed-size-attack fix applies here too, one test over:
    // the same "an event whose data lines never get a blank line" test for
    // max_pending_bytes had the identical weakness as the max_line_bytes
    // one named in the finding, sizing its attack from the constant it was
    // supposed to pin. 16 MiB is fixed, well over the documented 8 MiB
    // cap.
    const attack_total = 16 * 1024 * 1024;
    comptime std.debug.assert(attack_total > Parser.max_pending_bytes);
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var total: usize = 0;
    var hit_cap = false;
    while (total < attack_total) : (total += chunk.len) {
        parser.feed("data: ") catch unreachable;
        parser.feed(chunk) catch unreachable;
        parser.feed("\n") catch |err| {
            try std.testing.expectEqual(error.EventTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);

    // The discarded event's own blank line, arriving late, is what lets
    // the parser resync: per SSE framing, any data: line fed before a
    // blank line arrives belongs to whatever event is already open, so
    // there is no way to tell "still more of the discarded event" apart
    // from "an unrelated new event" without one. A real peer that keeps
    // talking after tripping this cap eventually sends it, even if only
    // because it moves on to its next real event.
    try parser.feed("\n");

    // Recovers: a fresh small event right after still parses.
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

fn expectApplyDeltaError(err: ApplyDeltaError, json_text: []const u8) !void {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try std.testing.expectError(err, applyDeltaJson(allocator, &assembler, &text, &reasoning, json_text));
}

test "Finding 1, attack 1: an empty object returns MissingChoices instead of aborting" {
    try expectApplyDeltaError(error.MissingChoices, "{}");
}

test "Finding 1, attack 2: an empty choices array returns NoChoices instead of aborting" {
    try expectApplyDeltaError(error.NoChoices, "{\"choices\":[]}");
}

test "Finding 1, attack 3: choices as an object returns ChoicesNotArray instead of aborting" {
    try expectApplyDeltaError(error.ChoicesNotArray, "{\"choices\":{}}");
}

test "Finding 1, attack 4: a choice with no delta returns MissingDelta instead of aborting" {
    try expectApplyDeltaError(error.MissingDelta, "{\"choices\":[{}]}");
}

test "Finding 1, attack 5: a tool call with no index returns ToolCallMissingIndex instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallMissingIndex,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 6: a negative index returns ToolCallIndexNegative instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallIndexNegative,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":-1,\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 7: an index too large for an i64 returns ToolCallIndexNotInteger instead of aborting" {
    try expectApplyDeltaError(
        error.ToolCallIndexNotInteger,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":99999999999999999999999999999,\"function\":{\"name\":\"x\"}}]}}]}",
    );
}

test "Finding 1, attack 8: an empty delta is a defined no-op, not an error and not a crash" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try applyDeltaJson(allocator, &assembler, &text, &reasoning, "{\"choices\":[{\"delta\":{}}]}");

    try std.testing.expectEqual(@as(usize, 0), text.items.len);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);
    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 0), calls.len);
}

test "Finding 1, attack 9: arguments of the wrong JSON type are skipped, not an error and not a crash" {
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    try applyDeltaJson(
        allocator,
        &assembler,
        &text,
        &reasoning,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":123}}]}}]}",
    );

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 1), calls.len);
    try std.testing.expectEqual(@as(usize, 0), calls[0].arguments.len);
    try std.testing.expect(!calls[0].complete);
}

test "a single complete line longer than the cap is rejected even though its terminator already arrived" {
    // Finding 4. max_line_bytes used to bound only a line that was still
    // growing, one feed() call at a time, with no line break yet. A single
    // feed() call whose bytes already contain the line's own terminator
    // skipped that check entirely: a reviewer's single 6 MiB data: line
    // was accepted whole, and one 32 MiB feed peaked at 48 MiB. Checking a
    // complete line's length as it is found, not only while it is still
    // incomplete, closes that gap.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(allocator, "data: ");
    try body.appendNTimes(allocator, 'x', Parser.max_line_bytes + 1);
    try body.appendSlice(allocator, "\n\n");

    try std.testing.expectError(error.LineTooLong, parser.feed(body.items));

    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}", event.data.body);
}

test "the event queue is bounded, and TooManyQueuedEvents does not lose events already queued" {
    // Finding 4. 500,000 undrained events held 22 MiB with no bound at
    // all. max_queued_events stops the queue from growing without limit
    // when a caller falls behind on draining, proven here by feeding one
    // more event than the cap allows in a single feed() call and checking
    // every event up to and including the one that tripped the cap is
    // still there to read back: this is a backpressure signal, not a
    // discard.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    var body = try manySmallEvents(allocator, Parser.max_queued_events + 1);
    defer body.deinit(allocator);

    try std.testing.expectError(error.TooManyQueuedEvents, parser.feed(body.items));

    var drained: usize = 0;
    while (parser.next()) |event| {
        defer event.deinit(allocator);
        drained += 1;
    }
    try std.testing.expectEqual(Parser.max_queued_events + 1, drained);
}

test "the caps free the oversized buffer's capacity, not just its length" {
    // Finding 5. Choosing clearAndFree over clearRetainingCapacity, so the
    // parser actually gives memory back instead of holding a permanently
    // oversized buffer at idle, was called out as deliberate in the
    // earlier pass's report but had no test pinning it: every other test
    // in this file checks only items.len and content, never capacity, so
    // clearRetainingCapacity would have passed all of them just as well.
    const allocator = std.testing.allocator;
    var parser = Parser.init(allocator);
    defer parser.deinit();

    const oversized = try allocator.alloc(u8, Parser.max_line_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');
    try std.testing.expectError(error.LineTooLong, parser.feed(oversized));
    try std.testing.expectEqual(@as(usize, 0), parser.line_buf.capacity);

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');
    var total: usize = 0;
    var hit_cap = false;
    while (total < Parser.max_pending_bytes + chunk.len) : (total += chunk.len) {
        parser.feed("data: ") catch unreachable;
        parser.feed(chunk) catch unreachable;
        parser.feed("\n") catch |err| {
            try std.testing.expectEqual(error.EventTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);
    try std.testing.expectEqual(@as(usize, 0), parser.pending.capacity);
}

test "a tool call's accumulated arguments are capped" {
    // Finding 2. 64 MiB of arguments accumulated on one index, in
    // fragments individually well under any per-event cap Parser enforces,
    // held 90 MiB with no cap at all. max_arguments_bytes stops it: a
    // fragment that would push one index's accumulated arguments past the
    // cap is rejected before it is appended.
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    const chunk = try allocator.alloc(u8, 64 * 1024);
    defer allocator.free(chunk);
    @memset(chunk, 'x');

    var total: usize = 0;
    var hit_cap = false;
    while (total < ToolCallAssembler.max_arguments_bytes + chunk.len) : (total += chunk.len) {
        assembler.feed(.{ .index = 0, .arguments = chunk }) catch |err| {
            try std.testing.expectEqual(error.ArgumentsTooLarge, err);
            hit_cap = true;
            break;
        };
    }
    try std.testing.expect(hit_cap);
}

/// Feed `count` distinct tool call indices into a fresh assembler, and
/// return how many stored indices the lookups examined in total. Checks on
/// the way out that every index really landed, so a lookup that silently
/// dropped fragments cannot make the count look good. Only the test below
/// uses this.
fn lookupStepsToFeedDistinctIndices(allocator: std.mem.Allocator, count: usize) !usize {
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();

    var i: usize = 0;
    while (i < count) : (i += 1) {
        try assembler.feed(.{ .index = i, .id = "id", .name = "name", .arguments = "{}" });
    }

    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(count, calls.len);
    return assembler.lookup_steps;
}

test "feeding n distinct tool call indices costs work proportional to n, not to n squared" {
    // Finding 2. entryFor used to scan entries.items linearly on every
    // feed() call: O(n) per fragment, O(n^2) to feed n distinct indices. A
    // reviewer measured 435 ms for 20,000 distinct indices and 1794 ms for
    // 40,000, four times the work for twice the input.
    //
    // This test used to assert that 150,000 indices drained in under eight
    // seconds. A wall clock measures the machine and the load on it, not
    // the code, so that assertion said nothing a reader could act on, and
    // it failed on a Darwin machine that was not slow. It now counts the
    // operation that goes quadratic instead: `ToolCallAssembler.lookup_steps`,
    // the number of stored indices the lookups examined. That count is the
    // same on every machine.
    const allocator = std.testing.allocator;

    // Small counts on purpose. The old wall clock assertion needed 150,000
    // indices before the difference was even measurable, and it still held a
    // gigabyte and ran for a minute to say so. A counter needs only enough
    // input to tell the two growth shapes apart, so 4,000 against 8,000 is
    // as conclusive as 150,000 was, and it costs almost nothing.
    const small_count: usize = 4_000;
    const large_count: usize = 2 * small_count;

    const small_steps = try lookupStepsToFeedDistinctIndices(allocator, small_count);
    const large_steps = try lookupStepsToFeedDistinctIndices(allocator, large_count);

    // The lower bound. Every feed does one lookup, and a lookup examines at
    // least one stored index, so the count is at least the feed count. A
    // counter that a later rewrite left stuck at zero fails here, instead of
    // passing the growth check below for free.
    try std.testing.expect(small_steps >= small_count);
    try std.testing.expect(large_steps >= large_count);

    // The growth. Twice the input must cost about twice the work. A hash map
    // lookup gives one step per feed, so 8,000 steps against 4,000, a factor
    // of two. A linear scan over the stored indices costs n * (n - 1) / 2
    // steps, so 31,996,000 against 7,998,000, a factor of four. A factor of
    // three separates the two shapes with room on both sides.
    try std.testing.expect(large_steps <= 3 * small_steps);
}

test "Finding 3: a rejected body applies nothing, not even the parts that came before the bad field" {
    // A reviewer fed a body with real content and a real first tool call
    // fragment, both individually valid, followed later by a second
    // tool_calls entry with no index: a malformed field deep in the body
    // used to still leave "LEAKED" in text and a complete read_file call
    // in the assembler, even though applyDeltaJson returned an error. This
    // is what the doc comment's "blast radius is one event" claim now
    // actually guarantees, made true by validating the whole body before
    // committing any of it: nothing below should be visible after the
    // error.
    const allocator = std.testing.allocator;
    var assembler = ToolCallAssembler.init(allocator);
    defer assembler.deinit();
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    var reasoning: std.ArrayList(u8) = .empty;
    defer reasoning.deinit(allocator);

    const body =
        \\{"choices":[{"delta":{"content":"LEAKED","tool_calls":[
        \\{"index":0,"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"x\"}"}},
        \\{"function":{"name":"no_index"}}
        \\]}}]}
    ;

    try std.testing.expectError(
        error.ToolCallMissingIndex,
        applyDeltaJson(allocator, &assembler, &text, &reasoning, body),
    );

    try std.testing.expectEqual(@as(usize, 0), text.items.len);
    try std.testing.expectEqual(@as(usize, 0), reasoning.items.len);
    const calls = try assembler.finished();
    defer freeFinished(allocator, calls);
    try std.testing.expectEqual(@as(usize, 0), calls.len);
}

fn expectOnlyCleanEventFollows(allocator: std.mem.Allocator, parser: *Parser) !void {
    try parser.feed("data: {\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}\n\n");
    const event = parser.next() orelse return error.TestExpectedEvent;
    defer event.deinit(allocator);
    try std.testing.expect(event == .data);
    try std.testing.expectEqualStrings("{\"choices\":[{\"delta\":{\"content\":\"clean\"}}]}", event.data.body);
    try std.testing.expect(parser.next() == null);
}

test "every error path leaves the parser clean: a known good event after each comes out exactly right" {
    // The test that proves the bug class is swept, not just the two
    // instances a reviewer happened to name. Fix pass 1 fixed one early
    // reject path that left a stale pending buffer behind. The reviewer
    // then found the same bug in two sibling paths this pass fixes: the
    // lesson was never the one instance, it was that the class was never
    // swept. Every error `feed` can return is triggered here, each on its
    // own fresh parser seeded first with a real data: line that has no
    // blank line yet, so a leftover `pending` buffer actually exists to
    // leak if the error path forgot to clear it. A known good event is fed
    // right after. Exactly that event, and nothing else, must come out:
    // nothing joined onto it, nothing swallowed by it, nothing left queued
    // behind it.
    const allocator = std.testing.allocator;

    // 1. LineTooLong, the early-reject path in feed(): one oversized chunk
    // with no line break at all, nothing buffered before it.
    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        const oversized = try allocator.alloc(u8, Parser.max_line_bytes + 1);
        defer allocator.free(oversized);
        @memset(oversized, 'x');
        try std.testing.expectError(error.LineTooLong, parser.feed(oversized));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    // 2. LineTooLong, the path after the loop in feed(): a real data: line
    // with no blank line yet leaves pending populated, then one feed()
    // call whose bytes start with a short line (dodging the early-reject
    // check, which only fires when the whole chunk has no line break)
    // but whose leftover tail alone, once that first line is consumed, is
    // past the cap.
    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        try parser.feed("data: leftover from a half-built event\n");
        var attack: std.ArrayList(u8) = .empty;
        defer attack.deinit(allocator);
        try attack.appendSlice(allocator, "data: x\n");
        try attack.appendNTimes(allocator, 'x', Parser.max_line_bytes + 100);
        try std.testing.expectError(error.LineTooLong, parser.feed(attack.items));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    // 3. LineTooLong, the mid-loop path added this pass: one complete
    // line past the cap, terminator included, delivered whole in a single
    // feed() call.
    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        try parser.feed("data: leftover from a half-built event\n");
        var attack: std.ArrayList(u8) = .empty;
        defer attack.deinit(allocator);
        try attack.appendSlice(allocator, "data: ");
        try attack.appendNTimes(allocator, 'x', Parser.max_line_bytes + 1);
        try attack.appendSlice(allocator, "\n\n");
        try std.testing.expectError(error.LineTooLong, parser.feed(attack.items));
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    // 4. EventTooLarge: many capped data: lines for one event that never
    // gets its blank line.
    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        const chunk = try allocator.alloc(u8, 64 * 1024);
        defer allocator.free(chunk);
        @memset(chunk, 'x');
        var total: usize = 0;
        var hit_cap = false;
        while (total < Parser.max_pending_bytes + chunk.len) : (total += chunk.len) {
            parser.feed("data: ") catch unreachable;
            parser.feed(chunk) catch unreachable;
            parser.feed("\n") catch |err| {
                try std.testing.expectEqual(error.EventTooLarge, err);
                hit_cap = true;
                break;
            };
        }
        try std.testing.expect(hit_cap);
        // The discarded event's own blank line, arriving late: see the
        // matching comment on the pending-cap test above for why this is
        // needed for a clean event fed right after to read back as its
        // own event rather than being swallowed as more of the discarded
        // one.
        try parser.feed("\n");
        try expectOnlyCleanEventFollows(allocator, &parser);
    }

    // 5. TooManyQueuedEvents: the queue fills because the caller never
    // drains.
    {
        var parser = Parser.init(allocator);
        defer parser.deinit();
        var body = try manySmallEvents(allocator, Parser.max_queued_events + 1);
        defer body.deinit(allocator);
        try std.testing.expectError(error.TooManyQueuedEvents, parser.feed(body.items));

        var drained: usize = 0;
        while (parser.next()) |event| {
            defer event.deinit(allocator);
            drained += 1;
        }
        try std.testing.expectEqual(Parser.max_queued_events + 1, drained);

        try expectOnlyCleanEventFollows(allocator, &parser);
    }
}
