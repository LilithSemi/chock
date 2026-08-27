//! The interface that hides which process, or which host, answers a model
//! request. A later change moves the model client into its own process, with
//! an empty filesystem, that receives a connected socket over `SCM_RIGHTS`
//! instead of dialing out itself. Nothing above `Client` may change when that
//! happens, so `Client` is a plain value, `ptr` and `vtable`, the same shape
//! `std.mem.Allocator` uses: a caller holds a `Client`, never a `*HttpClient`,
//! and has no way to ask which concrete type backs it. See `HttpClient` below
//! for the one implementation that exists today. A second, in process, no
//! network implementation in this file's own tests is what actually proves
//! that.
//!
//! `send` streams. It hands every piece of a model's reply to `on_delta` as
//! soon as one underlying read of the connection makes that piece available,
//! never waiting for a fixed size buffer to fill first: see `streamBody`'s
//! own doc comment for why `std.Io.Reader.readSliceShort` cannot do this and
//! `std.Io.Reader.fillMore` can. The same content, reasoning, and tool call
//! fragments `sse.zig` already knows how to frame and assemble arrive this
//! way. `sendAndAssemble` folds that stream into one `message.Message`, the
//! shape a caller that just wants the finished turn, for example the agent
//! loop, actually wants, and
//! `sendAndAssembleWatching` gives that caller the same stream to show a
//! person while the turn is still running.
//!
//! **A reply that says nothing for long enough is stopped**, and nothing else
//! about a model call is bounded: see `default_gap_ns` for why the bound is on
//! the silence between two pieces and never on the call itself.
//!
//! **A truncated reply is an error, never a short message.** A stream that
//! stops before its own end marker must never read back as though the model
//! simply said less: see `SendError.StreamTruncated` and the doc comment on
//! `sse.Parser.finish`, which names this exact trap. The two wires end
//! differently, and `streamBody` says which marker each one uses. A model
//! provider is a peer Chock does not control, so `send` treats every byte it
//! reads as hostile in the same spirit `sse.zig` already does: a malformed
//! delta chunk fails the whole call rather than being silently skipped,
//! because a provider that sends one is either broken or compromised, and
//! neither case is one to keep talking to quietly.
//!
//! **The key never enters a request body.** `HttpClient` puts it in a header
//! only, and which header is the adapter's business: `Authorization: Bearer`
//! on the OpenAI compatible wire, `x-api-key` on the Anthropic one. See
//! `openai.zig`'s and `anthropic.zig`'s own doc comments: the body is exactly
//! what a session log ends up holding, and
//! `chockd` re-serves that log to other clients.

const std = @import("std");
const message = @import("message.zig");
const anthropic = @import("anthropic.zig");
const openai = @import("openai.zig");
const sse = @import("sse.zig");
const retry = @import("retry.zig");

/// Which wire format an `HttpClient` speaks. **An adapter is not a
/// provider**: many providers share one adapter,
/// and ai& serves both of these on the same host. A caller picks the adapter
/// from the provider instance's kind and keeps saying the provider's name to
/// the user.
pub const Adapter = enum {
    /// `/chat/completions`, `Authorization: Bearer`. Covers ai& and a local
    /// llama.cpp server. See `openai.zig`.
    openai_compatible,
    /// `/messages`, `x-api-key`, `anthropic-version`. See `anthropic.zig`.
    anthropic,

    /// Whether this wire format can express `capability` at all. The first of
    /// the two gates a tool passes before anybody offers it: see
    /// `message.Capability`.
    ///
    /// **A comptime property of the adapter**, not a runtime question about
    /// a host. A pure function over two enums, so a caller may read it at
    /// comptime, and the test at the bottom of this file does. What a
    /// specific provider instance does with the wire is the other gate, and
    /// it lives in the instance's own capability record.
    ///
    /// The switch names every member of both enums with no `else`, so a new
    /// adapter, or a new capability, fails the build here rather than
    /// falling into whichever branch an `else` happened to name. That is the
    /// same rule `src/main.zig`'s own `exitFor` keeps for a session end
    /// reason.
    pub fn carries(self: Adapter, capability: message.Capability) bool {
        return switch (self) {
            .openai_compatible => switch (capability) {
                .tool_calls => true,
                // `openai.zig` builds its content parts from
                // `message.ContentPart`, which has no image part, so there
                // is no image for this adapter to encode.
                .image_results => false,
            },
            .anthropic => switch (capability) {
                .tool_calls => true,
                // The Anthropic wire does have an image content block, and
                // the neutral type still has no image part to fill it from.
                // The gap is in `chock-proto`, not here, so this stays false
                // until that part exists.
                .image_results => false,
            },
        };
    }
};

/// Why the provider stopped a turn, in the provider's own words.
///
/// **`reason` is one short token, and the other two are whatever the provider
/// chose to add.** The Anthropic wire sends the extra two in a `stop_details`
/// object beside the reason, and it sends that object for one reason only,
/// `refusal`. The OpenAI compatible wire has no such field and leaves both
/// empty always.
///
/// **An empty `category` or `explanation` means the provider said nothing**,
/// and never that there was nothing to say: both are nullable on the wire even
/// on a real refusal. A refusal that arrives with neither is a different fact
/// from one that arrives with them, and a reader that reports the two the same
/// way loses that difference. See `anthropic.StopDetails`.
pub const Stop = struct {
    /// The provider's own word, for example "end_turn", "tool_use",
    /// "max_tokens", or "refusal".
    reason: []const u8,
    /// A short token naming the class of a refusal, for example `cyber`.
    category: []const u8 = "",
    /// The provider's own sentence about a refusal, for example "This request
    /// was declined because it could enable cyber harm."
    explanation: []const u8 = "",

    /// Whether the provider declined the request rather than stopping for any
    /// other reason.
    ///
    /// **One token, matched exactly, and no second name for it.** `refusal` is
    /// what the Anthropic wire sends. The OpenAI compatible wire has
    /// `content_filter`, which reads like the same fact and is not measured to
    /// be one: it arrives from a different mechanism, with no `stop_details`
    /// beside it, and reading it as a refusal would end sessions on a guess.
    /// A caller that learns the two are the same adds it here, once, with what
    /// it measured.
    pub fn isRefusal(self: Stop) bool {
        return std.mem.eql(u8, self.reason, "refusal");
    }
};

/// One piece of a model's reply as it streams off the wire. Every field of
/// every variant is a slice borrowed from whatever buffer `send` is
/// currently parsing: it is valid only for the duration of the `on_delta`
/// call it was passed to. A callback that wants to keep the bytes, such as
/// `Collector.onDelta` below, must copy them before returning.
pub const Delta = union(enum) {
    /// A piece of the model's answer text.
    text: []const u8,
    /// A piece of the model's reasoning text. See `message.Reasoning`.
    reasoning: []const u8,
    /// A piece of the signature of the reasoning block this stream is
    /// carrying. **The OpenAI compatible wire has no field for one and never
    /// sends this**; the Anthropic wire sends it as its own `signature_delta`
    /// after the thinking text. A signature that is dropped or regenerated
    /// makes the provider treat the block as forged on the next turn, which
    /// is the permanent loss a lossy conversion makes, so it has a variant of
    /// its own rather than riding inside
    /// `reasoning`.
    reasoning_signature: []const u8,
    /// One fragment of one tool call, keyed by `index` the same way
    /// `sse.ToolCallAssembler.feed` expects: `sse.ToolCallFragment` is an
    /// alias of this same neutral type, not a second shape. A caller that
    /// wants whole tool calls feeds every fragment it sees, in order, to a
    /// `sse.ToolCallAssembler` of its own, or uses `sendAndAssemble`, which
    /// already does that. Neutral, not `sse.zig`'s own type by name: see
    /// `message.ToolCallFragment`'s doc comment on why a second adapter's
    /// `Client.send` must not have to import `sse.zig` to produce one.
    tool_call: message.ToolCallFragment,
    /// What the call has cost so far. **The counts are cumulative and not
    /// incremental**, on both wires: a receiver keeps the last one it was
    /// given and never adds them up. See `anthropic.Decoder`'s own usage note
    /// on why this arrives in the stream rather than in an HTTP header: Chock
    /// streams, so by the time the headers were read the provider had not
    /// counted anything yet.
    usage: message.Usage,
    /// Why the provider stopped this turn, in the provider's own words. See
    /// `Stop`. The Anthropic wire sends it on `message_delta` and the OpenAI
    /// compatible wire sends the reason as a choice's `finish_reason`, so both
    /// adapters produce this and neither invents a value the provider did not
    /// say.
    ///
    /// **Kept because a reply with no content is only explainable by it.** A
    /// turn that returns nothing at all was measured on 2026-08-26: the log
    /// held 7367 input tokens, zero output tokens, an empty assistant
    /// message, and a session that ended `finished`. The provider had said
    /// why and this reader threw the word away, so Chock made up a reason of
    /// its own. The refusal case says the same thing one level deeper: the
    /// word was "refusal", the provider sent a sentence explaining it in the
    /// same event, and a reader that keeps only the word tells nobody
    /// anything. See `AssembledReply.stopReason` and `AssembledReply.stop`.
    ///
    /// **All three parts arrive together, and the receiver replaces all three
    /// together.** They describe one stop, so a fold that kept a refusal's
    /// explanation beside a later reason would attach it to the wrong word.
    stop_reason: Stop,
};

/// `on_delta`'s error set. Deliberately just allocation failure: a callback
/// that wants to reject a delta for some other reason, for example
/// `sse.ToolCallAssembler.Error.ArgumentsTooLarge`, has nowhere else to put
/// that fact and must record it itself and check afterward. `Collector`
/// below does exactly that.
pub const OnDeltaError = std.mem.Allocator.Error;

/// Receives one `Delta` at a time as `send` parses them. `ctx` is whatever
/// the caller of `send` passed alongside this function pointer.
pub const OnDelta = *const fn (ctx: ?*anyopaque, delta: Delta) OnDeltaError!void;

/// A response the provider refused. `body` is whatever it said about the
/// refusal, for example a JSON object naming the reason: a provider spends
/// real words explaining itself, and throwing that away wastes the words.
/// Owned by the caller, freed with the allocator `send` or `sendAndAssemble`
/// was given. Named, not an anonymous struct, so `SendResult` and
/// `AssembledReply` share exactly one shape for it instead of two
/// structurally identical types Zig still treats as distinct.
///
/// **`status` is the status the response actually carried, which is not
/// always outside the 2xx range.** The Anthropic wire can put an `error`
/// event inside a stream whose status was 200 and stayed 200, for example an
/// `overloaded_error` that would have been a 529 in a non-streaming call. A
/// reader that only checks the status misses it entirely, so this type
/// carries that case too and `status` says 200 when that is the truth.
///
/// **`retry_after_s` is what the response's own `Retry-After` header said**,
/// in seconds, or null when it sent none. ai& sends one on a 429, and a wait
/// that honours it is the difference between a
/// session that carries on and a session that dies on the most recoverable
/// error there is. See `chock_provider.retry.retryAfterSeconds` for which
/// forms are read, and `retry.waitMs` for what a caller does with it. Null for
/// a refusal that arrived inside a stream, because a stream's error event
/// carries no headers.
pub const StatusError = struct {
    status: std.http.Status,
    body: []u8,
    retry_after_s: ?u64 = null,
};

/// What `send` returns for a request that reached the provider and read a
/// response, whether or not the provider was happy with it. A transport
/// fault, a malformed stream, or a truncated one is a `SendError` instead:
/// see its doc comment.
pub const SendResult = union(enum) {
    /// Every delta reached `on_delta` and the stream ended cleanly with
    /// nothing left half parsed.
    ok,
    status_error: StatusError,
};

/// The ways one streamed delta chunk's JSON body can fail to have the shape
/// this reader expects. Named the same way `sse.zig`'s own, private,
/// `ApplyDeltaError` is: that type cannot be reused directly, because
/// `sse.zig`'s doc comment says decoding the chunk schema for real use
/// "belongs to whichever adapter calls this parser, built in a later
/// task." This file is that adapter.
pub const DeltaShapeError = error{
    BodyNotObject,
    MissingChoices,
    ChoicesNotArray,
    NoChoices,
    ChoiceNotObject,
    MissingDelta,
    DeltaNotObject,
    ToolCallsNotArray,
    ToolCallNotObject,
    ToolCallMissingIndex,
    ToolCallIndexNotInteger,
    ToolCallIndexNegative,
    ToolCallFunctionNotObject,
    /// The Anthropic wire's own three, from `anthropic.DecodeError`. The
    /// names match that set member for member, so a `try` on `Decoder.feed`
    /// needs no translation, and `BodyNotObject` above is shared because the
    /// two wires agree that a body which is not an object is not a body.
    MissingEventType,
    BlockIndexInvalid,
};

/// Every way `Client.send` can fail to hand back a `SendResult` at all. A
/// non-2xx status is not in this set: that is a value, `SendResult.status_error`,
/// because the caller wants the body text back, not just the fact that
/// something went wrong.
///
/// **Every member here must describe a fact any implementation of `Client`
/// could raise, never a fact about which implementation it happens to be.**
/// An earlier version of this set carried `std.http.Client`'s own error
/// members directly: `ConnectionRefused`, `TlsInitializationFailed`,
/// `UnknownHostName`, `ResolvConfParseFailed`, `InvalidDnsARecord`,
/// `HttpChunkTruncated`, `TooManyHttpRedirects`, and more, all of them facts
/// only an implementation that dials a connection itself can produce. A later
/// change moves that dialing into a parent process, leaving `HttpClient`, at
/// that point, receiving an already connected socket over `SCM_RIGHTS`
/// instead: none of those members could ever fire again, and the new failure
/// that change needs, the parent refusing to hand over a host, would have
/// needed a new one added, changing this declared set at every call site.
/// `TransportFailed` below is what took their place: see its own doc comment
/// for where the specific reason went instead.
pub const SendError =
    std.mem.Allocator.Error ||
    std.json.ParseError(std.json.Scanner) ||
    DeltaShapeError ||
    sse.Parser.Error ||
    sse.ToolCallAssembler.Error ||
    error{
        /// The request could not reach the provider, or the connection
        /// carrying its reply failed, for a reason outside the reply's own
        /// content: a DNS failure, a refused or dropped connection, a TLS
        /// failure, too many redirects, a malformed HTTP chunk, or any other
        /// fault below the SSE framing `sse.zig` parses. Every
        /// implementation of `Client` can fail this way, for a different
        /// underlying reason particular to how it talks to a provider, so
        /// this member names the fact, not the reason. `HttpClient` keeps
        /// the specific reason on `HttpClient.last_transport_error`, a plain
        /// string, for a caller that holds this concrete type, not just a
        /// `Client`, to log: see that field's own doc comment.
        TransportFailed,
        /// The provider compressed the reply. **This is measured, not
        /// hypothetical**: `std.http.Client` advertises `gzip, deflate` by
        /// itself unless a caller says otherwise, `api.anthropic.com` takes
        /// that offer and gzips the event stream, and `Response.reader` hands
        /// back the compressed bytes, because only `readerDecompressing` does
        /// the other thing. Gzip bytes hold no `data:` line, so `sse.Parser`
        /// found no event in a whole reply, `saw_end` stayed false, and every
        /// live Anthropic session ended in about two seconds with
        /// `StreamTruncated` and a usage event of nothing but zeros: a fault
        /// reported as a broken connection, which is a different fault in a
        /// different file. `send` now asks for `identity` and this member is
        /// what a provider that compresses anyway gets, so the answer names
        /// the real fact instead of the parser's confusion about it.
        BodyCompressed,
        /// The provider went quiet: nothing at all arrived on the connection
        /// for `HttpClient.gap_ns`, and the reply was not finished. See
        /// `default_gap_ns` for why the bound is on the gap between pieces
        /// and never on the whole call.
        ///
        /// **A different fact from `StreamTruncated`.** A truncated stream
        /// ended: the connection closed, or the transport failed, and there is
        /// nothing more to wait for. A stalled one did not end at all. The
        /// connection is open and the provider is simply not saying anything,
        /// which from the outside is the one case a session cannot tell apart
        /// from working without a clock.
        StreamStalled,
        /// The stream ended before a `[DONE]` marker ever arrived. This
        /// fires even when nothing was left half parsed: `sse.Parser.finish`'s
        /// own doc comment warns that a connection closed right after a
        /// whole event reports `.complete` too, because nothing fed to the
        /// parser was lost, and only a caller that tracks `.done` itself
        /// can tell that shape apart from a real, finished reply. Tracking
        /// it and returning this instead is the entire reason `send`
        /// exists on top of `sse.Parser`.
        StreamTruncated,
    };

/// The interface a caller holds. `ptr` and `vtable` are the same shape
/// `std.mem.Allocator` uses, and for the same reason: a value, not an
/// interface type the compiler enforces, so any implementation, in this
/// process or in another one reached over a socket
/// `SCM_RIGHTS` handed over, can produce one.
pub const Client = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            request: message.Request,
            on_delta: OnDelta,
            ctx: ?*anyopaque,
        ) SendError!SendResult,
    };

    /// Send `request` and stream the reply through `on_delta`. `request` is
    /// `message.Request`, the neutral shape, not any one adapter's own wire
    /// type: see `message.Request`'s own doc comment on why an OpenAI
    /// compatible adapter's `openai.Request` cannot be the type this interface
    /// carries.
    /// Every implementation is expected to always stream, setting whatever
    /// wire specific flag it needs to itself, the way `HttpClient` does when
    /// it builds its own `openai.Request` from this one.
    pub fn send(
        self: Client,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        return self.vtable.send(self.ptr, allocator, request, on_delta, ctx);
    }
};

/// The HTTP implementation. Speaks either wire format: see `Adapter` on why
/// the wire and the provider are two different things. Holds the one API
/// token this connection uses, and nothing else.
///
/// **The path and the auth header are the adapter's business, not this
/// file's.** `anthropic.path` and `openai_path` say where each wire lives,
/// and `anthropic.key_header` says the key travels in `x-api-key` there and
/// not in `Authorization: Bearer`.
pub const HttpClient = struct {
    http: std.http.Client,
    io: std.Io,
    /// Which wire this client speaks. See `init` and `initAnthropic`.
    adapter: Adapter,
    /// For example `"http://127.0.0.1:5000/v1"`. `send` appends the
    /// adapter's own path. Not owned: the caller keeps this alive for as
    /// long as this `HttpClient` is used.
    base_url: []const u8,
    /// The literal credential. Not owned. Never written into a request
    /// body: see this file's own top comment and `openai.zig`'s.
    ///
    /// **Empty means send no credential header at all**, and that is a real
    /// case, not a mistake. An instance that names no credential and has none
    /// stored sends none, which is what a local llama.cpp server wants, and
    /// there is no placeholder string pretending to be a secret. Sending
    /// `Authorization: Bearer ` with nothing after it is not the same thing:
    /// a real provider reads that as a credential it cannot parse and
    /// answers 401, so a caller with no credential must send no header.
    key: []const u8,
    /// The specific reason the last `send` call failed with
    /// `SendError.TransportFailed`, kept for a caller that holds this
    /// concrete `HttpClient`, not just the neutral `Client` interface, to
    /// log. Always `@errorName` of the underlying error: a static string
    /// literal, never allocated, so there is nothing to free and nothing
    /// this field can leak. `SendError` itself carries only the one generic
    /// member, deliberately: see its own doc comment on why the specific
    /// reason cannot live there. Empty before any call, and left unchanged
    /// by a call that did not fail this way, so a stale reason from an
    /// earlier failed call can survive a later success: check the
    /// `SendResult` or error a call actually returned first.
    last_transport_error: []const u8 = "",
    /// How long a reply may say nothing at all before `send` gives up on it
    /// with `SendError.StreamStalled`. See `default_gap_ns`, which is what
    /// this is unless a caller says otherwise, and which explains why this
    /// bounds the silence between pieces and never the call.
    gap_ns: u64 = default_gap_ns,
    /// What answers "is the provider still sending". Null, the default, is the
    /// connection itself. See `Wire`, which is the seam a test drives.
    wire: ?Wire = null,
    /// What the caller does while this waits for the provider to say something.
    /// Null, the default, is nothing at all, which is what every caller with no
    /// display gives. See `Idle`.
    idle: ?Idle = null,

    /// A client for an OpenAI compatible endpoint: ai&, a local llama.cpp
    /// server, or a user's own `openai-compat` URL. Two named constructors
    /// rather than one that takes an `Adapter`, so a call site says which
    /// wire it means and a wrong default cannot hide in a struct literal.
    pub fn init(allocator: std.mem.Allocator, io: std.Io, base_url: []const u8, key: []const u8) HttpClient {
        return initAdapter(allocator, io, .openai_compatible, base_url, key);
    }

    /// A client for the Anthropic native wire. ai& serves this shape too, at
    /// the same host.
    pub fn initAnthropic(
        allocator: std.mem.Allocator,
        io: std.Io,
        base_url: []const u8,
        key: []const u8,
    ) HttpClient {
        return initAdapter(allocator, io, .anthropic, base_url, key);
    }

    fn initAdapter(
        allocator: std.mem.Allocator,
        io: std.Io,
        adapter: Adapter,
        base_url: []const u8,
        key: []const u8,
    ) HttpClient {
        return .{
            .http = .{ .allocator = allocator, .io = io },
            .io = io,
            .adapter = adapter,
            .base_url = base_url,
            .key = key,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.http.deinit();
    }

    /// The `Client` interface value for this implementation. A caller holds
    /// this, never a `*HttpClient`, and this file's own tests are what
    /// prove that matters: see `"the fake and the HTTP client are
    /// interchangeable for a caller"` below.
    pub fn client(self: *HttpClient) Client {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Client.VTable{ .send = sendVtable };

    fn sendVtable(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        const self: *HttpClient = @ptrCast(@alignCast(ptr));
        return self.send(allocator, request, on_delta, ctx);
    }

    /// Record `err`'s name on `last_transport_error` and report the one
    /// generic reason `SendError` carries for it. `error.OutOfMemory` is
    /// never folded in here: it stays itself, since `SendError` already
    /// carries `std.mem.Allocator.Error` directly and a caller genuinely
    /// out of memory needs to know that, not "some transport thing failed."
    fn transportFailed(self: *HttpClient, err: anytype) SendError {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        self.last_transport_error = @errorName(err);
        return error.TransportFailed;
    }

    fn send(
        self: *HttpClient,
        allocator: std.mem.Allocator,
        request: message.Request,
        on_delta: OnDelta,
        ctx: ?*anyopaque,
    ) SendError!SendResult {
        // Each adapter's own wire shaped type, not the interface's: see
        // message.Request's doc comment. `stream` is set here, not read from
        // the neutral request,
        // because streaming is this whole file's job, not the caller's
        // choice.
        const body = switch (self.adapter) {
            .openai_compatible => try openai.buildRequest(allocator, .{
                .model = request.model,
                .system = request.system,
                .messages = request.messages,
                .tools = request.tools,
                .stream = true,
            }),
            .anthropic => try anthropic.buildRequest(allocator, .{
                .model = request.model,
                .system = request.system,
                .messages = request.messages,
                .tools = request.tools,
                .stream = true,
            }),
        };
        defer allocator.free(body);

        const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{
            self.base_url,
            switch (self.adapter) {
                .openai_compatible => openai_path,
                .anthropic => anthropic.path,
            },
        });
        defer allocator.free(url);
        const uri = std.Uri.parse(url) catch |err| return self.transportFailed(err);

        // An empty key builds no header value and sends no header: see the
        // `key` field's own doc comment. The buffer is still allocated in
        // both cases, so there is one free path and not two. The Anthropic
        // wire puts the key in `x-api-key` verbatim instead, so it builds no
        // buffer of its own and this one stays empty there.
        const auth_value = if (self.key.len == 0 or self.adapter != .openai_compatible)
            try allocator.dupe(u8, "")
        else
            try std.fmt.allocPrint(allocator, "Bearer {s}", .{self.key});
        defer {
            // Finding 6: a credential sitting freed-but-unzeroed in the heap
            // is still readable in a crash dump, a swapped page, or a reused
            // allocation until something overwrites it. Zero it before
            // freeing: the only reader of this buffer, the header override
            // above, has already copied whatever it needed out of it by
            // this point.
            std.crypto.secureZero(u8, @volatileCast(auth_value));
            allocator.free(auth_value);
        }
        const authorization: std.http.Client.Request.Headers.Value =
            if (auth_value.len == 0) .omit else .{ .override = auth_value };

        // Three headers at most, and which three depends on the wire. The
        // array is sized for the largest case and sliced down, so nothing
        // here allocates and every entry's value outlives the request.
        var header_storage: [3]std.http.Header = undefined;
        var header_count: usize = 0;
        header_storage[header_count] = .{ .name = "Accept", .value = "text/event-stream" };
        header_count += 1;
        switch (self.adapter) {
            .openai_compatible => {
                // ai&'s own cost and timing metadata arrives only when the
                // request asks for it, and it
                // is off by default. A provider that has never heard of this
                // header ignores it, which is what a local llama.cpp server
                // does.
                header_storage[header_count] = .{ .name = aiand_metrics_header, .value = "true" };
                header_count += 1;
            },
            .anthropic => {
                header_storage[header_count] = .{
                    .name = anthropic.version_header,
                    .value = anthropic.version,
                };
                header_count += 1;
                if (self.key.len != 0) {
                    header_storage[header_count] = .{ .name = anthropic.key_header, .value = self.key };
                    header_count += 1;
                }
            },
        }

        var req = self.http.request(.POST, uri, .{
            .keep_alive = false,
            // No redirect is followed. A provider that answers a chat
            // completion with a redirect is not one to follow blindly:
            // the allowlist principle, applied to an HTTP response instead
            // of a system call.
            .redirect_behavior = .not_allowed,
            .headers = .{
                .authorization = authorization,
                .content_type = .{ .override = "application/json" },
                // **Ask for the bytes as they are.** See `identity_encoding`.
                .accept_encoding = .{ .override = identity_encoding },
            },
            .extra_headers = header_storage[0..header_count],
        }) catch |err| return self.transportFailed(err);
        defer req.deinit();

        req.sendBodyComplete(body) catch |err| return self.transportFailed(err);

        var redirect_buf: [4 * 1024]u8 = undefined;
        var response = req.receiveHead(&redirect_buf) catch |err| return self.transportFailed(err);

        // Before the status, because it decides whether either body below can
        // be read at all: a compressed body is compressed whether the
        // provider was happy or not. See `SendError.BodyCompressed`.
        if (response.head.content_encoding != .identity) return error.BodyCompressed;

        if (response.head.status.class() != .success) {
            // Read before the body, because `Response.reader` invalidates
            // every pointer the head holds: see `Response.head`'s own doc
            // comment. A `Retry-After` read after that would be read out of a
            // buffer the body is already being parsed into.
            const retry_after = retryAfterOf(response.head);
            var transfer_buf: [4 * 1024]u8 = undefined;
            const body_reader = response.reader(&transfer_buf);
            const error_body = try readErrorBody(allocator, body_reader);
            return .{ .status_error = .{
                .status = response.head.status,
                .body = error_body,
                .retry_after_s = retry_after,
            } };
        }

        var transfer_buf: [4 * 1024]u8 = undefined;
        const body_reader = response.reader(&transfer_buf);
        // What says the provider stopped sending, built from the connection
        // this reply is already arriving on. Null when there is no connection
        // to watch, which leaves the read exactly as it was: see `Gap`.
        const gap: ?Gap = if (req.connection) |connection| .{
            .io = self.io,
            .stream = connection.stream_reader.stream,
            .in_hand = connection.reader(),
            .gap_ns = self.gap_ns,
            .wire = self.wire,
            .idle = self.idle,
        } else null;
        // Everything streamBody can fail with is already a member of
        // SendError as declared, no translation needed: only the connect
        // and request-write stage above, which talks in std.http.Client's
        // own error types, needs transportFailed's help.
        return streamBody(allocator, self.adapter, response.head.status, body_reader, gap, on_delta, ctx);
    }
};

/// Where the OpenAI compatible wire lives under a base URL. The Anthropic
/// one names its own: see `anthropic.path`.
const openai_path = "/chat/completions";

/// ai& sends its cost and timing metadata only when the request asks for it.
const aiand_metrics_header = "X-Aiand-Metrics";

/// What `send` puts in `Accept-Encoding`. **The bytes as they are, with no
/// compression at all.**
///
/// `std.http.Client` offers `gzip, deflate` by itself unless the caller
/// overrides this header, and a provider that takes the offer answers with a
/// compressed body. `Response.reader`, which `send` uses, gives back exactly
/// what arrived: only `Response.readerDecompressing` unpacks it. So the
/// compressed bytes reach `sse.Parser`, which finds no `data:` line in them,
/// and a whole good reply reads back as an empty, truncated stream. That is
/// what happened against `api.anthropic.com`: see `SendError.BodyCompressed`.
///
/// Asked for rather than merely not asked for: a request with no
/// `Accept-Encoding` at all leaves every coding acceptable, per RFC 9110, so
/// a server may still compress. `identity` says what this reader can read.
///
/// Decompressing instead would save bytes, and it is the wrong trade here.
/// Chock streams: `streamBody` hands each delta on as soon as one read of the
/// connection produces it, and a decompressor gives back only what its own
/// framing lets it give back, so the moment a delta becomes visible would
/// stop being the moment it arrived. An event stream is short text a model
/// writes a few tokens at a time, and latency is what a user watches.
const identity_encoding = "identity";

/// How long a reply may say nothing at all before `send` calls the provider
/// stalled. Five minutes.
///
/// **The bound is on the gap between pieces, and there is deliberately no
/// bound on the whole call.** A model call had no bound of any kind before
/// this, so a provider that stopped sending hung the session for as long as
/// anybody left it running, with nothing to tell that apart from a provider
/// that was working.
///
/// A bound on the whole call cannot tell those apart either, and the measured
/// session is what proves it: one turn of a real session took nineteen minutes
/// while the model was genuinely generating the whole time, deltas arriving in
/// gaps of a few seconds throughout. Any whole call bound short enough to
/// catch a real stall would have thrown that turn away, and any bound long
/// enough to keep it would not catch anything. **A gap bound stays quiet
/// through exactly that turn**, because nothing was ever silent for long, and
/// fires the moment a provider actually stops.
///
/// Five minutes, and not five seconds, because the first piece is the slow
/// one: a local llama.cpp server reading a twenty thousand token context on
/// one card spends minutes on the prompt before it emits a first token, and
/// that is the wait this must not interrupt. Between tokens of a healthy
/// stream the gap is under a second, so the bound is two orders of magnitude
/// clear of the case it must not touch. It bounds silence, never work.
pub const default_gap_ns: u64 = 5 * std.time.ns_per_min;

/// What answers "has the provider said anything within the bound", and the
/// seam a test drives instead of a clock.
///
/// **This exists so that no test of the gap bound measures elapsed time.** The
/// fact the bound carries is that a stream which is slow but still live is left
/// alone, and a stream that has gone silent is cut. Neither fact is about a
/// duration. A test that scripted real pauses against a real bound measured the
/// machine and the load on it: one such test failed on a loaded Darwin box and
/// passed on a rerun of the same tree, and three earlier tests in this project
/// were removed for the same reason. A margin that is wide enough today is a
/// test that fails on a busier machine later.
///
/// The same shape `retry.Sleeper` uses, and for the same reason. Null on
/// `HttpClient.wire` is the real answer, which is a poll of the socket: see
/// `Gap.moreIsComing`.
///
/// **The seam covers this one question and nothing else.** `Gap.eventInHand`
/// still reads the real buffer, `Gap.stopReading` still shuts the real socket,
/// and `streamBody` still decodes real bytes off a real connection, so a test
/// that drives this drives every other part of the machinery for real.
pub const Wire = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// True while the provider is still sending. False means `gap_ns`
        /// passed with the connection saying nothing at all.
        moreIsComing: *const fn (ptr: *anyopaque, gap_ns: u64) bool,
    };

    pub fn moreIsComing(self: Wire, gap_ns: u64) bool {
        return self.vtable.moreIsComing(self.ptr, gap_ns);
    }
};

/// What the caller does while this file waits for the provider.
///
/// **The wait for the first piece of a reply is the longest one in a session**,
/// and a caller drawing a full screen display reads its keyboard in the same
/// thread that sits in that wait. Without this the display is frozen for the
/// whole of it: it cannot scroll, and it cannot answer a key. See
/// `Gap.moreIsComing`, which is the one place this is called, and
/// `lib/chock-core/idle.zig` for why a second thread is not the answer.
///
/// **A second definition of the same shape, on purpose.** `chock-core` has one
/// of these for the wait a sandboxed program's own pipe makes, and this module
/// imports no `chock-core`: it is the model adapters and nothing else. The two
/// are joined by a few lines in `src/run.zig`, which is the same cost
/// `chock_core.ask.Console` pays to stay out of `src/approval.zig`.
///
/// **Built in place and never copied**: the value holds a pointer.
pub const Idle = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// One look. **It cannot fail and it cannot say anything**: a wait must
        /// behave the same whether or not anybody is watching it.
        step: *const fn (ptr: *anyopaque) void,
    };

    pub fn step(self: Idle) void {
        self.vtable.step(self.ptr);
    }
};

/// How long one slice of the wait for the provider is, in milliseconds.
///
/// **The same tenth of a second `chock_core.idle.slice_ms` names**, written
/// again here rather than imported because this module imports no `chock-core`.
/// A slice bounds how long a key waits for the screen, and nothing else: the
/// gap bound itself is unchanged, because a slice that expires with the wire
/// still quiet goes straight back into the next one.
pub const idle_slice_ms: u64 = 100;

/// How long the next slice of a wait with `left_ms` still to run is.
///
/// **Its own function, over one number, so the one rule that matters is
/// somewhere a test can reach**: the slices of a wait add up to the wait. A
/// slice that overran would give the provider longer to go quiet than
/// `gap_ns` says, and a slice of zero would turn the wait into a busy loop.
pub fn idleSlice(left_ms: i32) i32 {
    std.debug.assert(left_ms > 0);
    return @min(left_ms, @as(i32, @intCast(idle_slice_ms)));
}

/// Watches one connection for the provider going quiet. Built by `send` from
/// the connection it is already reading, and used by `streamBody` between one
/// read and the next.
///
/// **This waits on the socket rather than bounding the read**, and that is
/// forced. `std.Io.Reader` carries no deadline, `SO_RCVTIMEO` surfaces as an
/// `EAGAIN` that `std.Io`'s own posix read treats as a programmer bug and
/// panics on, and `Io.operateTimeout` needs a concurrent operation, which is
/// exactly what the `Io` a session runs on cannot start: see `src/main.zig`
/// on the failing allocator that makes `fork` safe. A poll needs none of
/// those things.
///
/// ## Three questions, and each one was measured before it was written
///
/// "Are there any bytes in hand" is the wrong question, and it is wrong in
/// both directions:
///
/// * A chunked body leaves the two bytes that end one chunk in the
///   connection's own buffer, and those two bytes cannot make an event. A read
///   issued on the strength of them goes straight to the socket and waits
///   there with no bound at all, which is the fault this type exists to
///   remove. That is what a provider stalling between two events actually
///   looks like, so it is the case that matters most.
/// * The other way round, treating "no bytes in hand" as reason enough to wait
///   holds back pieces that had already arrived: reading the response head
///   takes the first pieces of the body with it.
///
/// So the question `eventInHand` asks is "will the decoder produce something
/// without the socket", the question `moreIsComing` asks is "has the wire said
/// anything within the bound", and `stopReading` is what makes a wrong answer
/// to the first one survivable: every byte already read is still decoded and
/// still delivered after this end stops listening.
const Gap = struct {
    io: std.Io,
    /// The socket the reply is arriving on.
    stream: std.Io.net.Stream,
    /// What the connection has already read and not yet handed up: the
    /// protocol's own reader, which is the decrypted one on a TLS connection
    /// and the socket's own on a plain one. Read by `eventInHand` and by
    /// nothing else.
    in_hand: *std.Io.Reader,
    gap_ns: u64,
    /// What answers `moreIsComing`. Null is the socket itself, which is what
    /// every caller outside a test gives. See `Wire`.
    wire: ?Wire = null,
    /// What the caller does while this waits. Null is nothing at all. See
    /// `Idle`.
    idle: ?Idle = null,

    /// Whether what has already arrived holds at least one whole event, so
    /// the next read has something to give with no help from the wire.
    ///
    /// **Without this the first piece of every reply can be held back.**
    /// Reading the response head routinely takes the first pieces of the body
    /// with it, so a whole event is often in hand before this loop runs once.
    /// Waiting on the socket then delays a piece that had already arrived
    /// until the provider happens to send the next one, which is the opposite
    /// of what streaming is for. Measured on Darwin, where it pushed the first
    /// delta of a reply from immediate to the moment the second one was sent.
    ///
    /// **A blank line, because that is what ends an event on this wire**, and
    /// the question this has to answer is "will the decoder produce something
    /// without the socket", not "are there any bytes at all". Any bytes at all
    /// is the wrong question: a chunked body leaves the two bytes that end one
    /// chunk in this buffer, and a read issued on the strength of those two
    /// goes straight to the socket and waits there with no bound, which is the
    /// fault this whole type exists to remove.
    ///
    /// Wrong in the safe direction when it is wrong. A wire format that ended
    /// its events some other way would read as nothing in hand, and then this
    /// waits on the socket, which is bounded, and `stopReading` still lets
    /// every buffered byte through afterwards.
    fn eventInHand(self: Gap) bool {
        const buffered = self.in_hand.buffered();
        if (std.mem.indexOf(u8, buffered, "\n\n") != null) return true;
        return std.mem.indexOf(u8, buffered, "\r\n\r\n") != null;
    }

    /// Whether anything more is on its way. False means the bound passed with
    /// the connection saying nothing at all.
    ///
    /// **The one question a test answers in place of the wire.** See `Wire`.
    ///
    /// **The wait is cut into slices when a caller has something to do in
    /// them**, and it is the same wait either way: a slice that ends with the
    /// wire still quiet goes straight into the next one, and the number of
    /// milliseconds this will sit here in total is `gap_ns` whichever branch
    /// runs. Only the caller's own display moves in between. See `Idle`.
    fn moreIsComing(self: Gap) bool {
        if (self.wire) |scripted| return scripted.moreIsComing(self.gap_ns);
        const ms = self.gap_ns / std.time.ns_per_ms;
        const whole: i32 = if (ms > std.math.maxInt(i32)) std.math.maxInt(i32) else @intCast(ms);

        const filler = self.idle orelse return self.readable(whole);

        var left = whole;
        while (left > 0) {
            const slice = idleSlice(left);
            if (self.readable(slice)) return true;
            left -= slice;
            // **After the poll and not before it**, so a reply that was already
            // on its way is delivered without waiting on a frame first.
            filler.step();
        }
        return false;
    }

    /// Whether the socket has anything to read within `timeout_ms`.
    ///
    /// **True is the safe answer to every question this cannot settle.** A poll
    /// that cannot run says nothing about the provider, so it must not be read
    /// as the provider being silent: the caller goes back to the read and the
    /// behaviour this whole type is an improvement on stands.
    fn readable(self: Gap, timeout_ms: i32) bool {
        var fds = [_]std.posix.pollfd{.{
            .fd = self.stream.socket.handle,
            // A closed connection is readable: the read that follows gets the
            // end of the stream, which is a different fault with its own
            // answer. See `SendError.StreamTruncated`.
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, timeout_ms) catch return true;
        return ready != 0;
    }

    /// Close this end's half of the connection, so no read after this can
    /// wait on the socket again.
    ///
    /// **This is what bounds the read without bounding the reader.** A read
    /// with a deadline is not available here: `std.Io.Reader` carries none,
    /// `SO_RCVTIMEO` surfaces as an `EAGAIN` that `std.Io`'s own posix read
    /// treats as a programmer bug and panics on, and `Io.operateTimeout` needs
    /// a concurrent operation, which is exactly what the `Io` a session runs
    /// on cannot start: see `src/main.zig` on the failing allocator that makes
    /// `fork` safe. Shutting the read side turns every later read into a clean
    /// end of stream instead, which the loop already knows how to finish on.
    ///
    /// **Nothing already read is lost.** This closes the socket's half, not
    /// the buffers above it, so every byte already in hand is still decoded
    /// and still delivered, and a reply whose end marker was already buffered
    /// still finishes as a complete reply.
    fn stopReading(self: Gap) void {
        // A shutdown that fails leaves the read exactly as it was, which is
        // the behaviour this whole type is an improvement on: there is
        // nothing better to do about it and nothing to say.
        self.stream.shutdown(self.io, .recv) catch {};
    }
};

/// The largest non-2xx response body `send` will read into memory. 8 MiB:
/// the same order of magnitude as `sse.Parser.max_line_bytes`, generous for
/// any real provider's refusal message while still bounding a hostile or
/// merely broken server's arbitrarily large error body. A reviewer measured
/// the old, uncapped `allocRemaining(allocator, .unlimited)` allocate 24 MiB
/// for a 24 MiB error body, three times `sse.Parser`'s own cap: this walks
/// straight around the bound the streaming path already enforces. See
/// `readErrorBody`.
const max_error_body_bytes: usize = 8 * 1024 * 1024;

/// What this response's `Retry-After` header asked for, in seconds, or null
/// when it carried none.
///
/// `std.http.Client.Response.Head` names a field for each of the few headers
/// it interprets itself and leaves the rest in `iterateHeaders`, so this walks
/// them. **Must be called before `Response.reader`**: that call invalidates
/// every pointer the head holds, this one included.
fn retryAfterOf(head: std.http.Client.Response.Head) ?u64 {
    var headers = head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "retry-after")) continue;
        return retry.retryAfterSeconds(header.value);
    }
    return null;
}

/// Read a non-2xx response body, capped at `max_error_body_bytes`. Never
/// silently returns an empty body for one that was actually there: the old
/// version of this function folded `error.StreamTooLong` and
/// `error.ReadFailed` into the same empty string, so a body that was too
/// large to keep and a body that failed to read at all both read back
/// indistinguishable from a provider that genuinely sent nothing. Each gets
/// its own placeholder text instead, so a caller can tell "the provider said
/// nothing" apart from "something was lost."
fn readErrorBody(allocator: std.mem.Allocator, body_reader: *std.Io.Reader) std.mem.Allocator.Error![]u8 {
    return body_reader.allocRemaining(allocator, .limited(max_error_body_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => try std.fmt.allocPrint(
            allocator,
            "[error body exceeded {d} bytes and was discarded]",
            .{max_error_body_bytes},
        ),
        error.ReadFailed => try std.fmt.allocPrint(
            allocator,
            "[error body could not be read: the connection failed partway through]",
            .{},
        ),
    };
}

/// Read `body_reader` to the end, feeding every byte to an `sse.Parser` and
/// every parsed event's JSON to `deliverDelta`. Returns
/// `error.StreamTruncated` the moment either the transport itself fails, for
/// example a chunked body cut off mid chunk, or the stream ends without
/// ever producing a `.done` event: see `SendError.StreamTruncated`.
///
/// **This is where streaming actually happens, and it earlier did not.**
/// `std.Io.Reader.readSliceShort(&chunk_buf)`, the call this function used
/// before this fix, loops internally until `chunk_buf` is either completely
/// full or the stream has ended: see its own doc comment, "returns the
/// number of bytes read, which is less than `buffer.len` if and only if the
/// stream reached the end." With a 4 KiB buffer, that meant no delta ever
/// reached `on_delta` until 4 KiB of reply had piled up, or the reply ended,
/// whichever came first. Measured against a fake server that sent three
/// events at t=0ms, t=300ms, and t=600ms: all three were delivered to
/// `on_delta` together at t+906ms, only once the connection closed. Measured
/// against a real `glm4.7-flash` server: 328 deltas arrived in bursts of
/// about 16, roughly once a second, the first burst at t+1734ms.
///
/// `std.Io.Reader.fillMore` does exactly one underlying read of whatever the
/// connection currently has, adding it to `body_reader`'s buffer without
/// waiting for more: see its own doc comment. `body_reader.buffered()` reads
/// back only the bytes that call just added (everything before them was
/// already fed to `parser` and `toss`ed on the previous loop iteration), so
/// every piece reaches `parser.feed`, and in turn `on_delta`, the moment one
/// read off the wire produced it.
///
/// **`gap` is what stops this loop waiting forever**, and it is the only bound
/// on a model call anywhere in Chock: see `Gap` for how the silence is
/// measured and `default_gap_ns` for why it is measured between pieces and
/// never over the whole call. Null leaves the loop exactly as it was.
///
/// **The two wires end differently, and only one of them says `[DONE]`.** The
/// OpenAI compatible wire ends with a literal `data: [DONE]` line, so a
/// stream that stops before one was cut short. The Anthropic wire ends with a
/// `message_stop` event and never sends `[DONE]` at all, so waiting for one
/// there would call every complete reply truncated. `saw_end` below is set by
/// whichever of the two this stream actually uses.
fn streamBody(
    allocator: std.mem.Allocator,
    adapter: Adapter,
    status: std.http.Status,
    body_reader: *std.Io.Reader,
    gap: ?Gap,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!SendResult {
    var parser = sse.Parser.init(allocator);
    defer parser.deinit();
    var decoder = anthropic.Decoder.init(allocator);
    defer decoder.deinit();
    // The last stop reason handed to `on_delta`, so a decoder that still holds
    // the same one does not send it again on every event after it arrived.
    var sent_stop_reason: [max_stop_reason]u8 = @splat(0);
    var sent_len: usize = 0;
    var saw_end = false;
    // Set when the gap bound passed and this end stopped reading the socket.
    // The loop carries on from there and decodes whatever is already in hand:
    // see `Gap.stopReading`. It only decides what an unfinished reply is
    // called, at the bottom.
    var stalled = false;

    while (true) {
        // **Between one piece and the next, which is the only place silence
        // means anything.** Everything already read has been parsed and
        // delivered by this point in the loop, so a connection with nothing
        // arriving is a provider that stopped sending. Asked once: after the
        // read side is shut, no read can wait on the socket again, so there is
        // nothing left to wait for and nothing left to ask.
        if (gap) |watch| {
            if (!stalled and !saw_end and !watch.eventInHand() and !watch.moreIsComing()) {
                watch.stopReading();
                stalled = true;
            }
        }

        body_reader.fillMore() catch |err| switch (err) {
            // A clean end of body, the same fact the old readSliceShort
            // based loop read off a short count instead: `sse.Parser.finish`
            // below is what actually decides whether that end was clean.
            error.EndOfStream => break,
            // A transport fault mid body, for example a chunked body cut off
            // mid chunk: the same shape the old loop caught via a bare
            // ShortError from readSliceShort. See SendError.StreamTruncated.
            //
            // **Once this end has stopped reading, this is that and not a
            // transport fault.** The read side was shut deliberately, and a
            // body reader that was midway through a chunk frame reports the
            // end it then sees as a failure rather than as an end of stream.
            // Calling that a broken connection would name the wrong fault, in
            // the wrong file, for a provider that simply went quiet.
            error.ReadFailed => return if (stalled) error.StreamStalled else error.StreamTruncated,
        };

        // fillMore's own doc comment allows it to add zero bytes without
        // that being end of stream: nothing more to feed the parser yet, so
        // just ask again. A blocking connection, the only kind this
        // implementation dials, does not busy loop here: the next fillMore
        // blocks on its own underlying read the same way this one did.
        const available = body_reader.buffered();
        if (available.len == 0) continue;

        try parser.feed(available);
        body_reader.toss(available.len);

        while (parser.next()) |event| {
            defer event.deinit(allocator);
            switch (event) {
                .done => saw_end = true,
                .data => |data| switch (adapter) {
                    .openai_compatible => try deliverDelta(allocator, data, on_delta, ctx),
                    .anthropic => {
                        if (try deliverAnthropic(allocator, &decoder, data, status, on_delta, ctx)) |refusal| {
                            return .{ .status_error = refusal };
                        }
                        // The decoder keeps this across events, so the check
                        // is on whether it has changed since it was last sent
                        // on. See `Delta.stop_reason`.
                        const reason = decoder.stopReason();
                        if (reason.len != 0 and !std.mem.eql(u8, reason, sent_stop_reason[0..sent_len])) {
                            sent_len = keepCut(&sent_stop_reason, reason);
                            // The details of the same event, because the
                            // decoder replaces them with the reason they
                            // belong to and this is the one send that reason
                            // gets. See `Stop`.
                            const details = decoder.stopDetails();
                            try on_delta(ctx, .{ .stop_reason = .{
                                .reason = reason,
                                .category = details.category,
                                .explanation = details.explanation,
                            } });
                        }
                        // Or, never a plain assignment: an end already seen
                        // must not be un-seen by a later event.
                        saw_end = saw_end or decoder.saw_message_stop;
                    },
                },
            }
        }
    }

    if (!saw_end or parser.finish() != .complete) {
        // **Which fault it was depends on why the reading stopped**, and the
        // two are different things to tell a user. A truncated stream ended:
        // the connection closed or the transport failed, and there was
        // nothing more to wait for. A stalled one never ended at all, and
        // this end is the one that stopped listening, after the provider said
        // nothing for the whole bound.
        return if (stalled) error.StreamStalled else error.StreamTruncated;
    }
    // A reply whose own end marker was already in hand finishes as a complete
    // reply, even when the wire went quiet first: the answer is all there, and
    // a session that threw it away over the connection's manners would lose a
    // whole turn of real work. `send` asks for `keep_alive = false`, so this
    // connection was not going to be used again in any case.
    return .ok;
}

/// Read one Anthropic stream event and hand whatever it carried to
/// `on_delta`. Answers with a `StatusError` when the event was an `error`
/// event, which is the case a reader that only checks the HTTP status misses:
/// see `StatusError`'s own doc comment. `status` is the status the response
/// actually carried, which for this case is 200.
fn deliverAnthropic(
    allocator: std.mem.Allocator,
    decoder: *anthropic.Decoder,
    json_text: []const u8,
    status: std.http.Status,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!?StatusError {
    const piece = try decoder.feed(json_text);
    switch (piece) {
        .none => {},
        .text => |text| if (text.len != 0) try on_delta(ctx, .{ .text = text }),
        .reasoning => |text| if (text.len != 0) try on_delta(ctx, .{ .reasoning = text }),
        .reasoning_signature => |text| if (text.len != 0) {
            try on_delta(ctx, .{ .reasoning_signature = text });
        },
        .tool_call => |fragment| try on_delta(ctx, .{ .tool_call = fragment }),
        .usage => |usage| try on_delta(ctx, .{ .usage = usage }),
        .stream_error => return StatusError{
            .status = status,
            // The whole event, not a re-worded summary: a provider spends
            // real words explaining a refusal and the caller wants them.
            .body = try allocator.dupe(u8, json_text),
        },
    }
    return null;
}

/// Read the fields this adapter cares about out of one delta chunk's JSON
/// body and hand each one to `on_delta` as it is found, mirroring the shape
/// `sse.zig`'s own, private, `parseDelta` reads. Unlike that function, this
/// one delivers each piece immediately instead of collecting them first:
/// `on_delta` is expected to copy what it needs before returning, per
/// `Delta`'s own doc comment, so there is nothing left to lose by not
/// batching. A field this reader cannot make sense of fails the whole
/// event, the same "blast radius is one event" reasoning `sse.zig` already
/// documents, propagated up through `send`'s `SendError` instead of being
/// silently skipped: a provider sending a malformed delta is not one to
/// keep trusting quietly.
fn deliverDelta(
    allocator: std.mem.Allocator,
    json_text: []const u8,
    on_delta: OnDelta,
    ctx: ?*anyopaque,
) SendError!void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_text, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.BodyNotObject;

    // Before the choices, because **the chunk that carries the counts and the
    // cost carries no choice at all**: a stream that asked for usage ends
    // with `"choices":[]` beside a `usage` object, and ai& puts its cost in
    // that same trailing event rather than in a header. A reader that
    // demands a choice first throws the number away and calls the event
    const reported_usage = openAiUsage(parsed.value.object);
    if (reported_usage) |usage| try on_delta(ctx, .{ .usage = usage });

    const choices_value = parsed.value.object.get("choices") orelse {
        if (reported_usage != null) return;
        return error.MissingChoices;
    };
    if (choices_value != .array) return error.ChoicesNotArray;
    if (choices_value.array.items.len == 0) {
        if (reported_usage != null) return;
        return error.NoChoices;
    }

    const choice_value = choices_value.array.items[0];
    if (choice_value != .object) return error.ChoiceNotObject;

    // On the choice and not inside its `delta`: this wire ends a reply with a
    // chunk whose `delta` is empty and whose `finish_reason` is the only thing
    // that says anything. Read before the delta, so a chunk this reader then
    // rejects has still handed the reason on. See `Delta.stop_reason`.
    // This wire carries the word and nothing more: it has no `stop_details`,
    // so the other two parts of `Stop` stay empty here.
    if (choice_value.object.get("finish_reason")) |v| {
        if (v == .string and v.string.len != 0) {
            try on_delta(ctx, .{ .stop_reason = .{ .reason = v.string } });
        }
    }

    const delta_value = choice_value.object.get("delta") orelse return error.MissingDelta;
    if (delta_value != .object) return error.DeltaNotObject;
    const delta = delta_value.object;

    if (delta.get("content")) |v| {
        if (v == .string and v.string.len != 0) try on_delta(ctx, .{ .text = v.string });
    }
    if (delta.get("reasoning_content")) |v| {
        if (v == .string and v.string.len != 0) try on_delta(ctx, .{ .reasoning = v.string });
    }

    if (delta.get("tool_calls")) |tool_calls_value| {
        if (tool_calls_value != .array) return error.ToolCallsNotArray;
        for (tool_calls_value.array.items) |call_value| {
            if (call_value != .object) return error.ToolCallNotObject;
            const call = call_value.object;

            const index_value = call.get("index") orelse return error.ToolCallMissingIndex;
            if (index_value != .integer) return error.ToolCallIndexNotInteger;
            if (index_value.integer < 0) return error.ToolCallIndexNegative;
            var fragment = message.ToolCallFragment{ .index = @intCast(index_value.integer) };

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
            try on_delta(ctx, .{ .tool_call = fragment });
        }
    }
}

/// The value of `object[name]` under any of `names`, or null. The exact
/// spelling ai& uses for its metric fields inside the trailing stream event
/// is not something this project has read off a live endpoint. ai& names the
/// HTTP headers `X-Cost` and `X-Cost-Currency`, and the streaming path carries
/// them in the final event instead. Accepting
/// the header spelling, the snake case spelling, and the bare name costs
/// nothing and guessing one of the three wrong loses the number in silence,
/// which is the failure this whole milestone exists to stop.
fn firstOf(object: std.json.ObjectMap, names: []const []const u8) ?std.json.Value {
    for (names) |name| {
        if (object.get(name)) |value| return value;
    }
    return null;
}

fn countOf(object: std.json.ObjectMap, names: []const []const u8) ?u64 {
    const value = firstOf(object, names) orelse return null;
    if (value != .integer or value.integer < 0) return null;
    return @intCast(value.integer);
}

fn textOf(object: std.json.ObjectMap, names: []const []const u8) ?[]const u8 {
    const value = firstOf(object, names) orelse return null;
    return if (value == .string) value.string else null;
}

/// Read the OpenAI compatible `usage` object, and ai&'s own cost and timing
/// metadata, out of one stream event. Null when the event carried neither, so
/// a caller can tell "the provider said nothing" apart from "the provider
/// said zero": see `message.Cost`, where those are different states.
///
/// Every string in the answer is a slice into `object`, which is the same
/// lifetime rule `Delta` already states.
fn openAiUsage(object: std.json.ObjectMap) ?message.Usage {
    var usage = message.Usage{};
    var said_anything = false;

    if (object.get("usage")) |usage_value| {
        if (usage_value == .object) {
            const counts = usage_value.object;
            said_anything = true;
            if (countOf(counts, &.{ "prompt_tokens", "input_tokens" })) |count| {
                usage.input_tokens = count;
            }
            if (countOf(counts, &.{ "completion_tokens", "output_tokens" })) |count| {
                usage.output_tokens = count;
            }
            // A cached prompt token is billed at a fraction of a fresh one,
            // so it is counted apart rather than folded into the input.
            if (counts.get("prompt_tokens_details")) |details| {
                if (details == .object) {
                    if (countOf(details.object, &.{"cached_tokens"})) |count| {
                        usage.cache_read_input_tokens = count;
                    }
                }
            }
        }
    }

    if (firstOf(object, &.{ "X-Cost", "x_cost", "cost" })) |cost_value| {
        const amount: ?f64 = switch (cost_value) {
            .float => |value| value,
            .integer => |value| @floatFromInt(value),
            .number_string => |text| std.fmt.parseFloat(f64, text) catch null,
            else => null,
        };
        if (amount) |value| {
            said_anything = true;
            usage.cost = .{ .known = .{
                .value = value,
                .currency = textOf(object, &.{ "X-Cost-Currency", "x_cost_currency", "cost_currency" }) orelse "",
            } };
        }
    }
    if (textOf(object, &.{ "X-Request-ID", "x_request_id", "request_id", "id" })) |text| {
        usage.request_id = text;
    }
    if (countOf(object, &.{ "X-Inference-Ms", "x_inference_ms", "inference_ms" })) |count| {
        said_anything = true;
        usage.inference_ms = count;
    }
    if (textOf(object, &.{ "X-Reasoning-Effort", "x_reasoning_effort", "reasoning_effort" })) |text| {
        said_anything = true;
        usage.reasoning_effort_applied = text;
    }

    return if (said_anything) usage else null;
}

/// One model turn, folded from a `Client.send` stream, and what it cost.
///
/// **A struct with the outcome inside it, and not the bare union it used to
/// be, because the cost is true in every case.** A refusal still burned input
/// tokens. A stream cut off partway still billed for what it generated.
/// Chock enforces a cap from what it counted, so a shape that could only
/// report usage on the happy path would under count
/// exactly the turns a user most wants counted.
pub const AssembledReply = struct {
    outcome: Outcome,
    /// The provider's own last word on why the turn stopped, or empty when it
    /// said none. Read it with `stopReason`.
    ///
    /// **A fixed buffer and not an owned slice**, because every caller of
    /// `sendAndAssemble` already has two ownership rules to keep, `freeUsage`
    /// and `freeAssembledMessage`, and a third one would be a third way to
    /// leak. The values on both wires are short tokens, and `max_stop_reason`
    /// gives the longest one this reader keeps.
    stop_reason_buffer: [max_stop_reason]u8 = @splat(0),
    /// How much of `stop_reason_buffer` the provider filled.
    stop_reason_len: usize = 0,
    /// What more the provider said about that reason, cut to
    /// `max_stop_category` and `max_stop_explanation`. Fixed buffers, for the
    /// same reason `stop_reason_buffer` is one: a third and a fourth owned
    /// slice here would be a third and a fourth way to leak. Read them with
    /// `stop`. Both stay empty on every wire except a refusal on the Anthropic
    /// one, and can stay empty there too: see `Stop`.
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    /// How much of `stop_category_buffer` the provider filled.
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    /// How much of `stop_explanation_buffer` the provider filled.
    stop_explanation_len: usize = 0,
    /// What the provider reported. `cost` is `unknown` when it reported
    /// nothing, which is a different fact from free: see `message.Cost`.
    /// Every string field is owned by the caller and freed with `freeUsage`.
    usage: message.Usage,

    pub const Outcome = union(enum) {
        message: message.Message,
        status_error: StatusError,
        /// The stream did not reach a clean end: `err` is why, the same value
        /// `Client.send` itself would have returned. `partial` is everything
        /// `on_delta` handed over before that happened, folded the same way
        /// `.message` is. A caller that only checked for a bare error, the way
        /// an earlier version of this function worked, threw every good delta
        /// that arrived first away with it. A review said it plainly: "the
        /// caller must be able to tell the two apart, and today it cannot,"
        /// about a provider emitting one malformed
        /// delta versus a broken connection, and "keep failing, and give the
        /// caller what was already assembled along with the error." `partial`
        /// is owned the same way `.message` is: free it with
        /// `freeAssembledMessage`.
        failed: struct { err: SendError, partial: message.Message },
    };

    /// Why the provider stopped this turn, in its own word, or empty when it
    /// said none. See `Delta.stop_reason`.
    pub fn stopReason(self: *const AssembledReply) []const u8 {
        return self.stop_reason_buffer[0..self.stop_reason_len];
    }

    /// Why the provider stopped this turn, in all the words it used, which is
    /// the reason `stopReason` gives plus whatever the provider said about it.
    /// See `Stop`, and read its doc comment before reporting an empty
    /// `category` or `explanation` as anything at all.
    pub fn stop(self: *const AssembledReply) Stop {
        return .{
            .reason = self.stopReason(),
            .category = self.stop_category_buffer[0..self.stop_category_len],
            .explanation = self.stop_explanation_buffer[0..self.stop_explanation_len],
        };
    }
};

/// The longest `stop_reason` this reader keeps. Every value either wire sends
/// is one short token, and the longest the Anthropic wire sends today is
/// `model_context_window_exceeded`, at 29 bytes. A longer one is cut to this
/// length rather than dropped: a cut word still names the provider's reason,
/// and an empty one names nothing at all.
pub const max_stop_reason: usize = 64;

/// The longest refusal category this reader keeps. Defined by the wire that
/// sends one: see `anthropic.max_stop_category`.
pub const max_stop_category: usize = anthropic.max_stop_category;

/// The longest refusal explanation this reader keeps. Defined by the wire that
/// sends one: see `anthropic.max_stop_explanation`, which says why prose gets
/// a bound of its own rather than sharing `max_stop_reason`.
pub const max_stop_explanation: usize = anthropic.max_stop_explanation;

/// Copy as much of `text` as `buffer` holds, and answer how much that was.
///
/// The twin of `anthropic.keepCut`, and deliberately not shared with it: an
/// adapter must not import this file, because that is a cycle, and neither
/// file has a utility module between them to hold four lines. Both wires cut
/// their own copy, so both need one.
fn keepCut(buffer: []u8, text: []const u8) usize {
    const kept = @min(text.len, buffer.len);
    @memcpy(buffer[0..kept], text[0..kept]);
    return kept;
}

/// Told about each delta as it arrives, on its way into the fold. See
/// `sendAndAssembleWatching`.
///
/// **It returns nothing, and it is not allowed to stop the call.** A watcher
/// is showing a person what the model is saying while it says it, and a
/// terminal that went away must not end a session that is doing real work.
/// That is the same rule `chock_core.Loop.Observer` keeps, for the same
/// reason, and it is why this is not an `OnDelta`: an `OnDelta` may fail, and
/// a failure there fails the whole stream.
///
/// `delta` is borrowed for the duration of the call, exactly as `Delta`'s own
/// doc comment says: a watcher that keeps the bytes copies them first.
pub const OnWatchedDelta = *const fn (ctx: ?*anyopaque, delta: Delta) void;

/// Somebody watching the stream go past. See `sendAndAssembleWatching`.
pub const Watcher = struct {
    ctx: ?*anyopaque = null,
    on_delta: OnWatchedDelta,
};

/// `sendAndAssembleWatching` with nobody watching. See that function: the
/// finished reply is identical either way, and this is the call for a caller
/// that only wants it.
pub fn sendAndAssemble(
    c: Client,
    allocator: std.mem.Allocator,
    request: message.Request,
) SendError!AssembledReply {
    return sendAndAssembleWatching(c, allocator, request, null);
}

/// Send `request` through `c` and fold the resulting deltas into one
/// `message.Message`: every content and reasoning delta concatenated in
/// order, every tool call fragment assembled by index, exactly the way
/// `sse.zig`'s own tests already prove `sse.ToolCallAssembler` does it. Built
/// here, once, instead of leaving every caller to re-implement the same
/// fold: the agent loop appends the result to the session log.
///
/// **`watcher` sees each delta at the moment it arrives, and the fold happens
/// anyway.** `send` already streams: it hands over every piece as soon as one
/// read of the connection produces it. Before this parameter existed, a caller
/// that wanted the finished message had no way to see that stream at all, so a
/// model that spent five minutes writing was five minutes of an empty
/// terminal. Watching costs the caller nothing: the same deltas go into the
/// same fold and the returned reply is byte for byte what it always was.
///
/// A stream that fails partway through does not throw away what already
/// arrived: see `AssembledReply.failed`. The one exception is
/// `error.OutOfMemory` raised while folding the partial reply itself, which
/// still reaches the caller as a bare error, because at that point there is
/// nothing left to trust with building even a partial message to hand back.
///
/// On `.message` or `.failed`, the caller owns `content` and everything it
/// points to: free it with `freeAssembledMessage`. On `.status_error`, free
/// `body` with `allocator`. In every case free `usage` with `freeUsage`.
pub fn sendAndAssembleWatching(
    c: Client,
    allocator: std.mem.Allocator,
    request: message.Request,
    watcher: ?Watcher,
) SendError!AssembledReply {
    var collector = Collector.init(allocator);
    collector.watcher = watcher;
    defer collector.deinit();

    const result = c.send(allocator, request, Collector.onDelta, &collector) catch |err| {
        return collector.reply(.{ .failed = .{ .err = err, .partial = try collector.toMessage() } });
    };
    switch (result) {
        .status_error => |status_error| return collector.reply(.{ .status_error = status_error }),
        .ok => {},
    }
    // Collector.onDelta cannot propagate a ToolCallAssembler.Error itself:
    // see OnDeltaError's own doc comment. Check what it recorded instead,
    // now that send has finished calling it.
    if (collector.err) |err| {
        return collector.reply(.{ .failed = .{ .err = err, .partial = try collector.toMessage() } });
    }
    return collector.reply(.{ .message = try collector.toMessage() });
}

/// Frees a `message.Usage` that `sendAndAssemble` produced. **Only one that
/// `sendAndAssemble` produced**: a usage read back out of a session log owns
/// its strings through the `std.json.Parsed` value it came from, and freeing
/// those here would free memory twice.
///
/// A field the provider never set is an empty slice with no allocation
/// behind it, so it is skipped rather than freed.
pub fn freeUsage(allocator: std.mem.Allocator, usage: message.Usage) void {
    if (usage.cost == .known and usage.cost.known.currency.len != 0) {
        allocator.free(usage.cost.known.currency);
    }
    if (usage.request_id.len != 0) allocator.free(usage.request_id);
    if (usage.reasoning_effort_applied.len != 0) allocator.free(usage.reasoning_effort_applied);
    if (usage.model.len != 0) allocator.free(usage.model);
}

/// Frees a `message.Message` built by `sendAndAssemble`, either its
/// `.message` or its `.failed.partial`. Not interchangeable with freeing a
/// message `openai.toMessage` or a session log read produced: this only
/// ever holds `.text`, `.reasoning`, and `.tool_use` parts, because those
/// are the only parts a model's own streamed reply can carry.
///
/// A `.tool_result` or `.unknown` part reaching here means this was handed a
/// message `Collector.toMessage` never built, a caller's own bug: this
/// panics rather than reaching `unreachable`, so a caller that makes this
/// mistake gets a clear, safe crash naming exactly what went wrong in every
/// build mode, not undefined behavior in a release one.
pub fn freeAssembledMessage(allocator: std.mem.Allocator, msg: message.Message) void {
    for (msg.content) |part| {
        switch (part) {
            .text => |text| allocator.free(text),
            .reasoning => |reasoning| {
                allocator.free(reasoning.text);
                allocator.free(reasoning.signature);
            },
            .tool_use => |tool_use| {
                allocator.free(tool_use.call_id);
                allocator.free(tool_use.tool);
                allocator.free(tool_use.arguments);
            },
            .tool_result, .unknown => std.debug.panic(
                "freeAssembledMessage received a .{s} content part; sendAndAssemble never builds one",
                .{@tagName(part)},
            ),
        }
    }
    allocator.free(msg.content);
}

/// Folds an `on_delta` stream into one message. See `sendAndAssemble`.
const Collector = struct {
    allocator: std.mem.Allocator,
    text: std.ArrayList(u8) = .empty,
    reasoning: std.ArrayList(u8) = .empty,
    assembler: sse.ToolCallAssembler,
    /// The order text, reasoning, and each distinct tool call index were
    /// first seen in the stream. `toMessage` walks this to put the finished
    /// content parts back in the order the model actually sent them,
    /// instead of the fixed text-then-reasoning-then-tool-calls order an
    /// earlier version of this type always used. A real capture had the model
    /// reason before it answered, and the old, fixed order inverted the two, a
    /// permanent
    /// loss once `chockd` re-serves the session. Text and reasoning each
    /// appear here at most once, recorded the moment their running buffer
    /// goes from empty to non-empty. A tool call index appears here once,
    /// recorded on its first fragment.
    order: std.ArrayList(Kind) = .empty,
    /// Which distinct tool call indices already have an entry in `order`,
    /// so a call's later fragments do not add a second one.
    seen_tool_indices: std.AutoArrayHashMapUnmanaged(usize, void) = .empty,
    /// The signature of the reasoning block, assembled from however many
    /// `signature_delta` events carried it. Kept apart from `reasoning` so
    /// nothing has to parse it back out of prose later, which is what makes a
    /// byte for byte round trip possible: see `openai.WireMessage.reasoning_signature`
    /// for the same argument on the other wire.
    reasoning_signature: std.ArrayList(u8) = .empty,
    /// The last usage the stream reported, **never the sum of them**: the
    /// counts on both wires are cumulative, so adding them over counts. Every
    /// string in it is a copy this collector owns until `takeUsage` hands it
    /// to the caller.
    usage: message.Usage = .{},
    /// Whether any usage delta arrived at all. Without this a provider that
    /// reports nothing is indistinguishable from one that reports zero, and
    /// those are different facts.
    saw_usage: bool = false,
    /// Set when `assembler.feed` fails. See `OnDeltaError`'s doc comment on
    /// why `onDelta` cannot return this itself.
    err: ?sse.ToolCallAssembler.Error = null,
    /// The last stop reason the stream carried, cut to `max_stop_reason`. A
    /// buffer and not an owned slice for the reason
    /// `AssembledReply.stop_reason_buffer` gives.
    stop_reason_buffer: [max_stop_reason]u8 = @splat(0),
    /// How much of `stop_reason_buffer` is in use.
    stop_reason_len: usize = 0,
    /// What the stream said about that stop reason, cut to
    /// `max_stop_category` and `max_stop_explanation`. Buffers and not owned
    /// slices for the reason `AssembledReply.stop_category_buffer` gives.
    stop_category_buffer: [max_stop_category]u8 = @splat(0),
    /// How much of `stop_category_buffer` is in use.
    stop_category_len: usize = 0,
    stop_explanation_buffer: [max_stop_explanation]u8 = @splat(0),
    /// How much of `stop_explanation_buffer` is in use.
    stop_explanation_len: usize = 0,
    /// Told about each delta before it is folded. Null for a caller that only
    /// wants the finished message. See `sendAndAssembleWatching`.
    watcher: ?Watcher = null,

    const Kind = union(enum) {
        text,
        reasoning,
        tool_call: usize,
    };

    fn init(allocator: std.mem.Allocator) Collector {
        return .{ .allocator = allocator, .assembler = sse.ToolCallAssembler.init(allocator) };
    }

    fn deinit(self: *Collector) void {
        self.text.deinit(self.allocator);
        self.reasoning.deinit(self.allocator);
        self.reasoning_signature.deinit(self.allocator);
        self.order.deinit(self.allocator);
        self.seen_tool_indices.deinit(self.allocator);
        self.assembler.deinit();
        freeUsage(self.allocator, self.usage);
    }

    /// Build the finished reply around `outcome`, and hand over the usage and
    /// the stop reason with it.
    ///
    /// **Every return of `sendAndAssembleWatching` goes through here.** Three
    /// of the four used to build the struct by hand, so a field added to
    /// `AssembledReply` would have been filled on some paths and defaulted on
    /// others, and a stop reason that only survived the happy path is exactly
    /// the loss this field exists to stop.
    fn reply(self: *Collector, outcome: AssembledReply.Outcome) std.mem.Allocator.Error!AssembledReply {
        return .{
            .outcome = outcome,
            .usage = try self.takeUsage(),
            .stop_reason_buffer = self.stop_reason_buffer,
            .stop_reason_len = self.stop_reason_len,
            .stop_category_buffer = self.stop_category_buffer,
            .stop_category_len = self.stop_category_len,
            .stop_explanation_buffer = self.stop_explanation_buffer,
            .stop_explanation_len = self.stop_explanation_len,
        };
    }

    /// Hand the collected usage to the caller, and stop owning it. Called
    /// once, at the end of `sendAndAssemble`, so `deinit` afterwards frees
    /// nothing twice.
    fn takeUsage(self: *Collector) std.mem.Allocator.Error!message.Usage {
        const usage = self.usage;
        self.usage = .{};
        return usage;
    }

    /// Copy the strings of an incoming usage delta, which are only valid for
    /// the duration of the callback, and drop whatever the previous one held.
    fn replaceUsage(self: *Collector, incoming: message.Usage) OnDeltaError!void {
        var copy = incoming;
        copy.request_id = if (incoming.request_id.len == 0)
            ""
        else
            try self.allocator.dupe(u8, incoming.request_id);
        errdefer if (copy.request_id.len != 0) self.allocator.free(copy.request_id);

        copy.reasoning_effort_applied = if (incoming.reasoning_effort_applied.len == 0)
            ""
        else
            try self.allocator.dupe(u8, incoming.reasoning_effort_applied);
        errdefer if (copy.reasoning_effort_applied.len != 0) {
            self.allocator.free(copy.reasoning_effort_applied);
        };

        copy.model = if (incoming.model.len == 0) "" else try self.allocator.dupe(u8, incoming.model);
        errdefer if (copy.model.len != 0) self.allocator.free(copy.model);

        if (incoming.cost == .known and incoming.cost.known.currency.len != 0) {
            copy.cost = .{ .known = .{
                .value = incoming.cost.known.value,
                .currency = try self.allocator.dupe(u8, incoming.cost.known.currency),
            } };
        }

        freeUsage(self.allocator, self.usage);
        self.usage = copy;
        self.saw_usage = true;
    }

    fn onDelta(ctx: ?*anyopaque, delta: Delta) OnDeltaError!void {
        const self: *Collector = @ptrCast(@alignCast(ctx.?));
        // **Before the fold, not after it.** The whole value of watching is
        // that the piece is handed on at the moment it arrived, and a fold
        // that ran first would only delay it. The watcher cannot fail and
        // cannot refuse, so nothing about the fold below depends on what it
        // did: see `OnWatchedDelta`.
        if (self.watcher) |watching| watching.on_delta(watching.ctx, delta);
        switch (delta) {
            .text => |text| {
                if (self.text.items.len == 0) try self.order.append(self.allocator, .text);
                try self.text.appendSlice(self.allocator, text);
            },
            .reasoning => |text| {
                if (self.reasoning.items.len == 0) try self.order.append(self.allocator, .reasoning);
                try self.reasoning.appendSlice(self.allocator, text);
            },
            .reasoning_signature => |text| {
                // A signature with no reasoning text yet still belongs to the
                // reasoning part, so the part is ordered here too: a stream
                // that sent the signature first would otherwise lose it.
                if (self.reasoning.items.len == 0 and self.reasoning_signature.items.len == 0) {
                    try self.order.append(self.allocator, .reasoning);
                }
                try self.reasoning_signature.appendSlice(self.allocator, text);
            },
            // **Replace, never add.** See the field's own doc comment.
            .usage => |usage| try self.replaceUsage(usage),
            // The last word wins, the same way the last usage does: a wire
            // that revises its own stop reason means the later one.
            // All three parts of it, every time, because they describe one
            // stop: keeping a refusal's explanation beside the reason that
            // replaced it would report the wrong reason for the wrong word.
            // See `Stop`.
            .stop_reason => |stopped| {
                self.stop_reason_len = keepCut(&self.stop_reason_buffer, stopped.reason);
                self.stop_category_len = keepCut(&self.stop_category_buffer, stopped.category);
                self.stop_explanation_len = keepCut(
                    &self.stop_explanation_buffer,
                    stopped.explanation,
                );
            },
            .tool_call => |fragment| {
                if (!self.seen_tool_indices.contains(fragment.index)) {
                    try self.seen_tool_indices.put(self.allocator, fragment.index, {});
                    try self.order.append(self.allocator, .{ .tool_call = fragment.index });
                }
                self.assembler.feed(fragment) catch |err| {
                    self.err = err;
                };
            },
        }
    }

    fn findCall(calls: []const sse.ToolCall, index: usize) ?sse.ToolCall {
        for (calls) |call| {
            if (call.index == index) return call;
        }
        return null;
    }

    fn toMessage(self: *Collector) std.mem.Allocator.Error!message.Message {
        var parts: std.ArrayList(message.ContentPart) = .empty;
        errdefer parts.deinit(self.allocator);

        const calls = try self.assembler.finished();
        defer sse.freeFinished(self.allocator, calls);

        // order holds `.text` and `.reasoning` at most once each, and each
        // tool call index at most once: see the field's own doc comment.
        // toOwnedSlice is safe to call unconditionally in the loop body
        // below because of that guarantee, and because toMessage itself is
        // only ever called once per Collector.
        for (self.order.items) |kind| {
            switch (kind) {
                .text => try parts.append(self.allocator, .{ .text = try self.text.toOwnedSlice(self.allocator) }),
                .reasoning => try parts.append(self.allocator, .{
                    .reasoning = .{
                        .text = try self.reasoning.toOwnedSlice(self.allocator),
                        // Byte for byte what the stream carried. The OpenAI
                        // compatible wire sends none and this stays empty there.
                        .signature = try self.reasoning_signature.toOwnedSlice(self.allocator),
                    },
                }),
                .tool_call => |index| {
                    const call = findCall(calls, index) orelse continue;
                    // An orphan fragment, id and name never seen, has
                    // nothing sensible to dispatch: see
                    // sse.ToolCall.complete's own doc comment. Skipping it
                    // here is the same call sse.zig's own tests make about
                    // what "complete" means.
                    if (!call.complete) continue;
                    try parts.append(self.allocator, .{ .tool_use = .{
                        .call_id = try self.allocator.dupe(u8, call.id),
                        .tool = try self.allocator.dupe(u8, call.name),
                        .arguments = try self.allocator.dupe(u8, call.arguments),
                    } });
                },
            }
        }

        return .{
            .role = .assistant,
            .content = try parts.toOwnedSlice(self.allocator),
            .model_alias = "",
        };
    }
};

// This file's own tests live in `test/core/client.zig`, not here: they need
// `test/core/fake_provider.zig`, a real socket server, and Zig 0.16 refuses
// a relative `@import` that reaches outside this file's own module. See that
// file's top comment.
