//! What a provider's refusal means, read from the status and the body.
//!
//! **Two faults look the same at the call site and want opposite answers.**
//! A 429 or a 503 is a transport fault: the request was good and the provider
//! could not take it now, so the answer is to wait and send the same request
//! again. A context overflow is not a fault at all in that sense: the request
//! was too large, sending it again cannot work, and the answer is to make the
//! context smaller and take the turn again. See
//! `lib/chock-core/compaction.zig`.
//!
//! Before this file, `chock_core.Loop` read every non-2xx status the same way
//! and ended the session. A session measured on 2026-08-21 died on
//! `request (77857 tokens) exceeds the available context size (65536 tokens)`
//! with a full log of work that nothing was wrong with.
//!
//! ## Why the body, and not the status alone
//!
//! Every provider this library speaks to reports a context overflow as a 400,
//! which is also the status for a malformed request, an unknown model, and a
//! bad parameter. The status alone therefore cannot separate a request that is
//! too large from a request that is wrong, and treating every 400 as an
//! overflow would compact a session that has a real fault and then send the
//! same broken request again.
//!
//! So the body decides, and each phrase below is one provider's own wording,
//! named in the comment beside it. **A phrase this table does not hold reads
//! as `permanent`**, which keeps the old behaviour of ending the session: an
//! overflow Chock cannot recognize is a session that stops with its log
//! intact, never a session that compacts in a circle.

const std = @import("std");

/// What kind of refusal this is. **Four members and no boolean**: a caller
/// must name the case it handles, and a new member later is a compile error at
/// every switch rather than a wrong branch nobody looks at.
pub const Class = enum {
    /// The request carried more tokens than the model can hold. Compact and
    /// take the turn again. Sending the same request cannot work.
    context_overflow,
    /// The provider is rate limiting this credential. Wait, then send the
    /// same request again.
    rate_limited,
    /// The provider could not answer this time, and it may answer the next
    /// one: a 5xx, or a timeout the provider itself reports. Send the same
    /// request again after a wait.
    transient,
    /// Sending this request again cannot help. A bad model name, a refused
    /// credential, a malformed body.
    permanent,
};

/// The phrases that mean a context overflow, each one a real provider's own
/// wording. Matched case insensitively as a substring of the response body.
///
/// **Keep this list to phrases somebody has actually seen.** A guess that is
/// too wide turns a real fault into a compaction loop, which is worse than a
/// session that ends and says why.
const overflow_phrases = [_][]const u8{
    // llama.cpp, and the swap server this project develops against. The
    // measured line was: request (77857 tokens) exceeds the available
    // context size (65536 tokens).
    "exceed_context_size_error",
    "exceeds the available context size",
    // OpenAI, and every endpoint that copies its error shape.
    "context_length_exceeded",
    "maximum context length",
    // Anthropic: prompt is too long: 219418 tokens > 200000 maximum.
    "prompt is too long",
    // ai&, and several OpenAI compatible servers, word it around the window.
    "context window",
    // vLLM and text-generation-inference.
    "reduce the length of the messages",
    "input is too long",
};

/// The phrases that mean the provider is overloaded. **These matter because
/// the status cannot always say it.** The Anthropic wire puts an
/// `overloaded_error` inside a stream whose status was 200 and stayed 200, so
/// `chock_provider.Client.StatusError.status` reads 200 for a fault that would
/// have been a 529 in a call that did not stream. Without this list that fault
/// reads as `permanent` and the session ends on something a second attempt
/// would have answered.
const transient_phrases = [_][]const u8{
    "overloaded_error",
    "overloaded",
    "server_error",
    "try again later",
};

/// Read one refusal. `body` is the response body exactly as it arrived.
///
/// A status this reader has no rule for is `permanent`, which is the safe
/// direction: a session that ends with its log intact costs the user a
/// restart, and a session that retries a request nothing can accept costs
/// them every turn until something else stops it.
pub fn classify(status: std.http.Status, body: []const u8) Class {
    // A rate limit first, because ai& and Anthropic both send a 429 with a
    // body that says a great deal about tokens, and a "tokens per minute"
    // limit must never read as a context overflow. The two are the pair this
    // whole file exists to keep apart.
    if (status == .too_many_requests) return .rate_limited;

    const code = @intFromEnum(status);
    if (code >= 500) return .transient;
    if (status == .request_timeout) return .transient;

    // The overflow phrases are read first. They are specific sentences about
    // the size of one request, while the overload phrases are general words a
    // provider can put in any message, so a body that holds both is about the
    // request and not about the server.
    if (holdsAny(body, &overflow_phrases)) return .context_overflow;
    if (holdsAny(body, &transient_phrases)) return .transient;
    return .permanent;
}

/// True when `body` holds any of `phrases`.
fn holdsAny(body: []const u8, phrases: []const []const u8) bool {
    for (phrases) |phrase| {
        if (containsIgnoreCase(body, phrase)) return true;
    }
    return false;
}

/// A case insensitive substring search over ASCII. The phrases are ASCII and
/// so is every provider error body this library has read, so a fold that
/// handles only ASCII is the whole of the job here.
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var start: usize = 0;
    while (start + needle.len <= haystack.len) : (start += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
    }
    return false;
}

const testing = std.testing;

test "the measured llama.cpp overflow reads as a context overflow and not as a fault" {
    // The exact body that ended a real session on 2026-08-21. See this
    // file's own top comment.
    const body =
        \\{"error":{"code":400,"message":"request (77857 tokens) exceeds the available
        \\context size (65536 tokens)","type":"exceed_context_size_error"}}
    ;
    try testing.expectEqual(Class.context_overflow, classify(.bad_request, body));
}

test "each provider's own wording for a full context reads as a context overflow" {
    const bodies = [_][]const u8{
        \\{"error":{"message":"This model's maximum context length is 128000 tokens","code":"context_length_exceeded"}}
        ,
        \\{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 219418 tokens > 200000 maximum"}}
        ,
        \\{"error":{"message":"the request exceeds the context window for this model"}}
        ,
        \\{"error":{"message":"This model's maximum context length is 8192 tokens. Please reduce the length of the messages."}}
        ,
    };
    for (bodies) |body| {
        try testing.expectEqual(Class.context_overflow, classify(.bad_request, body));
    }
}

test "a rate limit is never a context overflow, however much it says about tokens" {
    // **The fault this file exists to prevent.** A 429 body names token
    // limits, so a reader that only looked for the word "tokens" would
    // compact a session that had nothing wrong with its context, throw away
    // the turns it folded, and send the same request into the same rate
    // limit.
    const body =
        \\{"error":{"message":"Rate limit reached for gpt-4 in organization org-x on tokens per min (TPM): Limit 10000, Used 9999","type":"tokens"}}
    ;
    try testing.expectEqual(Class.rate_limited, classify(.too_many_requests, body));
}

test "a 429 whose body happens to hold an overflow phrase is still a rate limit" {
    // The status decides for a 429, because a provider that is rate limiting
    // cannot also be reporting the size of a request it never read.
    const body = "slow down: prompt is too long is not why";
    try testing.expectEqual(Class.rate_limited, classify(.too_many_requests, body));
}

test "a server fault is transient and a bad model name is permanent" {
    try testing.expectEqual(Class.transient, classify(.internal_server_error, "upstream died"));
    try testing.expectEqual(Class.transient, classify(.service_unavailable, ""));
    try testing.expectEqual(Class.transient, classify(.request_timeout, ""));

    const unknown_model =
        \\{"error":{"message":"The model `gpt-9` does not exist","code":"model_not_found"}}
    ;
    try testing.expectEqual(Class.permanent, classify(.bad_request, unknown_model));
    try testing.expectEqual(Class.permanent, classify(.unauthorized, "bad key"));
}

test "an overloaded error inside a stream whose status stayed 200 is still transient" {
    // The Anthropic wire can carry a fault the status never reports: see
    // `chock_provider.Client.StatusError`, whose `status` says 200 when that
    // is the truth. A reader that only looked at the status would call this
    // permanent and end a session a second attempt would have finished.
    const body =
        \\{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}
    ;
    try testing.expectEqual(Class.transient, classify(.ok, body));
}

test "an overflow phrase is found whatever case the provider wrote it in" {
    try testing.expectEqual(
        Class.context_overflow,
        classify(.bad_request, "Prompt Is Too Long: 10 > 5"),
    );
    try testing.expectEqual(Class.permanent, classify(.bad_request, ""));
}
