//! What a provider's refusal means, read from the status and the body.

const std = @import("std");

pub const Class = enum {
    context_overflow,
    rate_limited,
    transient,
    permanent,
};

const overflow_phrases = [_][]const u8{
    "exceed_context_size_error",
    "exceeds the available context size",
    "context_length_exceeded",
    "maximum context length",
    "prompt is too long",
    "context window",
    "reduce the length of the messages",
    "input is too long",
};

const transient_phrases = [_][]const u8{
    "overloaded_error",
    "overloaded",
    "server_error",
    "try again later",
};

pub fn classify(status: std.http.Status, body: []const u8) Class {
    // A rate limit is checked first: ai& and Anthropic both send a 429 with a body that says a great deal about tokens, and a tokens per minute limit must never read as a context overflow.
    if (status == .too_many_requests) return .rate_limited;

    const code = @intFromEnum(status);
    if (code >= 500) return .transient;
    if (status == .request_timeout) return .transient;

    // The overflow phrases are read before the overload phrases: they are specific sentences about the size of one request, while the overload phrases are general words a provider can put in any message.
    if (holdsAny(body, &overflow_phrases)) return .context_overflow;
    if (holdsAny(body, &transient_phrases)) return .transient;
    return .permanent;
}

fn holdsAny(body: []const u8, phrases: []const []const u8) bool {
    for (phrases) |phrase| {
        if (containsIgnoreCase(body, phrase)) return true;
    }
    return false;
}

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
    const body =
        \\{"error":{"message":"Rate limit reached for gpt-4 in organization org-x on tokens per min (TPM): Limit 10000, Used 9999","type":"tokens"}}
    ;
    try testing.expectEqual(Class.rate_limited, classify(.too_many_requests, body));
}

test "a 429 whose body happens to hold an overflow phrase is still a rate limit" {
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
