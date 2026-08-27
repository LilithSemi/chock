//! The check before storing. A provider with a model catalogue, such as ai&'s
//! `/v1/models`, gives a cheap call that proves the key works. A user who
//! mistypes a key learns at login and not on their first turn. Chock stores
//! the key only after the check passes, and says which provider answered.
//!
//! **This library reaches a provider and no other one does.** It talks HTTP
//! through `std.http.Client` directly rather than through
//! `chock-provider`, because a model catalogue is not a chat completion and
//! nothing in the adapters describes one. That keeps `chock-auth` free of
//! every other Chock library, which is what lets `chock login` run before a
//! session, a workspace, or a sandbox exists.
//!
//! **The credential is in a header and never in a URL.** A URL reaches a
//! proxy log, a redirect target, and a provider's own access log. The same
//! rule `lib/chock-provider/Client.zig` already keeps for a request body.

const std = @import("std");
const config = @import("config.zig");

/// The largest answer this reader keeps. A model catalogue is a small
/// document and a refusal is a sentence. This bounds a provider that answers
/// with something else entirely.
pub const max_body_bytes: usize = 1024 * 1024;

/// What this reader puts in `Accept-Encoding`. **The bytes as they are.**
///
/// `std.http.Client` offers `gzip, deflate` by itself unless the caller
/// overrides this header, and `Response.reader` gives back exactly what
/// arrived: only `Response.readerDecompressing` unpacks it. So a provider
/// that takes the offer leaves this file counting models in compressed bytes,
/// which reads as a catalogue it cannot count, and printing a refusal that is
/// not text. The same fault, measured against the same endpoint, made every
/// live Anthropic session end as a truncated stream: see
/// `lib/chock-provider/Client.zig`'s own `identity_encoding`.
///
/// Asked for rather than merely not asked for: a request with no
/// `Accept-Encoding` at all leaves every coding acceptable, per RFC 9110.
const identity_encoding = "identity";

/// What the provider said.
pub const Outcome = union(enum) {
    ok: Ok,
    /// The provider answered and refused. The credential is wrong, or it is
    /// not allowed to read a catalogue.
    rejected: Rejected,
    /// The provider was not reached at all: a refused connection, a name
    /// that does not resolve, a TLS failure. The value is the name of the
    /// underlying fault. **This is not proof that the credential is wrong**,
    /// so a caller says so rather than blaming the key.
    not_reached: []const u8,

    pub fn deinit(self: *Outcome, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .rejected => |rejected| gpa.free(rejected.body),
            .ok, .not_reached => {},
        }
        self.* = undefined;
    }
};

pub const Ok = struct {
    /// How many models the catalogue listed, or null when the answer did not
    /// have a shape this reader could count. Null is never a zero: section
    /// 10.1.3's rule that an absent answer is never a permissive answer, and
    /// never a number either.
    model_count: ?usize,
};

pub const Rejected = struct {
    status: std.http.Status,
    /// Whatever the provider said, capped at `max_body_bytes`. A provider
    /// spends real words explaining a refusal and throwing them away wastes
    /// them. Owned by the caller.
    body: []u8,
};

pub const Error = std.mem.Allocator.Error;

/// Ask `base_url`'s model catalogue whether `token` works.
///
/// An empty `token` sends no credential at all, which is the case a local
/// llama.cpp server needs: see `lib/chock-auth/lookup.zig`.
pub fn credential(
    gpa: std.mem.Allocator,
    io: std.Io,
    kind: config.Kind,
    base_url: []const u8,
    token: []const u8,
) Error!Outcome {
    const url = try std.fmt.allocPrint(gpa, "{s}/models", .{base_url});
    defer gpa.free(url);
    const uri = std.Uri.parse(url) catch |err| return .{ .not_reached = @errorName(err) };

    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    defer http.deinit();

    // Built once, wiped before it is freed. A credential sitting freed but
    // unzeroed in the heap is still readable in a crash dump or a swapped
    // page: the same care `lib/chock-provider/Client.zig` takes.
    const header_value = try switch (kind) {
        .anthropic => gpa.dupe(u8, token),
        .aiand, .openai_compat => std.fmt.allocPrint(gpa, "Bearer {s}", .{token}),
    };
    defer {
        std.crypto.secureZero(u8, header_value);
        gpa.free(header_value);
    }

    // Anthropic reads `x-api-key` and requires its own version header.
    // Everything OpenAI compatible reads `Authorization`.
    var extra: [2]std.http.Header = undefined;
    var extra_count: usize = 0;
    var authorization: std.http.Client.Request.Headers.Value = .omit;
    switch (kind) {
        .anthropic => {
            extra[0] = .{ .name = "anthropic-version", .value = "2023-06-01" };
            extra_count = 1;
            if (token.len != 0) {
                extra[1] = .{ .name = "x-api-key", .value = header_value };
                extra_count = 2;
            }
        },
        .aiand, .openai_compat => {
            if (token.len != 0) authorization = .{ .override = header_value };
        },
    }

    var request = http.request(.GET, uri, .{
        .keep_alive = false,
        // The same refusal `lib/chock-provider/Client.zig` makes: a provider
        // that answers a catalogue with a redirect is not one to follow
        // blindly, and a redirect carries the credential to wherever it
        // points.
        .redirect_behavior = .not_allowed,
        .headers = .{
            .authorization = authorization,
            // **The bytes as they are.** See `identity_encoding`.
            .accept_encoding = .{ .override = identity_encoding },
        },
        .extra_headers = extra[0..extra_count],
    }) catch |err| return .{ .not_reached = @errorName(err) };
    defer request.deinit();

    request.sendBodiless() catch |err| return .{ .not_reached = @errorName(err) };

    var redirect_buffer: [4 * 1024]u8 = undefined;
    var response = request.receiveHead(&redirect_buffer) catch |err| return .{ .not_reached = @errorName(err) };

    var transfer_buffer: [4 * 1024]u8 = undefined;
    const body_reader = response.reader(&transfer_buffer);
    const body = body_reader.allocRemaining(gpa, .limited(max_body_bytes)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => try std.fmt.allocPrint(gpa, "[the answer could not be read: {s}]", .{@errorName(err)}),
    };

    if (response.head.status.class() != .success) {
        return .{ .rejected = .{ .status = response.head.status, .body = body } };
    }
    defer gpa.free(body);
    return .{ .ok = .{ .model_count = countModels(gpa, body) } };
}

/// How many entries the catalogue's own `data` array holds, or null when the
/// answer did not have that shape. Every OpenAI compatible catalogue uses
/// `data`, and so does a local llama.cpp server. An answer this reader cannot
/// count is still an answer that accepted the credential, which is the fact
/// the caller asked about.
fn countModels(gpa: std.mem.Allocator, body: []const u8) ?usize {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const data = parsed.value.object.get("data") orelse return null;
    if (data != .array) return null;
    return data.array.items.len;
}

const testing = std.testing;

test "a catalogue with a data array is counted, and one without is null rather than zero" {
    const gpa = testing.allocator;
    try testing.expectEqual(@as(?usize, 2), countModels(gpa,
        \\{"object":"list","data":[{"id":"a"},{"id":"b"}]}
    ));
    try testing.expectEqual(@as(?usize, 0), countModels(gpa,
        \\{"object":"list","data":[]}
    ));
    try testing.expectEqual(@as(?usize, null), countModels(gpa,
        \\{"object":"list"}
    ));
    try testing.expectEqual(@as(?usize, null), countModels(gpa, "not json at all"));
    try testing.expectEqual(@as(?usize, null), countModels(gpa,
        \\{"data":"a string, not a list"}
    ));
}

test "a provider that cannot be reached is not reported as a wrong credential" {
    // The two are different facts and a user acts on them differently. A
    // port nothing listens on gives the first one.
    const gpa = testing.allocator;
    var outcome = try credential(gpa, testing.io, .openai_compat, "http://127.0.0.1:1/v1", "sk-not-a-real-key");
    defer outcome.deinit(gpa);
    try testing.expectEqual(std.meta.activeTag(outcome), Outcome.not_reached);
}

test {
    testing.refAllDecls(@This());
}
