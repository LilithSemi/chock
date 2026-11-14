//! Service OIDC transport using the operating system's configured trust roots.
//!
//! Identity providers are commonly installed behind an organization's
//! private CA. The machine's trust store is the operator-controlled boundary
//! for the service, so discovery, token exchange, and JWKS fetches use it.

const std = @import("std");
const zurl = @import("zurl");
const oauth = @import("oauth-core");

const Allocator = std.mem.Allocator;

pub const Transport = @This();

io: std.Io,
ca_file: ?[]const u8 = null,
max_response_bytes: usize = 1024 * 1024,

pub fn init(io: std.Io, ca_file: ?[]const u8) Transport {
    return .{ .io = io, .ca_file = ca_file };
}

pub fn transport(self: *Transport) oauth.Transport {
    return .{ .ptr = self, .vtable = &.{ .send = send } };
}

fn send(ptr: *anyopaque, gpa: Allocator, request: oauth.Request) oauth.SendError!oauth.Response {
    const self: *Transport = @ptrCast(@alignCast(ptr));
    var client: zurl.Client = .init(gpa, self.io);
    defer client.deinit();
    var memory: zurl.request_body.Memory = .{
        .bytes = request.body orelse "",
        .content_type = request.content_type,
    };
    const response = client.perform(request.url, .{
        .method = request.method,
        .body = if (request.body != null) memory.source() else null,
        .headers = request.headers,
        .redirects = .unfollowed,
        .accept_encoding = false,
        .user_agent = "Chock service",
        .ca = .{ .ssl_cert_file = self.ca_file, .ca_native = true },
    }, null) catch |err| return mapError(err);

    const head = try gpa.dupe(u8, response.final_headers orelse "");
    errdefer gpa.free(head);
    const scratch = try gpa.alloc(u8, self.max_response_bytes + 1);
    defer {
        std.crypto.secureZero(u8, scratch);
        gpa.free(scratch);
    }
    const len = response.body.readSliceShort(scratch) catch |err| return switch (err) {
        error.ReadFailed => mapError(client.resolveBodyError(null)),
    };
    if (len > self.max_response_bytes) return error.ResponseTooLarge;
    const body = try gpa.dupe(u8, scratch[0..len]);
    return .{ .status = response.status, .head = head, .body = body };
}

fn mapError(err: zurl.Error) oauth.SendError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.PeerFailedVerification, error.SslInvalidCertStatus => error.CertificateInvalid,
        error.CaCertBadFile => error.TrustStoreMissing,
        else => error.TransportFailed,
    };
}
