//! Chock's durable-log adapter around the package-owned provider clients.

const provider = @import("llm-provider");

pub const failure = provider.failure;
pub const retry = provider.retry;
pub const message = provider.message;
pub const anthropic = provider.anthropic;
pub const openai = provider.openai;
pub const responses = provider.responses;
pub const sse = provider.sse;
pub const Client = provider.Client;

pub const proto = @import("chock-provider/proto.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
