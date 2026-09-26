//! The Agent Client Protocol, from the agent's side.
//!
//! An editor launches Chock as a subprocess and drives it over standard input
//! and output. This library is the wire: the JSON-RPC envelope, the framing, and
//! version 1's method table. It holds no session, runs no loop and reads no
//! policy, so the command that wires it to Chock decides all of that.
//!
//! See <https://agentclientprotocol.com>, and Forgejo issue 1 for what Chock
//! is answering it with.
//!
//! ## Two files, because there are two questions
//!
//! * `jsonrpc.zig` is the envelope and the framing. It knows nothing about ACP
//!   beyond the error codes ACP adds, so a second protocol version reuses it
//!   whole.
//! * `v1.zig` is version 1: which methods exist, which side answers each, and
//!   what its enums spell on the wire.
//!
//! ## What was read to build this
//!
//! The schema at `schema/v1/schema.json`, not the documentation site. The two
//! disagree in three places that matter, and the schema is what a client is
//! built from:
//!
//! * The site lists `session/update` under the client's methods and also says
//!   the agent sends it. The schema tags it `x-side: client`, meaning the client
//!   implements it and the agent calls it. The agent sends it.
//! * The site lists three permission option kinds. The schema has four:
//!   `reject_always` is missing from the page.
//! * The site's error page says "documentation coming soon". The eight codes in
//!   `jsonrpc.zig` come from the schema's own `ErrorCode`.

pub const jsonrpc = @import("chock-acp/jsonrpc.zig");
pub const v1 = @import("chock-acp/v1.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
