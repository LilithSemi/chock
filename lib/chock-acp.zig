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
//! ## Both protocol versions, and what separates them
//!
//! * `jsonrpc.zig` is the envelope and the framing. It knows nothing about ACP
//!   beyond the error codes ACP adds, so both versions use it whole.
//! * `common.zig` is what the two versions spell identically, checked against
//!   both schemas: a stop reason, a tool kind, a permission option kind. It also
//!   holds `negotiate`, which picks the version to answer a client with.
//! * `v1.zig` and `v2.zig` are each version's method table, update variants and
//!   tool call status.
//!
//! Version 1 is what clients speak: it is released at 1.9.1, and the Claude
//! adapter, the reference for wrapping a harness like this one, declares
//! `protocolVersion: 1`. Version 2 is `2.0.0-alpha.5` and its fields moved
//! between alphas, so it is answered when a client asks for it and never chosen
//! over a version the client offered.
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
pub const common = @import("chock-acp/common.zig");
pub const v1 = @import("chock-acp/v1.zig");
pub const v2 = @import("chock-acp/v2.zig");

pub const Version = common.Version;
pub const negotiate = common.negotiate;

test {
    @import("std").testing.refAllDecls(@This());
}
