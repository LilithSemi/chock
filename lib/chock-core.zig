//! Root of chock-core: the tool definitions the model is offered, the
//! dispatch that runs one, and the agent loop that joins a model client,
//! the session log, and a tool runner into a session.

pub const tools = @import("chock-core/tools.zig");
pub const context = @import("chock-core/context.zig");
pub const compaction = @import("chock-core/compaction.zig");
pub const prompt = @import("chock-core/prompt.zig");
pub const Loop = @import("chock-core/Loop.zig");

pub const constitution = @import("chock-core/constitution.zig");
pub const index = @import("chock-core/index.zig");
pub const instructions = @import("chock-core/instructions.zig");
pub const memory = @import("chock-core/memory.zig");
pub const guidance = @import("chock-core/guidance.zig");
pub const skills = @import("chock-core/skills.zig");
pub const notices = @import("chock-core/notices.zig");
pub const idle = @import("chock-core/idle.zig");
pub const lsp = @import("chock-core/lsp.zig");
pub const helper = @import("chock-core/helper.zig");
pub const lsp_driver = @import("chock-core/lsp_driver.zig");
pub const mcp = @import("chock-core/mcp.zig");
pub const mcp_driver = @import("chock-core/mcp_driver.zig");
pub const plugin = @import("chock-core/plugin.zig");
pub const nix = @import("chock-core/nix.zig");
pub const plugin_module = @import("chock-core/plugin_module.zig");
pub const plugin_engine = @import("chock-core/plugin_engine.zig");
pub const plugin_host = @import("chock-core/plugin_host.zig");
pub const Diagnostic = @import("chock-core/diagnostic.zig").Diagnostic;

pub const cache = @import("chock-core/cache.zig");

pub const credentials = @import("chock-core/credentials.zig");
pub const tool_secrets = @import("chock-core/tool_secrets.zig");
pub const packages = @import("chock-core/packages.zig");
pub const scratchpad = @import("chock-core/scratchpad.zig");
pub const tasks = @import("chock-core/tasks.zig");
pub const subagent = @import("chock-core/subagent.zig");
pub const self_policy = @import("chock-core/self_policy.zig");
pub const arbiter = @import("chock-core/arbiter.zig");
pub const fetch = @import("chock-core/fetch.zig");
pub const search = @import("chock-core/search.zig");
pub const handback = @import("chock-core/handback.zig");
pub const ask = @import("chock-core/ask.zig");
pub const redact = @import("chock-core/redact.zig");
pub const devices = @import("chock-core/devices.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
