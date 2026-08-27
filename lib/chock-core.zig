//! Root of chock-core: the tool definitions the model is offered, the dispatch
//! that runs one, the two tools built on it, and the agent loop that joins a
//! model client, the session log, and a tool runner into an actual session.
//! This is the first library in Chock whose output can change something on the
//! machine, so it imports `chock-sandbox` directly, for the one
//! `Sandbox.Config` and `Sandbox.spawn` every tool call goes through, plus
//! `chock-proto` for the tool call and tool result event types, and
//! `chock-provider` for the tool definition shape a caller offers the model.
//! It does not import `chock-workspace`: `dispatch` takes an already built
//! `sandbox.Config`, the value `Workspace.sandboxConfig` returns, never a
//! `Workspace` itself, for the `std.Io` reason `lib/chock-core/tools.zig`'s
//! own top comment gives in full, and `lib/chock-core/Loop.zig` keeps the same
//! rule for the same reason. See those two files, plus `context.zig` and
//! `prompt.zig`, for everything else.

pub const tools = @import("chock-core/tools.zig");
pub const context = @import("chock-core/context.zig");
/// When to fold the context into a summary, which span to fold, and what to
/// keep verbatim. See its own top comment: the log keeps every event either
/// way, and only the model's view gets shorter.
pub const compaction = @import("chock-core/compaction.zig");
pub const prompt = @import("chock-core/prompt.zig");
pub const Loop = @import("chock-core/Loop.zig");

/// Chock's own expectations of an agent: engineering conduct, carried in the
/// system prompt whole rather than behind a tool. It enforces nothing, and
/// nothing in Chock enforces it. See its own top comment for why both halves
/// of that sentence are deliberate.
pub const constitution = @import("chock-core/constitution.zig");
/// The one mechanism three things share: an index of one line entries in the
/// prompt, and a tool that fetches the body of one. See its own top comment.
pub const index = @import("chock-core/index.zig");
/// Instruction files, read in: `AGENTS.md` at three layers that do not carry
/// the same trust.
pub const instructions = @import("chock-core/instructions.zig");
/// The knowledgebase, written out: what an agent worked out in one session
/// and does not have to work out again in the next.
pub const memory = @import("chock-core/memory.zig");
/// The guidance shelf: the engineering process the harness carries so a small
/// model does not have to hold it.
pub const guidance = @import("chock-core/guidance.zig");
/// The facts only the harness can know, told to the agent on the turn they
/// matter and never in the system prompt. See its own top comment.
pub const notices = @import("chock-core/notices.zig");
/// What the caller does while this library waits for something slow, so a full
/// screen display stays live through a turn without a second thread. See its
/// own top comment for why a thread is the wrong answer here.
pub const idle = @import("chock-core/idle.zig");
/// Diagnostics in the edit loop: what a language server said about the file the
/// agent just wrote, ranked, bounded, and appended to the tool result. A seam,
/// and `lsp_driver` below is what is on the other side of it.
pub const lsp = @import("chock-core/lsp.zig");
/// One long lived program inside the sandbox, reached over a pipe both ways:
/// the mechanism a language server, an MCP server and a plugin host all need,
/// built once. See its own top comment for the lifecycle and for which signal
/// ends a helper.
pub const helper = @import("chock-core/helper.zig");
/// The production `lsp.Server`: a language server over a `helper.Helper`,
/// speaking the Language Server Protocol on its standard input and standard
/// output. The first real consumer of the helper mechanism.
pub const lsp_driver = @import("chock-core/lsp_driver.zig");
/// Model Context Protocol: tools a third party program supplies, and every
/// rule that has to hold before the model is offered one. A seam, and
/// `mcp_driver` below is what is on the other side of it.
pub const mcp = @import("chock-core/mcp.zig");
/// The production `mcp.Host`: an MCP server over a `helper.Helper`, speaking
/// JSON-RPC on its standard input and standard output.
pub const mcp_driver = @import("chock-core/mcp_driver.zig");
/// Plugins: tools a third party WebAssembly module supplies, and every rule
/// that has to hold before the model is offered one. A seam, and
/// `plugin_module` below is what is on the other side of it.
pub const plugin = @import("chock-core/plugin.zig");
/// Reading a plugin out of a WebAssembly module, with no engine at all. The
/// host side of `chock-plugin-core`, and the reason discovery runs no guest
/// code.
pub const plugin_module = @import("chock-core/plugin_module.zig");
/// Running a plugin: the seam an engine sits behind, the capability gate that
/// decides which imports a guest gets before it is instantiated, and the
/// bounded reads of a guest's own memory. It runs in the plugin host process
/// and nowhere else. See its own top comment for why no check made while a
/// guest runs is worth anything.
pub const plugin_engine = @import("chock-core/plugin_engine.zig");
/// The plugin host process and the pipe that reaches it: the production
/// `plugin.Host`, the loop the host process itself runs, and the lockdown that
/// config gets. **Both sides of one wire are in that one file**, because the
/// peer is a program this project ships.
pub const plugin_host = @import("chock-core/plugin_host.zig");
/// The toolchain cache: the writable directory a `run_command` call gets for
/// the compiler, kept out of the project and kept across sessions.
/// Why a piece of the loop's own scaffolding could not be made or kept. One
/// type for the whole module: see its own top comment.
pub const Diagnostic = @import("chock-core/diagnostic.zig").Diagnostic;

pub const cache = @import("chock-core/cache.zig");
/// The packages a project's own manifest declares, fetched on the host at
/// session start and left in the workspace where the build looks for them.
/// The sandbox has no network, so this is what makes a real build possible at
/// all. See its own top comment for where Zig really puts a package.
pub const packages = @import("chock-core/packages.zig");
/// The session scratchpad: the writable directory a `run_command` call gets
/// for files that are not the project, gone when the run ends.
pub const scratchpad = @import("chock-core/scratchpad.zig");
/// Background commands: a command that runs while the turn goes on, and the
/// read only directory its output lands in.
pub const tasks = @import("chock-core/tasks.zig");
/// One subagent: a child process with a session and a log of its own, and the
/// answer its parent reads back out of that log. See its own top comment.
pub const subagent = @import("chock-core/subagent.zig");
/// The promises an agent made about itself, carried from the fold of the log
/// into the form `chock_policy.ratchet` reads them in. One function, and the
/// one place a ceiling this build cannot read is turned into a decision.
pub const self_policy = @import("chock-core/self_policy.zig");
/// How the loop asks somebody else whether an act may happen. **A seam, because
/// `chock-core` imports no `chock-broker`**: the policy table belongs to the
/// broker, and the broker moves into a process of its own later. See its own
/// top comment.
pub const arbiter = @import("chock-core/arbiter.zig");
/// How the loop reads a URL for the agent. **A seam, for the reason `arbiter`
/// is one**: which host may be read is a row of the policy table, and the table
/// belongs to the broker. See its own top comment, and note that a fetched page
/// is a stranger's writing and is marked as such.
pub const fetch = @import("chock-core/fetch.zig");
/// How the loop asks the person a question mid session. **A seam, for the reason
/// `arbiter` is one**: what asks a person is a terminal or a display, and every
/// device belongs to `src/`. **It is not an approval and grants nothing**: read
/// its own top comment before joining the two.
pub const ask = @import("chock-core/ask.zig");
/// Secrets kept out of a model request. **Read its top comment first**: this
/// is protection against an accident and it is not a boundary, and
/// `redact.not_a_boundary` is the one sentence that says so.
pub const redact = @import("chock-core/redact.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
