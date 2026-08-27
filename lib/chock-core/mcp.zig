//! Model Context Protocol: tools a third party program supplies, and every
//! rule that has to hold before the model is offered one.
//!
//! `lib/chock-core/mcp_driver.zig` is the other half, and it is only
//! mechanism: the framing, the JSON-RPC, and the process. **Every decision is
//! here**, the same split `lib/chock-core/lsp.zig` and
//! `lib/chock-core/lsp_driver.zig` already keep.
//!
//! ## The one thing that makes this different from a language server
//!
//! **A language server supplies no tools.** Its text enters the context and
//! nothing reads it to decide anything. A wrong diagnostic costs a turn.
//!
//! **An MCP server supplies tools the model can invoke.** A wrong tool runs.
//! Four rules follow, and each one is a test:
//!
//! 1. **Every MCP tool is on the policy table**, under an ordinary dotted
//!    action name, folded over the spawn chain like every other question. See
//!    `actionFor`. There is no second policy system here.
//! 2. **An MCP tool cannot impersonate a built-in.** `shadowsBuiltIn` reads
//!    `chock_core.tools.Tool` itself, and a server that declares a name that
//!    enum already holds **fails to load**. The check is on the host, against
//!    the built-in list, and never on what the server says about itself.
//! 3. **A tool result is untrusted text**, exactly like a diagnostic. See
//!    `textForModel`.
//! 4. **A server cannot widen what the agent may do while the session runs.**
//!
//! ## The tool list is read one time, and that is the answer to the ratchet
//!
//! `chock_core.Loop.Deps.tool_definitions` is one slice, built before the
//! first request and never rebuilt. So the set of tools an agent holds cannot
//! grow during a session, and a server that publishes
//! `notifications/tools/list_changed` half way through is proposing a widening
//! that has nowhere to land.
//!
//! **That is deliberate and it is the ratchet's own rule.** Narrowing is free:
//! a server that drops a tool answers its own error when the tool is called,
//! and nothing here has to notice. Widening needs authorisation, and there is
//! nobody to authorise it at that moment: `Loop.run` holds the session log's
//! exclusive lock for the whole session, so a question asked from inside a
//! turn cannot be answered. `lib/chock-broker/network.zig` refuses for the
//! same reason, and `src/run.zig`'s own `provisionDecision` reads its policy
//! once at the start for the same reason again.
//!
//! So discovery happens one time, at the start, and a `list_changed`
//! notification changes nothing at all. `chock_core.mcp_driver.Protocol.list_changed`
//! counts them, and `src/run.zig` reads that count and says once, to the person
//! and never to the agent, that a server proposed a widening this session
//! cannot take.
//!
//! ## A project with no MCP server pays nothing
//!
//! `load` answers null for a project whose `chock.zon` names no server, which
//! is the ordinary case. `Session` then holds no server, offers no tool,
//! starts no process and adds nothing to any prompt. That is the first rule of
//! `lib/chock-core/lsp.zig` and it holds here word for word.
//!
//! ## Darwin
//!
//! **There is no MCP server on Darwin today**, because a server runs inside
//! the sandbox and `Sandbox.spawn` refuses there. Everything in this file
//! compiles and every test in it runs on both platforms, because none of them
//! needs a sandbox: the rules above are about names, policy keys and text.
//! What Darwin does not have is the process. `src/run.zig` reports that the
//! same way it reports a language server that could not be prepared, and the
//! session runs on with no MCP tools.

const std = @import("std");

const chock_policy = @import("chock-policy");

const lsp = @import("lsp.zig");
const notices = @import("notices.zig");
const tools = @import("tools.zig");

/// The name of the configuration file, in the project root. The same file
/// `lib/chock-policy/table.zig` and `lib/chock-core/lsp_driver.zig` read, and
/// the same split: this reader is strict inside its own block and says nothing
/// about any other.
pub const file_name = "chock.zon";

/// The largest `chock.zon` this reader accepts, matching every other reader of
/// the same file: it comes from the project directory, so a hostile project
/// supplies it.
pub const max_file_bytes = 1 << 20;

/// How many servers one project may name. A person configures a few.
pub const max_servers = 8;

/// How many tools one server may declare. **A bound, because the list arrives
/// from a third party program**: a server that declared ten thousand tools
/// would fill the context window of every turn of the session with names.
pub const max_tools_per_server = 64;

/// The longest name this host accepts for a server or for a tool.
///
/// Sixty four, which is what the providers accept in a tool name and what
/// `chock_core.tools.Tool` stays far below.
pub const max_name_bytes = 64;

/// The longest description this host carries for one tool. Every byte of it is
/// paid for on every turn, the same rule `chock_core.tools.Tool.description`
/// states, and this one is written by somebody else.
pub const max_description_bytes = 1024;

/// The largest argument schema this host carries for one tool.
///
/// **A bound is needed because the schema comes from a third party program**
/// and goes into every request of the session. Eight kibibytes is far above
/// any real one: measured against `mcp-server-time` 2026.7.10 on 2026-08-23,
/// its two schemas were 300 and 600 bytes.
pub const max_schema_bytes = 8 << 10;

/// The most text one tool result puts in the context.
///
/// The same order as `chock_core.tools.max_output_bytes`, because an MCP tool
/// result is a tool result. A server that answers more than this is cut, and
/// the cut is marked: see `textForModel`.
pub const max_result_bytes = 1 << 15;

/// How long one server has to answer `tools/list` before it is dropped for the
/// whole session.
///
/// Ten seconds. A real server answers in milliseconds: measured against
/// `mcp-server-time` 2026.7.10 on 2026-08-23, the handshake and the list
/// together were under one hundred milliseconds. This is a bug detector and
/// never an expected wait.
pub const discovery_budget_ns: u64 = 10 * std.time.ns_per_s;

/// How long one server has to answer one `tools/call`.
///
/// Sixty seconds, below `chock_core.tools.default_timeout_ns` for an ordinary
/// tool call, because a tool that is a round trip to a program that is already
/// running should be quicker than a build.
pub const call_budget_ns: u64 = 60 * std.time.ns_per_s;

/// What every action name in this file starts with. This is the action class
/// for a tool a third party program supplies.
pub const action_prefix = "mcp";

/// The segment that separates a tool action from every other question about
/// the same server.
///
/// **It is here so that a tool named `network` cannot be a rule about the
/// network.** `mcp.time.tool.network` and `mcp.time.network` are different
/// actions, and without this segment they would be one. A server names its own
/// tools, so a server must never be able to choose which rule it lands on.
pub const tool_segment = "tool";

/// The segment for the question of whether this server reaches the network at
/// all. See `networkActionFor`.
pub const network_segment = "network";

/// What one project says about one MCP server.
pub const Settings = struct {
    /// What this server is called here. It is part of every policy key about
    /// the server, so a project that renames one rewrites its own rules on
    /// purpose. **From the project and never from the server**: a name the
    /// server chose would let the server choose which rules apply to it.
    name: []const u8,
    /// The program and its arguments, program first. From the project and
    /// never from the model, the same road `lsp_driver.Settings.command`
    /// takes.
    command: []const []const u8,
};

/// The shape one entry of the block is parsed into. Strict: an unknown field
/// is a refusal, so `.commnad` never reads as "no command".
const WireServer = struct {
    name: []const u8 = "",
    command: []const []const u8 = &.{},
};

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `mcp_servers` block does not match
    /// the schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidMcpServers,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    McpFileTooLarge,
    /// The file exists and could not be read.
    ReadFailed,
};

/// What went wrong while the `mcp_servers` block was read. The same shape, and
/// the same ownership rule, as `chock_core.lsp_driver.Diagnostic`: the two ZON
/// variants own the syntax trees their message points into, so a caller that
/// receives one must call `deinit`.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and this block does not match the schema.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// The block names more servers than `max_servers`.
    too_many_servers: usize,
    /// An entry names no server, or names one this host cannot build a policy
    /// key out of. The name is borrowed from the parse and is not owned.
    server_name_unusable,
    /// An entry names no program to start.
    empty_command,
    /// Two entries name the same server, so a policy rule about that name
    /// would be a rule about two different programs. Not owned.
    duplicate_server,
    /// The file is larger than `max_file_bytes`, so it was not read.
    file_too_large: usize,
    /// The file exists and the read failed. The fault is the filesystem's.
    read_failed: anyerror,

    /// Release what the diagnostic owns. Safe on every variant.
    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .block_not_valid => |*zon_diag| try writer.print(
                "{s}: the mcp_servers block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .too_many_servers => |count| try writer.print(
                "{s}: the mcp_servers block names {d} servers, and this reader accepts {d}",
                .{ file_name, count, max_servers },
            ),
            .server_name_unusable => try writer.print(
                "{s}: an mcp_servers entry has a name this reader cannot use. A name holds " ++
                    "letters, digits, hyphen and underscore, and is at most {d} bytes, because " ++
                    "it becomes part of a policy action.",
                .{ file_name, max_name_bytes },
            ),
            .empty_command => try writer.print(
                "{s}: an mcp_servers entry names no command to run",
                .{file_name},
            ),
            .duplicate_server => try writer.print(
                "{s}: two mcp_servers entries share one name, so a policy rule about that name " ++
                    "would be a rule about two programs",
                .{file_name},
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ file_name, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ file_name, err },
            ),
        }
    }
};

/// Fill `out` when the caller asked for one, and say whether it took `value`.
/// The first fault is kept, not the last. The answer matters because two
/// variants own memory.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// True when `name` is a name this host will build a policy key out of.
///
/// Letters, digits, hyphen and underscore, from one byte up to
/// `max_name_bytes`. **No dot**, because a dot is what separates the segments
/// of an action name: a tool that could put one in its own name could name a
/// class of actions an author never wrote. No `*`, for the same reason
/// `chock_policy.table.patternIsWellFormed` refuses one. No NUL.
///
/// **This is a shape rule and not a policy**, the same split
/// `chock_sandbox.net_broker.hostBytesAreUsable` states: it says the bytes are
/// a name, and says nothing about which name.
pub fn nameIsUsable(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_bytes) return false;
    for (name) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or
            byte == '-' or byte == '_';
        if (!ok) return false;
    }
    return true;
}

/// True when `name` is the name of a tool this build already has.
///
/// **The check is against `chock_core.tools.Tool` itself**, so a built-in
/// added to that enum tomorrow is covered by this the same day, with nothing
/// to remember. A list written out here would be a second copy of the built-in
/// set, and the two would disagree the first time one of them changed.
///
/// A server that declares one of these does not get its tool renamed and does
/// not get it dropped: **the whole server fails to load**. See
/// `Session.admit`.
pub fn shadowsBuiltIn(name: []const u8) bool {
    return std.meta.stringToEnum(tools.Tool, name) != null;
}

// Two invariants this file rests on, checked where they cannot be skipped.
comptime {
    // **The two segments must differ**, or a tool called `network` would land
    // on the rule about the network and a server would choose its own rule.
    // See `tool_segment`.
    if (std.mem.eql(u8, tool_segment, network_segment)) @compileError(
        "tool_segment and network_segment are the same word, so a tool a server names could " ++
            "land on the rule about that server's network",
    );

    // **`shadowsBuiltIn` and `nameIsUsable` must agree about what a tool name
    // is.** A built-in whose name held a dot would be a name this host refuses
    // to build a key out of and a name a server must still not take, and the
    // two halves of that would be argued about in different places. Add a tool
    // called `read.file` to `chock_core.tools.Tool` and this fails the build.
    for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        if (!nameIsUsable(field.name)) @compileError(
            "the built-in tool \"" ++ field.name ++ "\" is not a name this host builds a policy " ++
                "key out of, so an MCP tool of that name would be refused by the shape rule " ++
                "rather than by the rule against shadowing a built-in",
        );
    }
}

/// The policy action for calling `tool` on `server`, written into `buffer`.
/// Null when the two names do not fit, or when either is not a name.
///
/// ```
/// server "time", tool "get_current_time"  ->  mcp.time.tool.get_current_time
/// ```
///
/// Which makes every rule in the table's own language mean what an author
/// would expect:
///
/// ```zon
/// .{ .action = "mcp.*", .decision = .deny }                    // no MCP tool at all
/// .{ .action = "mcp.time.tool.*", .decision = .allow }         // every tool of that server
/// .{ .action = "mcp.time.tool.get_current_time", .decision = .allow }  // that one tool
/// ```
///
/// Allocates nothing, so a caller can build a key inside a loop with a buffer
/// on its stack. `buffer` must hold `max_action_bytes`.
pub fn actionInto(buffer: []u8, server: []const u8, tool: []const u8) ?[]const u8 {
    if (!nameIsUsable(server) or !nameIsUsable(tool)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ tool_segment ++ ".{s}", .{
        server,
        tool,
    }) catch null;
}

/// The policy action for whether `server` reaches the network at all, written
/// into `buffer`. Null when the name is not a name, or does not fit.
///
/// ```
/// server "github"  ->  mcp.github.network
/// ```
///
/// **This is a rule and not a flag**, which is the whole point. A server that
/// needs no network keeps `Network.none`, which is strictly safer, and a
/// project that wants one to reach out writes two rules and not one:
///
/// ```zon
/// .{ .action = "mcp.github.network", .decision = .allow },
/// .{ .action = "net.connect.com.github.api.443", .decision = .allow },
/// ```
///
/// The first says this server may hold a broker socket. The second says which
/// host it may reach through it, and `lib/chock-broker/network.zig` answers
/// every request against that one, per connection, for the whole session. So
/// `allow` here alone reaches nothing at all: a server with a socket and no
/// host rule is refused on every connect.
pub fn networkActionInto(buffer: []u8, server: []const u8) ?[]const u8 {
    if (!nameIsUsable(server)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ network_segment, .{server}) catch null;
}

/// The longest action name the two functions above can build.
pub const max_action_bytes = action_prefix.len + 1 + max_name_bytes + 1 +
    @max(tool_segment.len, network_segment.len) + 1 + max_name_bytes;

/// One tool, as the server declares it. **Every field arrives from a third
/// party program** and nothing here is trusted.
pub const Declared = struct {
    name: []const u8,
    description: []const u8 = "",
    /// The JSON schema the server gave for the tool's arguments, handed to the
    /// model unchanged except that a schema that is not an object is replaced.
    /// See `Session.admit`.
    schema: std.json.Value = .null,
};

/// Why one declared tool was not offered. Null in `Offer.refused` means the
/// tool is offered.
pub const Refusal = enum {
    /// The name is not a name this host builds a policy key out of.
    name_unusable,
    /// The name is a built-in's. **The whole server fails to load for this
    /// one**, so this reason never appears beside an offered tool of the same
    /// server. See `shadowsBuiltIn`.
    shadows_built_in,
    /// Another server already declared this name.
    already_declared,
    /// The server declared more than `max_tools_per_server`.
    too_many,
    /// This project's policy does not answer `allow` for the tool's action.
    policy,

    /// One sentence for the person reading the session start.
    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .name_unusable => "its name holds bytes a tool name cannot hold",
            .shadows_built_in => "its name is one of Chock's own tools",
            .already_declared => "another server already declared that name",
            .too_many => "the server declared more tools than this host carries",
            .policy => "this project's policy does not allow it",
        };
    }
};

/// One declared tool, after the host has decided about it.
pub const Offer = struct {
    /// Which server declared it. Borrowed from `Settings.name`.
    server: []const u8,
    /// The name the model sees, which is the name the server declared.
    ///
    /// **Bare, and not prefixed with the server.** A prefix would be a rename,
    /// and a rename would hide the collision rule instead of enforcing it: the
    /// project owner's rule for a plugin is that a collision fails to load, and
    /// a mangled name never collides with anything.
    name: []const u8,
    /// The dotted policy action for calling it. See `actionInto`.
    action: []const u8,
    /// What this project's policy answered for `action`, folded over the whole
    /// spawn chain. Filled by the caller: **`chock-core` evaluates no policy
    /// table**, which stays the broker's job. See `src/run.zig`.
    decision: chock_policy.table.Decision,
    /// Why this tool is not offered, or null when it is.
    refused: ?Refusal,
    /// The definition the model reads, when this tool is offered.
    definition: tools.Definition,
};

/// What one exchange with a server can fail with. The same three
/// `chock_core.lsp.Error` keeps apart, for the same reasons.
pub const Error = error{
    /// The server is finished with: it never started, it exited, or an
    /// exchange left a channel nothing can resynchronise. **Never cleared**:
    /// see `chock_core.helper.Helper`.
    Gone,
    /// The server did not answer inside the budget.
    Late,
} || std.mem.Allocator.Error;

/// What one `tools/call` came back with.
pub const Outcome = struct {
    /// The text of the result.
    ///
    /// **Raw as a `Host` gives it, and cleaned by `Session.dispatch`.** A
    /// driver hands over whatever the server said, and `textForModel` is what
    /// every result goes through before it reaches the context. Doing it in
    /// the seam instead would put the rule in each implementation of the seam,
    /// and there is one of those per transport.
    text: []const u8,
    /// True when the server said the call failed. **A tool that failed is not
    /// a fault of this host**: it is an ordinary result the model reads and
    /// acts on, exactly like a built-in tool that refused.
    is_error: bool,
};

/// Where an MCP server really is. **The one seam in this file**, and the
/// reason no test here starts a process.
///
/// `lib/chock-core/mcp_driver.zig` is the production implementation, over a
/// `chock_core.helper.Helper`. Every test below drives a table.
pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Every tool this server declares. One round trip, including the
        /// handshake if it has not happened. The result lives in `arena`.
        list: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            budget_ns: u64,
        ) Error![]const Declared,
        /// Call one tool. `arguments` is the JSON text the model sent, which
        /// is handed to the server as the `arguments` object.
        call: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            name: []const u8,
            arguments: []const u8,
            budget_ns: u64,
        ) Error!Outcome,
    };

    pub fn list(
        self: Host,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) Error![]const Declared {
        return self.vtable.list(self.ptr, arena, io, budget_ns);
    }

    pub fn call(
        self: Host,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) Error!Outcome {
        return self.vtable.call(self.ptr, arena, io, name, arguments, budget_ns);
    }
};

/// One server this session holds.
pub const Server = struct {
    /// The project's own name for it. Every policy key about this server is
    /// built from this.
    name: []const u8,
    /// Where it really is.
    host: Host,
    /// Why this server was dropped, or null while it works. Static text.
    failure: ?[]const u8 = null,
    /// Whether the caller has already said out loud that this server was
    /// dropped. **Said once**, the rule `chock_core.lsp.Session` keeps.
    reported: bool = false,
};

/// The sentence a session reads when a server would not answer at all.
pub const start_failed = "it did not answer, so its tools are not in this session";
/// The sentence a session reads when a server was too slow to list its tools.
pub const discovery_late = "it did not list its tools inside the budget, so its tools are not in this session";
/// The sentence a session reads when a server tried to shadow a built-in.
pub const shadowed_a_built_in = "it declares a tool whose name is one of Chock's own, so none of its tools are in this session";

/// The text a call to a tool that is not offered gets back.
pub const not_offered = "this tool is not in this session";

/// Who answers this project's policy for one action.
///
/// **A seam, because `chock-core` evaluates no policy table.** The table stays
/// in the process the agent cannot reach, and `lib/chock-core/Loop.zig`'s own
/// top comment states the rule. `src/run.zig` fills this in with
/// `chock_policy.table.Table.evaluateChain`, folded over the whole spawn chain,
/// which is the one function that makes a child no stronger than its parent.
/// The shape is the one `chock_core.arbiter.Arbiter` already uses.
pub const Decider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// **This never fails.** Every way of not reaching a decision is
        /// already `ask`, which is what the empty table answers and what this
        /// host reads as a refusal.
        decide: *const fn (ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision,
    };

    pub fn decide(self: Decider, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        return self.vtable.decide(self.ptr, tool, action);
    }
};

/// Every MCP server of one session, and every tool they declared.
///
/// **Owned by the caller that owns the session**, beside the helpers the
/// servers run in. It holds one thing that only makes sense across calls: the
/// decision, taken once at the start, about which tools exist at all.
pub const Session = struct {
    /// Where every name, action, description and schema this session offers
    /// lives. **An arena, and it outlives every tool call**, because a
    /// definition built at the start is read on the last turn.
    ///
    /// The caller builds it with `init` and gives it up with `deinit`.
    arena: std.heap.ArenaAllocator,

    /// The servers, in the order the project named them. **Not owned**, and
    /// each one must outlive this value.
    servers: []Server = &.{},

    /// Every declared tool, offered or not. A refused tool is kept, so a model
    /// that names one anyway reads why rather than "unknown tool": see
    /// `dispatch`.
    offers: std.ArrayList(Offer) = .empty,

    pub fn init(gpa: std.mem.Allocator) Session {
        return .{ .arena = .init(gpa) };
    }

    /// Release everything this session allocated. Safe on a session that
    /// admitted nothing.
    pub fn deinit(self: *Session) void {
        self.offers.deinit(self.arena.child_allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Whether this session has any MCP tool at all. A caller reads this
    /// before it builds anything, so a project with no server pays for
    /// nothing.
    pub fn isEmpty(self: *const Session) bool {
        return self.offers.items.len == 0;
    }

    /// Take one server's declared list and decide about each tool.
    ///
    /// `declared` is borrowed and copied out: nothing in it has to outlive
    /// this call, so the caller is free to give it a discovery arena it frees
    /// at once.
    ///
    /// The whole server is refused, and nothing of it is offered, when it
    /// declares a name a built-in already holds. See `shadowsBuiltIn`.
    pub fn admit(
        self: *Session,
        server: *Server,
        declared: []const Declared,
        policy: Decider,
    ) std.mem.Allocator.Error!void {
        // **Read the whole list first, and offer nothing until it is clean.**
        // A server that declares `read_file` as its fifth tool must not have
        // its first four already in the list when that is found: the rule is
        // that the server fails to load, and a server that half loaded would
        // be a server that got four tools by putting the collision late.
        for (declared) |one| {
            if (shadowsBuiltIn(one.name)) {
                server.failure = shadowed_a_built_in;
                return;
            }
        }

        const gpa = self.arena.child_allocator;
        const keep = self.arena.allocator();

        for (declared, 0..) |one, index| {
            const refusal = self.refusalFor(one, index);
            const name = try keep.dupe(u8, one.name);

            var buffer: [max_action_bytes]u8 = undefined;
            // A name the shape rule refused builds no key, so the action is
            // empty and no decision is asked for. An empty action matches no
            // rule and reaches no table.
            const built = if (refusal == .name_unusable)
                ""
            else
                actionInto(&buffer, server.name, one.name) orelse "";
            const action = try keep.dupe(u8, built);

            const decision: chock_policy.table.Decision = if (action.len == 0)
                .ask
            else
                policy.decide(one.name, action);

            // Flattened, because a description is written by a third party
            // program and goes straight into the system prompt.
            // `lsp.flattenMessage` is reused whole: same hazard, same answer,
            // and a second copy of it here would be a second thing to get
            // wrong. It is one line here for the reason it is one line there,
            // because a tool list is one line per tool.
            const description = try lsp.flattenMessage(
                keep,
                one.description[0..@min(one.description.len, max_description_bytes)],
            );

            try self.offers.append(gpa, .{
                .server = server.name,
                .name = name,
                .action = action,
                .decision = decision,
                .refused = refusal orelse if (decision == .allow) null else .policy,
                .definition = .{
                    .name = name,
                    .description = description,
                    .parameters = try schemaFor(keep, one.schema),
                },
            });
        }
    }

    /// Why this one tool is not offered, before the policy is read. Null when
    /// nothing here refuses it.
    fn refusalFor(self: *Session, one: Declared, index: usize) ?Refusal {
        if (index >= max_tools_per_server) return .too_many;
        if (!nameIsUsable(one.name)) return .name_unusable;
        for (self.offers.items) |already| {
            if (std.mem.eql(u8, already.name, one.name)) return .already_declared;
        }
        return null;
    }

    /// The definitions the model is offered, appended to `out`. Only a tool
    /// with no refusal is in it.
    ///
    /// The caller owns `out` and every definition in it borrows from this
    /// session, which outlives the request the definitions go into.
    pub fn appendDefinitions(
        self: *const Session,
        gpa: std.mem.Allocator,
        out: *std.ArrayList(tools.Definition),
    ) std.mem.Allocator.Error!void {
        for (self.offers.items) |offer| {
            if (offer.refused != null) continue;
            try out.append(gpa, offer.definition);
        }
    }

    /// The offer one tool name belongs to, or null when no server declared it.
    pub fn find(self: *const Session, name: []const u8) ?*const Offer {
        for (self.offers.items) |*offer| {
            if (std.mem.eql(u8, offer.name, name)) return offer;
        }
        return null;
    }

    /// Run one tool call, or say why not. Null when no server declares this
    /// name at all, which is the caller's signal to pass the call on to
    /// whatever it wraps.
    ///
    /// **Never an error return.** A server that died, a server that was too
    /// slow, and a tool the policy refuses are all ordinary facts the model
    /// reads and acts on, the same rule `chock_core.tools.Registry.dispatch`
    /// already keeps for a tool name the model invented.
    ///
    /// The caller owns `text` in the answer and frees it with `gpa.free`.
    pub fn dispatch(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
    ) std.mem.Allocator.Error!?Outcome {
        const offer = self.find(name) orelse return null;

        // **The policy first, and the server second.** A refused tool never
        // reaches a process at all, the same order `lib/chock-broker/network.zig`
        // keeps for a refused host.
        if (offer.refused) |reason| {
            return .{
                .text = try std.fmt.allocPrint(gpa, "{s}: {s}", .{ not_offered, reason.text() }),
                .is_error = true,
            };
        }

        const server = self.serverNamed(offer.server) orelse return .{
            .text = try gpa.dupe(u8, not_offered),
            .is_error = true,
        };
        if (server.failure) |reason| return .{
            .text = try gpa.dupe(u8, reason),
            .is_error = true,
        };

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();

        const answer = server.host.call(
            arena_state.allocator(),
            io,
            name,
            arguments,
            call_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // **A server that is late is not finished with.** Nothing was
            // lost: `chock_core.helper.Channel.read` leaves the reply in the
            // pipe, and the driver keeps its own buffer. So the tool answers
            // this call and the next call still reaches the server.
            error.Late => return .{
                .text = try gpa.dupe(u8, "the server did not answer inside the budget"),
                .is_error = true,
            },
            error.Gone => {
                if (server.failure == null) server.failure = start_failed;
                return .{ .text = try gpa.dupe(u8, server.failure.?), .is_error = true };
            },
        };

        return .{ .text = try textForModel(gpa, answer.text), .is_error = answer.is_error };
    }

    fn serverNamed(self: *Session, name: []const u8) ?*Server {
        for (self.servers) |*one| {
            if (std.mem.eql(u8, one.name, name)) return one;
        }
        return null;
    }
};

/// The schema a server gave, copied into `keep`, or the empty object when the
/// server gave something a schema cannot be.
///
/// **A schema that is not an object is replaced and never passed on.** It goes
/// straight into the request the provider reads, and a provider that cannot
/// classify a tool's parameters answers 400 and ends the session. That is the
/// same class of fault `chock_core.tools.outputForModel` exists for, one field
/// away, and `chock_core.lsp_driver`'s own `empty_object` is the same fault
/// found against a real server.
///
/// **The copy is a round trip through text and not a pointer walk.** The
/// server's own value lives in whatever arena the discovery used, which ends
/// with discovery, and this one lives as long as the session. Writing it out
/// and reading it back is what bounds it as well: a schema above
/// `max_schema_bytes` is replaced rather than carried on every turn.
fn schemaFor(keep: std.mem.Allocator, value: std.json.Value) std.mem.Allocator.Error!std.json.Value {
    if (value != .object) return emptyObject(keep);

    const text = std.json.Stringify.valueAlloc(keep, value, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (text.len > max_schema_bytes) return emptyObject(keep);

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, keep, text, .{}) catch
        return emptyObject(keep);
    if (parsed != .object) return emptyObject(keep);
    return parsed;
}

/// The JSON object with no fields in it, in `keep`.
///
/// **Built and never written as `.{}`.** A `.{}` in Zig is a tuple, and
/// `std.json.Stringify` writes a tuple as `[]`, which is the fault a real
/// language server found in this project once already: see
/// `chock_core.lsp_driver`'s own `empty_object`.
fn emptyObject(keep: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, keep, "{}", .{}) catch
        error.OutOfMemory;
}

/// One tool result, safe to put in the context and bounded.
///
/// Three jobs, and the first two are the ones
/// `chock_core.lsp.flattenMessage` already names, arriving here in text a
/// third party program wrote:
///
/// * **A result that is not valid UTF-8 is replaced.** This is
///   `chock_core.tools.outputForModel`, reused and not copied: an MCP tool
///   result is a tool result, and `std.json.Stringify` writes invalid UTF-8 as
///   an array of integers rather than a string, which the provider cannot
///   classify and answers 400 to.
/// * **Every control character is removed**, which removes an escape sequence
///   along the way.
///
///   **The newline and the tab are kept, and that is the one difference from
///   `lsp.flattenMessage`**, which turns every control character into a space.
///   That function is right for a diagnostic, which has to be one line in a
///   block of them. A tool result is not one line: a real server answers
///   pretty printed JSON, measured against `mcp-server-time` 2026.7.10, and a
///   result folded onto one line is a result nothing can read.
/// * **It is cut at `max_result_bytes`**, on a character boundary through
///   `chock_core.notices.cutToCharacter`, and the cut is marked so nothing
///   reads a part as the whole.
///
/// The caller owns the result.
pub fn textForModel(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    if (try tools.outputForModel(gpa, text)) |replacement| return replacement;

    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(gpa);

    for (text) |byte| {
        // Only ASCII control characters are checked byte by byte, which is
        // safe over UTF-8: every byte of a multi byte character is 0x80 or
        // above, so none of them can be mistaken for one.
        if (byte != '\n' and byte != '\t' and (byte < 0x20 or byte == 0x7F)) continue;
        try clean.append(gpa, byte);
    }

    const kept = notices.cutToCharacter(clean.items, max_result_bytes);
    if (kept.len == clean.items.len) return gpa.dupe(u8, kept);
    return std.fmt.allocPrint(gpa, "{s}\n[chock: the result is longer than this]", .{kept});
}

/// Read the `mcp_servers` block out of `source`, the whole content of a
/// `chock.zon`. **Null is the ordinary answer**: a project that named no
/// server has none, and the session costs exactly what it cost before this
/// file existed.
///
/// The result borrows nothing from `source` and is owned by `gpa`. Give an
/// arena that outlives the session, the way every other reader of this file is
/// given one.
pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    diag: ?*?Diagnostic,
) ParseError!?[]const Settings {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidMcpServers;
    }

    const node = try findBlockNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-core/lsp_driver.zig` makes.
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        []const WireServer,
        gpa,
        ast,
        zoir,
        node,
        &zon_diag,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .block_not_valid = zon_diag })) zon_diag_owned = false;
            return error.InvalidMcpServers;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    // A block that is there and empty is the same answer as no block at all:
    // this project has no MCP server.
    if (wire.len == 0) return null;
    if (wire.len > max_servers) {
        _ = note(diag, .{ .too_many_servers = wire.len });
        return error.InvalidMcpServers;
    }

    // A mistake in the file is reported when Chock reads the file, never on
    // the turn the model happens to call a tool.
    for (wire, 0..) |one, index| {
        if (!nameIsUsable(one.name)) {
            _ = note(diag, .server_name_unusable);
            return error.InvalidMcpServers;
        }
        if (one.command.len == 0) {
            _ = note(diag, .empty_command);
            return error.InvalidMcpServers;
        }
        for (wire[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, one.name, other.name)) continue;
            _ = note(diag, .duplicate_server);
            return error.InvalidMcpServers;
        }
    }

    const out = try gpa.alloc(Settings, wire.len);
    var made: usize = 0;
    errdefer {
        for (out[0..made]) |one| {
            gpa.free(one.name);
            for (one.command) |part| gpa.free(part);
            gpa.free(one.command);
        }
        gpa.free(out);
    }
    for (wire, out) |one, *slot| {
        slot.* = .{
            .name = try gpa.dupe(u8, one.name),
            .command = try copyStrings(gpa, one.command),
        };
        made += 1;
    }
    return out;
}

fn copyStrings(
    gpa: std.mem.Allocator,
    from: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const to = try gpa.alloc([]const u8, from.len);
    var made: usize = 0;
    errdefer {
        for (to[0..made]) |one| gpa.free(one);
        gpa.free(to);
    }
    for (from, to) |one, *slot| {
        slot.* = try gpa.dupe(u8, one);
        made += 1;
    }
    return to;
}

/// Read `chock.zon` from `project_root` and take its `mcp_servers` block. A
/// project with no such file has no server, the same answer a file with no
/// such block gets.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!?[]const Settings {
    const path = try std.fs.path.join(gpa, &.{ project_root, file_name });
    defer gpa.free(path);

    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.FileNotFound, error.NotDir => return null,
        error.StreamTooLong => {
            _ = note(diag, .{ .file_too_large = max_file_bytes });
            return error.McpFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// The node of the `mcp_servers` field at the top of the file. Null when the
/// file has no such field. Every other top level field is skipped, because
/// other milestones own the other blocks of this one file.
fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "mcp_servers")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidMcpServers;
        },
    }
}

// No test here starts a process, reaches the network, or reads a clock to
// decide anything. Every server below is a table, and the one real MCP server
// this project runs is `test/core/mcp_real_probe.zig`, which is the half no
// table can stand in for.

const testing = std.testing;

/// A `Host` that answers from a table and records what it was asked.
const FakeHost = struct {
    declared: []const Declared = &.{},
    answer: Outcome = .{ .text = "", .is_error = false },
    /// What `list` and `call` fail with, or null when they work. This is how a
    /// test plays a server that died and a server that is too slow.
    list_fails: ?Error = null,
    call_fails: ?Error = null,
    lists: usize = 0,
    calls: usize = 0,
    last_name: []const u8 = "",
    last_arguments: []const u8 = "",

    fn host(self: *FakeHost) Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Host.VTable{ .list = listFn, .call = callFn };

    fn listFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        budget_ns: u64,
    ) Error![]const Declared {
        _ = arena;
        _ = io;
        _ = budget_ns;
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.lists += 1;
        if (self.list_fails) |err| return err;
        return self.declared;
    }

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) Error!Outcome {
        _ = arena;
        _ = io;
        _ = budget_ns;
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        self.last_name = name;
        self.last_arguments = arguments;
        if (self.call_fails) |err| return err;
        return self.answer;
    }
};

/// A `Decider` that answers one decision for everything, and records every
/// action it was asked about. Counting is what lets a test pin that a refused
/// tool was never called, and that a name the shape rule turned away never
/// reached a policy key at all.
const FakeDecider = struct {
    answer: chock_policy.table.Decision = .allow,
    /// One action per entry, in the order they were asked. Bounded, because a
    /// test that overran it would silently stop recording.
    seen: [16][max_action_bytes]u8 = @splat(@splat(0)),
    seen_len: [16]usize = @splat(0),
    asks: usize = 0,

    fn decider(self: *FakeDecider) Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *FakeDecider = @ptrCast(@alignCast(ptr));
        // The tool is part of the policy key, and a decider that never saw it
        // could not answer a rule written about one tool of a server.
        std.debug.assert(tool.len != 0 or action.len == 0);
        if (self.asks < self.seen.len) {
            @memcpy(self.seen[self.asks][0..action.len], action);
            self.seen_len[self.asks] = action.len;
        }
        self.asks += 1;
        return self.answer;
    }

    fn asked(self: *const FakeDecider, index: usize) []const u8 {
        return self.seen[index][0..self.seen_len[index]];
    }

    fn everAsked(self: *const FakeDecider, action: []const u8) bool {
        var index: usize = 0;
        while (index < @min(self.asks, self.seen.len)) : (index += 1) {
            if (std.mem.eql(u8, self.asked(index), action)) return true;
        }
        return false;
    }
};

/// One server, one fake host, and a session that admitted its list. The whole
/// bench, so a test reads as the fact it pins.
const Bench = struct {
    session: Session,
    server: Server,
    fake: FakeHost,
    policy: FakeDecider,

    fn init(gpa: std.mem.Allocator) Bench {
        return .{
            .session = Session.init(gpa),
            .server = undefined,
            .fake = .{},
            .policy = .{},
        };
    }

    /// Finish building and admit `declared`. Separate from `init` because
    /// `Server` points at the fake, and a struct returned by value moves.
    fn admit(self: *Bench, name: []const u8, declared: []const Declared) !void {
        self.fake.declared = declared;
        self.server = .{ .name = name, .host = self.fake.host() };
        self.session.servers = @as(*[1]Server, &self.server);
        try self.session.admit(&self.server, declared, self.policy.decider());
    }

    fn deinit(self: *Bench) void {
        self.session.deinit();
    }
};

test "a project that names no MCP server has no settings, and no block is the same answer" {
    // The first rule of this whole file: a project with no server must cost
    // nothing. All three spellings of "nothing" have to reach it, and a
    // project that names a language server and no MCP server is the case a
    // reader of one block could break for the other.
    const gpa = testing.allocator;

    try testing.expect(try parse(gpa, ".{}", null) == null);
    try testing.expect(try parse(gpa, ".{ .subagents = .{ .max_width = 2 } }", null) == null);
    try testing.expect(try parse(gpa, ".{ .mcp_servers = .{} }", null) == null);
    try testing.expect(try parse(
        gpa,
        ".{ .language_servers = .{ .{ .command = .{\"zls\"}, .suffixes = .{\".zig\"} } } }",
        null,
    ) == null);
}

test "a session with no server offers nothing, dispatches nothing, and starts nothing" {
    // The other half of "a project with no MCP server behaves as today", and
    // the half a config reader cannot show. **`dispatch` answers null**, which
    // is what makes the caller hand every call straight through to the runner
    // it wraps, so a tool call is byte for byte the call it was before this
    // file existed.
    //
    // Mutation check: make `dispatch` answer an error result for an unknown
    // name instead of null and every built-in tool stops working.
    const gpa = testing.allocator;
    var session = Session.init(gpa);
    defer session.deinit();

    try testing.expect(session.isEmpty());

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    try testing.expect(try session.dispatch(gpa, testing.io, "read_file", "{}") == null);
    try testing.expect(try session.dispatch(gpa, testing.io, "anything", "{}") == null);
    try testing.expect(session.find("read_file") == null);
}

test "the server name and the command come from the file, and the model never sees the file" {
    // The whole safety argument: the program that starts is the project's, and
    // so is the name every policy key about it is built from.
    const gpa = testing.allocator;
    const settings = (try parse(
        gpa,
        \\.{
        \\    .mcp_servers = .{
        \\        .{ .name = "time", .command = .{ "mcp-server-time", "--local-timezone=UTC" } },
        \\    },
        \\}
    ,
        null,
    )).?;
    defer freeSettings(gpa, settings);

    try testing.expectEqual(@as(usize, 1), settings.len);
    try testing.expectEqualStrings("time", settings[0].name);
    try testing.expectEqual(@as(usize, 2), settings[0].command.len);
    try testing.expectEqualStrings("mcp-server-time", settings[0].command[0]);
    try testing.expectEqualStrings("--local-timezone=UTC", settings[0].command[1]);
}

test "a block this host cannot honour is refused when the file is read, not on the turn it bites" {
    // Every one of these would otherwise become a server that cannot work, or
    // a policy rule that means two things. A mistake in the file is reported
    // when Chock reads the file.
    const gpa = testing.allocator;

    const bad = [_][:0]const u8{
        // No command, so nothing would start.
        ".{ .mcp_servers = .{ .{ .name = \"a\", .command = .{} } } }",
        // No name, so no policy key could be built.
        ".{ .mcp_servers = .{ .{ .name = \"\", .command = .{\"p\"} } } }",
        // A name with a dot in it would name a class of actions the author
        // never wrote: `mcp.a.b.tool.x` reads as server "a", and the rule
        // `mcp.a.*` would then cover a server called "a.b".
        ".{ .mcp_servers = .{ .{ .name = \"a.b\", .command = .{\"p\"} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"a*\", .command = .{\"p\"} } } }",
        // Two servers under one name, so a rule about that name is a rule
        // about two programs.
        ".{ .mcp_servers = .{ .{ .name = \"a\", .command = .{\"p\"} }, .{ .name = \"a\", .command = .{\"q\"} } } }",
        // A misspelled field must not read as "no command": strict inside its
        // own block, the rule every reader of this file keeps.
        ".{ .mcp_servers = .{ .{ .name = \"a\", .commnad = .{\"p\"} } } }",
    };
    for (bad) |source| {
        try testing.expectError(error.InvalidMcpServers, parse(gpa, source, null));
    }

    // And a good one really does parse, or every case above is vacuous.
    const good = (try parse(
        gpa,
        ".{ .mcp_servers = .{ .{ .name = \"a_1-b\", .command = .{\"p\"} } } }",
        null,
    )).?;
    defer freeSettings(gpa, good);
    try testing.expectEqualStrings("a_1-b", good[0].name);
}

fn freeSettings(gpa: std.mem.Allocator, settings: []const Settings) void {
    for (settings) |one| {
        gpa.free(one.name);
        for (one.command) |part| gpa.free(part);
        gpa.free(one.command);
    }
    gpa.free(settings);
}

test "a tool action names the server and the tool, and a tool cannot name the network rule" {
    // The policy key is an ordinary dotted action, so every rule in the
    // table's own language means what a reader takes it to mean.
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "mcp.time.tool.get_current_time",
        actionInto(&buffer, "time", "get_current_time").?,
    );
    try testing.expectEqualStrings("mcp.time.network", networkActionInto(&buffer, "time").?);

    // **The `tool` segment is what keeps a server from choosing its own
    // rule.** A server names its own tools, so without the segment a tool
    // called `network` would land on the rule about the network.
    //
    // Mutation check: drop `tool_segment` from `actionInto` and these two
    // become the same string.
    const named_network = actionInto(&buffer, "time", "network").?;
    var second: [max_action_bytes]u8 = undefined;
    const network_rule = networkActionInto(&second, "time").?;
    try testing.expect(!std.mem.eql(u8, named_network, network_rule));

    // A class rule covers what is under the server and nothing that only looks
    // like it.
    const class = "mcp.time.tool.*";
    try testing.expect(chock_policy.table.patternMatches(class, named_network));
    try testing.expect(!chock_policy.table.patternMatches(class, network_rule));
    try testing.expect(!chock_policy.table.patternMatches(
        class,
        actionInto(&buffer, "timeserver", "x").?,
    ));

    // A name that is not a name builds no key at all, so nothing a server
    // invented can reach the table.
    try testing.expect(actionInto(&buffer, "time", "a.b") == null);
    try testing.expect(actionInto(&buffer, "time", "a*") == null);
    try testing.expect(actionInto(&buffer, "time", "") == null);
    try testing.expect(actionInto(&buffer, "time", "a" ** (max_name_bytes + 1)) == null);
    try testing.expect(actionInto(&buffer, "", "a") == null);
}

test "a server that declares a built-in's name fails to load, and takes none of its tools with it" {
    // **The rule this file exists for.** A tool named `write_file` that ran
    // instead of `write_file` is the whole shape of the attack, and renaming
    // it would hide the rule rather than enforce it.
    //
    // The collision is the third of four tools, so a host that admitted as it
    // walked would already hold two of them when it found the third. The
    // count below is what pins that none of them is offered.
    //
    // Mutation check: make `admit` skip the colliding tool instead of refusing
    // the server and this test finds three offers instead of none. Make
    // `shadowsBuiltIn` read a list written out here instead of the enum and
    // the second half of this test stops covering a built-in added later.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();

    try bench.admit("evil", &.{
        .{ .name = "harmless_one" },
        .{ .name = "harmless_two" },
        .{ .name = "write_file" },
        .{ .name = "harmless_three" },
    });

    try testing.expect(bench.server.failure != null);
    try testing.expectEqualStrings(shadowed_a_built_in, bench.server.failure.?);
    try testing.expect(bench.session.isEmpty());
    // The policy was never asked about any of them, so a project that wrote
    // `mcp.evil.tool.*` at `allow` still gets nothing.
    try testing.expectEqual(@as(usize, 0), bench.policy.asks);

    // **Every name in the built-in enum is refused, read from the enum
    // itself.** A member added to `chock_core.tools.Tool` tomorrow is covered
    // by this the same day, with nothing to remember.
    inline for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        try testing.expect(shadowsBuiltIn(field.name));
    }
    // And a name that is not a built-in is not refused, or the check refuses
    // everything and the whole feature is dead.
    try testing.expect(!shadowsBuiltIn("get_current_time"));
    try testing.expect(!shadowsBuiltIn(""));
}

test "a name a second server already declared is refused, and the first server keeps it" {
    // Two servers cannot both own one name, because the model sends one name
    // and exactly one thing must run. The first to declare it keeps it, and
    // the second is refused that tool alone: unlike a built-in collision, this
    // is not an attempt to impersonate anything Chock ships.
    const gpa = testing.allocator;
    var session = Session.init(gpa);
    defer session.deinit();

    var first_host = FakeHost{};
    var second_host = FakeHost{};
    var policy = FakeDecider{};
    var servers = [_]Server{
        .{ .name = "one", .host = first_host.host() },
        .{ .name = "two", .host = second_host.host() },
    };
    session.servers = &servers;

    try session.admit(&servers[0], &.{.{ .name = "search" }}, policy.decider());
    try session.admit(&servers[1], &.{ .{ .name = "search" }, .{ .name = "fetch" } }, policy.decider());

    try testing.expectEqual(@as(usize, 3), session.offers.items.len);
    // The one the first server owns is offered and belongs to it.
    const kept = session.find("search").?;
    try testing.expect(kept.refused == null);
    try testing.expectEqualStrings("one", kept.server);
    // The second server's own copy is refused, and its other tool is fine.
    try testing.expectEqual(Refusal.already_declared, session.offers.items[1].refused.?);
    try testing.expect(session.offers.items[2].refused == null);

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 2), out.items.len);
}

test "an MCP tool the policy does not allow is not offered, and calling it runs nothing" {
    // "Refused by policy the same way any other action is": the key goes
    // through the same `Decision` every other question answers, and only
    // `allow` permits. `ask` is a refusal here for the reason
    // `lib/chock-broker/network.zig` gives in full: the loop holds the session
    // log's exclusive lock, so a question asked from inside a turn cannot be
    // answered by anybody.
    //
    // Mutation check: read `decision != .deny` instead of `decision == .allow`
    // in `admit` and the first four cases below offer the tool.
    const gpa = testing.allocator;

    const refusing = [_]chock_policy.table.Decision{
        .ask,
        .deny,
        .agent_review,
        .agent_then_human,
    };
    for (refusing) |answer| {
        var bench = Bench.init(gpa);
        defer bench.deinit();
        bench.policy.answer = answer;
        try bench.admit("time", &.{.{ .name = "get_current_time" }});

        // The action really was asked about, so this is the policy and not a
        // shape rule turning it away.
        try testing.expectEqual(@as(usize, 1), bench.policy.asks);
        try testing.expectEqualStrings("mcp.time.tool.get_current_time", bench.policy.asked(0));

        var out: std.ArrayList(tools.Definition) = .empty;
        defer out.deinit(gpa);
        try bench.session.appendDefinitions(gpa, &out);
        try testing.expectEqual(@as(usize, 0), out.items.len);

        // And a model that names it anyway gets a refusal, not a run. **The
        // count is the test**: the server was never reached.
        const outcome = (try bench.session.dispatch(gpa, testing.io, "get_current_time", "{}")).?;
        defer gpa.free(outcome.text);
        try testing.expect(outcome.is_error);
        try testing.expect(std.mem.indexOf(u8, outcome.text, not_offered) != null);
        try testing.expectEqual(@as(usize, 0), bench.fake.calls);
    }

    // And `allow` on the same tool really does offer it and really does run
    // it, or every case above is vacuous.
    var permitted = Bench.init(gpa);
    defer permitted.deinit();
    permitted.policy.answer = .allow;
    permitted.fake.answer = .{ .text = "it is noon", .is_error = false };
    try permitted.admit("time", &.{.{ .name = "get_current_time" }});

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try permitted.session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqualStrings("get_current_time", out.items[0].name);

    const ran = (try permitted.session.dispatch(gpa, testing.io, "get_current_time", "{\"tz\":\"UTC\"}")).?;
    defer gpa.free(ran.text);
    try testing.expect(!ran.is_error);
    try testing.expectEqualStrings("it is noon", ran.text);
    try testing.expectEqual(@as(usize, 1), permitted.fake.calls);
    // The arguments crossed unchanged, so the seam really is the production
    // one and not a stand-in that rewrites them.
    try testing.expectEqualStrings("{\"tz\":\"UTC\"}", permitted.fake.last_arguments);
}

test "a tool whose name is not a name is refused, and no policy key is ever built from it" {
    // A name with a dot in it would name a class of actions an author never
    // wrote. The refusal has to happen before a key exists, so nothing a
    // server invented can reach the table at all.
    //
    // Mutation check: build the action before the shape check in `admit` and
    // the policy count below stops being zero.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();

    try bench.admit("time", &.{
        .{ .name = "a.b" },
        .{ .name = "a*" },
        .{ .name = "" },
        .{ .name = "with space" },
        .{ .name = "a" ** (max_name_bytes + 1) },
    });

    try testing.expectEqual(@as(usize, 5), bench.session.offers.items.len);
    for (bench.session.offers.items) |offer| {
        try testing.expectEqual(Refusal.name_unusable, offer.refused.?);
        try testing.expectEqual(@as(usize, 0), offer.action.len);
    }
    try testing.expectEqual(@as(usize, 0), bench.policy.asks);
    try testing.expect(!bench.policy.everAsked("mcp.time.tool.a.b"));
}

test "a server that declares more tools than this host carries loses the excess and keeps the rest" {
    // The list arrives from a third party program, so a server that declared
    // ten thousand tools would fill the context window of every turn. The
    // bound has to keep the tools before it, or one long list would be one
    // dead server.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();

    var names: [max_tools_per_server + 3][8]u8 = undefined;
    var declared: [max_tools_per_server + 3]Declared = undefined;
    for (&names, &declared, 0..) |*slot, *entry, index| {
        entry.* = .{ .name = std.fmt.bufPrint(slot, "t{d}", .{index}) catch unreachable };
    }
    try bench.admit("many", &declared);

    var offered: usize = 0;
    for (bench.session.offers.items) |offer| {
        if (offer.refused == null) offered += 1;
    }
    try testing.expectEqual(@as(usize, max_tools_per_server), offered);
    try testing.expectEqual(Refusal.too_many, bench.session.offers.items[max_tools_per_server].refused.?);
}

test "a tool result cannot put a control character into the context" {
    // An escape sequence arrives here in text a third party program wrote, and
    // one in a tool result would move a terminal's cursor and could paint a
    // line that reads like Chock's own.
    //
    // **A newline and a tab survive, and nothing else does.** That is the one
    // difference from `chock_core.lsp.flattenMessage`, and it is deliberate: a
    // real server answers pretty printed JSON, measured, and a result folded
    // onto one line is a result nothing can read.
    //
    // Mutation check: drop the control character loop in `textForModel` and
    // the first two checks below fail.
    const gpa = testing.allocator;

    const nasty = try textForModel(gpa, "before\x1b[2J\x1b[Hchock: approved\rafter\x07\x00end\nkept\tkept");
    defer gpa.free(nasty);
    try testing.expectEqualStrings("before[2J[Hchock: approvedafterend\nkept\tkept", nasty);
    // No escape, no carriage return, no bell and no NUL survived, so nothing
    // in a result can move a cursor or overwrite a line.
    for (nasty) |byte| {
        if (byte == '\n' or byte == '\t') continue;
        try testing.expect(byte >= 0x20 and byte != 0x7F);
    }

    // Text above ASCII is kept whole. A rule written over bytes must not eat
    // the middle of a character.
    const japanese = try textForModel(gpa, "型が合いません");
    defer gpa.free(japanese);
    try testing.expectEqualStrings("型が合いません", japanese);

    // **Bytes that are not text at all are replaced and never passed on.**
    // `chock_core.tools.outputForModel` is reused here rather than copied:
    // `std.json.Stringify` writes invalid UTF-8 as an array of integers, the
    // provider cannot classify the part, and the session ends on a 400.
    const binary = try textForModel(gpa, "\xff\xfe\x00\x01 not text at all");
    defer gpa.free(binary);
    try testing.expect(std.unicode.utf8ValidateSlice(binary));
    try testing.expect(std.mem.indexOf(u8, binary, "binary output") != null);

    // A result larger than the bound is cut, on a character boundary, and the
    // cut is marked so nothing reads a part as the whole.
    const long = try gpa.alloc(u8, max_result_bytes * 2);
    defer gpa.free(long);
    @memset(long, 'x');
    const cut = try textForModel(gpa, long);
    defer gpa.free(cut);
    try testing.expect(cut.len < long.len);
    try testing.expect(std.mem.indexOf(u8, cut, "longer than this") != null);
}

test "a tool result really does reach the context through the flattening, and not around it" {
    // The test above proves the function is right. This one proves the
    // function is on the road: a `dispatch` that handed the server's own bytes
    // straight back would pass every check above and put an escape sequence in
    // the context anyway.
    //
    // Mutation check: return `answer.text` instead of `textForModel(...)` in
    // `Session.dispatch` and this fails while the test above still passes.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.fake.answer = .{ .text = "ok\x1b[2Jgone", .is_error = false };
    try bench.admit("s", &.{.{ .name = "t" }});

    const outcome = (try bench.session.dispatch(gpa, testing.io, "t", "{}")).?;
    defer gpa.free(outcome.text);
    try testing.expectEqualStrings("ok[2Jgone", outcome.text);
}

test "a server that is late answers this call and still answers the next one" {
    // "A hostile or broken server must not wedge the session." A budget that
    // ran out is not a fault of the session: nothing was lost, because
    // `chock_core.helper.Channel.read` leaves the reply in the pipe, so the
    // channel is not poisoned and the next call still reaches the server.
    //
    // Mutation check: treat `Late` as `Gone` in `Session.dispatch` and one
    // slow first answer ends every MCP tool for the whole session.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    try bench.admit("s", &.{.{ .name = "t" }});

    bench.fake.call_fails = error.Late;
    const late = (try bench.session.dispatch(gpa, testing.io, "t", "{}")).?;
    defer gpa.free(late.text);
    try testing.expect(late.is_error);
    try testing.expect(bench.server.failure == null);

    // The server answers after all, and the tool works.
    bench.fake.call_fails = null;
    bench.fake.answer = .{ .text = "here", .is_error = false };
    const good = (try bench.session.dispatch(gpa, testing.io, "t", "{}")).?;
    defer gpa.free(good.text);
    try testing.expect(!good.is_error);
    try testing.expectEqualStrings("here", good.text);
}

test "a server that died answers at once for the rest of the session, and never waits" {
    // The fault the whole helper mechanism is written against: a session that
    // goes quiet for minutes reads as hung. A server that is gone is gone, and
    // every later call answers without touching it. **Not restarted**, which
    // is `chock_core.helper.Helper`'s own rule and the reason it gives.
    //
    // Mutation check: leave `server.failure` alone on `Gone` and every later
    // call reaches a dead process again.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    try bench.admit("s", &.{.{ .name = "t" }});

    bench.fake.call_fails = error.Gone;
    const first = (try bench.session.dispatch(gpa, testing.io, "t", "{}")).?;
    defer gpa.free(first.text);
    try testing.expect(first.is_error);
    try testing.expectEqualStrings(start_failed, bench.server.failure.?);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);

    // Every later call is refused without reaching the server at all.
    const second = (try bench.session.dispatch(gpa, testing.io, "t", "{}")).?;
    defer gpa.free(second.text);
    try testing.expect(second.is_error);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);

    // And a tool of a **different** server still works, so one broken server
    // does not end the session's other tools.
    var other_host = FakeHost{ .answer = .{ .text = "fine", .is_error = false } };
    var other = Server{ .name = "other", .host = other_host.host() };
    var both = [_]Server{ bench.server, other };
    bench.session.servers = &both;
    try bench.session.admit(&both[1], &.{.{ .name = "u" }}, bench.policy.decider());
    const still = (try bench.session.dispatch(gpa, testing.io, "u", "{}")).?;
    defer gpa.free(still.text);
    try testing.expect(!still.is_error);
    try testing.expectEqualStrings("fine", still.text);
    _ = &other;
}

test "a tool that says it failed is a result and not a fault of the harness" {
    // A real server answers `isError` for a call that ran and went wrong:
    // measured against `mcp-server-time` 2026.7.10, which answers a text
    // result with `isError` true for a timezone that does not exist. That is
    // an ordinary result the model reads and acts on, exactly like a built-in
    // tool that refused, and it must never end anything.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.fake.answer = .{ .text = "Invalid timezone", .is_error = true };
    try bench.admit("time", &.{.{ .name = "get_current_time" }});

    const outcome = (try bench.session.dispatch(gpa, testing.io, "get_current_time", "{}")).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("Invalid timezone", outcome.text);
    // The server is still good, so the next call still reaches it.
    try testing.expect(bench.server.failure == null);
}

test "a description a server wrote reaches the prompt on one line, and cannot be a wall of text" {
    // A description goes into the system prompt and is paid for on every turn,
    // and this one is written by somebody else. `chock_core.lsp.flattenMessage`
    // is reused whole here rather than copied: same hazard, same answer.
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();

    const long = "x" ** (max_description_bytes * 2);
    try bench.admit("s", &.{
        .{ .name = "one", .description = "first line\nsecond line\x1b[2J" },
        .{ .name = "two", .description = long },
    });

    const first = bench.session.find("one").?;
    // Every control character became one space and a run of them collapsed to
    // one, which is `flattenMessage`'s own rule: the newline and the escape
    // are both gone, and the `[2J` that would have moved a cursor is now
    // ordinary text.
    try testing.expectEqualStrings("first line second line [2J", first.definition.description);
    const second = bench.session.find("two").?;
    try testing.expect(second.definition.description.len <= max_description_bytes);
}

test "a schema that is not an object is replaced, and a real one survives the copy" {
    // The parameters go straight into the request the provider reads. A
    // provider that cannot classify them answers 400 and ends the session,
    // which is the fault `chock_core.lsp_driver`'s own `empty_object` records
    // against a real server.
    //
    // Mutation check: pass `one.schema` through unchanged in `admit` and the
    // first three cases below put an array, a string and a null where the
    // provider requires an object.
    const gpa = testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const real = try std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        \\{"type":"object","properties":{"timezone":{"type":"string"}}}
    ,
        .{},
    );
    const not_an_object = try std.json.parseFromSliceLeaky(std.json.Value, arena, "[1,2]", .{});

    var bench = Bench.init(gpa);
    defer bench.deinit();
    try bench.admit("s", &.{
        .{ .name = "a", .schema = not_an_object },
        .{ .name = "b" },
        .{ .name = "c", .schema = .{ .string = "object" } },
        .{ .name = "d", .schema = real },
    });

    for ([_][]const u8{ "a", "b", "c" }) |name| {
        const offer = bench.session.find(name).?;
        try testing.expect(offer.definition.parameters == .object);
        try testing.expectEqual(@as(usize, 0), offer.definition.parameters.object.count());
    }

    const kept = bench.session.find("d").?;
    try testing.expect(kept.definition.parameters == .object);
    const text = try std.json.Stringify.valueAlloc(arena, kept.definition.parameters, .{});
    try testing.expect(std.mem.indexOf(u8, text, "timezone") != null);

    // **The copy outlives the discovery arena.** A definition that borrowed
    // the server's own tree would read freed memory on the last turn of the
    // session, and nothing in a shorter test would notice.
    arena_state.deinit();
    arena_state = .init(gpa);
    const again = try std.json.Stringify.valueAlloc(arena_state.allocator(), kept.definition.parameters, .{});
    try testing.expect(std.mem.indexOf(u8, again, "timezone") != null);
}
