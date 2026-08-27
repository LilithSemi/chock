//! Plugins: tools a third party WebAssembly module supplies, and every rule
//! that has to hold before the model is offered one.
//!
//! `lib/chock-core/plugin_module.zig` is the other half, and it is only the
//! parse: the sections, the symbols, and the metadata blob. **Every decision
//! is here**, the same split `lib/chock-core/mcp.zig` keeps with its driver.
//!
//! ## WebAssembly buys this host nothing, and the process is the boundary
//!
//! **Do not relax the plugin host process on the grounds that WebAssembly is
//! memory safe. It is not, in the engine this project has.** Measured on
//! Vulcan, 2026-08-22: `memPtr` is `mem_base + addr + offset` with no bounds
//! check at all, and `callIndirect` loads a table slot and calls it with
//! neither a bounds check nor a signature check. A module declaring sixteen
//! pages and storing to offset 100000000 dumped core, where wasmtime trapped.
//! **A hostile module therefore holds the whole address space of the process
//! that runs it.**
//!
//! So a plugin runs **as its own process**, locked down like the agent
//! sandbox and not like a helper, and it speaks to the harness over a pipe.
//! `lib/chock-core/helper.zig` is that mechanism,
//! `lib/chock-core/plugin_host.zig` is the boundary and the lockdown, and
//! `src/plugin-host.zig` is the program.
//!
//! ## The four rules. The first three are tests, and the fourth is a fact
//!
//! 1. **Every plugin tool is on the policy table**, under an ordinary dotted
//!    action name, folded over the spawn chain like every other question. See
//!    `actionInto`. There is no second policy system here.
//! 2. **A plugin tool cannot impersonate a built-in.** `shadowsBuiltIn` reads
//!    `chock_core.tools.Tool` itself, and a plugin that declares a name that
//!    enum already holds **fails to load**, whole, with none of its other
//!    tools offered. The check is on the host, against the built-in list, and
//!    never on what the plugin says about itself. This is the project owner's
//!    own answer, and `mcp.zig` already keeps it word for word.
//! 3. **A capability is a claim, and the claim is priced before the tool is
//!    offered.** A tool declares the actions it needs in the policy table's
//!    own language, and its decision is the intersection of the decision for
//!    its own action and the decision for each action it declared. A tool that
//!    names `fs.write` in a project that denies `fs.write` is not offered.
//! 4. **A plugin cannot widen what the agent may do while the session runs.**
//!    There is no test for this one, because there is nothing to test: a
//!    plugin states its tools in its metadata, the metadata is read once out
//!    of a file, and **a plugin has no way to say anything a second time**.
//!    An MCP server does, which is why `mcp.zig` argues the point at length
//!    and counts the notifications it refuses to act on.
//!
//! ## The name comes from the project, never from the plugin
//!
//! `admit` takes the plugin's name as an argument. **It must not be the
//! `name` field of the metadata**, which the plugin author writes. That field
//! is what a person reads. The name in every policy key is the project's, for
//! the reason `mcp.Settings.name` states: a name the plugin chose would let
//! the plugin choose which rules apply to it.

const std = @import("std");

const chock_policy = @import("chock-policy");
const core = @import("chock-plugin-core");

const lsp = @import("lsp.zig");
const mcp = @import("mcp.zig");
const plugin_module = @import("plugin_module.zig");
const tools = @import("tools.zig");

/// The first segment of every policy action about a plugin.
pub const action_prefix = "plugin";

/// The segment that separates a tool action from every other question about
/// the same plugin.
///
/// **It is here for the reason `mcp.tool_segment` is here**: so that a tool
/// named `network` cannot be a rule about the network. A plugin names its own
/// tools, so a plugin must never be able to choose which rule it lands on.
pub const tool_segment = "tool";

/// The longest name this host accepts for a plugin or for one of its tools.
/// The same number `mcp.max_name_bytes` keeps, and for the same reason: it is
/// what the providers accept in a tool name.
pub const max_name_bytes = 64;

/// How many tools one plugin may offer.
///
/// **Below `core.max_tools`, which is 256.** That number bounds what a blob
/// may state and this one bounds what this host carries into a session, and
/// they are different questions: every tool offered costs its name and its
/// description on every turn of the session.
pub const max_tools_per_plugin = 64;

/// How many capabilities one tool may declare. A tool that needed more than
/// this many separate permissions is a tool nobody can reason about.
pub const max_capabilities_per_tool = 16;

/// The longest capability action this host accepts. An action is a few dotted
/// segments, such as `fs.read` or `net.connect.com.github.api.443`.
pub const max_capability_bytes = 128;

/// The locale this host reads a description in.
///
/// Chock translates nothing itself, so a plugin that carries no description in
/// this locale gets an empty description rather than one in a language the
/// person did not ask for. There is no locale setting to read yet, so this is
/// the one this build looks for.
pub const locale = "en";

/// What this project's policy answers, asked one question at a time.
///
/// **The same interface `mcp.Decider` is**, on purpose and not by copy. It
/// asks exactly the question a policy table answers, and `src/run.zig`
/// implements it once for whatever asks. A second shape of the same thing here
/// would be a second thing to keep in step.
pub const Decider = mcp.Decider;

/// True when `name` is a name this host will build a policy key out of.
///
/// The same rule `mcp.nameIsUsable` keeps, reused whole: letters, digits,
/// hyphen and underscore, from one byte up to `max_name_bytes`. **No dot**,
/// because a dot separates the segments of an action name, so a tool that
/// could put one in its own name could name a class of actions an author never
/// wrote. No `*`, and no NUL.
///
/// **This is a shape rule and not a policy.** It says the bytes are a name,
/// and says nothing about which name.
pub fn nameIsUsable(name: []const u8) bool {
    return mcp.nameIsUsable(name);
}

/// True when `name` is the name of a tool this build already has.
///
/// **The check is against `chock_core.tools.Tool` itself**, by way of the one
/// function that already does it, so a built-in added to that enum tomorrow is
/// covered by this the same day with nothing to remember.
///
/// A plugin that declares one of these does not get its tool renamed and does
/// not get it dropped: **the whole plugin fails to load**. See `Session.admit`.
pub fn shadowsBuiltIn(name: []const u8) bool {
    return mcp.shadowsBuiltIn(name);
}

/// True when `action` is a capability this host will ask the policy table
/// about.
///
/// A capability is an action in the table's own language: one or more segments
/// that are names, separated by single dots. **No `*` anywhere**, which is the
/// rule that matters: a plugin declaring `fs.*` would be a plugin naming a
/// class of actions, and a class is what an author writes in a rule, never
/// what a subject of the rules writes about itself.
pub fn capabilityIsUsable(action: []const u8) bool {
    if (action.len == 0 or action.len > max_capability_bytes) return false;
    var segments = std.mem.splitScalar(u8, action, '.');
    while (segments.next()) |segment| {
        if (!nameIsUsable(segment)) return false;
    }
    return true;
}

// Two invariants this file rests on, checked where they cannot be skipped.
comptime {
    // A capability must be a thing the policy table would accept as a
    // pattern too, or this host would ask about actions the table's own
    // reader would have refused in a rule.
    if (!chock_policy.table.patternIsWellFormed("fs.read")) @compileError(
        "the policy table no longer accepts a plain dotted action, so `capabilityIsUsable` " ++
            "is measuring against a language that has moved",
    );

    // **`shadowsBuiltIn` and `nameIsUsable` must agree about what a tool name
    // is.** A built-in whose name held a dot would be a name this host refuses
    // to build a key out of and a name a plugin must still not take, and the
    // two halves of that would be argued about in different places.
    for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        if (!nameIsUsable(field.name)) @compileError(
            "the built-in tool \"" ++ field.name ++ "\" is not a name this host builds a policy " ++
                "key out of, so a plugin tool of that name would be refused by the shape rule " ++
                "rather than by the rule against shadowing a built-in",
        );
    }
}

/// The policy action for calling `tool` of `plugin`, written into `buffer`.
/// Null when the two names do not fit, or when either is not a name.
///
/// ```
/// plugin "hello", tool "hello"  ->  plugin.hello.tool.hello
/// ```
///
/// Which makes every rule in the table's own language mean what an author
/// would expect:
///
/// ```zon
/// .{ .action = "plugin.*", .decision = .deny }                  // no plugin tool at all
/// .{ .action = "plugin.hello.tool.*", .decision = .allow }      // every tool of that plugin
/// .{ .action = "plugin.hello.tool.hello", .decision = .allow }  // that one tool
/// ```
///
/// Allocates nothing, so a caller builds a key inside a loop with one buffer.
pub fn actionInto(buffer: []u8, plugin: []const u8, tool: []const u8) ?[]const u8 {
    if (!nameIsUsable(plugin) or !nameIsUsable(tool)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ tool_segment ++ ".{s}", .{
        plugin,
        tool,
    }) catch null;
}

/// The longest action name `actionInto` can build.
pub const max_action_bytes = action_prefix.len + 1 + max_name_bytes + 1 +
    tool_segment.len + 1 + max_name_bytes;

/// Why a whole plugin was not loaded. **None of its tools is offered when one
/// of these is answered**, which is the difference between this and `Refusal`.
pub const Failure = enum {
    /// The name the project gave this plugin is not a name a policy key can be
    /// built out of.
    plugin_name_unusable,
    /// One of its tools is named after a built-in. See `shadowsBuiltIn`.
    shadows_built_in,
    already_loaded,
    too_many_tools,

    /// One sentence for the person reading the session start.
    pub fn text(self: Failure) []const u8 {
        return switch (self) {
            .plugin_name_unusable => "its name holds bytes a plugin name cannot hold",
            .shadows_built_in => "one of its tools is named after one of Chock's own tools",
            .already_loaded => "a plugin of that name is already loaded",
            .too_many_tools => "it declares more tools than this host carries",
        };
    }
};

/// Why one tool of a loaded plugin is not offered. Null in `Offer.refused`
/// means the tool is offered.
pub const Refusal = enum {
    /// The name is not a name this host builds a policy key out of.
    name_unusable,
    /// Another plugin already declared this name, or another supplier of tools
    /// in this session holds it. See `Session.reserved`.
    already_declared,
    /// It declares a capability that is not an action name, or more of them
    /// than this host reads.
    capability_unusable,
    /// This project's policy does not answer `allow` for the tool's own action
    /// or for one of the capabilities it declares.
    policy,

    /// One sentence for the person reading the session start.
    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .name_unusable => "its name holds bytes a tool name cannot hold",
            .already_declared => "another tool of this session already holds that name",
            .capability_unusable => "it declares a capability that is not an action name",
            .policy => "this project's policy does not allow it",
        };
    }
};

/// One declared tool, after the host has decided about it.
pub const Offer = struct {
    /// Which plugin declared it. The project's name for the plugin, never the
    /// plugin's own. See this file's top comment.
    plugin: []const u8,
    /// The name the model sees, which is the name the plugin declared.
    ///
    /// **Bare, and not prefixed with the plugin.** A prefix would be a rename,
    /// and a rename would hide the collision rule instead of enforcing it: the
    /// project owner's rule is that a collision fails to load, and a mangled
    /// name never collides with anything.
    name: []const u8,
    /// This tool's position in its own plugin's metadata tool list.
    ///
    /// **The number the guest ABI takes.** `chock_plugin_init` binds one entry
    /// per declared tool in that same order, so the position a host read out
    /// of the file is the position the guest bound. See
    /// `lib/chock-plugin-core/call.zig`, and see `plugin_engine.Runner.load`
    /// for the check that the two counts agree before any index is used.
    index: u32,
    /// The dotted policy action for calling it. See `actionInto`.
    action: []const u8,
    /// The actions this tool declared it needs, in the order it declared them.
    /// Each one is a name `capabilityIsUsable` accepted.
    capabilities: []const []const u8,
    /// What this project's policy answered, folded over the tool's own action
    /// and every capability it declared, and over the whole spawn chain.
    /// Filled by the caller: **`chock-core` evaluates no policy table**, which
    /// stays the broker's job. See `src/run.zig`.
    decision: chock_policy.table.Decision,
    /// Why this tool is not offered, or null when it is.
    refused: ?Refusal,
    /// The definition the model reads, when this tool is offered.
    definition: tools.Definition,
};

/// What one exchange with a plugin host can fail with. The same three
/// `mcp.Error` keeps apart, for the same reasons.
pub const Error = error{
    /// The host is finished with: it never started, it exited, or an exchange
    /// left a channel nothing can resynchronise. **Never cleared**: see
    /// `chock_core.helper.Helper`.
    Gone,
    /// The host did not answer inside the budget.
    Late,
} || std.mem.Allocator.Error;

/// What one plugin tool call came back with. The same shape `mcp.Outcome` has,
/// on purpose: a result from a third party is a result from a third party, and
/// the loop reads both the same way.
pub const Outcome = struct {
    /// The text of the result. **Raw as a `Host` gives it, and cleaned by
    /// `Session.dispatch`**, for the reason `mcp.Outcome.text` states.
    text: []const u8,
    /// True when the tool said the call failed. **A tool that failed is not a
    /// fault of this host**: it is an ordinary result the model reads and acts
    /// on, exactly like a built-in tool that refused.
    is_error: bool,
};

/// How long one plugin tool call may take.
///
/// The same number `mcp.call_budget_ns` keeps. A plugin runs in a process of
/// its own, so this is what stops a guest that loops forever from wedging the
/// session: the exchange answers `Late` and the loop goes on. See
/// `lib/chock-core/plugin_host.zig`.
pub const call_budget_ns: u64 = 60 * std.time.ns_per_s;

/// The one sentence a person reads about a plugin whose host is finished with.
pub const start_failed = "its host did not answer, so its tools are not in this session";

/// What the model is told when it names a tool that is declared and not
/// offered.
pub const not_offered = "that tool is not offered in this session";

/// Where a plugin really runs. **The one seam in this file**, and the reason
/// no test here starts a process.
///
/// `lib/chock-core/plugin_host.zig` is the production implementation, over a
/// `chock_core.helper.Helper` that reaches a locked down process. There is no
/// `list` beside `call`, and that is the difference from `mcp.Host` worth
/// stating: **a plugin's tool list is read out of its file with no engine**,
/// by `plugin_module.read`, before anything runs. A host that had to be asked
/// would be a host that ran guest code to find out whether to run guest code.
pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Call one tool. `index` is its position in the metadata's own tool
        /// list, which is what the guest ABI takes; `name` is for the message
        /// a person reads. `arguments` is the JSON text the model sent.
        call: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            index: u32,
            name: []const u8,
            arguments: []const u8,
            budget_ns: u64,
        ) Error!Outcome,
    };

    pub fn call(
        self: Host,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) Error!Outcome {
        return self.vtable.call(self.ptr, arena, io, index, name, arguments, budget_ns);
    }
};

/// One plugin this session holds.
pub const Loaded = struct {
    /// The project's own name for it. Every policy key about this plugin is
    /// built from this. See this file's top comment.
    name: []const u8,
    /// Where it really runs.
    host: Host,
    /// Why this plugin was dropped, or null while it works. Static text.
    failure: ?[]const u8 = null,
    /// Whether the caller has already said out loud that this plugin was
    /// dropped. **Said once**, the rule `chock_core.lsp.Session` keeps.
    reported: bool = false,
};

/// Every plugin of one session, and every tool they declared.
///
/// **Owned by the caller that owns the session.** It holds the one thing that
/// only makes sense across calls: the decision, taken once at the start, about
/// which tools exist at all.
pub const Session = struct {
    /// Where every name, action and description this session offers lives.
    /// **An arena, and it outlives every tool call**, because a definition
    /// built at the start is read on the last turn.
    arena: std.heap.ArenaAllocator,

    /// Every declared tool, offered or not. A refused tool is kept, so a model
    /// that names one anyway can be told why rather than "unknown tool".
    offers: std.ArrayList(Offer) = .empty,

    /// The name of each plugin that loaded, in the order they were admitted.
    /// Borrowed from the caller's own names.
    loaded: std.ArrayList([]const u8) = .empty,

    /// Tool names another supplier of tools already holds in this session, so
    /// no plugin may take one. **Filled by the caller before `admit`**, and
    /// borrowed.
    ///
    /// **A built-in is not one of these**, and must never be put here: a name
    /// a built-in holds fails the whole plugin to load, which is a stronger
    /// rule than losing one tool, and `shadowsBuiltIn` is where it is kept.
    /// What belongs here is a peer: an MCP server names its own tools too, and
    /// two suppliers offering one name would leave the model with a name whose
    /// meaning depends on which runner reads it first. See `src/run.zig`.
    reserved: []const []const u8 = &.{},

    /// Where each loaded plugin really runs. **Filled by the caller, after
    /// `admit`**, and borrowed: the caller owns the host processes, because
    /// they live exactly as long as the session does. Empty in a session that
    /// only decided about tools and never ran one, which is every test in this
    /// file.
    plugins: []Loaded = &.{},

    pub fn init(gpa: std.mem.Allocator) Session {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(self: *Session) void {
        const gpa = self.arena.child_allocator;
        self.offers.deinit(gpa);
        self.loaded.deinit(gpa);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Whether this session has any plugin tool at all. A caller reads this
    /// before it builds anything, so a project with no plugin pays nothing.
    pub fn isEmpty(self: *const Session) bool {
        return self.offers.items.len == 0;
    }

    /// Take one plugin's metadata and decide about each tool. Answers null
    /// when the plugin loaded, and the reason when it did not.
    ///
    /// `name` is the project's name for this plugin and **must not come from
    /// `record.name`**: see this file's top comment. `record` is borrowed and
    /// everything kept out of it is copied, so the caller is free to release
    /// the `plugin_module.Module` as soon as this returns.
    ///
    /// The whole plugin is refused, and nothing of it is offered, when it
    /// declares a name a built-in already holds.
    pub fn admit(
        self: *Session,
        name: []const u8,
        record: core.Metadata,
        policy: Decider,
    ) std.mem.Allocator.Error!?Failure {
        if (!nameIsUsable(name)) return .plugin_name_unusable;
        for (self.loaded.items) |already| {
            if (std.mem.eql(u8, already, name)) return .already_loaded;
        }
        if (record.tools.len > max_tools_per_plugin) return .too_many_tools;

        // **Read the whole list first, and offer nothing until it is clean.**
        // A plugin that declares `read_file` as its fifth tool must not have
        // its first four already in the list when that is found: the rule is
        // that the plugin fails to load, and a plugin that half loaded would
        // be one that got four tools by putting the collision late.
        for (record.tools) |tool| {
            if (shadowsBuiltIn(tool.name)) return .shadows_built_in;
        }

        const gpa = self.arena.child_allocator;
        const keep = self.arena.allocator();

        try self.loaded.append(gpa, name);

        for (record.tools, 0..) |tool, position| {
            const refusal = self.refusalFor(tool);
            const kept_name = try keep.dupe(u8, tool.name);

            var buffer: [max_action_bytes]u8 = undefined;
            // A name the shape rule refused builds no key, so the action is
            // empty and no decision is asked for. An empty action matches no
            // rule and reaches no table.
            const built = if (refusal == .name_unusable)
                ""
            else
                actionInto(&buffer, name, tool.name) orelse "";
            const action = try keep.dupe(u8, built);

            const capabilities = if (refusal == null)
                try copyCapabilities(keep, tool.capabilities)
            else
                &.{};

            // **The fold.** The tool's own action first, then every action it
            // declared it needs. `Decision.intersect` is the same operation
            // `chock_policy.table.evaluateChain` folds a spawn chain with, so
            // a capability the project denies makes the tool as refused as a
            // parent agent that lacks a permission makes its child.
            var decision: chock_policy.table.Decision = if (action.len == 0)
                .ask
            else
                policy.decide(tool.name, action);
            if (refusal == null) {
                for (capabilities) |capability| {
                    decision = decision.intersect(policy.decide(tool.name, capability));
                }
            }

            // Flattened, because a description is written by somebody else and
            // goes straight into the system prompt. `lsp.flattenMessage` is
            // reused whole: same hazard, same answer, and it is the bound as
            // well: it cuts at `lsp.max_message_bytes` on a character
            // boundary. **There is no second bound here**, because a second
            // one below that number would never fire and one above it would
            // never be reached. What arrives is already bounded too, at
            // `core.max_string_bytes`, because the blob reader refused
            // anything longer.
            const description = try lsp.flattenMessage(keep, describe(tool.description));

            try self.offers.append(gpa, .{
                .plugin = name,
                .name = kept_name,
                .index = @intCast(position),
                .action = action,
                .capabilities = capabilities,
                .decision = decision,
                .refused = refusal orelse if (decision == .allow) null else .policy,
                .definition = .{
                    .name = kept_name,
                    .description = description,
                    .parameters = try emptyObject(keep),
                },
            });
        }
        return null;
    }

    /// Why this one tool is not offered, before the policy is read. Null when
    /// nothing here refuses it.
    fn refusalFor(self: *Session, tool: core.ToolDescriptor) ?Refusal {
        if (!nameIsUsable(tool.name)) return .name_unusable;
        if (tool.capabilities.len > max_capabilities_per_tool) return .capability_unusable;
        for (tool.capabilities) |capability| {
            if (!capabilityIsUsable(capability)) return .capability_unusable;
        }
        for (self.offers.items) |already| {
            if (std.mem.eql(u8, already.name, tool.name)) return .already_declared;
        }
        for (self.reserved) |already| {
            if (std.mem.eql(u8, already, tool.name)) return .already_declared;
        }
        return null;
    }

    /// The definitions the model is offered, appended to `out`. Only a tool
    /// with no refusal is in it.
    ///
    /// The caller owns `out`, and every definition in it borrows from this
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

    /// The offer one tool name belongs to, or null when no plugin declared it.
    pub fn find(self: *const Session, name: []const u8) ?*const Offer {
        for (self.offers.items) |*offer| {
            if (std.mem.eql(u8, offer.name, name)) return offer;
        }
        return null;
    }

    /// Run one plugin tool call, or say why not. Null when no plugin declares
    /// this name at all, which is the caller's signal to pass the call on to
    /// whatever it wraps.
    ///
    /// **Never an error return.** A host that died, a host that was too slow,
    /// and a tool the policy refuses are all ordinary facts the model reads
    /// and acts on, the same rule `mcp.Session.dispatch` and
    /// `chock_core.tools.Registry.dispatch` already keep.
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

        // **A name that is somebody else's is not this session's to answer.**
        // `reserved` holds the names another supplier of tools already offers,
        // and a call to one of those has to reach that supplier: a refusal here
        // would hide a working tool behind a plugin that wanted its name. Two
        // plugins never reach this, because `find` answers the offer that holds
        // the name and not the one that lost it.
        if (offer.refused == .already_declared and !self.declares(name)) return null;

        // **The policy first, and the host second.** A refused tool never
        // reaches a process at all, the same order `mcp.Session.dispatch`
        // keeps.
        if (offer.refused) |reason| {
            return .{
                .text = try std.fmt.allocPrint(gpa, "{s}: {s}", .{ not_offered, reason.text() }),
                .is_error = true,
            };
        }

        const loaded = self.pluginNamed(offer.plugin) orelse return .{
            .text = try gpa.dupe(u8, not_offered),
            .is_error = true,
        };
        if (loaded.failure) |reason| return .{
            .text = try gpa.dupe(u8, reason),
            .is_error = true,
        };

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();

        const answer = loaded.host.call(
            arena_state.allocator(),
            io,
            offer.index,
            name,
            arguments,
            call_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // **A host that is late is not finished with.** Nothing was lost:
            // `chock_core.helper.Channel.read` leaves the reply in the pipe
            // and the driver keeps its own buffer, so the next call still
            // reaches the plugin. This is what stops a guest that loops
            // forever from wedging the session.
            error.Late => return .{
                .text = try gpa.dupe(u8, "the plugin did not answer inside the budget"),
                .is_error = true,
            },
            error.Gone => {
                if (loaded.failure == null) loaded.failure = start_failed;
                return .{ .text = try gpa.dupe(u8, loaded.failure.?), .is_error = true };
            },
        };

        // The same cleaning every third party result goes through, reused
        // whole rather than argued a second time: see `mcp.textForModel`.
        return .{ .text = try mcp.textForModel(gpa, answer.text), .is_error = answer.is_error };
    }

    /// Whether any plugin of this session really offers `name`. False when the
    /// only offer of that name is one that lost it.
    fn declares(self: *const Session, name: []const u8) bool {
        for (self.offers.items) |offer| {
            if (offer.refused != null) continue;
            if (std.mem.eql(u8, offer.name, name)) return true;
        }
        return false;
    }

    fn pluginNamed(self: *Session, name: []const u8) ?*Loaded {
        for (self.plugins) |*one| {
            if (std.mem.eql(u8, one.name, name)) return one;
        }
        return null;
    }

    /// Read one module and admit the plugin in it in one step, which is what a
    /// caller with a file does.
    ///
    /// Answers the module, which the caller owns and releases with `deinit`,
    /// or the module reader's own error with `module_refusal` filled. A plugin
    /// the module reader accepted and this session refused answers the module
    /// and fills `failure`, because the caller still wants to name the plugin
    /// it read when it says why the plugin was not loaded.
    pub fn load(
        self: *Session,
        gpa: std.mem.Allocator,
        name: []const u8,
        module: []const u8,
        policy: Decider,
        module_refusal: ?*?plugin_module.Refusal,
        failure: ?*?Failure,
    ) plugin_module.Error!plugin_module.Module {
        const read = try plugin_module.read(gpa, module, module_refusal);
        errdefer read.deinit();
        const answer = try self.admit(name, read.record(), policy);
        if (failure) |slot| slot.* = answer;
        return read;
    }
};

fn copyCapabilities(
    keep: std.mem.Allocator,
    declared: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const out = try keep.alloc([]const u8, declared.len);
    for (out, declared) |*slot, one| slot.* = try keep.dupe(u8, one);
    return out;
}

/// The text of a locale field set in `locale`, or empty when the author wrote
/// none for it. Chock translates nothing, so a locale it does not hold is a
/// locale the author did not supply.
fn describe(fields: []const core.LocaleField) []const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.locale, locale)) return field.value;
    }
    return "";
}

/// The JSON object with no fields in it.
///
/// A plugin tool takes no arguments this host knows how to describe yet: the
/// argument type lives in the guest's own Zig and nothing lowers it into a
/// schema. **Built and never written as `.{}`**, which Zig makes a tuple and
/// `std.json.Stringify` writes as `[]`: the fault a real language server found
/// in this project once already.
fn emptyObject(keep: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, keep, "{}", .{}) catch
        error.OutOfMemory;
}

/// The name of the configuration file, in the project root. **The same name
/// `mcp.file_name` holds**, read from that file rather than written a second
/// time: one project file, one spelling of it, and the same split every reader
/// of it keeps, which is that a reader is strict inside its own block and says
/// nothing about any other.
pub const file_name = mcp.file_name;

/// The largest `chock.zon` this reader accepts. The same bound, from the same
/// place, for the same reason: the file comes from the project directory.
pub const max_file_bytes = mcp.max_file_bytes;

/// How many plugins one project may name. A person configures a few, and every
/// one of them is a process this session may start.
pub const max_plugins = 8;

/// What one project says about one plugin.
pub const Settings = struct {
    /// What this plugin is called here. It is part of every policy key about
    /// the plugin, so a project that renames one rewrites its own rules on
    /// purpose. **From the project and never from the plugin**: see this
    /// file's own top comment, and `Session.admit`, which takes this name and
    /// not `record.name`.
    name: []const u8,
    /// The plugin's module, as the project wrote it. A relative path is read
    /// from the project root, and the caller is what joins the two: this
    /// reader keeps what the file said and resolves nothing.
    module: []const u8,
};

/// The shape one entry of the block is parsed into. Strict: an unknown field
/// is a refusal, so `.modlue` never reads as "no module".
const WirePlugin = struct {
    name: []const u8 = "",
    module: []const u8 = "",
};

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `plugins` block does not match the
    /// schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidPlugins,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    PluginFileTooLarge,
    /// The file exists and could not be read.
    ReadFailed,
};

/// What went wrong while the `plugins` block was read. The same shape, and the
/// same ownership rule, as `mcp.Diagnostic`: the two ZON variants own the
/// syntax trees their message points into, so a caller that receives one must
/// call `deinit`.
pub const Diagnostic = union(enum) {
    /// The file is not valid ZON at all.
    file_not_zon: std.zon.parse.Diagnostics,
    /// The file is valid ZON, and this block does not match the schema.
    block_not_valid: std.zon.parse.Diagnostics,
    /// The top level of the file is not a struct literal.
    not_a_struct_literal,
    /// The block names more plugins than `max_plugins`.
    too_many_plugins: usize,
    /// An entry names no plugin, or names one this host cannot build a policy
    /// key out of.
    plugin_name_unusable,
    /// An entry names no module to read.
    empty_module,
    /// Two entries name the same plugin, so a policy rule about that name
    /// would be a rule about two different modules.
    duplicate_plugin,
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
                "{s}: the plugins block is not valid:\n{f}",
                .{ file_name, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .too_many_plugins => |count| try writer.print(
                "{s}: the plugins block names {d} plugins, and this reader accepts {d}",
                .{ file_name, count, max_plugins },
            ),
            .plugin_name_unusable => try writer.print(
                "{s}: a plugins entry has a name this reader cannot use. A name holds letters, " ++
                    "digits, hyphen and underscore, and is at most {d} bytes, because it becomes " ++
                    "part of a policy action.",
                .{ file_name, max_name_bytes },
            ),
            .empty_module => try writer.print(
                "{s}: a plugins entry names no module to read",
                .{file_name},
            ),
            .duplicate_plugin => try writer.print(
                "{s}: two plugins entries share one name, so a policy rule about that name would " ++
                    "be a rule about two modules",
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

/// Read the `plugins` block out of `source`, the whole content of a
/// `chock.zon`. **Null is the ordinary answer**: a project that named no plugin
/// has none, and the session costs exactly what it cost before this file
/// existed.
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
        return error.InvalidPlugins;
    }

    const node = try findBlockNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
    // From here the diagnostics own the two trees, the same handover
    // `lib/chock-core/mcp.zig` makes.
    ast_owned = false;
    zoir_owned = false;
    var zon_diag_owned = true;
    defer if (zon_diag_owned) zon_diag.deinit(gpa);

    const wire = std.zon.parse.fromZoirNodeAlloc(
        []const WirePlugin,
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
            return error.InvalidPlugins;
        },
    };
    defer std.zon.parse.free(gpa, wire);

    // A block that is there and empty is the same answer as no block at all:
    // this project has no plugin.
    if (wire.len == 0) return null;
    if (wire.len > max_plugins) {
        _ = note(diag, .{ .too_many_plugins = wire.len });
        return error.InvalidPlugins;
    }

    // A mistake in the file is reported when Chock reads the file, never on
    // the turn the model happens to call a tool.
    for (wire, 0..) |one, index| {
        if (!nameIsUsable(one.name)) {
            _ = note(diag, .plugin_name_unusable);
            return error.InvalidPlugins;
        }
        if (one.module.len == 0) {
            _ = note(diag, .empty_module);
            return error.InvalidPlugins;
        }
        for (wire[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, one.name, other.name)) continue;
            _ = note(diag, .duplicate_plugin);
            return error.InvalidPlugins;
        }
    }

    const out = try gpa.alloc(Settings, wire.len);
    var made: usize = 0;
    errdefer {
        for (out[0..made]) |one| {
            gpa.free(one.name);
            gpa.free(one.module);
        }
        gpa.free(out);
    }
    for (wire, out) |one, *slot| {
        slot.* = .{
            .name = try gpa.dupe(u8, one.name),
            .module = try gpa.dupe(u8, one.module),
        };
        made += 1;
    }
    return out;
}

/// Read `chock.zon` from `project_root` and take its `plugins` block. A project
/// with no such file has no plugin, the same answer a file with no such block
/// gets.
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
            return error.PluginFileTooLarge;
        },
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

/// The node of the `plugins` field at the top of the file. Null when the file
/// has no such field. Every other top level field is skipped, because other
/// milestones own the other blocks of this one file.
fn findBlockNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "plugins")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidPlugins;
        },
    }
}

const testing = std.testing;

/// A policy that answers the same thing for everything, and records what it
/// was asked. Bounded, because a test that overran it would silently stop
/// recording.
const FakeDecider = struct {
    answer: chock_policy.table.Decision = .allow,
    /// One action per entry, in the order they were asked.
    seen: [32][max_capability_bytes]u8 = @splat(@splat(0)),
    seen_len: [32]usize = @splat(0),
    asks: usize = 0,
    /// An action that answers `deny` whatever `answer` says.
    denied: []const u8 = "",

    fn decider(self: *FakeDecider) Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *FakeDecider = @ptrCast(@alignCast(ptr));
        _ = tool;
        if (self.asks < self.seen.len and action.len <= max_capability_bytes) {
            @memcpy(self.seen[self.asks][0..action.len], action);
            self.seen_len[self.asks] = action.len;
        }
        self.asks += 1;
        if (self.denied.len != 0 and std.mem.eql(u8, action, self.denied)) return .deny;
        return self.answer;
    }

    fn asked(self: *const FakeDecider, action: []const u8) bool {
        for (self.seen[0..@min(self.asks, self.seen.len)], self.seen_len[0..@min(self.asks, self.seen.len)]) |entry, length| {
            if (std.mem.eql(u8, entry[0..length], action)) return true;
        }
        return false;
    }
};

/// One plugin that declares one tool, kept in a value the test owns.
///
/// **The tool list has to live somewhere the caller holds.** A helper that
/// answered a `core.Metadata` with `.tools = &.{ ... }` built inside itself
/// would answer a pointer to a temporary that dies with the call, and a
/// `Session` that read it would read whatever landed on that stack next.
const Plugin = struct {
    tools: [1]core.ToolDescriptor,
    name: []const u8 = "written by the author",

    fn record(self: *const Plugin) core.Metadata {
        return .{
            .name = self.name,
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
            .author = "somebody",
            .tools = &self.tools,
        };
    }
};

fn oneTool(name: []const u8, capabilities: []const []const u8) Plugin {
    return .{ .tools = .{.{
        .name = name,
        .description = &.{.{ .locale = "en", .value = "does a thing" }},
        .capabilities = capabilities,
    }} };
}

test "a plugin tool lands on the policy table under a dotted action" {
    // Rule 1. There is no second policy system for plugins, so the key must be
    // one an author writes in `chock.zon` beside every other rule.
    var buffer: [max_action_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "plugin.hello.tool.hello",
        actionInto(&buffer, "hello", "hello").?,
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        actionInto(&buffer, "hello.evil", "hello"),
    );
    try testing.expectEqual(
        @as(?[]const u8, null),
        actionInto(&buffer, "hello", "tool.*"),
    );
}

test "the tool segment keeps a tool from naming a rule about its own plugin" {
    // Without the segment, a plugin with a tool called `network` would build
    // `plugin.hello.network`, which is the shape a rule about that plugin's
    // network would take. A plugin names its own tools, so a plugin must never
    // choose which rule it lands on.
    var one: [max_action_bytes]u8 = undefined;
    const built = actionInto(&one, "hello", "network").?;
    try testing.expectEqualStrings("plugin.hello.tool.network", built);
    try testing.expect(!std.mem.eql(u8, built, "plugin.hello.network"));
}

test "a tool named after a built-in fails the whole plugin to load" {
    // Rule 2, and the project owner's own answer. The plugin below declares a
    // good tool first and `read_file` second, so a host that refused one tool
    // and kept the rest would leave the first one offered.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const record: core.Metadata = .{
        .name = "impostor",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "harmless" },
            .{ .name = "read_file" },
        },
    };

    const failure = try session.admit("impostor", record, policy.decider());
    try testing.expectEqual(Failure.shadows_built_in, failure.?);
    try testing.expect(session.isEmpty());
    try testing.expectEqual(@as(?*const Offer, null), session.find("harmless"));
    try testing.expectEqual(@as(usize, 0), session.loaded.items.len);
    try testing.expectEqual(@as(usize, 0), policy.asks);
}

test "the collision rule reads the built-in enum and not a list" {
    // Add a tool to `chock_core.tools.Tool` and this covers it the same day.
    // A list written out in this file would be a second copy of the built-in
    // set, and the two would disagree the first time one of them changed.
    inline for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        try testing.expect(shadowsBuiltIn(field.name));
    }
    try testing.expect(!shadowsBuiltIn("hello"));
    try testing.expect(!shadowsBuiltIn("read_fil"));
}

test "a declared capability is asked of the policy beside the tool's own action" {
    // Rule 3. A capability is the whole reason a plugin tool is on the table
    // with everything else that has consequence, so each one must reach the
    // policy under its own name.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const failure = try session.admit(
        "hello",
        oneTool("greet", &.{ "fs.read", "git.commit" }).record(),
        policy.decider(),
    );
    try testing.expectEqual(@as(?Failure, null), failure);

    try testing.expect(policy.asked("plugin.hello.tool.greet"));
    try testing.expect(policy.asked("fs.read"));
    try testing.expect(policy.asked("git.commit"));
    try testing.expectEqual(@as(usize, 3), policy.asks);

    const offer = session.find("greet").?;
    try testing.expectEqual(@as(?Refusal, null), offer.refused);
    try testing.expectEqual(@as(usize, 2), offer.capabilities.len);
    try testing.expectEqualStrings("fs.read", offer.capabilities[0]);
}

test "one denied capability refuses the tool even when the tool's own action is allowed" {
    // The fold. A tool that names `fs.write` in a project that denies
    // `fs.write` must not be offered, or the declaration would be decoration.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{ .answer = .allow, .denied = "fs.write" };

    _ = try session.admit("hello", oneTool("greet", &.{ "fs.read", "fs.write" }).record(), policy.decider());

    const offer = session.find("greet").?;
    try testing.expectEqual(Refusal.policy, offer.refused.?);
    try testing.expectEqual(chock_policy.table.Decision.deny, offer.decision);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

test "a tool that declares nothing is priced on its own action alone" {
    // The other side of the fold. An empty capability set is a claim that the
    // tool changes nothing outside itself, so nothing but the tool's own
    // action is asked about.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    try testing.expectEqual(@as(usize, 1), policy.asks);
    try testing.expect(policy.asked("plugin.hello.tool.greet"));

    const offer = session.find("greet").?;
    try testing.expectEqual(@as(?Refusal, null), offer.refused);
    try testing.expectEqual(@as(usize, 0), offer.capabilities.len);
}

test "a capability with a wildcard in it refuses the tool" {
    // A class of actions is what an author writes in a rule. A plugin that
    // could declare `fs.*` would be naming a class about itself, which is the
    // subject of the rules writing the rules.
    try testing.expect(capabilityIsUsable("fs.read"));
    try testing.expect(capabilityIsUsable("net.connect.com.github.api.443"));
    try testing.expect(!capabilityIsUsable("fs.*"));
    try testing.expect(!capabilityIsUsable("*"));
    try testing.expect(!capabilityIsUsable(""));
    try testing.expect(!capabilityIsUsable("fs."));
    try testing.expect(!capabilityIsUsable(".read"));
    try testing.expect(!capabilityIsUsable("fs..read"));

    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};
    _ = try session.admit("hello", oneTool("greet", &.{"fs.*"}).record(), policy.decider());

    const offer = session.find("greet").?;
    try testing.expectEqual(Refusal.capability_unusable, offer.refused.?);
    // The tool's own action is still priced, and no capability is: a name this
    // host will not build a key out of never reaches the table.
    try testing.expect(!policy.asked("fs.*"));
}

test "the plugin name in a policy key is the project's and not the author's" {
    // A name the plugin chose would let the plugin choose which rules apply to
    // it. The record below calls itself something else on purpose.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var declared = oneTool("greet", &.{});
    declared.name = "trusted";
    _ = try session.admit("untrusted", declared.record(), policy.decider());

    try testing.expect(policy.asked("plugin.untrusted.tool.greet"));
    try testing.expect(!policy.asked("plugin.trusted.tool.greet"));
    try testing.expectEqualStrings("untrusted", session.find("greet").?.plugin);
}

test "two plugins cannot both declare one tool name" {
    // The second one loses the name and keeps the rest of itself, which is not
    // the built-in rule: a built-in is Chock's own and a plugin must never
    // take one, and two plugins are peers.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    _ = try session.admit("first", oneTool("greet", &.{}).record(), policy.decider());
    const failure = try session.admit("second", oneTool("greet", &.{}).record(), policy.decider());

    try testing.expectEqual(@as(?Failure, null), failure);
    try testing.expectEqual(@as(usize, 2), session.offers.items.len);
    try testing.expectEqual(@as(?Refusal, null), session.offers.items[0].refused);
    try testing.expectEqual(Refusal.already_declared, session.offers.items[1].refused.?);
    try testing.expectEqualStrings("first", session.find("greet").?.plugin);
}

test "a plugin loaded twice under one name is refused" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    const failure = try session.admit("hello", oneTool("other", &.{}).record(), policy.decider());
    try testing.expectEqual(Failure.already_loaded, failure.?);
    try testing.expectEqual(@as(?*const Offer, null), session.find("other"));
}

test "a plugin with more tools than this host carries is refused whole" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var many: [max_tools_per_plugin + 1]core.ToolDescriptor = undefined;
    var names: [max_tools_per_plugin + 1][8]u8 = undefined;
    for (&many, &names, 0..) |*tool, *name, index| {
        tool.* = .{ .name = std.fmt.bufPrint(name, "t{d}", .{index}) catch unreachable };
    }
    const record: core.Metadata = .{
        .name = "big",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &many,
    };

    try testing.expectEqual(Failure.too_many_tools, (try session.admit("big", record, policy.decider())).?);
    try testing.expect(session.isEmpty());
}

test "a description is flattened and read in this host's locale" {
    // The text goes straight into the system prompt and is written by somebody
    // else, so a newline in it must not become a line of the prompt.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const record: core.Metadata = .{
        .name = "hello",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{
            .name = "greet",
            .description = &.{
                .{ .locale = "ja", .value = "挨拶する" },
                .{ .locale = "en", .value = "says\nhello\nto the world" },
            },
        }},
    };
    _ = try session.admit("hello", record, policy.decider());
    try testing.expectEqualStrings(
        "says hello to the world",
        session.find("greet").?.definition.description,
    );
}

test "a tool with no description in this host's locale gets an empty one" {
    // Chock translates nothing, so a locale it does not hold is a locale the
    // author did not supply. Putting the wrong language in the prompt would be
    // worse than putting nothing.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const record: core.Metadata = .{
        .name = "hello",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{
            .name = "greet",
            .description = &.{.{ .locale = "ja", .value = "挨拶する" }},
        }},
    };
    _ = try session.admit("hello", record, policy.decider());
    try testing.expectEqualStrings("", session.find("greet").?.definition.description);
}

test "a tool name a policy key cannot be built from is refused and never priced" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    _ = try session.admit("hello", oneTool("greet.me", &.{}).record(), policy.decider());
    const offer = session.find("greet.me").?;
    try testing.expectEqual(Refusal.name_unusable, offer.refused.?);
    try testing.expectEqualStrings("", offer.action);
    try testing.expectEqual(@as(usize, 0), policy.asks);
}

test "a plugin name a policy key cannot be built from refuses the plugin" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};
    try testing.expectEqual(
        Failure.plugin_name_unusable,
        (try session.admit("hello.evil", oneTool("greet", &.{}).record(), policy.decider())).?,
    );
    try testing.expect(session.isEmpty());
}

test "the offers a session keeps outlive the record they were read from" {
    // `admit` borrows the record and the caller releases the module at once,
    // so a session that kept slices into it would answer with freed memory.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    {
        const name = try testing.allocator.dupe(u8, "greet");
        defer testing.allocator.free(name);
        const capability = try testing.allocator.dupe(u8, "fs.read");
        defer testing.allocator.free(capability);
        const capabilities = try testing.allocator.alloc([]const u8, 1);
        defer testing.allocator.free(capabilities);
        capabilities[0] = capability;

        const tool_list = try testing.allocator.alloc(core.ToolDescriptor, 1);
        defer testing.allocator.free(tool_list);
        tool_list[0] = .{ .name = name, .capabilities = capabilities };

        _ = try session.admit("hello", .{
            .name = "hello",
            .version = .{ .major = 1, .minor = 0, .patch = 0 },
            .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
            .author = "somebody",
            .tools = tool_list,
        }, policy.decider());
    }

    const offer = session.find("greet").?;
    try testing.expectEqualStrings("greet", offer.name);
    try testing.expectEqualStrings("fs.read", offer.capabilities[0]);
    try testing.expectEqualStrings("plugin.hello.tool.greet", offer.action);
}

test "a tool the policy does not allow is not in the definitions the model reads" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{ .answer = .ask };

    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    try testing.expectEqual(Refusal.policy, session.find("greet").?.refused.?);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

test "an offered tool's parameters are a JSON object and not an array" {
    // `.{}` in Zig is a tuple, and `std.json.Stringify` writes a tuple as
    // `[]`. A provider that read `[]` where a schema belongs is the fault a
    // real language server found in this project once already.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    const text = try std.json.Stringify.valueAlloc(
        testing.allocator,
        session.find("greet").?.definition.parameters,
        .{},
    );
    defer testing.allocator.free(text);
    try testing.expectEqualStrings("{}", text);
}

test "a description longer than the prompt carries is cut" {
    // Every byte of a description is paid for on every turn of the session,
    // and the text is written by somebody else. `lsp.flattenMessage` is the
    // one bound, so this pins that the description really goes through it
    // rather than reaching the prompt whole.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const long = "x" ** (lsp.max_message_bytes * 4);
    const record: core.Metadata = .{
        .name = "hello",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{.{
            .name = "greet",
            .description = &.{.{ .locale = "en", .value = long }},
        }},
    };
    _ = try session.admit("hello", record, policy.decider());

    const kept = session.find("greet").?.definition.description;
    try testing.expect(kept.len < long.len);
    try testing.expect(std.mem.startsWith(u8, kept, "xxxx"));
    try testing.expect(std.mem.endsWith(u8, kept, "[chock: the message is longer than this]"));
}

test "a tool that declares more capabilities than this host reads is refused" {
    // A tool that needed this many separate permissions is a tool nobody can
    // reason about, and each one costs a question to the policy table.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var many: [max_capabilities_per_tool + 1][]const u8 = @splat("fs.read");
    var declared = oneTool("greet", &many);
    _ = try session.admit("hello", declared.record(), policy.decider());

    try testing.expectEqual(Refusal.capability_unusable, session.find("greet").?.refused.?);
    // Not one of them reached the table. A refused tool must cost nothing.
    try testing.expect(!policy.asked("fs.read"));
}

test "a tool name another supplier already holds is refused, and the plugin keeps the rest" {
    // Two suppliers of tools reach one model through one name space. Without
    // this, an MCP server and a plugin could both offer `greet`, and which one
    // the model reached would be decided by the order of the runner chain
    // rather than by a rule.
    //
    // **Not the built-in rule**, which fails the whole plugin: an MCP server is
    // a peer and Chock's own tool set is not. See `Session.reserved`.
    //
    // Mutation check: drop the `reserved` walk in `refusalFor` and `greet` is
    // offered twice in one session.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const taken = [_][]const u8{"greet"};
    session.reserved = &taken;

    const record: core.Metadata = .{
        .name = "hello",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "greet" },
            .{ .name = "wave" },
        },
    };
    try testing.expectEqual(@as(?Failure, null), try session.admit("hello", record, policy.decider()));

    try testing.expectEqual(Refusal.already_declared, session.find("greet").?.refused.?);
    try testing.expectEqual(@as(?Refusal, null), session.find("wave").?.refused);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 1), offered.items.len);
    try testing.expectEqualStrings("wave", offered.items[0].name);
}

test "a project that names no plugin has no settings, and no block is the same answer" {
    // The first rule of this whole file: a project with no plugin must cost
    // nothing. All three spellings of "nothing" have to reach it, and a project
    // that names an MCP server and no plugin is the case a reader of one block
    // could break for the other.
    const gpa = testing.allocator;

    try testing.expect(try parse(gpa, ".{}", null) == null);
    try testing.expect(try parse(gpa, ".{ .plugins = .{} }", null) == null);
    try testing.expect(try parse(gpa, ".{ .subagents = .{ .max_width = 2 } }", null) == null);
    try testing.expect(try parse(
        gpa,
        ".{ .mcp_servers = .{ .{ .name = \"time\", .command = .{\"mcp-server-time\"} } } }",
        null,
    ) == null);
}

test "the plugin name and the module come from the file, and the model never sees the file" {
    // The whole safety argument: the module that is read is the project's, and
    // so is the name every policy key about it is built from.
    const gpa = testing.allocator;
    const settings = (try parse(
        gpa,
        \\.{
        \\    .plugins = .{
        \\        .{ .name = "hello", .module = "plugins/chock-plugin-hello.wasm" },
        \\    },
        \\}
    ,
        null,
    )).?;
    defer freeSettings(gpa, settings);

    try testing.expectEqual(@as(usize, 1), settings.len);
    try testing.expectEqualStrings("hello", settings[0].name);
    try testing.expectEqualStrings("plugins/chock-plugin-hello.wasm", settings[0].module);
}

test "a plugins block this host cannot honour is refused when the file is read" {
    // Every one of these would otherwise become a plugin that cannot work, or a
    // policy rule that means two things. A mistake in the file is reported when
    // Chock reads the file, and never on the turn it bites.
    const gpa = testing.allocator;

    const bad = [_][:0]const u8{
        // No module, so there would be nothing to read.
        ".{ .plugins = .{ .{ .name = \"a\", .module = \"\" } } }",
        // No name, so no policy key could be built.
        ".{ .plugins = .{ .{ .name = \"\", .module = \"a.wasm\" } } }",
        // A name with a dot in it would name a class of actions the author
        // never wrote: `plugin.a.b.tool.x` reads as plugin "a", and the rule
        // `plugin.a.*` would then cover a plugin called "a.b".
        ".{ .plugins = .{ .{ .name = \"a.b\", .module = \"a.wasm\" } } }",
        ".{ .plugins = .{ .{ .name = \"a*\", .module = \"a.wasm\" } } }",
        // Two plugins under one name, so a rule about that name is a rule about
        // two modules.
        ".{ .plugins = .{ .{ .name = \"a\", .module = \"a.wasm\" }, .{ .name = \"a\", .module = \"b.wasm\" } } }",
        // A misspelled field must not read as "no module": strict inside its
        // own block, the rule every reader of this file keeps.
        ".{ .plugins = .{ .{ .name = \"a\", .modlue = \"a.wasm\" } } }",
    };
    for (bad) |source| {
        try testing.expectError(error.InvalidPlugins, parse(gpa, source, null));
    }

    // And a good one really does parse, or every case above is vacuous.
    const good = (try parse(
        gpa,
        ".{ .plugins = .{ .{ .name = \"a_1-b\", .module = \"a.wasm\" } } }",
        null,
    )).?;
    defer freeSettings(gpa, good);
    try testing.expectEqualStrings("a_1-b", good[0].name);
}

test "a project that names more plugins than this host carries is refused, and says how many" {
    const gpa = testing.allocator;

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(gpa);
    try source.appendSlice(gpa, ".{ .plugins = .{");
    for (0..max_plugins + 1) |index| {
        try source.print(gpa, " .{{ .name = \"p{d}\", .module = \"p.wasm\" }},", .{index});
    }
    try source.appendSlice(gpa, " } }");
    const text = try source.toOwnedSliceSentinel(gpa, 0);
    defer gpa.free(text);

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidPlugins, parse(gpa, text, &diag));
    try testing.expectEqual(@as(usize, max_plugins + 1), diag.?.too_many_plugins);
}

fn freeSettings(gpa: std.mem.Allocator, settings: []const Settings) void {
    for (settings) |one| {
        gpa.free(one.name);
        gpa.free(one.module);
    }
    gpa.free(settings);
}

test "a call to a name this session lost passes through, so its real owner answers" {
    // The other half of `reserved`. A plugin that wanted a name an MCP server
    // already declared loses it, and a refusal here would hide a working tool
    // behind the plugin that wanted its name. **Null is the caller's signal to
    // pass the call on**, which is what puts the call in front of the supplier
    // that really holds the name.
    //
    // Mutation check: answer the refusal for every refused offer and the MCP
    // tool of that name stops working the day a plugin declares one like it.
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const taken = [_][]const u8{"greet"};
    session.reserved = &taken;
    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());

    try testing.expectEqual(Refusal.already_declared, session.find("greet").?.refused.?);
    try testing.expectEqual(
        @as(?Outcome, null),
        try session.dispatch(testing.allocator, testing.io, "greet", "{}"),
    );

    // And a tool this session really does hold, and refuses for a reason of its
    // own, is still answered here: that one is nobody else's.
    var denied: Session = .init(testing.allocator);
    defer denied.deinit();
    var deny: FakeDecider = .{ .answer = .deny };
    _ = try denied.admit("hello", oneTool("greet", &.{}).record(), deny.decider());

    const answer = (try denied.dispatch(testing.allocator, testing.io, "greet", "{}")).?;
    defer testing.allocator.free(answer.text);
    try testing.expect(answer.is_error);
    try testing.expect(std.mem.startsWith(u8, answer.text, not_offered));
}
