//! Model Context Protocol: the tools a third party program supplies, and the
//! rules that hold before the model is offered one. `mcp_driver.zig` holds the
//! mechanism, this file holds the decisions.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");

const arbiter = @import("arbiter.zig");
const lsp = @import("lsp.zig");
const notices = @import("notices.zig");
const tools = @import("tools.zig");

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const max_servers = 8;

pub const max_tools_per_server = 64;

/// Sixty four, which is what the providers accept in a tool name.
pub const max_name_bytes = chock_policy.table.max_label_bytes;

pub const max_description_bytes = 1024;

/// `mcp-server-time` 2026.7.10 declares schemas of 300 and 600 bytes.
pub const max_schema_bytes = 8 << 10;

pub const max_result_bytes = 1 << 15;

/// A real server lists its tools in under 100 milliseconds, so this finds a bug.
pub const discovery_budget_ns: u64 = 10 * std.time.ns_per_s;

pub const call_budget_ns: u64 = 60 * std.time.ns_per_s;

pub const action_prefix = "mcp";

/// A server names its own tools, so this segment keeps a tool called `network`
/// off the rule about that server's network.
pub const tool_segment = "tool";

pub const network_segment = "network";

pub const Settings = struct {
    /// From the project and never from the server, which must not pick its own rules.
    name: []const u8,
    command: []const []const u8,
};

/// Strict, so a misspelled `.commnad` does not read as "no command".
const WireServer = struct {
    name: []const u8 = "",
    command: []const []const u8 = &.{},
};

pub const ParseError = error{
    OutOfMemory,
    InvalidMcpServers,
};

pub const LoadError = ParseError || error{
    McpFileTooLarge,
    ReadFailed,
};

/// The two ZON variants own the trees their message points into, so call `deinit`.
pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    too_many_servers: usize,
    server_name_unusable,
    empty_command,
    duplicate_server,
    file_too_large: usize,
    read_failed: anyerror,

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

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// No dot, because a dot separates the segments of an action name, and no `*`.
pub fn nameIsUsable(name: []const u8) bool {
    return chock_policy.table.labelIsUsable(name);
}

pub fn shadowsBuiltIn(name: []const u8) bool {
    return std.meta.stringToEnum(tools.Tool, name) != null;
}

comptime {
    if (std.mem.eql(u8, tool_segment, network_segment)) @compileError(
        "tool_segment and network_segment are the same word, so a tool a server names could " ++
            "land on the rule about that server's network",
    );

    for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        if (!nameIsUsable(field.name)) @compileError(
            "the built-in tool \"" ++ field.name ++ "\" is not a name this host builds a policy " ++
                "key out of, so an MCP tool of that name would be refused by the shape rule " ++
                "rather than by the rule against shadowing a built-in",
        );
    }
}

/// Server "time" and tool "get_current_time" give `mcp.time.tool.get_current_time`.
pub fn actionInto(buffer: []u8, server: []const u8, tool: []const u8) ?[]const u8 {
    if (!nameIsUsable(server) or !nameIsUsable(tool)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ tool_segment ++ ".{s}", .{
        server,
        tool,
    }) catch null;
}

/// Server "github" gives `mcp.github.*`, the pattern that reaches everything one
/// server can do.
///
/// A pattern and not an action, for the one caller that has to read the policy
/// before the server has said what tools it has: what a server is given at
/// start cannot wait for a tool name.
pub fn namespaceInto(buffer: []u8, server: []const u8) ?[]const u8 {
    if (!nameIsUsable(server)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}.*", .{server}) catch null;
}

/// Server "github" gives `mcp.github.network`. Allow alone reaches nothing: the
/// broker still refuses every connect that no `net.connect` rule covers.
pub fn networkActionInto(buffer: []u8, server: []const u8) ?[]const u8 {
    if (!nameIsUsable(server)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ network_segment, .{server}) catch null;
}

pub const max_action_bytes = action_prefix.len + 1 + max_name_bytes + 1 +
    @max(tool_segment.len, network_segment.len) + 1 + max_name_bytes;

/// Every field comes from a third party program.
pub const Declared = struct {
    name: []const u8,
    description: []const u8 = "",
    schema: std.json.Value = .null,
};

pub const Refusal = enum {
    name_unusable,
    shadows_built_in,
    already_declared,
    too_many,
    policy,

    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .name_unusable => "its name holds bytes a tool name cannot hold",
            .shadows_built_in => "its name is one of Chock's own tools",
            .already_declared => "another server already declared that name",
            .too_many => "the server declared more tools than this host carries",
            .policy => "this project's policy denies it",
        };
    }
};

pub const Offer = struct {
    server: []const u8,
    /// Bare and never prefixed with the server, because a mangled name never collides.
    name: []const u8,
    action: []const u8,
    /// What the table answered at the start. Never the last word on a call:
    /// `dispatch` asks again, because a session can narrow itself later.
    decision: chock_policy.table.Decision,
    refused: ?Refusal,
    definition: tools.Definition,
};

pub const Error = error{
    /// Never cleared, and the server is never restarted.
    Gone,
    Late,
} || std.mem.Allocator.Error;

pub const Outcome = struct {
    /// Raw as the server gave it. `Session.dispatch` is what cleans it.
    text: []const u8,
    is_error: bool,
};

pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        list: *const fn (
            ptr: *anyopaque,
            arena: std.mem.Allocator,
            io: std.Io,
            budget_ns: u64,
        ) Error![]const Declared,
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

pub const Server = struct {
    name: []const u8,
    host: Host,
    failure: ?[]const u8 = null,
    reported: bool = false,
};

pub const start_failed = "it did not answer, so its tools are not in this session";
pub const discovery_late = "it did not list its tools inside the budget, so its tools are not in this session";
pub const shadowed_a_built_in = "it declares a tool whose name is one of Chock's own, so none of its tools are in this session";

pub const not_offered = "this tool is not in this session";

pub const Decider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Never fails. Every way of not reaching a decision is already `ask`.
        decide: *const fn (ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision,
    };

    pub fn decide(self: Decider, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        return self.vtable.decide(self.ptr, tool, action);
    }
};

pub const Session = struct {
    /// Outlives every tool call: a definition built at the start is read on the last turn.
    arena: std.heap.ArenaAllocator,

    servers: []Server = &.{},

    offers: std.ArrayList(Offer) = .empty,

    /// Null refuses every call, which is the safe direction.
    asker: ?arbiter.Asker = null,

    pub fn init(gpa: std.mem.Allocator) Session {
        return .{ .arena = .init(gpa) };
    }

    pub fn deinit(self: *Session) void {
        self.offers.deinit(self.arena.child_allocator);
        self.arena.deinit();
        self.* = undefined;
    }

    /// Once, after `Loop.run` has taken the lock, and never per call.
    pub fn giveLocked(self: *Session, locked: *arbiter.Locked) void {
        if (self.asker) |*one| one.locked = locked;
    }

    pub fn isEmpty(self: *const Session) bool {
        return self.offers.items.len == 0;
    }

    /// `declared` is borrowed and copied out.
    pub fn admit(
        self: *Session,
        server: *Server,
        declared: []const Declared,
        policy: Decider,
    ) std.mem.Allocator.Error!void {
        // Read the whole list before anything is offered, or a server gets four
        // tools by putting the collision fifth.
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
            const built = if (refusal == .name_unusable)
                ""
            else
                actionInto(&buffer, server.name, one.name) orelse "";
            const action = try keep.dupe(u8, built);

            const decision: chock_policy.table.Decision = if (action.len == 0)
                .deny
            else
                policy.decide(one.name, action);

            const description = try lsp.flattenMessage(
                keep,
                one.description[0..@min(one.description.len, max_description_bytes)],
            );

            try self.offers.append(gpa, .{
                .server = server.name,
                .name = name,
                .action = action,
                .decision = decision,
                .refused = refusal orelse if (decision == .deny) .policy else null,
                .definition = .{
                    .name = name,
                    .description = description,
                    .parameters = try schemaFor(keep, one.schema),
                },
            });
        }
    }

    fn refusalFor(self: *Session, one: Declared, index: usize) ?Refusal {
        if (index >= max_tools_per_server) return .too_many;
        if (!nameIsUsable(one.name)) return .name_unusable;
        for (self.offers.items) |already| {
            if (std.mem.eql(u8, already.name, one.name)) return .already_declared;
        }
        return null;
    }

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

    pub fn find(self: *const Session, name: []const u8) ?*const Offer {
        for (self.offers.items) |*offer| {
            if (std.mem.eql(u8, offer.name, name)) return offer;
        }
        return null;
    }

    /// Null when no server declares this name, which tells the caller to pass the
    /// call on. Never an error return: a dead server, a slow server and a refused
    /// tool are ordinary results. Every call is asked about, because a session
    /// can narrow itself after `admit` read the table.
    pub fn dispatch(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: tools.ToolCall,
    ) std.mem.Allocator.Error!?Outcome {
        const name = call.tool;
        const offer = self.find(name) orelse return null;

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

        // After the local checks, so no question is spent on a call that could not run.
        const answer_about_call = try self.askAbout(gpa, io, offer, call.call_id);
        if (!answer_about_call.permitted) return .{
            .text = try arbiter.refusalText(gpa, name, answer_about_call),
            .is_error = true,
        };

        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();

        const answer = server.host.call(
            arena_state.allocator(),
            io,
            name,
            call.arguments,
            call_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Not finished with: the reply stays in the pipe, so the next call works.
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

    fn askAbout(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        offer: *const Offer,
        call_id: []const u8,
    ) std.mem.Allocator.Error!arbiter.Answer {
        std.debug.assert(offer.action.len > 0);

        const summary = try std.fmt.allocPrint(
            gpa,
            "run the tool \"{s}\" that the MCP server \"{s}\" supplies",
            .{ offer.name, offer.server },
        );
        defer gpa.free(summary);

        return arbiter.Asker.decide(self.asker, gpa, io, .{
            .action = offer.action,
            .summary = summary,
            // The effect and never the arguments, which a model wrote.
            .detail = offer.action,
            .reason = "",
            .tool = offer.name,
            .tool_call_id = call_id,
            .source = "an MCP server",
        });
    }

    fn serverNamed(self: *Session, name: []const u8) ?*Server {
        for (self.servers) |*one| {
            if (std.mem.eql(u8, one.name, name)) return one;
        }
        return null;
    }
};

/// A schema that is not an object makes the provider answer 400 and end the
/// session. The copy goes through text, because the server's own value dies
/// with the discovery arena and this one lives as long as the session.
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

/// Built and never written as `.{}`, which is a tuple in Zig and which
/// `std.json.Stringify` writes as `[]`.
fn emptyObject(keep: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, keep, "{}", .{}) catch
        error.OutOfMemory;
}

/// The newline and the tab survive, unlike `lsp.flattenMessage`: a real server
/// answers pretty printed JSON, which one line cannot hold.
pub fn textForModel(gpa: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    if (try tools.outputForModel(gpa, text)) |replacement| return replacement;

    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(gpa);

    for (text) |byte| {
        // Safe over UTF-8: every byte of a multi byte character is 0x80 or above.
        if (byte != '\n' and byte != '\t' and (byte < 0x20 or byte == 0x7F)) continue;
        try clean.append(gpa, byte);
    }

    const kept = notices.cutToCharacter(clean.items, max_result_bytes);
    if (kept.len == clean.items.len) return gpa.dupe(u8, kept);
    return std.fmt.allocPrint(gpa, "{s}\n[chock: the result is longer than this]", .{kept});
}

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
    // From here the diagnostics own the two trees.
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

    if (wire.len == 0) return null;
    if (wire.len > max_servers) {
        _ = note(diag, .{ .too_many_servers = wire.len });
        return error.InvalidMcpServers;
    }

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

/// Every other top level field belongs to another reader of this file.
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

// No test here starts a process. `test/core/mcp_real_probe.zig` runs a real one.

const testing = std.testing;

const FakeHost = struct {
    declared: []const Declared = &.{},
    answer: Outcome = .{ .text = "", .is_error = false },
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

const FakeDecider = struct {
    answer: chock_policy.table.Decision = .allow,
    seen: [16][max_action_bytes]u8 = @splat(@splat(0)),
    seen_len: [16]usize = @splat(0),
    asks: usize = 0,

    fn decider(self: *FakeDecider) Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Decider.VTable{ .decide = decideFn };

    fn decideFn(ptr: *anyopaque, tool: []const u8, action: []const u8) chock_policy.table.Decision {
        const self: *FakeDecider = @ptrCast(@alignCast(ptr));
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

const FakeArbiter = struct {
    answer: arbiter.Answer = .{ .permitted = true, .outcome = "allowed_by_policy" },
    asks: usize = 0,
    last_action: [max_action_bytes]u8 = @splat(0),
    last_action_len: usize = 0,
    last_tool: [max_name_bytes]u8 = @splat(0),
    last_tool_len: usize = 0,
    last_call_id: [max_name_bytes]u8 = @splat(0),
    last_call_id_len: usize = 0,

    fn arbiterSeam(self: *FakeArbiter) arbiter.Arbiter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = arbiter.Arbiter.VTable{ .decide = decideFn };

    fn decideFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        locked: *arbiter.Locked,
        ask: arbiter.Ask,
    ) arbiter.Answer {
        _ = gpa;
        _ = io;
        _ = locked;
        const self: *FakeArbiter = @ptrCast(@alignCast(ptr));
        self.asks += 1;
        self.last_action_len = @min(ask.action.len, self.last_action.len);
        @memcpy(self.last_action[0..self.last_action_len], ask.action[0..self.last_action_len]);
        self.last_tool_len = @min(ask.tool.len, self.last_tool.len);
        @memcpy(self.last_tool[0..self.last_tool_len], ask.tool[0..self.last_tool_len]);
        self.last_call_id_len = @min(ask.tool_call_id.len, self.last_call_id.len);
        @memcpy(self.last_call_id[0..self.last_call_id_len], ask.tool_call_id[0..self.last_call_id_len]);
        return self.answer;
    }

    fn action(self: *const FakeArbiter) []const u8 {
        return self.last_action[0..self.last_action_len];
    }

    fn tool(self: *const FakeArbiter) []const u8 {
        return self.last_tool[0..self.last_tool_len];
    }

    fn callId(self: *const FakeArbiter) []const u8 {
        return self.last_call_id[0..self.last_call_id_len];
    }
};

const Bench = struct {
    session: Session,
    server: Server,
    fake: FakeHost,
    policy: FakeDecider,
    judge: FakeArbiter,
    backing: chock_proto.storage.Memory = undefined,
    store: chock_proto.storage.Storage = undefined,
    locked: arbiter.Locked = undefined,
    armed: bool = false,

    fn init(gpa: std.mem.Allocator) Bench {
        return .{
            .session = Session.init(gpa),
            .server = undefined,
            .fake = .{},
            .policy = .{},
            .judge = .{},
        };
    }

    /// Separate from `init`, because a struct returned by value moves.
    fn openLog(self: *Bench, io: std.Io) !void {
        const gpa = self.session.arena.child_allocator;
        self.backing = try chock_proto.storage.Memory.init(gpa, "01MCPBENCH");
        self.store = self.backing.storage();
        self.locked = try self.store.lock(io);
        self.armed = true;
    }

    fn arm(self: *Bench, io: std.Io) !void {
        try self.openLog(io);
        self.session.asker = .{ .arbiter = self.judge.arbiterSeam(), .locked = &self.locked };
    }

    fn admit(self: *Bench, name: []const u8, declared: []const Declared) !void {
        self.fake.declared = declared;
        self.server = .{ .name = name, .host = self.fake.host() };
        self.session.servers = @as(*[1]Server, &self.server);
        try self.session.admit(&self.server, declared, self.policy.decider());
    }

    fn deinit(self: *Bench) void {
        if (self.armed) {
            self.locked.unlock(testing.io) catch {};
            self.store.close(testing.io);
        }
        self.session.deinit();
    }
};

fn callOf(name: []const u8, arguments: []const u8) tools.ToolCall {
    return .{ .call_id = "call1", .tool = name, .arguments = arguments };
}

test "a project that names no MCP server has no settings, and no block is the same answer" {
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
    const gpa = testing.allocator;
    var session = Session.init(gpa);
    defer session.deinit();

    try testing.expect(session.isEmpty());

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    try testing.expect(try session.dispatch(gpa, testing.io, callOf("read_file", "{}")) == null);
    try testing.expect(try session.dispatch(gpa, testing.io, callOf("anything", "{}")) == null);
    try testing.expect(session.find("read_file") == null);
}

test "the server name and the command come from the file, and the model never sees the file" {
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
    const gpa = testing.allocator;

    const bad = [_][:0]const u8{
        ".{ .mcp_servers = .{ .{ .name = \"a\", .command = .{} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"\", .command = .{\"p\"} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"a.b\", .command = .{\"p\"} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"a*\", .command = .{\"p\"} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"a\", .command = .{\"p\"} }, .{ .name = \"a\", .command = .{\"q\"} } } }",
        ".{ .mcp_servers = .{ .{ .name = \"a\", .commnad = .{\"p\"} } } }",
    };
    for (bad) |source| {
        try testing.expectError(error.InvalidMcpServers, parse(gpa, source, null));
    }

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

test "a server's namespace is the pattern that reaches everything it can do" {
    var buffer: [max_action_bytes]u8 = undefined;

    const namespace = namespaceInto(&buffer, "github").?;
    try testing.expectEqualStrings("mcp.github.*", namespace);
    try testing.expect(chock_policy.table.patternIsWellFormed(namespace));

    // Every action this server can carry is under it, and another server's is
    // not, which is what a caller reading the policy at start relies on.
    var second: [max_action_bytes]u8 = undefined;
    try testing.expect(chock_policy.table.patternMatches(
        namespace,
        actionInto(&second, "github", "create_issue").?,
    ));
    try testing.expect(chock_policy.table.patternMatches(
        namespace,
        networkActionInto(&second, "github").?,
    ));
    try testing.expect(!chock_policy.table.patternMatches(
        namespace,
        actionInto(&second, "githubbing", "x").?,
    ));

    try testing.expect(namespaceInto(&buffer, "") == null);
    try testing.expect(namespaceInto(&buffer, "a.b") == null);
}

test "a tool action names the server and the tool, and a tool cannot name the network rule" {
    var buffer: [max_action_bytes]u8 = undefined;

    try testing.expectEqualStrings(
        "mcp.time.tool.get_current_time",
        actionInto(&buffer, "time", "get_current_time").?,
    );
    try testing.expectEqualStrings("mcp.time.network", networkActionInto(&buffer, "time").?);

    const named_network = actionInto(&buffer, "time", "network").?;
    var second: [max_action_bytes]u8 = undefined;
    const network_rule = networkActionInto(&second, "time").?;
    try testing.expect(!std.mem.eql(u8, named_network, network_rule));

    const class = "mcp.time.tool.*";
    try testing.expect(chock_policy.table.patternMatches(class, named_network));
    try testing.expect(!chock_policy.table.patternMatches(class, network_rule));
    try testing.expect(!chock_policy.table.patternMatches(
        class,
        actionInto(&buffer, "timeserver", "x").?,
    ));

    try testing.expect(actionInto(&buffer, "time", "a.b") == null);
    try testing.expect(actionInto(&buffer, "time", "a*") == null);
    try testing.expect(actionInto(&buffer, "time", "") == null);
    try testing.expect(actionInto(&buffer, "time", "a" ** (max_name_bytes + 1)) == null);
    try testing.expect(actionInto(&buffer, "", "a") == null);
}

test "a server that declares a built-in's name fails to load, and takes none of its tools with it" {
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
    try testing.expectEqual(@as(usize, 0), bench.policy.asks);

    inline for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        try testing.expect(shadowsBuiltIn(field.name));
    }
    try testing.expect(!shadowsBuiltIn("get_current_time"));
    try testing.expect(!shadowsBuiltIn(""));
}

test "a name a second server already declared is refused, and the first server keeps it" {
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
    const kept = session.find("search").?;
    try testing.expect(kept.refused == null);
    try testing.expectEqualStrings("one", kept.server);
    try testing.expectEqual(Refusal.already_declared, session.offers.items[1].refused.?);
    try testing.expect(session.offers.items[2].refused == null);

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 2), out.items.len);
}

test "an MCP tool the policy denies is not offered, and calling it runs nothing" {
    const gpa = testing.allocator;

    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.policy.answer = .deny;
    try bench.arm(testing.io);
    try bench.admit("time", &.{.{ .name = "get_current_time" }});

    try testing.expectEqual(@as(usize, 1), bench.policy.asks);
    try testing.expectEqualStrings("mcp.time.tool.get_current_time", bench.policy.asked(0));

    var out: std.ArrayList(tools.Definition) = .empty;
    defer out.deinit(gpa);
    try bench.session.appendDefinitions(gpa, &out);
    try testing.expectEqual(@as(usize, 0), out.items.len);

    const outcome = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expect(std.mem.indexOf(u8, outcome.text, not_offered) != null);
    try testing.expectEqual(@as(usize, 0), bench.fake.calls);
    try testing.expectEqual(@as(usize, 0), bench.judge.asks);

    var permitted = Bench.init(gpa);
    defer permitted.deinit();
    permitted.policy.answer = .allow;
    permitted.fake.answer = .{ .text = "it is noon", .is_error = false };
    try permitted.arm(testing.io);
    try permitted.admit("time", &.{.{ .name = "get_current_time" }});

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try permitted.session.appendDefinitions(gpa, &offered);
    try testing.expectEqual(@as(usize, 1), offered.items.len);
    try testing.expectEqualStrings("get_current_time", offered.items[0].name);

    const ran = (try permitted.session.dispatch(gpa, testing.io, callOf("get_current_time", "{\"tz\":\"UTC\"}"))).?;
    defer gpa.free(ran.text);
    try testing.expect(!ran.is_error);
    try testing.expectEqualStrings("it is noon", ran.text);
    try testing.expectEqual(@as(usize, 1), permitted.fake.calls);
    try testing.expectEqualStrings("{\"tz\":\"UTC\"}", permitted.fake.last_arguments);
}

test "an MCP tool whose row asks is offered, and every call reaches a person before the server" {
    const gpa = testing.allocator;

    const asking = [_]chock_policy.table.Decision{ .ask, .agent_review, .agent_then_human };
    for (asking) |answer| {
        var bench = Bench.init(gpa);
        defer bench.deinit();
        bench.policy.answer = answer;
        bench.fake.answer = .{ .text = "it is noon", .is_error = false };
        try bench.arm(testing.io);
        try bench.admit("time", &.{.{ .name = "get_current_time" }});

        var out: std.ArrayList(tools.Definition) = .empty;
        defer out.deinit(gpa);
        try bench.session.appendDefinitions(gpa, &out);
        try testing.expectEqual(@as(usize, 1), out.items.len);

        bench.judge.answer = .{ .permitted = false, .outcome = "refused_by_user" };
        const refused = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
        defer gpa.free(refused.text);
        try testing.expect(refused.is_error);
        try testing.expect(std.mem.indexOf(u8, refused.text, "refused_by_user") != null);
        try testing.expectEqual(@as(usize, 1), bench.judge.asks);
        try testing.expectEqual(@as(usize, 0), bench.fake.calls);

        try testing.expectEqualStrings("mcp.time.tool.get_current_time", bench.judge.action());
        try testing.expectEqualStrings("get_current_time", bench.judge.tool());
        try testing.expectEqualStrings("call1", bench.judge.callId());

        bench.judge.answer = .{ .permitted = true, .outcome = "approved_by_user" };
        const ran = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
        defer gpa.free(ran.text);
        try testing.expect(!ran.is_error);
        try testing.expectEqualStrings("it is noon", ran.text);
        try testing.expectEqual(@as(usize, 2), bench.judge.asks);
        try testing.expectEqual(@as(usize, 1), bench.fake.calls);
    }
}

test "an MCP tool the table allowed is still asked about on every call, so a later promise binds it" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.policy.answer = .allow;
    bench.fake.answer = .{ .text = "it is noon", .is_error = false };
    try bench.arm(testing.io);
    try bench.admit("time", &.{.{ .name = "get_current_time" }});
    try testing.expect(bench.session.find("get_current_time").?.refused == null);

    const first = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(first.text);
    try testing.expect(!first.is_error);
    try testing.expectEqual(@as(usize, 1), bench.judge.asks);

    bench.judge.answer = .{ .permitted = false, .outcome = "denied_by_policy" };
    const second = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(second.text);
    try testing.expect(second.is_error);
    try testing.expect(std.mem.indexOf(u8, second.text, "denied_by_policy") != null);
    try testing.expectEqual(@as(usize, 2), bench.judge.asks);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);
}

test "an MCP session with nobody to ask runs nothing, and says that is what happened" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.policy.answer = .allow;
    bench.fake.answer = .{ .text = "it is noon", .is_error = false };
    try bench.admit("time", &.{.{ .name = "get_current_time" }});

    const outcome = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expect(std.mem.indexOf(u8, outcome.text, arbiter.not_asked.outcome) != null);
    try testing.expectEqual(@as(usize, 0), bench.fake.calls);
}

test "a session whose log handle has not arrived asks nobody, and the handle is what changes that" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.policy.answer = .allow;
    bench.fake.answer = .{ .text = "it is noon", .is_error = false };
    try bench.admit("time", &.{.{ .name = "get_current_time" }});

    bench.session.asker = .{ .arbiter = bench.judge.arbiterSeam() };
    const early = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(early.text);
    try testing.expect(early.is_error);
    try testing.expect(std.mem.indexOf(u8, early.text, arbiter.not_asked.outcome) != null);
    try testing.expectEqual(@as(usize, 0), bench.judge.asks);
    try testing.expectEqual(@as(usize, 0), bench.fake.calls);

    try bench.openLog(testing.io);
    bench.session.giveLocked(&bench.locked);
    const later = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(later.text);
    try testing.expect(!later.is_error);
    try testing.expectEqual(@as(usize, 1), bench.judge.asks);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);
}

test "a tool whose name is not a name is refused, and no policy key is ever built from it" {
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
    const gpa = testing.allocator;

    const nasty = try textForModel(gpa, "before\x1b[2J\x1b[Hchock: approved\rafter\x07\x00end\nkept\tkept");
    defer gpa.free(nasty);
    try testing.expectEqualStrings("before[2J[Hchock: approvedafterend\nkept\tkept", nasty);
    for (nasty) |byte| {
        if (byte == '\n' or byte == '\t') continue;
        try testing.expect(byte >= 0x20 and byte != 0x7F);
    }

    const japanese = try textForModel(gpa, "型が合いません");
    defer gpa.free(japanese);
    try testing.expectEqualStrings("型が合いません", japanese);

    const binary = try textForModel(gpa, "\xff\xfe\x00\x01 not text at all");
    defer gpa.free(binary);
    try testing.expect(std.unicode.utf8ValidateSlice(binary));
    try testing.expect(std.mem.indexOf(u8, binary, "binary output") != null);

    const long = try gpa.alloc(u8, max_result_bytes * 2);
    defer gpa.free(long);
    @memset(long, 'x');
    const cut = try textForModel(gpa, long);
    defer gpa.free(cut);
    try testing.expect(cut.len < long.len);
    try testing.expect(std.mem.indexOf(u8, cut, "longer than this") != null);
}

test "a tool result really does reach the context through the flattening, and not around it" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.fake.answer = .{ .text = "ok\x1b[2Jgone", .is_error = false };
    try bench.arm(testing.io);
    try bench.admit("s", &.{.{ .name = "t" }});

    const outcome = (try bench.session.dispatch(gpa, testing.io, callOf("t", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expectEqualStrings("ok[2Jgone", outcome.text);
}

test "a server that is late answers this call and still answers the next one" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    try bench.arm(testing.io);
    try bench.admit("s", &.{.{ .name = "t" }});

    bench.fake.call_fails = error.Late;
    const late = (try bench.session.dispatch(gpa, testing.io, callOf("t", "{}"))).?;
    defer gpa.free(late.text);
    try testing.expect(late.is_error);
    try testing.expect(bench.server.failure == null);

    bench.fake.call_fails = null;
    bench.fake.answer = .{ .text = "here", .is_error = false };
    const good = (try bench.session.dispatch(gpa, testing.io, callOf("t", "{}"))).?;
    defer gpa.free(good.text);
    try testing.expect(!good.is_error);
    try testing.expectEqualStrings("here", good.text);
}

test "a server that died answers at once for the rest of the session, and never waits" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    try bench.arm(testing.io);
    try bench.admit("s", &.{.{ .name = "t" }});

    bench.fake.call_fails = error.Gone;
    const first = (try bench.session.dispatch(gpa, testing.io, callOf("t", "{}"))).?;
    defer gpa.free(first.text);
    try testing.expect(first.is_error);
    try testing.expectEqualStrings(start_failed, bench.server.failure.?);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);

    const second = (try bench.session.dispatch(gpa, testing.io, callOf("t", "{}"))).?;
    defer gpa.free(second.text);
    try testing.expect(second.is_error);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);

    var other_host = FakeHost{ .answer = .{ .text = "fine", .is_error = false } };
    var other = Server{ .name = "other", .host = other_host.host() };
    var both = [_]Server{ bench.server, other };
    bench.session.servers = &both;
    try bench.session.admit(&both[1], &.{.{ .name = "u" }}, bench.policy.decider());
    const still = (try bench.session.dispatch(gpa, testing.io, callOf("u", "{}"))).?;
    defer gpa.free(still.text);
    try testing.expect(!still.is_error);
    try testing.expectEqualStrings("fine", still.text);
    _ = &other;
}

test "a tool that says it failed is a result and not a fault of the harness" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    bench.fake.answer = .{ .text = "Invalid timezone", .is_error = true };
    try bench.arm(testing.io);
    try bench.admit("time", &.{.{ .name = "get_current_time" }});

    const outcome = (try bench.session.dispatch(gpa, testing.io, callOf("get_current_time", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("Invalid timezone", outcome.text);
    try testing.expect(bench.server.failure == null);
}

test "a description a server wrote reaches the prompt on one line, and cannot be a wall of text" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();

    const long = "x" ** (max_description_bytes * 2);
    try bench.admit("s", &.{
        .{ .name = "one", .description = "first line\nsecond line\x1b[2J" },
        .{ .name = "two", .description = long },
    });

    const first = bench.session.find("one").?;
    try testing.expectEqualStrings("first line second line [2J", first.definition.description);
    const second = bench.session.find("two").?;
    try testing.expect(second.definition.description.len <= max_description_bytes);
}

test "a schema that is not an object is replaced, and a real one survives the copy" {
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

    arena_state.deinit();
    arena_state = .init(gpa);
    const again = try std.json.Stringify.valueAlloc(arena_state.allocator(), kept.definition.parameters, .{});
    try testing.expect(std.mem.indexOf(u8, again, "timezone") != null);
}
