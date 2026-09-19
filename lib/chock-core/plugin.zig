//! Plugins: tools a third party WebAssembly module supplies, and the rules that
//! hold before the model is offered one. The plugin name in every policy key
//! comes from the project, never from the `name` field the plugin author wrote.

const std = @import("std");

const chock_policy = @import("chock-policy");
const chock_proto = @import("chock-proto");
const core = @import("chock-plugin-core");

const arbiter = @import("arbiter.zig");
const lsp = @import("lsp.zig");
const mcp = @import("mcp.zig");
const plugin_module = @import("plugin_module.zig");
const tools = @import("tools.zig");

pub const action_prefix = "plugin";

/// A tool named `network` must not become a rule about the network.
pub const tool_segment = "tool";

pub const max_name_bytes = 64;

pub const max_tools_per_plugin = 64;

pub const max_capabilities_per_tool = 16;

pub const max_capability_bytes = 128;

/// A tool above this is refused and never carried with an empty schema, which
/// would tell the model the tool takes nothing while the plugin needs a field.
pub const max_schema_bytes = mcp.max_schema_bytes;

pub const locale = "en";

pub const Decider = mcp.Decider;

/// No dot, no `*`, and no NUL. A dot separates the segments of an action name,
/// so a tool with one could name a class of actions an author never wrote.
pub fn nameIsUsable(name: []const u8) bool {
    return mcp.nameIsUsable(name);
}

/// A plugin that declares one of these fails to load whole.
pub fn shadowsBuiltIn(name: []const u8) bool {
    return mcp.shadowsBuiltIn(name);
}

/// No `*`. Only an author writes a class of actions, never a subject of them.
pub fn capabilityIsUsable(action: []const u8) bool {
    if (action.len == 0 or action.len > max_capability_bytes) return false;
    var segments = std.mem.splitScalar(u8, action, '.');
    while (segments.next()) |segment| {
        if (!nameIsUsable(segment)) return false;
    }
    return true;
}

comptime {
    if (!chock_policy.table.patternIsWellFormed("fs.read")) @compileError(
        "the policy table no longer accepts a plain dotted action, so `capabilityIsUsable` " ++
            "is measuring against a language that has moved",
    );

    // `shadowsBuiltIn` and `nameIsUsable` must agree about what a tool name is.
    for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        if (!nameIsUsable(field.name)) @compileError(
            "the built-in tool \"" ++ field.name ++ "\" is not a name this host builds a policy " ++
                "key out of, so a plugin tool of that name would be refused by the shape rule " ++
                "rather than by the rule against shadowing a built-in",
        );
    }
}

/// ```
/// plugin "hello", tool "hello"  ->  plugin.hello.tool.hello
/// ```
pub fn actionInto(buffer: []u8, plugin: []const u8, tool: []const u8) ?[]const u8 {
    if (!nameIsUsable(plugin) or !nameIsUsable(tool)) return null;
    return std.fmt.bufPrint(buffer, action_prefix ++ ".{s}." ++ tool_segment ++ ".{s}", .{
        plugin,
        tool,
    }) catch null;
}

pub const max_action_bytes = action_prefix.len + 1 + max_name_bytes + 1 +
    tool_segment.len + 1 + max_name_bytes;

pub const Failure = enum {
    plugin_name_unusable,
    shadows_built_in,
    already_loaded,
    too_many_tools,

    pub fn text(self: Failure) []const u8 {
        return switch (self) {
            .plugin_name_unusable => "its name holds bytes a plugin name cannot hold",
            .shadows_built_in => "one of its tools is named after one of Chock's own tools",
            .already_loaded => "a plugin of that name is already loaded",
            .too_many_tools => "it declares more tools than this host carries",
        };
    }
};

pub const Refusal = enum {
    name_unusable,
    already_declared,
    capability_unusable,
    /// Only `deny`. Every other answer leaves the tool offered, decided per call.
    policy,
    schema_unusable,
    schema_too_large,
    /// A capability cannot be asked about per call. The capabilities of every
    /// offered tool decide the import set the whole plugin is instantiated
    /// with, once, before any guest code runs, and an import stays given.
    capability_policy,

    pub fn text(self: Refusal) []const u8 {
        return switch (self) {
            .name_unusable => "its name holds bytes a tool name cannot hold",
            .already_declared => "another tool of this session already holds that name",
            .capability_unusable => "it declares a capability that is not an action name",
            .schema_unusable => "its argument schema holds a field this host cannot describe",
            .schema_too_large => "its argument schema is larger than this host carries",
            .policy => "this project's policy denies it",
            .capability_policy => "this project's policy does not allow a capability it declares",
        };
    }
};

pub const Offer = struct {
    plugin: []const u8,
    /// Bare, not prefixed with the plugin. A prefix would hide the collision rule.
    name: []const u8,
    /// `chock_plugin_init` binds one entry per declared tool in this same
    /// order, so the position the host read is the position the guest bound.
    index: u32,
    action: []const u8,
    capabilities: []const []const u8,
    /// Read once, at the start, and never the last word on a call. The tool's
    /// own action is asked again on every call through `Session.asker`.
    decision: chock_policy.table.Decision,
    refused: ?Refusal,
    definition: tools.Definition,
};

pub const Error = error{
    Gone,
    Late,
} || std.mem.Allocator.Error;

pub const Outcome = struct {
    text: []const u8,
    is_error: bool,
};

pub const call_budget_ns: u64 = 60 * std.time.ns_per_s;

pub const start_failed = "its host did not answer, so its tools are not in this session";

pub const not_offered = "that tool is not offered in this session";

/// Where a plugin really runs, which is a process of its own. In the engine
/// this project has, `memPtr` is `mem_base + addr + offset` with no bounds
/// check, and `callIndirect` calls a table slot with neither a bounds check nor
/// a signature check. A module that declared sixteen pages and stored to offset
/// 100000000 dumped core, where wasmtime trapped.
pub const Host = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
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

pub const Loaded = struct {
    name: []const u8,
    host: Host,
    failure: ?[]const u8 = null,
    reported: bool = false,
};

pub const Session = struct {
    arena: std.heap.ArenaAllocator,

    offers: std.ArrayList(Offer) = .empty,

    asker: ?arbiter.Asker = null,

    loaded: std.ArrayList([]const u8) = .empty,

    /// Tool names another supplier already holds. A built-in is never one of
    /// these, because `shadowsBuiltIn` fails the whole plugin instead.
    reserved: []const []const u8 = &.{},

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

    pub fn giveLocked(self: *Session, locked: *arbiter.Locked) void {
        if (self.asker) |*one| one.locked = locked;
    }

    pub fn isEmpty(self: *const Session) bool {
        return self.offers.items.len == 0;
    }

    /// `name` must not come from `record.name`. `record` is borrowed, and
    /// everything kept out of it is copied.
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

        // Read the whole list first, and offer nothing until it is clean.
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
            const built = if (refusal == .name_unusable)
                ""
            else
                actionInto(&buffer, name, tool.name) orelse "";
            const action = try keep.dupe(u8, built);

            const capabilities = if (refusal == null)
                try copyCapabilities(keep, tool.capabilities)
            else
                &.{};

            const own: chock_policy.table.Decision = if (action.len == 0)
                .deny
            else
                policy.decide(tool.name, action);

            var declared: chock_policy.table.Decision = .allow;
            if (refusal == null) {
                for (capabilities) |capability| {
                    declared = declared.intersect(policy.decide(tool.name, capability));
                }
            }

            const decision = own.intersect(declared);
            const priced: ?Refusal = if (declared != .allow)
                .capability_policy
            else if (own == .deny)
                .policy
            else
                null;

            const description = try lsp.flattenMessage(keep, describe(tool.description));

            var schema_refusal: ?Refusal = null;
            const parameters = if (refusal != null)
                try emptyObject(keep)
            else
                try schemaInto(keep, tool.parameters, &schema_refusal) orelse try emptyObject(keep);

            try self.offers.append(gpa, .{
                .plugin = name,
                .name = kept_name,
                .index = @intCast(position),
                .action = action,
                .capabilities = capabilities,
                .decision = decision,
                .refused = refusal orelse schema_refusal orelse priced,
                .definition = .{
                    .name = kept_name,
                    .description = description,
                    .parameters = parameters,
                },
            });
        }
        return null;
    }

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

    /// Null when no plugin declares this name at all, which is the caller's
    /// signal to pass the call on. Never an error return.
    pub fn dispatch(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        call: tools.ToolCall,
    ) std.mem.Allocator.Error!?Outcome {
        const name = call.tool;
        const offer = self.find(name) orelse return null;

        if (offer.refused == .already_declared and !self.declares(name)) return null;

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

        // A call whose arguments do not match could not have run, so nobody is
        // asked about it.
        if (try argumentComplaint(
            arena_state.allocator(),
            offer.definition.parameters,
            call.arguments,
        )) |complaint| return .{
            .text = try std.fmt.allocPrint(gpa, "{s}: {s}", .{ name, complaint }),
            .is_error = true,
        };

        if (try self.refusalFrom(gpa, io, offer, call.call_id)) |text| return .{
            .text = text,
            .is_error = true,
        };

        const answer = loaded.host.call(
            arena_state.allocator(),
            io,
            offer.index,
            name,
            call.arguments,
            call_budget_ns,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // Nothing was lost. `chock_core.helper.Channel.read` leaves the
            // reply in the pipe and the driver keeps its own buffer, so the
            // next call still reaches the plugin.
            error.Late => return .{
                .text = try gpa.dupe(u8, "the plugin did not answer inside the budget"),
                .is_error = true,
            },
            error.Gone => {
                if (loaded.failure == null) loaded.failure = start_failed;
                return .{ .text = try gpa.dupe(u8, loaded.failure.?), .is_error = true };
            },
        };

        return .{ .text = try mcp.textForModel(gpa, answer.text), .is_error = answer.is_error };
    }

    fn refusalFrom(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        offer: *const Offer,
        call_id: []const u8,
    ) std.mem.Allocator.Error!?[]u8 {
        // An offered tool always has an action, which `Broker.request` asserts on.
        std.debug.assert(offer.action.len > 0);

        const own = try self.askAbout(gpa, io, offer, offer.action, call_id);
        if (!own.permitted) return try arbiter.refusalText(gpa, offer.name, own);

        for (offer.capabilities) |capability| {
            const answer = try self.askAbout(gpa, io, offer, capability, call_id);
            if (!answer.permitted) return try arbiter.refusalText(gpa, capability, answer);
        }
        return null;
    }

    fn askAbout(
        self: *Session,
        gpa: std.mem.Allocator,
        io: std.Io,
        offer: *const Offer,
        action: []const u8,
        call_id: []const u8,
    ) std.mem.Allocator.Error!arbiter.Answer {
        const summary = try std.fmt.allocPrint(
            gpa,
            "run the tool \"{s}\" that the plugin \"{s}\" supplies, which needs \"{s}\"",
            .{ offer.name, offer.plugin, action },
        );
        defer gpa.free(summary);

        return arbiter.Asker.decide(self.asker, gpa, io, .{
            .action = action,
            .summary = summary,
            .detail = action,
            .reason = "",
            .tool = offer.name,
            .tool_call_id = call_id,
            .source = "a plugin",
        });
    }

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

fn describe(fields: []const core.LocaleField) []const u8 {
    for (fields) |field| {
        if (std.mem.eql(u8, field.locale, locale)) return field.value;
    }
    return "";
}

/// The host checks, so a plugin only ever runs on arguments that match what it
/// said it takes. A field the schema does not name is left alone.
fn argumentComplaint(
    arena: std.mem.Allocator,
    schema: std.json.Value,
    text: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    const source = if (trimmed.len == 0) "{}" else trimmed;

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, source, .{}) catch
        return "the arguments are not JSON";

    return try objectComplaint(arena, schema, parsed, "");
}

fn objectComplaint(
    arena: std.mem.Allocator,
    schema: std.json.Value,
    value: std.json.Value,
    where: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    if (value != .object) {
        return try std.fmt.allocPrint(arena, "{s}must be a JSON object", .{whose(where)});
    }
    if (schema != .object) return null;

    if (schema.object.get("required")) |required| {
        if (required == .array) {
            for (required.array.items) |one| {
                if (one != .string) continue;
                if (value.object.get(one.string) == null) {
                    return try std.fmt.allocPrint(
                        arena,
                        "{s}leaves out the field \"{s}\", which this tool needs",
                        .{ whose(where), one.string },
                    );
                }
            }
        }
    }

    const properties = schema.object.get("properties") orelse return null;
    if (properties != .object) return null;

    var walk = value.object.iterator();
    while (walk.next()) |entry| {
        const declared = properties.object.get(entry.key_ptr.*) orelse continue;
        if (try valueComplaint(arena, declared, entry.value_ptr.*, entry.key_ptr.*)) |complaint| {
            return complaint;
        }
    }
    return null;
}

fn valueComplaint(
    arena: std.mem.Allocator,
    schema: std.json.Value,
    value: std.json.Value,
    where: []const u8,
) std.mem.Allocator.Error!?[]const u8 {
    if (schema != .object) return null;
    const declared = schema.object.get("type") orelse return null;
    if (declared != .string) return null;

    // Every provider writes a null for an argument the model chose not to set.
    if (value == .null) return null;

    const kind = core.Kind.fromJsonName(declared.string) orelse return null;
    switch (kind) {
        .object => return try objectComplaint(arena, schema, value, where),
        .array => {
            if (value != .array) return try wrongType(arena, where, "an array");
            const items = schema.object.get("items") orelse return null;
            for (value.array.items) |one| {
                if (try valueComplaint(arena, items, one, where)) |complaint| return complaint;
            }
            return null;
        },
        .string => if (value != .string) return try wrongType(arena, where, "a string"),
        .boolean => if (value != .bool) return try wrongType(arena, where, "true or false"),
        .integer => if (value != .integer) return try wrongType(arena, where, "a whole number"),
        .number => if (value != .integer and value != .float) {
            return try wrongType(arena, where, "a number");
        },
    }
    return null;
}

fn wrongType(
    arena: std.mem.Allocator,
    where: []const u8,
    wanted: []const u8,
) std.mem.Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "the field \"{s}\" must be {s}", .{ where, wanted });
}

fn whose(where: []const u8) []const u8 {
    return if (where.len == 0) "the arguments " else "that field ";
}

/// A field name has to be a name. The model writes it back as a JSON key, and a
/// key with a quote, a newline, or a byte that is not UTF-8 gets a 400.
fn schemaInto(
    keep: std.mem.Allocator,
    properties: []const core.Property,
    refusal: *?Refusal,
) std.mem.Allocator.Error!?std.json.Value {
    const copied = try copyProperties(keep, properties, 0, refusal) orelse return null;
    const value = try core.schema.jsonValue(copied, keep);

    const text = std.json.Stringify.valueAlloc(keep, value, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    if (text.len > max_schema_bytes) {
        refusal.* = .schema_too_large;
        return null;
    }
    return value;
}

fn copyProperties(
    keep: std.mem.Allocator,
    properties: []const core.Property,
    depth: u32,
    refusal: *?Refusal,
) std.mem.Allocator.Error!?[]const core.Property {
    if (properties.len > core.max_properties) {
        refusal.* = .schema_unusable;
        return null;
    }

    const out = try keep.alloc(core.Property, properties.len);
    for (out, properties) |*slot, property| {
        if (!nameIsUsable(property.name)) {
            refusal.* = .schema_unusable;
            return null;
        }
        slot.* = .{
            .name = try keep.dupe(u8, property.name),
            .description = try lsp.flattenMessage(keep, property.description),
            .required = property.required,
            .shape = try copyShape(keep, property.shape, depth + 1, refusal) orelse return null,
        };
    }
    return out;
}

fn copyShape(
    keep: std.mem.Allocator,
    shape: core.Shape,
    depth: u32,
    refusal: *?Refusal,
) std.mem.Allocator.Error!?core.Shape {
    if (depth > core.max_schema_depth) {
        refusal.* = .schema_unusable;
        return null;
    }
    switch (shape.kind) {
        .array => {
            const item = shape.items orelse return core.Shape{ .kind = .array };
            const copied = try keep.create(core.Shape);
            copied.* = try copyShape(keep, item.*, depth + 1, refusal) orelse return null;
            return core.Shape{ .kind = .array, .items = copied };
        },
        .object => return core.Shape{
            .kind = .object,
            .properties = try copyProperties(keep, shape.properties, depth, refusal) orelse return null,
        },
        else => return core.Shape{ .kind = shape.kind },
    }
}

/// Never written as `.{}`, which Zig makes a tuple and `std.json.Stringify`
/// writes as `[]`. A real language server found that fault in this project.
fn emptyObject(keep: std.mem.Allocator) std.mem.Allocator.Error!std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, keep, "{}", .{}) catch
        error.OutOfMemory;
}

pub const file_name = mcp.file_name;

pub const max_file_bytes = mcp.max_file_bytes;

pub const max_plugins = 8;

pub const Settings = struct {
    name: []const u8,
    module: []const u8,
};

/// Strict: an unknown field is a refusal, so `.modlue` is not "no module".
const WirePlugin = struct {
    name: []const u8 = "",
    module: []const u8 = "",
};

pub const ParseError = error{
    OutOfMemory,
    InvalidPlugins,
};

pub const LoadError = ParseError || error{
    PluginFileTooLarge,
    ReadFailed,
};

/// The two ZON variants own the syntax trees their message points into, so a
/// caller that receives one must call `deinit`.
pub const Diagnostic = union(enum) {
    file_not_zon: std.zon.parse.Diagnostics,
    block_not_valid: std.zon.parse.Diagnostics,
    not_a_struct_literal,
    too_many_plugins: usize,
    plugin_name_unusable,
    empty_module,
    duplicate_plugin,
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

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
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
        return error.InvalidPlugins;
    }

    const node = try findBlockNode(zoir, diag) orelse return null;

    var zon_diag: std.zon.parse.Diagnostics = .{};
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

    if (wire.len == 0) return null;
    if (wire.len > max_plugins) {
        _ = note(diag, .{ .too_many_plugins = wire.len });
        return error.InvalidPlugins;
    }

    // A mistake in the file is reported when Chock reads the file, never on the
    // turn the model happens to call a tool.
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

fn callOf(name: []const u8, arguments: []const u8) tools.ToolCall {
    return .{ .call_id = "call1", .tool = name, .arguments = arguments };
}

const FakeDecider = struct {
    answer: chock_policy.table.Decision = .allow,
    seen: [32][max_capability_bytes]u8 = @splat(@splat(0)),
    seen_len: [32]usize = @splat(0),
    asks: usize = 0,
    denied: []const u8 = "",
    asking: []const u8 = "",

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
        if (self.asking.len != 0 and std.mem.eql(u8, action, self.asking)) return .ask;
        return self.answer;
    }

    fn asked(self: *const FakeDecider, action: []const u8) bool {
        for (self.seen[0..@min(self.asks, self.seen.len)], self.seen_len[0..@min(self.asks, self.seen.len)]) |entry, length| {
            if (std.mem.eql(u8, entry[0..length], action)) return true;
        }
        return false;
    }
};

/// The tool list has to live somewhere the caller holds. A helper that built
/// `.tools = &.{ ... }` inside itself would answer a pointer to a temporary.
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

fn typedTool(name: []const u8, parameters: []const core.Property) Plugin {
    return .{ .tools = .{.{
        .name = name,
        .description = &.{.{ .locale = "en", .value = "does a thing" }},
        .parameters = parameters,
    }} };
}

const greet_fields: []const core.Property = &.{
    .{ .name = "who", .description = "Who to greet.", .required = true, .shape = .{ .kind = .string } },
    .{ .name = "loudly", .description = "True to shout.", .required = false, .shape = .{ .kind = .boolean } },
};

test "a tool's argument schema is what the model is offered" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var declared = typedTool("greet", greet_fields);
    _ = try session.admit("hello", declared.record(), policy.decider());

    const text = try std.json.Stringify.valueAlloc(
        testing.allocator,
        session.find("greet").?.definition.parameters,
        .{},
    );
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        "{\"type\":\"object\",\"properties\":{\"who\":{\"type\":\"string\"," ++
            "\"description\":\"Who to greet.\"},\"loudly\":{\"type\":\"boolean\"," ++
            "\"description\":\"True to shout.\"}},\"required\":[\"who\"]}",
        text,
    );
}

test "a field name this host will not show the model refuses the tool" {
    for ([_][]const u8{ "who\"s", "who\n", "", "a." ++ "b", "x" ** (max_name_bytes + 1) }) |bad| {
        var session: Session = .init(testing.allocator);
        defer session.deinit();
        var policy: FakeDecider = .{};

        var declared = typedTool("greet", &.{.{
            .name = bad,
            .description = "A field.",
            .required = true,
            .shape = .{ .kind = .string },
        }});
        _ = try session.admit("hello", declared.record(), policy.decider());
        try testing.expectEqual(Refusal.schema_unusable, session.find("greet").?.refused.?);
    }
}

test "a schema larger than this host carries refuses the tool, and does not thin it" {
    var fields: [core.max_properties]core.Property = undefined;
    var names: [core.max_properties][max_name_bytes]u8 = undefined;
    for (&fields, &names, 0..) |*field, *name, index| {
        @memset(name, 'f');
        _ = std.fmt.bufPrint(name[name.len - 3 ..], "{d:0>3}", .{index}) catch unreachable;
        field.* = .{
            .name = name,
            .description = "x" ** 400,
            .required = true,
            .shape = .{ .kind = .string },
        };
    }

    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var declared = typedTool("greet", &fields);
    _ = try session.admit("hello", declared.record(), policy.decider());
    try testing.expectEqual(Refusal.schema_too_large, session.find("greet").?.refused.?);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

test "a field description is flattened and cut like every other third party sentence" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const long = "a\nb" ++ "x" ** (lsp.max_message_bytes * 4);
    var declared = typedTool("greet", &.{.{
        .name = "who",
        .description = long,
        .required = true,
        .shape = .{ .kind = .string },
    }});
    _ = try session.admit("hello", declared.record(), policy.decider());

    const shown = session.find("greet").?.definition.parameters
        .object.get("properties").?.object.get("who").?.object.get("description").?.string;
    try testing.expect(shown.len < long.len);
    try testing.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, shown, '\n'));
    try testing.expectEqualStrings("a b", shown[0..3]);
    try testing.expect(std.mem.endsWith(u8, shown, "longer than this]"));
}

test "a schema that nests past what this host walks refuses the tool" {
    var holder: [core.max_schema_depth + 2]core.Shape = undefined;
    holder[0] = .{ .kind = .string };
    for (holder[1..], 0..) |*slot, before| {
        slot.* = .{ .kind = .array, .items = &holder[before] };
    }

    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var declared = typedTool("greet", &.{.{
        .name = "deep",
        .description = "A field.",
        .required = false,
        .shape = holder[holder.len - 1],
    }});
    _ = try session.admit("hello", declared.record(), policy.decider());
    try testing.expectEqual(Refusal.schema_unusable, session.find("greet").?.refused.?);
}

test "a plugin tool lands on the policy table under a dotted action" {
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
    var one: [max_action_bytes]u8 = undefined;
    const built = actionInto(&one, "hello", "network").?;
    try testing.expectEqualStrings("plugin.hello.tool.network", built);
    try testing.expect(!std.mem.eql(u8, built, "plugin.hello.network"));
}

test "a tool named after a built-in fails the whole plugin to load" {
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
    inline for (@typeInfo(tools.Tool).@"enum".fields) |field| {
        try testing.expect(shadowsBuiltIn(field.name));
    }
    try testing.expect(!shadowsBuiltIn("hello"));
    try testing.expect(!shadowsBuiltIn("read_fil"));
}

test "a declared capability is asked of the policy beside the tool's own action" {
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
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{ .answer = .allow, .denied = "fs.write" };

    _ = try session.admit("hello", oneTool("greet", &.{ "fs.read", "fs.write" }).record(), policy.decider());

    const offer = session.find("greet").?;
    try testing.expectEqual(Refusal.capability_policy, offer.refused.?);
    try testing.expectEqual(chock_policy.table.Decision.deny, offer.decision);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);
}

test "a tool that declares nothing is priced on its own action alone" {
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
    try testing.expect(!policy.asked("fs.*"));
}

test "the plugin name in a policy key is the project's and not the author's" {
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

test "a tool the policy denies is not in the definitions the model reads, and costs nobody a question" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    var policy: FakeDecider = .{ .answer = .deny };

    _ = try bench.session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    try bench.arm(testing.io, "hello");
    try testing.expectEqual(Refusal.policy, bench.session.find("greet").?.refused.?);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(gpa);
    try bench.session.appendDefinitions(gpa, &offered);
    try testing.expectEqual(@as(usize, 0), offered.items.len);

    const outcome = (try bench.session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expect(std.mem.startsWith(u8, outcome.text, not_offered));
    try testing.expectEqual(@as(usize, 0), bench.judge.asks);
    try testing.expectEqual(@as(usize, 0), bench.fake.calls);
}

test "a tool whose row asks is in the definitions the model reads" {
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{ .answer = .allow, .asking = "plugin.hello.tool.greet" };

    _ = try session.admit("hello", oneTool("greet", &.{"fs.read"}).record(), policy.decider());

    const offer = session.find("greet").?;
    try testing.expectEqual(@as(?Refusal, null), offer.refused);
    try testing.expectEqual(chock_policy.table.Decision.ask, offer.decision);

    var offered: std.ArrayList(tools.Definition) = .empty;
    defer offered.deinit(testing.allocator);
    try session.appendDefinitions(testing.allocator, &offered);
    try testing.expectEqual(@as(usize, 1), offered.items.len);
    try testing.expectEqualStrings("greet", offered.items[0].name);
}

test "a tool that takes nothing advertises an object and not an array" {
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
    try testing.expectEqualStrings("{\"type\":\"object\",\"properties\":{},\"required\":[]}", text);
}

test "a description longer than the prompt carries is cut" {
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
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    var many: [max_capabilities_per_tool + 1][]const u8 = @splat("fs.read");
    var declared = oneTool("greet", &many);
    _ = try session.admit("hello", declared.record(), policy.decider());

    try testing.expectEqual(Refusal.capability_unusable, session.find("greet").?.refused.?);
    try testing.expect(!policy.asked("fs.read"));
}

test "a tool name another supplier already holds is refused, and the plugin keeps the rest" {
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
    const gpa = testing.allocator;

    const bad = [_][:0]const u8{
        ".{ .plugins = .{ .{ .name = \"a\", .module = \"\" } } }",
        ".{ .plugins = .{ .{ .name = \"\", .module = \"a.wasm\" } } }",
        ".{ .plugins = .{ .{ .name = \"a.b\", .module = \"a.wasm\" } } }",
        ".{ .plugins = .{ .{ .name = \"a*\", .module = \"a.wasm\" } } }",
        ".{ .plugins = .{ .{ .name = \"a\", .module = \"a.wasm\" }, .{ .name = \"a\", .module = \"b.wasm\" } } }",
        ".{ .plugins = .{ .{ .name = \"a\", .modlue = \"a.wasm\" } } }",
    };
    for (bad) |source| {
        try testing.expectError(error.InvalidPlugins, parse(gpa, source, null));
    }

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
    var session: Session = .init(testing.allocator);
    defer session.deinit();
    var policy: FakeDecider = .{};

    const taken = [_][]const u8{"greet"};
    session.reserved = &taken;
    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());

    try testing.expectEqual(Refusal.already_declared, session.find("greet").?.refused.?);
    try testing.expectEqual(
        @as(?Outcome, null),
        try session.dispatch(testing.allocator, testing.io, callOf("greet", "{}")),
    );

    var denied: Session = .init(testing.allocator);
    defer denied.deinit();
    var deny: FakeDecider = .{ .answer = .deny };
    _ = try denied.admit("hello", oneTool("greet", &.{}).record(), deny.decider());

    const answer = (try denied.dispatch(testing.allocator, testing.io, callOf("greet", "{}"))).?;
    defer testing.allocator.free(answer.text);
    try testing.expect(answer.is_error);
    try testing.expect(std.mem.startsWith(u8, answer.text, not_offered));
}

const FakeHost = struct {
    answer: Outcome = .{ .text = "hello", .is_error = false },
    calls: usize = 0,

    fn host(self: *FakeHost) Host {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = Host.VTable{ .call = callFn };

    fn callFn(
        ptr: *anyopaque,
        arena: std.mem.Allocator,
        io: std.Io,
        index: u32,
        name: []const u8,
        arguments: []const u8,
        budget_ns: u64,
    ) Error!Outcome {
        _ = arena;
        _ = io;
        _ = index;
        _ = name;
        _ = arguments;
        _ = budget_ns;
        const self: *FakeHost = @ptrCast(@alignCast(ptr));
        self.calls += 1;
        return self.answer;
    }
};

const FakeArbiter = struct {
    permits: bool = true,
    refuses: []const u8 = "",
    asks: usize = 0,
    seen: [8][max_capability_bytes]u8 = @splat(@splat(0)),
    seen_len: [8]usize = @splat(0),

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
        if (self.asks < self.seen.len) {
            const length = @min(ask.action.len, self.seen[self.asks].len);
            @memcpy(self.seen[self.asks][0..length], ask.action[0..length]);
            self.seen_len[self.asks] = length;
        }
        self.asks += 1;
        if (self.refuses.len != 0 and std.mem.eql(u8, self.refuses, ask.action))
            return .{ .permitted = false, .outcome = "refused_by_user" };
        if (!self.permits) return .{ .permitted = false, .outcome = "refused_by_user" };
        return .{ .permitted = true, .outcome = "approved_by_user" };
    }

    fn asked(self: *const FakeArbiter, index: usize) []const u8 {
        return self.seen[index][0..self.seen_len[index]];
    }
};

const Bench = struct {
    session: Session,
    fake: FakeHost = .{},
    judge: FakeArbiter = .{},
    loaded: [1]Loaded = undefined,
    backing: chock_proto.storage.Memory = undefined,
    store: chock_proto.storage.Storage = undefined,
    locked: arbiter.Locked = undefined,

    fn init(gpa: std.mem.Allocator) Bench {
        return .{ .session = .init(gpa) };
    }

    /// Separate from `init` because a `Loaded` points at the fake beside it.
    fn arm(self: *Bench, io: std.Io, name: []const u8) !void {
        const gpa = self.session.arena.child_allocator;
        self.loaded[0] = .{ .name = name, .host = self.fake.host() };
        self.session.plugins = &self.loaded;
        self.backing = try chock_proto.storage.Memory.init(gpa, "01PLUGBENCH");
        self.store = self.backing.storage();
        self.locked = try self.store.lock(io);
        self.session.asker = .{ .arbiter = self.judge.arbiterSeam(), .locked = &self.locked };
    }

    fn deinit(self: *Bench) void {
        self.locked.unlock(testing.io) catch {};
        self.store.close(testing.io);
        self.session.deinit();
    }
};

test "a plugin tool whose row asks is asked about on every call, and a refusal never reaches the plugin" {
    const gpa = testing.allocator;

    const asking = [_]chock_policy.table.Decision{ .ask, .agent_review, .agent_then_human };
    for (asking) |answer| {
        var bench = Bench.init(gpa);
        defer bench.deinit();
        var policy: FakeDecider = .{ .answer = answer };

        _ = try bench.session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
        try bench.arm(testing.io, "hello");
        try testing.expectEqual(@as(?Refusal, null), bench.session.find("greet").?.refused);

        var offered: std.ArrayList(tools.Definition) = .empty;
        defer offered.deinit(gpa);
        try bench.session.appendDefinitions(gpa, &offered);
        try testing.expectEqual(@as(usize, 1), offered.items.len);

        bench.judge.permits = false;
        const refused = (try bench.session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
        defer gpa.free(refused.text);
        try testing.expect(refused.is_error);
        try testing.expect(std.mem.indexOf(u8, refused.text, "refused_by_user") != null);
        try testing.expectEqual(@as(usize, 1), bench.judge.asks);
        try testing.expectEqualStrings("plugin.hello.tool.greet", bench.judge.asked(0));
        try testing.expectEqual(@as(usize, 0), bench.fake.calls);

        bench.judge.permits = true;
        const ran = (try bench.session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
        defer gpa.free(ran.text);
        try testing.expect(!ran.is_error);
        try testing.expectEqualStrings("hello", ran.text);
        try testing.expectEqual(@as(usize, 1), bench.fake.calls);
    }
}

test "arguments that do not match the schema never reach the plugin, and nobody is asked" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    var policy: FakeDecider = .{ .answer = .allow };

    var declared = typedTool("greet", greet_fields);
    _ = try bench.session.admit("hello", declared.record(), policy.decider());
    try bench.arm(testing.io, "hello");
    try testing.expectEqual(@as(?Refusal, null), bench.session.find("greet").?.refused);

    const cases = [_]struct { arguments: []const u8, says: []const u8 }{
        .{ .arguments = "{}", .says = "leaves out the field \"who\"" },
        .{ .arguments = "{\"loudly\":true}", .says = "leaves out the field \"who\"" },
        .{ .arguments = "{\"who\":7}", .says = "the field \"who\" must be a string" },
        .{ .arguments = "{\"who\":\"a\",\"loudly\":\"yes\"}", .says = "the field \"loudly\" must be true or false" },
        .{ .arguments = "[]", .says = "the arguments must be a JSON object" },
        .{ .arguments = "not json", .says = "the arguments are not JSON" },
    };
    for (cases) |one| {
        const answer = (try bench.session.dispatch(gpa, testing.io, callOf("greet", one.arguments))).?;
        defer gpa.free(answer.text);
        try testing.expect(answer.is_error);
        try testing.expect(std.mem.indexOf(u8, answer.text, one.says) != null);
        try testing.expect(std.mem.startsWith(u8, answer.text, "greet: "));
    }
    try testing.expectEqual(@as(usize, 0), bench.fake.calls);
    try testing.expectEqual(@as(usize, 0), bench.judge.asks);

    const ran = (try bench.session.dispatch(
        gpa,
        testing.io,
        callOf("greet", "{\"who\":\"Ross\"}"),
    )).?;
    defer gpa.free(ran.text);
    try testing.expect(!ran.is_error);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);
}

test "a field the schema does not name is left alone, and a null is a field left out" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    var policy: FakeDecider = .{ .answer = .allow };

    var declared = typedTool("greet", greet_fields);
    _ = try bench.session.admit("hello", declared.record(), policy.decider());
    try bench.arm(testing.io, "hello");

    for ([_][]const u8{
        "{\"who\":\"Ross\",\"extra\":1}",
        "{\"who\":\"Ross\",\"loudly\":null}",
    }) |arguments| {
        const answer = (try bench.session.dispatch(gpa, testing.io, callOf("greet", arguments))).?;
        defer gpa.free(answer.text);
        try testing.expect(!answer.is_error);
    }
    try testing.expectEqual(@as(usize, 2), bench.fake.calls);
}

test "a tool that takes nothing is called exactly as it was before schemas" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    var policy: FakeDecider = .{ .answer = .allow };

    _ = try bench.session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    try bench.arm(testing.io, "hello");

    for ([_][]const u8{ "{}", "", "   ", "{\"stray\":1}" }) |arguments| {
        const answer = (try bench.session.dispatch(gpa, testing.io, callOf("greet", arguments))).?;
        defer gpa.free(answer.text);
        try testing.expect(!answer.is_error);
        try testing.expectEqualStrings("hello", answer.text);
    }
    try testing.expectEqual(@as(usize, 4), bench.fake.calls);
}

test "a plugin tool the table allowed raises a question for its own action and for each capability it declared" {
    const gpa = testing.allocator;
    var bench = Bench.init(gpa);
    defer bench.deinit();
    var policy: FakeDecider = .{ .answer = .allow };

    _ = try bench.session.admit(
        "hello",
        oneTool("greet", &.{ "fs.read", "fs.write" }).record(),
        policy.decider(),
    );
    try bench.arm(testing.io, "hello");
    try testing.expectEqual(@as(?Refusal, null), bench.session.find("greet").?.refused);

    const ran = (try bench.session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
    defer gpa.free(ran.text);
    try testing.expect(!ran.is_error);
    try testing.expectEqual(@as(usize, 3), bench.judge.asks);
    try testing.expectEqualStrings("plugin.hello.tool.greet", bench.judge.asked(0));
    try testing.expectEqualStrings("fs.read", bench.judge.asked(1));
    try testing.expectEqualStrings("fs.write", bench.judge.asked(2));
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);

    bench.judge.asks = 0;
    bench.judge.refuses = "fs.read";
    const refused = (try bench.session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
    defer gpa.free(refused.text);
    try testing.expect(refused.is_error);
    try testing.expect(std.mem.indexOf(u8, refused.text, "fs.read") != null);
    try testing.expectEqual(@as(usize, 2), bench.judge.asks);
    try testing.expectEqual(@as(usize, 1), bench.fake.calls);
}

test "a plugin session with nobody to ask runs nothing, and says that is what happened" {
    const gpa = testing.allocator;
    var session: Session = .init(gpa);
    defer session.deinit();
    var policy: FakeDecider = .{ .answer = .allow };
    var fake: FakeHost = .{};

    _ = try session.admit("hello", oneTool("greet", &.{}).record(), policy.decider());
    var loaded = [_]Loaded{.{ .name = "hello", .host = fake.host() }};
    session.plugins = &loaded;

    const outcome = (try session.dispatch(gpa, testing.io, callOf("greet", "{}"))).?;
    defer gpa.free(outcome.text);
    try testing.expect(outcome.is_error);
    try testing.expect(std.mem.indexOf(u8, outcome.text, arbiter.not_asked.outcome) != null);
    try testing.expectEqual(@as(usize, 0), fake.calls);
}
