//! Lifecycle hooks: a program a project runs at a point in a session, for
//! example a check before the agent writes a file.
//!
//! A hook is not an escape hatch. It names an argv and never a shell line, so
//! nothing parses a quote or a semicolon. Its run goes through the gate every
//! tool call goes through, so the same `exec.*` rule decides it, the same
//! sandbox holds it, and the log records it. What a hook can do to a session
//! is to refuse something or to say something. There is no case that permits,
//! so a hook cannot widen what a policy decided.

const std = @import("std");

const frontmatter = @import("frontmatter.zig");
const tools = @import("tools.zig");

pub const max_hooks: usize = 8;

pub const max_name_bytes: usize = 64;

pub const max_argv: usize = 16;

pub const max_argument_bytes: usize = 4096;

pub const default_timeout_ms: u32 = 30_000;

pub const max_timeout_ms: u32 = 600_000;

/// What the agent is told of a hook's output, past which the rest is dropped.
pub const max_note_bytes: usize = 2048;

pub const Trigger = enum {
    session_start,
    session_end,
    tool_before,
    tool_after,

    pub fn wireName(self: Trigger) []const u8 {
        return switch (self) {
            .session_start => "session.start",
            .session_end => "session.end",
            .tool_before => "tool.before",
            .tool_after => "tool.after",
        };
    }

    pub fn fromWireName(text: []const u8) ?Trigger {
        inline for (@typeInfo(Trigger).@"enum".field_values) |value| {
            const one: Trigger = @enumFromInt(value);
            if (std.mem.eql(u8, text, one.wireName())) return one;
        }
        return null;
    }

    /// Whether this trigger is about one tool call, which is what makes a
    /// `tool` name meaningful on a hook.
    pub fn isAboutATool(self: Trigger) bool {
        return self == .tool_before or self == .tool_after;
    }
};

/// A fact a hook asks for. Each one reaches the program as two more arguments,
/// `--<name>` and the value, because an argv has no shell to read them.
pub const Input = enum {
    trigger,
    tool,
    action,
    session,

    pub fn wireName(self: Input) []const u8 {
        return @tagName(self);
    }

    pub fn fromWireName(text: []const u8) ?Input {
        inline for (@typeInfo(Input).@"enum".field_values) |value| {
            const one: Input = @enumFromInt(value);
            if (std.mem.eql(u8, text, one.wireName())) return one;
        }
        return null;
    }
};

pub const Output = enum {
    /// The run is logged and changes nothing.
    ignore,
    /// A run that ends with anything but zero refuses what the hook fired on.
    refuse,
    /// What the run wrote reaches the agent.
    note,

    pub fn wireName(self: Output) []const u8 {
        return @tagName(self);
    }

    pub fn fromWireName(text: []const u8) ?Output {
        inline for (@typeInfo(Output).@"enum".field_values) |value| {
            const one: Output = @enumFromInt(value);
            if (std.mem.eql(u8, text, one.wireName())) return one;
        }
        return null;
    }

    /// A hook can only refuse something that has not happened yet, and can
    /// only tell the agent something where the agent is listening.
    pub fn allowedFor(self: Output, trigger: Trigger) bool {
        return switch (self) {
            .ignore => true,
            .refuse => trigger == .session_start or trigger == .tool_before,
            .note => trigger.isAboutATool(),
        };
    }
};

pub const Hook = struct {
    name: []const u8,
    trigger: Trigger,
    /// The one tool this hook is about. Empty means every tool.
    tool: []const u8 = "",
    inputs: []const Input = &.{},
    argv: []const []const u8,
    timeout_ms: u32 = default_timeout_ms,
    output: Output = .ignore,

    pub fn matches(self: Hook, trigger: Trigger, tool: []const u8) bool {
        if (self.trigger != trigger) return false;
        if (self.tool.len == 0) return true;
        return std.mem.eql(u8, self.tool, tool);
    }
};

/// What a hook is told about the moment it fired.
pub const Moment = struct {
    trigger: Trigger,
    tool: []const u8 = "",
    action: []const u8 = "",
    session: []const u8 = "",
    /// What the moment was, for the call id: the call a tool trigger fired on,
    /// or the trigger's own name where no call is involved.
    about: []const u8 = "",

    pub fn aboutOr(self: Moment) []const u8 {
        return if (self.about.len != 0) self.about else self.trigger.wireName();
    }

    fn valueOf(self: Moment, input: Input) []const u8 {
        return switch (input) {
            .trigger => self.trigger.wireName(),
            .tool => self.tool,
            .action => self.action,
            .session => self.session,
        };
    }
};

/// The whole argv a hook runs with: what it named, then two arguments for each
/// input it asked for. An input with nothing in it is left out, so a program
/// never has to tell an empty value from a missing one.
///
/// Every element is owned, so `freeArgv` frees the lot.
pub fn argvFor(
    allocator: std.mem.Allocator,
    hook: Hook,
    moment: Moment,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| allocator.free(one);
        out.deinit(allocator);
    }

    for (hook.argv) |one| try out.append(allocator, try allocator.dupe(u8, one));
    for (hook.inputs) |input| {
        const value = moment.valueOf(input);
        if (value.len == 0) continue;
        try out.append(allocator, try std.fmt.allocPrint(allocator, "--{s}", .{input.wireName()}));
        try out.append(allocator, try allocator.dupe(u8, value));
    }
    return out.toOwnedSlice(allocator);
}

pub fn freeArgv(allocator: std.mem.Allocator, argv: []const []const u8) void {
    for (argv) |one| allocator.free(one);
    allocator.free(argv);
}

/// The `run_command` arguments a hook's run is made of. A hook goes through
/// the gate as a command, so what it runs is written the way a command is.
pub fn argumentsFor(
    allocator: std.mem.Allocator,
    hook: Hook,
    moment: Moment,
) std.mem.Allocator.Error![]u8 {
    const argv = try argvFor(allocator, hook, moment);
    defer freeArgv(allocator, argv);

    return std.json.Stringify.valueAlloc(allocator, .{
        .argv = argv,
        .timeout_ms = hook.timeout_ms,
    }, .{});
}

/// A hook that ran, and what it did to the session.
pub const Said = struct {
    /// The hook refuses what it fired on.
    refused: bool = false,
    /// What the hook wrote, where its output reaches the agent. Borrowed from
    /// the result the runner gave.
    note: []const u8 = "",
};

/// Every hook that matched, folded into one answer: any refusal refuses, and
/// the notes are kept in the order the hooks are written.
pub const Folded = struct {
    refused_by: []const u8 = "",
    ran: usize = 0,
};

pub fn refusalText(
    allocator: std.mem.Allocator,
    hook_name: []const u8,
    trigger: Trigger,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "the {s} hook \"{s}\" refused this, because the program it runs ended with an error. " ++
            "This is the project's own check and not a policy rule, so there is nothing to ask " ++
            "for: put right what the check is about.",
        .{ trigger.wireName(), hook_name },
    );
}

/// A hook's run reaches the log as a tool call of its own, under the id
/// `hook:<name>:<about>`. `about` is the call the hook fired on, or the
/// trigger where no call is involved, so two runs of one hook never share an
/// id: an editor keys its view of a call on that id.
pub const call_id_prefix = "hook:";

pub fn callIdFor(
    allocator: std.mem.Allocator,
    name: []const u8,
    about: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, call_id_prefix ++ "{s}:{s}", .{ name, about });
}

/// The hook a call id names, for a line a person reads. Null for every other
/// call, which is how the agent's own calls are told apart.
pub fn nameInCallId(call_id: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, call_id, call_id_prefix)) return null;
    const rest = call_id[call_id_prefix.len..];
    const end = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    return if (end == 0) null else rest[0..end];
}

pub fn findIn(hooks: []const Hook, name: []const u8) ?Hook {
    for (hooks) |one| {
        if (std.mem.eql(u8, one.name, name)) return one;
    }
    return null;
}

/// Whether any hook at all is about this trigger, so a session with none pays
/// nothing at the points where hooks fire.
pub fn anyFor(hooks: []const Hook, trigger: Trigger) bool {
    for (hooks) |one| {
        if (one.trigger == trigger) return true;
    }
    return false;
}

// The `hooks` block of a project's own `chock.zon`, read here beside the
// shape it reads into, the way `mcp.zig` reads its own block.

pub const file_name = "chock.zon";

pub const max_file_bytes = 1 << 20;

pub const block_name = "hooks";

pub const max_entries = max_hooks;

pub const Block = struct {
    hooks: []const Hook = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        for (self.hooks) |one| {
            gpa.free(one.name);
            if (one.tool.len != 0) gpa.free(one.tool);
            for (one.argv) |word| gpa.free(word);
            gpa.free(one.argv);
            gpa.free(one.inputs);
        }
        gpa.free(self.hooks);
        self.* = undefined;
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidHooks,
};

pub const LoadError = ParseError || error{
    HooksFileTooLarge,
    ReadFailed,
};

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Named = struct {
        name: []const u8,
        text: []const u8,
    };

    pub const Fault = union(enum) {
        not_a_struct_literal,
        not_a_list,
        entry_not_a_struct,
        too_many_entries: usize,
        unknown_field: []const u8,
        name_missing,
        name_not_a_string,
        name_too_long: []const u8,
        name_not_the_shape: []const u8,
        name_already_taken: []const u8,
        on_missing,
        on_not_a_string,
        on_unknown: []const u8,
        tool_not_a_string,
        tool_unknown: []const u8,
        tool_without_a_tool_trigger: Named,
        run_missing,
        run_not_a_list,
        run_empty,
        run_not_strings,
        run_too_long: usize,
        argument_too_long: usize,
        timeout_not_a_number,
        timeout_too_long: usize,
        output_not_a_string,
        output_unknown: []const u8,
        output_not_for_this_trigger: Named,
        inputs_not_a_list,
        input_not_a_string,
        input_unknown: []const u8,
        file_too_large: usize,
        read_failed: anyerror,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .unknown_field,
            .name_too_long,
            .name_not_the_shape,
            .name_already_taken,
            .on_unknown,
            .tool_unknown,
            .output_unknown,
            .input_unknown,
            => |text| gpa.free(text),
            .tool_without_a_tool_trigger, .output_not_for_this_trigger => |named| {
                gpa.free(named.name);
                gpa.free(named.text);
            },
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .not_a_list => try writer.print(
                "{s}: the hooks block must hold a list of hooks",
                .{self.source},
            ),
            .entry_not_a_struct => try writer.print(
                "{s}: every hook must be a struct literal",
                .{self.source},
            ),
            .too_many_entries => |bound| try writer.print(
                "{s}: the hooks block holds more than {d} hooks",
                .{ self.source, bound },
            ),
            .unknown_field => |field| try writer.print(
                "{s}: a hook names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .name_missing => try writer.print(
                "{s}: every hook needs a name, which is what a refusal and the log say",
                .{self.source},
            ),
            .name_not_a_string => try writer.print(
                "{s}: a hook's name must be a string",
                .{self.source},
            ),
            .name_too_long => |text| try writer.print(
                "{s}: the hook name \"{s}\" is longer than {d} characters",
                .{ self.source, text, max_name_bytes },
            ),
            .name_not_the_shape => |text| try writer.print(
                "{s}: \"{s}\" cannot name a hook. A name holds lowercase letters, digits and " ++
                    "single hyphens between them, because it is read back out of the call id " ++
                    "the hook's own run carries.",
                .{ self.source, text },
            ),
            .name_already_taken => |text| try writer.print(
                "{s}: two hooks are named \"{s}\", and a refusal could then name either",
                .{ self.source, text },
            ),
            .on_missing => try writer.print(
                "{s}: every hook needs an on, naming when it runs",
                .{self.source},
            ),
            .on_not_a_string => try writer.print(
                "{s}: a hook's on must be a string",
                .{self.source},
            ),
            .on_unknown => |text| try writer.print(
                "{s}: no trigger is named \"{s}\". They are {s}.",
                .{ self.source, text, trigger_list },
            ),
            .tool_not_a_string => try writer.print(
                "{s}: a hook's tool must be a string",
                .{self.source},
            ),
            .tool_unknown => |text| try writer.print(
                "{s}: no tool is named \"{s}\", so the hook would never run",
                .{ self.source, text },
            ),
            .tool_without_a_tool_trigger => |named| try writer.print(
                "{s}: the hook \"{s}\" names a tool and runs at {s}, which is not about one " ++
                    "tool call. Take the tool out, or run it at tool.before or tool.after.",
                .{ self.source, named.name, named.text },
            ),
            .run_missing => try writer.print(
                "{s}: every hook needs a run, naming the program and its arguments",
                .{self.source},
            ),
            .run_not_a_list => try writer.print(
                "{s}: a hook's run must be a list of strings, so there is no line for a shell " ++
                    "to read. Write .{{ \"sh\", \"-c\", \"...\" }} and the shell is yours to " ++
                    "name, under the same policy as any other program.",
                .{self.source},
            ),
            .run_empty => try writer.print(
                "{s}: a hook's run names no program",
                .{self.source},
            ),
            .run_not_strings => try writer.print(
                "{s}: every word of a hook's run must be a string",
                .{self.source},
            ),
            .run_too_long => |bound| try writer.print(
                "{s}: a hook's run holds more than {d} words",
                .{ self.source, bound },
            ),
            .argument_too_long => |bound| try writer.print(
                "{s}: a word of a hook's run is longer than {d} bytes",
                .{ self.source, bound },
            ),
            .timeout_not_a_number => try writer.print(
                "{s}: a hook's timeout_ms must be a whole number of milliseconds",
                .{self.source},
            ),
            .timeout_too_long => |bound| try writer.print(
                "{s}: a hook's timeout_ms is longer than {d}",
                .{ self.source, bound },
            ),
            .output_not_a_string => try writer.print(
                "{s}: a hook's output must be a string",
                .{self.source},
            ),
            .output_unknown => |text| try writer.print(
                "{s}: no output is named \"{s}\". They are ignore, refuse and note. There is " ++
                    "none that permits, because a hook may narrow what a policy decided and " ++
                    "never widen it.",
                .{ self.source, text },
            ),
            .output_not_for_this_trigger => |named| try writer.print(
                "{s}: the hook \"{s}\" cannot {s} at that trigger. refuse needs session.start " ++
                    "or tool.before, where the thing has not happened yet, and note needs " ++
                    "tool.before or tool.after, where a tool result can carry it.",
                .{ self.source, named.name, named.text },
            ),
            .inputs_not_a_list => try writer.print(
                "{s}: a hook's inputs must be a list of strings",
                .{self.source},
            ),
            .input_not_a_string => try writer.print(
                "{s}: every input of a hook must be a string",
                .{self.source},
            ),
            .input_unknown => |text| try writer.print(
                "{s}: no input is named \"{s}\". They are {s}.",
                .{ self.source, text, input_list },
            ),
            .file_too_large => |bound| try writer.print(
                "{s}: the file is larger than {d} bytes",
                .{ self.source, bound },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ self.source, err },
            ),
        }
    }
};

const trigger_list = "session.start, session.end, tool.before and tool.after";

const input_list = "trigger, tool, action and session";

fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Block {
    return parseFrom(gpa, source, file_name, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    defer zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        _ = note(diag, source_name, .not_a_struct_literal);
        return error.InvalidHooks;
    }

    const node = try findBlock(zoir, source_name, diag) orelse return .{};
    return readHooks(gpa, zoir, node, source_name, diag);
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Block {
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
        error.FileNotFound, error.NotDir => return .{},
        error.StreamTooLong => {
            _ = note(diag, file_name, .{ .file_too_large = max_file_bytes });
            return error.HooksFileTooLarge;
        },
        else => {
            _ = note(diag, file_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parseFrom(gpa, source, file_name, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(&zoir), block_name)) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidHooks;
        },
    }
}

fn readHooks(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return .{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .not_a_list);
            return error.InvalidHooks;
        },
    };

    if (items.len > max_entries) {
        _ = note(diag, source_name, .{ .too_many_entries = max_entries });
        return error.InvalidHooks;
    }

    var out: std.ArrayList(Hook) = .empty;
    errdefer {
        for (out.items) |one| freeHook(gpa, one);
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        const one = try readHook(gpa, zoir, items.at(@intCast(index)), source_name, diag);
        if (findIn(out.items, one.name) != null) {
            const taken = try gpa.dupe(u8, one.name);
            freeHook(gpa, one);
            _ = note(diag, source_name, .{ .name_already_taken = taken });
            return error.InvalidHooks;
        }
        try out.append(gpa, one);
    }
    return .{ .hooks = try out.toOwnedSlice(gpa) };
}

fn freeHook(gpa: std.mem.Allocator, one: Hook) void {
    gpa.free(one.name);
    if (one.tool.len != 0) gpa.free(one.tool);
    for (one.argv) |word| gpa.free(word);
    gpa.free(one.argv);
    gpa.free(one.inputs);
}

fn readHook(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Hook {
    const fields = switch (node.get(&zoir)) {
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .entry_not_a_struct);
            return error.InvalidHooks;
        },
    };

    var name: ?[]const u8 = null;
    var trigger: ?Trigger = null;
    var tool: ?[]const u8 = null;
    var argv: ?[]const []const u8 = null;
    var inputs: ?[]const Input = null;
    var timeout_ms: u32 = default_timeout_ms;
    var output: Output = .ignore;
    errdefer {
        if (name) |held| gpa.free(held);
        if (tool) |held| gpa.free(held);
        if (argv) |held| {
            for (held) |word| gpa.free(word);
            gpa.free(held);
        }
        if (inputs) |held| gpa.free(held);
    }

    for (fields.names, 0..) |field_id, index| {
        const field = field_id.get(&zoir);
        const value = fields.vals.at(@intCast(index));
        if (std.mem.eql(u8, field, "name")) {
            name = try readString(gpa, zoir, value, source_name, .name_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "on")) {
            const text = try readString(gpa, zoir, value, source_name, .on_not_a_string, diag);
            defer gpa.free(text);
            trigger = Trigger.fromWireName(text) orelse {
                _ = note(diag, source_name, .{ .on_unknown = try gpa.dupe(u8, text) });
                return error.InvalidHooks;
            };
        } else if (std.mem.eql(u8, field, "tool")) {
            const text = try readString(gpa, zoir, value, source_name, .tool_not_a_string, diag);
            if (std.meta.stringToEnum(tools.Tool, text) == null) {
                _ = note(diag, source_name, .{ .tool_unknown = text });
                return error.InvalidHooks;
            }
            tool = text;
        } else if (std.mem.eql(u8, field, "run")) {
            argv = try readArgv(gpa, zoir, value, source_name, diag);
        } else if (std.mem.eql(u8, field, "inputs")) {
            inputs = try readInputs(gpa, zoir, value, source_name, diag);
        } else if (std.mem.eql(u8, field, "timeout_ms")) {
            timeout_ms = try readTimeout(zoir, value, source_name, diag);
        } else if (std.mem.eql(u8, field, "output")) {
            const text = try readString(gpa, zoir, value, source_name, .output_not_a_string, diag);
            defer gpa.free(text);
            output = Output.fromWireName(text) orelse {
                _ = note(diag, source_name, .{ .output_unknown = try gpa.dupe(u8, text) });
                return error.InvalidHooks;
            };
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidHooks;
        }
    }

    const held_name = name orelse {
        _ = note(diag, source_name, .name_missing);
        return error.InvalidHooks;
    };
    if (held_name.len > max_name_bytes) {
        _ = note(diag, source_name, .{ .name_too_long = try gpa.dupe(u8, held_name) });
        return error.InvalidHooks;
    }
    if (!frontmatter.isTheShape(held_name)) {
        _ = note(diag, source_name, .{ .name_not_the_shape = try gpa.dupe(u8, held_name) });
        return error.InvalidHooks;
    }

    const held_trigger = trigger orelse {
        _ = note(diag, source_name, .on_missing);
        return error.InvalidHooks;
    };
    const held_argv = argv orelse {
        _ = note(diag, source_name, .run_missing);
        return error.InvalidHooks;
    };

    if (tool != null and !held_trigger.isAboutATool()) {
        _ = note(diag, source_name, .{ .tool_without_a_tool_trigger = .{
            .name = try gpa.dupe(u8, held_name),
            .text = try gpa.dupe(u8, held_trigger.wireName()),
        } });
        return error.InvalidHooks;
    }

    if (!output.allowedFor(held_trigger)) {
        _ = note(diag, source_name, .{ .output_not_for_this_trigger = .{
            .name = try gpa.dupe(u8, held_name),
            .text = try gpa.dupe(u8, output.wireName()),
        } });
        return error.InvalidHooks;
    }

    return .{
        .name = held_name,
        .trigger = held_trigger,
        .tool = tool orelse "",
        .inputs = inputs orelse try gpa.alloc(Input, 0),
        .argv = held_argv,
        .timeout_ms = timeout_ms,
        .output = output,
    };
}

fn readArgv(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const []const u8 {
    const items = switch (node.get(&zoir)) {
        .array_literal => |list| list,
        .empty_literal => {
            _ = note(diag, source_name, .run_empty);
            return error.InvalidHooks;
        },
        else => {
            _ = note(diag, source_name, .run_not_a_list);
            return error.InvalidHooks;
        },
    };

    if (items.len == 0) {
        _ = note(diag, source_name, .run_empty);
        return error.InvalidHooks;
    }
    if (items.len > max_argv) {
        _ = note(diag, source_name, .{ .run_too_long = max_argv });
        return error.InvalidHooks;
    }

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        const text = switch (items.at(@intCast(index)).get(&zoir)) {
            .string_literal => |one| one,
            else => {
                _ = note(diag, source_name, .run_not_strings);
                return error.InvalidHooks;
            },
        };
        if (text.len > max_argument_bytes) {
            _ = note(diag, source_name, .{ .argument_too_long = max_argument_bytes });
            return error.InvalidHooks;
        }
        try out.append(gpa, try gpa.dupe(u8, text));
    }
    return out.toOwnedSlice(gpa);
}

fn readInputs(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const Input {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return gpa.alloc(Input, 0),
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .inputs_not_a_list);
            return error.InvalidHooks;
        },
    };

    var out: std.ArrayList(Input) = .empty;
    errdefer out.deinit(gpa);

    for (0..items.len) |index| {
        const text = switch (items.at(@intCast(index)).get(&zoir)) {
            .string_literal => |one| one,
            else => {
                _ = note(diag, source_name, .input_not_a_string);
                return error.InvalidHooks;
            },
        };
        const one = Input.fromWireName(text) orelse {
            _ = note(diag, source_name, .{ .input_unknown = try gpa.dupe(u8, text) });
            return error.InvalidHooks;
        };
        try out.append(gpa, one);
    }
    return out.toOwnedSlice(gpa);
}

fn readTimeout(
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!u32 {
    const held = switch (node.get(&zoir)) {
        .int_literal => |one| switch (one) {
            .small => |small| small,
            else => {
                _ = note(diag, source_name, .{ .timeout_too_long = max_timeout_ms });
                return error.InvalidHooks;
            },
        },
        else => {
            _ = note(diag, source_name, .timeout_not_a_number);
            return error.InvalidHooks;
        },
    };
    if (held <= 0) {
        _ = note(diag, source_name, .timeout_not_a_number);
        return error.InvalidHooks;
    }
    if (held > max_timeout_ms) {
        _ = note(diag, source_name, .{ .timeout_too_long = max_timeout_ms });
        return error.InvalidHooks;
    }
    return @intCast(held);
}

fn readString(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    fault: Diagnostic.Fault,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    switch (node.get(&zoir)) {
        .string_literal => |text| return gpa.dupe(u8, text),
        else => {
            _ = note(diag, source_name, fault);
            return error.InvalidHooks;
        },
    }
}

const testing = std.testing;

test "a trigger and its wire name agree in both directions" {
    inline for (@typeInfo(Trigger).@"enum".field_values) |value| {
        const one: Trigger = @enumFromInt(value);
        try testing.expectEqual(one, Trigger.fromWireName(one.wireName()).?);
    }
    try testing.expect(Trigger.fromWireName("tool.during") == null);
    try testing.expect(Trigger.fromWireName("") == null);

    try testing.expect(Trigger.tool_before.isAboutATool());
    try testing.expect(Trigger.tool_after.isAboutATool());
    try testing.expect(!Trigger.session_start.isAboutATool());
}

test "an output is allowed only where it could mean something" {
    try testing.expect(Output.refuse.allowedFor(.session_start));
    try testing.expect(Output.refuse.allowedFor(.tool_before));
    // The thing already happened, so there is nothing left to refuse.
    try testing.expect(!Output.refuse.allowedFor(.tool_after));
    try testing.expect(!Output.refuse.allowedFor(.session_end));

    try testing.expect(Output.note.allowedFor(.tool_before));
    try testing.expect(Output.note.allowedFor(.tool_after));
    // No tool result is open to carry it.
    try testing.expect(!Output.note.allowedFor(.session_start));
    try testing.expect(!Output.note.allowedFor(.session_end));

    inline for (@typeInfo(Trigger).@"enum".field_values) |value| {
        try testing.expect(Output.ignore.allowedFor(@enumFromInt(value)));
    }
}

test "there is no output that permits, so a hook cannot widen a decision" {
    inline for (@typeInfo(Output).@"enum".field_names) |name| {
        try testing.expect(!std.mem.eql(u8, name, "allow"));
        try testing.expect(!std.mem.eql(u8, name, "permit"));
    }
    try testing.expectEqual(@as(usize, 3), @typeInfo(Output).@"enum".field_names.len);
}

test "a hook is about one tool or about every tool" {
    const every = Hook{
        .name = "watch",
        .trigger = .tool_before,
        .argv = &.{"./check"},
    };
    try testing.expect(every.matches(.tool_before, "write_file"));
    try testing.expect(every.matches(.tool_before, "run_command"));
    try testing.expect(!every.matches(.tool_after, "write_file"));

    const one = Hook{
        .name = "watch-writes",
        .trigger = .tool_before,
        .tool = "write_file",
        .argv = &.{"./check"},
    };
    try testing.expect(one.matches(.tool_before, "write_file"));
    try testing.expect(!one.matches(.tool_before, "run_command"));
}

test "the inputs a hook asked for reach it as arguments, and an empty one does not" {
    const gpa = testing.allocator;

    const hook = Hook{
        .name = "check",
        .trigger = .tool_before,
        .inputs = &.{ .trigger, .tool, .action, .session },
        .argv = &.{ "./scripts/check", "--quiet" },
    };

    const argv = try argvFor(gpa, hook, .{
        .trigger = .tool_before,
        .tool = "write_file",
        .action = "file.write",
    });
    defer freeArgv(gpa, argv);

    try testing.expectEqual(@as(usize, 8), argv.len);
    try testing.expectEqualStrings("./scripts/check", argv[0]);
    try testing.expectEqualStrings("--quiet", argv[1]);
    try testing.expectEqualStrings("--trigger", argv[2]);
    try testing.expectEqualStrings("tool.before", argv[3]);
    try testing.expectEqualStrings("--tool", argv[4]);
    try testing.expectEqualStrings("write_file", argv[5]);
    try testing.expectEqualStrings("--action", argv[6]);
    try testing.expectEqualStrings("file.write", argv[7]);
}

test "a hook's run is written as a command, with every argument quoted" {
    const gpa = testing.allocator;

    const hook = Hook{
        .name = "check",
        .trigger = .tool_before,
        .inputs = &.{.tool},
        .argv = &.{"./check"},
    };

    const arguments = try argumentsFor(gpa, hook, .{
        .trigger = .tool_before,
        .tool = "write_file",
    });
    defer gpa.free(arguments);

    try testing.expectEqualStrings(
        "{\"argv\":[\"./check\",\"--tool\",\"write_file\"],\"timeout_ms\":30000}",
        arguments,
    );
}

test "an argument that holds a quote is written as text and never as a line" {
    const gpa = testing.allocator;

    // Nothing runs a shell, and the writer still has to keep the bytes whole.
    const hook = Hook{
        .name = "odd",
        .trigger = .tool_before,
        .argv = &.{ "./check", "a \"quoted\" word; rm -rf /" },
    };

    const arguments = try argumentsFor(gpa, hook, .{ .trigger = .tool_before });
    defer gpa.free(arguments);

    try testing.expect(std.mem.startsWith(
        u8,
        arguments,
        "{\"argv\":[\"./check\",\"a \\\"quoted\\\" word; rm -rf /\"]",
    ));
}

test "a session with no hook for a trigger pays nothing at that point" {
    const hooks = [_]Hook{.{
        .name = "check",
        .trigger = .tool_before,
        .argv = &.{"./check"},
    }};

    try testing.expect(anyFor(&hooks, .tool_before));
    try testing.expect(!anyFor(&hooks, .tool_after));
    try testing.expect(!anyFor(&hooks, .session_start));
    try testing.expect(!anyFor(&.{}, .tool_before));

    try testing.expect(findIn(&hooks, "check") != null);
    try testing.expect(findIn(&hooks, "other") == null);
}

test "a call id says which hook asked and what about, and two runs never share one" {
    const gpa = testing.allocator;

    const first = try callIdFor(gpa, "tests-pass", "call1");
    defer gpa.free(first);
    const second = try callIdFor(gpa, "tests-pass", "call2");
    defer gpa.free(second);

    try testing.expectEqualStrings("hook:tests-pass:call1", first);
    try testing.expect(!std.mem.eql(u8, first, second));

    try testing.expectEqualStrings("tests-pass", nameInCallId(first).?);
    try testing.expectEqualStrings("tests-pass", nameInCallId(second).?);

    try testing.expect(nameInCallId("call1") == null);
    try testing.expect(nameInCallId("hook:") == null);
    try testing.expect(nameInCallId("hook::call1") == null);
    try testing.expect(nameInCallId("") == null);
}

test "a refusal names the hook and says there is nothing to ask for" {
    const gpa = testing.allocator;

    const text = try refusalText(gpa, "tests-pass", .tool_before);
    defer gpa.free(text);

    try testing.expect(std.mem.indexOf(u8, text, "tests-pass") != null);
    try testing.expect(std.mem.indexOf(u8, text, "tool.before") != null);
    try testing.expect(std.mem.indexOf(u8, text, "nothing to ask") != null);
}

test "a file with no hooks block holds none" {
    const gpa = testing.allocator;

    var none = try parse(gpa, ".{}", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.hooks.len);

    var other = try parse(gpa, ".{ .policy = .{} }", null);
    defer other.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), other.hooks.len);

    var empty = try parse(gpa, ".{ .hooks = .{} }", null);
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.hooks.len);
}

test "a hook reads with its trigger, its argv, and the defaults for the rest" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{
        \\    .hooks = .{
        \\        .{
        \\            .name = "tests-pass",
        \\            .on = "tool.before",
        \\            .tool = "request_action",
        \\            .run = .{ "zig", "build", "test" },
        \\            .inputs = .{ "tool", "action" },
        \\            .timeout_ms = 120000,
        \\            .output = "refuse",
        \\        },
        \\    },
        \\}
    , null);
    defer block.deinit(gpa);

    try testing.expectEqual(@as(usize, 1), block.hooks.len);
    const one = block.hooks[0];
    try testing.expectEqualStrings("tests-pass", one.name);
    try testing.expectEqual(Trigger.tool_before, one.trigger);
    try testing.expectEqualStrings("request_action", one.tool);
    try testing.expectEqual(@as(usize, 3), one.argv.len);
    try testing.expectEqualStrings("zig", one.argv[0]);
    try testing.expectEqual(@as(u32, 120000), one.timeout_ms);
    try testing.expectEqual(Output.refuse, one.output);
    try testing.expectEqual(@as(usize, 2), one.inputs.len);
    try testing.expectEqual(Input.tool, one.inputs[0]);

    var plain = try parse(gpa,
        \\.{ .hooks = .{ .{ .name = "say", .on = "session.end", .run = .{ "./say" } } } }
    , null);
    defer plain.deinit(gpa);
    try testing.expectEqual(Output.ignore, plain.hooks[0].output);
    try testing.expectEqual(default_timeout_ms, plain.hooks[0].timeout_ms);
    try testing.expectEqualStrings("", plain.hooks[0].tool);
    try testing.expectEqual(@as(usize, 0), plain.hooks[0].inputs.len);
}

test "a run written as one line is refused, and the message says how to ask for a shell" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .on = "session.end", .run = "zig build test" } } }
    , &diag));

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "list of strings") != null);
    try testing.expect(std.mem.indexOf(u8, rendered.items, "the shell is yours to name") != null);
}

test "an output a trigger cannot carry is refused by name" {
    const gpa = testing.allocator;

    var late: ?Diagnostic = null;
    defer if (late) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "too-late",
        \\    .on = "tool.after",
        \\    .run = .{ "./check" },
        \\    .output = "refuse",
        \\} } }
    , &late));
    try testing.expectEqualStrings("too-late", late.?.fault.output_not_for_this_trigger.name);

    var nobody: ?Diagnostic = null;
    defer if (nobody) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "nobody-listening",
        \\    .on = "session.end",
        \\    .run = .{ "./check" },
        \\    .output = "note",
        \\} } }
    , &nobody));
    try testing.expectEqualStrings("nobody-listening", nobody.?.fault.output_not_for_this_trigger.name);
}

test "no output permits, so a hook cannot be written to widen a decision" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "widen",
        \\    .on = "tool.before",
        \\    .run = .{ "./check" },
        \\    .output = "allow",
        \\} } }
    , &diag));

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "none that permits") != null);
    try testing.expect(std.mem.indexOf(u8, rendered.items, "never widen") != null);
}

test "a tool named at a trigger that is not about a tool call is refused" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "confused",
        \\    .on = "session.start",
        \\    .tool = "write_file",
        \\    .run = .{ "./check" },
        \\} } }
    , &diag));
    try testing.expectEqualStrings("confused", diag.?.fault.tool_without_a_tool_trigger.name);
    try testing.expectEqualStrings("session.start", diag.?.fault.tool_without_a_tool_trigger.text);
}

test "a tool no build has is refused, so a hook cannot wait for something that never comes" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "ghost",
        \\    .on = "tool.before",
        \\    .tool = "write_files_quickly",
        \\    .run = .{ "./check" },
        \\} } }
    , &diag));
    try testing.expectEqualStrings("write_files_quickly", diag.?.fault.tool_unknown);
}

test "a trigger, an input and a name this reader does not know are each refused" {
    const gpa = testing.allocator;

    var trigger: ?Diagnostic = null;
    defer if (trigger) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .on = "tool.during", .run = .{ "./x" } } } }
    , &trigger));
    try testing.expectEqualStrings("tool.during", trigger.?.fault.on_unknown);

    var input: ?Diagnostic = null;
    defer if (input) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "a",
        \\    .on = "tool.before",
        \\    .run = .{ "./x" },
        \\    .inputs = .{ "arguments" },
        \\} } }
    , &input));
    try testing.expectEqualStrings("arguments", input.?.fault.input_unknown);

    var field: ?Diagnostic = null;
    defer if (field) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .on = "tool.before", .run = .{ "./x" }, .shell = true } } }
    , &field));
    try testing.expectEqualStrings("shell", field.?.fault.unknown_field);
}

test "a timeout past the bound and one that is not a number are both refused" {
    const gpa = testing.allocator;

    var long: ?Diagnostic = null;
    defer if (long) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "a",
        \\    .on = "session.end",
        \\    .run = .{ "./x" },
        \\    .timeout_ms = 3600000,
        \\} } }
    , &long));
    try testing.expectEqual(max_timeout_ms, long.?.fault.timeout_too_long);

    var text: ?Diagnostic = null;
    defer if (text) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "a",
        \\    .on = "session.end",
        \\    .run = .{ "./x" },
        \\    .timeout_ms = "a while",
        \\} } }
    , &text));
    try testing.expectEqual(Diagnostic.Fault.timeout_not_a_number, text.?.fault);

    var zero: ?Diagnostic = null;
    defer if (zero) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{
        \\    .name = "a",
        \\    .on = "session.end",
        \\    .run = .{ "./x" },
        \\    .timeout_ms = 0,
        \\} } }
    , &zero));
}

test "two hooks cannot share a name, because a refusal names one" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{
        \\    .{ .name = "check", .on = "tool.before", .run = .{ "./a" } },
        \\    .{ .name = "check", .on = "tool.after", .run = .{ "./b" } },
        \\} }
    , &diag));
    try testing.expectEqualStrings("check", diag.?.fault.name_already_taken);
}

test "more hooks than the bound, an empty run, and a missing field are each refused" {
    const gpa = testing.allocator;

    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(gpa);
    try source.appendSlice(gpa, ".{ .hooks = .{");
    for (0..max_entries + 1) |at| {
        try source.print(
            gpa,
            " .{{ .name = \"h{d}\", .on = \"session.end\", .run = .{{ \"./x\" }} }},",
            .{at},
        );
    }
    try source.appendSlice(gpa, " } }");
    const text = try source.toOwnedSliceSentinel(gpa, 0);
    defer gpa.free(text);

    var many: ?Diagnostic = null;
    defer if (many) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa, text, &many));
    try testing.expectEqual(max_entries, many.?.fault.too_many_entries);

    var empty: ?Diagnostic = null;
    defer if (empty) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .on = "session.end", .run = .{} } } }
    , &empty));
    try testing.expectEqual(Diagnostic.Fault.run_empty, empty.?.fault);

    var no_run: ?Diagnostic = null;
    defer if (no_run) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .on = "session.end" } } }
    , &no_run));
    try testing.expectEqual(Diagnostic.Fault.run_missing, no_run.?.fault);

    var no_on: ?Diagnostic = null;
    defer if (no_on) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "a", .run = .{ "./x" } } } }
    , &no_on));
    try testing.expectEqual(Diagnostic.Fault.on_missing, no_on.?.fault);

    var no_name: ?Diagnostic = null;
    defer if (no_name) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .on = "session.end", .run = .{ "./x" } } } }
    , &no_name));
    try testing.expectEqual(Diagnostic.Fault.name_missing, no_name.?.fault);
}

test "the block comes off the disk, and a project with no file holds none" {
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = buffer[0..try tmp.dir.realPath(io, &buffer)];

    var none = try load(gpa, io, root, null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.hooks.len);

    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data =
        \\.{ .hooks = .{ .{ .name = "check", .on = "tool.before", .run = .{ "./check" } } } }
        ,
    });

    var found = try load(gpa, io, root, null);
    defer found.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), found.hooks.len);
    try testing.expectEqualStrings("check", found.hooks[0].name);
}

test "a hook name takes the shape a call id can be read back out of" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "has:a:colon", .on = "session.end", .run = .{ "./x" } } } }
    , &diag));
    try testing.expectEqualStrings("has:a:colon", diag.?.fault.name_not_the_shape);

    var shouting: ?Diagnostic = null;
    defer if (shouting) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidHooks, parse(gpa,
        \\.{ .hooks = .{ .{ .name = "Tests", .on = "session.end", .run = .{ "./x" } } } }
    , &shouting));

    var fine = try parse(gpa,
        \\.{ .hooks = .{ .{ .name = "tests-pass-2", .on = "session.end", .run = .{ "./x" } } } }
    , null);
    defer fine.deinit(gpa);
    try testing.expectEqualStrings("tests-pass-2", fine.hooks[0].name);
}

test "a moment with no call of its own is named by its trigger" {
    const start = Moment{ .trigger = .session_start };
    try testing.expectEqualStrings("session.start", start.aboutOr());

    const about_a_call = Moment{ .trigger = .tool_before, .about = "call7" };
    try testing.expectEqualStrings("call7", about_a_call.aboutOr());
}
