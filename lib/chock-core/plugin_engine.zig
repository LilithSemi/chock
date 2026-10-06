//! Running a plugin: the seam the execution engine sits behind, and the
//! rules that hold before, during and after one call.

const std = @import("std");

const core = @import("chock-plugin-core");

const plugin = @import("plugin.zig");
const plugin_module = @import("plugin_module.zig");

pub const Import = struct {
    module: []const u8,
    field: []const u8,

    pub fn eql(self: Import, other: Import) bool {
        return std.mem.eql(u8, self.module, other.module) and
            std.mem.eql(u8, self.field, other.field);
    }
};

pub fn importsFor(capability: []const u8) []const Import {
    _ = capability;
    return &.{};
}

pub const GateError = error{
    ImportNotDeclared,
    TooManyImports,
};

pub const max_imports: usize = 64;

pub const Refused = struct {
    wanted: Import,

    pub fn format(self: Refused, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "it imports {s}.{s}, which none of the capabilities it declares supplies",
            .{ self.wanted.module, self.wanted.field },
        );
    }
};

pub fn gate(
    wanted: []const Import,
    capabilities: []const []const u8,
    out: []usize,
    refused: ?*?Refused,
) GateError!void {
    if (wanted.len > max_imports) return error.TooManyImports;
    std.debug.assert(out.len >= wanted.len);

    for (wanted, 0..) |one, index| {
        const address = addressFor(one, capabilities) orelse {
            if (refused) |slot| {
                if (slot.* == null) slot.* = .{ .wanted = one };
            }
            return error.ImportNotDeclared;
        };
        out[index] = address;
    }
}

fn addressFor(wanted: Import, capabilities: []const []const u8) ?usize {
    for (capabilities) |capability| {
        for (importsFor(capability)) |supplied| {
            if (supplied.eql(wanted)) {
                return null;
            }
        }
    }
    return null;
}

pub const Error = error{
    EngineRefused,
    GuestMisbehaved,
    ToolCountDisagrees,
    ArgumentsTooLong,
} || GateError || std.mem.Allocator.Error;

pub const Engine = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        instantiate: *const fn (
            ptr: *anyopaque,
            module: []const u8,
            imports: []const usize,
        ) anyerror!void,
        memory: *const fn (ptr: *anyopaque) []u8,
        call0: *const fn (ptr: *anyopaque, name: []const u8) anyerror!u32,
        call3: *const fn (
            ptr: *anyopaque,
            name: []const u8,
            a0: u32,
            a1: u32,
            a2: u32,
        ) anyerror!u32,
    };

    pub fn instantiate(self: Engine, module: []const u8, addresses: []const usize) anyerror!void {
        return self.vtable.instantiate(self.ptr, module, addresses);
    }
    pub fn memory(self: Engine) []u8 {
        return self.vtable.memory(self.ptr);
    }
    pub fn call0(self: Engine, name: []const u8) anyerror!u32 {
        return self.vtable.call0(self.ptr, name);
    }
    pub fn call3(self: Engine, name: []const u8, a0: u32, a1: u32, a2: u32) anyerror!u32 {
        return self.vtable.call3(self.ptr, name, a0, a1, a2);
    }
};

pub const arguments_symbol = core.call.arguments_symbol;

pub const Diagnostic = struct {
    call: Call,
    cause: ?anyerror = null,

    pub const Call = enum {
        instantiate,
        init_call,
        before_instantiation,
        tool_index,
        arguments_call,
        tool_call,
        empty_answer,

        pub fn text(self: Call) []const u8 {
            return switch (self) {
                .instantiate => "the engine would not instantiate the module",
                .init_call => "the call to chock_plugin_init did not come back",
                .before_instantiation => "a tool was called before the module was instantiated",
                .tool_index => "a tool was called by an index the module never bound",
                .arguments_call => "the call to chock_plugin_arguments did not come back",
                .tool_call => "the call to chock_plugin_call did not come back",
                .empty_answer => "chock_plugin_call answered that it has nothing to say",
            };
        }
    };

    pub fn format(self: Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeAll(self.call.text());
        if (self.cause) |err| try writer.print(": {t}", .{err});
    }
};

pub const Runner = struct {
    engine: Engine,
    bound: u32 = 0,
    ready: bool = false,
    tools: []const core.ToolDescriptor = &.{},
    refusal: ?Diagnostic = null,

    pub fn load(
        self: *Runner,
        gpa: std.mem.Allocator,
        module: []const u8,
        declared: []const core.ToolDescriptor,
        wanted: []const Import,
        capabilities: []const []const u8,
        refused: ?*?Refused,
    ) Error!void {
        self.refusal = null;

        const addresses = try gpa.alloc(usize, @max(wanted.len, 1));
        defer gpa.free(addresses);
        try gate(wanted, capabilities, addresses, refused);

        self.engine.instantiate(module, addresses[0..wanted.len]) catch |err|
            return self.refuse(.instantiate, err);

        const bound = self.engine.call0(core.init_symbol) catch |err|
            return self.refuse(.init_call, err);
        if (bound != declared.len) return error.ToolCountDisagrees;

        self.bound = bound;
        self.tools = declared;
        self.ready = true;
    }

    pub fn call(
        self: *Runner,
        gpa: std.mem.Allocator,
        index: u32,
        arguments: []const u8,
    ) Error!plugin.Outcome {
        self.refusal = null;

        if (!self.ready) return self.refuse(.before_instantiation, null);
        if (index >= self.bound) return self.refuse(.tool_index, null);

        const record = try self.recordFor(gpa, index, arguments);
        defer gpa.free(record);
        const written = try self.writeArguments(record);

        const address = self.engine.call3(
            core.call_symbol,
            index,
            written.address,
            written.length,
        ) catch |err| return self.refuse(.tool_call, err);
        if (address == core.call.no_answer) return self.refuse(.empty_answer, null);

        const memory = self.engine.memory();
        const answer = core.call.readAnswer(memory, address) catch
            return error.GuestMisbehaved;

        return .{
            .text = core.call.textOf(memory, answer),
            .is_error = answer.outcome == .failure,
        };
    }

    fn refuse(self: *Runner, call_site: Diagnostic.Call, cause: ?anyerror) Error {
        self.refusal = .{ .call = call_site, .cause = cause };
        return error.EngineRefused;
    }

    fn recordFor(
        self: *Runner,
        gpa: std.mem.Allocator,
        index: u32,
        arguments: []const u8,
    ) Error![]u8 {
        const properties = if (index < self.tools.len) self.tools[index].parameters else &.{};
        if (properties.len == 0) return gpa.alloc(u8, 0);

        const trimmed = std.mem.trim(u8, arguments, " \t\r\n");
        const text = if (trimmed.len == 0) "{}" else trimmed;

        var parsed: std.json.Parsed(std.json.Value) = std.json.parseFromSlice(
            std.json.Value,
            gpa,
            text,
            .{},
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.refuse(.arguments_call, error.ArgumentsUnreadable),
        };
        defer parsed.deinit();

        return core.args.encodeAlloc(gpa, properties, parsed.value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.refuse(.arguments_call, err),
        };
    }

    const Written = struct { address: u32, length: u32 };

    fn writeArguments(self: *Runner, arguments: []const u8) Error!Written {
        if (arguments.len == 0) return .{ .address = 0, .length = 0 };
        if (arguments.len > std.math.maxInt(u32)) return error.ArgumentsTooLong;
        const length: u32 = @intCast(arguments.len);

        const address = self.engine.call3(arguments_symbol, length, 0, 0) catch |err|
            return self.refuse(.arguments_call, err);
        if (address == 0) return error.ArgumentsTooLong;

        const memory = self.engine.memory();
        const end = std.math.add(usize, address, length) catch return error.GuestMisbehaved;
        if (end > memory.len) return error.GuestMisbehaved;

        @memcpy(memory[address..][0..length], arguments);
        return .{ .address = address, .length = length };
    }
};

pub fn unionOfCapabilities(
    gpa: std.mem.Allocator,
    session: *const plugin.Session,
    name: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    for (session.offers.items) |offer| {
        if (offer.refused != null) continue;
        if (offer.decision != .allow) continue;
        if (!std.mem.eql(u8, offer.plugin, name)) continue;
        for (offer.capabilities) |capability| {
            var already = false;
            for (out.items) |kept| {
                if (std.mem.eql(u8, kept, capability)) already = true;
            }
            if (!already) try out.append(gpa, capability);
        }
    }
    return out.toOwnedSlice(gpa);
}

const testing = std.testing;

const one_tool: [1]core.ToolDescriptor = .{.{ .name = "hello" }};

const who = "{\"who\":\"Ross\"}";

const typed_tool: [1]core.ToolDescriptor = .{.{
    .name = "greet",
    .parameters = &.{.{
        .name = "who",
        .description = "Who to greet.",
        .required = true,
        .shape = .{ .kind = .string },
    }},
}};

const FakeEngine = struct {
    guest: []u8,
    wanted: []const Import = &.{},
    binds: u32 = 1,
    answer_at: u32 = 0,
    arguments_at: u32 = 0,
    refuses: bool = false,
    refusing_symbol: ?[]const u8 = null,
    supplied: usize = 0,
    instantiated: bool = false,

    fn engine(self: *FakeEngine) Engine {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn refusesSymbol(self: *const FakeEngine, name: []const u8) bool {
        const which = self.refusing_symbol orelse return false;
        return std.mem.eql(u8, which, name);
    }

    const vtable = Engine.VTable{
        .instantiate = instantiateFn,
        .memory = memoryFn,
        .call0 = call0Fn,
        .call3 = call3Fn,
    };

    fn instantiateFn(ptr: *anyopaque, module: []const u8, addresses: []const usize) anyerror!void {
        const self: *FakeEngine = @ptrCast(@alignCast(ptr));
        _ = module;
        self.instantiated = true;
        self.supplied = addresses.len;
        if (self.refuses) return error.Refused;
    }
    fn memoryFn(ptr: *anyopaque) []u8 {
        const self: *FakeEngine = @ptrCast(@alignCast(ptr));
        return self.guest;
    }
    fn call0Fn(ptr: *anyopaque, name: []const u8) anyerror!u32 {
        const self: *FakeEngine = @ptrCast(@alignCast(ptr));
        if (self.refusesSymbol(name)) return error.Refused;
        return self.binds;
    }
    fn call3Fn(ptr: *anyopaque, name: []const u8, a0: u32, a1: u32, a2: u32) anyerror!u32 {
        const self: *FakeEngine = @ptrCast(@alignCast(ptr));
        _ = a1;
        _ = a2;
        if (self.refusesSymbol(name)) return error.Refused;
        if (std.mem.eql(u8, name, arguments_symbol)) {
            _ = a0;
            return self.arguments_at;
        }
        return self.answer_at;
    }
};

fn stageAnswer(guest: []u8, at: u32, outcome: core.call.Outcome, text: []const u8) void {
    @memset(guest, 0);
    const text_at: u32 = 256;
    @memcpy(guest[text_at..][0..text.len], text);
    std.mem.writeInt(
        u32,
        guest[at + core.call.Answer.outcome_offset ..][0..4],
        @intFromEnum(outcome),
        .little,
    );
    std.mem.writeInt(u32, guest[at + core.call.Answer.text_ptr_offset ..][0..4], text_at, .little);
    std.mem.writeInt(
        u32,
        guest[at + core.call.Answer.text_len_offset ..][0..4],
        @intCast(text.len),
        .little,
    );
}

test "a module that imports nothing runs, and the engine is handed no address" {
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .success, "Hello, world!");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };

    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);
    try testing.expect(fake.instantiated);
    try testing.expectEqual(@as(usize, 0), fake.supplied);

    const outcome = try runner.call(testing.allocator, 0, "");
    try testing.expectEqualStrings("Hello, world!", outcome.text);
    try testing.expect(!outcome.is_error);
}

test "a module that imports anything is refused before it is instantiated" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{
        .guest = &guest,
        .wanted = &.{.{ .module = "env", .field = "read_file" }},
    };

    var runner: Runner = .{ .engine = fake.engine() };
    var refused: ?Refused = null;
    try testing.expectError(
        error.ImportNotDeclared,
        runner.load(testing.allocator, "module", &one_tool, fake.wanted, &.{"fs.read"}, &refused),
    );
    try testing.expect(!fake.instantiated);
    try testing.expect(!runner.ready);
    try testing.expectEqualStrings("read_file", refused.?.wanted.field);
}

test "a declared capability does not supply an import in this build, and says so" {
    try testing.expectEqual(@as(usize, 0), importsFor("fs.read").len);
    try testing.expectEqual(@as(usize, 0), importsFor("git.commit").len);
    try testing.expectEqual(@as(usize, 0), importsFor("anything.at.all").len);
}

test "a guest whose bound count disagrees with its metadata is refused" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .binds = 3 };

    var runner: Runner = .{ .engine = fake.engine() };
    try testing.expectError(
        error.ToolCountDisagrees,
        runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null),
    );
    try testing.expect(!runner.ready);
}

test "an answer pointing past the guest's own memory is refused rather than read" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);

    std.mem.writeInt(u32, guest[16 + core.call.Answer.text_ptr_offset ..][0..4], 1000, .little);
    std.mem.writeInt(u32, guest[16 + core.call.Answer.text_len_offset ..][0..4], 500, .little);
    try testing.expectError(error.GuestMisbehaved, runner.call(testing.allocator, 0, ""));
}

test "a tool index no guest bound is refused without reaching the engine" {
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .success, "unreachable");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);

    try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 1, ""));
    try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 99, ""));
}

test "a runner that never loaded refuses every call" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .refuses = true };
    var runner: Runner = .{ .engine = fake.engine() };

    try testing.expectError(
        error.EngineRefused,
        runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null),
    );
    try testing.expect(!runner.ready);
    try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 0, ""));
}

test "every refusal names the call it came out of" {
    var guest: [1024]u8 = @splat(0);

    {
        var fake: FakeEngine = .{ .guest = &guest, .refuses = true };
        var runner: Runner = .{ .engine = fake.engine() };
        try testing.expectError(
            error.EngineRefused,
            runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null),
        );
        try testing.expectEqual(Diagnostic.Call.instantiate, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);

        try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 0, ""));
        try testing.expectEqual(Diagnostic.Call.before_instantiation, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, null), runner.refusal.?.cause);
    }

    {
        var fake: FakeEngine = .{ .guest = &guest, .refusing_symbol = core.init_symbol };
        var runner: Runner = .{ .engine = fake.engine() };
        try testing.expectError(
            error.EngineRefused,
            runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null),
        );
        try testing.expectEqual(Diagnostic.Call.init_call, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);
    }

    {
        stageAnswer(&guest, 16, .success, "unreachable");
        var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 1, ""));
        try testing.expectEqual(Diagnostic.Call.tool_index, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, null), runner.refusal.?.cause);
    }

    {
        var fake: FakeEngine = .{
            .guest = &guest,
            .answer_at = 16,
            .arguments_at = 512,
            .refusing_symbol = arguments_symbol,
        };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", &typed_tool, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 0, who));
        try testing.expectEqual(Diagnostic.Call.arguments_call, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);
    }

    {
        var fake: FakeEngine = .{
            .guest = &guest,
            .answer_at = 16,
            .refusing_symbol = core.call_symbol,
        };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 0, ""));
        try testing.expectEqual(Diagnostic.Call.tool_call, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);
    }

    {
        var fake: FakeEngine = .{ .guest = &guest, .answer_at = core.call.no_answer };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(testing.allocator, 0, ""));
        try testing.expectEqual(Diagnostic.Call.empty_answer, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, null), runner.refusal.?.cause);
    }
}

test "a refusal reads as a sentence, and no two of them read the same" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    try writer.print("{f}", .{Diagnostic{ .call = .instantiate, .cause = error.Unsupported }});
    try testing.expectEqualStrings(
        "the engine would not instantiate the module: Unsupported",
        writer.buffered(),
    );

    writer = .fixed(&buffer);
    try writer.print("{f}", .{Diagnostic{ .call = .tool_index }});
    try testing.expectEqualStrings(
        "a tool was called by an index the module never bound",
        writer.buffered(),
    );

    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |one, i| {
        try testing.expect(one.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, one.text(), other.text()));
        }
    }
}

test "arguments the guest has no room for are refused, and never written anyway" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 0 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &typed_tool, &.{}, &.{}, null);

    try testing.expectError(error.ArgumentsTooLong, runner.call(testing.allocator, 0, who));
    try testing.expectEqual(@as(u8, 0), guest[0]);
}

test "an argument address the guest answered is checked before anything is written" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 1020 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &typed_tool, &.{}, &.{}, null);

    try testing.expectError(error.GuestMisbehaved, runner.call(testing.allocator, 0, who));
}

test "the model's arguments reach the guest as the record its schema names" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 512 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &typed_tool, &.{}, &.{}, null);

    stageAnswer(&guest, 16, .success, "done");
    const outcome = try runner.call(testing.allocator, 0, who);
    try testing.expectEqualStrings("done", outcome.text);
    try testing.expectEqualSlices(u8, &.{ 1, 4, 0, 0, 0 }, guest[512..][0..5]);
    try testing.expectEqualStrings("Ross", guest[517..][0..4]);
}

test "a tool that takes nothing is handed no bytes at all" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 512 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);

    stageAnswer(&guest, 16, .success, "done");
    const outcome = try runner.call(testing.allocator, 0, who);
    try testing.expectEqualStrings("done", outcome.text);
    try testing.expectEqualSlices(u8, &(.{0} ** 16), guest[512..][0..16]);

    const anyway = try runner.call(testing.allocator, 0, "not json");
    try testing.expectEqualStrings("done", anyway.text);
    try testing.expect(!anyway.is_error);
}

test "arguments that do not match the schema are refused before the guest runs" {
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 512 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &typed_tool, &.{}, &.{}, null);

    try testing.expectError(
        error.EngineRefused,
        runner.call(testing.allocator, 0, "{\"who\":7}"),
    );
    try testing.expectEqual(Diagnostic.Call.arguments_call, runner.refusal.?.call);
    try testing.expectEqual(@as(?anyerror, error.TypeMismatch), runner.refusal.?.cause);

    try testing.expectError(
        error.EngineRefused,
        runner.call(testing.allocator, 0, "not json"),
    );
    try testing.expectEqual(
        @as(?anyerror, error.ArgumentsUnreadable),
        runner.refusal.?.cause,
    );
}

test "a tool that failed is a result and not a fault of this host" {
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .failure, "no such file");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", &one_tool, &.{}, &.{}, null);

    const outcome = try runner.call(testing.allocator, 0, "");
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("no such file", outcome.text);
}

test "the union of capabilities leaves out a tool the policy refused" {
    var session: plugin.Session = .init(testing.allocator);
    defer session.deinit();

    var policy: DenyOne = .{ .denied = "fs.write" };
    const record: core.Metadata = .{
        .name = "two",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "reader", .capabilities = &.{"fs.read"} },
            .{ .name = "writer", .capabilities = &.{"fs.write"} },
        },
    };
    _ = try session.admit("two", record, policy.decider());

    const union_of = try unionOfCapabilities(testing.allocator, &session, "two");
    defer testing.allocator.free(union_of);
    try testing.expectEqual(@as(usize, 1), union_of.len);
    try testing.expectEqualStrings("fs.read", union_of[0]);
}

test "the union of capabilities leaves out a tool that still has to ask" {
    var session: plugin.Session = .init(testing.allocator);
    defer session.deinit();

    var policy: AskOne = .{ .asking = "plugin.two.tool.writer" };
    const record: core.Metadata = .{
        .name = "two",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .chock_version = .{ .min = .{ .major = 0, .minor = 1, .patch = 0 } },
        .author = "somebody",
        .tools = &.{
            .{ .name = "reader", .capabilities = &.{"fs.read"} },
            .{ .name = "writer", .capabilities = &.{"fs.write"} },
        },
    };
    _ = try session.admit("two", record, policy.decider());

    try testing.expectEqual(@as(?plugin.Refusal, null), session.find("writer").?.refused);

    const union_of = try unionOfCapabilities(testing.allocator, &session, "two");
    defer testing.allocator.free(union_of);
    try testing.expectEqual(@as(usize, 1), union_of.len);
    try testing.expectEqualStrings("fs.read", union_of[0]);
}

const AskOne = struct {
    asking: []const u8,

    fn decider(self: *AskOne) plugin.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable = plugin.Decider.VTable{ .decide = decideFn };
    fn decideFn(
        ptr: *anyopaque,
        tool: []const u8,
        action: []const u8,
    ) @import("chock-policy").table.Decision {
        const self: *AskOne = @ptrCast(@alignCast(ptr));
        _ = tool;
        if (std.mem.eql(u8, action, self.asking)) return .ask;
        return .allow;
    }
};

const DenyOne = struct {
    denied: []const u8,

    fn decider(self: *DenyOne) plugin.Decider {
        return .{ .ptr = self, .vtable = &vtable };
    }
    const vtable = plugin.Decider.VTable{ .decide = decideFn };
    fn decideFn(
        ptr: *anyopaque,
        tool: []const u8,
        action: []const u8,
    ) @import("chock-policy").table.Decision {
        const self: *DenyOne = @ptrCast(@alignCast(ptr));
        _ = tool;
        if (std.mem.eql(u8, action, self.denied)) return .deny;
        return .allow;
    }
};

comptime {
    _ = plugin_module.max_module_bytes;
}
