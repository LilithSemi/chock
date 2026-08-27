//! Running a plugin: the seam whatever executes a module sits behind, and the
//! rules that hold before, during and after one call.
//!
//! `lib/chock-core/plugin.zig` decides which tools are offered and what each
//! one costs. `lib/chock-core/plugin_module.zig` reads a module with no engine
//! at all. **This file is what happens after both have said yes**, and it runs
//! in the plugin host process and nowhere else.
//!
//! ## WebAssembly buys this host nothing
//!
//! **Do not relax anything here on the grounds that a wasm guest is contained.
//! It is not, in the engine this project has.** Measured on Vulcan 2026-08-22:
//! `memPtr` is `mem_base + addr + offset` with **no bounds check**, and
//! `callIndirect` loads a table slot and calls it with **neither a bounds
//! check nor a signature check**. A module declaring sixteen pages and storing
//! to offset 100000000 **dumped core**, where wasmtime trapped.
//!
//! Three things follow, and every one of them is load bearing.
//!
//! 1. **A running guest owns the whole address space of the process that runs
//!    it.** So a plugin runs in a process of its own, locked down like the
//!    agent sandbox and not like a helper, and it speaks to the harness over a
//!    pipe. See `lib/chock-core/plugin_host.zig`.
//! 2. **No check made while a guest runs is worth anything.** A guest can
//!    rewrite any table this process holds, including a table of what it is
//!    allowed to do. So the capability gate below runs **before instantiation**
//!    and never during a call. See `gate`.
//! 3. **Every number a guest hands back is measured against the guest's own
//!    memory before it is used.** That is
//!    `lib/chock-plugin-core/call.zig`'s `readAnswer`, and this file never
//!    reaches into guest memory any other way.
//!
//! ## The gate is a set of imports, decided once, before anything runs
//!
//! A wasm module states what it imports. An engine supplies one host address
//! per import, and a module whose imports the host will not supply **fails to
//! instantiate**. That is the enforcement point, and it is the only one that
//! is sound given fact 2 above.
//!
//! So a tool's declared capabilities decide which imports this host supplies,
//! and a module that imports anything else never runs at all.
//!
//! This is what `lib/chock-core/plugin.zig`'s own top comment says is missing.
//! Rule 3 there prices a declaration. This file is what holds a running plugin
//! to it.
//!
//! ## The order of the four steps, which is the whole design
//!
//! ```text
//! 1. read the module          no engine, no guest code       plugin_module.read
//! 2. decide about its tools   no engine, no guest code       plugin.Session.admit
//! 3. gate its imports         no engine, no guest code       gate, here
//! 4. instantiate and call     guest code runs, at last       Runner, here
//! ```
//!
//! Nothing at step 4 can undo a decision taken at steps 1 to 3, because by
//! step 4 the decisions are already spent: the import set is fixed, and the
//! only thing left that a guest chooses is the bytes of its own answer.

const std = @import("std");

const core = @import("chock-plugin-core");

const plugin = @import("plugin.zig");
const plugin_module = @import("plugin_module.zig");

/// One import a module asks for: the module name and the field name, which is
/// how WebAssembly spells the pair.
pub const Import = struct {
    module: []const u8,
    field: []const u8,

    pub fn eql(self: Import, other: Import) bool {
        return std.mem.eql(u8, self.module, other.module) and
            std.mem.eql(u8, self.field, other.field);
    }
};

/// The imports this build supplies for one declared capability.
///
/// **Empty for every capability today, because this build has no host
/// function.** A capability such as `fs.read` is a real claim that
/// `lib/chock-core/plugin.zig` prices against the policy table, and the tool
/// is refused when the project denies it. What does not exist yet is a way for
/// guest code to *act* on the claim, which would be an import here.
///
/// **So the empty answer is the safe one and not a missing one.** A guest that
/// imports a function this build does not supply fails to instantiate, which
/// is exactly what should happen to a plugin built against a host function
/// this Chock does not have.
pub fn importsFor(capability: []const u8) []const Import {
    _ = capability;
    return &.{};
}

/// Why a module was not allowed to run.
pub const GateError = error{
    /// The module imports something no declared capability supplies.
    ImportNotDeclared,
    /// The module declares more imports than this host walks.
    TooManyImports,
};

/// How many imports one module may state. A plugin with more than this is not
/// a plugin this host has any way to satisfy, and the number bounds the walk
/// below.
pub const max_imports: usize = 64;

/// The detail behind a refusal at the gate, for the sentence a person reads.
pub const Refused = struct {
    /// The import that was not covered. Borrowed from the caller's own module.
    wanted: Import,

    pub fn format(self: Refused, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print(
            "it imports {s}.{s}, which none of the capabilities it declares supplies",
            .{ self.wanted.module, self.wanted.field },
        );
    }
};

/// Decide whether a module may run, and answer the host address for each
/// import it states.
///
/// `wanted` is what the module imports, in the module's own order, because an
/// engine matches host addresses to imports by position. `capabilities` is
/// what the tool being called declared, already checked and already priced by
/// `plugin.Session`.
///
/// **Every import must be covered, and the answer is one address per import in
/// the module's own order.** A gate that answered a shorter list would have
/// the engine read past the end of it, and a gate that answered addresses in a
/// different order would bind the guest's calls to the wrong host function,
/// which is worse than refusing.
///
/// Answers into `out`, which the caller sizes at `wanted.len`, so nothing here
/// allocates.
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

/// The host address that satisfies one import, or null when no declared
/// capability supplies it.
///
/// **Null for everything today**, because `importsFor` answers an empty set
/// for every capability: see its own comment. When a capability gets a host
/// function, its address is answered from here.
fn addressFor(wanted: Import, capabilities: []const []const u8) ?usize {
    for (capabilities) |capability| {
        for (importsFor(capability)) |supplied| {
            if (supplied.eql(wanted)) {
                // Unreachable while `importsFor` is empty, and written out so
                // the first host function has one place to land rather than a
                // shape to invent.
                return null;
            }
        }
    }
    return null;
}

/// What could go wrong running a plugin, once it has been let through the
/// gate.
pub const Error = error{
    /// The engine would not load or instantiate the module.
    EngineRefused,
    /// A call into the guest did not come back with something this host can
    /// read: see `core.call.readAnswer`.
    GuestMisbehaved,
    /// `chock_plugin_init` bound a different number of tools than the metadata
    /// declared. The two come from one compilation, so a disagreement is a
    /// module that was tampered with after it was built.
    ToolCountDisagrees,
    /// The guest has no room for the arguments it was handed.
    ArgumentsTooLong,
} || GateError || std.mem.Allocator.Error;

/// Whatever really executes a module, behind one interface.
///
/// **A seam, and the reason is not testing.** The engine is a dependency of
/// the plugin host process alone: `chock-core` must build with no engine at
/// all, on every platform, because every other consumer of this library links
/// it. `src/plugin-host.zig` is the one program that supplies a real one.
pub const Engine = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Load `module` and set it up with exactly `imports`, one host
        /// address per import in the module's own order.
        instantiate: *const fn (
            ptr: *anyopaque,
            module: []const u8,
            imports: []const usize,
        ) anyerror!void,
        /// The guest's whole linear memory. Empty before instantiation.
        memory: *const fn (ptr: *anyopaque) []u8,
        /// Call an exported function of no arguments that answers a `u32`.
        call0: *const fn (ptr: *anyopaque, name: []const u8) anyerror!u32,
        /// Call an exported function of three `u32` arguments that answers a
        /// `u32`.
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

/// The guest symbol that answers where a host may write the argument text. See
/// `lib/chock-plugin-core/call.zig`, which both sides read it from.
pub const arguments_symbol = core.call.arguments_symbol;

/// Why a plugin would not run, for the sentence a person reads.
///
/// **`error.EngineRefused` is answered from seven different places**, and the
/// name alone tells a reader none of them. A machine that runs a plugin and a
/// machine that does not can then produce the same one word, which is what
/// made an x86_64 failure of this project's own suite unreadable until the
/// engine was measured by hand. So every refusal names the call it came out
/// of, and carries the error the engine gave where there was one.
///
/// **The same shape as `namespace.Diagnostic` in
/// `lib/chock-sandbox/linux/namespace.zig`**, and for the same reason: a
/// `Call` that says what was being done, the underlying answer beside it, and
/// a `format` that turns the pair into a sentence at the caller. This one owns
/// no memory either.
pub const Diagnostic = struct {
    call: Call,
    /// What the engine answered. **Null where this host refused before it
    /// called the engine at all**, which is a different fact from an engine
    /// that was asked and said no.
    cause: ?anyerror = null,

    /// The places a plugin can be refused. Named for what was being done and
    /// not for the engine method, because `call3` says much less than "the
    /// call to `chock_plugin_call`".
    pub const Call = enum {
        instantiate,
        init_call,
        before_instantiation,
        tool_index,
        arguments_call,
        tool_call,
        empty_answer,

        /// What happened, as a sentence that reads after "chock: ".
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

/// One plugin, instantiated, ready to be called.
///
/// **Owned by the plugin host process.** One `Runner` is one module, and the
/// process holds exactly one: a second plugin is a second process, so a plugin
/// that dumps core takes only itself down.
pub const Runner = struct {
    engine: Engine,
    /// How many tools `chock_plugin_init` said it bound. The metadata's own
    /// count, checked against the guest's.
    bound: u32 = 0,
    /// Whether the guest has been instantiated and initialised.
    ready: bool = false,
    /// Why the last `error.EngineRefused` was answered.
    ///
    /// **The latest and not the first**, which is the opposite of
    /// `namespace.note` and right here for a different reason: a `Runner`
    /// serves one `load` and then any number of `call`s, and each one of those
    /// is a whole operation of its own. A caller reads this straight after the
    /// call that refused.
    refusal: ?Diagnostic = null,

    /// Let the module through the gate, instantiate it, and bind its tools.
    ///
    /// `capabilities` is the union of what every offered tool of this plugin
    /// declared. **The union and not one tool's set**, because the import set
    /// is fixed at instantiation and one instance serves every tool of the
    /// plugin. A tool's own set still decides whether that tool is offered at
    /// all, which is `plugin.Session`'s job and already done by here.
    /// `wanted` is every import the module states, read out of the file by
    /// `chock_core.plugin_module.readImports`. **From the module reader and
    /// never from the engine**: an engine may track one kind of import and
    /// step over the rest, so a gate that asked the engine would never see an
    /// imported memory. See that function's own comment.
    pub fn load(
        self: *Runner,
        gpa: std.mem.Allocator,
        module: []const u8,
        declared_tools: usize,
        wanted: []const Import,
        capabilities: []const []const u8,
        refused: ?*?Refused,
    ) Error!void {
        // **Cleared first, so nothing here can be read as the reason for
        // something else.** A `refusal` left over from an earlier operation
        // would be a sentence about the wrong fault, which is worse than no
        // sentence at all.
        self.refusal = null;

        // **The gate, before the engine is told to build anything.** Nothing
        // of the guest has run at this point and nothing of it will if this
        // answers no.
        const addresses = try gpa.alloc(usize, @max(wanted.len, 1));
        defer gpa.free(addresses);
        try gate(wanted, capabilities, addresses, refused);

        // Every import is refused in this build, so `wanted` is empty by the
        // time this line is reached and the engine is handed no address at
        // all. **The first host function makes this line the place where the
        // gate's order and the engine's own import order have to be
        // reconciled**, because the two lists are read by two different
        // walkers.
        self.engine.instantiate(module, addresses[0..wanted.len]) catch |err|
            return self.refuse(.instantiate, err);

        const bound = self.engine.call0(core.init_symbol) catch |err|
            return self.refuse(.init_call, err);
        if (bound != declared_tools) return error.ToolCountDisagrees;

        self.bound = bound;
        self.ready = true;
    }

    /// Run one tool and answer what it said. The text points into the guest's
    /// own memory, so a caller copies it before the next call.
    ///
    /// `index` is the tool's position in the metadata's own tool list.
    pub fn call(self: *Runner, index: u32, arguments: []const u8) Error!plugin.Outcome {
        // See `load`: a `refusal` from an earlier call must never be read as
        // the reason for this one.
        self.refusal = null;

        if (!self.ready) return self.refuse(.before_instantiation, null);
        if (index >= self.bound) return self.refuse(.tool_index, null);

        const written = try self.writeArguments(arguments);

        const address = self.engine.call3(
            core.call_symbol,
            index,
            written.address,
            written.length,
        ) catch |err| return self.refuse(.tool_call, err);
        if (address == core.call.no_answer) return self.refuse(.empty_answer, null);

        // **Every field of this is a number the guest chose**, and the engine
        // checked none of them. See `core.call.readAnswer`.
        const memory = self.engine.memory();
        const answer = core.call.readAnswer(memory, address) catch
            return error.GuestMisbehaved;

        return .{
            .text = core.call.textOf(memory, answer),
            .is_error = answer.outcome == .failure,
        };
    }

    /// Record why this refusal happened, and answer the one error every
    /// refusal answers.
    ///
    /// **Every `error.EngineRefused` in this file comes out of here.** A
    /// second way to answer it would be a seventh site with no diagnostic, and
    /// that is the fault this type exists to remove.
    fn refuse(self: *Runner, call_site: Diagnostic.Call, cause: ?anyerror) Error {
        self.refusal = .{ .call = call_site, .cause = cause };
        return error.EngineRefused;
    }

    /// Where the argument text went in the guest's memory, and how much of it.
    const Written = struct { address: u32, length: u32 };

    /// Put the argument text where the guest said it may go.
    ///
    /// Nothing is written for an empty text, so a tool called with no argument
    /// never reaches into guest memory at all.
    fn writeArguments(self: *Runner, arguments: []const u8) Error!Written {
        if (arguments.len == 0) return .{ .address = 0, .length = 0 };
        if (arguments.len > std.math.maxInt(u32)) return error.ArgumentsTooLong;
        const length: u32 = @intCast(arguments.len);

        // The guest owns the bound on its own buffer and answers zero when the
        // text does not fit, so this host never has to know how big it is.
        const address = self.engine.call3(arguments_symbol, length, 0, 0) catch |err|
            return self.refuse(.arguments_call, err);
        if (address == 0) return error.ArgumentsTooLong;

        // **And the address the guest answered is checked anyway.** A guest
        // that answered an address near the end of its memory would otherwise
        // have this host write the arguments past it, which is a write and not
        // a read: the worse half of the same fault.
        const memory = self.engine.memory();
        const end = std.math.add(usize, address, length) catch return error.GuestMisbehaved;
        if (end > memory.len) return error.GuestMisbehaved;

        @memcpy(memory[address..][0..length], arguments);
        return .{ .address = address, .length = length };
    }
};

/// The union of the capabilities every offered tool of one plugin declared.
///
/// One instance serves every tool of a plugin, so the import set has to cover
/// all of them. **A refused tool contributes nothing**, because a tool the
/// policy did not allow must not widen what the plugin's guest code can reach
/// through some other tool.
pub fn unionOfCapabilities(
    gpa: std.mem.Allocator,
    session: *const plugin.Session,
    name: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(gpa);
    for (session.offers.items) |offer| {
        if (offer.refused != null) continue;
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

// The gate and the answer reading are tested here against an engine written in
// this file, and that is worth exactly one thing on its own: it proves the
// rules hold against a peer written by the same hand.
//
// **The acceptance test is `test/plugin/engine.zig`**, which builds
// `plugins/hello.zig` for `wasm32-freestanding`, runs it through the real
// engine, and reads the answer real guest code produced. Nothing here is
// allowed to be the only test of anything.

const testing = std.testing;

/// An engine that runs nothing and answers what a test tells it to. It exists
/// for the cases a real module cannot be made to show: an engine that refuses,
/// a guest that answers an address past its own memory, and a tool count that
/// disagrees with the metadata.
const FakeEngine = struct {
    /// The guest's linear memory, owned by the test.
    guest: []u8,
    /// What the module imports.
    wanted: []const Import = &.{},
    /// What `chock_plugin_init` answers.
    binds: u32 = 1,
    /// The address `chock_plugin_call` answers.
    answer_at: u32 = 0,
    /// The address `chock_plugin_arguments` answers. Zero means no room.
    arguments_at: u32 = 0,
    /// Whether `instantiate` refuses.
    refuses: bool = false,
    /// The symbol whose call refuses, if any. **A name and not a flag**,
    /// because the three guest symbols are three separate refusal sites and a
    /// test has to be able to reach exactly one of them.
    refusing_symbol: ?[]const u8 = null,
    /// How many addresses `instantiate` was handed, so a test can pin that the
    /// gate's answer really reaches the engine.
    supplied: usize = 0,
    /// Whether `instantiate` was reached at all. **Separate from `supplied`**,
    /// which is zero both for a module with no import and for a module that
    /// never got that far: only this one tells a gate test that nothing of the
    /// guest was ever built.
    instantiated: bool = false,

    fn engine(self: *FakeEngine) Engine {
        return .{ .ptr = self, .vtable = &vtable };
    }

    /// Whether this call is the one the test asked to refuse.
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

/// A guest memory with one answer record in it, and its text.
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
    // The positive control for the gate. A plugin built for this Chock imports
    // nothing at all: measured on `plugins/hello.zig` built in tree, which has
    // zero imports.
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .success, "Hello, world!");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };

    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);
    try testing.expect(fake.instantiated);
    try testing.expectEqual(@as(usize, 0), fake.supplied);

    const outcome = try runner.call(0, "");
    try testing.expectEqualStrings("Hello, world!", outcome.text);
    try testing.expect(!outcome.is_error);
}

test "a module that imports anything is refused before it is instantiated" {
    // The gate, and the whole point of this file. No capability supplies an
    // import in this build, so a module that wants one never runs.
    //
    // Mutation check: let `gate` pass an uncovered import through and
    // `instantiate` is reached, which this test catches by `supplied`.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{
        .guest = &guest,
        .wanted = &.{.{ .module = "env", .field = "read_file" }},
    };

    var runner: Runner = .{ .engine = fake.engine() };
    var refused: ?Refused = null;
    try testing.expectError(
        error.ImportNotDeclared,
        runner.load(testing.allocator, "module", 1, fake.wanted, &.{"fs.read"}, &refused),
    );
    // Nothing of the guest ran, which is the property that matters: the engine
    // was never told to build anything.
    try testing.expect(!fake.instantiated);
    try testing.expect(!runner.ready);
    try testing.expectEqualStrings("read_file", refused.?.wanted.field);
}

test "a declared capability does not supply an import in this build, and says so" {
    // The honest half of the gate. `fs.read` is a real capability that
    // `chock_core.plugin` prices against the policy table, and it still
    // supplies no import, because this build has no host function behind it.
    // A plugin built against one is refused rather than half served.
    try testing.expectEqual(@as(usize, 0), importsFor("fs.read").len);
    try testing.expectEqual(@as(usize, 0), importsFor("git.commit").len);
    try testing.expectEqual(@as(usize, 0), importsFor("anything.at.all").len);
}

test "a guest whose bound count disagrees with its metadata is refused" {
    // Both numbers come from one compilation: the metadata says how many tools
    // the author declared and `chock_plugin_init` binds one per declared tool.
    // A disagreement means the module was changed after it was built, and
    // every index would then name the wrong tool.
    //
    // Mutation check: drop the comparison and a module with the tool list
    // rewritten calls whatever sits at that index.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .binds = 3 };

    var runner: Runner = .{ .engine = fake.engine() };
    try testing.expectError(
        error.ToolCountDisagrees,
        runner.load(testing.allocator, "module", 1, &.{}, &.{}, null),
    );
    try testing.expect(!runner.ready);
}

test "an answer pointing past the guest's own memory is refused rather than read" {
    // The fault that follows from Vulcan checking nothing. A guest that names
    // an address past its memory would otherwise have this host read whatever
    // the allocator put after it, and put those bytes in front of the model.
    //
    // Mutation check: read the record without `readAnswer` and this test reads
    // past the end of `guest`.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    // A text that starts inside the memory and ends outside it.
    std.mem.writeInt(u32, guest[16 + core.call.Answer.text_ptr_offset ..][0..4], 1000, .little);
    std.mem.writeInt(u32, guest[16 + core.call.Answer.text_len_offset ..][0..4], 500, .little);
    try testing.expectError(error.GuestMisbehaved, runner.call(0, ""));
}

test "a tool index no guest bound is refused without reaching the engine" {
    // The host reads the tool list out of the metadata, so it knows how many
    // there are. An index past that never becomes a call.
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .success, "unreachable");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    try testing.expectError(error.EngineRefused, runner.call(1, ""));
    try testing.expectError(error.EngineRefused, runner.call(99, ""));
}

test "a runner that never loaded refuses every call" {
    // A host process whose module would not instantiate must answer and never
    // reach into a memory that was never built.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .refuses = true };
    var runner: Runner = .{ .engine = fake.engine() };

    try testing.expectError(
        error.EngineRefused,
        runner.load(testing.allocator, "module", 1, &.{}, &.{}, null),
    );
    try testing.expect(!runner.ready);
    try testing.expectError(error.EngineRefused, runner.call(0, ""));
}

test "every refusal names the call it came out of" {
    // **The fault this pins is a log nobody can read.** `EngineRefused` is
    // one word for seven places, and a CI run on a machine the owner does not
    // have is exactly where that word costs the most: it says a plugin did
    // not run and nothing about which step of running it stopped.
    //
    // Mutation check: answer `error.EngineRefused` anywhere in this file
    // without going through `Runner.refuse` and one of these reads the
    // refusal of an earlier line.
    var guest: [1024]u8 = @splat(0);

    {
        var fake: FakeEngine = .{ .guest = &guest, .refuses = true };
        var runner: Runner = .{ .engine = fake.engine() };
        try testing.expectError(
            error.EngineRefused,
            runner.load(testing.allocator, "module", 1, &.{}, &.{}, null),
        );
        try testing.expectEqual(Diagnostic.Call.instantiate, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);

        // The same runner, still not ready, refuses a call for a different
        // reason, and says so.
        try testing.expectError(error.EngineRefused, runner.call(0, ""));
        try testing.expectEqual(Diagnostic.Call.before_instantiation, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, null), runner.refusal.?.cause);
    }

    {
        var fake: FakeEngine = .{ .guest = &guest, .refusing_symbol = core.init_symbol };
        var runner: Runner = .{ .engine = fake.engine() };
        try testing.expectError(
            error.EngineRefused,
            runner.load(testing.allocator, "module", 1, &.{}, &.{}, null),
        );
        try testing.expectEqual(Diagnostic.Call.init_call, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);
    }

    {
        stageAnswer(&guest, 16, .success, "unreachable");
        var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(1, ""));
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
        try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(0, "{\"a\":1}"));
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
        try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(0, ""));
        try testing.expectEqual(Diagnostic.Call.tool_call, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, error.Refused), runner.refusal.?.cause);
    }

    {
        // `no_answer` is the address the guest answers when it has nothing,
        // and it is what `FakeEngine` answers by default.
        var fake: FakeEngine = .{ .guest = &guest, .answer_at = core.call.no_answer };
        var runner: Runner = .{ .engine = fake.engine() };
        try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);
        try testing.expectError(error.EngineRefused, runner.call(0, ""));
        try testing.expectEqual(Diagnostic.Call.empty_answer, runner.refusal.?.call);
        try testing.expectEqual(@as(?anyerror, null), runner.refusal.?.cause);
    }
}

test "a refusal reads as a sentence, and no two of them read the same" {
    var buffer: [256]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);

    // The one a real x86_64 runner produced, measured 2026-08-26: Vulcan's
    // JIT would not build the module. See this file's `Diagnostic`.
    try writer.print("{f}", .{Diagnostic{ .call = .instantiate, .cause = error.Unsupported }});
    try testing.expectEqualStrings(
        "the engine would not instantiate the module: Unsupported",
        writer.buffered(),
    );

    // A refusal with no engine behind it prints the fact and stops. **No
    // trailing colon**, because there is nothing after it to read.
    writer = .fixed(&buffer);
    try writer.print("{f}", .{Diagnostic{ .call = .tool_index }});
    try testing.expectEqualStrings(
        "a tool was called by an index the module never bound",
        writer.buffered(),
    );

    // **No two calls read the same.** A reader has to be able to tell which
    // of the seven sites answered, which is the whole reason this type exists.
    const calls = std.enums.values(Diagnostic.Call);
    for (calls, 0..) |one, i| {
        try testing.expect(one.text().len > 0);
        for (calls[i + 1 ..]) |other| {
            try testing.expect(!std.mem.eql(u8, one.text(), other.text()));
        }
    }
}

test "arguments the guest has no room for are refused, and never written anyway" {
    // The guest owns the bound on its own buffer and answers zero when the
    // text does not fit. A host that wrote regardless would be writing past
    // the buffer, which is the worse half of the same fault as a bad read.
    //
    // Mutation check: treat address zero as usable and this writes at the
    // start of the guest's memory, over whatever is there.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 0 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    try testing.expectError(error.ArgumentsTooLong, runner.call(0, "{\"a\":1}"));
    // Nothing was written: the first bytes of the guest's memory are still the
    // answer record this test staged and not the arguments.
    try testing.expectEqual(@as(u8, 0), guest[0]);
}

test "an argument address the guest answered is checked before anything is written" {
    // A guest that answered an address near the end of its own memory would
    // otherwise have this host write past it.
    //
    // Mutation check: drop the `end > memory.len` test and this writes past
    // the end of `guest`.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 1020 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    try testing.expectError(error.GuestMisbehaved, runner.call(0, "{\"a\":1}"));
}

test "arguments that fit really reach the guest's memory" {
    // The other side of the two tests above: the ordinary path has to work, or
    // `Context.arguments` is a field a tool body can never read.
    var guest: [1024]u8 = @splat(0);
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16, .arguments_at = 512 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    stageAnswer(&guest, 16, .success, "done");
    const outcome = try runner.call(0, "{\"a\":1}");
    try testing.expectEqualStrings("done", outcome.text);
    try testing.expectEqualStrings("{\"a\":1}", guest[512..][0..7]);
}

test "a tool that failed is a result and not a fault of this host" {
    // A plugin that answers `errorResult` did run, and what it said is what
    // the model reads. Turning it into an error here would hide the plugin's
    // own words behind this host's.
    var guest: [1024]u8 = @splat(0);
    stageAnswer(&guest, 16, .failure, "no such file");
    var fake: FakeEngine = .{ .guest = &guest, .answer_at = 16 };
    var runner: Runner = .{ .engine = fake.engine() };
    try runner.load(testing.allocator, "module", 1, &.{}, &.{}, null);

    const outcome = try runner.call(0, "");
    try testing.expect(outcome.is_error);
    try testing.expectEqualStrings("no such file", outcome.text);
}

test "the union of capabilities leaves out a tool the policy refused" {
    // A refused tool must not widen what the plugin's guest code reaches
    // through some other tool. One instance serves every tool of a plugin, so
    // the import set is decided once and a refused tool contributing to it
    // would be a denied permission arriving by the side door.
    //
    // Mutation check: include a refused offer and `fs.write` appears here.
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

/// A policy that allows everything but one action.
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
    // `plugin_module` is named here so a reader of this file finds the step
    // that comes before it, and so the two never drift into separate ideas of
    // what a module is.
    _ = plugin_module.max_module_bytes;
}
