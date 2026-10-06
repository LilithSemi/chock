//! Which way of sandboxing a session uses, and who may say so.
//!
//! **Not the project.** `lib/chock-policy/ratchet.zig` states the rule this
//! follows: a project may only narrow what it may do. A project that could name
//! its own sandbox driver could name a weaker one, and that widens. So this block
//! is read from the operator's own `config.zon`, which lives in the configuration
//! directory the sandbox puts beyond an agent's reach, and never from `chock.zon`.
//!
//! An organisation can pin or forbid a driver through `Ceiling`, the way it
//! already does for a search engine's kind: see `lib/chock-policy/search.zig`.
//!
//! ## A driver is not a permission
//!
//! Choosing `microvm` adds a layer and takes nothing away: a guest has a kernel
//! of its own, so the driver that already exists runs inside it. See
//! `docs/security/microvm.md`. Choosing `native` is today's behaviour.

const std = @import("std");

const limits = @import("limits.zig");

pub const block_name = "sandbox";

/// The ways of sandboxing a person may name. An enum and not a free string: a
/// reader has to act on this value, and a free string cannot be told apart from a
/// typo.
pub const Driver = enum {
    /// The one for the machine Chock runs on. What a file that names none gets.
    native,
    /// A Linux guest, with the native Linux driver running inside it.
    microvm,

    pub fn wireName(self: Driver) []const u8 {
        return switch (self) {
            .native => "native",
            .microvm => "microvm",
        };
    }

    pub fn fromWireName(text: []const u8) ?Driver {
        inline for (@typeInfo(Driver).@"enum".fields) |field| {
            const one: Driver = @enumFromInt(field.value);
            if (std.mem.eql(u8, one.wireName(), text)) return one;
        }
        return null;
    }

    pub const all_wire_names = "native, microvm";
};

/// How much memory a guest is given when the file names none.
pub const default_memory_mb: u64 = 512;

/// How many processors a guest is given for a machine of `available`, when the
/// file names no number.
///
/// **A small machine keeps most of itself, and a large one is capped.** A guest
/// that took half of an eight core laptop would leave the host, which is running
/// the model call, the terminal and the agent's own harness, with too little to
/// stay responsive. Past two dozen the guest gains little from more: what it runs
/// is one call at a time, and the rest is better left where the rest of the work
/// is.
///
/// The steps are a table rather than a ratio because no single ratio says both
/// things: a quarter is right at eight and miserly at twenty four, and a half is
/// right at twenty four and greedy at eight.
pub fn scaledCores(available: usize) u32 {
    if (available >= 24) return 12;
    if (available >= 16) return 6;
    if (available >= 12) return 4;
    if (available >= 8) return 2;
    return 1;
}

/// The most processors a guest on a Mac is given, whatever the curve says.
///
/// **The interrupt controller decides this, not the machine.** A guest there gets
/// a version 2 controller, and that version has no CPU interface past eight. Asked
/// for more, Mirage refuses in words when the guest starts rather than booting
/// something lame, so the clamp belongs here where the number is chosen.
pub const darwin_max_cores: u32 = 8;

/// The curve, with what the machine a guest runs on can actually give.
pub fn coresOn(available: usize, on: std.Target.Os.Tag) u32 {
    const wanted = scaledCores(available);
    return switch (on) {
        .macos => @min(wanted, darwin_max_cores),
        else => wanted,
    };
}

/// What the machine a guest is started on has to give. Read once by the caller,
/// so the two answers below are chosen against the same numbers.
pub const Machine = struct {
    total_mb: u64,
    cores: usize,

    /// A machine nothing could be read from: one processor and no memory to
    /// share, which gives the smallest guest the curves allow.
    pub const unknown: Machine = .{ .total_mb = 0, .cores = 1 };

    pub fn now() Machine {
        const read = limits.Machine.read() catch return unknown;
        return .{
            .total_mb = read.memory_bytes / (1024 * 1024),
            .cores = read.cpu_count,
        };
    }
};

/// The largest share of a machine's memory a guest takes when the file names no
/// size. The host runs the model call, the terminal and the agent's own harness
/// beside the guest, and an eighth leaves all of that room on every size of
/// machine a ratio has to cover.
pub const memory_share: u64 = 8;

/// How much memory one processor of a guest is given, and the least it can run a
/// compiler on. A build runner starts one job a processor, so these two numbers
/// together are what decides whether a build fits.
pub const memory_mb_a_core: u64 = 1024;
pub const least_memory_mb_a_core: u64 = 512;

/// How many processors a guest gets, with the memory to feed them.
///
/// **The core curve alone is not enough.** A machine with two dozen processors
/// and little memory would give a guest twelve of them and an eighth of a small
/// total, and a build runner starting one job a processor is then killed for
/// memory rather than slowed. So the count is also capped by what the guest's own
/// share of memory can feed, and never below one.
pub fn processorsOn(machine: Machine, on: std.Target.Os.Tag) u32 {
    const wanted = coresOn(machine.cores, on);
    const spare = machine.total_mb / memory_share;
    const fed: u64 = spare / least_memory_mb_a_core;
    if (fed == 0) return 1;
    return @intCast(@max(1, @min(@as(u64, wanted), fed)));
}

/// How much memory a guest gets: one gigabyte for each processor it ended up
/// with, never more than its share of the machine, and never less than what a
/// guest was given before any of this scaled.
pub fn memoryOn(machine: Machine, on: std.Target.Os.Tag) u64 {
    const wanted = @as(u64, processorsOn(machine, on)) * memory_mb_a_core;
    const spare = machine.total_mb / memory_share;
    return @max(default_memory_mb, @min(wanted, spare));
}

/// The `sandbox` block of the operator's own file.
pub const Block = struct {
    /// Null for a file that names none, which is every file today and answers
    /// `native`.
    driver: ?Driver = null,
    /// The kernel a guest boots, and its initial filesystem. **Owned**, because
    /// `parse` frees the tree it read them out of: a borrowed slice here was a
    /// dangling pointer the moment the block was returned.
    ///
    /// **Required for `microvm`, and never guessed at.** A path derived from where
    /// the binary happens to sit would be a layout this module invented, and a
    /// person who moved the files would get a session that does not start with no
    /// idea which path was tried.
    kernel: ?[]const u8 = null,
    initrd: ?[]const u8 = null,
    memory_mb: ?u64 = null,
    /// How many processors a guest is given, or null to scale with the machine.
    /// See `scaledCores`.
    cores: ?u32 = null,

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        if (self.kernel) |one| gpa.free(one);
        if (self.initrd) |one| gpa.free(one);
        self.* = undefined;
    }

    pub fn chosen(self: Block) Driver {
        return self.driver orelse .native;
    }

    /// A size in the file is taken as it is. See `memoryOn` for the curve.
    pub fn memory(self: Block, machine: Machine, on: std.Target.Os.Tag) u64 {
        return self.memory_mb orelse memoryOn(machine, on);
    }

    /// How many processors a guest gets. A number in the file is taken as it is:
    /// an operator who names one has a reason, and the machine's own numbers are
    /// what they were choosing against.
    pub fn processors(self: Block, machine: Machine, on: std.Target.Os.Tag) u32 {
        return self.cores orelse processorsOn(machine, on);
    }

    /// What is missing before this block can start a session, or null when it can.
    pub fn missing(self: Block) ?[]const u8 {
        if (self.chosen() != .microvm) return null;
        if (self.kernel == null) return "kernel";
        if (self.initrd == null) return "initrd";
        return null;
    }
};

/// What an organisation permits. Absent `drivers` permits every one, which is
/// what a bundle that says nothing means.
pub const Ceiling = struct {
    drivers: ?[]const Driver = null,
};

pub const CeilingError = error{
    DriverNotPermitted,
};

/// Whether `wanted` is one this organisation permits.
///
/// **A bundle that names a driver narrows and never widens.** A bundle naming
/// only `microvm` means a session on a machine that cannot boot one does not
/// start, which is the point: an organisation that requires a guest requires it.
pub fn underCeiling(ceiling: Ceiling, wanted: Driver) CeilingError!void {
    const permitted = ceiling.drivers orelse return;
    for (permitted) |one| {
        if (one == wanted) return;
    }
    return error.DriverNotPermitted;
}

pub const ParseError = error{
    OutOfMemory,
    InvalidSandbox,
};

pub const Diagnostic = struct {
    fault: Fault,

    pub const Fault = union(enum) {
        not_a_struct_literal,
        driver_not_a_string,
        driver_unknown: []const u8,
        driver_empty,
        path_not_a_string: []const u8,
        path_empty: []const u8,
        path_not_absolute: []const u8,
        memory_not_a_number,
        cores_not_a_number,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .driver_unknown => |name| gpa.free(name),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .not_a_struct_literal => try writer.writeAll(
                "the sandbox block must be a struct literal",
            ),
            .driver_not_a_string => try writer.writeAll(
                "the sandbox driver must be a string",
            ),
            .driver_empty => try writer.print(
                "the sandbox driver is empty. It is one of: {s}",
                .{Driver.all_wire_names},
            ),
            .driver_unknown => |name| try writer.print(
                "the sandbox driver \"{s}\" is not one this build has. It is one of: {s}",
                .{ name, Driver.all_wire_names },
            ),
            .path_not_a_string => |field| try writer.print(
                "the sandbox {s} must be a string",
                .{field},
            ),
            .path_empty => |field| try writer.print(
                "the sandbox {s} is empty, and a path cannot be",
                .{field},
            ),
            .path_not_absolute => |field| try writer.print(
                "the sandbox {s} must be an absolute path: a guest is started by the daemon, " ++
                    "whose working directory is not the one this file was written in",
                .{field},
            ),
            .memory_not_a_number => try writer.writeAll(
                "the sandbox memory_mb must be a number of megabytes",
            ),
            .cores_not_a_number => try writer.writeAll(
                "the sandbox cores must be a number of processors, and at least one",
            ),
        }
    }
};

fn note(out: ?*?Diagnostic, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .fault = fault };
    return true;
}

/// An allocator that zeroes a block before it hands it back, and otherwise is
/// the one it was given.
///
/// **`std.mem.Allocator.free` writes over released bytes only where runtime
/// safety is on**, so a release build leaves them readable for as long as the
/// memory behind them is unused. `resize` and `remap` both refuse, which makes
/// the caller allocate, copy and free instead, so a block that grows is zeroed
/// where it was rather than left behind.
const Zeroing = struct {
    child: std.mem.Allocator,

    fn allocator(self: *Zeroing) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = std.mem.Allocator.noResize,
        .remap = std.mem.Allocator.noRemap,
        .free = free,
    };

    fn alloc(ptr: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Zeroing = @ptrCast(@alignCast(ptr));
        return self.child.rawAlloc(len, alignment, ret_addr);
    }

    fn free(ptr: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Zeroing = @ptrCast(@alignCast(ptr));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, ret_addr);
    }
};

/// Read the `sandbox` block out of a whole `config.zon`. A file with no such
/// block answers a block that names nothing, which is `native`.
///
/// **The tree is zeroed as it is freed, and that is not an optimisation.** The
/// file this reads can carry a provider token inline, and `ZonGen` with
/// `parse_str_lits` keeps a copy of every string literal in it, so the token is
/// in two places until the tree goes. A caller that hands this an arena cannot
/// give that copy back, and plain `free` only overwrites it where runtime safety
/// is on, which is a credential whose scrubbing depends on the optimize mode. So
/// the tree is read through `Zeroing` and the paths the block keeps are duped
/// with `gpa` itself, which is also what makes `Block.deinit` take `gpa`.
pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    var zeroing: Zeroing = .{ .child = gpa };
    const tree = zeroing.allocator();

    var ast = std.zig.Ast.parse(tree, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(tree);

    var zoir = try std.zig.ZonGen.generate(tree, ast, .{ .parse_str_lits = true });
    defer zoir.deinit(tree);
    if (zoir.hasCompileErrors()) return .{};

    const node = try findBlock(zoir, diag) orelse return .{};
    return readDriver(gpa, zoir, node, diag);
}

fn findBlock(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, at| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(at));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidSandbox;
        },
    }
}

fn readDriver(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const fields = switch (node.get(zoir)) {
        .empty_literal => return .{},
        .struct_literal => |it| it,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidSandbox;
        },
    };

    var block: Block = .{};
    errdefer block.deinit(gpa);

    for (fields.names, 0..) |name, at| {
        const field = name.get(zoir);
        const value = fields.vals.at(@intCast(at));

        if (std.mem.eql(u8, field, "driver")) {
            const text = switch (value.get(zoir)) {
                .string_literal => |it| it,
                else => {
                    _ = note(diag, .driver_not_a_string);
                    return error.InvalidSandbox;
                },
            };
            if (text.len == 0) {
                _ = note(diag, .driver_empty);
                return error.InvalidSandbox;
            }
            block.driver = Driver.fromWireName(text) orelse {
                _ = note(diag, .{ .driver_unknown = try gpa.dupe(u8, text) });
                return error.InvalidSandbox;
            };
        } else if (std.mem.eql(u8, field, "kernel")) {
            block.kernel = try readPath(gpa, zoir, value, "kernel", diag);
        } else if (std.mem.eql(u8, field, "initrd")) {
            block.initrd = try readPath(gpa, zoir, value, "initrd", diag);
        } else if (std.mem.eql(u8, field, "memory_mb")) {
            block.memory_mb = switch (value.get(zoir)) {
                .int_literal => |it| switch (it) {
                    .small => |small| if (small > 0) @intCast(small) else {
                        _ = note(diag, .memory_not_a_number);
                        return error.InvalidSandbox;
                    },
                    .big => {
                        _ = note(diag, .memory_not_a_number);
                        return error.InvalidSandbox;
                    },
                },
                else => {
                    _ = note(diag, .memory_not_a_number);
                    return error.InvalidSandbox;
                },
            };
        } else if (std.mem.eql(u8, field, "cores")) {
            block.cores = switch (value.get(zoir)) {
                .int_literal => |it| switch (it) {
                    .small => |small| if (small > 0) @intCast(small) else {
                        _ = note(diag, .cores_not_a_number);
                        return error.InvalidSandbox;
                    },
                    .big => {
                        _ = note(diag, .cores_not_a_number);
                        return error.InvalidSandbox;
                    },
                },
                else => {
                    _ = note(diag, .cores_not_a_number);
                    return error.InvalidSandbox;
                },
            };
        }
        // A field this build does not know is left alone, the rule
        // `lib/chock-auth/config.zig` keeps for a top level block: a later Chock
        // may write more here and an older one must still read the driver.
    }

    return block;
}

/// A path out of the block, absolute, not empty, and owned by the caller.
fn readPath(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    value: std.zig.Zoir.Node.Index,
    field: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    const text = switch (value.get(zoir)) {
        .string_literal => |it| it,
        else => {
            _ = note(diag, .{ .path_not_a_string = field });
            return error.InvalidSandbox;
        },
    };
    if (text.len == 0) {
        _ = note(diag, .{ .path_empty = field });
        return error.InvalidSandbox;
    }
    if (!std.fs.path.isAbsolute(text)) {
        _ = note(diag, .{ .path_not_absolute = field });
        return error.InvalidSandbox;
    }
    return gpa.dupe(u8, text);
}

const testing = std.testing;

test "a guest's memory scales with the machine, and its processors with the memory" {
    const of = struct {
        fn machine(gb: u64, cores: usize) Machine {
            return .{ .total_mb = gb * 1024, .cores = cores };
        }
    };

    // The owner's own machine: a dozen processors and a guest big enough to build
    // on, which is what the 512MB default never was.
    const big = of.machine(512, 24);
    try std.testing.expectEqual(@as(u32, 12), processorsOn(big, .linux));
    try std.testing.expectEqual(@as(u64, 12 * 1024), memoryOn(big, .linux));

    // A laptop, where an eighth of the memory is the binding limit rather than the
    // core curve.
    const laptop = of.machine(8, 8);
    try std.testing.expectEqual(@as(u32, 2), processorsOn(laptop, .linux));
    try std.testing.expectEqual(@as(u64, 1024), memoryOn(laptop, .linux));

    // **Many processors and little memory is the case the core curve alone got
    // wrong.** A build runner starts one job a processor, and twelve of them on an
    // eighth of 8GB is what killed a compiler for memory in a guest.
    const lopsided = of.machine(8, 24);
    try std.testing.expectEqual(@as(u32, 2), processorsOn(lopsided, .linux));

    // Nothing smaller than what a guest was given before any of this scaled.
    try std.testing.expectEqual(@as(u32, 1), processorsOn(Machine.unknown, .linux));
    try std.testing.expectEqual(default_memory_mb, memoryOn(Machine.unknown, .linux));

    // A size or a count in the file wins over both curves.
    const named: Block = .{ .memory_mb = 2048, .cores = 3 };
    try std.testing.expectEqual(@as(u64, 2048), named.memory(big, .linux));
    try std.testing.expectEqual(@as(u32, 3), named.processors(big, .linux));
}

test "a file that names no driver answers native, and so does one with no block" {
    const gpa = testing.allocator;

    for ([_][:0]const u8{ ".{}", ".{ .providers = .{} }", ".{ .sandbox = .{} }" }) |source| {
        var block = try parse(gpa, source, null);
        defer block.deinit(gpa);
        try testing.expectEqual(Driver.native, block.chosen());
        // And a block that names none reports none, which is different from
        // naming `native`: a caller that wants to say "the file chose this" can
        // tell the two apart.
        try testing.expectEqual(@as(?Driver, null), block.driver);
    }
}

test "the operator's own file chooses the driver" {
    const gpa = testing.allocator;

    var wanted = try parse(gpa, ".{ .sandbox = .{ .driver = \"microvm\" } }", null);
    defer wanted.deinit(gpa);
    try testing.expectEqual(Driver.microvm, wanted.driver.?);
    try testing.expectEqual(Driver.microvm, wanted.chosen());

    var plain = try parse(gpa, ".{ .sandbox = .{ .driver = \"native\" } }", null);
    defer plain.deinit(gpa);
    try testing.expectEqual(Driver.native, plain.driver.?);
}

test "a driver this build has no name for is refused, and the message lists the ones it has" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .driver = \"no-sandbox-at-all\" } }", &diag),
    );
    try testing.expectEqualStrings("no-sandbox-at-all", diag.?.fault.driver_unknown);

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "native, microvm") != null);

    // **A typo is never read as a choice.** Answering `native` here would run a
    // session with a boundary the author did not ask for.
    var second: ?Diagnostic = null;
    defer if (second) |*one| one.deinit(gpa);
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .driver = \"microvms\" } }", &second),
    );
}

test "a field this build does not know is left alone, and the driver beside it is read" {
    const gpa = testing.allocator;

    var block = try parse(
        gpa,
        ".{ .sandbox = .{ .no_such_field = 1, .driver = \"microvm\" } }",
        null,
    );
    defer block.deinit(gpa);
    try testing.expectEqual(Driver.microvm, block.driver.?);
}

test "a bundle that names no driver permits every one, and one that names some narrows" {
    // Absent is not empty: a bundle that says nothing about the sandbox must not
    // forbid the driver every session uses today.
    try underCeiling(.{}, .native);
    try underCeiling(.{}, .microvm);

    const only_guest = Ceiling{ .drivers = &.{.microvm} };
    try underCeiling(only_guest, .microvm);
    try testing.expectError(error.DriverNotPermitted, underCeiling(only_guest, .native));

    // An empty list permits nothing, which is a bundle forbidding every driver.
    // It is a strange thing to write and it is not this module's to reinterpret.
    const none = Ceiling{ .drivers = &.{} };
    try testing.expectError(error.DriverNotPermitted, underCeiling(none, .native));
}

test "every driver has a wire name, and the list in the message names all of them" {
    inline for (@typeInfo(Driver).@"enum".fields) |field| {
        const one: Driver = @enumFromInt(field.value);
        try testing.expect(one.wireName().len != 0);
        try testing.expectEqual(one, Driver.fromWireName(one.wireName()).?);
        // A driver added to the enum and left out of the message would be one a
        // person is told does not exist.
        try testing.expect(std.mem.indexOf(u8, Driver.all_wire_names, one.wireName()) != null);
    }
    try testing.expectEqual(@as(?Driver, null), Driver.fromWireName("Native"));
    try testing.expectEqual(@as(?Driver, null), Driver.fromWireName(""));
}

test "a guest needs a kernel and an initrd named, and the missing one is said by name" {
    const gpa = testing.allocator;

    // **Never guessed at.** A path derived from where the binary sits would be a
    // layout this module invented, and a person who moved the files would get a
    // session that does not start with no idea which path was tried.
    var bare = try parse(gpa, ".{ .sandbox = .{ .driver = \"microvm\" } }", null);
    defer bare.deinit(gpa);
    try testing.expectEqualStrings("kernel", bare.missing().?);

    var half = try parse(
        gpa,
        ".{ .sandbox = .{ .driver = \"microvm\", .kernel = \"/k/Image\" } }",
        null,
    );
    defer half.deinit(gpa);
    try testing.expectEqualStrings("initrd", half.missing().?);

    var whole = try parse(
        gpa,
        ".{ .sandbox = .{ .driver = \"microvm\", .kernel = \"/k/Image\", .initrd = \"/k/i\" } }",
        null,
    );
    defer whole.deinit(gpa);
    try testing.expectEqual(@as(?[]const u8, null), whole.missing());
    try testing.expectEqualStrings("/k/Image", whole.kernel.?);
    try testing.expectEqualStrings("/k/i", whole.initrd.?);

    // The native driver needs neither, so a file that names a kernel and stays
    // native is not refused for it.
    var plain = try parse(gpa, ".{ .sandbox = .{ .kernel = \"/k/Image\" } }", null);
    defer plain.deinit(gpa);
    try testing.expectEqual(@as(?[]const u8, null), plain.missing());
}

test "a relative guest path is refused, because the daemon starts the guest" {
    const gpa = testing.allocator;

    // The daemon's working directory is not the one this file was written in, so a
    // relative path would name a file that is not there, or worse, one that is.
    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .kernel = \"guest/Image\" } }", &diag),
    );
    try testing.expectEqualStrings("kernel", diag.?.fault.path_not_absolute);

    var rendered: std.ArrayList(u8) = .empty;
    defer rendered.deinit(gpa);
    try rendered.print(gpa, "{f}", .{diag.?});
    try testing.expect(std.mem.indexOf(u8, rendered.items, "absolute path") != null);
}

test "how much memory a guest gets, and a value that is not a count is refused" {
    const gpa = testing.allocator;

    var none = try parse(gpa, ".{}", null);
    defer none.deinit(gpa);
    try testing.expectEqual(default_memory_mb, none.memory(Machine.unknown, .linux));

    var given = try parse(gpa, ".{ .sandbox = .{ .memory_mb = 2048 } }", null);
    defer given.deinit(gpa);
    try testing.expectEqual(@as(u64, 2048), given.memory(Machine.unknown, .linux));

    // Zero is not a size, and neither is a string.
    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .memory_mb = 0 } }", &diag),
    );
    var second: ?Diagnostic = null;
    defer if (second) |*one| one.deinit(gpa);
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .memory_mb = \"lots\" } }", &second),
    );
}

test "the processor count scales with the machine, and stops at both ends" {
    // The four Ross named, which are what the steps were drawn through.
    try testing.expectEqual(@as(u32, 2), scaledCores(8));
    try testing.expectEqual(@as(u32, 4), scaledCores(12));
    try testing.expectEqual(@as(u32, 12), scaledCores(24));
    try testing.expectEqual(@as(u32, 12), scaledCores(128));

    // A machine too small to share still runs a guest, on one.
    try testing.expectEqual(@as(u32, 1), scaledCores(1));
    try testing.expectEqual(@as(u32, 1), scaledCores(7));

    // It never goes down as the machine grows, which a table is easy to break.
    var last: u32 = 0;
    var cores: usize = 1;
    while (cores <= 256) : (cores += 1) {
        const now = scaledCores(cores);
        try testing.expect(now >= last);
        last = now;
    }
    try testing.expectEqual(@as(u32, 12), last);
}

test "a guest on a Mac is held to what its interrupt controller has" {
    // Twelve is right for twenty four cores and impossible on a Mac: a version 2
    // controller has no CPU interface past eight, and Mirage refuses rather than
    // booting something lame.
    try testing.expectEqual(@as(u32, 12), coresOn(24, .linux));
    try testing.expectEqual(@as(u32, 8), coresOn(24, .macos));
    try testing.expectEqual(@as(u32, 8), coresOn(128, .macos));

    // Below the ceiling the curve is the curve, on either.
    try testing.expectEqual(@as(u32, 4), coresOn(12, .macos));
    try testing.expectEqual(@as(u32, 2), coresOn(8, .macos));
}

test "a number in the file is taken as it is, and no number scales" {
    const gpa = testing.allocator;

    var named = try parse(gpa, ".{ .sandbox = .{ .cores = 3 } }", null);
    defer named.deinit(gpa);
    try testing.expectEqual(@as(u32, 3), named.processors(.{ .total_mb = 512 * 1024, .cores = 128 }, .linux));

    var silent = try parse(gpa, ".{ .sandbox = .{} }", null);
    defer silent.deinit(gpa);
    try testing.expectEqual(@as(u32, 12), silent.processors(.{ .total_mb = 512 * 1024, .cores = 24 }, .linux));

    // Zero is not a machine, and neither is a word.
    var diag: ?Diagnostic = null;
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .cores = 0 } }", &diag),
    );
    try testing.expectError(
        error.InvalidSandbox,
        parse(gpa, ".{ .sandbox = .{ .cores = \"many\" } }", null),
    );
}
