//! Which way of sandboxing a session uses. Read from the operator's own
//! `config.zon`, never from `chock.zon`, so a project cannot name a weaker
//! driver for itself.

const std = @import("std");

const limits = @import("limits.zig");

pub const block_name = "sandbox";

pub const Driver = enum {
    native,
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

pub const default_memory_mb: u64 = 512;

pub fn scaledCores(available: usize) u32 {
    if (available >= 24) return 12;
    if (available >= 16) return 6;
    if (available >= 12) return 4;
    if (available >= 8) return 2;
    return 1;
}

/// The most processors a guest on a Mac is given: its version 2 interrupt
/// controller has no CPU interface past eight.
pub const darwin_max_cores: u32 = 8;

pub fn coresOn(available: usize, on: std.Target.Os.Tag) u32 {
    const wanted = scaledCores(available);
    return switch (on) {
        .macos => @min(wanted, darwin_max_cores),
        else => wanted,
    };
}

pub const Machine = struct {
    total_mb: u64,
    cores: usize,

    pub const unknown: Machine = .{ .total_mb = 0, .cores = 1 };

    pub fn now() Machine {
        const read = limits.Machine.read() catch return unknown;
        return .{
            .total_mb = read.memory_bytes / (1024 * 1024),
            .cores = read.cpu_count,
        };
    }
};

pub const memory_share: u64 = 8;

pub const memory_mb_a_core: u64 = 1024;
pub const least_memory_mb_a_core: u64 = 512;

pub fn processorsOn(machine: Machine, on: std.Target.Os.Tag) u32 {
    const wanted = coresOn(machine.cores, on);
    const spare = machine.total_mb / memory_share;
    const fed: u64 = spare / least_memory_mb_a_core;
    if (fed == 0) return 1;
    return @intCast(@max(1, @min(@as(u64, wanted), fed)));
}

pub fn memoryOn(machine: Machine, on: std.Target.Os.Tag) u64 {
    const wanted = @as(u64, processorsOn(machine, on)) * memory_mb_a_core;
    const spare = machine.total_mb / memory_share;
    return @max(default_memory_mb, @min(wanted, spare));
}

pub const Block = struct {
    driver: ?Driver = null,
    /// Owned: `parse` frees the tree it read this out of, so a borrowed
    /// slice here would dangle.
    kernel: ?[]const u8 = null,
    initrd: ?[]const u8 = null,
    memory_mb: ?u64 = null,
    cores: ?u32 = null,

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        if (self.kernel) |one| gpa.free(one);
        if (self.initrd) |one| gpa.free(one);
        self.* = undefined;
    }

    pub fn chosen(self: Block) Driver {
        return self.driver orelse .native;
    }

    pub fn memory(self: Block, machine: Machine, on: std.Target.Os.Tag) u64 {
        return self.memory_mb orelse memoryOn(machine, on);
    }

    pub fn processors(self: Block, machine: Machine, on: std.Target.Os.Tag) u32 {
        return self.cores orelse processorsOn(machine, on);
    }

    pub fn missing(self: Block) ?[]const u8 {
        if (self.chosen() != .microvm) return null;
        if (self.kernel == null) return "kernel";
        if (self.initrd == null) return "initrd";
        return null;
    }
};

pub const Ceiling = struct {
    drivers: ?[]const Driver = null,
};

pub const CeilingError = error{
    DriverNotPermitted,
};

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

/// Zeroes memory before it frees it, since plain `free` leaves a release
/// build's freed credentials readable.
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

/// The file this reads can carry a provider token inline, so the syntax
/// tree is read through `Zeroing`.
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
        // Left alone: a later Chock may write more here.
    }

    return block;
}

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

    const big = of.machine(512, 24);
    try std.testing.expectEqual(@as(u32, 12), processorsOn(big, .linux));
    try std.testing.expectEqual(@as(u64, 12 * 1024), memoryOn(big, .linux));

    const laptop = of.machine(8, 8);
    try std.testing.expectEqual(@as(u32, 2), processorsOn(laptop, .linux));
    try std.testing.expectEqual(@as(u64, 1024), memoryOn(laptop, .linux));

    const lopsided = of.machine(8, 24);
    try std.testing.expectEqual(@as(u32, 2), processorsOn(lopsided, .linux));

    try std.testing.expectEqual(@as(u32, 1), processorsOn(Machine.unknown, .linux));
    try std.testing.expectEqual(default_memory_mb, memoryOn(Machine.unknown, .linux));

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
    try underCeiling(.{}, .native);
    try underCeiling(.{}, .microvm);

    const only_guest = Ceiling{ .drivers = &.{.microvm} };
    try underCeiling(only_guest, .microvm);
    try testing.expectError(error.DriverNotPermitted, underCeiling(only_guest, .native));

    const none = Ceiling{ .drivers = &.{} };
    try testing.expectError(error.DriverNotPermitted, underCeiling(none, .native));
}

test "every driver has a wire name, and the list in the message names all of them" {
    inline for (@typeInfo(Driver).@"enum".fields) |field| {
        const one: Driver = @enumFromInt(field.value);
        try testing.expect(one.wireName().len != 0);
        try testing.expectEqual(one, Driver.fromWireName(one.wireName()).?);
        try testing.expect(std.mem.indexOf(u8, Driver.all_wire_names, one.wireName()) != null);
    }
    try testing.expectEqual(@as(?Driver, null), Driver.fromWireName("Native"));
    try testing.expectEqual(@as(?Driver, null), Driver.fromWireName(""));
}

test "a guest needs a kernel and an initrd named, and the missing one is said by name" {
    const gpa = testing.allocator;

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

    var plain = try parse(gpa, ".{ .sandbox = .{ .kernel = \"/k/Image\" } }", null);
    defer plain.deinit(gpa);
    try testing.expectEqual(@as(?[]const u8, null), plain.missing());
}

test "a relative guest path is refused, because the daemon starts the guest" {
    const gpa = testing.allocator;

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
    try testing.expectEqual(@as(u32, 2), scaledCores(8));
    try testing.expectEqual(@as(u32, 4), scaledCores(12));
    try testing.expectEqual(@as(u32, 12), scaledCores(24));
    try testing.expectEqual(@as(u32, 12), scaledCores(128));

    try testing.expectEqual(@as(u32, 1), scaledCores(1));
    try testing.expectEqual(@as(u32, 1), scaledCores(7));

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
    try testing.expectEqual(@as(u32, 12), coresOn(24, .linux));
    try testing.expectEqual(@as(u32, 8), coresOn(24, .macos));
    try testing.expectEqual(@as(u32, 8), coresOn(128, .macos));

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
