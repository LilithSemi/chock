//! The sandbox's resource limits, read from three files that spell the same
//! block: the operator's `config.zon` is the machine's default, `chock.zon`
//! overrides it, and the org policy bundle is a ceiling over both.

const std = @import("std");
const builtin = @import("builtin");

pub const file_name = "chock.zon";

/// Copied from `lib/chock-auth/config.zig`, because that library imports no
/// other chock library and this one cannot import it back.
pub const operator_file_name = "config.zon";

pub const max_file_bytes = 1 << 20;

/// Copied from `lib/chock-sandbox/linux/rlimits.zig`. Never used alone:
/// `builtinProcesses` is the bottom of the fold and this is its floor.
pub const default_processes: u64 = 256;

pub const default_memory_bytes: u64 = 2 << 30;

/// On the 128 cpu machine this file exists for, `cargo` ran about 128 parallel
/// `rustc`, each wanting several threads. 8 is a round number above that,
/// chosen so an 8 cpu machine stays under the floor of 256 and a 128 cpu
/// machine reaches 1024 with no project configuring anything.
pub const processes_per_cpu: u64 = 8;

/// An eighth, so a 16 GiB machine reaches exactly `default_memory_bytes` and is
/// unchanged, while the 197 GiB machine this file exists for reaches about
/// 24.6 GiB and still leaves most of the machine for everything else.
pub const memory_share_divisor: u64 = 8;

pub fn builtinProcesses(machine: Machine) Setting {
    return .{ .absolute = @max(default_processes, machine.cpu_count * processes_per_cpu) };
}

pub fn builtinMemory(machine: Machine) Setting {
    return .{ .absolute = @max(default_memory_bytes, machine.memory_bytes / memory_share_divisor) };
}

pub const Setting = union(enum) {
    percent: u7,
    absolute: u64,

    /// `basis` and `100` both fit inside `u128`, so the multiply cannot
    /// overflow whatever `basis` a real machine reports.
    pub fn resolve(self: Setting, basis: u64) u64 {
        return switch (self) {
            .absolute => |value| value,
            .percent => |pct| @intCast(@as(u128, basis) * pct / 100),
        };
    }
};

pub const SettingError = error{
    Malformed,
    PercentOverHundred,
    Overflow,
};

/// The units `parseAbsolute` knows, longest suffix first. Order matters:
/// `KiB` and `GiB` both end in `iB` and every one ends in `B`, so the bare byte
/// suffix has to be tried last or `"4GiB"` reads as the digits `"4Gi"`.
const units = [_]struct { suffix: []const u8, multiplier: u64 }{
    .{ .suffix = "TiB", .multiplier = 1 << 40 },
    .{ .suffix = "GiB", .multiplier = 1 << 30 },
    .{ .suffix = "MiB", .multiplier = 1 << 20 },
    .{ .suffix = "KiB", .multiplier = 1 << 10 },
    .{ .suffix = "B", .multiplier = 1 },
};

fn parseAbsolute(text: []const u8) SettingError!u64 {
    // Checked up front and not left to `std.fmt.parseInt`: that reader accepts
    // a leading '-' on an unsigned type and answers `error.Overflow` for any
    // negative value that is not exactly zero, so "-5" would read as a number
    // too large to hold instead of a shape this field cannot take.
    if (std.mem.startsWith(u8, text, "-")) return error.Malformed;

    for (units) |unit| {
        if (!std.mem.endsWith(u8, text, unit.suffix)) continue;
        const digits = text[0 .. text.len - unit.suffix.len];
        if (digits.len == 0) return error.Malformed;
        const value = std.fmt.parseInt(u64, digits, 10) catch |err| switch (err) {
            error.Overflow => return error.Overflow,
            error.InvalidCharacter => return error.Malformed,
        };
        return std.math.mul(u64, value, unit.multiplier) catch error.Overflow;
    }
    if (text.len == 0) return error.Malformed;
    return std.fmt.parseInt(u64, text, 10) catch |err| switch (err) {
        error.Overflow => error.Overflow,
        error.InvalidCharacter => error.Malformed,
    };
}

pub fn parseSetting(text: []const u8) SettingError!Setting {
    if (std.mem.endsWith(u8, text, "%")) {
        const digits = text[0 .. text.len - 1];
        if (digits.len == 0) return error.Malformed;
        const value = std.fmt.parseInt(u16, digits, 10) catch return error.Malformed;
        if (value > 100) return error.PercentOverHundred;
        return .{ .percent = @intCast(value) };
    }
    return .{ .absolute = try parseAbsolute(text) };
}

/// Every member is optional, so "this file named nothing" is told apart from
/// "this file named today's default".
pub const Limits = struct {
    processes: ?Setting = null,
    memory: ?Setting = null,
};

pub const Resolved = struct {
    processes: u64,
    memory_bytes: u64,
    processes_from_org: bool = false,
    memory_from_org: bool = false,
};

pub fn foldLayers(project: Limits, operator: Limits, ceiling: ?Ceiling, machine: Machine) Resolved {
    const processes_setting = project.processes orelse operator.processes orelse builtinProcesses(machine);
    const memory_setting = project.memory orelse operator.memory orelse builtinMemory(machine);
    const resolved = Resolved{
        .processes = processes_setting.resolve(machine.cpu_count),
        .memory_bytes = memory_setting.resolve(machine.memory_bytes),
    };
    return underCeiling(resolved, ceiling, machine);
}

/// The most an organisation lets any project of this installation ask for.
///
/// Text, and not `Setting`. `org.zig` reads the whole bundle through one
/// `std.zon.parse.fromSliceAlloc` call, which needs one static schema per
/// field, and `std.zon.parse` cannot be told "a bare integer or a quoted
/// string". `.processes = "300"` says what `.processes = 300` says in a
/// project's own file, one keystroke longer.
pub const Ceiling = struct {
    processes: ?[]const u8 = null,
    memory: ?[]const u8 = null,
};

/// A minimum, and never a refusal. A program inside the sandbox cannot see the
/// cap that kills it, so a session held to a lower number without being told
/// would die of a `SIGKILL` that explains nothing. `src/doctor.zig`'s
/// `measureOrgCeilings` is where a person reads the lowered number.
///
/// A ceiling this build cannot parse leaves the field unchanged rather than
/// crashing: the safe reading of "this organisation's number is unreadable" is
/// "this organisation set no ceiling".
pub fn underCeiling(resolved: Resolved, ceiling: ?Ceiling, machine: Machine) Resolved {
    const bound = ceiling orelse return resolved;
    var held = resolved;
    if (bound.processes) |text| {
        if (parseSetting(text)) |setting| {
            const value = setting.resolve(machine.cpu_count);
            if (value < held.processes) {
                held.processes = value;
                held.processes_from_org = true;
            }
        } else |_| {}
    }
    if (bound.memory) |text| {
        if (parseSetting(text)) |setting| {
            const value = setting.resolve(machine.memory_bytes);
            if (value < held.memory_bytes) {
                held.memory_bytes = value;
                held.memory_from_org = true;
            }
        } else |_| {}
    }
    return held;
}

pub const Machine = struct {
    cpu_count: u64,
    memory_bytes: u64,

    pub const ReadError = error{CannotReadMachine};

    /// A caller reads these once, before it sizes a sandbox, and never from
    /// inside one: `namespace.zig` hides `/proc/meminfo` from the program a
    /// limit bounds precisely so it cannot be confused by the host's numbers.
    pub fn read() ReadError!Machine {
        const cpu_count = std.Thread.getCpuCount() catch return error.CannotReadMachine;
        const memory_bytes = try readMemoryBytes();
        return .{ .cpu_count = cpu_count, .memory_bytes = memory_bytes };
    }
};

fn readMemoryBytes() Machine.ReadError!u64 {
    switch (builtin.os.tag) {
        .linux => {
            var info: std.os.linux.Sysinfo = undefined;
            if (std.os.linux.errno(std.os.linux.sysinfo(&info)) != .SUCCESS) {
                return error.CannotReadMachine;
            }
            return @as(u64, info.totalram) * @as(u64, info.mem_unit);
        },
        .macos => {
            var value: u64 = 0;
            var len: usize = @sizeOf(u64);
            const rc = std.c.sysctlbyname("hw.memsize", &value, &len, null, 0);
            if (rc != 0) return error.CannotReadMachine;
            return value;
        },
        else => return error.CannotReadMachine,
    }
}

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Fault = union(enum) {
        file_not_zon: std.zon.parse.Diagnostics,
        not_a_struct_literal,
        unknown_field: []const u8,
        value_not_string_or_number: []const u8,
        invalid_setting: InvalidSetting,
        negative_setting: []const u8,
        setting_overflow: []const u8,
        file_too_large: usize,
        read_failed: anyerror,
    };

    pub const InvalidSetting = struct {
        field: []const u8,
        text: []const u8,
        reason: SettingError,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| zon_diag.deinit(gpa),
            .unknown_field, .value_not_string_or_number, .negative_setting, .setting_overflow => |name| gpa.free(name),
            .invalid_setting => |setting| {
                gpa.free(setting.field);
                gpa.free(setting.text);
            },
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.fault) {
            .file_not_zon => |*zon_diag| try writer.print(
                "{s} is not valid:\n{f}",
                .{ self.source, zon_diag },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{self.source},
            ),
            .unknown_field => |field| try writer.print(
                "{s}: the limits block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .value_not_string_or_number => |field| try writer.print(
                "{s}: the limits block's {s} field must be a percentage, an absolute value, or a number",
                .{ self.source, field },
            ),
            .invalid_setting => |setting| try writer.print(
                "{s}: the limits block's {s} field holds \"{s}\", which {s}",
                .{ self.source, setting.field, setting.text, reasonText(setting.reason) },
            ),
            .negative_setting => |field| try writer.print(
                "{s}: the limits block's {s} field is a negative number, and a resource limit cannot be",
                .{ self.source, field },
            ),
            .setting_overflow => |field| try writer.print(
                "{s}: the limits block's {s} field names a number too large to hold",
                .{ self.source, field },
            ),
            .file_too_large => |limit| try writer.print(
                "{s}: the file is larger than {d} bytes, so it was not read",
                .{ self.source, limit },
            ),
            .read_failed => |err| try writer.print(
                "{s}: the file could not be read: {t}",
                .{ self.source, err },
            ),
        }
    }
};

pub fn reasonText(reason: SettingError) []const u8 {
    return switch (reason) {
        error.Malformed => "is not a percentage and not an absolute value this reader knows",
        error.PercentOverHundred => "names a percentage over 100",
        error.Overflow => "names a number too large to hold, once its unit is applied",
    };
}

pub const ParseError = error{
    OutOfMemory,
    InvalidLimits,
};

pub const LoadError = ParseError || error{
    LimitsFileTooLarge,
    ReadFailed,
};

fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Limits {
    return parseFrom(gpa, source, file_name, diag);
}

pub fn parseFrom(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Limits {
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    var ast_owned = true;
    defer if (ast_owned) ast.deinit(gpa);

    // `parse_str_lits = true`, unlike `table.zig` and `subagents.zig`. Those
    // hand every value node to `std.zon.parse.fromZoirNodeAlloc`, which reads a
    // string's bytes off the `Ast`. This reader reads `Node.string_literal`
    // directly off `zoir.string_bytes`, and that pool is left empty when the
    // option is false: every string field then reads back as `""`.
    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    var zoir_owned = true;
    defer if (zoir_owned) zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        if (note(diag, source_name, .{ .file_not_zon = .{ .ast = ast, .zoir = zoir } })) {
            ast_owned = false;
            zoir_owned = false;
        }
        return error.InvalidLimits;
    }

    const node = try findLimitsNode(zoir, source_name, diag) orelse return .{};

    // Every field below is read by hand off the raw syntax tree. A percentage
    // string beside a bare integer is not one schema `fromZoirNodeAlloc` can
    // express, so `ast` and `zoir` stay owned by this function to the end.
    return parseFields(gpa, zoir, node, source_name, diag);
}

fn parseFields(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Limits {
    var limits = Limits{};
    switch (node.get(zoir)) {
        .empty_literal => return limits,
        .struct_literal => |fields| {
            for (fields.names, 0..) |name_id, index| {
                const name = name_id.get(zoir);
                const value_node = fields.vals.at(@intCast(index));
                if (std.mem.eql(u8, name, "processes")) {
                    limits.processes = try readSetting(gpa, zoir, "processes", value_node, source_name, diag);
                } else if (std.mem.eql(u8, name, "memory")) {
                    limits.memory = try readSetting(gpa, zoir, "memory", value_node, source_name, diag);
                } else {
                    _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, name) });
                    return error.InvalidLimits;
                }
            }
        },
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidLimits;
        },
    }
    return limits;
}

fn readSetting(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    field: []const u8,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Setting {
    switch (node.get(zoir)) {
        .string_literal => |text| {
            return parseSetting(text) catch |err| {
                const owned_field = try gpa.dupe(u8, field);
                const owned_text = try gpa.dupe(u8, text);
                if (!note(diag, source_name, .{ .invalid_setting = .{
                    .field = owned_field,
                    .text = owned_text,
                    .reason = err,
                } })) {
                    gpa.free(owned_field);
                    gpa.free(owned_text);
                }
                return error.InvalidLimits;
            };
        },
        .int_literal => |lit| {
            const value = intLiteralToU64(lit) catch |err| {
                const owned_field = try gpa.dupe(u8, field);
                const taken = switch (err) {
                    error.NegativeSetting => note(diag, source_name, .{ .negative_setting = owned_field }),
                    error.SettingOverflow => note(diag, source_name, .{ .setting_overflow = owned_field }),
                };
                if (!taken) gpa.free(owned_field);
                return error.InvalidLimits;
            };
            return .{ .absolute = value };
        },
        else => {
            _ = note(diag, source_name, .{ .value_not_string_or_number = try gpa.dupe(u8, field) });
            return error.InvalidLimits;
        },
    }
}

const IntLiteralError = error{ NegativeSetting, SettingOverflow };

/// `.small` is a plain `i32` and always fits once it is proven non-negative.
/// `.big` needs `std.math.big.int.Const.toInt`, which already tells negative
/// and too large apart.
fn intLiteralToU64(lit: anytype) IntLiteralError!u64 {
    return switch (lit) {
        .small => |v| std.math.cast(u64, v) orelse error.NegativeSetting,
        .big => |big| big.toInt(u64) catch |err| switch (err) {
            error.NegativeIntoUnsigned => error.NegativeSetting,
            error.TargetTooSmall => error.SettingOverflow,
        },
    };
}

fn findLimitsNode(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), "limits")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidLimits;
        },
    }
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Limits {
    return loadFrom(gpa, io, project_root, file_name, diag);
}

pub fn loadOperator(
    gpa: std.mem.Allocator,
    io: std.Io,
    config_dir: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Limits {
    return loadFrom(gpa, io, config_dir, operator_file_name, diag);
}

fn loadFrom(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: []const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Limits {
    const path = try std.fs.path.join(gpa, &.{ dir, source_name });
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
            _ = note(diag, source_name, .{ .file_too_large = max_file_bytes });
            return error.LimitsFileTooLarge;
        },
        else => {
            _ = note(diag, source_name, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parseFrom(gpa, source, source_name, diag);
}

// Every test below builds its own source in the test binary.

const testing = std.testing;

/// `std.testing.tmpDir` hands back a directory only a relative path reaches,
/// and the loaders need a root independent of the test binary's cwd.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a percentage resolves against the basis it is given" {
    try testing.expectEqual(@as(u64, 64), (Setting{ .percent = 50 }).resolve(128));
    try testing.expectEqual(@as(u64, 0), (Setting{ .percent = 0 }).resolve(128));
    try testing.expectEqual(@as(u64, 128), (Setting{ .percent = 100 }).resolve(128));
    try testing.expectEqual(@as(u64, 3), (Setting{ .percent = 33 }).resolve(10));

    try testing.expectEqual(@as(u64, 4 << 30), (Setting{ .absolute = 4 << 30 }).resolve(1));
    try testing.expectEqual(@as(u64, 4 << 30), (Setting{ .absolute = 4 << 30 }).resolve(1 << 40));
}

test "a percentage against a huge basis does not overflow" {
    const huge: u64 = std.math.maxInt(u64) - 3;
    try testing.expectEqual(huge / 2, (Setting{ .percent = 50 }).resolve(huge));
    try testing.expectEqual(huge, (Setting{ .percent = 100 }).resolve(huge));
}

test "a percentage string is read, and one over 100 is refused" {
    try testing.expectEqual(Setting{ .percent = 50 }, try parseSetting("50%"));
    try testing.expectEqual(Setting{ .percent = 0 }, try parseSetting("0%"));
    try testing.expectEqual(Setting{ .percent = 100 }, try parseSetting("100%"));

    try testing.expectError(error.PercentOverHundred, parseSetting("101%"));
    try testing.expectError(error.PercentOverHundred, parseSetting("200%"));
    try testing.expectError(error.Malformed, parseSetting("%"));
    try testing.expectError(error.Malformed, parseSetting("fifty%"));
}

test "an absolute value is read as a bare number or a number with a unit" {
    try testing.expectEqual(Setting{ .absolute = 300 }, try parseSetting("300"));
    try testing.expectEqual(Setting{ .absolute = 0 }, try parseSetting("0"));
    try testing.expectEqual(Setting{ .absolute = 4 }, try parseSetting("4B"));
    try testing.expectEqual(Setting{ .absolute = 4 << 10 }, try parseSetting("4KiB"));
    try testing.expectEqual(Setting{ .absolute = 4 << 20 }, try parseSetting("4MiB"));
    try testing.expectEqual(Setting{ .absolute = 4 << 30 }, try parseSetting("4GiB"));
    try testing.expectEqual(Setting{ .absolute = 4 << 40 }, try parseSetting("4TiB"));

    // The unit suffixes overlap on their trailing bytes, so the longest match
    // has to win or a value is read with the wrong multiplier.
    try testing.expectEqual(Setting{ .absolute = 4 << 10 }, try parseSetting("4KiB"));

    try testing.expectError(error.Malformed, parseSetting(""));
    try testing.expectError(error.Malformed, parseSetting("GiB"));
    try testing.expectError(error.Malformed, parseSetting("four"));
    try testing.expectError(error.Malformed, parseSetting("-5"));
    try testing.expectError(error.Overflow, parseSetting("99999999999999999999999GiB"));
}

test "a limits block is read, and the rest of the file is left to other readers" {
    const source =
        \\.{
        \\    .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .deny } } },
        \\    .budget = .{ .max_cost = 5.0 },
        \\    .limits = .{ .processes = "50%", .memory = "4GiB" },
        \\}
    ;
    const limits = try parse(testing.allocator, source, null);
    try testing.expectEqual(Setting{ .percent = 50 }, limits.processes.?);
    try testing.expectEqual(Setting{ .absolute = 4 << 30 }, limits.memory.?);
}

test "a bare ZON integer is read directly, with no string in between" {
    const limits = try parse(testing.allocator, ".{ .limits = .{ .processes = 300 } }", null);
    try testing.expectEqual(Setting{ .absolute = 300 }, limits.processes.?);
    // The field left unnamed is null, not a default value, so a later layer
    // can still supply it.
    try testing.expectEqual(@as(?Setting, null), limits.memory);

    try testing.expectError(
        error.InvalidLimits,
        parse(testing.allocator, ".{ .limits = .{ .processes = -1 } }", null),
    );
}

test "a file with no limits block, or a block naming one field, leaves the rest null" {
    for ([_][:0]const u8{ ".{}", ".{ .policy = .{} }", ".{ .budget = .{ .max_cost = 1.0 } }" }) |source| {
        const limits = try parse(testing.allocator, source, null);
        try testing.expectEqual(@as(?Setting, null), limits.processes);
        try testing.expectEqual(@as(?Setting, null), limits.memory);
    }

    const only_memory = try parse(testing.allocator, ".{ .limits = .{ .memory = \"1GiB\" } }", null);
    try testing.expectEqual(@as(?Setting, null), only_memory.processes);
    try testing.expectEqual(Setting{ .absolute = 1 << 30 }, only_memory.memory.?);
}

test "a misspelled field inside the limits block is refused rather than silently skipped" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidLimits,
        parse(testing.allocator, ".{ .limits = .{ .procceses = \"50%\" } }", &diag),
    );
    try testing.expectEqualStrings("procceses", diag.?.fault.unknown_field);
    try testing.expectEqualStrings(file_name, diag.?.source);

    const limits = try parse(testing.allocator, ".{ .telepathy = .{ .range_m = 3 } }", null);
    try testing.expectEqual(@as(?Setting, null), limits.processes);
}

test "a value that is not a string and not a number is refused" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidLimits,
        parse(testing.allocator, ".{ .limits = .{ .processes = true } }", &diag),
    );
    try testing.expectEqualStrings("processes", diag.?.fault.value_not_string_or_number);
}

test "the field and the text of a malformed setting reach the caller" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidLimits,
        parse(testing.allocator, ".{ .limits = .{ .processes = \"200%\" } }", &diag),
    );
    try testing.expectEqualStrings("processes", diag.?.fault.invalid_setting.field);
    try testing.expectEqualStrings("200%", diag.?.fault.invalid_setting.text);
    try testing.expectEqual(SettingError.PercentOverHundred, diag.?.fault.invalid_setting.reason);

    var buffer: [160]u8 = undefined;
    try testing.expectEqualStrings(
        "chock.zon: the limits block's processes field holds \"200%\", which names a percentage over 100",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "the same fault reads with config.zon's own name when it is the source" {
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(testing.allocator);
    try testing.expectError(
        error.InvalidLimits,
        parseFrom(testing.allocator, ".{ .limits = .{ .processes = \"200%\" } }", operator_file_name, &diag),
    );
    var buffer: [160]u8 = undefined;
    try testing.expectEqualStrings(
        "config.zon: the limits block's processes field holds \"200%\", which names a percentage over 100",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "the limits come off the disk, and a project with no file gets nothing named" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&path_buffer, tmp.dir);

    const missing = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?Setting, null), missing.processes);

    {
        var file = try tmp.dir.createFile(testing.io, file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, ".{ .limits = .{ .processes = \"25%\" } }");
    }

    const written = try load(gpa, testing.io, root, null);
    try testing.expectEqual(Setting{ .percent = 25 }, written.processes.?);
}

test "the operator's own config.zon is read through the same loader, by a different name" {
    const gpa = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const root = try absoluteDirPath(&path_buffer, tmp.dir);

    const missing = try loadOperator(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?Setting, null), missing.memory);

    {
        var file = try tmp.dir.createFile(testing.io, operator_file_name, .{});
        defer file.close(testing.io);
        try file.writeStreamingAll(testing.io, ".{ .limits = .{ .memory = \"1GiB\" } }");
    }

    const written = try loadOperator(gpa, testing.io, root, null);
    try testing.expectEqual(Setting{ .absolute = 1 << 30 }, written.memory.?);

    const project_side = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?Setting, null), project_side.memory);
}

test "the fold: the project wins over the operator, and the operator wins over the machine" {
    const machine = Machine{ .cpu_count = 8, .memory_bytes = 16 << 30 };

    const nothing_named = foldLayers(.{}, .{}, null, machine);
    try testing.expectEqual(default_processes, nothing_named.processes);
    try testing.expectEqual(default_memory_bytes, nothing_named.memory_bytes);

    const operator_only = foldLayers(.{}, .{ .processes = .{ .absolute = 500 } }, null, machine);
    try testing.expectEqual(@as(u64, 500), operator_only.processes);

    const both_named = foldLayers(
        .{ .processes = .{ .absolute = 900 } },
        .{ .processes = .{ .absolute = 500 } },
        null,
        machine,
    );
    try testing.expectEqual(@as(u64, 900), both_named.processes);

    const mixed = foldLayers(
        .{ .memory = .{ .absolute = 1 << 30 } },
        .{ .processes = .{ .absolute = 500 } },
        null,
        machine,
    );
    try testing.expectEqual(@as(u64, 500), mixed.processes);
    try testing.expectEqual(@as(u64, 1 << 30), mixed.memory_bytes);
}

test "the machine sized default reaches four times the old fixed number on a 128 cpu box" {
    // The measurement this file exists to answer: 256 threads on a 128 cpu
    // machine.
    const big_machine = Machine{ .cpu_count = 128, .memory_bytes = 197 << 30 };
    const resolved = foldLayers(.{}, .{}, null, big_machine);
    try testing.expectEqual(@as(u64, 1024), resolved.processes);
    try testing.expect(resolved.processes > default_processes);

    const ordinary = Machine{ .cpu_count = 8, .memory_bytes = 16 << 30 };
    const same_as_before = foldLayers(.{}, .{}, null, ordinary);
    try testing.expectEqual(default_processes, same_as_before.processes);
    try testing.expectEqual(default_memory_bytes, same_as_before.memory_bytes);
}

test "a resolved pair of limits is held to an org ceiling, and never widened by one" {
    const machine = Machine{ .cpu_count = 128, .memory_bytes = 64 << 30 };
    const generous = Limits{
        .processes = .{ .absolute = 1000 },
        .memory = .{ .absolute = 32 << 30 },
    };
    const resolved = foldLayers(generous, .{}, null, machine);

    const held = underCeiling(resolved, .{ .processes = "256", .memory = "8GiB" }, machine);
    try testing.expectEqual(@as(u64, 256), held.processes);
    try testing.expectEqual(@as(u64, 8 << 30), held.memory_bytes);
    try testing.expect(held.processes_from_org);
    try testing.expect(held.memory_from_org);

    const modest = Limits{
        .processes = .{ .absolute = 64 },
        .memory = .{ .absolute = 1 << 30 },
    };
    const untouched = underCeiling(foldLayers(modest, .{}, null, machine), .{ .processes = "256", .memory = "8GiB" }, machine);
    try testing.expectEqual(@as(u64, 64), untouched.processes);
    try testing.expectEqual(@as(u64, 1 << 30), untouched.memory_bytes);
    try testing.expect(!untouched.processes_from_org);
    try testing.expect(!untouched.memory_from_org);

    try testing.expectEqual(resolved, underCeiling(resolved, null, machine));
}

test "a ceiling may cap one field and say nothing about the other" {
    const machine = Machine{ .cpu_count = 128, .memory_bytes = 64 << 30 };
    const resolved = foldLayers(.{
        .processes = .{ .absolute = 1000 },
        .memory = .{ .absolute = 32 << 30 },
    }, .{}, null, machine);

    const width_only = underCeiling(resolved, .{ .processes = "256" }, machine);
    try testing.expectEqual(@as(u64, 256), width_only.processes);
    try testing.expectEqual(resolved.memory_bytes, width_only.memory_bytes);
    try testing.expect(width_only.processes_from_org);
    try testing.expect(!width_only.memory_from_org);
}

test "a ceiling can name a percentage too, and it resolves against the same machine" {
    const machine = Machine{ .cpu_count = 128, .memory_bytes = 64 << 30 };
    const resolved = foldLayers(.{ .processes = .{ .absolute = 1000 } }, .{}, null, machine);

    const held = underCeiling(resolved, .{ .processes = "50%" }, machine);
    try testing.expectEqual(@as(u64, 64), held.processes);
    try testing.expect(held.processes_from_org);
}

test "a ceiling this build cannot parse changes nothing, rather than crashing" {
    const machine = Machine{ .cpu_count = 128, .memory_bytes = 64 << 30 };
    const resolved = foldLayers(.{ .processes = .{ .absolute = 1000 } }, .{}, null, machine);
    const held = underCeiling(resolved, .{ .processes = "not a number" }, machine);
    try testing.expectEqual(resolved.processes, held.processes);
    try testing.expect(!held.processes_from_org);
}

test "this machine's own cpu count and memory can really be read" {
    const machine = try Machine.read();
    try testing.expect(machine.cpu_count >= 1);
    try testing.expect(machine.memory_bytes > 0);
}
