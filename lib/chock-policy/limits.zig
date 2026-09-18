//! The sandbox's resource limits, and the three places a number for them can
//! come from.
//!
//! ```zon
//! .{
//!     .limits = .{
//!         .processes = "50%",
//!         .memory = "4GiB",
//!     },
//! }
//! ```
//!
//! The same block, spelled the same way, reads in three files, and each one
//! answers a different question:
//!
//! 1. **`~/.config/chock/config.zon`, the operator's own default.** The
//!    machine's own answer, set once by whoever owns it, and used by every
//!    project on that machine that says nothing of its own. A **default**,
//!    and a project may set whatever it likes over it.
//! 2. **`chock.zon`, the project's override.** What this file's own top
//!    comment shows. It wins over the operator's default.
//! 3. **The org policy bundle, the ceiling.** `Ceiling` below, read from
//!    `lib/chock-policy/org.zig`'s `Bundle`. A project above the bundle's
//!    number is held to the bundle's number, the same as `subagents.Ceiling`
//!    already holds a spawn tree, and it is never refused: see `underCeiling`.
//!
//! Read in that order: the project's own number wins over the operator's, and
//! the org ceiling is the last word over both. `foldLayers` is the one
//! function that does the whole fold, machine facts and all.
//!
//! ## The bug this closes, measured
//!
//! `lib/chock-sandbox/linux/rlimits.zig` compiles `default_processes` and
//! `default_memory_bytes` in, as one number each for every machine Chock
//! runs on. That is wrong on a large machine, and it was measured wrong
//! rather than argued wrong:
//!
//! * The sandbox set `RLIMIT_NPROC` (and `pids.max`) to 256. Linux counts
//!   **threads**, not processes, against that limit. On a 128 CPU machine
//!   `cargo` defaults to about 128 parallel `rustc`, each wanting several
//!   threads of its own, so the budget of 256 was exhausted at once and
//!   every `rustc` died with `EAGAIN` on thread spawn.
//! * It was not only processes. Two crates were `SIGKILL`ed even at `-j 4`,
//!   which is the memory ceiling and not the process one. From inside the
//!   sandbox `/proc/meminfo` reported 197 GiB available, because
//!   `/sys/fs/cgroup` is hidden from the program the limit bounds: see
//!   `lib/chock-sandbox/linux/namespace.zig`'s own top comment on why. So
//!   the program that was killed could not see the number that killed it,
//!   and neither could the person reading its output.
//!
//! A number hardcoded in a source file is a number somebody will hit and be
//! unable to change. This file is the wiring `rlimits.zig`'s own `Limits`
//! doc comment named as missing.
//!
//! ## Chock's own default is sized to the machine, not fixed
//!
//! `builtinProcesses` and `builtinMemory` are the bottom of the fold: the
//! answer a machine gets when nobody, at any of the three layers, named a
//! number. **A sensible default means most people configure nothing at
//! all**, so this is not the flat 256 and 2 GiB `rlimits.zig` still
//! documents as its own compiled in numbers. Each is the larger of that same
//! floor and a share of what the machine actually has, so an ordinary
//! machine keeps today's exact number and a large one gets one sized to it:
//! see each function's own doc comment for the ratio and the reasoning
//! behind it.
//!
//! ## A percentage or an absolute value
//!
//! `Setting` is one of the two. A percentage is a share of what the machine
//! has: the cpu count for `processes`, the total memory for `memory`. An
//! absolute value is that number exactly, in the field's own unit: a count
//! for `processes`, bytes for `memory`. `parseSetting` reads either shape out
//! of one string:
//!
//! * `"50%"` is half of whatever `resolve` is given as the basis.
//! * `"300"` is the literal number 300.
//! * `"4GiB"` is `4 * (1 << 30)` bytes. The units this reader knows are
//!   `TiB`, `GiB`, `MiB`, `KiB` and `B`, the binary ones, matching the
//!   `<<` shifts every other default in this project is written with.
//!
//! **`chock.zon` and `config.zon` also accept a bare ZON integer**, such as
//! `.processes = 300`, read straight off the syntax tree with no string in
//! between. The org policy bundle does not: see `Ceiling`'s own doc comment
//! for why one reader takes a number two ways and the other takes it one.
//!
//! A percentage above 100, and a value that does not parse at all, are both
//! refused **when the file is read**, with a diagnostic that names the field
//! and the reason. A number that would only fail at the moment it sized a
//! sandbox is a number that fails during somebody's session instead of at
//! start up, which is the trap this project keeps finding and keeps fixing.
//!
//! ## This reader is strict inside its own block and lenient outside it
//!
//! The same split `lib/chock-policy/table.zig` and
//! `lib/chock-policy/subagents.zig` make, and for the same reason: other
//! milestones own the other blocks of `chock.zon`, and a misspelled field
//! name inside this one must never become a limit the author did not write.
//! `.{ .limits = .{ .procceses = "50%" } }` is refused, not read as the
//! default.

const std = @import("std");
const builtin = @import("builtin");

/// The name of the project's own configuration file, in the project root.
/// `lib/chock-policy/table.zig` and `lib/chock-policy/subagents.zig` look in
/// the same place.
pub const file_name = "chock.zon";

/// The name of the operator's own configuration file. Copied from
/// `lib/chock-auth/config.zig`'s `file_name`, because that library imports no
/// other chock library and this one cannot import it back: see this file's
/// own top comment on why the two default numbers below are copies as well.
pub const operator_file_name = "config.zon";

/// The largest `limits` source this reader accepts, matching every other
/// reader of `chock.zon`: it comes out of the project directory, so a
/// hostile project supplies it. `config.zon` is not hostile, the same way
/// `lib/chock-auth/config.zig`'s own `max_file_bytes` is not chosen against
/// an attacker, but one bound serves both: a roster of limits is a small
/// file either way.
pub const max_file_bytes = 1 << 20;

/// The process and thread floor. Copied from
/// `lib/chock-sandbox/linux/rlimits.zig`'s `default_processes`: see this
/// file's own top comment for why it is a copy and not an import. Never
/// used alone: `builtinProcesses` is the real bottom of the fold, and this
/// is the number it never goes under.
pub const default_processes: u64 = 256;

/// The resident memory floor. Copied from
/// `lib/chock-sandbox/linux/rlimits.zig`'s `default_memory_bytes`. Never
/// used alone: see `builtinMemory`.
pub const default_memory_bytes: u64 = 2 << 30;

/// How many threads `builtinProcesses` allows per cpu, above `default_processes`.
///
/// **Measured, not guessed.** On the 128 cpu machine this whole file exists
/// for, `cargo` ran about 128 parallel `rustc`, and "each wanting several
/// threads of its own" is what emptied a budget of 256 in one instant: see
/// this file's own top comment. 8 is a round number above that "several",
/// chosen so the floor of 256 already covers an 8 cpu machine unchanged
/// (`8 * 8 = 64`, under the floor) and a 128 cpu machine reaches `1024`,
/// four times the old fixed number, without a project having to configure
/// anything. A workload that still needs more writes its own
/// `.limits.processes`, which always wins over this.
pub const processes_per_cpu: u64 = 8;

/// What share of total memory `builtinMemory` allows, as the divisor of it.
///
/// An eighth, so a 16 GiB machine (`16 GiB / 8 = 2 GiB`) reaches exactly
/// `default_memory_bytes` and is unchanged, while the 197 GiB machine this
/// file exists for reaches about 24.6 GiB, which is both far above the flat
/// 2 GiB that made no sense there and still leaves most of the machine for
/// everything else running on it.
pub const memory_share_divisor: u64 = 8;

/// The process and thread ceiling this machine gets when nothing at any
/// layer named one. The larger of `default_processes` and
/// `processes_per_cpu` times the cpu count this machine reports.
pub fn builtinProcesses(machine: Machine) Setting {
    return .{ .absolute = @max(default_processes, machine.cpu_count * processes_per_cpu) };
}

/// The resident memory ceiling this machine gets when nothing at any layer
/// named one. The larger of `default_memory_bytes` and one
/// `memory_share_divisor`th of this machine's own total memory.
pub fn builtinMemory(machine: Machine) Setting {
    return .{ .absolute = @max(default_memory_bytes, machine.memory_bytes / memory_share_divisor) };
}

/// A share of what the machine has, or an exact number. See this file's own
/// top comment for the two spellings `parseSetting` reads.
pub const Setting = union(enum) {
    /// A percentage of `resolve`'s basis, 0 through 100. Refused above 100 at
    /// parse time: see `SettingError.PercentOverHundred`.
    percent: u7,
    /// A count or a number of bytes, exactly as the file named it.
    absolute: u64,

    /// `self` against `basis`, which is a cpu count for `processes` and a
    /// byte count for `memory`. `basis` and `100` both fit comfortably inside
    /// `u128`, so the multiply cannot overflow whatever `basis` a real
    /// machine reports, and only the final divide is what a caller reads
    /// back.
    pub fn resolve(self: Setting, basis: u64) u64 {
        return switch (self) {
            .absolute => |value| value,
            .percent => |pct| @intCast(@as(u128, basis) * pct / 100),
        };
    }
};

/// What can go wrong turning one field's text into a `Setting`. Every member
/// is a fact about the text alone, so this is exactly the error set
/// `Ceiling`'s own validation in `lib/chock-policy/org.zig` reads too.
pub const SettingError = error{
    /// Not a percentage, not a bare number, and not a number with a unit
    /// this reader knows.
    Malformed,
    /// A percentage named more than 100.
    PercentOverHundred,
    /// An absolute value, after any unit was applied, does not fit a `u64`.
    Overflow,
};

/// The units `parseAbsolute` knows, longest suffix first. **Order matters**:
/// `KiB` and `GiB` both end in `iB`, and every one of them ends in `B`, so
/// the bare byte suffix has to be tried last or `"4GiB"` would be read as the
/// digits `"4Gi"` before a unit named `"B"`.
const units = [_]struct { suffix: []const u8, multiplier: u64 }{
    .{ .suffix = "TiB", .multiplier = 1 << 40 },
    .{ .suffix = "GiB", .multiplier = 1 << 30 },
    .{ .suffix = "MiB", .multiplier = 1 << 20 },
    .{ .suffix = "KiB", .multiplier = 1 << 10 },
    .{ .suffix = "B", .multiplier = 1 },
};

/// `text` as an absolute value: a bare number, or a number followed by one of
/// `units`.
fn parseAbsolute(text: []const u8) SettingError!u64 {
    // Checked up front, and not left to `std.fmt.parseInt`: that reader
    // accepts a leading '-' on an unsigned type and answers `error.Overflow`
    // for any negative value that is not exactly zero, which would read
    // "-5" as a number too large to hold instead of what it actually is, a
    // shape this field cannot take at all.
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

/// One field's text, read as a `Setting`. Public because
/// `lib/chock-policy/org.zig` reads the org policy bundle's own ceiling
/// through the same rule: a percentage there resolves against the same
/// machine, and a malformed string is the same fault either place it is
/// written.
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

/// What one `limits` block asks for. **Every member is optional**, because
/// this same type reads both `chock.zon`'s own block and
/// `~/.config/chock/config.zon`'s, and "this file named nothing" has to be
/// told apart from "this file named today's default": `foldLayers` is what
/// falls through to the next layer on a null, and it can only do that when
/// null really means absent.
pub const Limits = struct {
    /// The process and thread ceiling. See
    /// `lib/chock-sandbox/linux/rlimits.zig`'s `Limits.processes`, which is
    /// `RLIMIT_NPROC` and `pids.max`.
    processes: ?Setting = null,
    /// The resident memory ceiling. See `rlimits.zig`'s
    /// `Limits.memory_bytes`, which is `memory.max`.
    memory: ?Setting = null,
};

/// A pair of `Limits`, resolved to real numbers against one machine.
pub const Resolved = struct {
    processes: u64,
    memory_bytes: u64,
    /// True when `processes` is the org policy bundle's number and not the
    /// project's or the operator's own. Only `underCeiling` sets this, the
    /// same shape `subagents.Limits.depth_from_org` uses and for the same
    /// reason: a message that blamed a number on the wrong file would send
    /// its author looking at a file that does not hold it.
    processes_from_org: bool = false,
    /// True when `memory_bytes` is the org policy bundle's number.
    memory_from_org: bool = false,
};

/// The whole fold, in the order this file's own top comment gives: the
/// project's own `limits` block wins over the operator's, the operator's
/// wins over what the machine itself suggests, and the org ceiling is read
/// last, over the result of the first three.
///
/// `project` and `operator` both default every field to null when their file
/// named nothing, which is exactly what makes "fall through to the next
/// layer" the right reading of `orelse`.
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
/// Each member is optional on its own, so a bundle may cap memory and say
/// nothing about processes, the same shape `subagents.Ceiling` already has
/// for the spawn tree.
///
/// **Text, and not `Setting`.** `lib/chock-policy/org.zig` reads the whole
/// bundle through one `std.zon.parse.fromSliceAlloc(Bundle, ...)` call, which
/// needs one static schema for every field. `Setting` is not that: it reads
/// a bare ZON integer *or* a quoted string, and `std.zon.parse` cannot be
/// told "either of these" for one field. A quoted string alone is a schema
/// that reader can express, and `parseAbsolute` already reads a bare number
/// out of a string exactly the way it reads one out of a ZON integer, so
/// nothing an organisation would write is out of reach: `.processes = "300"`
/// says the same thing `.processes = 300` says in a project's own
/// `chock.zon`, one keystroke longer.
///
/// `org.zig`'s own `validate` calls `parseSetting` on each field that is
/// present, once, when the bundle is read, so a malformed ceiling is refused
/// there and never at the moment it would have bound a session.
pub const Ceiling = struct {
    processes: ?[]const u8 = null,
    memory: ?[]const u8 = null,
};

/// `resolved` held to `ceiling`, resolved against the same `machine`.
///
/// **A minimum, and never a refusal.** The same shape
/// `subagents.underCeiling` already has, and for the same reason: a program
/// inside the sandbox cannot see the cap that kills it, `/proc/meminfo`
/// reports the whole machine and `/sys/fs/cgroup` is hidden, so a session
/// held to a lower number without being told would die of a `SIGKILL` that
/// explains nothing. Refusing the session outright would be the `budget`
/// answer, and it is the wrong one here: a project that asked for more
/// memory than its organisation allows should still run, at the
/// organisation's number, the same as a spawn tree over the org's width is
/// held to that width rather than refused. **Say it out loud** is the part
/// that is not code: `src/doctor.zig`'s own `measureOrgCeilings` is where a
/// person reads the number this function may have lowered, before a session
/// ever starts.
///
/// **Defensive against a ceiling this build cannot parse.** `org.zig`
/// refuses a bundle whose `limits` block does not parse when the bundle is
/// read, so `ceiling`'s text is proven to parse by the time it reaches here
/// in every real path. A caller that hands over an unparsed `Ceiling`
/// anyway, built by hand rather than read from a file, gets `resolved`
/// unchanged for the field that does not parse rather than a crash: the
/// safe reading of "this organisation's own number is unreadable" is "this
/// organisation set no ceiling", never "trust the project instead" and never
/// a panic over a bundle another process already validated.
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

/// What a percentage in `chock.zon`, `config.zon`, or an org policy bundle
/// resolves against: this machine's own cpu count and total memory.
pub const Machine = struct {
    cpu_count: u64,
    memory_bytes: u64,

    pub const ReadError = error{CannotReadMachine};

    /// Read this machine's own facts. A caller reads these once, before it
    /// sizes a sandbox, and never from inside one: `namespace.zig` hides
    /// `/proc/meminfo` from the program a limit bounds precisely so that
    /// program cannot see, and cannot be confused by, the host's own numbers
    /// rather than its own cap. This is the host side of that line, called
    /// before a sandbox exists at all.
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

/// Why a `limits` block was refused, in the words the author of the file that
/// held it needs. See `lib/chock-policy/table.zig`'s own `Diagnostic` for the
/// same shape, and the same rule: some faults own memory, and `deinit`
/// releases all of them.
///
/// **`source` names which file this is about.** `chock.zon` and
/// `config.zon` share this one reader, so the diagnostic itself has to carry
/// which of the two was being read, rather than a message hardcoding one of
/// the two names. It is always a literal of this module, `file_name` or
/// `operator_file_name`, so `deinit` never frees it.
pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Fault = union(enum) {
        /// The file is not valid ZON at all. The parser names the place.
        file_not_zon: std.zon.parse.Diagnostics,
        /// The top level of the file is not a struct literal.
        not_a_struct_literal,
        /// A field of the `limits` block this reader does not know. Owned.
        unknown_field: []const u8,
        /// A field held something other than a string or a number: `true`,
        /// `null`, a float, an array, a nested struct. Owned.
        value_not_string_or_number: []const u8,
        /// A field's text was not a percentage, not an absolute value, or
        /// named a percentage over 100. Owned.
        invalid_setting: InvalidSetting,
        /// A bare ZON integer was negative. A resource limit cannot be.
        /// Owned.
        negative_setting: []const u8,
        /// A bare ZON integer does not fit a `u64`. Owned.
        setting_overflow: []const u8,
        /// The file is larger than `max_file_bytes`, so it was not read.
        file_too_large: usize,
        /// The file exists and the read failed. The fault is the
        /// filesystem's.
        read_failed: anyerror,
    };

    pub const InvalidSetting = struct {
        field: []const u8,
        text: []const u8,
        reason: SettingError,
    };

    /// Release what the diagnostic owns. Safe on every variant.
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

/// `SettingError` as the clause that finishes "which ...", for `Diagnostic`'s
/// own `.invalid_setting` message. Public so `lib/chock-policy/org.zig` can
/// build the same sentence for the org policy bundle's own ceiling, which
/// reads the same error set through `parseSetting`.
pub fn reasonText(reason: SettingError) []const u8 {
    return switch (reason) {
        error.Malformed => "is not a percentage and not an absolute value this reader knows",
        error.PercentOverHundred => "names a percentage over 100",
        error.Overflow => "names a number too large to hold, once its unit is applied",
    };
}

pub const ParseError = error{
    OutOfMemory,
    /// The file is not valid ZON, or the `limits` block does not match the
    /// schema. Pass a `Diagnostic` to learn which line, and why.
    InvalidLimits,
};

pub const LoadError = ParseError || error{
    /// The file is larger than `max_file_bytes`.
    LimitsFileTooLarge,
    /// The file exists and could not be read. Pass a `Diagnostic` to learn
    /// which fault the filesystem gave.
    ReadFailed,
};

/// Fill `out` when the caller asked for one, and say whether it took `value`.
/// The first fault is kept, not the last: a later step can only fail because
/// an earlier one did, so the first is the one that explains the rest.
fn note(out: ?*?Diagnostic, source: []const u8, fault: Diagnostic.Fault) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = .{ .source = source, .fault = fault };
    return true;
}

/// Read the limits out of `source`, the whole content of `chock.zon`. A file
/// that names no `limits` block gets every field null, which `foldLayers`
/// reads as "this layer named nothing" and falls through.
///
/// `diag` is optional. A caller that passes null pays nothing and learns
/// only the error. A caller that passes a slot must call `Diagnostic.deinit`
/// on whatever lands in it.
pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8, diag: ?*?Diagnostic) ParseError!Limits {
    return parseFrom(gpa, source, file_name, diag);
}

/// `parse`, naming a different source file in every diagnostic. Used to read
/// `config.zon`'s own `limits` block through the same reader, so the two
/// files can never silently drift onto two schemas: see this file's own top
/// comment.
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

    // **`parse_str_lits = true`, unlike `table.zig` and `subagents.zig`.**
    // Both of those hand every value node straight to
    // `std.zon.parse.fromZoirNodeAlloc`, which reads a string's bytes off the
    // `Ast` itself and needs nothing pre-parsed here. This reader has no such
    // call for a `Setting`: it reads `Node.string_literal` directly, off
    // `zoir.string_bytes`, and that pool is left empty when this option is
    // false. Measured while writing this file: every string field read back
    // as `""`, and a percentage of `""` failed as "malformed" rather than as
    // the percentage it was.
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

    // Every field below is read by hand, off the raw syntax tree, instead of
    // being handed to `std.zon.parse.fromZoirNodeAlloc`. A percentage string
    // beside a bare integer is not one schema that reader can express, so
    // `ast` and `zoir` stay owned by this function to the end: nothing below
    // borrows them into a `std.zon.parse.Diagnostics`.
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

/// One field's raw value node, read as a `Setting`. A string is read through
/// `parseSetting`; a bare integer is decoded here, because `Setting` mixes
/// two literal kinds and `std.zon.parse` reads one schema at a time.
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

/// A ZOIR `int_literal` node as a `u64`. `.small` is a plain `i32` and always
/// fits once it is proven non-negative; `.big` needs
/// `std.math.big.int.Const.toInt`, which already tells negative and too
/// large apart.
fn intLiteralToU64(lit: anytype) IntLiteralError!u64 {
    return switch (lit) {
        .small => |v| std.math.cast(u64, v) orelse error.NegativeSetting,
        .big => |big| big.toInt(u64) catch |err| switch (err) {
            error.NegativeIntoUnsigned => error.NegativeSetting,
            error.TargetTooSmall => error.SettingOverflow,
        },
    };
}

/// The node of the `limits` field at the top of the file. Null when the file
/// has no such field. Every other top level field is skipped, because other
/// readers own the other blocks of `chock.zon`, and `config.zon`'s own
/// `.providers` and `.defaults` blocks belong to `lib/chock-auth/config.zig`
/// alone.
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

/// Read `chock.zon` from `project_root` and take its limits. A project with
/// no such file gets every field null, the same answer a file with no
/// `limits` block gets.
///
/// `diag` carries the same detail `parse` carries, and the same rule
/// applies: null costs nothing, and a filled slot must be released with
/// `Diagnostic.deinit`.
pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    project_root: []const u8,
    diag: ?*?Diagnostic,
) LoadError!Limits {
    return loadFrom(gpa, io, project_root, file_name, diag);
}

/// Read `config.zon` from the configuration directory `chock_auth.paths`
/// names, the same directory `chock_auth.config.load` already reads, and
/// take its `limits` block. A machine with no such file, or a file that
/// names no `limits` block, gets every field null: the operator's default
/// then contributes nothing to the fold, and `builtinProcesses` /
/// `builtinMemory` are what a project sees instead.
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

// Every test below builds its own source in the test binary, the same rule
// `subagents.zig`'s own tests keep, so no test reads the checkout Chock
// itself lives in.

const testing = std.testing;

/// The absolute path of an already open directory. Mirrors the helper of the
/// same name in `lib/chock-policy/subagents.zig` and `table.zig`.
fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

test "a percentage resolves against the basis it is given" {
    try testing.expectEqual(@as(u64, 64), (Setting{ .percent = 50 }).resolve(128));
    try testing.expectEqual(@as(u64, 0), (Setting{ .percent = 0 }).resolve(128));
    try testing.expectEqual(@as(u64, 128), (Setting{ .percent = 100 }).resolve(128));
    // A basis that does not divide evenly truncates, the same as any integer
    // division: 33 percent of 10 is 3, not 3.3 and not 4.
    try testing.expectEqual(@as(u64, 3), (Setting{ .percent = 33 }).resolve(10));

    // An absolute value ignores the basis completely, which is the whole
    // reason a project would write one instead of a percentage.
    try testing.expectEqual(@as(u64, 4 << 30), (Setting{ .absolute = 4 << 30 }).resolve(1));
    try testing.expectEqual(@as(u64, 4 << 30), (Setting{ .absolute = 4 << 30 }).resolve(1 << 40));
}

test "a percentage against a huge basis does not overflow" {
    // The multiply happens in u128 before the divide, so a basis near the top
    // of u64 (a real machine's total memory in bytes, for instance) cannot
    // wrap around on the way to the answer.
    //
    // Mutation check: do the multiply in u64 instead of u128 and this
    // overflows in safe builds and wraps silently in fast ones.
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

    // The unit suffixes overlap on their trailing bytes, and the longest one
    // has to win, or "4GiB" would be misread as the digits "4Gi" before a
    // unit named "B".
    //
    // Mutation check: reorder `units` so "B" is tried before "KiB" and this
    // fails with error.Malformed instead of reading 4 KiB.
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
    // The field left unnamed is null, not a default value: this file's own
    // block reader never fills one in, only `foldLayers` does.
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

    // A field name this reader does not know, outside the block, belongs to
    // another milestone. That one is read past.
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
    // **The whole reason `source` is a field and not a constant.** One
    // reader serves both files, and a person editing their own
    // `~/.config/chock/config.zon` must never be told to go look in a
    // project's `chock.zon` instead.
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

    // And a `chock.zon` beside it, in the same directory, is not what this
    // loader reads: the two files are named apart on purpose.
    const project_side = try load(gpa, testing.io, root, null);
    try testing.expectEqual(@as(?Setting, null), project_side.memory);
}

test "the fold: the project wins over the operator, and the operator wins over the machine" {
    const machine = Machine{ .cpu_count = 8, .memory_bytes = 16 << 30 };

    // Nobody named anything: the machine sized default, which for this
    // machine equals today's fixed numbers exactly, because 8 cpus and
    // 16 GiB both sit at or under the floor.
    //
    // Mutation check: swap the operand order in `foldLayers`'s `orelse`
    // chain so the operator's own number is read first, and the third
    // expectation below (the project winning) fails.
    const nothing_named = foldLayers(.{}, .{}, null, machine);
    try testing.expectEqual(default_processes, nothing_named.processes);
    try testing.expectEqual(default_memory_bytes, nothing_named.memory_bytes);

    // The operator's own default is used when the project says nothing.
    const operator_only = foldLayers(.{}, .{ .processes = .{ .absolute = 500 } }, null, machine);
    try testing.expectEqual(@as(u64, 500), operator_only.processes);

    // The project's own number wins over the operator's, for the same
    // field.
    const both_named = foldLayers(
        .{ .processes = .{ .absolute = 900 } },
        .{ .processes = .{ .absolute = 500 } },
        null,
        machine,
    );
    try testing.expectEqual(@as(u64, 900), both_named.processes);

    // And the two fields fold apart: a project that names only memory still
    // gets the operator's own number for processes.
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
    // The measurement this whole file exists to answer: 256 threads on a 128
    // cpu machine running about 128 parallel rustc, each wanting several
    // threads of its own. `processes_per_cpu` of 8 reaches 1024 there, with
    // no project and no operator configuring anything at all.
    const big_machine = Machine{ .cpu_count = 128, .memory_bytes = 197 << 30 };
    const resolved = foldLayers(.{}, .{}, null, big_machine);
    try testing.expectEqual(@as(u64, 1024), resolved.processes);
    try testing.expect(resolved.processes > default_processes);

    // And an ordinary 8 cpu, 16 GiB machine is unchanged: this is the
    // "today's values as the default" promise, read off the formula rather
    // than off a constant.
    const ordinary = Machine{ .cpu_count = 8, .memory_bytes = 16 << 30 };
    const same_as_before = foldLayers(.{}, .{}, null, ordinary);
    try testing.expectEqual(default_processes, same_as_before.processes);
    try testing.expectEqual(default_memory_bytes, same_as_before.memory_bytes);
}

test "a resolved pair of limits is held to an org ceiling, and never widened by one" {
    // **The gap this closes.** `rlimits.zig`'s own defaults are a fixed
    // number for every machine, and an organisation had no way to say
    // "no project of mine gets more than this", the same gap `subagents`
    // closed for the width of a spawn tree.
    //
    // Mutation check: make `underCeiling` take the ceiling rather than the
    // minimum and the first two expectations fail, because a project that
    // asked for less than its org allows would be raised to the org's
    // number.
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

    // A project already under the ceiling keeps its own numbers, and neither
    // is read as coming from the bundle.
    const modest = Limits{
        .processes = .{ .absolute = 64 },
        .memory = .{ .absolute = 1 << 30 },
    };
    const untouched = underCeiling(foldLayers(modest, .{}, null, machine), .{ .processes = "256", .memory = "8GiB" }, machine);
    try testing.expectEqual(@as(u64, 64), untouched.processes);
    try testing.expectEqual(@as(u64, 1 << 30), untouched.memory_bytes);
    try testing.expect(!untouched.processes_from_org);
    try testing.expect(!untouched.memory_from_org);

    // No ceiling at all changes nothing, the ordinary case for an
    // installation nobody manages.
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

    // 50% of 128 cpus is 64, well under the project's 1000.
    const held = underCeiling(resolved, .{ .processes = "50%" }, machine);
    try testing.expectEqual(@as(u64, 64), held.processes);
    try testing.expect(held.processes_from_org);
}

test "a ceiling this build cannot parse changes nothing, rather than crashing" {
    // `org.zig` refuses a bundle whose limits block does not parse before a
    // `Ceiling` like this can ever be built from a real file. This is the
    // defensive branch for a `Ceiling` built by hand, so the safe answer is
    // "no ceiling from this field", never a trust-the-project fallback and
    // never a panic.
    const machine = Machine{ .cpu_count = 128, .memory_bytes = 64 << 30 };
    const resolved = foldLayers(.{ .processes = .{ .absolute = 1000 } }, .{}, null, machine);
    const held = underCeiling(resolved, .{ .processes = "not a number" }, machine);
    try testing.expectEqual(resolved.processes, held.processes);
    try testing.expect(!held.processes_from_org);
}

test "this machine's own cpu count and memory can really be read" {
    // The one test that is not deterministic, and it asks the smallest
    // question that is still a real one: a real machine reports at least one
    // cpu and more than zero bytes of memory.
    const machine = try Machine.read();
    try testing.expect(machine.cpu_count >= 1);
    try testing.expect(machine.memory_bytes > 0);
}
