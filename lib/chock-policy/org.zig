//! The org bundle: the policy an organisation gives an installation, above the
//! project's own `chock.zon`, which may only narrow it.

const std = @import("std");
const table = @import("table.zig");
const subagent = @import("subagents.zig");
const limits_mod = @import("limits.zig");
const nix_mod = @import("nix.zig");
const search_mod = @import("search.zig");

pub const file_name = "org-policy.zon";

pub const max_file_bytes = 1 << 20;

pub const max_subject_bytes = 256;

pub const max_issuer_bytes = 256;

/// A file above this was written by a newer Chock, which may narrow something
/// this build cannot see.
pub const max_version: u32 = 1;

pub const max_sinks: usize = 4;

pub const max_sink_path_bytes = 4096;

/// A place every session of this installation sends its log, whatever the
/// person at the keyboard asked for. This is the control the command line could
/// not be.
pub const RequiredSink = struct {
    kind: Kind,
    /// Absolute, and the reader refuses anything else: a relative path puts
    /// the trail inside the tree the observed person owns.
    path: []const u8,

    /// No network sink. `chock run` is single threaded on the tool path, so a sink
    /// that could block on a network would block the session. A bundle cannot
    /// require what Chock cannot carry.
    pub const Kind = enum {
        directory,
        syslog,
    };
};

/// A bound and not a rule, so it is a field and not a `table.Rule`. The fold
/// for a number is a minimum, and `chock_cost.budget.underCeiling` takes it.
/// Written out again here because this library imports no other chock library.
pub const BudgetCeiling = struct {
    max_cost: f64,
    /// ISO 4217. Empty when the bundle named none, and the one default lives
    /// in `chock_cost.budget.default_currency`.
    currency: []const u8 = "",
};

pub const Bundle = struct {
    subject: []const u8 = "",
    issuer: []const u8 = "",
    issued_ms: i64 = 0,
    expires_ms: i64 = 0,
    rules: []const table.Rule = &.{},
    sinks: []const RequiredSink = &.{},
    budget: ?BudgetCeiling = null,
    subagents: ?subagent.Ceiling = null,
    limits: ?limits_mod.Ceiling = null,
    nix: ?nix_mod.Ceiling = null,
    /// What the search engine may be. An organisation can pin a kind or a
    /// base url, and can forbid the `scrape` kind outright.
    search: ?search_mod.Ceiling = null,
    /// Files every project of this installation must keep out of the sandbox,
    /// on top of its own `deny_read` block.
    ///
    /// A union and not a minimum: a project adds to this list and can take
    /// nothing off it. The entries are checked by `chock_workspace.deny.check`,
    /// which this module cannot reach, so the refusal happens a moment later
    /// rather than in a second copy of that rule.
    deny_read: []const []const u8 = &.{},
    version: u32 = 1,

    /// An expired bundle keeps binding, in full and for ever. A bundle only
    /// narrows, so dropping an expired one can only widen, at exactly the
    /// moment nobody can be reached to say whether that is right. It is said
    /// out loud on every start, and `refusalForInstall` refuses to install one:
    /// the date is the day after which nobody may hand this file to Chock, not
    /// the day it stops binding a machine that already has it.
    pub fn expiredAt(self: *const Bundle, now_ms: i64) bool {
        if (self.expires_ms == 0) return false;
        return now_ms > self.expires_ms;
    }

    pub fn expiredForMs(self: *const Bundle, now_ms: i64) ?i64 {
        if (!self.expiredAt(now_ms)) return null;
        return now_ms -| self.expires_ms;
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidBundle,
    InvalidPattern,
    TooManyRules,
    NameTooLong,
    VersionTooNew,
    TooManySinks,
    InvalidSinkPath,
    InvalidBudgetCeiling,
    InvalidSubagentCeiling,
    InvalidLimitsCeilingEmpty,
    InvalidLimitsCeilingSetting,
    InvalidNixCeilingEmpty,
    InvalidNixCeilingSetting,
};

pub const LoadError = ParseError || error{
    /// The ordinary answer for an installation nobody gave a bundle, and never
    /// a fault.
    NoBundleFile,
    BundleTooLarge,
    ReadFailed,
};

pub const Diagnostic = union(enum) {
    not_valid: std.zon.parse.Diagnostics,
    read_failed: anyerror,
    too_many_rules: usize,
    pattern_matches_everything: []const u8,
    pattern_malformed: []const u8,
    name_too_long: NameTooLong,
    version_too_new: u32,
    too_many_sinks: usize,
    /// A position and never the path itself. A bundle that fails to validate is
    /// freed by `parse` before this reaches a caller, so a diagnostic that
    /// borrowed a string out of it would dangle.
    sink_path_empty: usize,
    sink_path_relative: usize,
    sink_path_too_long: usize,
    budget_max_cost_not_positive: f64,
    subagent_ceiling_names_nothing,
    limits_ceiling_names_nothing,
    invalid_limits_ceiling: InvalidLimitsCeiling,
    nix_ceiling_names_nothing,
    invalid_nix_ceiling: InvalidNixCeiling,

    pub const InvalidLimitsCeiling = struct {
        field: []const u8,
        reason: limits_mod.SettingError,
    };

    pub const InvalidNixCeiling = struct {
        field: []const u8,
        reason: nix_mod.BytesError,
    };

    pub const NameTooLong = struct {
        field: []const u8,
        held: usize,
        bound: usize,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .not_valid => |*zon_diag| zon_diag.deinit(gpa),
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .not_valid => |*zon_diag| try writer.print(
                "the org policy bundle is not valid:\n{f}",
                .{zon_diag},
            ),
            .read_failed => |err| try writer.print(
                "reading the org policy bundle failed: {s}",
                .{@errorName(err)},
            ),
            .too_many_rules => |held| try writer.print(
                "the org policy bundle holds {d} rules, and this reader accepts {d}",
                .{ held, table.max_rules },
            ),
            .pattern_matches_everything => |field| try writer.print(
                "the org policy bundle has a rule whose {s} holds \"*\". Leave the field out to match every value.",
                .{field},
            ),
            .pattern_malformed => |field| try writer.print(
                "the org policy bundle has a rule whose {s} holds an invalid name. A name matches itself, and a name that ends in \".*\" matches every name below it.",
                .{field},
            ),
            .name_too_long => |name| try writer.print(
                "the org policy bundle holds a {s} of {d} bytes, and this reader accepts {d}",
                .{ name.field, name.held, name.bound },
            ),
            .version_too_new => |held| try writer.print(
                "the org policy bundle names version {d}, and this Chock reads up to version {d}. " ++
                    "A bundle this build cannot fully read is refused rather than applied in part, " ++
                    "because the part it cannot read may be the part that narrows something. Update Chock.",
                .{ held, max_version },
            ),
            .too_many_sinks => |held| try writer.print(
                "the org policy bundle requires {d} audit sinks, and this reader accepts {d}. " ++
                    "Every sink is written on the session's own path, once per event.",
                .{ held, max_sinks },
            ),
            .sink_path_empty => |which| try writer.print(
                "audit sink {d} of the org policy bundle names no path.",
                .{which},
            ),
            .sink_path_relative => |which| try writer.print(
                "audit sink {d} of the org policy bundle names a path that is not absolute. " ++
                    "A relative path resolves against whatever directory a session started in, " ++
                    "which is the project the session works on, so the audit trail would land " ++
                    "inside the tree the person under audit owns. Name the path from the root.",
                .{which},
            ),
            .sink_path_too_long => |which| try writer.print(
                "audit sink {d} of the org policy bundle names a path longer than {d} bytes.",
                .{ which, max_sink_path_bytes },
            ),
            .subagent_ceiling_names_nothing => try writer.writeAll(
                "the org policy bundle's subagent ceiling names neither max_depth nor " ++
                    "max_width, so it caps nothing. Name at least one, or remove the block.",
            ),
            .limits_ceiling_names_nothing => try writer.writeAll(
                "the org policy bundle's limits ceiling names neither processes nor " ++
                    "memory, so it caps nothing. Name at least one, or remove the block.",
            ),
            .invalid_limits_ceiling => |ceiling| try writer.print(
                "the org policy bundle's limits ceiling names a {s} field that {s}",
                .{ ceiling.field, limits_mod.reasonText(ceiling.reason) },
            ),
            .nix_ceiling_names_nothing => try writer.writeAll(
                "the org policy bundle's nix ceiling names neither max_object_bytes nor " ++
                    "max_session_bytes, so it caps nothing. Name at least one, or remove the block.",
            ),
            .invalid_nix_ceiling => |ceiling| try writer.print(
                "the org policy bundle's nix ceiling names a {s} field that {s}",
                .{ ceiling.field, nix_mod.reasonText(ceiling.reason) },
            ),
            .budget_max_cost_not_positive => |value| try writer.print(
                "the org policy bundle's budget ceiling must be a number above zero, and this " ++
                    "one is {d}. A ceiling of zero stops every session in this installation on " ++
                    "its first turn, which is not a cap anybody writes on purpose.",
                .{value},
            ),
        }
    }
};

/// The first fault is kept and not the last.
fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// This reader is looser about a field name than `chock.zon`'s reader, and the
/// two are loose in opposite directions on purpose. A misspelled key field in a
/// project file makes a rule match more and so permit more. Here it makes a
/// rule match more and so narrow more, because this layer is a ceiling.
pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    diag: ?*?Diagnostic,
) ParseError!*const Bundle {
    var zon_diag: std.zon.parse.Diagnostics = .{};
    var diag_owned = true;
    defer if (diag_owned) zon_diag.deinit(gpa);

    const bundle = std.zon.parse.fromSliceAlloc(Bundle, gpa, source, &zon_diag, .{
        // A member this build has no field for is kept out rather than refusing
        // the bundle: only an unknown version refuses.
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => {
            if (note(diag, .{ .not_valid = zon_diag })) diag_owned = false;
            return error.InvalidBundle;
        },
    };
    errdefer std.zon.parse.free(gpa, bundle);

    try validate(bundle, diag);

    const owned = try gpa.create(Bundle);
    owned.* = bundle;
    return owned;
}

pub fn load(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diag: ?*?Diagnostic,
) LoadError!*const Bundle {
    const source = std.Io.Dir.cwd().readFileAllocOptions(
        io,
        path,
        gpa,
        .limited(max_file_bytes),
        .of(u8),
        0,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.StreamTooLong => return error.BundleTooLarge,
        error.FileNotFound, error.NotDir => return error.NoBundleFile,
        else => {
            _ = note(diag, .{ .read_failed = err });
            return error.ReadFailed;
        },
    };
    defer gpa.free(source);

    return parse(gpa, source, diag);
}

pub fn destroy(gpa: std.mem.Allocator, self: *const Bundle) void {
    std.zon.parse.free(gpa, self.*);
    gpa.destroy(self);
}

fn validate(bundle: Bundle, diag: ?*?Diagnostic) ParseError!void {
    // The version first, because every other check is a check of a schema this
    // build may not be reading correctly at all.
    if (bundle.version > max_version) {
        _ = note(diag, .{ .version_too_new = bundle.version });
        return error.VersionTooNew;
    }
    if (bundle.rules.len > table.max_rules) {
        _ = note(diag, .{ .too_many_rules = bundle.rules.len });
        return error.TooManyRules;
    }
    if (bundle.subject.len > max_subject_bytes) {
        _ = note(diag, .{ .name_too_long = .{
            .field = "subject",
            .held = bundle.subject.len,
            .bound = max_subject_bytes,
        } });
        return error.NameTooLong;
    }
    if (bundle.issuer.len > max_issuer_bytes) {
        _ = note(diag, .{ .name_too_long = .{
            .field = "issuer",
            .held = bundle.issuer.len,
            .bound = max_issuer_bytes,
        } });
        return error.NameTooLong;
    }

    for (bundle.rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            try validatePattern(field, @field(rule, field), diag);
        }
    }

    if (bundle.sinks.len > max_sinks) {
        _ = note(diag, .{ .too_many_sinks = bundle.sinks.len });
        return error.TooManySinks;
    }
    for (bundle.sinks, 1..) |sink, which| {
        if (sink.path.len == 0) {
            _ = note(diag, .{ .sink_path_empty = which });
            return error.InvalidSinkPath;
        }
        if (sink.path.len > max_sink_path_bytes) {
            _ = note(diag, .{ .sink_path_too_long = which });
            return error.InvalidSinkPath;
        }
        if (!std.fs.path.isAbsolute(sink.path)) {
            _ = note(diag, .{ .sink_path_relative = which });
            return error.InvalidSinkPath;
        }
    }

    if (bundle.budget) |ceiling| {
        if (!(ceiling.max_cost > 0) or !std.math.isFinite(ceiling.max_cost)) {
            _ = note(diag, .{ .budget_max_cost_not_positive = ceiling.max_cost });
            return error.InvalidBudgetCeiling;
        }
    }

    // Zero is a real ceiling here and an empty block is not. A `max_width` of
    // zero turns subagents off for the installation, and a block that names
    // neither limit caps nothing.
    if (bundle.subagents) |ceiling| {
        if (ceiling.max_depth == null and ceiling.max_width == null) {
            _ = note(diag, .subagent_ceiling_names_nothing);
            return error.InvalidSubagentCeiling;
        }
    }

    if (bundle.limits) |ceiling| {
        if (ceiling.processes == null and ceiling.memory == null) {
            _ = note(diag, .limits_ceiling_names_nothing);
            return error.InvalidLimitsCeilingEmpty;
        }
        if (ceiling.processes) |text| {
            _ = limits_mod.parseSetting(text) catch |err| {
                _ = note(diag, .{ .invalid_limits_ceiling = .{ .field = "processes", .reason = err } });
                return error.InvalidLimitsCeilingSetting;
            };
        }
        if (ceiling.memory) |text| {
            _ = limits_mod.parseSetting(text) catch |err| {
                _ = note(diag, .{ .invalid_limits_ceiling = .{ .field = "memory", .reason = err } });
                return error.InvalidLimitsCeilingSetting;
            };
        }
    }

    if (bundle.nix) |ceiling| {
        if (ceiling.max_object_bytes == null and ceiling.max_session_bytes == null) {
            _ = note(diag, .nix_ceiling_names_nothing);
            return error.InvalidNixCeilingEmpty;
        }
        if (ceiling.max_object_bytes) |text| {
            _ = nix_mod.parseBytes(text) catch |err| {
                _ = note(diag, .{ .invalid_nix_ceiling = .{ .field = "max_object_bytes", .reason = err } });
                return error.InvalidNixCeilingSetting;
            };
        }
        if (ceiling.max_session_bytes) |text| {
            _ = nix_mod.parseBytes(text) catch |err| {
                _ = note(diag, .{ .invalid_nix_ceiling = .{ .field = "max_session_bytes", .reason = err } });
                return error.InvalidNixCeilingSetting;
            };
        }
    }
}

/// The same check `table.validatePattern` makes, with the message the person
/// who installed the bundle needs.
fn validatePattern(field: []const u8, pattern: ?[]const u8, diag: ?*?Diagnostic) ParseError!void {
    const text = pattern orelse return;
    if (std.mem.eql(u8, text, "*")) {
        _ = note(diag, .{ .pattern_matches_everything = field });
        return error.InvalidPattern;
    }
    if (!table.patternIsWellFormed(text)) {
        _ = note(diag, .{ .pattern_malformed = field });
        return error.InvalidPattern;
    }
}

pub fn refusalForInstall(bundle: *const Bundle, now_ms: i64) ?[]const u8 {
    if (bundle.expiredAt(now_ms)) {
        return "this org policy bundle expired before it was given to Chock. Ask whoever issued " ++
            "it for a current one. A bundle already installed on this machine keeps binding " ++
            "whatever its date says, so nothing is lost by refusing this file.";
    }
    return null;
}

// Every test below reads bytes built in the test binary.

const testing = std.testing;

fn bundleSource(
    gpa: std.mem.Allocator,
    body: []const u8,
) ![:0]u8 {
    return std.fmt.allocPrintSentinel(gpa, ".{{{s}}}", .{body}, 0);
}

test "a bundle states a subject, and reading it verifies nothing about that subject" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .issuer = "example.org",
        \\ .issued_ms = 1000,
        \\ .expires_ms = 5000,
        \\ .rules = .{ .{ .action = "git.push", .decision = .deny } },
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expectEqualStrings("ross@example.org", bundle.subject);
    try testing.expectEqualStrings("example.org", bundle.issuer);
    try testing.expectEqual(@as(i64, 1000), bundle.issued_ms);
    try testing.expectEqual(@as(i64, 5000), bundle.expires_ms);
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
    try testing.expectEqualStrings("git.push", bundle.rules[0].action.?);
    try testing.expectEqual(table.Decision.deny, bundle.rules[0].decision);
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].agent_kind);
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].model);
    try testing.expectEqual(@as(?[]const u8, null), bundle.rules[0].tool);

    const anonymous = try parse(gpa, ".{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }", null);
    defer destroy(gpa, anonymous);
    try testing.expectEqualStrings("", anonymous.subject);
    try testing.expectEqualStrings("", anonymous.issuer);
    try testing.expectEqual(@as(i64, 0), anonymous.expires_ms);
}

test "an expired bundle keeps binding, says how long ago, and may not be installed" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .expires_ms = 5000,
        \\ .rules = .{ .{ .action = "provider.public.*", .decision = .deny } },
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expect(bundle.expiredAt(9000));
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
    try testing.expectEqualStrings("provider.public.*", bundle.rules[0].action.?);

    try testing.expectEqual(@as(?i64, 4000), bundle.expiredForMs(9000));
    try testing.expectEqual(@as(?i64, null), bundle.expiredForMs(4999));
    try testing.expect(!bundle.expiredAt(5000));
    try testing.expect(bundle.expiredAt(5001));

    try testing.expect(refusalForInstall(bundle, 9000) != null);
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(bundle, 5000));
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(bundle, 1));

    const forever = try parse(gpa, ".{ .rules = .{} }", null);
    defer destroy(gpa, forever);
    try testing.expect(!forever.expiredAt(9000));
    try testing.expect(!forever.expiredAt(std.math.maxInt(i64)));
    try testing.expectEqual(@as(?i64, null), forever.expiredForMs(std.math.maxInt(i64)));
    try testing.expectEqual(@as(?[]const u8, null), refusalForInstall(forever, std.math.maxInt(i64)));
}

test "a bundle from a newer Chock is refused whole, and an unknown field is not" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.VersionTooNew,
        parse(gpa, ".{ .version = 2, .rules = .{} }", &diag),
    );
    try testing.expect(diag != null);

    const current = try parse(gpa, ".{ .version = 1, .rules = .{} }", null);
    defer destroy(gpa, current);
    try testing.expectEqual(@as(u32, 1), current.version);

    const with_extra = try parse(
        gpa,
        ".{ .display_name = \"Example Org\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
        null,
    );
    defer destroy(gpa, with_extra);
    try testing.expectEqual(@as(usize, 1), with_extra.rules.len);
    try testing.expectEqual(table.Decision.deny, with_extra.rules[0].decision);
}

test "a bundle with a pattern the language does not allow is refused before it binds" {
    const gpa = testing.allocator;

    inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(gpa);
        const source = ".{ .rules = .{ .{ ." ++ field ++ " = \"*\", .decision = .deny } } }";
        try testing.expectError(error.InvalidPattern, parse(gpa, source, &diag));
        try testing.expect(diag.? == .pattern_matches_everything);
        try testing.expectEqualStrings(field, diag.?.pattern_matches_everything);
    }

    var malformed: ?Diagnostic = null;
    defer if (malformed) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidPattern,
        parse(gpa, ".{ .rules = .{ .{ .action = \"a.*.b\", .decision = .deny } } }", &malformed),
    );
    try testing.expect(malformed.? == .pattern_malformed);

    const good = try parse(gpa, ".{ .rules = .{ .{ .action = \"provider.*\", .decision = .deny } } }", null);
    defer destroy(gpa, good);
    try testing.expectEqualStrings("provider.*", good.rules[0].action.?);
}

test "a bundle larger than the reader accepts is refused by count and by name length" {
    const gpa = testing.allocator;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, " .rules = .{");
    for (0..table.max_rules + 1) |index| {
        try body.print(gpa, " .{{ .action = \"a{d}\", .decision = .deny }},", .{index});
    }
    try body.appendSlice(gpa, " },");

    const too_many = try bundleSource(gpa, body.items);
    defer gpa.free(too_many);
    var count_diag: ?Diagnostic = null;
    defer if (count_diag) |*d| d.deinit(gpa);
    try testing.expectError(error.TooManyRules, parse(gpa, too_many, &count_diag));
    try testing.expectEqual(@as(usize, table.max_rules + 1), count_diag.?.too_many_rules);

    const long_subject = "s" ** (max_subject_bytes + 1);
    var name_diag: ?Diagnostic = null;
    defer if (name_diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.NameTooLong,
        parse(gpa, ".{ .subject = \"" ++ long_subject ++ "\", .rules = .{} }", &name_diag),
    );
    try testing.expectEqualStrings("subject", name_diag.?.name_too_long.field);
    try testing.expectEqual(@as(usize, max_subject_bytes + 1), name_diag.?.name_too_long.held);

    const at_bound = "s" ** max_subject_bytes;
    const accepted = try parse(gpa, ".{ .subject = \"" ++ at_bound ++ "\", .rules = .{} }", null);
    defer destroy(gpa, accepted);
    try testing.expectEqual(@as(usize, max_subject_bytes), accepted.subject.len);
}

test "a file that is not there is not a fault, and one that is broken names its line" {
    const gpa = testing.allocator;

    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = tmp.dir.realPath(io, &path_buffer) catch return error.RealPathFailed;
    const dir_path = path_buffer[0..written];

    const missing = try std.fs.path.join(gpa, &.{ dir_path, file_name });
    defer gpa.free(missing);
    try testing.expectError(error.NoBundleFile, load(gpa, io, missing, null));

    try tmp.dir.writeFile(io, .{ .sub_path = file_name, .data = ".{ .rules = " });
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidBundle, load(gpa, io, missing, &diag));
    try testing.expect(diag.? == .not_valid);

    try tmp.dir.writeFile(io, .{
        .sub_path = file_name,
        .data = ".{ .subject = \"ross\", .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }",
    });
    const bundle = try load(gpa, io, missing, null);
    defer destroy(gpa, bundle);
    try testing.expectEqualStrings("ross", bundle.subject);
    try testing.expectEqual(@as(usize, 1), bundle.rules.len);
}

test "a bundle requires a sink, and an installation that requires none reads as empty" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .sinks = .{
        \\   .{ .kind = .directory, .path = "/var/audit/chock" },
        \\   .{ .kind = .syslog, .path = "/dev/log" },
        \\ },
        \\ .rules = .{},
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expectEqual(@as(usize, 2), bundle.sinks.len);
    try testing.expectEqual(RequiredSink.Kind.directory, bundle.sinks[0].kind);
    try testing.expectEqualStrings("/var/audit/chock", bundle.sinks[0].path);
    try testing.expectEqual(RequiredSink.Kind.syslog, bundle.sinks[1].kind);
    try testing.expectEqualStrings("/dev/log", bundle.sinks[1].path);

    const none = try parse(gpa, ".{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } }", null);
    defer destroy(gpa, none);
    try testing.expectEqual(@as(usize, 0), none.sinks.len);
}

test "an expired bundle keeps requiring its sinks, the same way it keeps binding its rules" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .expires_ms = 5000,
        \\ .sinks = .{ .{ .kind = .directory, .path = "/var/audit/chock" } },
        \\ .rules = .{},
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);

    try testing.expect(bundle.expiredAt(9000));
    try testing.expectEqual(@as(usize, 1), bundle.sinks.len);
    try testing.expectEqualStrings("/var/audit/chock", bundle.sinks[0].path);
    try testing.expectEqual(@as(?i64, 4000), bundle.expiredForMs(9000));
}

test "a required sink that is not an absolute path is refused before it binds" {
    // A relative path in an installation wide file resolves against the
    // directory a session started in, which for `chock run` is the project.
    const gpa = testing.allocator;

    var relative: ?Diagnostic = null;
    defer if (relative) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"audit\" } }, .rules = .{} }",
        &relative,
    ));
    try testing.expectEqual(@as(usize, 1), relative.?.sink_path_relative);

    const said = try std.fmt.allocPrint(gpa, "{f}", .{&relative.?});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "the tree the person under audit owns") != null);

    var second: ?Diagnostic = null;
    defer if (second) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .syslog, .path = \"/dev/log\" }, " ++
            ".{ .kind = .directory, .path = \"./here\" } }, .rules = .{} }",
        &second,
    ));
    try testing.expectEqual(@as(usize, 2), second.?.sink_path_relative);

    var empty: ?Diagnostic = null;
    defer if (empty) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"\" } }, .rules = .{} }",
        &empty,
    ));
    try testing.expectEqual(@as(usize, 1), empty.?.sink_path_empty);

    const long = "/" ++ "p" ** max_sink_path_bytes;
    var too_long: ?Diagnostic = null;
    defer if (too_long) |*d| d.deinit(gpa);
    try testing.expectError(error.InvalidSinkPath, parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"" ++ long ++ "\" } }, .rules = .{} }",
        &too_long,
    ));
    try testing.expectEqual(@as(usize, 1), too_long.?.sink_path_too_long);

    const at_bound = "/" ++ "p" ** (max_sink_path_bytes - 1);
    const accepted = try parse(
        gpa,
        ".{ .sinks = .{ .{ .kind = .directory, .path = \"" ++ at_bound ++ "\" } }, .rules = .{} }",
        null,
    );
    defer destroy(gpa, accepted);
    try testing.expectEqual(@as(usize, max_sink_path_bytes), accepted.sinks[0].path.len);
}

test "a bundle that requires more sinks than the reader accepts is refused" {
    const gpa = testing.allocator;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try body.appendSlice(gpa, " .rules = .{}, .sinks = .{");
    for (0..max_sinks + 1) |index| {
        try body.print(gpa, " .{{ .kind = .directory, .path = \"/var/audit/{d}\" }},", .{index});
    }
    try body.appendSlice(gpa, " },");

    const source = try bundleSource(gpa, body.items);
    defer gpa.free(source);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.TooManySinks, parse(gpa, source, &diag));
    try testing.expectEqual(@as(usize, max_sinks + 1), diag.?.too_many_sinks);
}

test "no two faults of this module read the same" {
    const gpa = testing.allocator;

    const faults = [_]Diagnostic{
        .{ .read_failed = error.AccessDenied },
        .{ .too_many_rules = 900 },
        .{ .pattern_matches_everything = "action" },
        .{ .pattern_malformed = "model" },
        .{ .name_too_long = .{ .field = "subject", .held = 300, .bound = max_subject_bytes } },
        .{ .version_too_new = 7 },
        .{ .too_many_sinks = 9 },
        .{ .sink_path_empty = 1 },
        .{ .sink_path_relative = 1 },
        .{ .sink_path_too_long = 1 },
        .{ .budget_max_cost_not_positive = 0 },
    };

    var rendered: [faults.len][]u8 = undefined;
    var written: usize = 0;
    defer for (rendered[0..written]) |one| gpa.free(one);
    for (&faults, &rendered) |*fault, *slot| {
        slot.* = try std.fmt.allocPrint(gpa, "{f}", .{fault});
        written += 1;
    }
    for (rendered, 0..) |left, index| {
        for (rendered[index + 1 ..]) |right| {
            try testing.expect(!std.mem.eql(u8, left, right));
        }
        try testing.expect(left.len > 0);
    }
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.OutOfMemory, parse(failing.allocator(), ".{ .rules = .{} }", null));

    try testing.expectError(error.InvalidBundle, parse(testing.allocator, ".{ .rules = ", null));
    try testing.expectError(
        error.VersionTooNew,
        parse(testing.allocator, ".{ .version = 99, .rules = .{} }", null),
    );
}

test "a bundle sets a budget ceiling, and one that names none sets no ceiling" {
    const gpa = testing.allocator;

    const source = try bundleSource(gpa,
        \\ .subject = "ross@example.org",
        \\ .budget = .{ .max_cost = 5.0, .currency = "USD" },
    );
    defer gpa.free(source);

    const bundle = try parse(gpa, source, null);
    defer destroy(gpa, bundle);
    try testing.expectApproxEqAbs(@as(f64, 5.0), bundle.budget.?.max_cost, 1e-12);
    try testing.expectEqualStrings("USD", bundle.budget.?.currency);

    const no_ceiling = try parse(gpa, ".{ .rules = .{} }", null);
    defer destroy(gpa, no_ceiling);
    try testing.expectEqual(@as(?BudgetCeiling, null), no_ceiling.budget);
}

test "a budget ceiling that names no currency leaves the field empty for the folder to fill" {
    const gpa = testing.allocator;
    const bundle = try parse(gpa, ".{ .budget = .{ .max_cost = 5.0 } }", null);
    defer destroy(gpa, bundle);
    try testing.expectEqualStrings("", bundle.budget.?.currency);
}

test "a budget ceiling of zero or below is refused when the bundle is read" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidBudgetCeiling,
        parse(gpa, ".{ .budget = .{ .max_cost = 0.0 } }", &diag),
    );
    try testing.expectApproxEqAbs(
        @as(f64, 0.0),
        diag.?.budget_max_cost_not_positive,
        1e-12,
    );

    try testing.expectError(
        error.InvalidBudgetCeiling,
        parse(gpa, ".{ .budget = .{ .max_cost = -1.0 } }", null),
    );
}

test "a bundle carries a subagent ceiling, and one that caps nothing is refused" {
    const gpa = testing.allocator;

    const both = try parse(gpa, ".{ .subagents = .{ .max_depth = 3, .max_width = 2 } }", null);
    defer destroy(gpa, both);
    try testing.expectEqual(@as(?u16, 3), both.subagents.?.max_depth);
    try testing.expectEqual(@as(?u16, 2), both.subagents.?.max_width);

    const width_only = try parse(gpa, ".{ .subagents = .{ .max_width = 0 } }", null);
    defer destroy(gpa, width_only);
    try testing.expectEqual(@as(?u16, null), width_only.subagents.?.max_depth);
    try testing.expectEqual(@as(?u16, 0), width_only.subagents.?.max_width);

    const older = try parse(gpa, ".{ .rules = .{} }", null);
    defer destroy(gpa, older);
    try testing.expectEqual(@as(?subagent.Ceiling, null), older.subagents);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSubagentCeiling,
        parse(gpa, ".{ .subagents = .{} }", &diag),
    );
    const text = try std.fmt.allocPrint(gpa, "{f}", .{diag.?});
    defer gpa.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "max_depth") != null);
    try testing.expect(std.mem.indexOf(u8, text, "max_width") != null);
}

test "a bundle carries a limits ceiling, and one that caps nothing is refused" {
    const gpa = testing.allocator;

    const both = try parse(gpa, ".{ .limits = .{ .processes = \"256\", .memory = \"8GiB\" } }", null);
    defer destroy(gpa, both);
    try testing.expectEqualStrings("256", both.limits.?.processes.?);
    try testing.expectEqualStrings("8GiB", both.limits.?.memory.?);

    const memory_only = try parse(gpa, ".{ .limits = .{ .memory = \"50%\" } }", null);
    defer destroy(gpa, memory_only);
    try testing.expectEqual(@as(?[]const u8, null), memory_only.limits.?.processes);
    try testing.expectEqualStrings("50%", memory_only.limits.?.memory.?);

    const older = try parse(gpa, ".{ .rules = .{} }", null);
    defer destroy(gpa, older);
    try testing.expectEqual(@as(?limits_mod.Ceiling, null), older.limits);

    var empty_diag: ?Diagnostic = null;
    defer if (empty_diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidLimitsCeilingEmpty,
        parse(gpa, ".{ .limits = .{} }", &empty_diag),
    );
    const empty_text = try std.fmt.allocPrint(gpa, "{f}", .{empty_diag.?});
    defer gpa.free(empty_text);
    try testing.expect(std.mem.indexOf(u8, empty_text, "processes") != null);
    try testing.expect(std.mem.indexOf(u8, empty_text, "memory") != null);
}

test "a limits ceiling that cannot parse is refused when the bundle is read" {
    // Read time and not the moment it would have sized a sandbox.
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidLimitsCeilingSetting,
        parse(gpa, ".{ .limits = .{ .processes = \"200%\" } }", &diag),
    );
    try testing.expectEqualStrings("processes", diag.?.invalid_limits_ceiling.field);
    try testing.expectEqual(limits_mod.SettingError.PercentOverHundred, diag.?.invalid_limits_ceiling.reason);

    var other_diag: ?Diagnostic = null;
    defer if (other_diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidLimitsCeilingSetting,
        parse(gpa, ".{ .limits = .{ .memory = \"not a number\" } }", &other_diag),
    );
    try testing.expectEqualStrings("memory", other_diag.?.invalid_limits_ceiling.field);
}

test "a bundle carries a search ceiling, and it reaches the fold that enforces it" {
    // `Bundle.search` is filled by the struct parser and not by a field table
    // of its own, so nothing in this module names it. This test is what says
    // the field is reachable from a real bundle rather than only from a Zig
    // literal a test wrote.
    const gpa = testing.allocator;

    const bundle = try parse(gpa,
        \\.{ .search = .{ .kinds = .{ .self_hosted, .api } } }
    , null);
    defer destroy(gpa, bundle);

    const ceiling = bundle.search.?;
    try testing.expectEqual(@as(usize, 2), ceiling.kinds.?.len);

    var wanted = try search_mod.parse(gpa,
        \\.{ .search = .{ .kind = "scrape", .provider = "duckduckgo", .base_url = "https://example.org" } }
    , null);
    defer wanted.deinit(gpa);
    try testing.expectError(
        search_mod.CeilingError.KindNotPermitted,
        search_mod.foldLayers(wanted, ceiling, null),
    );

    const none = try parse(gpa, ".{}", null);
    defer destroy(gpa, none);
    try testing.expectEqual(@as(?search_mod.Ceiling, null), none.search);
}
