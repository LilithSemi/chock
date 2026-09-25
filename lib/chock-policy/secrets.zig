//! The `secrets` block of a project's own `chock.zon`: which secret a tool may
//! be given, and which tool may be given it.
//!
//! ## The agent never sees the value
//!
//! A secret named here reaches the environment of one tool call and nothing
//! else. It does not enter the prompt, and whatever a tool prints is redacted
//! before it reaches the log or the model. So an agent can use the GitHub CLI
//! without ever holding the token.
//!
//! ## The mapping is the user's, and the agent cannot widen it
//!
//! Every entry is written by a person in the project's own file. Nothing is
//! discovered, and an agent has no way to ask for a secret that is not here.
//!
//! ## An entry names an action and not a program
//!
//! `to` is an action name pattern, read by the same table every other
//! permission uses, so `exec.path.gh` reaches one program and `mcp.github.*`
//! reaches every tool of one MCP server. Using a secret is itself asked about,
//! under `secret.use.<name>`, so a project decides whether that is a question
//! or a standing permission.

const std = @import("std");
const limits_mod = @import("limits.zig");
const table = @import("table.zig");

pub const file_name = limits_mod.file_name;

pub const block_name = "secrets";

/// Every entry is one more secret a tool call may carry, and one more thing to
/// read before trusting a project. A real bound, not a round number.
pub const max_entries: usize = 32;

/// What a secret may be called. SecretSpec names look like environment
/// variables, and this is what that shape allows.
pub const max_name_bytes: usize = 128;

/// How a secret arrives, because not every program reads one the same way.
pub const Bind = enum {
    /// In the environment of the tool call. What most programs read.
    env,
    /// In a file, with the environment naming its path. What a program that
    /// wants a credentials file reads, and the only way to give one to a
    /// program that will not read an environment variable.
    file,
};

/// One grant: a secret, what it may reach, and how it arrives.
pub const Entry = struct {
    /// The secret's own name, as the store knows it.
    name: []const u8,
    /// The action name pattern this secret may be given to.
    to: []const u8,
    /// How it arrives.
    bind: Bind = .env,
    /// The environment variable it arrives under, or that names the file's
    /// path. Null means the secret's own name, which is what a program that
    /// reads `GITHUB_TOKEN` wants.
    as: ?[]const u8 = null,

    /// The variable this entry sets, whichever way it binds.
    pub fn variable(self: Entry) []const u8 {
        return self.as orelse self.name;
    }
};

pub const Block = struct {
    entries: []const Entry = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        for (self.entries) |one| {
            gpa.free(one.name);
            gpa.free(one.to);
            if (one.as) |held| gpa.free(held);
        }
        gpa.free(self.entries);
        self.* = undefined;
    }

    /// Whether `action` may be given `name`, by any entry.
    pub fn permits(self: Block, name: []const u8, action: []const u8) bool {
        for (self.entries) |one| {
            if (!std.mem.eql(u8, one.name, name)) continue;
            if (table.patternMatches(one.to, action)) return true;
        }
        return false;
    }

    /// Every secret `action` may be given. The caller keeps the block alive.
    pub fn forAction(self: Block, gpa: std.mem.Allocator, action: []const u8) ![]const []const u8 {
        var found: std.ArrayList([]const u8) = .empty;
        errdefer found.deinit(gpa);
        for (self.entries) |one| {
            if (!table.patternMatches(one.to, action)) continue;
            var already = false;
            for (found.items) |seen| {
                if (std.mem.eql(u8, seen, one.name)) already = true;
            }
            if (!already) try found.append(gpa, one.name);
        }
        return found.toOwnedSlice(gpa);
    }
};

/// The action a project answers to say whether a secret may be used at all.
/// One key per secret, so a project can make the one that matters a question
/// and leave the rest alone.
pub fn actionFor(gpa: std.mem.Allocator, name: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(gpa, "secret.use.{s}", .{name});
}

/// Whether `name` is a shape this reader accepts.
///
/// Letters, digits and underscore. A name reaches an action name as
/// `secret.use.<name>`, so a dot would let one entry name a class of actions
/// nobody wrote, and a `*` would do worse.
pub fn nameIsWellFormed(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_bytes) return false;
    for (name) |c| {
        const ok = (c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or c == '_';
        if (!ok) return false;
    }
    return true;
}

/// Whether `name` is a shape an environment variable takes.
///
/// The same set a secret name allows, and it may not begin with a digit. A
/// shell will not read one that does, so a grant naming it would set a variable
/// the program never sees.
pub fn variableIsWellFormed(name: []const u8) bool {
    if (!nameIsWellFormed(name)) return false;
    return !(name[0] >= '0' and name[0] <= '9');
}

pub const ParseError = error{
    OutOfMemory,
    InvalidSecrets,
};

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Fault = union(enum) {
        not_a_struct_literal,
        not_a_list,
        entry_not_a_struct,
        too_many_entries: usize,
        unknown_field: []const u8,
        name_missing,
        name_not_a_string,
        name_not_well_formed: []const u8,
        to_missing,
        to_not_a_string,
        to_not_well_formed: []const u8,
        bind_not_a_string,
        bind_unknown: []const u8,
        as_not_a_string,
        as_not_well_formed: []const u8,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .unknown_field,
            .name_not_well_formed,
            .to_not_well_formed,
            .bind_unknown,
            .as_not_well_formed,
            => |text| gpa.free(text),
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
                "{s}: the secrets block must hold a list of entries",
                .{self.source},
            ),
            .entry_not_a_struct => try writer.print(
                "{s}: every entry of the secrets block must be a struct literal",
                .{self.source},
            ),
            .too_many_entries => |bound| try writer.print(
                "{s}: the secrets block holds more than {d} entries",
                .{ self.source, bound },
            ),
            .unknown_field => |field| try writer.print(
                "{s}: an entry of the secrets block names a field this reader does not know: {s}",
                .{ self.source, field },
            ),
            .name_missing => try writer.print(
                "{s}: every entry of the secrets block needs a name",
                .{self.source},
            ),
            .name_not_a_string => try writer.print(
                "{s}: an entry's name must be a string",
                .{self.source},
            ),
            .name_not_well_formed => |text| try writer.print(
                "{s}: \"{s}\" cannot name a secret. A name holds letters, digits and underscore, " ++
                    "because it becomes part of the action secret.use.<name>.",
                .{ self.source, text },
            ),
            .to_missing => try writer.print(
                "{s}: every entry of the secrets block needs a to",
                .{self.source},
            ),
            .to_not_a_string => try writer.print(
                "{s}: an entry's to must be a string",
                .{self.source},
            ),
            .bind_not_a_string => try writer.print(
                "{s}: an entry's bind must be a string",
                .{self.source},
            ),
            .bind_unknown => |text| try writer.print(
                "{s}: an entry binds as \"{s}\", and this reader knows env and file",
                .{ self.source, text },
            ),
            .as_not_a_string => try writer.print(
                "{s}: an entry's as must be a string",
                .{self.source},
            ),
            .as_not_well_formed => |text| try writer.print(
                "{s}: \"{s}\" cannot name an environment variable. A name holds letters, digits " ++
                    "and underscore, and does not begin with a digit.",
                .{ self.source, text },
            ),
            .to_not_well_formed => |text| try writer.print(
                "{s}: \"{s}\" is not an action name this table reads. A pattern ends with .* or " ++
                    "names an action outright, and never holds a * anywhere else.",
                .{ self.source, text },
            ),
        }
    }
};

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
    var ast = std.zig.Ast.parse(gpa, source, .zon) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer ast.deinit(gpa);

    var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = true });
    defer zoir.deinit(gpa);

    if (zoir.hasCompileErrors()) {
        _ = note(diag, source_name, .not_a_struct_literal);
        return error.InvalidSecrets;
    }

    const node = try findBlock(zoir, source_name, diag) orelse return .{};
    return readEntries(gpa, zoir, node, source_name, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(zoir), block_name)) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidSecrets;
        },
    }
}

fn readEntries(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const items = switch (node.get(zoir)) {
        .empty_literal => return .{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .not_a_list);
            return error.InvalidSecrets;
        },
    };

    if (items.len > max_entries) {
        _ = note(diag, source_name, .{ .too_many_entries = max_entries });
        return error.InvalidSecrets;
    }

    var out: std.ArrayList(Entry) = .empty;
    errdefer {
        for (out.items) |one| {
            gpa.free(one.name);
            gpa.free(one.to);
        }
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        const entry = try readEntry(gpa, zoir, items.at(@intCast(index)), source_name, diag);
        try out.append(gpa, entry);
    }
    return .{ .entries = try out.toOwnedSlice(gpa) };
}

fn readEntry(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Entry {
    const fields = switch (node.get(zoir)) {
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .entry_not_a_struct);
            return error.InvalidSecrets;
        },
    };

    var name: ?[]const u8 = null;
    var to: ?[]const u8 = null;
    var bind: Bind = .env;
    var as: ?[]const u8 = null;
    errdefer {
        if (name) |held| gpa.free(held);
        if (to) |held| gpa.free(held);
        if (as) |held| gpa.free(held);
    }

    for (fields.names, 0..) |field_id, index| {
        const field = field_id.get(zoir);
        const value = fields.vals.at(@intCast(index));
        if (std.mem.eql(u8, field, "name")) {
            name = try readString(gpa, zoir, value, source_name, .name_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "to")) {
            to = try readString(gpa, zoir, value, source_name, .to_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "bind")) {
            const text = try readString(gpa, zoir, value, source_name, .bind_not_a_string, diag);
            defer gpa.free(text);
            bind = std.meta.stringToEnum(Bind, text) orelse {
                _ = note(diag, source_name, .{ .bind_unknown = try gpa.dupe(u8, text) });
                return error.InvalidSecrets;
            };
        } else if (std.mem.eql(u8, field, "as")) {
            as = try readString(gpa, zoir, value, source_name, .as_not_a_string, diag);
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidSecrets;
        }
    }

    const held_name = name orelse {
        _ = note(diag, source_name, .name_missing);
        return error.InvalidSecrets;
    };
    const held_to = to orelse {
        _ = note(diag, source_name, .to_missing);
        return error.InvalidSecrets;
    };

    if (!nameIsWellFormed(held_name)) {
        _ = note(diag, source_name, .{ .name_not_well_formed = try gpa.dupe(u8, held_name) });
        return error.InvalidSecrets;
    }
    // **The same check the table makes, made here.** A pattern this reader
    // accepted and the table did not would grant a secret to nothing at all,
    // and the file would look right while doing nothing.
    if (!table.patternIsWellFormed(held_to)) {
        _ = note(diag, source_name, .{ .to_not_well_formed = try gpa.dupe(u8, held_to) });
        return error.InvalidSecrets;
    }

    if (as) |named| {
        if (!variableIsWellFormed(named)) {
            _ = note(diag, source_name, .{ .as_not_well_formed = try gpa.dupe(u8, named) });
            return error.InvalidSecrets;
        }
    }

    return .{ .name = held_name, .to = held_to, .bind = bind, .as = as };
}

fn readString(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    fault: Diagnostic.Fault,
    diag: ?*?Diagnostic,
) ParseError![]const u8 {
    switch (node.get(zoir)) {
        .string_literal => |text| return gpa.dupe(u8, text),
        else => {
            _ = note(diag, source_name, fault);
            return error.InvalidSecrets;
        },
    }
}

const testing = std.testing;

test "a file with no secrets block grants nothing" {
    const gpa = testing.allocator;

    var none = try parse(gpa, ".{}", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.entries.len);
    try testing.expect(!none.permits("github", "exec.path.gh"));

    var other = try parse(gpa, ".{ .policy = .{} }", null);
    defer other.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), other.entries.len);
}

test "a secret reaches the action it was granted to and no other" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{ .secrets = .{
        \\    .{ .name = "GITHUB_TOKEN", .to = "exec.path.gh" },
        \\    .{ .name = "GITHUB_TOKEN", .to = "mcp.github.*" },
        \\} }
    , null);
    defer block.deinit(gpa);

    try testing.expect(block.permits("GITHUB_TOKEN", "exec.path.gh"));
    try testing.expect(block.permits("GITHUB_TOKEN", "mcp.github.tool.create_issue"));

    // A program nobody granted it to, and a secret nobody granted.
    try testing.expect(!block.permits("GITHUB_TOKEN", "exec.path.curl"));
    try testing.expect(!block.permits("OPENAI_KEY", "exec.path.gh"));
}

test "a pattern the policy table would refuse is refused here" {
    const gpa = testing.allocator;

    // An interior star is what the table will not read, so a file holding one
    // would grant nothing while looking as though it granted something.
    for ([_][]const u8{ "exec.*.gh", "*", "" }) |bad| {
        var diag: ?Diagnostic = null;
        defer if (diag) |*d| d.deinit(gpa);

        const source = try std.fmt.allocPrintSentinel(gpa, ".{{ .secrets = .{{ .{{ .name = \"A\", .to = \"{s}\" }} }} }}", .{bad}, 0);
        defer gpa.free(source);

        try testing.expectError(error.InvalidSecrets, parse(gpa, source, &diag));
        try testing.expect(diag.?.fault == .to_not_well_formed);
    }
}

test "every pattern this reader accepts is one the table accepts too" {
    // The binding that stops the two drifting apart.
    for ([_][]const u8{ "exec.path.gh", "mcp.github.*", "call.run_command" }) |good| {
        try testing.expect(table.patternIsWellFormed(good));
    }
}

test "a name that could reach past its own action is refused" {
    const gpa = testing.allocator;

    // A dot would make `secret.use.<name>` name a class nobody wrote, and a
    // star would make it name every one.
    for ([_][]const u8{ "a.b", "a*", "a b", "", "a/b" }) |bad| {
        try testing.expect(!nameIsWellFormed(bad));
    }
    for ([_][]const u8{ "GITHUB_TOKEN", "openai_key", "k3" }) |good| {
        try testing.expect(nameIsWellFormed(good));
    }

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .name = \"a.b\", .to = \"exec.path.gh\" } } }", &diag),
    );
    try testing.expect(diag.?.fault == .name_not_well_formed);
}

test "the action a secret is asked about carries its own name" {
    const gpa = testing.allocator;
    const action = try actionFor(gpa, "GITHUB_TOKEN");
    defer gpa.free(action);

    try testing.expectEqualStrings("secret.use.GITHUB_TOKEN", action);
    // And it is a name the table can read, or a project could not write a rule
    // about it.
    try testing.expect(table.patternIsWellFormed(action));
}

test "every secret one action may be given is listed once" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{ .secrets = .{
        \\    .{ .name = "A", .to = "exec.path.gh" },
        \\    .{ .name = "B", .to = "exec.*" },
        \\    .{ .name = "A", .to = "exec.*" },
        \\} }
    , null);
    defer block.deinit(gpa);

    const found = try block.forAction(gpa, "exec.path.gh");
    defer gpa.free(found);

    // `A` is granted twice by two patterns and appears once.
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("A", found[0]);
    try testing.expectEqualStrings("B", found[1]);

    const none = try block.forAction(gpa, "call.read_file");
    defer gpa.free(none);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "a missing field is refused rather than read as empty" {
    const gpa = testing.allocator;

    var no_to: ?Diagnostic = null;
    defer if (no_to) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .name = \"A\" } } }", &no_to),
    );
    try testing.expect(no_to.?.fault == .to_missing);

    var no_name: ?Diagnostic = null;
    defer if (no_name) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .to = \"exec.path.gh\" } } }", &no_name),
    );
    try testing.expect(no_name.?.fault == .name_missing);

    var typo: ?Diagnostic = null;
    defer if (typo) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .name = \"A\", .too = \"x\" } } }", &typo),
    );
    try testing.expectEqualStrings("too", typo.?.fault.unknown_field);
}

test "a secret says how it arrives, and the environment is the default" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{ .secrets = .{
        \\    .{ .name = "GITHUB_TOKEN", .to = "exec.path.gh" },
        \\    .{ .name = "GCP_KEY", .to = "exec.path.gcloud", .bind = "file", .as = "GOOGLE_APPLICATION_CREDENTIALS" },
        \\} }
    , null);
    defer block.deinit(gpa);

    try testing.expectEqual(Bind.env, block.entries[0].bind);
    try testing.expectEqualStrings("GITHUB_TOKEN", block.entries[0].variable());

    try testing.expectEqual(Bind.file, block.entries[1].bind);
    try testing.expectEqualStrings("GOOGLE_APPLICATION_CREDENTIALS", block.entries[1].variable());
}

test "an unknown binding is refused, and the message names the two" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .name = \"A\", .to = \"exec.path.gh\", .bind = \"stdin\" } } }", &diag),
    );
    try testing.expectEqualStrings("stdin", diag.?.fault.bind_unknown);

    const text = try std.fmt.allocPrint(gpa, "{f}", .{diag.?});
    defer gpa.free(text);
    inline for (@typeInfo(Bind).@"enum".fields) |field| {
        try testing.expect(std.mem.indexOf(u8, text, field.name) != null);
    }
}

test "a variable a shell would not read is refused" {
    const gpa = testing.allocator;

    // A leading digit is the one an ordinary name allows and a shell does not.
    try testing.expect(nameIsWellFormed("9LIVES"));
    try testing.expect(!variableIsWellFormed("9LIVES"));

    for ([_][]const u8{ "GITHUB_TOKEN", "_hidden", "k3" }) |good| {
        try testing.expect(variableIsWellFormed(good));
    }

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.InvalidSecrets,
        parse(gpa, ".{ .secrets = .{ .{ .name = \"A\", .to = \"exec.path.gh\", .as = \"9LIVES\" } } }", &diag),
    );
    try testing.expect(diag.?.fault == .as_not_well_formed);
}
