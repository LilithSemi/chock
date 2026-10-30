//! The `style` block of a project's own `chock.zon`: which languages it can
//! parse, and which of its own queries refuse a write. The block says what a
//! rule is. Whether a rule may run at all is `style.parse` in the policy
//! table, and what a match means is decided where the verdict is taken.
//!
//! The block holds no path to a parser. A Nix store path changes when the
//! package it came from is bumped, so `parsers` and `module` name environment
//! variables the dev shell exports, and Chock looks for one file a language
//! under each.

const std = @import("std");

const limits = @import("limits.zig");
const table = @import("table.zig");

pub const file_name = limits.file_name;

pub const max_rules: usize = 32;
pub const max_grammars: usize = 16;
pub const max_extensions: usize = 8;
pub const max_extension_bytes: usize = 16;

/// What a rule does with a file that breaks it.
pub const Decision = enum {
    /// Nothing is written.
    refuse,
    /// The write lands and the model is told anyway, for a rule a project is
    /// still adopting.
    report,
};

/// One bound a rule, because a rule with two bounds is two rules.
pub const Bound = union(enum) {
    /// Matches tolerated. Zero refuses on the first one.
    max_matches: u32,
    /// Lines one match may cover. A match on one row covers one line, so a
    /// bound of zero lines cannot be met and is refused when it is read.
    max_lines: u32,
    /// Matched lines against the file's own line count, as a percentage.
    max_share: u8,

    pub fn fieldName(self: Bound) []const u8 {
        return @tagName(self);
    }
};

pub const Grammar = struct {
    language: []const u8,
    extensions: []const []const u8,
};

pub const Rule = struct {
    name: []const u8,
    query: []const u8,
    bound: Bound,
    decision: Decision = .refuse,
};

pub const Which = enum { command, wasm };

/// The variable Chock looks for when a project names none of its own, for
/// where the parser modules are.
pub const default_modules_variable = "CHOCK_PARSER_MODULES";

pub const Block = struct {
    /// The environment variable naming the directory that holds the parsers.
    parsers: []const u8 = "",
    /// The environment variable naming the directory of parser modules.
    /// Empty takes `default_modules_variable`, because Chock builds them.
    modules: []const u8 = "",
    engine: Which = .command,
    grammars: []const Grammar = &.{},
    rules: []const Rule = &.{},

    pub fn deinit(self: *Block, gpa: std.mem.Allocator) void {
        gpa.free(self.parsers);
        gpa.free(self.modules);
        for (self.grammars) |one| {
            gpa.free(one.language);
            for (one.extensions) |ext| gpa.free(ext);
            gpa.free(one.extensions);
        }
        gpa.free(self.grammars);
        for (self.rules) |one| {
            gpa.free(one.name);
            gpa.free(one.query);
        }
        gpa.free(self.rules);
        self.* = undefined;
    }

    /// The language whose extensions cover `path`, or null for a file no
    /// grammar of this project can read.
    pub fn languageFor(self: Block, path: []const u8) ?[]const u8 {
        for (self.grammars) |one| {
            for (one.extensions) |ext| {
                if (std.mem.endsWith(u8, path, ext)) return one.language;
            }
        }
        return null;
    }
};

pub const ParseError = error{
    OutOfMemory,
    InvalidStyle,
};

pub const LoadError = ParseError || error{
    StyleFileTooLarge,
    ReadFailed,
};

pub const max_file_bytes = 1 << 20;

pub const Diagnostic = struct {
    source: []const u8,
    fault: Fault,

    pub const Named = struct {
        rule: []const u8,
        text: []const u8,
    };

    pub const Fault = union(enum) {
        not_a_struct_literal,
        not_a_list,
        entry_not_a_struct,
        unknown_field: []const u8,
        too_many_rules: usize,
        too_many_grammars: usize,
        too_many_extensions: usize,
        parsers_not_a_string,
        parsers_not_a_variable: []const u8,
        modules_not_a_string,
        modules_not_a_variable: []const u8,
        engine_not_a_string,
        engine_unknown: []const u8,
        language_not_a_string,
        language_missing,
        language_not_a_name: []const u8,
        extensions_not_a_list,
        extension_not_a_string,
        extension_not_an_extension: []const u8,
        grammar_has_no_extension: []const u8,
        rule_name_not_a_string,
        rule_has_no_name,
        rule_name_not_a_label: []const u8,
        query_not_a_string,
        rule_has_no_query: []const u8,
        query_not_relative: Named,
        query_leaves_the_project: Named,
        bound_not_a_number: []const u8,
        no_bound_on_a_rule: []const u8,
        two_bounds_on_one_rule: Named,
        share_is_not_a_percentage: Named,
        lines_bound_is_zero: []const u8,
        decision_not_a_string,
        decision_unknown: []const u8,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.fault) {
            .unknown_field,
            .parsers_not_a_variable,
            .modules_not_a_variable,
            .engine_unknown,
            .language_not_a_name,
            .extension_not_an_extension,
            .grammar_has_no_extension,
            .rule_name_not_a_label,
            .rule_has_no_query,
            .bound_not_a_number,
            .no_bound_on_a_rule,
            .lines_bound_is_zero,
            .decision_unknown,
            => |text| gpa.free(text),
            .query_not_relative,
            .query_leaves_the_project,
            .two_bounds_on_one_rule,
            .share_is_not_a_percentage,
            => |named| {
                gpa.free(named.rule);
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
                "{s}: the grammars and rules of the style block must each be a list",
                .{self.source},
            ),
            .entry_not_a_struct => try writer.print(
                "{s}: every grammar and every rule must be a struct",
                .{self.source},
            ),
            .unknown_field => |name| try writer.print(
                "{s}: the style block has no field named {s}",
                .{ self.source, name },
            ),
            .too_many_rules => |limit| try writer.print(
                "{s}: the style block names more than {d} rules",
                .{ self.source, limit },
            ),
            .too_many_grammars => |limit| try writer.print(
                "{s}: the style block names more than {d} grammars",
                .{ self.source, limit },
            ),
            .too_many_extensions => |limit| try writer.print(
                "{s}: a grammar names more than {d} extensions",
                .{ self.source, limit },
            ),
            .parsers_not_a_string => try writer.print(
                "{s}: parsers must be the name of an environment variable",
                .{self.source},
            ),
            .parsers_not_a_variable => |name| try writer.print(
                "{s}: parsers is {s}, which is not the name of an environment variable. " ++
                    "It must not be a path: a store path changes when its package is bumped",
                .{ self.source, name },
            ),
            .modules_not_a_string => try writer.print(
                "{s}: modules must be the name of an environment variable",
                .{self.source},
            ),
            .modules_not_a_variable => |name| try writer.print(
                "{s}: modules is {s}, which is not the name of an environment variable. " ++
                    "It must not be a path: a store path changes when its package is bumped",
                .{ self.source, name },
            ),
            .engine_not_a_string => try writer.print(
                "{s}: engine must be a string",
                .{self.source},
            ),
            .engine_unknown => |name| try writer.print(
                "{s}: engine is {s}, and it must be command or wasm",
                .{ self.source, name },
            ),
            .language_not_a_string => try writer.print(
                "{s}: a grammar's language must be a string",
                .{self.source},
            ),
            .language_missing => try writer.print(
                "{s}: a grammar names no language",
                .{self.source},
            ),
            .language_not_a_name => |name| try writer.print(
                "{s}: the language {s} becomes a file name, so it must be one plain name",
                .{ self.source, name },
            ),
            .extensions_not_a_list => try writer.print(
                "{s}: a grammar's extensions must be a list of strings",
                .{self.source},
            ),
            .extension_not_a_string => try writer.print(
                "{s}: every extension must be a string",
                .{self.source},
            ),
            .extension_not_an_extension => |name| try writer.print(
                "{s}: the extension {s} must start with a dot and hold no separator",
                .{ self.source, name },
            ),
            .grammar_has_no_extension => |name| try writer.print(
                "{s}: the grammar for {s} names no extension, so no file would reach it",
                .{ self.source, name },
            ),
            .rule_name_not_a_string => try writer.print(
                "{s}: a rule's name must be a string",
                .{self.source},
            ),
            .rule_has_no_name => try writer.print(
                "{s}: a rule names nothing, and a refusal has to say which rule it was",
                .{self.source},
            ),
            .rule_name_not_a_label => |name| try writer.print(
                "{s}: the rule name {s} must hold letters, digits, hyphens and underscores",
                .{ self.source, name },
            ),
            .query_not_a_string => try writer.print(
                "{s}: a rule's query must be a path to a query file",
                .{self.source},
            ),
            .rule_has_no_query => |name| try writer.print(
                "{s}: the rule {s} names no query file",
                .{ self.source, name },
            ),
            .query_not_relative => |named| try writer.print(
                "{s}: the rule {s} names the query {s}, which must be a path under the project",
                .{ self.source, named.rule, named.text },
            ),
            .query_leaves_the_project => |named| try writer.print(
                "{s}: the rule {s} names the query {s}, which reaches outside the project",
                .{ self.source, named.rule, named.text },
            ),
            .bound_not_a_number => |name| try writer.print(
                "{s}: the rule {s} has a bound that is not a whole number",
                .{ self.source, name },
            ),
            .no_bound_on_a_rule => |name| try writer.print(
                "{s}: the rule {s} has no bound, so write one of max_matches, " ++
                    "max_lines or max_share",
                .{ self.source, name },
            ),
            .two_bounds_on_one_rule => |named| try writer.print(
                "{s}: the rule {s} already has a bound, and {s} is a second one. " ++
                    "A rule with two bounds is two rules",
                .{ self.source, named.rule, named.text },
            ),
            .share_is_not_a_percentage => |named| try writer.print(
                "{s}: the rule {s} has a max_share of {s}, and a share is 0 to 100",
                .{ self.source, named.rule, named.text },
            ),
            .lines_bound_is_zero => |name| try writer.print(
                "{s}: the rule {s} has a max_lines of 0, and a match covers one line " ++
                    "at least, so write max_matches instead",
                .{ self.source, name },
            ),
            .decision_not_a_string => try writer.print(
                "{s}: a rule's decision must be a string",
                .{self.source},
            ),
            .decision_unknown => |name| try writer.print(
                "{s}: the decision {s} must be refuse or report",
                .{ self.source, name },
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

/// A variable name and not a path, so a store path cannot be written here.
pub fn variableIsWellFormed(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    if (name[0] >= '0' and name[0] <= '9') return false;
    for (name) |byte| {
        const ok = (byte >= 'A' and byte <= 'Z') or
            (byte >= 'a' and byte <= 'z') or
            (byte >= '0' and byte <= '9') or
            byte == '_';
        if (!ok) return false;
    }
    return true;
}

/// A language becomes one file name under the parsers directory, so it must
/// carry no separator and nothing that climbs out of it.
pub fn languageIsWellFormed(name: []const u8) bool {
    return table.labelIsUsable(name);
}

pub fn extensionIsWellFormed(text: []const u8) bool {
    if (text.len < 2 or text.len > max_extension_bytes) return false;
    if (text[0] != '.') return false;
    for (text[1..]) |byte| {
        if (byte == '/' or byte == '\\' or byte == '.' or byte == 0) return false;
    }
    return true;
}

pub fn parse(
    gpa: std.mem.Allocator,
    source: [:0]const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
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
        return error.InvalidStyle;
    }

    const node = try findBlock(zoir, source_name, diag) orelse return .{};
    return readBlock(gpa, zoir, node, source_name, diag);
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
        error.StreamTooLong => return error.StyleFileTooLarge,
        else => return error.ReadFailed,
    };
    defer gpa.free(source);

    return parseFrom(gpa, source, path, diag);
}

fn findBlock(
    zoir: std.zig.Zoir,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, at| {
                if (std.mem.eql(u8, name.get(&zoir), "style")) {
                    return fields.vals.at(@intCast(at));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidStyle;
        },
    }
}

fn readBlock(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Block {
    const fields = switch (node.get(&zoir)) {
        .empty_literal => return .{},
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .not_a_struct_literal);
            return error.InvalidStyle;
        },
    };

    var out: Block = .{};
    errdefer out.deinit(gpa);

    for (fields.names, 0..) |field_id, index| {
        const field = field_id.get(&zoir);
        const value = fields.vals.at(@intCast(index));
        if (std.mem.eql(u8, field, "parsers")) {
            gpa.free(out.parsers);
            out.parsers = try readString(gpa, zoir, value, source_name, .parsers_not_a_string, diag);
            if (!variableIsWellFormed(out.parsers)) {
                _ = note(diag, source_name, .{
                    .parsers_not_a_variable = try gpa.dupe(u8, out.parsers),
                });
                return error.InvalidStyle;
            }
        } else if (std.mem.eql(u8, field, "modules")) {
            gpa.free(out.modules);
            out.modules = try readString(gpa, zoir, value, source_name, .modules_not_a_string, diag);
            if (!variableIsWellFormed(out.modules)) {
                _ = note(diag, source_name, .{
                    .modules_not_a_variable = try gpa.dupe(u8, out.modules),
                });
                return error.InvalidStyle;
            }
        } else if (std.mem.eql(u8, field, "engine")) {
            const text = try readString(gpa, zoir, value, source_name, .engine_not_a_string, diag);
            defer gpa.free(text);
            out.engine = std.meta.stringToEnum(Which, text) orelse {
                _ = note(diag, source_name, .{ .engine_unknown = try gpa.dupe(u8, text) });
                return error.InvalidStyle;
            };
        } else if (std.mem.eql(u8, field, "grammars")) {
            out.grammars = try readGrammars(gpa, zoir, value, source_name, diag);
        } else if (std.mem.eql(u8, field, "rules")) {
            out.rules = try readRules(gpa, zoir, value, source_name, diag);
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidStyle;
        }
    }
    return out;
}

fn readGrammars(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const Grammar {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return &.{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .not_a_list);
            return error.InvalidStyle;
        },
    };
    if (items.len > max_grammars) {
        _ = note(diag, source_name, .{ .too_many_grammars = max_grammars });
        return error.InvalidStyle;
    }

    var out: std.ArrayList(Grammar) = .empty;
    errdefer {
        for (out.items) |one| {
            gpa.free(one.language);
            for (one.extensions) |ext| gpa.free(ext);
            gpa.free(one.extensions);
        }
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        try out.append(gpa, try readGrammar(
            gpa,
            zoir,
            items.at(@intCast(index)),
            source_name,
            diag,
        ));
    }
    return out.toOwnedSlice(gpa);
}

fn readGrammar(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Grammar {
    const fields = switch (node.get(&zoir)) {
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .entry_not_a_struct);
            return error.InvalidStyle;
        },
    };

    var language: ?[]const u8 = null;
    var extensions: ?[]const []const u8 = null;
    errdefer {
        if (language) |held| gpa.free(held);
        if (extensions) |held| {
            for (held) |one| gpa.free(one);
            gpa.free(held);
        }
    }

    for (fields.names, 0..) |field_id, index| {
        const field = field_id.get(&zoir);
        const value = fields.vals.at(@intCast(index));
        if (std.mem.eql(u8, field, "language")) {
            language = try readString(gpa, zoir, value, source_name, .language_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "extensions")) {
            extensions = try readExtensions(gpa, zoir, value, source_name, diag);
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidStyle;
        }
    }

    const held_language = language orelse {
        _ = note(diag, source_name, .language_missing);
        return error.InvalidStyle;
    };
    if (!languageIsWellFormed(held_language)) {
        _ = note(diag, source_name, .{
            .language_not_a_name = try gpa.dupe(u8, held_language),
        });
        return error.InvalidStyle;
    }

    const held_extensions = extensions orelse &.{};
    if (held_extensions.len == 0) {
        _ = note(diag, source_name, .{
            .grammar_has_no_extension = try gpa.dupe(u8, held_language),
        });
        return error.InvalidStyle;
    }
    return .{ .language = held_language, .extensions = held_extensions };
}

fn readExtensions(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const []const u8 {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return &.{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .extensions_not_a_list);
            return error.InvalidStyle;
        },
    };
    if (items.len > max_extensions) {
        _ = note(diag, source_name, .{ .too_many_extensions = max_extensions });
        return error.InvalidStyle;
    }

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |one| gpa.free(one);
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        const text = try readString(
            gpa,
            zoir,
            items.at(@intCast(index)),
            source_name,
            .extension_not_a_string,
            diag,
        );
        if (!extensionIsWellFormed(text)) {
            defer gpa.free(text);
            _ = note(diag, source_name, .{
                .extension_not_an_extension = try gpa.dupe(u8, text),
            });
            return error.InvalidStyle;
        }
        try out.append(gpa, text);
    }
    return out.toOwnedSlice(gpa);
}

fn readRules(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError![]const Rule {
    const items = switch (node.get(&zoir)) {
        .empty_literal => return &.{},
        .array_literal => |list| list,
        else => {
            _ = note(diag, source_name, .not_a_list);
            return error.InvalidStyle;
        },
    };
    if (items.len > max_rules) {
        _ = note(diag, source_name, .{ .too_many_rules = max_rules });
        return error.InvalidStyle;
    }

    var out: std.ArrayList(Rule) = .empty;
    errdefer {
        for (out.items) |one| {
            gpa.free(one.name);
            gpa.free(one.query);
        }
        out.deinit(gpa);
    }

    for (0..items.len) |index| {
        try out.append(gpa, try readRule(
            gpa,
            zoir,
            items.at(@intCast(index)),
            source_name,
            diag,
        ));
    }
    return out.toOwnedSlice(gpa);
}

fn readRule(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Rule {
    const fields = switch (node.get(&zoir)) {
        .struct_literal => |one| one,
        else => {
            _ = note(diag, source_name, .entry_not_a_struct);
            return error.InvalidStyle;
        },
    };

    var name: ?[]const u8 = null;
    var query: ?[]const u8 = null;
    var bound: ?Bound = null;
    var decision: Decision = .refuse;
    errdefer {
        if (name) |held| gpa.free(held);
        if (query) |held| gpa.free(held);
    }

    for (fields.names, 0..) |field_id, index| {
        const field = field_id.get(&zoir);
        const value = fields.vals.at(@intCast(index));
        if (std.mem.eql(u8, field, "name")) {
            name = try readString(gpa, zoir, value, source_name, .rule_name_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "query")) {
            query = try readString(gpa, zoir, value, source_name, .query_not_a_string, diag);
        } else if (std.mem.eql(u8, field, "decision")) {
            const text = try readString(gpa, zoir, value, source_name, .decision_not_a_string, diag);
            defer gpa.free(text);
            decision = std.meta.stringToEnum(Decision, text) orelse {
                _ = note(diag, source_name, .{ .decision_unknown = try gpa.dupe(u8, text) });
                return error.InvalidStyle;
            };
        } else if (boundFieldFor(field)) |which| {
            const named = name orelse "";
            if (bound != null) {
                _ = note(diag, source_name, .{ .two_bounds_on_one_rule = .{
                    .rule = try gpa.dupe(u8, named),
                    .text = try gpa.dupe(u8, field),
                } });
                return error.InvalidStyle;
            }
            bound = try readBound(gpa, zoir, value, which, named, source_name, diag);
        } else {
            _ = note(diag, source_name, .{ .unknown_field = try gpa.dupe(u8, field) });
            return error.InvalidStyle;
        }
    }

    const held_name = name orelse {
        _ = note(diag, source_name, .rule_has_no_name);
        return error.InvalidStyle;
    };
    if (held_name.len == 0) {
        _ = note(diag, source_name, .rule_has_no_name);
        return error.InvalidStyle;
    }
    if (!table.labelIsUsable(held_name)) {
        _ = note(diag, source_name, .{ .rule_name_not_a_label = try gpa.dupe(u8, held_name) });
        return error.InvalidStyle;
    }

    const held_query = query orelse {
        _ = note(diag, source_name, .{ .rule_has_no_query = try gpa.dupe(u8, held_name) });
        return error.InvalidStyle;
    };
    if (held_query.len == 0) {
        _ = note(diag, source_name, .{ .rule_has_no_query = try gpa.dupe(u8, held_name) });
        return error.InvalidStyle;
    }
    try checkQueryPath(gpa, held_name, held_query, source_name, diag);

    const held_bound = bound orelse {
        _ = note(diag, source_name, .{ .no_bound_on_a_rule = try gpa.dupe(u8, held_name) });
        return error.InvalidStyle;
    };

    return .{
        .name = held_name,
        .query = held_query,
        .bound = held_bound,
        .decision = decision,
    };
}

const BoundField = enum { max_matches, max_lines, max_share };

fn boundFieldFor(field: []const u8) ?BoundField {
    return std.meta.stringToEnum(BoundField, field);
}

fn readBound(
    gpa: std.mem.Allocator,
    zoir: std.zig.Zoir,
    node: std.zig.Zoir.Node.Index,
    which: BoundField,
    rule: []const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!Bound {
    const value: u64 = switch (node.get(&zoir)) {
        .int_literal => |one| switch (one) {
            .small => |small| if (small < 0) {
                _ = note(diag, source_name, .{ .bound_not_a_number = try gpa.dupe(u8, rule) });
                return error.InvalidStyle;
            } else @intCast(small),
            else => {
                _ = note(diag, source_name, .{ .bound_not_a_number = try gpa.dupe(u8, rule) });
                return error.InvalidStyle;
            },
        },
        else => {
            _ = note(diag, source_name, .{ .bound_not_a_number = try gpa.dupe(u8, rule) });
            return error.InvalidStyle;
        },
    };

    switch (which) {
        .max_matches => {
            if (value > std.math.maxInt(u32)) {
                _ = note(diag, source_name, .{ .bound_not_a_number = try gpa.dupe(u8, rule) });
                return error.InvalidStyle;
            }
            return .{ .max_matches = @intCast(value) };
        },
        .max_lines => {
            if (value == 0) {
                _ = note(diag, source_name, .{ .lines_bound_is_zero = try gpa.dupe(u8, rule) });
                return error.InvalidStyle;
            }
            if (value > std.math.maxInt(u32)) {
                _ = note(diag, source_name, .{ .bound_not_a_number = try gpa.dupe(u8, rule) });
                return error.InvalidStyle;
            }
            return .{ .max_lines = @intCast(value) };
        },
        .max_share => {
            if (value > 100) {
                var written: [24]u8 = undefined;
                const text = std.fmt.bufPrint(&written, "{d}", .{value}) catch "a large number";
                _ = note(diag, source_name, .{ .share_is_not_a_percentage = .{
                    .rule = try gpa.dupe(u8, rule),
                    .text = try gpa.dupe(u8, text),
                } });
                return error.InvalidStyle;
            }
            return .{ .max_share = @intCast(value) };
        },
    }
}

/// The cheap half of the check, which is the half that needs no disk. A query
/// is read from the project, so it must be under the project.
fn checkQueryPath(
    gpa: std.mem.Allocator,
    rule: []const u8,
    text: []const u8,
    source_name: []const u8,
    diag: ?*?Diagnostic,
) ParseError!void {
    if (std.fs.path.isAbsolute(text)) {
        _ = note(diag, source_name, .{ .query_not_relative = .{
            .rule = try gpa.dupe(u8, rule),
            .text = try gpa.dupe(u8, text),
        } });
        return error.InvalidStyle;
    }
    var walk = std.mem.splitScalar(u8, text, '/');
    while (walk.next()) |part| {
        if (std.mem.eql(u8, part, "..")) {
            _ = note(diag, source_name, .{ .query_leaves_the_project = .{
                .rule = try gpa.dupe(u8, rule),
                .text = try gpa.dupe(u8, text),
            } });
            return error.InvalidStyle;
        }
    }
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
            return error.InvalidStyle;
        },
    }
}

const testing = std.testing;

fn faultOf(gpa: std.mem.Allocator, source: [:0]const u8) !std.meta.Tag(Diagnostic.Fault) {
    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    const block = parse(gpa, source, &diag);
    if (block) |*held| {
        var owned = held.*;
        owned.deinit(gpa);
        return error.TestExpectedAFault;
    } else |err| {
        try testing.expectEqual(error.InvalidStyle, err);
    }
    const held = diag orelse return error.TestExpectedADiagnostic;
    return held.fault;
}

fn tagIs(comptime which: std.meta.Tag(Diagnostic.Fault)) std.meta.Tag(Diagnostic.Fault) {
    return which;
}

test "a rule carries one bound, and a second one is refused by name" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{ .style = .{
        \\    .parsers = "TREE_SITTER_PARSERS",
        \\    .grammars = .{ .{ .language = "zig", .extensions = .{ ".zig" } } },
        \\    .rules = .{
        \\        .{ .name = "comment-block", .query = ".chock/style/comment.scm", .max_lines = 10 },
        \\    },
        \\} }
    , null);
    defer block.deinit(gpa);

    try testing.expectEqualStrings("TREE_SITTER_PARSERS", block.parsers);
    try testing.expectEqual(Which.command, block.engine);
    try testing.expectEqual(@as(usize, 1), block.grammars.len);
    try testing.expectEqualStrings("zig", block.grammars[0].language);
    try testing.expectEqualStrings(".zig", block.grammars[0].extensions[0]);
    try testing.expectEqual(@as(usize, 1), block.rules.len);
    try testing.expectEqual(@as(u32, 10), block.rules[0].bound.max_lines);
    try testing.expectEqual(Decision.refuse, block.rules[0].decision);

    try testing.expectEqual(
        tagIs(.two_bounds_on_one_rule),
        try faultOf(gpa,
            \\.{ .style = .{ .rules = .{
            \\    .{ .name = "both", .query = "a.scm", .max_lines = 10, .max_matches = 0 },
            \\} } }
        ),
    );
}

test "a rule with no bound says which three it could have, and a name is never empty" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.no_bound_on_a_rule),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"n\", .query = \"a.scm\" } } } }"),
    );
    try testing.expectEqual(
        tagIs(.rule_has_no_name),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"\", .query = \"a.scm\", .max_matches = 0 } } } }"),
    );
    try testing.expectEqual(
        tagIs(.rule_has_no_query),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"n\", .max_matches = 0 } } } }"),
    );
}

test "a share is a percentage, and a line bound of zero is refused as the wrong rule" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.share_is_not_a_percentage),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"s\", .query = \"a.scm\", .max_share = 101 } } } }"),
    );
    // A match covers one line at least, so no file could satisfy this.
    try testing.expectEqual(
        tagIs(.lines_bound_is_zero),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"l\", .query = \"a.scm\", .max_lines = 0 } } } }"),
    );
    // Zero matches is a rule, and it is spelled max_matches.
    var block = try parse(gpa,
        \\.{ .style = .{ .rules = .{
        \\    .{ .name = "none", .query = "a.scm", .max_matches = 0 },
        \\} } }
    , null);
    defer block.deinit(gpa);
    try testing.expectEqual(@as(u32, 0), block.rules[0].bound.max_matches);
}

test "a query path stays under the project" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.query_leaves_the_project),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"q\", .query = \"../out.scm\", .max_matches = 0 } } } }"),
    );
    try testing.expectEqual(
        tagIs(.query_not_relative),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"q\", .query = \"/etc/out.scm\", .max_matches = 0 } } } }"),
    );
}

test "a grammar names a language and at least one extension" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.grammar_has_no_extension),
        try faultOf(gpa, ".{ .style = .{ .grammars = .{ .{ .language = \"zig\", .extensions = .{} } } } }"),
    );
    // A language becomes a file name under the parsers directory.
    try testing.expectEqual(
        tagIs(.language_not_a_name),
        try faultOf(gpa, ".{ .style = .{ .grammars = .{ .{ .language = \"../zig\", .extensions = .{ \".zig\" } } } } }"),
    );
    try testing.expectEqual(
        tagIs(.extension_not_an_extension),
        try faultOf(gpa, ".{ .style = .{ .grammars = .{ .{ .language = \"zig\", .extensions = .{ \"zig\" } } } } }"),
    );
}

test "parsers names a variable, because a store path would go stale" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.parsers_not_a_variable),
        try faultOf(gpa, ".{ .style = .{ .parsers = \"/nix/store/aaa-tree-sitter-zig\" } }"),
    );
}

test "the engine is one of the two this harness has" {
    const gpa = testing.allocator;

    var block = try parse(gpa, ".{ .style = .{ .engine = \"wasm\" } }", null);
    defer block.deinit(gpa);
    try testing.expectEqual(Which.wasm, block.engine);

    try testing.expectEqual(
        tagIs(.engine_unknown),
        try faultOf(gpa, ".{ .style = .{ .engine = \"tree-sitter\" } }"),
    );
}

test "no style block at all is a block with no rule, and never a fault" {
    const gpa = testing.allocator;

    var none = try parse(gpa, ".{ .skills = .{} }", null);
    defer none.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), none.rules.len);
    try testing.expectEqual(@as(usize, 0), none.grammars.len);

    var empty = try parse(gpa, ".{ .style = .{} }", null);
    defer empty.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), empty.rules.len);
}

test "a file reaches the language whose extension it carries, and no other" {
    const gpa = testing.allocator;

    var block = try parse(gpa,
        \\.{ .style = .{ .grammars = .{
        \\    .{ .language = "zig", .extensions = .{ ".zig" } },
        \\    .{ .language = "python", .extensions = .{ ".py", ".pyi" } },
        \\} } }
    , null);
    defer block.deinit(gpa);

    try testing.expectEqualStrings("zig", block.languageFor("src/main.zig").?);
    try testing.expectEqualStrings("python", block.languageFor("tool.pyi").?);
    try testing.expectEqual(@as(?[]const u8, null), block.languageFor("notes.md"));
    try testing.expectEqual(@as(?[]const u8, null), block.languageFor("Makefile"));
}

test "a field the block does not have is named rather than ignored" {
    const gpa = testing.allocator;

    try testing.expectEqual(
        tagIs(.unknown_field),
        try faultOf(gpa, ".{ .style = .{ .parser = \"TS\" } }"),
    );
    try testing.expectEqual(
        tagIs(.unknown_field),
        try faultOf(gpa, ".{ .style = .{ .rules = .{ .{ .name = \"n\", .query = \"a.scm\", .max_match = 0 } } } }"),
    );
}

test "a diagnostic says what is wrong in a sentence" {
    const gpa = testing.allocator;

    var diag: ?Diagnostic = null;
    defer if (diag) |*one| one.deinit(gpa);
    try testing.expectError(error.InvalidStyle, parse(gpa,
        \\.{ .style = .{ .rules = .{
        \\    .{ .name = "comment-block", .query = "a.scm", .max_lines = 10, .max_share = 40 },
        \\} } }
    , &diag));

    const said = try std.fmt.allocPrint(gpa, "{f}", .{&diag.?});
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "comment-block") != null);
    try testing.expect(std.mem.indexOf(u8, said, "max_share") != null);
    try testing.expect(std.mem.indexOf(u8, said, "two rules") != null);
}
