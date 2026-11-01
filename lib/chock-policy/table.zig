//! The policy table. A key has four parts, the agent kind, the model, the tool
//! and the action, and the answer is the most specific rule that matches.

const std = @import("std");
const chock_zon = @import("chock-zon");
const defaults = @import("defaults.zig");

pub const file_name = "chock.zon";

/// `chock.zon` sits in the project directory, so a hostile project writes it.
pub const max_file_bytes = 1 << 20;

pub const max_rules = 512;

pub const max_agents = 64;

/// Grows with the cube of the number of names the rules spell out, so
/// `max_rules` and `max_agents` do not bound it on their own.
pub const max_check_work: u64 = 1 << 32;

/// Rank order, least permitting to most. `agent_review` is above `ask`
/// since it lets work through while nobody is awake.
pub const Decision = enum {
    deny,
    agent_then_human,
    ask,
    agent_review,
    allow,

    pub fn rank(self: Decision) u8 {
        return @backingInt(self);
    }

    pub fn needsReview(self: Decision) bool {
        return switch (self) {
            .agent_review, .agent_then_human => true,
            .deny, .ask, .allow => false,
        };
    }

    pub fn needsHuman(self: Decision) bool {
        return switch (self) {
            .ask, .agent_then_human => true,
            .deny, .agent_review, .allow => false,
        };
    }

    pub fn intersect(a: Decision, b: Decision) Decision {
        return if (a.rank() <= b.rank()) a else b;
    }
};

pub const ChainAnswer = struct {
    decision: Decision,
    /// False when no rule matched: `decision` is then the `ask` default.
    named: bool,
};

pub const Key = struct {
    agent_kind: []const u8,
    model: []const u8,
    tool: []const u8,
    action: []const u8,
};

/// Each key field is a pattern; an absent one matches every value, and
/// `git.*` names `git.push` and not `git` itself. The most specific rule
/// wins, compared action, tool, model, agent kind in that order.
pub const Rule = struct {
    agent_kind: ?[]const u8 = null,
    model: ?[]const u8 = null,
    tool: ?[]const u8 = null,
    action: ?[]const u8 = null,
    decision: Decision,
};

pub const Agent = struct {
    kind: []const u8,
    parent: ?[]const u8 = null,
};

pub const Policy = struct {
    agents: []const Agent = &.{},
    rules: []const Rule = &.{},
    net: Net = .{},
};

pub const Net = struct {
    router: Router = .auto,
    /// A background call never asks a person: it is refused, not queued.
    background: Router = .auto,
};

pub const Router = enum {
    auto,
    none,
    filtered,
};

pub const ParseError = error{
    OutOfMemory,
    InvalidPolicy,
    InvalidPattern,
    DuplicateAgent,
    UnknownParent,
    AgentCycle,
    ChildStrongerThanParent,
    TooManyRules,
    TooManyAgents,
    PolicyTooComplex,
};

pub const LoadError = ParseError || error{
    NoPolicyFile,
    PolicyTooLarge,
    ReadFailed,
};

/// The variants that name an agent kind hold a copy of it.
pub const Diagnostic = union(enum) {
    file_not_zon: ZonFailure,
    block_not_valid: ZonFailure,
    not_a_struct_literal,
    read_failed: anyerror,
    too_many_rules: usize,
    too_many_agents: usize,
    pattern_matches_everything: []const u8,
    pattern_malformed: []const u8,
    name_malformed: []const u8,
    duplicate_agent_kind: []const u8,
    unknown_parent: Parent,
    agent_cycle: []const u8,
    child_stronger_than_parent: ChildStronger,
    policy_too_complex: TooComplex,

    /// `arena` backs `diag`'s messages and must outlive it; `deinit` frees both together.
    pub const ZonFailure = struct {
        arena: std.heap.ArenaAllocator,
        diag: std.zon.parse.Diagnostics,
    };

    pub const Parent = struct {
        kind: []const u8,
        parent: []const u8,
    };

    pub const ChildStronger = struct {
        kind: []const u8,
        child_answer: Decision,
        parent_kind: []const u8,
        parent_answer: Decision,
        model: []const u8,
        tool: []const u8,
        action: []const u8,
    };

    pub const TooComplex = struct {
        reads: u64,
        longest_name: u64,
        work: u64,
        rules: u64,
        models: u64,
        tools: u64,
        actions: u64,
        links: u64,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .file_not_zon, .block_not_valid => |*zf| zf.arena.deinit(),
            .duplicate_agent_kind, .agent_cycle => |name| gpa.free(name),
            .unknown_parent => |names| {
                gpa.free(names.kind);
                gpa.free(names.parent);
            },
            .child_stronger_than_parent => |names| {
                gpa.free(names.kind);
                gpa.free(names.parent_kind);
                gpa.free(names.model);
                gpa.free(names.tool);
                gpa.free(names.action);
            },
            else => {},
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .file_not_zon => |*zf| try writer.print(
                "{s} is not valid:\n{f}",
                .{ file_name, zf.diag.fmt(file_name) },
            ),
            .block_not_valid => |*zf| try writer.print(
                "{s}: the policy block is not valid:\n{f}",
                .{ file_name, zf.diag.fmt(file_name) },
            ),
            .not_a_struct_literal => try writer.print(
                "{s}: the file must hold a struct literal",
                .{file_name},
            ),
            .read_failed => |err| try writer.print(
                "reading {s} failed: {s}",
                .{ file_name, @errorName(err) },
            ),
            .too_many_rules => |held| try writer.print(
                "{s}: the policy holds {d} rules, and this reader accepts {d}",
                .{ file_name, held, max_rules },
            ),
            .too_many_agents => |held| try writer.print(
                "{s}: the policy holds {d} agent kinds, and this reader accepts {d}",
                .{ file_name, held, max_agents },
            ),
            .pattern_matches_everything => |field| try writer.print(
                "{s}: the field {s} holds \"*\". Leave the field out to match every value.",
                .{ file_name, field },
            ),
            .pattern_malformed => |field| try writer.print(
                "{s}: the field {s} holds an invalid name. A name matches itself, and a name that ends in \".*\" matches every name below it.",
                .{ file_name, field },
            ),
            .name_malformed => |field| try writer.print(
                "{s}: the field {s} holds an invalid name",
                .{ file_name, field },
            ),
            .duplicate_agent_kind => |kind| try writer.print(
                "{s}: two agents name the kind {s}",
                .{ file_name, kind },
            ),
            .unknown_parent => |names| try writer.print(
                "{s}: the agent {s} names the parent {s}, and no agent declares that kind",
                .{ file_name, names.kind, names.parent },
            ),
            .agent_cycle => |kind| try writer.print(
                "{s}: the parents of the agent {s} make a loop",
                .{ file_name, kind },
            ),
            .child_stronger_than_parent => |names| try writer.print(
                "{s}: the agent {s} holds {t} and its parent {s} holds {t}, for {f}, {f}, and {f}",
                .{
                    file_name,
                    names.kind,
                    names.child_answer,
                    names.parent_kind,
                    names.parent_answer,
                    NameForMessage{ .field = "model", .name = names.model },
                    NameForMessage{ .field = "tool", .name = names.tool },
                    NameForMessage{ .field = "action", .name = names.action },
                },
            ),
            .policy_too_complex => |walk| try writer.print(
                "{s}: to prove that no child holds more than its parent, this reader must read a rule for a key {d} times, over names of up to {d} bytes. " ++
                    "That costs {d} units of work, and this reader accepts {d}. " ++
                    "The rules hold {d} lines, and they tell {d} models, {d} tools, and {d} actions apart, over {d} declared parent link{s}. " ++
                    "Name fewer of them, or give the names fewer bytes.",
                .{
                    file_name,
                    walk.reads,
                    walk.longest_name,
                    walk.work,
                    max_check_work,
                    walk.rules,
                    walk.models,
                    walk.tools,
                    walk.actions,
                    walk.links,
                    plural(walk.links),
                },
            ),
        }
    }
};

pub const ChainFault = union(enum) {
    empty: []const u8,
    link_with_no_name: []const u8,
    last_link_is_not_the_asker: Mismatch,

    pub const Mismatch = struct {
        agent_kind: []const u8,
        last: []const u8,
    };

    pub fn format(self: ChainFault, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self) {
            .empty => |action| try writer.print(
                "a policy question about the action {s} arrived with an empty spawn chain, so the answer is ask",
                .{action},
            ),
            .link_with_no_name => |action| try writer.print(
                "a policy question about the action {s} arrived with a spawn chain that holds a link with no name, so the answer is ask",
                .{action},
            ),
            .last_link_is_not_the_asker => |names| try writer.print(
                "a policy question from the kind {s} arrived with a spawn chain that ends in {s}, so the answer is ask",
                .{ names.agent_kind, names.last },
            ),
        }
    }
};

fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

fn noteChain(out: ?*?ChainFault, value: ChainFault) void {
    const slot = out orelse return;
    if (slot.* != null) return;
    slot.* = value;
}

pub const Table = struct {
    policy: *const Policy,
    /// A layer of its own, never appended to the file's rules: a tie
    /// between two rules of one list goes to the narrower decision, so a
    /// merged `git.push=allow` would lose to a file that denies `git.push`.
    given: []const Rule = &.{},
    org: []const Rule = &.{},
    hash: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    from_file: bool = false,
    /// Backs `policy`'s slices; `destroy` frees it instead of walking the policy by hand.
    arena: std.heap.ArenaAllocator,

    pub const Layers = struct {
        given: []const Rule = &.{},
        org: []const Rule = &.{},
    };

    pub fn parse(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        return parseUnder(gpa, source, &.{}, diag);
    }

    pub fn parseUnder(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        org: []const Rule,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        return parseLayered(gpa, source, .{ .org = org }, diag);
    }

    pub fn parseLayered(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        layers: Layers,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        return parseFrom(gpa, source, layers, false, diag);
    }

    fn parseFrom(
        gpa: std.mem.Allocator,
        source: [:0]const u8,
        layers: Layers,
        from_file: bool,
        diag: ?*?Diagnostic,
    ) ParseError!*const Table {
        var ast = std.zig.Ast.parse(gpa, source, .{ .mode = .zon }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
        };
        defer ast.deinit(gpa);

        // `parse_str_lits = false`: this file reads only field names.
        var zoir = try std.zig.ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
        defer zoir.deinit(gpa);

        // The arena backs the policy's slices and any diagnostics. On
        // success the table keeps it; on a fault handed to the caller,
        // `note` keeps it instead.
        var arena: std.heap.ArenaAllocator = .init(gpa);
        var arena_owned = true;
        defer if (arena_owned) arena.deinit();

        if (zoir.hasCompileErrors()) {
            var zon_diag: std.zon.parse.Diagnostics = undefined;
            _ = std.zon.parse.fromZoir(Policy, .{
                .arena = arena.allocator(),
                .ast = &ast,
                .zoir = &zoir,
                .diagnostics = &zon_diag,
            }) catch {};
            if (note(diag, .{ .file_not_zon = .{ .arena = arena, .diag = zon_diag } })) arena_owned = false;
            return error.InvalidPolicy;
        }

        const policy = policy: {
            const node = try findPolicyNode(zoir, diag) orelse break :policy Policy{};
            var zon_diag: std.zon.parse.Diagnostics = undefined;
            break :policy chock_zon.fromNode(
                Policy,
                gpa,
                arena.allocator(),
                source,
                &ast,
                &zoir,
                node,
                &zon_diag,
                .{},
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.ParseZon => {
                    if (note(diag, .{ .block_not_valid = .{ .arena = arena, .diag = zon_diag } })) arena_owned = false;
                    return error.InvalidPolicy;
                },
            };
        };

        try validate(gpa, policy, diag);

        const owned = try gpa.create(Policy);
        errdefer gpa.destroy(owned);
        owned.* = policy;

        const table = try gpa.create(Table);
        table.* = .{
            .policy = owned,
            .given = layers.given,
            .org = layers.org,
            .hash = hashSource(source),
            .from_file = from_file,
            .arena = arena,
        };
        arena_owned = false;
        return table;
    }

    pub fn load(
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        diag: ?*?Diagnostic,
    ) LoadError!*const Table {
        return loadUnder(gpa, io, project_root, &.{}, diag);
    }

    pub fn loadUnder(
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        org: []const Rule,
        diag: ?*?Diagnostic,
    ) LoadError!*const Table {
        return loadLayered(gpa, io, project_root, .{ .org = org }, diag);
    }

    pub fn loadLayered(
        gpa: std.mem.Allocator,
        io: std.Io,
        project_root: []const u8,
        layers: Layers,
        diag: ?*?Diagnostic,
    ) LoadError!*const Table {
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
            error.StreamTooLong => return error.PolicyTooLarge,
            error.FileNotFound, error.NotDir => return error.NoPolicyFile,
            else => {
                _ = note(diag, .{ .read_failed = err });
                return error.ReadFailed;
            },
        };
        defer gpa.free(source);

        return parseFrom(gpa, source, layers, true, diag);
    }

    pub fn destroy(gpa: std.mem.Allocator, self: *const Table) void {
        self.arena.deinit();
        gpa.destroy(self.policy);
        gpa.destroy(self);
    }

    pub fn evaluateKindAlone(self: *const Table, key: Key) Decision {
        return self.ownAnswer(key).decision.intersect(ceilingRules(self.org, key));
    }

    fn ownAnswer(self: *const Table, key: Key) ChainAnswer {
        if (winnerFor(self.given, key)) |winner| {
            return .{ .decision = winner.decision, .named = true };
        }
        return rulesAnswer(self.policy.rules, key);
    }

    fn ownCeiling(self: *const Table, key: Key) Decision {
        if (winnerFor(self.given, key)) |winner| return winner.decision;
        return ceilingRules(self.policy.rules, key);
    }

    /// `chain` names every agent kind from the root of the spawn tree down
    /// to the agent that asked, root first.
    pub fn evaluateChain(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        fault: ?*?ChainFault,
    ) Decision {
        return self.decideChain(chain, key, fault).decision;
    }

    pub fn decideChain(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        fault: ?*?ChainFault,
    ) ChainAnswer {
        if (chain.len == 0) {
            noteChain(fault, .{ .empty = key.action });
            return .{ .decision = .ask, .named = false };
        }
        for (chain) |kind| {
            if (kind.len > 0) continue;
            noteChain(fault, .{ .link_with_no_name = key.action });
            return .{ .decision = .ask, .named = false };
        }
        const last = chain[chain.len - 1];
        if (!std.mem.eql(u8, last, key.agent_kind)) {
            noteChain(fault, .{ .last_link_is_not_the_asker = .{
                .agent_kind = key.agent_kind,
                .last = last,
            } });
            return .{ .decision = .ask, .named = false };
        }

        var answer = self.linkAnswer(keyForKind(key, chain[0]));
        for (chain[1..]) |kind| {
            const link = self.linkAnswer(keyForKind(key, kind));
            answer = .{
                .decision = answer.decision.intersect(link.decision),
                .named = answer.named or link.named,
            };
        }
        return answer;
    }

    /// An org rule counts as naming the key, or a wider name could be read
    /// past it.
    fn linkAnswer(self: *const Table, link: Key) ChainAnswer {
        const own = self.ownAnswer(link);
        const ceiling = winnerFor(self.org, link);
        return .{
            .decision = own.decision.intersect(if (ceiling) |one| one.decision else .allow),
            .named = own.named or ceiling != null,
        };
    }

    /// `.auto` reads the rules, not the defaults.
    pub fn wantsRouter(self: *const Table) bool {
        return switch (self.policy.net.router) {
            .none => false,
            .filtered => true,
            .auto => rulesPermitBelow(self.policy.rules, "net") or
                rulesPermitBelow(self.given, "net"),
        };
    }

    pub fn wantsBackgroundRouter(self: *const Table) bool {
        if (!self.wantsRouter()) return false;
        return switch (self.policy.net.background) {
            .none => false,
            .filtered => true,
            .auto => true,
        };
    }

    /// The ports a project published, which are the ones a rule names one by one
    /// and answers `allow` for. A pattern such as `net.serve.*` publishes
    /// nothing: a listener is opened on the host for each of these, so the port
    /// has to be a number somebody wrote, not every port a pattern could match.
    ///
    /// Each candidate goes back through the ordinary answer, so a `deny` further
    /// in, or an org ceiling, still decides.
    pub fn servedPorts(self: *const Table, key: Key, into: []u16) []const u16 {
        var count: usize = 0;
        for ([_][]const Rule{ self.given, self.policy.rules }) |rules| {
            for (rules) |rule| {
                if (count == into.len) break;
                const action = rule.action orelse continue;
                const port = portNamedBy(action) orelse continue;
                if (!patternMatches(rule.tool, key.tool)) continue;
                if (!patternMatches(rule.model, key.model)) continue;
                if (!patternMatches(rule.agent_kind, key.agent_kind)) continue;

                var held = false;
                for (into[0..count]) |one| {
                    if (one == port) held = true;
                }
                if (held) continue;

                var asked = key;
                asked.action = action;
                if (self.evaluateKindAlone(asked) != .allow) continue;
                into[count] = port;
                count += 1;
            }
        }
        return into[0..count];
    }

    /// The finite domain subtrees a provider-side search may read. Provider
    /// allowlists include subdomains, so a literal host permission is not
    /// enough: the policy must allow both the domain itself and its whole
    /// subtree, with no narrower refusal in any effective layer.
    pub fn allowedFetchDomains(
        self: *const Table,
        allocator: std.mem.Allocator,
        chain: []const []const u8,
        key: Key,
        limit: usize,
    ) std.mem.Allocator.Error![]const []const u8 {
        var domains: std.ArrayList([]const u8) = .empty;
        errdefer domains.deinit(allocator);

        for ([_][]const Rule{ self.given, self.policy.rules }) |rules| {
            for (rules) |rule| {
                if (domains.items.len == limit) return domains.toOwnedSlice(allocator);
                if (!ruleAppliesOutsideAction(rule, key)) continue;
                const action = rule.action orelse continue;
                const base = fetchDomainAction(action) orelse continue;

                const domain = (try domainFromFetchAction(allocator, base)) orelse continue;
                defer if (domain.len != 0) allocator.free(domain);

                var held = false;
                for (domains.items) |existing| {
                    if (std.mem.eql(u8, existing, domain)) held = true;
                }
                if (held) continue;

                var asked = key;
                asked.action = base;
                if (self.evaluateChain(chain, asked, null) != .allow) continue;

                const probe = try std.fmt.allocPrint(allocator, "{s}.__chock_provider_probe", .{base});
                defer allocator.free(probe);
                asked.action = probe;
                if (self.evaluateChain(chain, asked, null) != .allow) continue;
                if (self.fetchSubtreeHasRefusal(chain, key, base)) continue;

                // Provider domain filters are DNS domains, not single labels,
                // IP literals, or local host names.
                if (std.mem.indexOfScalar(u8, domain, '.') == null) continue;
                try domains.append(allocator, try allocator.dupe(u8, domain));
            }
        }
        return domains.toOwnedSlice(allocator);
    }

    fn fetchSubtreeHasRefusal(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        base: []const u8,
    ) bool {
        for ([_][]const Rule{ self.given, self.policy.rules, self.org }) |rules| {
            for (rules) |rule| {
                if (rule.decision == .allow) continue;
                const action = rule.action orelse continue;
                if (action.len <= base.len or
                    !std.mem.startsWith(u8, action, base) or
                    action[base.len] != '.') continue;
                for (chain) |kind| {
                    var link = key;
                    link.agent_kind = kind;
                    if (ruleAppliesOutsideAction(rule, link)) return true;
                }
            }
        }
        return false;
    }

    /// An existence question: no caller may read a `true` here as a
    /// permission. A `deny` rule is skipped, or a refusal would resolve a host.
    pub fn permitsSomethingUnder(self: *const Table, key: Key) bool {
        return rulesReachBelow(self.given, key) or
            rulesReachBelow(self.policy.rules, key) or
            rulesReachBelow(defaults.rules, key);
    }

    /// For a resource rather than an act: a resource nobody named answers
    /// `allow`, and `fault` answers `deny`.
    pub fn ceilingChain(
        self: *const Table,
        chain: []const []const u8,
        key: Key,
        fault: ?*?ChainFault,
    ) Decision {
        if (chain.len == 0) {
            noteChain(fault, .{ .empty = key.action });
            return .deny;
        }
        for (chain) |kind| {
            if (kind.len > 0) continue;
            noteChain(fault, .{ .link_with_no_name = key.action });
            return .deny;
        }
        const last = chain[chain.len - 1];
        if (!std.mem.eql(u8, last, key.agent_kind)) {
            noteChain(fault, .{ .last_link_is_not_the_asker = .{
                .agent_kind = key.agent_kind,
                .last = last,
            } });
            return .deny;
        }

        var result: Decision = .allow;
        for (chain) |kind| {
            const link = keyForKind(key, kind);
            result = result
                .intersect(self.ownCeiling(link))
                .intersect(ceilingRules(self.org, link));
        }
        return result;
    }

    pub fn sourceHash(self: *const Table) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
        return self.hash;
    }

    pub fn hasFile(self: *const Table) bool {
        return self.from_file;
    }
};

fn keyForKind(key: Key, agent_kind: []const u8) Key {
    return .{
        .agent_kind = agent_kind,
        .model = key.model,
        .tool = key.tool,
        .action = key.action,
    };
}

// A change to `chock.zon` cannot change a running session's policy.
comptime {
    const pointer = @typeInfo(@FieldType(Table, "policy")).pointer;
    if (!pointer.attrs.@"const") @compileError(
        "Table.policy must point to const, or a caller could rewrite a rule of a live session",
    );

    refuseMutableTable(Table, "Table.");
    refuseMutableTable(@This(), "");
}

fn refuseMutableTable(comptime namespace: type, comptime prefix: []const u8) void {
    for (@typeInfo(namespace).@"struct".decl_names) |decl| {
        const info = switch (@typeInfo(@TypeOf(@field(namespace, decl)))) {
            .@"fn" => |function| function,
            else => continue,
        };
        for (info.param_types) |param| {
            const kind = param orelse continue;
            const pointer = switch (@typeInfo(kind)) {
                .pointer => |pointer| pointer,
                else => continue,
            };
            if (pointer.child != Table or pointer.attrs.@"const") continue;
            @compileError(prefix ++ decl ++
                " takes a mutable *Table, and no function may do that");
        }
    }
}

/// A project rule that matches `key` at all wins, whatever it names.
/// `defaults.zig`'s rules are read only when `rules` holds no match: the
/// two lists are not one search.
fn evaluateRules(rules: []const Rule, key: Key) Decision {
    return rulesAnswer(rules, key).decision;
}

fn rulesAnswer(rules: []const Rule, key: Key) ChainAnswer {
    if (winnerFor(rules, key)) |winner| return .{ .decision = winner.decision, .named = true };
    if (winnerFor(defaults.rules, key)) |winner| {
        return .{ .decision = winner.decision, .named = true };
    }
    return .{ .decision = .ask, .named = false };
}

/// `evaluateRules` as a ceiling: a key no rule names answers `allow`.
fn ceilingRules(rules: []const Rule, key: Key) Decision {
    const answer = winnerFor(rules, key) orelse return .allow;
    return answer.decision;
}

fn winnerFor(rules: []const Rule, key: Key) ?Rule {
    std.debug.assert(key.agent_kind.len > 0);
    std.debug.assert(key.model.len > 0);
    std.debug.assert(key.tool.len > 0);
    std.debug.assert(key.action.len > 0);

    var winner: ?Rule = null;
    for (rules) |rule| {
        if (!ruleMatches(rule, key)) continue;
        const best = winner orelse {
            winner = rule;
            continue;
        };
        if (ruleBeats(rule, best)) winner = rule;
    }
    return winner;
}

pub const serve_action_prefix = "net.serve";

pub const max_serve_action_bytes: usize = serve_action_prefix.len + 1 + 5;

/// The action one port is answered under. The parser below reads this back, and
/// a test holds the two together.
pub fn serveActionInto(buffer: []u8, port: u16) ?[]const u8 {
    if (port == 0) return null;
    return std.fmt.bufPrint(buffer, serve_action_prefix ++ ".{d}", .{port}) catch null;
}

/// The port a `net.serve.3000` rule names, or null for anything else, a pattern
/// included. Nothing but digits is read: `net.serve.3000.extra` names no port.
pub fn portNamedBy(action: []const u8) ?u16 {
    if (!std.mem.startsWith(u8, action, serve_action_prefix ++ ".")) return null;
    const tail = action[serve_action_prefix.len + 1 ..];
    if (tail.len == 0) return null;
    for (tail) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
    }
    const port = std.fmt.parseInt(u16, tail, 10) catch return null;
    if (port == 0) return null;
    return port;
}

fn rulesPermitBelow(rules: []const Rule, prefix: []const u8) bool {
    std.debug.assert(prefix.len > 0);
    for (rules) |rule| {
        if (rule.decision == .deny) continue;
        if (!actionReachesBelow(rule.action, prefix)) continue;
        return true;
    }
    return false;
}

fn rulesReachBelow(rules: []const Rule, key: Key) bool {
    std.debug.assert(key.action.len > 0);
    for (rules) |rule| {
        if (rule.decision == .deny) continue;
        if (!patternMatches(rule.tool, key.tool)) continue;
        if (!patternMatches(rule.model, key.model)) continue;
        if (!patternMatches(rule.agent_kind, key.agent_kind)) continue;
        if (!actionReachesBelow(rule.action, key.action)) continue;
        return true;
    }
    return false;
}

fn actionReachesBelow(pattern: ?[]const u8, prefix: []const u8) bool {
    const text = pattern orelse return true;
    if (patternMatches(text, prefix)) return true;
    // A class never matches its own prefix, yet it does permit below it.
    const body = classPrefix(text) orelse text;
    return std.mem.startsWith(u8, body, prefix) and
        (body.len == prefix.len or body[prefix.len] == '.');
}

fn ruleMatches(rule: Rule, key: Key) bool {
    return patternMatches(rule.action, key.action) and
        patternMatches(rule.tool, key.tool) and
        patternMatches(rule.model, key.model) and
        patternMatches(rule.agent_kind, key.agent_kind);
}

fn ruleAppliesOutsideAction(rule: Rule, key: Key) bool {
    return patternMatches(rule.tool, key.tool) and
        patternMatches(rule.model, key.model) and
        patternMatches(rule.agent_kind, key.agent_kind);
}

const fetch_action_prefix = "net.fetch.";

fn fetchDomainAction(action: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, action, fetch_action_prefix)) return null;
    var base = action;
    if (std.mem.endsWith(u8, base, ".*")) base = base[0 .. base.len - 2];
    if (base.len == fetch_action_prefix.len or
        std.mem.eql(u8, base[fetch_action_prefix.len..], "*")) return null;
    return base;
}

fn domainFromFetchAction(
    allocator: std.mem.Allocator,
    action: []const u8,
) std.mem.Allocator.Error!?[]u8 {
    const reversed = action[fetch_action_prefix.len..];
    if (reversed.len == 0) return null;
    const domain = try allocator.alloc(u8, reversed.len);
    errdefer allocator.free(domain);

    var written: usize = 0;
    var end = reversed.len;
    while (end != 0) {
        const before = std.mem.lastIndexOfScalar(u8, reversed[0..end], '.') orelse 0;
        const start = if (before == 0) 0 else before + 1;
        const label = reversed[start..end];
        if (written != 0) {
            domain[written] = '.';
            written += 1;
        }
        for (label) |byte| {
            domain[written] = std.ascii.toLower(byte);
            written += 1;
        }
        if (start == 0) break;
        end = before;
    }
    std.debug.assert(written == domain.len);
    return domain;
}

fn ruleBeats(candidate: Rule, best: Rule) bool {
    inline for (.{ "action", "tool", "model", "agent_kind" }) |field| {
        const left = patternScore(@field(candidate, field));
        const right = patternScore(@field(best, field));
        if (left != right) return left > right;
    }
    return candidate.decision.rank() < best.decision.rank();
}

fn classPrefix(pattern: []const u8) ?[]const u8 {
    if (!std.mem.endsWith(u8, pattern, ".*")) return null;
    return pattern[0 .. pattern.len - 2];
}

pub fn patternMatches(pattern: ?[]const u8, value: []const u8) bool {
    const text = pattern orelse return true;
    const prefix = classPrefix(text) orelse return std.mem.eql(u8, text, value);
    // `git.*` matches `git.push`, and it does not match `git` itself.
    return value.len > prefix.len + 1 and
        std.mem.startsWith(u8, value, prefix) and
        value[prefix.len] == '.';
}

pub fn patternCovers(outer: []const u8, inner: []const u8) bool {
    const outer_prefix = classPrefix(outer) orelse return std.mem.eql(u8, outer, inner);
    const inner_prefix = classPrefix(inner) orelse return patternMatches(outer, inner);
    if (std.mem.eql(u8, outer_prefix, inner_prefix)) return true;
    // `git.*` covers `git.branch.*`, and it does not cover `gitlab.*`.
    return inner_prefix.len > outer_prefix.len + 1 and
        std.mem.startsWith(u8, inner_prefix, outer_prefix) and
        inner_prefix[outer_prefix.len] == '.';
}

pub fn patternIsWellFormed(pattern: []const u8) bool {
    if (std.mem.eql(u8, pattern, "*")) return false;
    const body = classPrefix(pattern) orelse pattern;
    return body.len != 0 and
        std.mem.indexOfScalar(u8, body, '*') == null and
        std.mem.indexOfScalar(u8, body, 0) == null;
}

pub const max_label_bytes = 64;

/// No dot: a label holding one could name a class of actions never wrote.
pub fn labelIsUsable(bytes: []const u8) bool {
    if (bytes.len == 0 or bytes.len > max_label_bytes) return false;
    for (bytes) |byte| {
        const ok = (byte >= 'a' and byte <= 'z') or
            (byte >= 'A' and byte <= 'Z') or
            (byte >= '0' and byte <= '9') or
            byte == '-' or byte == '_';
        if (!ok) return false;
    }
    return true;
}

/// Writes `.<label>` for every label of `host`, the last label first, into
/// `buffer` after `written` bytes. So a rule about a domain is a prefix of a
/// rule about every name under it, and `net.fetch.com.example.*` reads as one.
/// Null is a host this does not put in an action name, and the caller then has
/// no key rather than a key that means something else.
pub fn hostIntoReversed(buffer: []u8, written: usize, host: []const u8) ?usize {
    var at = written;
    var end = host.len;
    while (end > 0) {
        const start = if (std.mem.lastIndexOfScalar(u8, host[0..end], '.')) |dot| dot + 1 else 0;
        const label = host[start..end];
        if (!labelIsUsable(label)) return null;
        if (at + 1 + label.len > buffer.len) return null;
        buffer[at] = '.';
        at += 1;
        for (label, buffer[at..][0..label.len]) |from, *to| to.* = std.ascii.toLower(from);
        at += label.len;
        end = if (start == 0) 0 else start - 1;
    }
    return at;
}

const exact_score: u64 = 1 << 32;

fn patternScore(pattern: ?[]const u8) u64 {
    const text = pattern orelse return 0;
    const prefix = classPrefix(text) orelse return exact_score;
    return segmentCount(prefix);
}

fn segmentCount(name: []const u8) u64 {
    return std.mem.count(u8, name, ".") + 1;
}

pub const GivenRuleError = error{
    NoEquals,
    ActionEmpty,
    ActionMalformed,
    DecisionUnknown,
};

pub fn givenRuleReason(reason: GivenRuleError) []const u8 {
    return switch (reason) {
        error.NoEquals => "holds no =, and a rule is written <action>=<decision>",
        error.ActionEmpty => "names no action before the =",
        error.ActionMalformed => "names an action a rule cannot carry. A * is allowed as the last part alone, as in net.fetch.*",
        error.DecisionUnknown => "names no decision this build knows. Write deny, ask, allow, agent_review or agent_then_human",
    };
}

/// The action is borrowed from `text`. Only the action and the decision: a
/// rule that narrows by the tool, model or agent kind belongs in a file.
pub fn parseGivenRule(text: []const u8) GivenRuleError!Rule {
    const split = std.mem.lastIndexOfScalar(u8, text, '=') orelse return error.NoEquals;
    const action = text[0..split];
    const decision = text[split + 1 ..];

    if (action.len == 0) return error.ActionEmpty;
    if (!patternIsWellFormed(action)) return error.ActionMalformed;

    inline for (@typeInfo(Decision).@"enum".field_names, @typeInfo(Decision).@"enum".field_values) |field_name, _| {
        if (std.mem.eql(u8, decision, field_name)) {
            return .{ .action = action, .decision = @field(Decision, field_name) };
        }
    }
    return error.DecisionUnknown;
}

pub fn hashSource(source: []const u8) [std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &out, .{});
    return out;
}

fn findPolicyNode(zoir: std.zig.Zoir, diag: ?*?Diagnostic) ParseError!?std.zig.Zoir.Node.Index {
    const root: std.zig.Zoir.Node.Index = .root;
    switch (root.get(&zoir)) {
        .struct_literal => |fields| {
            for (fields.names, 0..) |name, index| {
                if (std.mem.eql(u8, name.get(&zoir), "policy")) {
                    return fields.vals.at(@intCast(index));
                }
            }
            return null;
        },
        .empty_literal => return null,
        else => {
            _ = note(diag, .not_a_struct_literal);
            return error.InvalidPolicy;
        },
    }
}

fn validate(gpa: std.mem.Allocator, policy: Policy, diag: ?*?Diagnostic) ParseError!void {
    if (policy.rules.len > max_rules) {
        _ = note(diag, .{ .too_many_rules = policy.rules.len });
        return error.TooManyRules;
    }
    if (policy.agents.len > max_agents) {
        _ = note(diag, .{ .too_many_agents = policy.agents.len });
        return error.TooManyAgents;
    }

    for (policy.rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            try validatePattern(field, @field(rule, field), diag);
        }
    }

    for (policy.agents, 0..) |agent, index| {
        try validateName("kind", agent.kind, diag);
        for (policy.agents[index + 1 ..]) |other| {
            if (!std.mem.eql(u8, agent.kind, other.kind)) continue;
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .duplicate_agent_kind = try gpa.dupe(u8, agent.kind) });
            }
            return error.DuplicateAgent;
        }

        const parent = agent.parent orelse continue;
        try validateName("parent", parent, diag);
        if (findAgent(policy.agents, parent) == null) {
            if (wantsDiagnostic(diag)) {
                const kind_copy = try gpa.dupe(u8, agent.kind);
                errdefer gpa.free(kind_copy);
                const parent_copy = try gpa.dupe(u8, parent);
                _ = note(diag, .{ .unknown_parent = .{ .kind = kind_copy, .parent = parent_copy } });
            }
            return error.UnknownParent;
        }
    }

    try checkNoCycle(gpa, policy.agents, diag);
    try checkChildrenAreWeaker(gpa, policy, diag);
}

fn findAgent(agents: []const Agent, kind: []const u8) ?Agent {
    for (agents) |agent| {
        if (std.mem.eql(u8, agent.kind, kind)) return agent;
    }
    return null;
}

fn validatePattern(field: []const u8, pattern: ?[]const u8, diag: ?*?Diagnostic) ParseError!void {
    const text = pattern orelse return;
    if (std.mem.eql(u8, text, "*")) {
        _ = note(diag, .{ .pattern_matches_everything = field });
        return error.InvalidPattern;
    }
    if (!patternIsWellFormed(text)) {
        _ = note(diag, .{ .pattern_malformed = field });
        return error.InvalidPattern;
    }
}

fn validateName(field: []const u8, name: []const u8, diag: ?*?Diagnostic) ParseError!void {
    if (name.len > 0 and
        std.mem.indexOfScalar(u8, name, '*') == null and
        std.mem.indexOfScalar(u8, name, 0) == null) return;
    _ = note(diag, .{ .name_malformed = field });
    return error.InvalidPattern;
}

fn checkNoCycle(gpa: std.mem.Allocator, agents: []const Agent, diag: ?*?Diagnostic) ParseError!void {
    for (agents) |start| {
        var current = start;
        var steps: usize = 0;
        while (current.parent) |parent| {
            steps += 1;
            if (steps > agents.len) {
                if (wantsDiagnostic(diag)) {
                    _ = note(diag, .{ .agent_cycle = try gpa.dupe(u8, start.kind) });
                }
                return error.AgentCycle;
            }
            current = findAgent(agents, parent) orelse return error.UnknownParent;
        }
    }
}

/// `checkWorkFitsBudget` counts the walk before it starts.
fn checkChildrenAreWeaker(gpa: std.mem.Allocator, policy: Policy, diag: ?*?Diagnostic) ParseError!void {
    if (policy.agents.len == 0) return;

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const models = try representatives(arena, policy.rules, "model");
    const tools = try representatives(arena, policy.rules, "tool");
    const actions = try representatives(arena, policy.rules, "action");

    var links: usize = 0;
    for (policy.agents) |agent| {
        if (agent.parent != null) links += 1;
    }
    if (links == 0) return;
    try checkWorkFitsBudget(.{
        .models = models.len,
        .tools = tools.len,
        .actions = actions.len,
        .links = links,
        .rules = policy.rules.len,
        .longest_name = @max(longestPattern(policy.rules), longestPattern(defaults.rules)),
    }, diag);

    for (policy.agents) |agent| {
        const parent_kind = agent.parent orelse continue;
        for (models) |model| for (tools) |tool| for (actions) |action| {
            const child_answer = evaluateRules(policy.rules, .{
                .agent_kind = agent.kind,
                .model = model,
                .tool = tool,
                .action = action,
            });
            const parent_answer = evaluateRules(policy.rules, .{
                .agent_kind = parent_kind,
                .model = model,
                .tool = tool,
                .action = action,
            });
            if (child_answer.rank() <= parent_answer.rank()) continue;

            if (wantsDiagnostic(diag)) {
                var owned: Diagnostic = .{ .child_stronger_than_parent = .{
                    .kind = "",
                    .child_answer = child_answer,
                    .parent_kind = "",
                    .parent_answer = parent_answer,
                    .model = "",
                    .tool = "",
                    .action = "",
                } };
                errdefer owned.deinit(gpa);
                const names = &owned.child_stronger_than_parent;
                names.kind = try gpa.dupe(u8, agent.kind);
                names.parent_kind = try gpa.dupe(u8, parent_kind);
                names.model = try gpa.dupe(u8, model);
                names.tool = try gpa.dupe(u8, tool);
                names.action = try gpa.dupe(u8, action);
                _ = note(diag, owned);
            }
            return error.ChildStrongerThanParent;
        };
    }
}

const shortest_billed_name = 64;

const Walk = struct {
    models: u64,
    tools: u64,
    actions: u64,
    links: u64,
    /// The file's own count, never the sum with `defaults.rules.len`.
    rules: u64,
    longest_name: u64,
};

/// Saturates: the product of six numbers a file controls overflows a register.
fn checkWorkFitsBudget(walk: Walk, diag: ?*?Diagnostic) ParseError!void {
    const name_cost = @max(walk.longest_name, shortest_billed_name);
    const keys = walk.models *| walk.tools *| walk.actions *| walk.links;
    const rules_per_key = walk.rules +| @as(u64, defaults.rules.len);
    const reads = keys *| rules_per_key *| 2;
    const work = reads *| name_cost;
    if (work <= max_check_work) return;

    _ = note(diag, .{ .policy_too_complex = .{
        .reads = reads,
        .longest_name = walk.longest_name,
        .work = work,
        .rules = walk.rules,
        .models = walk.models,
        .tools = walk.tools,
        .actions = walk.actions,
        .links = walk.links,
    } });
    return error.PolicyTooComplex;
}

fn plural(count: u64) []const u8 {
    return if (count == 1) "" else "s";
}

fn longestPattern(rules: []const Rule) usize {
    var longest: usize = 0;
    for (rules) |rule| {
        inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
            if (@field(rule, field)) |pattern| longest = @max(longest, pattern.len);
        }
    }
    return longest;
}

/// `validatePattern` and `validateName` refuse a name holding this byte.
const fresh_marker = "\x00";

/// The shipped defaults must be sampled too, or a walk over the file's own
/// classes alone would miss what `evaluateRules` falls back to.
fn representatives(
    arena: std.mem.Allocator,
    rules: []const Rule,
    comptime field: []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    try list.ensureTotalCapacity(arena, rules.len + defaults.rules.len + 1);
    list.appendAssumeCapacity(fresh_marker);

    try appendRepresentatives(arena, &list, rules, field);
    try appendRepresentatives(arena, &list, defaults.rules, field);
    return list.items;
}

fn appendRepresentatives(
    arena: std.mem.Allocator,
    list: *std.ArrayList([]const u8),
    rules: []const Rule,
    comptime field: []const u8,
) std.mem.Allocator.Error!void {
    for (rules) |rule| {
        const pattern = @field(rule, field) orelse continue;
        const name = if (classPrefix(pattern)) |prefix|
            try std.fmt.allocPrint(arena, "{s}.{s}", .{ prefix, fresh_marker })
        else
            pattern;
        if (holdsName(list.items, name)) continue;
        list.appendAssumeCapacity(name);
    }
}

fn holdsName(names: []const []const u8, name: []const u8) bool {
    for (names) |held| {
        if (std.mem.eql(u8, held, name)) return true;
    }
    return false;
}

const NameForMessage = struct {
    field: []const u8,
    name: []const u8,

    pub fn format(self: NameForMessage, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (std.mem.eql(u8, self.name, fresh_marker)) {
            return writer.print("any {s}", .{self.field});
        }
        try writer.print("the {s} ", .{self.field});
        for (self.name) |byte| try writer.writeByte(if (byte == 0) '*' else byte);
    }
};

fn testKey(agent_kind: []const u8, action: []const u8) Key {
    return .{
        .agent_kind = agent_kind,
        .model = "test-model",
        .tool = "git",
        .action = action,
    };
}

fn absoluteDirPath(buffer: []u8, dir: std.Io.Dir) ![]u8 {
    const len = dir.realPath(std.testing.io, buffer) catch return error.RealPathFailed;
    return buffer[0..len];
}

fn repeatedSource(
    gpa: std.mem.Allocator,
    head: []const u8,
    item: []const u8,
    count: usize,
    tail: []const u8,
) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.appendSlice(gpa, head);
    for (0..count) |index| {
        var digits: [24]u8 = undefined;
        const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
        for (item) |byte| {
            if (byte == '#') {
                try out.appendSlice(gpa, number);
            } else {
                try out.append(gpa, byte);
            }
        }
    }
    try out.appendSlice(gpa, tail);
    return out.toOwnedSliceSentinel(gpa, 0);
}

fn wideSource(gpa: std.mem.Allocator, rules: usize, name_bytes: usize) ![:0]u8 {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.appendSlice(gpa, ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, " ++
        ".{ .kind = \"c\", .parent = \"p\" } }, .rules = .{");
    for (0..rules) |index| {
        var digits: [24]u8 = undefined;
        const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
        try out.appendSlice(gpa, " .{");
        inline for (.{ "model", "tool", "action" }) |field| {
            try out.appendSlice(gpa, " ." ++ field ++ " = \"");
            try out.appendNTimes(gpa, 'x', name_bytes - number.len);
            try out.appendSlice(gpa, number);
            try out.appendSlice(gpa, "\",");
        }
        try out.appendSlice(gpa, " .decision = .deny },");
    }
    try out.appendSlice(gpa, " } } }");
    return out.toOwnedSliceSentinel(gpa, 0);
}

fn wideName(buffer: []u8, index: usize, name_bytes: usize) ![]u8 {
    var digits: [24]u8 = undefined;
    const number = try std.fmt.bufPrint(&digits, "{d}", .{index});
    @memset(buffer[0..name_bytes], 'x');
    @memcpy(buffer[name_bytes - number.len ..][0..number.len], number);
    return buffer[0..name_bytes];
}

fn mutableTableFunctionNames() []const []const u8 {
    comptime {
        var names: []const []const u8 = &.{};
        for (.{ Table, @This() }) |namespace| {
            for (@typeInfo(namespace).@"struct".decl_names) |decl| {
                const info = switch (@typeInfo(@TypeOf(@field(namespace, decl)))) {
                    .@"fn" => |function| function,
                    else => continue,
                };
                for (info.param_types) |param| {
                    const kind = param orelse continue;
                    const pointer = switch (@typeInfo(kind)) {
                        .pointer => |pointer| pointer,
                        else => continue,
                    };
                    if (pointer.child != Table or pointer.attrs.@"const") continue;
                    names = names ++ [_][]const u8{decl};
                }
            }
        }
        return names;
    }
}

test "a policy that names an action exactly beats one that names a class" {
    const gpa = std.testing.allocator;

    const class_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .allow },
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const exact_first: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\            .{ .action = "git.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    for ([_][:0]const u8{ class_first, exact_first }) |source| {
        const table = try Table.parse(gpa, source, null);
        defer Table.destroy(gpa, table);

        try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "git.push")));
        try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.commit")));
        try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.branch.delete")));
    }

    const nested: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .allow },
        \\            .{ .action = "git.branch.*", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, nested, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "git.branch.delete")));
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.commit")));
}

test "a name the author never wrote a rule about reaches nothing, and one they wrote a port rule about does" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .tool = "git", .action = "net.connect.com.anthropic.api.443", .decision = .allow },
        \\            .{ .tool = "git", .action = "net.connect.com.evil.*", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    try std.testing.expect(table.permitsSomethingUnder(testKey("main", "net.connect.com.anthropic.api")));

    try std.testing.expect(!table.permitsSomethingUnder(testKey("main", "net.connect.test.evil.secret")));

    try std.testing.expect(!table.permitsSomethingUnder(testKey("main", "net.connect.com.evil.metadata")));

    try std.testing.expect(!table.permitsSomethingUnder(.{
        .agent_kind = "main",
        .model = "test-model",
        .tool = "fetch_url",
        .action = "net.connect.com.anthropic.api",
    }));
}

test "a class rule above a host reaches every host under it, and a rule about a different host does not" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.connect.com.anthropic.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    try std.testing.expect(table.permitsSomethingUnder(testKey("main", "net.connect.com.anthropic.api")));
    try std.testing.expect(table.permitsSomethingUnder(testKey("main", "net.connect.com.anthropic")));

    try std.testing.expect(!table.permitsSomethingUnder(testKey("main", "net.connect.api.anthropic.com.evil")));

    try std.testing.expect(!table.permitsSomethingUnder(testKey("main", "net.connect.com.anthropicx")));
}

test "a subagent's policy is the intersection of its parent's and its kind's" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .agent_kind = "a0", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a1", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a2", .action = "git.push", .decision = .ask },
        \\            .{ .agent_kind = "a3", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "a4", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "a5", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    const chain = [_][]const u8{ "a0", "a1", "a2", "a3", "a4", "a5" };

    const alone = [_]Decision{ .allow, .allow, .ask, .allow, .deny, .allow };
    for (chain, alone) |kind, want| {
        try std.testing.expectEqual(want, table.evaluateKindAlone(testKey(kind, "git.push")));
    }

    const want_chain = [_]Decision{ .allow, .allow, .ask, .ask, .deny, .deny };
    for (1..chain.len + 1) |depth| {
        const links = chain[0..depth];
        const got = table.evaluateChain(links, testKey(links[depth - 1], "git.push"), null);
        try std.testing.expectEqual(want_chain[depth - 1], got);

        if (depth > 1) {
            const parent_links = chain[0 .. depth - 1];
            const parent = table.evaluateChain(parent_links, testKey(parent_links[depth - 2], "git.push"), null);
            try std.testing.expect(got.rank() <= parent.rank());
        }
    }

    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("a5", "git.push")));
    try std.testing.expectEqual(Decision.deny, table.evaluateChain(&chain, testKey("a5", "git.push"), null));
}

test "an action no rule names resolves to ask, never to allow" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.commit", .decision = .allow },
        \\            .{ .action = "git.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "net.fetch")));
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git")));
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("reviewer", "net.fetch"), null),
    );

    for ([_][:0]const u8{ ".{ .policy = .{} }", ".{}", ".{ .models = .{} }" }) |empty_source| {
        const empty = try Table.parse(gpa, empty_source, null);
        defer Table.destroy(gpa, empty);
        try std.testing.expectEqual(Decision.ask, empty.evaluateKindAlone(testKey("main", "git.push")));
        try std.testing.expectEqual(Decision.ask, empty.evaluateKindAlone(testKey("main", "workspace.apply")));
    }
}

test "a project can write the two review decisions, and a child still cannot climb to one" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "workspace.apply", .decision = .agent_review },
        \\            .{ .action = "git.push", .decision = .agent_then_human },
        \\            .{ .agent_kind = "worker", .action = "workspace.apply", .decision = .agent_review },
        \\            .{ .agent_kind = "cautious", .action = "workspace.apply", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);

    try std.testing.expectEqual(
        Decision.agent_review,
        table.evaluateKindAlone(testKey("main", "workspace.apply")),
    );
    try std.testing.expectEqual(
        Decision.agent_then_human,
        table.evaluateKindAlone(testKey("main", "git.push")),
    );

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "cautious", "worker" }, testKey("worker", "workspace.apply"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "worker", "cautious" }, testKey("cautious", "workspace.apply"), null),
    );

    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .agent_reveiw } } } }
    , null));
}

test "a policy that gives a child more than its parent is refused when it is read" {
    const gpa = std.testing.allocator;

    const child_rule_is_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_rule_is_stronger, null),
    );

    const child_falls_back_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_falls_back_stronger, null),
    );

    const child_would_be_reviewed: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "worker", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "workspace.apply", .decision = .ask },
        \\            .{ .agent_kind = "worker", .action = "workspace.apply", .decision = .agent_review },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_would_be_reviewed, null),
    );

    const child_is_weaker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .allow },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, child_is_weaker, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("reviewer", "git.push")));
}

test "a child with no rule at all can still outrank a parent's blanket rule, through a shipped default the walk never sampled" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "parent" },
        \\            .{ .kind = "child", .parent = "parent" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "parent", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.ChildStrongerThanParent, Table.parse(gpa, source, null));
}

test "a child that narrows the same shipped default its parent narrows still loads" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "parent" },
        \\            .{ .kind = "child", .parent = "parent" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "parent", .decision = .ask },
        \\            .{ .agent_kind = "child", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("child", "call.write_file")));
}

test "an ordinary hierarchy with no chock.zon rules at all still loads" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "worker", .parent = "main" },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("worker", "call.write_file")));
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("worker", "git.push")));
}

test "a field name with a typo inside the policy block is refused, not ignored" {
    const gpa = std.testing.allocator;

    const typo: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .actoin = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa, typo, null));

    const table = try Table.parse(gpa, ".{ .models = .{ .main = \"sonnet\" } }", null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git.push")));
}

test "the table cannot be changed after a session starts" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try absoluteDirPath(&path_buffer, tmp.dir);

    const at_start = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .allow } } } }";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = at_start });

    const table = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));

    const after_edit = ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } } }";
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = after_edit });

    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "git.push")));

    const next_session = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, next_session);
    try std.testing.expectEqual(Decision.deny, next_session.evaluateKindAlone(testKey("main", "git.push")));

    try std.testing.expectEqualSlices(u8, &hashSource(at_start), &table.sourceHash());
    try std.testing.expect(!std.mem.eql(u8, &hashSource(after_edit), &table.sourceHash()));

    try std.testing.expect(@typeInfo(@FieldType(Table, "policy")).pointer.attrs.@"const");
    inline for (.{ Table.parse, Table.load }) |constructor| {
        const returns = @typeInfo(@typeInfo(@TypeOf(constructor)).@"fn".return_type.?)
            .error_union.payload;
        try std.testing.expect(@typeInfo(returns).pointer.attrs.@"const");
        try std.testing.expectEqual(Table, @typeInfo(returns).pointer.child);
    }
    const mutable = comptime mutableTableFunctionNames();
    try std.testing.expectEqual(@as(usize, 0), mutable.len);
}

test "an empty spawn chain answers ask, never allow" {
    const gpa = std.testing.allocator;

    const allows_everything: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, allows_everything, null);
    defer Table.destroy(gpa, table);

    try std.testing.expectEqual(
        Decision.allow,
        table.evaluateChain(&.{"main"}, testKey("main", "git.push"), null),
    );

    const empty: []const []const u8 = &.{};
    try std.testing.expectEqual(Decision.ask, table.evaluateChain(empty, testKey("main", "git.push"), null));

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("main", "git.push"), null),
    );
}

test "a spawn chain with a link of no name answers ask, never allow" {
    const gpa = std.testing.allocator;

    const allows_everything: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, allows_everything, null);
    defer Table.destroy(gpa, table);

    try std.testing.expectEqual(
        Decision.allow,
        table.evaluateChain(&.{ "main", "reviewer" }, testKey("reviewer", "git.push"), null),
    );

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "", "reviewer" }, testKey("reviewer", "git.push"), null),
    );

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{ "main", "" }, testKey("", "git.push"), null),
    );

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{""}, testKey("", "git.push"), null),
    );
}

test "a policy of few rules and long names is refused" {
    const gpa = std.testing.allocator;

    const long = try wideSource(gpa, 72, 4600);
    defer gpa.free(long);
    try std.testing.expect(long.len > 900 * 1024);
    try std.testing.expect(long.len < max_file_bytes);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, long, null));

    const long_names = try wideSource(gpa, 27, 4600);
    defer gpa.free(long_names);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, long_names, null));

    const short_names = try wideSource(gpa, 27, 4);
    defer gpa.free(short_names);
    const table = try Table.parse(gpa, short_names, null);
    defer Table.destroy(gpa, table);

    var buffer: [4]u8 = undefined;
    const name = try wideName(&buffer, 11, 4);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(.{
        .agent_kind = "c",
        .model = name,
        .tool = name,
        .action = name,
    }));
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(.{
        .agent_kind = "c",
        .model = name,
        .tool = name,
        .action = "no rule names this",
    }));
}

test "a name that holds the byte the read time check invents is refused" {
    // A rule naming the NUL byte would name the "matches nothing"
    // representative, letting a child outrank a parent that only asks.
    const gpa = std.testing.allocator;

    const holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "p" },
        \\            .{ .kind = "c", .parent = "p" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "c", .decision = .allow },
        \\            .{ .agent_kind = "p", .action = "\x00", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, holds_the_marker, null));

    const class_prefix_holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.\x00.*", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, class_prefix_holds_the_marker, null));

    const kind_holds_the_marker: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "\x00" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, kind_holds_the_marker, null));

    const same_shape_without_it: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "p" },
        \\            .{ .kind = "c", .parent = "p" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "c", .decision = .ask },
        \\            .{ .agent_kind = "p", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const table = try Table.parse(gpa, same_shape_without_it, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("p", "git.push")));
}

test "a bare star is refused, so matching every value keeps one spelling" {
    const gpa = std.testing.allocator;

    inline for (.{ "agent_kind", "model", "tool", "action" }) |field| {
        const source = ".{ .policy = .{ .rules = .{ .{ ." ++ field ++
            " = \"*\", .decision = .allow } } } }";
        try std.testing.expectError(error.InvalidPattern, Table.parse(gpa, source, null));
    }

    const table = try Table.parse(gpa, ".{ .policy = .{ .rules = .{ .{ .decision = .allow } } } }", null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(testKey("main", "net.fetch")));
}

test "one pattern covers another only when it names everything that one names" {
    try std.testing.expect(patternCovers("git.push", "git.push"));
    try std.testing.expect(!patternCovers("git.push", "git.commit"));
    try std.testing.expect(patternCovers("git.*", "git.push"));
    try std.testing.expect(patternCovers("git.*", "git.branch.delete"));
    try std.testing.expect(!patternCovers("git.*", "git"));
    try std.testing.expect(patternCovers("git.*", "git.*"));
    try std.testing.expect(patternCovers("git.*", "git.branch.*"));
    try std.testing.expect(!patternCovers("git.branch.*", "git.*"));
    try std.testing.expect(!patternCovers("git.push", "git.*"));
    try std.testing.expect(!patternCovers("git.*", "gitlab.*"));
    try std.testing.expect(!patternCovers("git.*", "gitlab.push"));

    const patterns = [_][]const u8{ "git.push", "git.*", "git.branch.*", "net.fetch" };
    const values = [_][]const u8{ "git.push", "git.branch.delete", "git", "net.fetch", "nix.build" };
    for (patterns) |pattern| {
        for (values) |value| {
            try std.testing.expectEqual(patternMatches(pattern, value), patternCovers(pattern, value));
        }
    }
}

test "a well formed pattern is a name, or a name and a class star, and nothing else" {
    try std.testing.expect(patternIsWellFormed("git.push"));
    try std.testing.expect(patternIsWellFormed("git.*"));
    try std.testing.expect(patternIsWellFormed("a"));
    try std.testing.expect(!patternIsWellFormed("*"));
    try std.testing.expect(!patternIsWellFormed(""));
    try std.testing.expect(!patternIsWellFormed(".*"));
    try std.testing.expect(!patternIsWellFormed("git.*.push"));
    try std.testing.expect(!patternIsWellFormed("git\x00push"));

    const gpa = std.testing.allocator;
    try std.testing.expectError(error.InvalidPattern, Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"git.*.push\", .decision = .deny } } } }",
        null,
    ));
}

test "a policy with more rules or more agents than the reader accepts is refused" {
    const gpa = std.testing.allocator;

    const too_many_rules = try repeatedSource(
        gpa,
        ".{ .policy = .{ .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules + 1,
        " } } }",
    );
    defer gpa.free(too_many_rules);
    try std.testing.expectError(error.TooManyRules, Table.parse(gpa, too_many_rules, null));

    const at_the_rule_cap = try repeatedSource(
        gpa,
        ".{ .policy = .{ .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(at_the_rule_cap);
    const table = try Table.parse(gpa, at_the_rule_cap, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("main", "a0")));

    const too_many_agents = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{",
        " .{ .kind = \"k#\" },",
        max_agents + 1,
        " } } }",
    );
    defer gpa.free(too_many_agents);
    try std.testing.expectError(error.TooManyAgents, Table.parse(gpa, too_many_agents, null));
}

test "a policy that would make the read time check walk too far is refused" {
    const gpa = std.testing.allocator;

    const wide = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, .{ .kind = \"c\", .parent = \"p\" } }, .rules = .{",
        " .{ .model = \"m#\", .tool = \"t#\", .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(wide);
    try std.testing.expect(wide.len < 64 * 1024);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, wide, null));

    const narrow = try repeatedSource(
        gpa,
        ".{ .policy = .{ .agents = .{ .{ .kind = \"p\" }, .{ .kind = \"c\", .parent = \"p\" } }, .rules = .{",
        " .{ .action = \"a#\", .decision = .deny },",
        max_rules,
        " } } }",
    );
    defer gpa.free(narrow);
    const table = try Table.parse(gpa, narrow, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(testKey("c", "a7")));
}

test "two agents that name the same kind are refused" {
    const gpa = std.testing.allocator;

    const twice: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "main", .parent = "main" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.DuplicateAgent, Table.parse(gpa, twice, null));
}

test "an agent whose parent no entry declares is refused" {
    const gpa = std.testing.allocator;

    const missing_parent: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.UnknownParent, Table.parse(gpa, missing_parent, null));
}

test "a loop in the parent links is refused" {
    const gpa = std.testing.allocator;

    const loop: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "a", .parent = "c" },
        \\            .{ .kind = "b", .parent = "a" },
        \\            .{ .kind = "c", .parent = "b" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, loop, null));

    const names_itself: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "a", .parent = "a" },
        \\        },
        \\    },
        \\}
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, names_itself, null));
}

test "a file larger than the byte cap, and a project with no file, are both reported" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const project_root = try absoluteDirPath(&path_buffer, tmp.dir);

    try std.testing.expectError(
        error.NoPolicyFile,
        Table.load(gpa, std.testing.io, project_root, null),
    );

    const oversized = try gpa.alloc(u8, max_file_bytes + 1);
    defer gpa.free(oversized);
    @memset(oversized, ' ');
    @memcpy(oversized[oversized.len - 4 ..], "\n.{}");
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = oversized });
    try std.testing.expectError(
        error.PolicyTooLarge,
        Table.load(gpa, std.testing.io, project_root, null),
    );

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = oversized[4..] });
    const table = try Table.load(gpa, std.testing.io, project_root, null);
    defer Table.destroy(gpa, table);
    try std.testing.expectEqual(Decision.ask, table.evaluateKindAlone(testKey("main", "git.push")));
}

test "the names in a refusal reach the caller, and no longer only a terminal" {
    const gpa = std.testing.allocator;
    const child_rule_is_stronger: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "reviewer", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .agent_kind = "main", .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "reviewer", .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try std.testing.expectError(
        error.ChildStrongerThanParent,
        Table.parse(gpa, child_rule_is_stronger, &diag),
    );

    const names = diag.?.child_stronger_than_parent;
    try std.testing.expectEqualStrings("reviewer", names.kind);
    try std.testing.expectEqualStrings("main", names.parent_kind);
    try std.testing.expectEqual(Decision.allow, names.child_answer);
    try std.testing.expectEqual(Decision.deny, names.parent_answer);
    try std.testing.expectEqualStrings("git.push", names.action);

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try std.testing.expectEqualStrings(
        "chock.zon: the agent reviewer holds allow and its parent main holds deny, " ++
            "for any model, any tool, and the action git.push",
        line,
    );
}

test "a misspelled decision names its line and column, and the trees behind it are released" {
    const gpa = std.testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try std.testing.expectError(error.InvalidPolicy, Table.parse(gpa,
        \\.{ .policy = .{ .rules = .{ .{ .action = "git.push", .decision = .agent_reveiw } } } }
    , &diag));

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try std.testing.expect(std.mem.startsWith(u8, line, "chock.zon: the policy block is not valid:\n"));
    // Relative to the block's own cut text, not to chock.zon as a whole:
    // see chock-zon.zig's own note on `fromNode`.
    try std.testing.expect(std.mem.indexOf(u8, line, "1:54: error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "agent_reveiw") != null);
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    const gpa = std.testing.allocator;
    const loop: [:0]const u8 =
        \\.{ .policy = .{ .agents = .{
        \\    .{ .kind = "a", .parent = "b" },
        \\    .{ .kind = "b", .parent = "a" },
        \\} } }
    ;
    try std.testing.expectError(error.AgentCycle, Table.parse(gpa, loop, null));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try std.testing.expect(note(&diag, .not_a_struct_literal));
    try std.testing.expect(!note(&diag, .{ .too_many_rules = 9 }));
    try std.testing.expectEqual(Diagnostic.not_a_struct_literal, diag.?);

    try std.testing.expect(!note(null, .not_a_struct_literal));
    try std.testing.expect(!wantsDiagnostic(null));
    try std.testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .not_a_struct_literal,
        .{ .read_failed = error.AccessDenied },
        .{ .too_many_rules = 1 },
        .{ .too_many_agents = 1 },
        .{ .pattern_matches_everything = "action" },
        .{ .pattern_malformed = "action" },
        .{ .name_malformed = "kind" },
        .{ .duplicate_agent_kind = "main" },
        .{ .unknown_parent = .{ .kind = "main", .parent = "root" } },
        .{ .agent_cycle = "main" },
        .{ .child_stronger_than_parent = .{
            .kind = "child",
            .child_answer = .allow,
            .parent_kind = "parent",
            .parent_answer = .deny,
            .model = "m",
            .tool = "t",
            .action = "a",
        } },
        .{ .policy_too_complex = .{
            .reads = 1,
            .longest_name = 2,
            .work = 3,
            .rules = 4,
            .models = 5,
            .tools = 6,
            .actions = 7,
            .links = 8,
        } },
    };
    var buffers: [cases.len][1024]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try std.testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try std.testing.expect(!std.mem.eql(u8, line, other));
    }
}

test "a spawn chain the reader cannot fold names why, and the answer stays ask" {
    const gpa = std.testing.allocator;
    const table = try Table.parse(gpa, ".{ .policy = .{ .rules = .{ .{ .decision = .allow } } } }", null);
    defer Table.destroy(gpa, table);

    var fault: ?ChainFault = null;
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{}, testKey("main", "git.push"), &fault),
    );
    try std.testing.expectEqualStrings("git.push", fault.?.empty);

    _ = table.evaluateChain(&.{""}, testKey("", "git.push"), &fault);
    try std.testing.expectEqualStrings("git.push", fault.?.empty);

    var second: ?ChainFault = null;
    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{"main"}, testKey("reviewer", "git.push"), &second),
    );
    var buffer: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "a policy question from the kind reviewer arrived with a spawn chain that ends in main, so the answer is ask",
        try std.fmt.bufPrint(&buffer, "{f}", .{second.?}),
    );

    try std.testing.expectEqual(
        Decision.ask,
        table.evaluateChain(&.{}, testKey("main", "git.push"), null),
    );
}

test "a project cannot widen what an org narrowed" {
    const gpa = std.testing.allocator;

    const project_allows: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "provider.public.gpt-5", .decision = .allow },
        \\            .{ .action = "git.push", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const org_narrows = [_]Rule{
        .{ .action = "provider.public.*", .decision = .deny },
        .{ .action = "git.push", .decision = .ask },
    };

    const bound = try Table.parseUnder(gpa, project_allows, &org_narrows, null);
    defer Table.destroy(gpa, bound);

    const chain = [_][]const u8{"main"};
    const push = testKey("main", "git.push");
    const model = testKey("main", "provider.public.gpt-5");

    try std.testing.expectEqual(Decision.ask, bound.evaluateChain(&chain, push, null));
    try std.testing.expectEqual(Decision.deny, bound.evaluateChain(&chain, model, null));
    try std.testing.expectEqual(Decision.deny, bound.ceilingChain(&chain, model, null));

    const alone = try Table.parse(gpa, project_allows, null);
    defer Table.destroy(gpa, alone);
    try std.testing.expectEqual(Decision.allow, alone.evaluateChain(&chain, push, null));
    try std.testing.expectEqual(Decision.allow, alone.evaluateChain(&chain, model, null));

    const project_narrows: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.push", .decision = .deny },
        \\        },
        \\    },
        \\}
    ;
    const org_permits = [_]Rule{
        .{ .action = "git.push", .decision = .allow },
    };
    const narrower = try Table.parseUnder(gpa, project_narrows, &org_permits, null);
    defer Table.destroy(gpa, narrower);
    try std.testing.expectEqual(Decision.deny, narrower.evaluateChain(&chain, push, null));

    const org_only = [_]Rule{
        .{ .action = "net.fetch", .decision = .deny },
    };
    const unmentioned = try Table.parseUnder(gpa, project_allows, &org_only, null);
    defer Table.destroy(gpa, unmentioned);
    try std.testing.expectEqual(
        Decision.deny,
        unmentioned.evaluateChain(&chain, testKey("main", "net.fetch"), null),
    );

    const every = [_]Decision{ .deny, .agent_then_human, .ask, .agent_review, .allow };
    for (every) |from_project| {
        for (every) |from_org| {
            const source = try std.fmt.allocPrintSentinel(
                gpa,
                ".{{ .policy = .{{ .rules = .{{ .{{ .action = \"git.push\", .decision = .{t} }} }} }} }}",
                .{from_project},
                0,
            );
            defer gpa.free(source);
            const ceiling = [_]Rule{.{ .action = "git.push", .decision = from_org }};
            const both = try Table.parseUnder(gpa, source, &ceiling, null);
            defer Table.destroy(gpa, both);
            try std.testing.expectEqual(
                @min(from_project.rank(), from_org.rank()),
                both.evaluateChain(&chain, push, null).rank(),
            );
        }
    }
}

test "a session with no org bundle answers exactly as it did before bundles existed" {
    const gpa = std.testing.allocator;

    const source: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .agents = .{
        \\            .{ .kind = "main" },
        \\            .{ .kind = "worker", .parent = "main" },
        \\        },
        \\        .rules = .{
        \\            .{ .action = "git.*", .decision = .ask },
        \\            .{ .action = "git.push", .decision = .deny },
        \\            .{ .agent_kind = "main", .action = "git.commit", .decision = .allow },
        \\            .{ .action = "net.fetch", .decision = .agent_review },
        \\        },
        \\    },
        \\}
    ;

    const plain = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, plain);
    const with_empty = try Table.parseUnder(gpa, source, &.{}, null);
    defer Table.destroy(gpa, with_empty);

    const kinds = [_][]const u8{ "main", "worker" };
    const actions = [_][]const u8{
        "git.push",
        "git.commit",
        "git.branch.delete",
        "net.fetch",
        "workspace.apply",
        "git",
    };
    const chains = [_][]const []const u8{
        &.{"main"},
        &.{"worker"},
        &.{ "main", "worker" },
        &.{ "main", "main" },
    };
    for (chains) |chain| {
        const asker = chain[chain.len - 1];
        for (actions) |action| {
            const key = testKey(asker, action);
            try std.testing.expectEqual(
                plain.evaluateChain(chain, key, null),
                with_empty.evaluateChain(chain, key, null),
            );
            try std.testing.expectEqual(
                plain.ceilingChain(chain, key, null),
                with_empty.ceilingChain(chain, key, null),
            );
        }
    }
    for (kinds) |kind| {
        for (actions) |action| {
            const key = testKey(kind, action);
            try std.testing.expectEqual(
                plain.evaluateKindAlone(key),
                with_empty.evaluateKindAlone(key),
            );
        }
    }

    try std.testing.expectEqual(
        Decision.deny,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "git.push"), null),
    );
    try std.testing.expectEqual(
        Decision.allow,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "git.commit"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        with_empty.evaluateChain(&.{ "main", "worker" }, testKey("worker", "git.commit"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        with_empty.evaluateChain(&.{"main"}, testKey("main", "workspace.apply"), null),
    );
    try std.testing.expectEqualSlices(u8, &plain.sourceHash(), &with_empty.sourceHash());
}

test "an org bundle is read as a ceiling, so a rule it never wrote narrows nothing" {
    const gpa = std.testing.allocator;

    const project: [:0]const u8 =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "git.commit", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const one_rule = [_]Rule{
        .{ .action = "provider.public.*", .decision = .deny },
    };

    const bound = try Table.parseUnder(gpa, project, &one_rule, null);
    defer Table.destroy(gpa, bound);
    const chain = [_][]const u8{"main"};

    try std.testing.expectEqual(
        Decision.allow,
        bound.evaluateChain(&chain, testKey("main", "git.commit"), null),
    );
    try std.testing.expectEqual(
        Decision.ask,
        bound.evaluateChain(&chain, testKey("main", "workspace.apply"), null),
    );
    try std.testing.expectEqual(
        Decision.deny,
        bound.evaluateChain(&chain, testKey("main", "provider.public.gpt-5"), null),
    );
}

test "the read time check counts the shipped defaults, and refuses what the file's own rules alone would not" {
    const gpa = std.testing.allocator;

    const source = try wideSource(gpa, 73, 64);
    defer gpa.free(source);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, source, &diag));

    const walk = diag.?.policy_too_complex;
    try std.testing.expectEqual(@as(u64, 73), walk.rules);
    try std.testing.expectEqual(@as(u64, 64), walk.longest_name);

    const keys: u64 = 74 * 74 * (74 + @as(u64, defaults.rules.len));
    const rules_per_key: u64 = walk.rules + @as(u64, defaults.rules.len);
    try std.testing.expectEqual(keys * rules_per_key * 2, walk.reads);
    try std.testing.expectEqual(keys * rules_per_key * 2 * 64, walk.work);
}

test "a decision the rules named is told apart from the ask a key nobody wrote gets" {
    const gpa = std.testing.allocator;

    const t = try Table.parse(gpa,
        \\.{
        \\    .policy = .{
        \\        .rules = .{ .{ .action = "nix.net.build.com.example.443", .decision = .ask } },
        \\    },
        \\}
    , null);
    defer Table.destroy(gpa, t);

    const written = t.decideChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "nix_build",
        .action = "nix.net.build.com.example.443",
    }, null);
    try std.testing.expect(written.named);
    try std.testing.expectEqual(Decision.ask, written.decision);

    const nobody = t.decideChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "nix_build",
        .action = "nix.net.build.com.other.443",
    }, null);
    try std.testing.expect(!nobody.named);
    try std.testing.expectEqual(Decision.ask, nobody.decision);

    const shipped = t.decideChain(&.{"main"}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "nix_build",
        .action = "nix.net.build.opaque",
    }, null);
    try std.testing.expect(shipped.named);
    try std.testing.expectEqual(Decision.allow, shipped.decision);

    const broken = t.decideChain(&.{}, .{
        .agent_kind = "main",
        .model = "a-model",
        .tool = "nix_build",
        .action = "nix.net.build.com.example.443",
    }, null);
    try std.testing.expect(!broken.named);

    for ([_][]const u8{
        "nix.net.build.com.example.443",
        "nix.net.build.com.other.443",
        "nix.net.build.opaque",
    }) |action| {
        const key: Key = .{
            .agent_kind = "main",
            .model = "a-model",
            .tool = "nix_build",
            .action = action,
        };
        try std.testing.expectEqual(
            t.evaluateChain(&.{"main"}, key, null),
            t.decideChain(&.{"main"}, key, null).decision,
        );
    }
}

test "the corrected budget still reads a table under it and still refuses one clearly over it" {
    const gpa = std.testing.allocator;

    var admitted: usize = 0;
    var count: usize = 1;
    while (count < max_rules) : (count += 1) {
        const source = try wideSource(gpa, count, 64);
        defer gpa.free(source);
        const table = Table.parse(gpa, source, null) catch |err| switch (err) {
            error.PolicyTooComplex => break,
            else => return err,
        };
        Table.destroy(gpa, table);
        admitted = count;
    }

    try std.testing.expect(admitted != 0);
    try std.testing.expect(count < max_rules);
    try std.testing.expectEqual(admitted + 1, count);

    try std.testing.expect(admitted >= 24);

    const clearly_over = try wideSource(gpa, max_rules, 64);
    defer gpa.free(clearly_over);
    try std.testing.expectError(error.PolicyTooComplex, Table.parse(gpa, clearly_over, null));
}

test "a router is wanted when the policy permits a host, and not when it only denies one" {
    const gpa = std.testing.allocator;

    const quiet = try Table.parse(gpa, ".{ .policy = .{ .rules = .{} } }", null);
    defer Table.destroy(gpa, quiet);
    try std.testing.expect(!quiet.wantsRouter());

    const permits = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"net.connect.com.github\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, permits);
    try std.testing.expect(permits.wantsRouter());

    const asks = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"net.connect.com.github\", .decision = .ask } } } }",
        null,
    );
    defer Table.destroy(gpa, asks);
    try std.testing.expect(asks.wantsRouter());

    const denies = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"net.connect.com.github\", .decision = .deny } } } }",
        null,
    );
    defer Table.destroy(gpa, denies);
    try std.testing.expect(!denies.wantsRouter());

    const fetches = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"net.fetch.rs.docs\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, fetches);
    try std.testing.expect(fetches.wantsRouter());

    const elsewhere = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, elsewhere);
    try std.testing.expect(!elsewhere.wantsRouter());
}

test "the router setting overrides what the rules would have decided, both ways" {
    const gpa = std.testing.allocator;

    const off = try Table.parse(
        gpa,
        ".{ .policy = .{ .net = .{ .router = .none }, .rules = .{ " ++
            ".{ .action = \"net.connect.com.github\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, off);
    try std.testing.expect(!off.wantsRouter());

    const on = try Table.parse(gpa, ".{ .policy = .{ .net = .{ .router = .filtered } } }", null);
    defer Table.destroy(gpa, on);
    try std.testing.expect(on.wantsRouter());

    const plain = try Table.parse(gpa, ".{ .policy = .{ .rules = .{} } }", null);
    defer Table.destroy(gpa, plain);
    try std.testing.expectEqual(Router.auto, plain.policy.net.router);
}

test "a background call follows the session's network, and can be refused one of its own" {
    const gpa = std.testing.allocator;

    const permits = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"net.connect.com.github\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, permits);
    try std.testing.expect(permits.wantsRouter());
    try std.testing.expect(permits.wantsBackgroundRouter());

    const foreground_only = try Table.parse(
        gpa,
        ".{ .policy = .{ .net = .{ .background = .none }, .rules = .{ " ++
            ".{ .action = \"net.connect.com.github\", .decision = .allow } } } }",
        null,
    );
    defer Table.destroy(gpa, foreground_only);
    try std.testing.expect(foreground_only.wantsRouter());
    try std.testing.expect(!foreground_only.wantsBackgroundRouter());

    const nothing = try Table.parse(
        gpa,
        ".{ .policy = .{ .net = .{ .router = .none, .background = .filtered } } }",
        null,
    );
    defer Table.destroy(gpa, nothing);
    try std.testing.expect(!nothing.wantsBackgroundRouter());
}

test "a rule given on the command line answers instead of the project's own" {
    const gpa = std.testing.allocator;

    const given = [_]Rule{.{ .action = "git.push", .decision = .allow }};
    const table = try Table.parseLayered(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } } }",
        .{ .given = &given },
        null,
    );
    defer Table.destroy(gpa, table);

    const key = Key{
        .agent_kind = "coder",
        .model = "m",
        .tool = "run_command",
        .action = "git.push",
    };
    try std.testing.expectEqual(Decision.allow, table.evaluateKindAlone(key));

    const plain = try Table.parse(
        gpa,
        ".{ .policy = .{ .rules = .{ .{ .action = \"git.push\", .decision = .deny } } } }",
        null,
    );
    defer Table.destroy(gpa, plain);
    try std.testing.expectEqual(Decision.deny, plain.evaluateKindAlone(key));
}

test "an org bundle still holds a rule given on the command line" {
    const gpa = std.testing.allocator;

    const given = [_]Rule{.{ .action = "git.push", .decision = .allow }};
    const org = [_]Rule{.{ .action = "git.push", .decision = .deny }};
    const table = try Table.parseLayered(gpa, ".{}", .{ .given = &given, .org = &org }, null);
    defer Table.destroy(gpa, table);

    const key = Key{
        .agent_kind = "coder",
        .model = "m",
        .tool = "run_command",
        .action = "git.push",
    };
    try std.testing.expectEqual(Decision.deny, table.evaluateKindAlone(key));
}

test "a given rule is read as <action>=<decision>, and every other shape is refused" {
    const rule = try parseGivenRule("net.fetch.*=allow");
    try std.testing.expectEqualStrings("net.fetch.*", rule.action.?);
    try std.testing.expectEqual(Decision.allow, rule.decision);
    try std.testing.expectEqual(@as(?[]const u8, null), rule.tool);

    try std.testing.expectEqual(Decision.agent_then_human, (try parseGivenRule("git.push=agent_then_human")).decision);

    try std.testing.expectError(error.NoEquals, parseGivenRule("git.push"));
    try std.testing.expectError(error.ActionEmpty, parseGivenRule("=allow"));
    try std.testing.expectError(error.DecisionUnknown, parseGivenRule("git.push=maybe"));
    try std.testing.expectError(error.ActionMalformed, parseGivenRule("net.*.fetch=allow"));
    try std.testing.expectError(error.ActionMalformed, parseGivenRule("*=allow"));
}

test "a table says whether a chock.zon was read, so an absent file is not an empty one" {
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const written = try tmp.dir.realPath(std.testing.io, &buffer);
    const root = buffer[0..written];

    try std.testing.expectError(
        error.NoPolicyFile,
        Table.load(gpa, std.testing.io, root, null),
    );

    const empty = try Table.parse(gpa, ".{}", null);
    defer Table.destroy(gpa, empty);
    try std.testing.expect(!empty.hasFile());

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = file_name, .data = ".{}" });
    const read = try Table.load(gpa, std.testing.io, root, null);
    defer Table.destroy(gpa, read);
    try std.testing.expect(read.hasFile());

    try std.testing.expectEqualSlices(u8, &empty.sourceHash(), &read.sourceHash());
}

test "a port is published by a rule that names it and answers allow, and by nothing else" {
    const gpa = std.testing.allocator;
    const source =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.serve.3000", .decision = .allow },
        \\            .{ .action = "net.serve.8080", .decision = .ask },
        \\            .{ .action = "net.serve.9999", .decision = .deny },
        \\            .{ .action = "net.serve.*", .decision = .allow },
        \\            .{ .action = "net.connect.com.example.443", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, parsed);

    const key = Key{ .agent_kind = "main", .model = "m", .tool = "run_command", .action = "" };
    var buffer: [8]u16 = undefined;
    const ports = parsed.servedPorts(key, &buffer);

    try std.testing.expectEqual(@as(usize, 1), ports.len);
    try std.testing.expectEqual(@as(u16, 3000), ports[0]);
}

test "the port a serve action names is read from digits alone" {
    try std.testing.expectEqual(@as(?u16, 3000), portNamedBy("net.serve.3000"));
    try std.testing.expectEqual(@as(?u16, 65535), portNamedBy("net.serve.65535"));

    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve.*"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve."));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve.3000.extra"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve.0"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve.99999"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.connect.3000"));
    try std.testing.expectEqual(@as(?u16, null), portNamedBy("net.serve.80a"));
}

test "provider search domains require a wholly allowed fetch subtree" {
    const gpa = std.testing.allocator;
    const source =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.fetch.com.example", .decision = .allow },
        \\            .{ .action = "net.fetch.com.example.*", .decision = .allow },
        \\            .{ .action = "net.fetch.org.ziglang.docs", .decision = .allow },
        \\            .{ .action = "net.fetch.org.ziglang.docs.*", .decision = .allow },
        \\            .{ .action = "net.fetch.org.ziglang.docs.private", .decision = .deny },
        \\            .{ .action = "net.fetch.net.lonely", .decision = .allow },
        \\            .{ .action = "net.fetch.net.lonely.*", .decision = .ask },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, parsed);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    const domains = try parsed.allowedFetchDomains(
        arena_state.allocator(),
        &.{"main"},
        .{ .agent_kind = "main", .model = "m", .tool = "web_search", .action = "" },
        100,
    );
    try std.testing.expectEqual(@as(usize, 1), domains.len);
    try std.testing.expectEqualStrings("example.com", domains[0]);
}

test "a published port is counted once, and the list stops at what the caller can hold" {
    const gpa = std.testing.allocator;
    const source =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.serve.3000", .decision = .allow },
        \\            .{ .action = "net.serve.3000", .decision = .allow },
        \\            .{ .action = "net.serve.4000", .decision = .allow },
        \\            .{ .action = "net.serve.5000", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, parsed);

    const key = Key{ .agent_kind = "main", .model = "m", .tool = "run_command", .action = "" };
    var all: [8]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 3), parsed.servedPorts(key, &all).len);

    var two: [2]u16 = undefined;
    try std.testing.expectEqual(@as(usize, 2), parsed.servedPorts(key, &two).len);
}

test "a rule for another tool or agent publishes nothing for this one" {
    const gpa = std.testing.allocator;
    const source =
        \\.{
        \\    .policy = .{
        \\        .rules = .{
        \\            .{ .action = "net.serve.3000", .decision = .allow, .tool = "nix_build" },
        \\            .{ .action = "net.serve.4000", .decision = .allow, .agent_kind = "reviewer" },
        \\            .{ .action = "net.serve.5000", .decision = .allow },
        \\        },
        \\    },
        \\}
    ;
    const parsed = try Table.parse(gpa, source, null);
    defer Table.destroy(gpa, parsed);

    const key = Key{ .agent_kind = "main", .model = "m", .tool = "run_command", .action = "" };
    var buffer: [8]u16 = undefined;
    const ports = parsed.servedPorts(key, &buffer);
    try std.testing.expectEqual(@as(usize, 1), ports.len);
    try std.testing.expectEqual(@as(u16, 5000), ports[0]);
}

test "the action a port is answered under reads back as that port" {
    var buffer: [max_serve_action_bytes]u8 = undefined;
    try std.testing.expectEqualStrings("net.serve.3000", serveActionInto(&buffer, 3000).?);
    try std.testing.expectEqualStrings("net.serve.65535", serveActionInto(&buffer, 65535).?);
    try std.testing.expectEqual(@as(?[]const u8, null), serveActionInto(&buffer, 0));

    for ([_]u16{ 1024, 3000, 8080, 65535 }) |port| {
        const action = serveActionInto(&buffer, port).?;
        try std.testing.expectEqual(port, portNamedBy(action).?);
    }
}
