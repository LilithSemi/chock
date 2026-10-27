//! Where a store path came from, as Nix records it, and whether that is what
//! the project asked for. Determinate Nix writes a chain of links for each
//! path: a copy names the store it arrived from, a build names the machine and
//! the derivation, and each link can carry the link before it.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

/// Nix writes one link for each step from a build to this machine. A longer
/// chain is read as a fault, so a cyclic answer cannot hold the check open.
pub const max_links: usize = 32;

/// What a project demands of a path before a tool call can run it. Every field
/// at its default asks nothing, and then Nix is never asked either.
pub const Expectation = struct {
    /// Refuse a path that carries no provenance at all.
    required: bool = false,
    /// The stores a copy may come from. Empty asks nothing.
    from: []const []const u8 = &.{},
    /// The machines a build may have run on. Empty asks nothing.
    built_by: []const []const u8 = &.{},

    pub fn asksNothing(self: Expectation) bool {
        return !self.required and self.from.len == 0 and self.built_by.len == 0;
    }
};

pub const Fault = union(enum) {
    /// Nix answered nothing a reader could use, with what it said.
    unreadable: []const u8,
    /// Nix answered `null` for the path, so it holds no record of it.
    path_unknown,
    no_provenance,
    copied_from: []const u8,
    built_by: []const u8,
    /// A build that names no machine, where the project named which machines.
    build_host_unknown,
    chain_too_long,
};

pub const Refusal = struct {
    path: []const u8,
    fault: Fault,
};

pub const Verdict = union(enum) {
    allowed,
    refused: Refusal,
};

/// The arguments that make Nix answer with the provenance of each path.
/// `--json-format` is given rather than left out: a bare `--json` is deprecated
/// and a Nix that refuses the flag is a Nix that records no provenance, which
/// `check` then says in full.
pub fn argsFor(
    allocator: std.mem.Allocator,
    paths: []const []const u8,
) Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &.{ "path-info", "--json", "--json-format", "1", "--" });
    try out.appendSlice(allocator, paths);
    return out.toOwnedSlice(allocator);
}

/// Reads what `argsFor` asked for and answers on the first path that fails.
/// One refusal is the answer, because one path that cannot be trusted is enough
/// to leave the whole tool out of the toolchain.
pub fn check(
    allocator: std.mem.Allocator,
    expectation: Expectation,
    answer: []const u8,
) Error!Verdict {
    if (expectation.asksNothing()) return .allowed;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, answer, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return unreadable(allocator, answer),
    };
    defer parsed.deinit();
    if (parsed.value != .object) return unreadable(allocator, answer);

    var entries = parsed.value.object.iterator();
    var seen: usize = 0;
    while (entries.next()) |entry| {
        seen += 1;
        if (faultIn(expectation, entry.value_ptr.*)) |fault| return .{ .refused = .{
            .path = try allocator.dupe(u8, entry.key_ptr.*),
            .fault = try ownFault(allocator, fault),
        } };
    }
    if (seen == 0) return unreadable(allocator, answer);
    return .allowed;
}

fn unreadable(allocator: std.mem.Allocator, answer: []const u8) Error!Verdict {
    return .{ .refused = .{
        .path = "",
        .fault = .{ .unreadable = try allocator.dupe(u8, cut(answer)) },
    } };
}

pub const max_shown_bytes: usize = 200;

fn cut(text: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (trimmed.len <= max_shown_bytes) return trimmed;
    return trimmed[0..max_shown_bytes];
}

/// The fault still points into the parsed answer here, so the caller copies
/// what it keeps before the answer is freed.
fn ownFault(allocator: std.mem.Allocator, fault: Fault) Error!Fault {
    return switch (fault) {
        .copied_from => |text| .{ .copied_from = try allocator.dupe(u8, text) },
        .built_by => |text| .{ .built_by = try allocator.dupe(u8, text) },
        .unreadable => |text| .{ .unreadable = try allocator.dupe(u8, text) },
        .path_unknown, .no_provenance, .build_host_unknown, .chain_too_long => fault,
    };
}

fn faultIn(expectation: Expectation, info: std.json.Value) ?Fault {
    if (info == .null) return .path_unknown;
    if (info != .object) return .{ .unreadable = "" };

    const carried = info.object.get("provenance") orelse std.json.Value.null;
    if (carried == .null) return if (expectation.required) .no_provenance else null;

    var link = carried;
    var depth: usize = 0;
    while (link == .object) {
        depth += 1;
        if (depth > max_links) return .chain_too_long;
        if (faultInLink(expectation, link.object)) |fault| return fault;
        link = link.object.get("next") orelse std.json.Value.null;
    }
    return null;
}

fn faultInLink(expectation: Expectation, link: std.json.ObjectMap) ?Fault {
    const kind = link.get("type") orelse return null;
    if (kind != .string) return null;

    if (std.mem.eql(u8, kind.string, "copied") and expectation.from.len != 0) {
        const named = link.get("from") orelse std.json.Value.null;
        if (named != .string) return .{ .copied_from = "" };
        if (!namesStore(expectation.from, named.string)) return .{ .copied_from = named.string };
    }

    if (std.mem.eql(u8, kind.string, "build") and expectation.built_by.len != 0) {
        const host = link.get("buildHost") orelse std.json.Value.null;
        if (host != .string) return .build_host_unknown;
        if (!holds(expectation.built_by, host.string)) return .{ .built_by = host.string };
    }

    return null;
}

fn holds(list: []const []const u8, text: []const u8) bool {
    for (list) |one| {
        if (std.mem.eql(u8, one, text)) return true;
    }
    return false;
}

/// A store is named by a URL, and a trailing slash is the same store.
fn namesStore(list: []const []const u8, named: []const u8) bool {
    for (list) |one| {
        if (std.mem.eql(u8, std.mem.trimEnd(u8, one, "/"), std.mem.trimEnd(u8, named, "/"))) return true;
    }
    return false;
}

/// One sentence for a person and for the agent that asked for the tool. Names
/// what the path says and what the project asked for, because a refusal that
/// names only one of the two cannot be acted on.
pub fn explain(
    allocator: std.mem.Allocator,
    expectation: Expectation,
    refusal: Refusal,
) Error![]u8 {
    return switch (refusal.fault) {
        .unreadable => |said| std.fmt.allocPrint(
            allocator,
            "this project asks where a tool came from, and the nix in use answered nothing a " ++
                "reader could use, so nothing was provisioned. This record needs Determinate " ++
                "Nix 3.16 or later: it holds both the record and the flag that asks for it. " ++
                "Nix said: {s}",
            .{said},
        ),
        .path_unknown => std.fmt.allocPrint(
            allocator,
            "{s} was built and nix then held no record of it, so where it came from cannot be " ++
                "told and it was not added to the toolchain.",
            .{refusal.path},
        ),
        .no_provenance => std.fmt.allocPrint(
            allocator,
            "{s} carries no provenance, and this project's nix block asks that every provisioned " ++
                "path says where it came from, so it was not added to the toolchain. A path " ++
                "registered by an older nix carries none: build it again, or substitute it from " ++
                "a store that records provenance.",
            .{refusal.path},
        ),
        .copied_from => |from| std.fmt.allocPrint(
            allocator,
            "{s} was copied from {s}, which this project's nix block does not name, so it was " ++
                "not added to the toolchain. It names {f}.",
            .{ refusal.path, shown(from), Listed{ .items = expectation.from } },
        ),
        .built_by => |host| std.fmt.allocPrint(
            allocator,
            "{s} was built on {s}, which this project's nix block does not name, so it was not " ++
                "added to the toolchain. It names {f}.",
            .{ refusal.path, host, Listed{ .items = expectation.built_by } },
        ),
        .build_host_unknown => std.fmt.allocPrint(
            allocator,
            "{s} was built on a machine its provenance does not name, and this project's nix " ++
                "block names which machines may build a tool, so it was not added to the " ++
                "toolchain. It names {f}.",
            .{ refusal.path, Listed{ .items = expectation.built_by } },
        ),
        .chain_too_long => std.fmt.allocPrint(
            allocator,
            "{s} carries more than {d} provenance links, which no honest chain needs, so it was " ++
                "not added to the toolchain.",
            .{ refusal.path, max_links },
        ),
    };
}

fn shown(text: []const u8) []const u8 {
    return if (text.len == 0) "a store it does not name" else text;
}

const Listed = struct {
    items: []const []const u8,

    pub fn format(self: Listed, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        if (self.items.len == 0) return writer.writeAll("none");
        for (self.items, 0..) |one, at| {
            if (at != 0) try writer.writeAll(", ");
            try writer.writeAll(one);
        }
    }
};

const testing = std.testing;

/// Real answers from Determinate Nix 3.22.5, cut to the fields the reader uses.
const copied_answer =
    \\{"/nix/store/9j97md1vaj6c9d90rc95a8258q81s3i7-determinate-nix-3.22.5":
    \\{"narSize":4910840,"provenance":{"from":"http://cache.argama.nix","next":null,
    \\"type":"copied"},"ultimate":false}}
;

const built_answer =
    \\{"/nix/store/1bxx4mdiyy4yhryr9nzsv65zzw3fczqv-treefmt-check":
    \\{"provenance":{"buildHost":"zeta3a","drv":"i59sjmw9g4hlzl8nam62nbck7li1zzvv-treefmt-check.drv",
    \\"next":{"meta":{"description":"Check that the project tree is formatted"},
    \\"next":{"flakeOutput":"checks.aarch64-linux.formatting","next":null,"pure":true,
    \\"type":"flake"},"type":"derivation"},"output":"out","system":"aarch64-linux",
    \\"tags":{},"type":"build"}}}
;

const bare_answer =
    \\{"/nix/store/4qcjnnczmmavc5sx4fci6299bg8iiz85-bash-5.3p9":
    \\{"narSize":100,"provenance":null,"ultimate":false}}
;

test "an expectation that asks nothing reads nothing, so no answer is needed" {
    const nothing = Expectation{};
    try testing.expect(nothing.asksNothing());
    try testing.expectEqual(Verdict.allowed, try check(testing.allocator, nothing, "not json at all"));

    try testing.expect(!(Expectation{ .required = true }).asksNothing());
    try testing.expect(!(Expectation{ .from = &.{"https://cache.nixos.org"} }).asksNothing());
    try testing.expect(!(Expectation{ .built_by = &.{"zeta3a"} }).asksNothing());
}

test "a path that carries no provenance passes until the project asks for one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const asked_elsewhere = try check(arena, .{ .built_by = &.{"zeta3a"} }, bare_answer);
    try testing.expectEqual(Verdict.allowed, asked_elsewhere);

    const refused = try check(arena, .{ .required = true }, bare_answer);
    try testing.expectEqual(Fault.no_provenance, refused.refused.fault);
    try testing.expect(std.mem.endsWith(u8, refused.refused.path, "bash-5.3p9"));

    const said = try explain(arena, .{ .required = true }, refused.refused);
    try testing.expect(std.mem.indexOf(u8, said, "bash-5.3p9") != null);
    try testing.expect(std.mem.indexOf(u8, said, "older nix") != null);
}

test "a copy from a store the project does not name is refused, and the refusal names both" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const named = Expectation{ .from = &.{ "https://cache.nixos.org", "http://cache.argama.nix/" } };
    try testing.expectEqual(Verdict.allowed, try check(arena, named, copied_answer));

    const elsewhere = Expectation{ .from = &.{"https://cache.nixos.org"} };
    const refused = try check(arena, elsewhere, copied_answer);
    try testing.expectEqualStrings("http://cache.argama.nix", refused.refused.fault.copied_from);

    const said = try explain(arena, elsewhere, refused.refused);
    try testing.expect(std.mem.indexOf(u8, said, "http://cache.argama.nix") != null);
    try testing.expect(std.mem.indexOf(u8, said, "https://cache.nixos.org") != null);
}

test "a build is read through the whole chain, and the machine decides" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(
        Verdict.allowed,
        try check(arena, .{ .built_by = &.{ "zeta3a", "zeta3b" } }, built_answer),
    );
    try testing.expectEqual(Verdict.allowed, try check(arena, .{ .required = true }, built_answer));

    const refused = try check(arena, .{ .built_by = &.{"someone-else"} }, built_answer);
    try testing.expectEqualStrings("zeta3a", refused.refused.fault.built_by);

    // The build link sits outside a copy on a path that was substituted, so a
    // project that names both must have both answered.
    const both = Expectation{ .from = &.{"http://cache.argama.nix"}, .built_by = &.{"zeta3a"} };
    try testing.expectEqual(Verdict.allowed, try check(arena, both, built_answer));
    try testing.expectEqual(Verdict.allowed, try check(arena, both, copied_answer));
}

test "a build that names no machine is refused when the project names machines" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const anonymous =
        \\{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool":
        \\{"provenance":{"buildHost":null,"drv":"d.drv","next":null,"output":"out",
        \\"system":"aarch64-linux","tags":{},"type":"build"}}}
    ;

    const refused = try check(arena, .{ .built_by = &.{"zeta3a"} }, anonymous);
    try testing.expectEqual(Fault.build_host_unknown, refused.refused.fault);

    // Asking only that provenance exists is answered by this path: it has one.
    try testing.expectEqual(Verdict.allowed, try check(arena, .{ .required = true }, anonymous));
}

test "a path nix holds no record of is refused, and so is an answer it could not give" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const absent =
        \\{"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool":null}
    ;
    const unknown = try check(arena, .{ .required = true }, absent);
    try testing.expectEqual(Fault.path_unknown, unknown.refused.fault);

    const refused_flag = try check(
        arena,
        .{ .required = true },
        "error: unrecognised flag '--json-format'\n",
    );
    try testing.expectEqualStrings("", refused_flag.refused.path);
    const said = try explain(arena, .{ .required = true }, refused_flag.refused);
    try testing.expect(std.mem.indexOf(u8, said, "Determinate") != null);
    try testing.expect(std.mem.indexOf(u8, said, "unrecognised flag") != null);

    const empty = try check(arena, .{ .required = true }, "{}");
    try testing.expectEqual(std.meta.Tag(Fault).unreadable, std.meta.activeTag(empty.refused.fault));
}

test "a chain past the bound is refused rather than followed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(arena, "{\"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-tool\":{\"provenance\":");
    for (0..max_links + 1) |_| {
        try deep.appendSlice(arena, "{\"type\":\"copied\",\"from\":\"http://one\",\"next\":");
    }
    try deep.appendSlice(arena, "null");
    for (0..max_links + 1) |_| try deep.append(arena, '}');
    try deep.appendSlice(arena, "}}");

    const refused = try check(arena, .{ .from = &.{"http://one"} }, deep.items);
    try testing.expectEqual(Fault.chain_too_long, refused.refused.fault);
}

test "the query names a json format, and the flags end before the paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const paths = [_][]const u8{ "/nix/store/a-one", "/nix/store/b-two" };
    const args = try argsFor(arena, &paths);
    try testing.expectEqualStrings("path-info", args[0]);
    try testing.expectEqualStrings("/nix/store/a-one", args[args.len - 2]);
    try testing.expectEqualStrings("/nix/store/b-two", args[args.len - 1]);

    var found_terminator = false;
    for (args, 0..) |one, at| {
        if (!std.mem.eql(u8, one, "--")) continue;
        found_terminator = true;
        try testing.expectEqual(args.len - paths.len - 1, at);
    }
    try testing.expect(found_terminator);
    try testing.expect(std.mem.indexOf(u8, args[3], "1") != null);
}
