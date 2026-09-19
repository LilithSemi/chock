//! Policy action names for the Nix tool: what a `nix build` or a `nix run`
//! call is named in the policy table, ahead of the tool itself.
//!
//! `Tool.runCommandActionInto` in `lib/chock-core/tools.zig` already turns a
//! path into a dotted action, and `Tool.writeSegmentEscaped` is the one thing
//! that makes that scheme a bijection: every dot and every percent sign a
//! real segment carries is escaped, so a plain dot in the built name is
//! always a boundary the builder wrote and never a byte a segment held. An
//! attribute path and a flake reference are dotted paths too, so this file
//! reuses that same escape rather than writing a second one.
//!
//! ## Why an attribute path needs escaping at all
//!
//! Nix lets an attribute name hold a dot, written quoted. `packages."a.b"`
//! is two attributes and `packages.a.b` is three, so a name that copied the
//! bytes through would write one action for both, and a rule aimed at one
//! would match the other.

const std = @import("std");

const tools = @import("tools.zig");

/// What every build action name starts with.
pub const build_prefix = "nix.build";

/// What every run action name starts with.
pub const run_prefix = "nix.run";

/// What the action for a named flake reference starts with. See
/// `flakeActionInto`.
pub const flake_prefix = "nix.build.flake";

/// The most segments this file turns into one action, for an attribute path
/// or for a split flake reference. Generous headroom over anything real:
/// `python312Packages.pytorchWithCuda.dev` is three segments deep, and even a
/// `git+https://host/deeply/nested/path` reference rarely passes six.
pub const max_segments = 16;

/// The longest single segment this file accepts, before it is escaped. An
/// attribute name or one piece of a flake reference stays far below this.
pub const max_segment_bytes = 128;

/// The largest action name any builder in this file can write. Sized for the
/// worst case any of them allows: the longest prefix, then every one of
/// `max_segments` segments at `max_segment_bytes`, every byte of it a dot, so
/// every byte becomes the three bytes `%2E`.
/// The cast is not decoration: `@max` of comptime integers answers the
/// smallest type that holds them, and the sum does not fit that.
pub const max_action_bytes: usize =
    @as(usize, @max(@max(build_prefix.len, run_prefix.len), flake_prefix.len)) +
    max_segments * (1 + 3 * max_segment_bytes);

/// The policy action for building `attr_path`, written into `buffer`. Null
/// when the path is empty, holds more than `max_segments` segments, holds a
/// segment longer than `max_segment_bytes`, or does not fit `buffer`.
///
/// ```
/// ["packages", "x86_64-linux", "default"]  ->  nix.build.packages.x86_64-linux.default
/// ```
///
/// **Every dot and every percent sign in a segment is escaped**, through
/// `Tool.writeSegmentEscaped`. A dot a segment itself holds, as the quoted
/// attribute `packages."foo.bar"` does, comes out as `%2E`, so
/// `["packages", "foo.bar"]` and `["packages", "foo", "bar"]` build two
/// different names, even though joining the raw bytes with a dot would write
/// the same name for both.
///
/// `buffer` must hold `max_action_bytes`.
pub fn buildActionInto(buffer: []u8, attr_path: []const []const u8) ?[]const u8 {
    return writeAction(buffer, build_prefix, attr_path);
}

/// The policy action for running `flake_ref`, written into `buffer`. Null for
/// the same reasons `buildActionInto` answers null.
///
/// ```
/// github:NixOS/nixpkgs  ->  nix.run.github.NixOS.nixpkgs
/// ```
///
/// `flake_ref` is split on `:` and `/` into dotted segments, each escaped the
/// same way `buildActionInto` escapes an attribute name.
///
/// **A revision or a fragment names content, not the repository, and is cut
/// off before anything is split.** `github:NixOS/nixpkgs?ref=some-branch` and
/// `github:NixOS/nixpkgs#hello` both build the same name a bare
/// `github:NixOS/nixpkgs` does. The policy row a project writes grants the
/// org or the repository, never a revision pinned in a query string or an
/// output named after `#`, so none of that belongs in the name the row is
/// written against.
///
/// `buffer` must hold `max_action_bytes`.
pub fn runActionInto(buffer: []u8, flake_ref: []const u8) ?[]const u8 {
    return referenceActionInto(buffer, run_prefix, flake_ref);
}

/// The policy action for building **from** `flake_ref`, written into
/// `buffer`. Null for the same reasons `runActionInto` answers null.
///
/// ```
/// github:NixOS/nixpkgs  ->  nix.build.flake.github.NixOS.nixpkgs
/// ```
///
/// **The second of the two questions a build that names a flake asks.** The
/// first is `buildActionInto`, which names the attribute path, and both must
/// be allowed before anything is built. One name holding both would not be a
/// name at all: two dotted paths joined into one are not injective, so a
/// reference of four segments with an attribute of two writes the same bytes
/// a reference of three with an attribute of three writes.
///
/// So the two are asked separately, which is the shape
/// `chock_core.mcp.networkActionInto` already has for a server that reaches
/// the network: one rule says the act is permitted and a second says where it
/// may go.
///
/// ```zon
/// .{ .action = "nix.build.packages.*", .decision = .allow },
/// .{ .action = "nix.build.flake.github.NixOS.*", .decision = .allow },
/// ```
///
/// The first alone authorises the project's own attributes and no foreign
/// flake, because a call that names one asks this as well and nobody wrote a
/// rule for it. The second alone authorises nothing either: an attribute the
/// project denied stays denied.
///
/// **A call that names no flake asks this at all.** It builds the workspace
/// the agent is already working in, which is the project itself, so the
/// attribute path is the whole question.
///
/// `buffer` must hold `max_action_bytes`.
pub fn flakeActionInto(buffer: []u8, flake_ref: []const u8) ?[]const u8 {
    return referenceActionInto(buffer, flake_prefix, flake_ref);
}

/// `prefix`, followed by the segments of `flake_ref`. One splitter for both
/// names a reference can carry, so the two cannot drift apart.
fn referenceActionInto(buffer: []u8, prefix: []const u8, flake_ref: []const u8) ?[]const u8 {
    const identity = identityPart(flake_ref);

    var segments: [max_segments][]const u8 = undefined;
    var count: usize = 0;

    var pieces = std.mem.tokenizeAny(u8, identity, ":/");
    while (pieces.next()) |piece| {
        if (count >= max_segments) return null;
        segments[count] = piece;
        count += 1;
    }

    return writeAction(buffer, prefix, segments[0..count]);
}

/// The part of `flake_ref` that names the repository, with a query string or
/// an output fragment dropped. See `runActionInto`'s own doc for why.
fn identityPart(flake_ref: []const u8) []const u8 {
    const cut = std.mem.indexOfAny(u8, flake_ref, "#?") orelse flake_ref.len;
    return flake_ref[0..cut];
}

/// The policy actions one `nix_build` call is asked about.
///
/// **Two names and not one**, for the reason `flakeActionInto` gives at
/// length: an attribute path and a flake reference are both dotted paths, and
/// one name built out of both would not tell them apart.
pub const Actions = struct {
    /// The attribute path, which every call has.
    attribute: []const u8,
    /// The flake reference, when the call named one. Null for a call that
    /// builds the workspace the agent is already working in.
    flake: ?[]const u8 = null,
};

/// The policy actions for one `nix_build` call, read from the arguments the
/// model sent. Null when the arguments do not parse, or when either name
/// cannot be built.
///
/// **Both must be allowed before anything is built.** An act nobody can name
/// is an act nobody can write a rule for, so an unnameable reference is
/// refused exactly as an unnameable attribute path is.
///
/// **The derivation is in neither name.** A derivation hash changes on every
/// edit of the Nix, so a rule keyed on one would be rewritten daily and would
/// become `nix.build.*` within a week. The row a person keeps answers whether
/// this agent may build this attribute, and from where.
///
/// `attribute_buffer` and `flake_buffer` must each hold `max_action_bytes`,
/// and each name is borrowed from its own buffer.
pub fn buildActionsFor(
    allocator: std.mem.Allocator,
    attribute_buffer: []u8,
    flake_buffer: []u8,
    arguments: []const u8,
) std.mem.Allocator.Error!?Actions {
    const parsed = std.json.parseFromSlice(
        tools.NixBuildArgs,
        allocator,
        arguments,
        .{ .ignore_unknown_fields = true },
    ) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        return null;
    };
    defer parsed.deinit();

    // Each name is copied into its buffer, so both outlive the parse above.
    const attribute = buildActionInto(attribute_buffer, parsed.value.attribute) orelse return null;
    const flake_ref = parsed.value.flake orelse return .{ .attribute = attribute };
    const flake = flakeActionInto(flake_buffer, flake_ref) orelse return null;
    return .{ .attribute = attribute, .flake = flake };
}

/// What a `nix_build` call gets when `buildActionsFor` could not name it. An
/// act nobody can name is an act nobody can write a rule for, so it does not
/// happen, and the sentence says what to send instead.
pub const unnamed_detail = "nothing was built: the call could not be named for this project's " ++
    "policy. Send \"attribute\" as a list with one name per entry, such as [\"packages\", " ++
    "\"x86_64-linux\", \"default\"], and send \"flake\", if you send it at all, as a plain " ++
    "reference such as \"github:NixOS/nixpkgs\".";

/// `prefix`, followed by one escaped dotted segment per entry of `segments`,
/// written into `buffer`. Null when `segments` is empty, holds more than
/// `max_segments` entries, holds a segment longer than `max_segment_bytes`,
/// or does not fit `buffer`.
fn writeAction(buffer: []u8, prefix: []const u8, segments: []const []const u8) ?[]const u8 {
    if (segments.len == 0 or segments.len > max_segments) return null;
    if (buffer.len < max_action_bytes) return null;

    var cursor: usize = 0;
    @memcpy(buffer[cursor..][0..prefix.len], prefix);
    cursor += prefix.len;

    for (segments) |segment| {
        if (segment.len == 0 or segment.len > max_segment_bytes) return null;
        buffer[cursor] = '.';
        cursor += 1;
        cursor = tools.Tool.writeSegmentEscaped(buffer, cursor, segment);
    }
    return buffer[0..cursor];
}

const testing = std.testing;

test "an attribute path builds a dotted build action" {
    var buffer: [max_action_bytes]u8 = undefined;
    const action = buildActionInto(&buffer, &.{ "packages", "x86_64-linux", "default" }).?;
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", action);
}

test "a flake reference builds a dotted run action" {
    var buffer: [max_action_bytes]u8 = undefined;
    const action = runActionInto(&buffer, "github:NixOS/nixpkgs").?;
    try testing.expectEqualStrings("nix.run.github.NixOS.nixpkgs", action);
}

test "an attribute name holding a dot is escaped so it cannot forge a level boundary" {
    // `packages."foo.bar"` is two segments, the second of which holds a
    // literal dot. A naive join would write the same bytes a three segment
    // path `packages.foo.bar` writes, and a rule aimed at one would then also
    // match the other.
    var buffer: [max_action_bytes]u8 = undefined;
    const action = buildActionInto(&buffer, &.{ "packages", "foo.bar" }).?;
    try testing.expectEqualStrings("nix.build.packages.foo%2Ebar", action);
}

test "two attribute paths that would collide unescaped build different names" {
    var with_a_dot: [max_action_bytes]u8 = undefined;
    var three_segments: [max_action_bytes]u8 = undefined;

    const from_with_a_dot = buildActionInto(&with_a_dot, &.{ "a.b", "c" }).?;
    const from_three_segments = buildActionInto(&three_segments, &.{ "a", "b", "c" }).?;

    try testing.expect(!std.mem.eql(u8, from_with_a_dot, from_three_segments));
}

test "a flake reference's revision and fragment are dropped, since a policy row grants the repository and never the content" {
    var bare: [max_action_bytes]u8 = undefined;
    var with_ref: [max_action_bytes]u8 = undefined;
    var with_fragment: [max_action_bytes]u8 = undefined;

    const bare_action = runActionInto(&bare, "github:NixOS/nixpkgs").?;
    const ref_action = runActionInto(&with_ref, "github:NixOS/nixpkgs?ref=some-branch").?;
    const fragment_action = runActionInto(&with_fragment, "github:NixOS/nixpkgs#hello").?;

    try testing.expectEqualStrings(bare_action, ref_action);
    try testing.expectEqualStrings(bare_action, fragment_action);
}

test "a call with no flake asks one action, named after its attribute path" {
    // The name a policy row is written against, read from the very JSON a
    // model sends. A project that builds its own flake writes one rule, and
    // this is the name that rule has to match.
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;

    const actions = (try buildActionsFor(std.testing.allocator, &attribute, &flake,
        \\{"attribute":["packages","x86_64-linux","default"]}
    )).?;
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", actions.attribute);
    // The whole question, because the flake is the project itself.
    try testing.expectEqual(@as(?[]const u8, null), actions.flake);
}

test "a call that names a flake asks a second action for the reference itself" {
    // The hole this closes: a rule a project wrote for its own attribute used
    // to authorise the same attribute of anybody's flake. Drop the second
    // name and that is true again.
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;

    const actions = (try buildActionsFor(std.testing.allocator, &attribute, &flake,
        \\{"attribute":["packages","x86_64-linux","default"],"flake":"github:evil/repo"}
    )).?;
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", actions.attribute);
    try testing.expectEqualStrings("nix.build.flake.github.evil.repo", actions.flake.?);

    // The attribute name is the same one the project's own call builds, so a
    // rule that allows it cannot tell the two apart. What tells them apart is
    // that only one of them asks the second question at all.
    var bare_attribute: [max_action_bytes]u8 = undefined;
    var bare_flake: [max_action_bytes]u8 = undefined;
    const bare = (try buildActionsFor(std.testing.allocator, &bare_attribute, &bare_flake,
        \\{"attribute":["packages","x86_64-linux","default"]}
    )).?;
    try testing.expectEqualStrings(bare.attribute, actions.attribute);
    try testing.expect(bare.flake == null);
}

test "a flake action drops a revision and a fragment, since the rule grants the repository" {
    // Read from the same splitter `runActionInto` uses, so the two names a
    // reference can carry cannot come to mean different repositories.
    var buffer: [max_action_bytes]u8 = undefined;
    var pinned: [max_action_bytes]u8 = undefined;

    const bare = flakeActionInto(&buffer, "github:NixOS/nixpkgs").?;
    try testing.expectEqualStrings("nix.build.flake.github.NixOS.nixpkgs", bare);

    const with_ref = flakeActionInto(&pinned, "github:NixOS/nixpkgs?ref=some-branch#hello").?;
    try testing.expectEqualStrings(bare, with_ref);
}

test "arguments that name no attribute path and a reference that cannot be named answer nothing" {
    // A dotted string is the shape a model reaches for, and it is refused
    // rather than split: an attribute name may itself hold a dot. A reference
    // nobody can name is refused for the reason an attribute path is.
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;
    const gpa = std.testing.allocator;

    const bad = [_][]const u8{
        "{\"attribute\":\"a.b\"}",
        "{\"attribute\":[]}",
        "not json",
        // A reference with nothing in it to split on.
        "{\"attribute\":[\"default\"],\"flake\":\"\"}",
        "{\"attribute\":[\"default\"],\"flake\":\"///\"}",
    };
    for (bad) |arguments| {
        try testing.expect(try buildActionsFor(gpa, &attribute, &flake, arguments) == null);
    }

    // And a good one really does answer, or every case above is vacuous.
    try testing.expect(try buildActionsFor(
        gpa,
        &attribute,
        &flake,
        "{\"attribute\":[\"default\"],\"flake\":\"github:NixOS/nixpkgs\"}",
    ) != null);
}

test "a buffer too small to hold the action answers null" {
    var too_small: [4]u8 = undefined;
    try testing.expect(buildActionInto(&too_small, &.{"default"}) == null);
    try testing.expect(runActionInto(&too_small, "github:NixOS/nixpkgs") == null);
}
