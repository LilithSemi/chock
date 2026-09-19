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

/// The most segments this file turns into one action, for an attribute path
/// or for a split flake reference. Generous headroom over anything real:
/// `python312Packages.pytorchWithCuda.dev` is three segments deep, and even a
/// `git+https://host/deeply/nested/path` reference rarely passes six.
pub const max_segments = 16;

/// The longest single segment this file accepts, before it is escaped. An
/// attribute name or one piece of a flake reference stays far below this.
pub const max_segment_bytes = 128;

/// The largest action name `buildActionInto` or `runActionInto` can build.
/// Sized for the worst case either allows: every one of `max_segments`
/// segments at `max_segment_bytes`, every byte of it a dot, so every byte
/// becomes the three bytes `%2E`.
/// The cast is not decoration: `@max` of two comptime integers answers the
/// smallest type that holds them, which is `u4` here, and the sum does not
/// fit that.
pub const max_action_bytes: usize = @as(usize, @max(build_prefix.len, run_prefix.len)) +
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
    const identity = identityPart(flake_ref);

    var segments: [max_segments][]const u8 = undefined;
    var count: usize = 0;

    var pieces = std.mem.tokenizeAny(u8, identity, ":/");
    while (pieces.next()) |piece| {
        if (count >= max_segments) return null;
        segments[count] = piece;
        count += 1;
    }

    return writeAction(buffer, run_prefix, segments[0..count]);
}

/// The part of `flake_ref` that names the repository, with a query string or
/// an output fragment dropped. See `runActionInto`'s own doc for why.
fn identityPart(flake_ref: []const u8) []const u8 {
    const cut = std.mem.indexOfAny(u8, flake_ref, "#?") orelse flake_ref.len;
    return flake_ref[0..cut];
}

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

test "a buffer too small to hold the action answers null" {
    var too_small: [4]u8 = undefined;
    try testing.expect(buildActionInto(&too_small, &.{"default"}) == null);
    try testing.expect(runActionInto(&too_small, "github:NixOS/nixpkgs") == null);
}
