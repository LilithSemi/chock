//! Policy action names for the Nix tool: what a `nix build` call is named in
//! the policy table, ahead of the tool itself.

const std = @import("std");

const tools = @import("tools.zig");

pub const build_prefix = "nix.build";

pub const flake_prefix = "nix.build.flake";

pub const max_segments = 16;

pub const max_segment_bytes = 128;

pub const max_action_bytes: usize =
    @as(usize, @max(build_prefix.len, flake_prefix.len)) +
    max_segments * (1 + 3 * max_segment_bytes);

pub fn buildActionInto(buffer: []u8, attr_path: []const []const u8) ?[]const u8 {
    return writeAction(buffer, build_prefix, attr_path);
}

pub fn flakeActionInto(buffer: []u8, flake_ref: []const u8) ?[]const u8 {
    return referenceActionInto(buffer, flake_prefix, flake_ref);
}

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

fn identityPart(flake_ref: []const u8) []const u8 {
    const cut = std.mem.indexOfAny(u8, flake_ref, "#?") orelse flake_ref.len;
    return flake_ref[0..cut];
}

pub const Actions = struct {
    attribute: []const u8,
    flake: ?[]const u8 = null,
};

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

    const attribute = buildActionInto(attribute_buffer, parsed.value.attribute) orelse return null;
    const flake_ref = parsed.value.flake orelse return .{ .attribute = attribute };
    const flake = flakeActionInto(flake_buffer, flake_ref) orelse return null;
    return .{ .attribute = attribute, .flake = flake };
}

pub const unnamed_detail = "nothing was built: the call could not be named for this project's " ++
    "policy. Send \"attribute\" as a list with one name per entry, such as [\"packages\", " ++
    "\"x86_64-linux\", \"default\"], and send \"flake\", if you send it at all, as a plain " ++
    "reference such as \"github:NixOS/nixpkgs\".";

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

test "an attribute name holding a dot is escaped so it cannot forge a level boundary" {
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

    const bare_action = flakeActionInto(&bare, "github:NixOS/nixpkgs").?;
    const ref_action = flakeActionInto(&with_ref, "github:NixOS/nixpkgs?ref=some-branch").?;
    const fragment_action = flakeActionInto(&with_fragment, "github:NixOS/nixpkgs#hello").?;

    try testing.expectEqualStrings(bare_action, ref_action);
    try testing.expectEqualStrings(bare_action, fragment_action);
}

test "a call with no flake asks one action, named after its attribute path" {
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;

    const actions = (try buildActionsFor(std.testing.allocator, &attribute, &flake,
        \\{"attribute":["packages","x86_64-linux","default"]}
    )).?;
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", actions.attribute);
    try testing.expectEqual(@as(?[]const u8, null), actions.flake);
}

test "a call that names a flake asks a second action for the reference itself" {
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;

    const actions = (try buildActionsFor(std.testing.allocator, &attribute, &flake,
        \\{"attribute":["packages","x86_64-linux","default"],"flake":"github:evil/repo"}
    )).?;
    try testing.expectEqualStrings("nix.build.packages.x86_64-linux.default", actions.attribute);
    try testing.expectEqualStrings("nix.build.flake.github.evil.repo", actions.flake.?);

    var bare_attribute: [max_action_bytes]u8 = undefined;
    var bare_flake: [max_action_bytes]u8 = undefined;
    const bare = (try buildActionsFor(std.testing.allocator, &bare_attribute, &bare_flake,
        \\{"attribute":["packages","x86_64-linux","default"]}
    )).?;
    try testing.expectEqualStrings(bare.attribute, actions.attribute);
    try testing.expect(bare.flake == null);
}

test "a flake action drops a revision and a fragment, since the rule grants the repository" {
    var buffer: [max_action_bytes]u8 = undefined;
    var pinned: [max_action_bytes]u8 = undefined;

    const bare = flakeActionInto(&buffer, "github:NixOS/nixpkgs").?;
    try testing.expectEqualStrings("nix.build.flake.github.NixOS.nixpkgs", bare);

    const with_ref = flakeActionInto(&pinned, "github:NixOS/nixpkgs?ref=some-branch#hello").?;
    try testing.expectEqualStrings(bare, with_ref);
}

test "arguments that name no attribute path and a reference that cannot be named answer nothing" {
    var attribute: [max_action_bytes]u8 = undefined;
    var flake: [max_action_bytes]u8 = undefined;
    const gpa = std.testing.allocator;

    const bad = [_][]const u8{
        "{\"attribute\":\"a.b\"}",
        "{\"attribute\":[]}",
        "not json",
        "{\"attribute\":[\"default\"],\"flake\":\"\"}",
        "{\"attribute\":[\"default\"],\"flake\":\"///\"}",
    };
    for (bad) |arguments| {
        try testing.expect(try buildActionsFor(gpa, &attribute, &flake, arguments) == null);
    }

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
    try testing.expect(flakeActionInto(&too_small, "github:NixOS/nixpkgs") == null);
}
