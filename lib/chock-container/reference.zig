//! What may be used as an image reference, and what may not.
//!
//! ## The project names the image. The model never does
//!
//! **This is the whole of the safety argument, and it is the same one
//! `lib/chock-nix/provision.zig` makes for a package name.** A reference comes
//! from the project's own configuration. Nothing a model says reaches this
//! function today, and the check below exists so that a future caller which
//! gets that wrong is refused rather than obeyed.
//!
//! A reference needs `/`, `:` and `@` to say what it means, so this rule
//! cannot refuse those three the way a Nix package name refuses them. What it
//! still refuses is every character that would turn a reference into
//! something other than a reference:
//!
//! * **No leading `-`**, so it cannot be read as an option by the runtime.
//! * **No whitespace**, so it is one argument and not several.
//! * **No `..`**, so it cannot be read as a walk out of a directory. A real
//!   reference never has one.
//! * **Nothing outside the allowed set**, so no shell metacharacter, no
//!   quote, and no control byte can be in it. The argument vector is passed
//!   to `execve` and never to a shell, so this is a second bound and not the
//!   only one.
//!
//! The worst a caller can then ask for is a repository that the registry does
//! not have. That answers with a plain refusal, which is the point.

const std = @import("std");

/// The longest reference this accepts. A real one is a domain, a path of a few
/// components, and a tag. This bounds a caller that sends a paragraph.
pub const max_bytes: usize = 512;

/// Why a reference was refused before any command was built.
pub const Error = error{
    /// The reference has no characters.
    ReferenceEmpty,
    /// The reference is longer than `max_bytes`.
    ReferenceTooLong,
    /// The reference holds a character an image reference may not have. See
    /// this file's own top comment for the list and the reason for each.
    ReferenceNotAnImage,
};

/// True when `character` may appear in an image reference.
///
/// Letters, digits, and `.`, `-`, `_`, `/`, `:`, `@`, `+`. The last five are
/// what a reference is built from: a registry host, a repository path, a tag,
/// and a digest.
fn isReferenceCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '.', '-', '_', '/', ':', '@', '+' => true,
        else => false,
    };
}

/// Check a reference against the rule this file's own top comment states.
pub fn check(text: []const u8) Error!void {
    if (text.len == 0) return error.ReferenceEmpty;
    if (text.len > max_bytes) return error.ReferenceTooLong;

    // The first character carries two rules at once. A leading `-` is an
    // option to every runtime, and a leading `/`, `:`, `.` or `@` names no
    // registry and no repository.
    if (!std.ascii.isAlphanumeric(text[0])) return error.ReferenceNotAnImage;

    // A reference that ends on a separator is a reference with a missing part:
    // an empty tag, an empty digest, or an empty repository component.
    switch (text[text.len - 1]) {
        '/', ':', '@', '.', '-', '_', '+' => return error.ReferenceNotAnImage,
        else => {},
    }

    for (text) |character| {
        if (!isReferenceCharacter(character)) return error.ReferenceNotAnImage;
    }

    // `..` is the shape that reads as a walk out of a directory. No real
    // reference has one, and this library writes the reference into a cache
    // directory name, so the rule is worth stating here as well as there.
    if (std.mem.indexOf(u8, text, "..") != null) return error.ReferenceNotAnImage;
}

/// One sentence saying why a reference was refused, for the person who wrote
/// it. The caller owns the result.
pub fn refusalText(
    allocator: std.mem.Allocator,
    text: []const u8,
    err: Error,
) std.mem.Allocator.Error![]u8 {
    return switch (err) {
        error.ReferenceEmpty => allocator.dupe(u8, "the image reference is empty"),
        error.ReferenceTooLong => std.fmt.allocPrint(
            allocator,
            "the image reference is longer than {d} bytes",
            .{max_bytes},
        ),
        error.ReferenceNotAnImage => std.fmt.allocPrint(
            allocator,
            "\"{s}\" is not an image reference. A reference is a repository and a tag, " ++
                "such as alpine:3.20 or ghcr.io/owner/name:1.2.",
            .{text},
        ),
    };
}

/// A name for `text` that is safe to use as one component of a directory
/// path. Every character outside the safe set becomes `_`, and the whole is
/// bounded. The caller owns the result.
///
/// **Not a reversible encoding, and it does not have to be.** The cache
/// directory this names holds a stamp with the image digest in it, and that
/// stamp is what decides whether the cache is current. This only has to be
/// stable for one reference and readable by a person looking at their own disk.
pub fn directoryName(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    const kept = @min(text.len, max_component_bytes);
    const name = try allocator.alloc(u8, kept);
    for (text[0..kept], 0..) |character, i| {
        name[i] = if (std.ascii.isAlphanumeric(character) or character == '.' or character == '-')
            character
        else
            '_';
    }
    return name;
}

/// The longest directory component `directoryName` produces. Most filesystems
/// refuse a component past 255 bytes, and a reference may be longer than that.
const max_component_bytes: usize = 128;

const testing = std.testing;

test "an ordinary reference is accepted in each of the shapes a person writes" {
    for ([_][]const u8{
        "alpine:3.20",
        "alpine",
        "ghcr.io/owner/name:1.2.3",
        "registry.example.com:5000/team/project/image:latest",
        "docker.io/library/debian@sha256:" ++ ("a" ** 64),
        "quay.io/org/tool_name:v1.0-rc1",
    }) |good| {
        // The reference is in the expectation, so a failure names which one
        // was refused without this test writing a line of its own.
        try testing.expectEqual(@as(anyerror!void, {}), check(good));
    }
}

test "a reference that could be read as an option is refused" {
    // The one that matters most. `--privileged` as a reference would become an
    // argument to the runtime rather than the thing it operates on.
    try testing.expectError(error.ReferenceNotAnImage, check("--privileged"));
    try testing.expectError(error.ReferenceNotAnImage, check("--rm"));
    try testing.expectError(error.ReferenceNotAnImage, check("-v"));
}

test "a reference holding a shell metacharacter, whitespace or a control byte is refused" {
    for ([_][]const u8{
        "alpine:3.20 --privileged",
        "alpine;rm",
        "alpine|cat",
        "alpine&",
        "alpine$(id)",
        "alpine`id`",
        "alpine\nsecond",
        "alpine\x00",
        "alpine\"quoted\"",
        "alpine'quoted'",
        "alpine#comment",
        "alpine\\escape",
    }) |bad| {
        try testing.expectEqual(
            @as(anyerror!void, error.ReferenceNotAnImage),
            check(bad),
        );
    }
}

test "a reference that walks out of a directory is refused" {
    try testing.expectError(error.ReferenceNotAnImage, check("a/../../etc/passwd"));
    try testing.expectError(error.ReferenceNotAnImage, check("alpine..3.20"));
}

test "an empty reference and one past the bound are refused by name" {
    try testing.expectError(error.ReferenceEmpty, check(""));

    const long = try testing.allocator.alloc(u8, max_bytes + 1);
    defer testing.allocator.free(long);
    @memset(long, 'a');
    try testing.expectError(error.ReferenceTooLong, check(long));
}

test "a reference that ends on a separator has a missing part and is refused" {
    // An empty tag and an empty digest are the two a person really types.
    try testing.expectError(error.ReferenceNotAnImage, check("alpine:"));
    try testing.expectError(error.ReferenceNotAnImage, check("alpine@"));
    try testing.expectError(error.ReferenceNotAnImage, check("ghcr.io/owner/"));
}

test "a refusal names the reference and says what a reference looks like" {
    const text = try refusalText(testing.allocator, "--privileged", error.ReferenceNotAnImage);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "--privileged") != null);
    try testing.expect(std.mem.indexOf(u8, text, "alpine:3.20") != null);
}

test "a directory name holds no separator, so a reference cannot reach another directory" {
    const name = try directoryName(testing.allocator, "ghcr.io/owner/name:1.2.3");
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("ghcr.io_owner_name_1.2.3", name);
    try testing.expect(std.mem.indexOfScalar(u8, name, '/') == null);
}

test "a directory name is bounded, because a filesystem component is" {
    const long = try testing.allocator.alloc(u8, max_bytes);
    defer testing.allocator.free(long);
    @memset(long, 'a');

    const name = try directoryName(testing.allocator, long);
    defer testing.allocator.free(name);
    try testing.expectEqual(max_component_bytes, name.len);
}
