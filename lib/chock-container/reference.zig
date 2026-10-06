//! What may be used as an image reference, and what may not. The project
//! names the image, and no model input reaches this check yet.

const std = @import("std");

pub const max_bytes: usize = 512;

pub const Error = error{
    ReferenceEmpty,
    ReferenceTooLong,
    ReferenceNotAnImage,
};

fn isReferenceCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '.', '-', '_', '/', ':', '@', '+' => true,
        else => false,
    };
}

pub fn check(text: []const u8) Error!void {
    if (text.len == 0) return error.ReferenceEmpty;
    if (text.len > max_bytes) return error.ReferenceTooLong;

    // A leading `-` reads as an option to the runtime.
    if (!std.ascii.isAlphanumeric(text[0])) return error.ReferenceNotAnImage;

    // Ends on a separator: a missing tag, digest, or repository component.
    switch (text[text.len - 1]) {
        '/', ':', '@', '.', '-', '_', '+' => return error.ReferenceNotAnImage,
        else => {},
    }

    for (text) |character| {
        if (!isReferenceCharacter(character)) return error.ReferenceNotAnImage;
    }

    // `..` reads as a walk out of a directory.
    if (std.mem.indexOf(u8, text, "..") != null) return error.ReferenceNotAnImage;
}

/// The caller owns the result.
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

/// Not a reversible encoding.
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

/// Filesystems refuse a path component past 255 bytes.
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
        try testing.expectEqual(@as(anyerror!void, {}), check(good));
    }
}

test "a reference that could be read as an option is refused" {
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
