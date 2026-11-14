//! Recording the session's work as a commit. The loop holds no git of its own, so the
//! host supplies the one part it cannot do for itself.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

/// What the agent asked for, read out of the tool call. `paths` null takes every
/// change in the workspace.
pub const Ask = struct {
    message: []const u8,
    paths: ?[]const []const u8 = null,
};

pub const Made = struct {
    /// The new commit, as a full object id.
    id: []const u8,
    branch: []const u8,
    files: usize,
};

/// A refusal carries the sentence the agent reads, so the host says why in its own
/// words rather than handing back an error name.
pub const Answer = union(enum) {
    made: Made,
    refused: []const u8,
};

pub const Committer = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        commit: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            ask: Ask,
        ) Error!Answer,
    };

    pub fn commit(
        self: Committer,
        gpa: std.mem.Allocator,
        io: std.Io,
        ask: Ask,
    ) Error!Answer {
        return self.vtable.commit(self.ptr, gpa, io, ask);
    }
};

pub const has_no_committer = "nothing was committed: this session was started with no git " ++
    "workspace to commit into.";

pub const message_is_blank = "nothing was committed: a commit needs a message saying why the " ++
    "change was made. Write one line in the imperative, and a body after a blank line if the " ++
    "reason needs it.";

/// True when the message carries no word at all. A commit whose message is only spaces
/// and newlines reads, later, as a commit nobody explained.
pub fn messageIsBlank(message: []const u8) bool {
    return std.mem.trim(u8, message, " \t\r\n").len == 0;
}

pub fn pathLeavesProject(gpa: std.mem.Allocator, path: []const u8) Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "nothing was committed: \"{s}\" is outside the project, and a commit only records " ++
            "files inside it. Name the path as it sits under the project root.",
        .{path},
    );
}

pub fn textForModel(gpa: std.mem.Allocator, made: Made) Error![]u8 {
    return std.fmt.allocPrint(
        gpa,
        "committed {s} on {s}, {d} file{s} changed. It is on this session's branch only: " ++
            "nobody else sees it until the session is landed.",
        .{ made.id, made.branch, made.files, if (made.files == 1) "" else "s" },
    );
}

const testing = std.testing;

test "a message of spaces, tabs and newlines is blank, and one with a word is not" {
    try testing.expect(messageIsBlank(""));
    try testing.expect(messageIsBlank("   "));
    try testing.expect(messageIsBlank("\n\n"));
    try testing.expect(messageIsBlank(" \t\r\n "));
    try testing.expect(!messageIsBlank("fix the leak"));
    try testing.expect(!messageIsBlank("\n fix the leak \n"));
}

test "what the model reads names the commit, the branch and the count, and says it is unshared" {
    const text = try textForModel(testing.allocator, .{
        .id = "0123456789abcdef0123456789abcdef01234567",
        .branch = "chock/01S",
        .files = 2,
    });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "0123456789abcdef0123456789abcdef01234567") != null);
    try testing.expect(std.mem.indexOf(u8, text, "chock/01S") != null);
    try testing.expect(std.mem.indexOf(u8, text, "2 files changed") != null);
    try testing.expect(std.mem.indexOf(u8, text, "landed") != null);
}

test "one file reads as a file and not as files" {
    const text = try textForModel(testing.allocator, .{ .id = "abc", .branch = "b", .files = 1 });
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "1 file changed") != null);
}
