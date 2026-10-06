//! The VMM's filesystem allow list, held against the server it answers for.
//!
//! **A list written by hand cannot see a caller appearing in somebody else's
//! source.** `seccomp.fs_callers` names every `std.Io` call `mirage-fs`'s
//! `Export` makes and the syscall each one reaches, and `seccomp.zig`'s own test
//! checks that the filter permits all of them. Neither notices a version bump
//! that gives `Export` a caller nobody wrote a row for, and the symptom of that
//! is a guest that dies with an empty console.
//!
//! So this reads `Export.zig` itself, out of the dependency the build resolved.
//! A caller with no row fails this test, naming the call.
//!
//! **A failing test and not a compile error.** Reading the file at compile time
//! was the first version and it works, and it costs about 50 seconds of compile
//! time: the interpreter walks 130KB a byte at a time, which is 21 seconds on its
//! own before anything is read out of it. That is a tax on every build that
//! touches `chock-sandbox`, and `zig build test` and `zig build test-vmm` both
//! run this, so the bump is caught either way.
//!
//! **What it sees, and what it does not.** `Export` keeps its `std.Io` in a field
//! and every call the served filesystem makes goes through `self.io`, so that is
//! what this looks for. A call reached through an `io` handed in as a parameter is
//! not seen: `Export`'s own test harness does that, and a helper inside `Export`
//! could. This also builds only where Mirage does, which is Linux on x86_64 and
//! aarch64, so a build for anything else runs the other half alone.

const std = @import("std");
const seccomp = @import("chock-sandbox").seccomp;

/// `mirage-fs/Export.zig`, as the build hands it over. The dependency's own file
/// and not a copy of it, so a bump changes this text.
const served = @embedFile("mirage-fs-export");

/// How the server reaches a file.
const held_io = "self.io";

test "every call the guest's filesystem server makes has a row, and the filter permits it" {
    const gpa = std.testing.allocator;
    const text = try gpa.alloc(u8, served.len);
    defer gpa.free(text);
    blankComments(text, served);

    // **Named and not counted.** A reading that found nothing would otherwise
    // pass this whole test, which is the shape of silence the table itself was
    // written to break. These two are what a guest does before it does anything.
    var opened = false;
    var read = false;

    var at: usize = 0;
    while (std.mem.indexOfPos(u8, text, at, held_io)) |hit| {
        at = hit + held_io.len;
        // A longer field name ending in `self.io` is a different field.
        if (at < text.len and isNameByte(text[at])) continue;

        const name = calledAt(text, hit) orelse {
            const message = try std.fmt.allocPrint(
                gpa,
                "a `self.io` in `Export` at byte {d} is not an argument to a call," ++
                    " which this test cannot read\n",
                .{hit},
            );
            defer gpa.free(message);
            try std.testing.expectEqualStrings("", message);
            return error.CannotRead;
        };
        if (std.mem.eql(u8, name, "openFileAbsolute")) opened = true;
        if (std.mem.eql(u8, name, "readPositionalAll")) read = true;

        var row: ?seccomp.FilesystemCaller = null;
        for (seccomp.fs_callers) |each| {
            for (each.names) |held| {
                if (std.mem.eql(u8, held, name)) row = each;
            }
        }
        const held = row orelse {
            const message = try std.fmt.allocPrint(
                gpa,
                "`Export` calls {s} and `seccomp.fs_callers` has no row for it." ++
                    " Add one naming the syscall it reaches, and that syscall to" ++
                    " `vmm_calls`, or a row with no syscall if a served filesystem" ++
                    " never reaches it\n",
                .{name},
            );
            defer gpa.free(message);
            try std.testing.expectEqualStrings("", message);
            return error.CallerWithNoRow;
        };

        const call = held.call orelse continue;
        var permitted = false;
        for (seccomp.vmm_calls) |each| {
            if (each == call) permitted = true;
        }
        if (!permitted) {
            const message = try std.fmt.allocPrint(
                gpa,
                "`Export` calls {s}, which reaches {t}, and the VMM allow list does not hold it\n",
                .{ name, call },
            );
            defer gpa.free(message);
            try std.testing.expectEqualStrings("", message);
        }
    }

    try std.testing.expect(opened);
    try std.testing.expect(read);
}

test "a call is read by the name of the call and not by the receiver's" {
    // Against source of this test's own making, so the reading itself is proven:
    // the name in front of the bracket nothing has closed, over a comment, and
    // over as many lines as a call is written across.
    const sample =
        \\fn one(self: *Export) void {
        \\    // self.io.notACall(self.io) in a comment, with a bracket ) in it
        \\    const file = std.Io.Dir.openFileAbsolute(self.io, path, .{});
        \\    file.setLength(self.io, asked.size) catch {};
        \\    std.Io.Dir.cwd().hardLink(from, .cwd(), to, self.io, .{}) catch {};
        \\    std.Io.Dir.renameAbsolute(from, to, self.io) catch {};
        \\    const got = file.readPositionalAll(
        \\        self.io,
        \\        room[0..wanted],
        \\    ) catch 0;
        \\    _ = self.iota;
        \\}
    ;
    var room: [sample.len]u8 = undefined;
    blankComments(&room, sample);

    const wanted = [_][]const u8{
        "openFileAbsolute", "setLength", "hardLink", "renameAbsolute", "readPositionalAll",
    };

    var seen: usize = 0;
    var at: usize = 0;
    while (std.mem.indexOfPos(u8, &room, at, held_io)) |hit| {
        at = hit + held_io.len;
        if (at < room.len and isNameByte(room[at])) continue;
        try std.testing.expectEqualStrings(wanted[seen], calledAt(&room, hit).?);
        seen += 1;
    }
    try std.testing.expectEqual(wanted.len, seen);
}

fn isNameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

/// `text` into `out`, with every line comment turned into spaces, so a `self.io`
/// written in prose is not read as a call and a bracket in prose does not
/// unbalance the walk back. Blanked and not removed, so a byte is still at the
/// offset the file has it at.
///
/// A `//` inside a string literal blanks the rest of that line, which can only
/// hide a call and never invent one, and `Export` has no such literal.
fn blankComments(out: []u8, text: []const u8) void {
    std.debug.assert(out.len == text.len);
    var commented = false;
    for (text, 0..) |byte, at| {
        if (byte == '\n') commented = false;
        if (!commented and byte == '/' and at + 1 < text.len and text[at + 1] == '/') {
            commented = true;
        }
        out[at] = if (commented) ' ' else byte;
    }
}

/// The name of the call whose argument list holds `at`, by walking back to the
/// bracket nothing has closed and reading the name in front of it.
fn calledAt(text: []const u8, at: usize) ?[]const u8 {
    var depth: usize = 0;
    var i = at;
    while (i > 0) {
        i -= 1;
        switch (text[i]) {
            ')', ']', '}' => depth += 1,
            '(', '[', '{' => {
                if (depth > 0) {
                    depth -= 1;
                    continue;
                }
                if (text[i] != '(') return null;
                var start = i;
                while (start > 0 and isNameByte(text[start - 1])) start -= 1;
                if (start == i) return null;
                return text[start..i];
            },
            else => {},
        }
    }
    return null;
}
