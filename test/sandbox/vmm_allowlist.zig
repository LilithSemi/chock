//! The VMM's filesystem allow list, held against the server it answers for.
//! Reads `Export.zig` out of the dependency the build resolved, and fails naming
//! any `self.io` call that `seccomp.fs_callers` has no row for.

const std = @import("std");
const seccomp = @import("chock-sandbox").seccomp;

const served = @embedFile("mirage-fs-export");

const held_io = "self.io";

test "every call the guest's filesystem server makes has a row, and the filter permits it" {
    const gpa = std.testing.allocator;
    const text = try gpa.alloc(u8, served.len);
    defer gpa.free(text);
    blankComments(text, served);

    // A reading that found nothing would otherwise pass this whole test.
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
    // Proves the reading itself, over a comment and across several lines.
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

/// `text` into `out`, with every line comment blanked to spaces so a `self.io`
/// or bracket written in prose is never read as code.
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

/// The name of the call whose argument list holds `at`.
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
