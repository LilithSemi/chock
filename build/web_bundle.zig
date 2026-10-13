//! Packs the browser interface into one file the binary carries.
//!
//! Each file is compressed on its own and the compressed bytes go into a tar.
//! The tar itself is not compressed, so `chock serve` reads the table once at
//! startup and hands each member straight to the browser with
//! `Content-Encoding: gzip`. Nothing is decompressed on the host.
//!
//! A program and not a build step: Zig 0.17 closed `Step.Tag`, so a build
//! carries no code of its own. `build.zig` runs this the way it runs the other
//! generators, naming every member on the command line. The list belongs to
//! whoever built the page, and phantom's `addWebDist` answers it, so a file it
//! adds or renames arrives here without this guessing.
//!
//! usage: web-bundle <out> (<name> <path>)...

const std = @import("std");

/// The most one member may be. A page asset past this is a mistake rather than
/// a need, and the limit keeps the whole bundle in memory while it is built.
const max_member_bytes: std.Io.Limit = .limited(16 * 1024 * 1024);

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.arena.allocator();
    const io = init.io;

    const args = try init.minimal.args.toSlice(gpa);
    // The output, then a name and a path for each member.
    if (args.len < 4 or (args.len - 2) % 2 != 0) {
        std.debug.print("usage: web-bundle <out> (<name> <path>)...\n", .{});
        return 2;
    }
    const out_path = args[1];

    var sink: std.Io.Writer.Allocating = try .initCapacity(gpa, 64 * 1024);
    defer sink.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &sink.writer };

    var at: usize = 2;
    while (at < args.len) : (at += 2) {
        const name = args[at];
        const from = args[at + 1];
        const raw = std.Io.Dir.cwd().readFileAlloc(io, from, gpa, max_member_bytes) catch |err| {
            std.debug.print("the page's {s} could not be read at {s}: {t}\n", .{ name, from, err });
            return err;
        };
        const squeezed = try gzip(gpa, raw);
        try tar.writeFileBytes(name, squeezed, .{});
    }
    try tar.finishPedantically();

    if (std.fs.path.dirname(out_path)) |parent| {
        std.Io.Dir.cwd().createDirPath(io, parent) catch {};
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = sink.written() });
    return 0;
}

fn gzip(gpa: std.mem.Allocator, raw: []const u8) ![]u8 {
    // `Compress.init` wants room to write a header into, so the sink starts with
    // a buffer rather than growing from nothing.
    var sink: std.Io.Writer.Allocating = try .initCapacity(gpa, @max(raw.len / 2, 4096));
    errdefer sink.deinit();

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    // Best, because this runs once in a build and the bytes ship in every
    // binary from then on.
    var compress = try std.compress.flate.Compress.init(
        &sink.writer,
        &window,
        .gzip,
        std.compress.flate.Compress.Options.best,
    );
    try compress.writer.writeAll(raw);
    try compress.finish();

    var out = sink.toArrayList();
    return out.toOwnedSlice(gpa);
}
