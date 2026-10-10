//! Packs the browser interface into one file the binary carries.
//!
//! Each file is compressed on its own and the compressed bytes go into a tar.
//! The tar itself is not compressed, so `chock serve` reads the table once at
//! startup and hands each member straight to the browser with
//! `Content-Encoding: gzip`. Nothing is decompressed on the host.
//!
//! The caller names every member, because the list belongs to whoever built the
//! page. Phantom's `addWebDist` answers both the directory and the list, so a
//! file it adds or renames arrives here without this step guessing.

const std = @import("std");

const Bundle = @This();

/// One file of the page: the name a browser asks for, and where it is now.
pub const Member = struct {
    /// Relative to the page root, with `/` separators. This is the name
    /// `chock serve` matches a request against.
    name: []const u8,
    source: std.Build.LazyPath,
};

step: std.Build.Step,
members: []const Member,
output: std.Build.GeneratedFile,

/// The most one member may be. A page asset past this is a mistake rather than
/// a need, and the limit keeps the whole bundle in memory at build time.
const max_member_bytes: std.Io.Limit = .limited(16 * 1024 * 1024);

pub fn create(owner: *std.Build, members: []const Member) *Bundle {
    const self = owner.allocator.create(Bundle) catch @panic("OOM");
    self.* = .{
        .step = .init(.{
            .id = .custom,
            .name = "bundle the browser interface",
            .owner = owner,
            .makeFn = make,
        }),
        .members = owner.allocator.dupe(Member, members) catch @panic("OOM"),
        .output = .{ .step = &self.step },
    };
    for (self.members) |one| one.source.addStepDependencies(&self.step);
    return self;
}

/// Where the packed bundle lands, for `@embedFile` through an anonymous import.
pub fn path(self: *Bundle) std.Build.LazyPath {
    return .{ .generated = .{ .file = &self.output } };
}

fn make(step: *std.Build.Step, options: std.Build.Step.MakeOptions) anyerror!void {
    const b = step.owner;
    const io = b.graph.io;
    const gpa = options.gpa;
    const self: *Bundle = @fieldParentPtr("step", step);

    // A bundle with nothing in it would serve a blank page and report success.
    if (self.members.len == 0) return step.fail("the browser interface has no files", .{});

    var sink: std.Io.Writer.Allocating = try .initCapacity(gpa, 64 * 1024);
    defer sink.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &sink.writer };

    for (self.members) |one| {
        const from = one.source.getPath3(b, step);
        const raw = from.root_dir.handle.readFileAlloc(
            io,
            from.subPathOrDot(),
            gpa,
            max_member_bytes,
        ) catch |err| {
            return step.fail("the page's {s} could not be read: {t}", .{ one.name, err });
        };
        defer gpa.free(raw);

        const squeezed = try gzip(gpa, raw);
        defer gpa.free(squeezed);

        try tar.writeFileBytes(one.name, squeezed, .{});
    }
    try tar.finishPedantically();
    const packed_bytes = sink.written();

    var hash = b.graph.cache.hash;
    hash.addBytes(packed_bytes);
    const digest = hash.final();

    const sub = try std.fmt.allocPrint(b.allocator, "o/{s}/web.tar", .{&digest});
    const full = try b.cache_root.join(b.allocator, &.{sub});
    if (std.fs.path.dirname(full)) |parent| try std.Io.Dir.cwd().createDirPath(io, parent);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = full, .data = packed_bytes });
    self.output.path = full;
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
