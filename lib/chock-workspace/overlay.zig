//! The overlay backing for a project that is not a git repository, behind one
//! driver per way of building it. The two drivers share a result and not a
//! mechanism, and no caller needs a platform branch of its own.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const builtin = @import("builtin");
const layout_mod = @import("layout.zig");
pub const Layout = layout_mod.Layout;
const sandbox = @import("chock-sandbox");

pub const Mount = sandbox.namespace.Mount;

pub const Error = error{
    OutOfMemory,
    Unexpected,
    NoOverlayFilesystem,
    /// The scratch directory and the project are on different volumes, and
    /// neither driver can build an overlay across that line.
    ScratchOnAnotherVolume,
    ScratchAlreadyExists,
    NoOverlayToAdopt,
    WorkAlreadyCarriedOut,
};

pub const ChangeKind = enum {
    added,
    modified,
    /// The project had a file at this path, and the agent removed it, or
    /// replaced it with something that is not a file or a link.
    deleted,
};

pub const ChangedFile = struct {
    path: []u8,
    kind: ChangeKind,

    pub fn deinit(self: *ChangedFile, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn freeChangedFiles(allocator: std.mem.Allocator, list: []ChangedFile) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

pub const Skip = struct {
    path: []u8,
    reason: []u8,

    pub fn deinit(self: *Skip, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.reason);
        self.* = undefined;
    }
};

pub fn freeSkips(allocator: std.mem.Allocator, list: []Skip) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

pub const ChangeReport = struct {
    changed: []ChangedFile,
    skipped: []Skip,

    pub fn deinit(self: *ChangeReport, allocator: std.mem.Allocator) void {
        freeChangedFiles(allocator, self.changed);
        freeSkips(allocator, self.skipped);
        self.* = undefined;
    }
};

pub const NestedMount = struct {
    path: []u8,

    pub fn deinit(self: *NestedMount, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn freeNestedMounts(allocator: std.mem.Allocator, list: []NestedMount) void {
    for (list) |*item| item.deinit(allocator);
    allocator.free(list);
}

pub const CarriedOut = struct {
    files: usize,
    deleted: usize,
    skipped: usize,
};

pub const carried_files_name = "files";

pub const carried_deleted_name = "deleted";

pub const carried_skipped_name = "skipped";

pub const Overlay = struct {
    project: []u8,
    upper: []u8,
    work: []u8,
    merged: []u8,
    layout: Layout = Layout.forHost(),

    pub fn sandboxRoot(self: Overlay) []const u8 {
        return switch (self.layout) {
            .remapped => self.project,
            .in_place => self.upper,
        };
    }

    pub fn deinit(self: *Overlay, allocator: std.mem.Allocator) void {
        allocator.free(self.project);
        allocator.free(self.upper);
        allocator.free(self.work);
        allocator.free(self.merged);
        self.* = undefined;
    }

    /// Describe the overlay mount. This performs no mount of its own: it only
    /// builds the one entry `chock-sandbox`'s own `buildRoot` calls `mount(2)`
    /// for, with `userxattr` in the options, which a rootless overlay mount
    /// requires. Building the list needs no privilege and no namespace.
    pub fn mounts(self: Overlay, allocator: std.mem.Allocator) Error![]Mount {
        const list = allocator.alloc(Mount, 1) catch return error.OutOfMemory;
        list[0] = switch (self.layout) {
            .remapped => .{ .overlay = .{
                .lower = self.project,
                .upper = self.upper,
                .work = self.work,
                .target = self.project,
            } },
            // macOS has no overlayfs, so `darwin/overlay.zig` already made a
            // whole copy on write clone of the project at `upper`. There is
            // nothing to merge, so the one entry is the clone at its own path.
            .in_place => .{ .bind = .{
                .source = self.upper,
                .target = self.upper,
                .read_only = false,
            } },
        };
        return list;
    }

    pub fn changedFiles(
        self: Overlay,
        allocator: std.mem.Allocator,
        io: std.Io,
        diag: ?*?Diagnostic,
    ) Error!ChangeReport {
        return driver.changedFiles(self, allocator, io, diag);
    }

    /// Put the work of an overlay at `destination`, and answer what arrived.
    ///
    /// The work goes beside the project and never over it. A git project gets
    /// its work back at a ref, with nothing of the person's moved. A project
    /// with no git has no object store and no commit to go back to, so copying
    /// the upper layer over the project is the one way that can destroy work,
    /// and there is no approval here because the session has already ended. A
    /// patch carries no binary file, no symbolic link and no file mode, and a
    /// project with no git has no `git apply` either.
    ///
    /// A deletion is work, so it is carried as a name and never as an act.
    /// Absence in `<destination>/files` says nothing, because a path the
    /// session never touched is absent too, so every deleted path is written
    /// to `<destination>/deleted` and not one of them is applied.
    ///
    /// `error.WorkAlreadyCarriedOut` when anything is at `destination`, checked
    /// before a byte is read: merging into a directory that already holds a
    /// carry out would write over files a person may have edited, and there is
    /// no way to tell those apart. The upper layer is not changed, so a caller
    /// that meets the refusal names another destination and gets everything.
    pub fn carryOut(
        self: Overlay,
        allocator: std.mem.Allocator,
        io: std.Io,
        destination: []const u8,
        diag: ?*?Diagnostic,
    ) Error!CarriedOut {
        // First, and before the upper layer is opened at all: a refusal that
        // had already written half a directory is one a caller cannot act on.
        const occupied = std.Io.Dir.cwd().statFile(io, destination, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => {
                diagnostic.noteErr(diag, .carried_work_check, err);
                return error.Unexpected;
            },
        };
        if (occupied != null) return error.WorkAlreadyCarriedOut;

        var report = try self.changedFiles(allocator, io, diag);
        defer report.deinit(allocator);

        const files_root = std.fs.path.join(allocator, &.{ destination, carried_files_name }) catch return error.OutOfMemory;
        defer allocator.free(files_root);
        std.Io.Dir.cwd().createDirPath(io, files_root) catch |err| {
            diagnostic.noteErr(diag, .carried_work_mkdir, err);
            return error.Unexpected;
        };

        var deleted: std.ArrayList([]const u8) = .empty;
        defer deleted.deinit(allocator);
        var skipped: std.ArrayList([]u8) = .empty;
        defer {
            for (skipped.items) |line| allocator.free(line);
            skipped.deinit(allocator);
        }

        for (report.skipped) |one| {
            const line = std.fmt.allocPrint(allocator, "{s}: {s}", .{ one.path, one.reason }) catch return error.OutOfMemory;
            errdefer allocator.free(line);
            skipped.append(allocator, line) catch return error.OutOfMemory;
        }

        var carried: usize = 0;
        for (report.changed) |one| {
            if (one.kind == .deleted) {
                deleted.append(allocator, one.path) catch return error.OutOfMemory;
                continue;
            }
            if (try carryOne(allocator, io, self.upper, files_root, one.path, &skipped, diag)) carried += 1;
        }

        std.mem.sort([]const u8, deleted.items, {}, lessThanBytes);
        std.mem.sort([]u8, skipped.items, {}, lessThanBytesMutable);

        try writeLines(allocator, io, destination, carried_deleted_name, deleted.items, diag);
        try writeLinesMutable(allocator, io, destination, carried_skipped_name, skipped.items, diag);

        return .{ .files = carried, .deleted = deleted.items.len, .skipped = skipped.items.len };
    }
};

const driver = switch (builtin.os.tag) {
    .linux => @import("linux/overlay.zig"),
    .macos => @import("darwin/overlay.zig"),
    else => @compileError("chock-workspace: no overlay driver for target os " ++ @tagName(builtin.os.tag)),
};

pub fn create(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    return driver.create(allocator, io, project, scratch, diag);
}

pub fn createWithLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!Overlay {
    var made = try driver.create(allocator, io, project, scratch, diag);
    made.layout = layout;
    return made;
}

/// Take over the overlay of a session whose process has ended. Neither driver
/// makes an upper layer and neither copies anything.
///
/// This call never removes a thing it did not make. The upper layer holds work
/// nothing else has a copy of, so a failure part way through leaves every file
/// where it was.
pub fn adopt(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    diag: ?*?Diagnostic,
) Error!Overlay {
    return driver.adopt(allocator, io, project, scratch, diag);
}

pub fn adoptWithLayout(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    scratch: []const u8,
    layout: Layout,
    diag: ?*?Diagnostic,
) Error!Overlay {
    var taken = try driver.adopt(allocator, io, project, scratch, diag);
    taken.layout = layout;
    return taken;
}

pub fn scratchDirOnDisk(io: std.Io, absolute_path: []const u8, diag: ?*?Diagnostic) Error!bool {
    const found = std.Io.Dir.cwd().statFile(io, absolute_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => {
            diagnostic.noteErr(diag, .overlay_scratch_check, err);
            return error.Unexpected;
        },
    };
    return found.kind == .directory;
}

/// Copy one changed path out of `upper` into `files_root`. A symbolic link is
/// copied as a link and never as what it points at, because a link the agent
/// made can point outside the project.
///
/// A path that went away between `changedFiles` and this copy is recorded as a
/// skip rather than dropped.
fn carryOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    upper: []const u8,
    files_root: []const u8,
    relative: []const u8,
    skipped: *std.ArrayList([]u8),
    diag: ?*?Diagnostic,
) Error!bool {
    const source = std.fs.path.join(allocator, &.{ upper, relative }) catch return error.OutOfMemory;
    defer allocator.free(source);
    const target = std.fs.path.join(allocator, &.{ files_root, relative }) catch return error.OutOfMemory;
    defer allocator.free(target);

    const found = std.Io.Dir.cwd().statFile(io, source, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return try noteSkip(allocator, skipped, relative, "it went away while the work was being carried out"),
        else => {
            diagnostic.noteErr(diag, .carried_entry_stat, err);
            return error.Unexpected;
        },
    };

    switch (found.kind) {
        .file => {
            // `copyFile` carries the permissions of the source, so a script
            // the agent made executable is still executable here.
            std.Io.Dir.copyFileAbsolute(source, target, io, .{ .make_path = true }) catch |err| {
                diagnostic.noteErr(diag, .carried_file_copy, err);
                return error.Unexpected;
            };
            return true;
        },
        .sym_link => {
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const length = std.Io.Dir.readLinkAbsolute(io, source, &buffer) catch |err| {
                diagnostic.noteErr(diag, .carried_link_read, err);
                return error.Unexpected;
            };
            const parent = std.fs.path.dirname(target) orelse target;
            std.Io.Dir.cwd().createDirPath(io, parent) catch |err| {
                diagnostic.noteErr(diag, .carried_work_mkdir, err);
                return error.Unexpected;
            };
            // `cwd().symLink` and never `symLinkAbsolute`. The second asserts
            // its target is absolute, and a link an agent makes inside a
            // project is usually relative, so that call panics on the ordinary
            // case in a Debug or ReleaseSafe build.
            std.Io.Dir.cwd().symLink(io, buffer[0..length], target, .{}) catch |err| {
                diagnostic.noteErr(diag, .carried_link_write, err);
                return error.Unexpected;
            };
            return true;
        },
        // `changedFiles` reports a path as added or modified only for a file
        // or a link, so anything else changed kind since the walk.
        else => |other| {
            const reason = std.fmt.allocPrint(
                allocator,
                "it is a {s} now, and only a file or a link is carried",
                .{@tagName(other)},
            ) catch return error.OutOfMemory;
            defer allocator.free(reason);
            return try noteSkip(allocator, skipped, relative, reason);
        },
    }
}

fn noteSkip(
    allocator: std.mem.Allocator,
    skipped: *std.ArrayList([]u8),
    relative: []const u8,
    reason: []const u8,
) Error!bool {
    const line = std.fmt.allocPrint(allocator, "{s}: {s}", .{ relative, reason }) catch return error.OutOfMemory;
    errdefer allocator.free(line);
    skipped.append(allocator, line) catch return error.OutOfMemory;
    return false;
}

fn lessThanBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn lessThanBytesMutable(_: void, a: []u8, b: []u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn writeLines(
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: []const u8,
    name: []const u8,
    lines: []const []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (lines) |line| {
        text.appendSlice(allocator, line) catch return error.OutOfMemory;
        text.append(allocator, '\n') catch return error.OutOfMemory;
    }

    const path = std.fs.path.join(allocator, &.{ destination, name }) catch return error.OutOfMemory;
    defer allocator.free(path);
    var file = std.Io.Dir.createFileAbsolute(io, path, .{}) catch |err| {
        diagnostic.noteErr(diag, .carried_list_write, err);
        return error.Unexpected;
    };
    defer file.close(io);
    file.writeStreamingAll(io, text.items) catch |err| {
        diagnostic.noteErr(diag, .carried_list_write, err);
        return error.Unexpected;
    };
}

/// Zig has no implicit conversion from `[]const []u8` to `[]const []const u8`.
fn writeLinesMutable(
    allocator: std.mem.Allocator,
    io: std.Io,
    destination: []const u8,
    name: []const u8,
    lines: []const []u8,
    diag: ?*?Diagnostic,
) Error!void {
    var view: std.ArrayList([]const u8) = .empty;
    defer view.deinit(allocator);
    for (lines) |line| view.append(allocator, line) catch return error.OutOfMemory;
    return writeLines(allocator, io, destination, name, view.items, diag);
}

pub fn nestedMounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    project: []const u8,
    diag: ?*?Diagnostic,
) Error![]NestedMount {
    return driver.nestedMounts(allocator, io, project, diag);
}

test "the linux driver and the darwin driver expose the same public shape" {
    // Guarded on `builtin.os.tag`, a comptime known value, so the branch this
    // test does not take is never imported: `linux/overlay.zig`'s own syscalls
    // do not type check for Darwin.
    if (builtin.os.tag != .linux) return;

    const linux_driver = @import("linux/overlay.zig");
    const darwin_driver = @import("darwin/overlay.zig");

    const shape = .{ "create", "adopt", "changedFiles", "nestedMounts" };
    inline for (shape) |name| {
        if (!@hasDecl(linux_driver, name)) @compileError("linux overlay driver is missing " ++ name);
        if (!@hasDecl(darwin_driver, name)) @compileError("darwin overlay driver is missing " ++ name);
    }
}
