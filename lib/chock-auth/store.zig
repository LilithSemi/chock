//! The credential store: what `chock login` wrote, and one source the
//! credential lookup reads.

const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const config = @import("config.zig");
const lock = @import("lock.zig");
const darwin_status = @import("darwin/status.zig");
const secret_fault = @import("linux/secret_fault.zig");
const secretspec_driver = @import("secretspec.zig");

pub const index_file_name = "instances.zon";

pub const index_lock_name = "instances.lock";

pub const max_index_bytes: usize = 256 * 1024;

pub const reserved_prefix = "chock:";

pub fn nameIsReserved(name: []const u8) bool {
    return std.mem.startsWith(u8, name, reserved_prefix);
}

pub const IndexEntry = struct {
    name: []const u8,
    kind: []const u8,
    base_url: []const u8 = "",
    stored_ms: i64,
};

const IndexFile = struct {
    version: u32 = 1,
    instances: []const IndexEntry = &.{},
};

pub const Error = std.mem.Allocator.Error || error{
    StoreUnreadable,
    StoreUnwritable,
    StoreIsReadable,
    StoreCorrupt,
};

pub const Diagnostic = union(enum) {
    data_dir_not_made: Failed,
    index_unreadable: Failed,
    index_not_valid: NotValid,
    no_value_for_name: NoValueForName,
    write_failed: WriteFailed,
    store_is_busy: Busy,
    store_lock_unusable: Failed,
    name_is_reserved: []const u8,
    name_already_stored: NameAlreadyStored,
    credential_file_unreadable: Failed,
    credential_file_readable_by_others: ReadableByOthers,
    credential_file_not_valid: []const u8,
    keychain_refused: KeychainRefused,
    secret_service_refused: SecretServiceRefused,
    secretspec_refused: SecretSpecRefused,

    pub const Failed = struct {
        path: []const u8,
        err: anyerror,
    };

    pub const ReadableByOthers = struct {
        path: []const u8,
        mode: u32,
    };

    pub const NotValid = struct {
        path: []const u8,
        zon: std.zon.parse.Diagnostics,
    };

    pub const NoValueForName = struct {
        name: []const u8,
        kind: []const u8,
    };

    pub const NameAlreadyStored = struct {
        name: []const u8,
        kind: []const u8,
    };

    pub const Busy = struct {
        file: []const u8,
        seconds: i64,
    };

    pub const WriteFailed = struct {
        path: []const u8,
        step: Step,
        err: ?anyerror = null,
        link_target: ?[]const u8 = null,

        pub const Step = enum {
            in_the_nix_store,
            links_into_the_nix_store,
            name_too_long,
            create,
            set_mode,
            write,
            rename,
        };
    };

    pub const SecretSpecRefused = struct {
        verb: []const u8,
        fault: secretspec_driver.Fault,
        detail: ?[]u8,
    };

    pub const SecretServiceRefused = struct {
        verb: []const u8,
        name: []const u8,
        fault: secret_fault.Fault,
    };

    pub const KeychainRefused = struct {
        verb: []const u8,
        name: []const u8,
        status: darwin_status.OSStatus,
    };

    pub fn deinit(self: *Diagnostic, gpa: std.mem.Allocator) void {
        switch (self.*) {
            .data_dir_not_made, .store_is_busy => {},
            .index_unreadable, .credential_file_unreadable, .store_lock_unusable => |failure| gpa.free(failure.path),
            .credential_file_readable_by_others => |failure| gpa.free(failure.path),
            .index_not_valid => |*failure| {
                gpa.free(failure.path);
                failure.zon.deinit(gpa);
            },
            .no_value_for_name => |names| {
                gpa.free(names.name);
                gpa.free(names.kind);
            },
            .name_already_stored => |names| {
                gpa.free(names.name);
                gpa.free(names.kind);
            },
            .write_failed => |failure| {
                gpa.free(failure.path);
                if (failure.link_target) |target| gpa.free(target);
            },
            .credential_file_not_valid, .name_is_reserved => |text| gpa.free(text),
            .keychain_refused => |failure| gpa.free(failure.name),
            .secret_service_refused => |failure| gpa.free(failure.name),
            .secretspec_refused => |failure| if (failure.detail) |text| gpa.free(text),
        }
        self.* = undefined;
    }

    pub fn format(self: *const Diagnostic, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (self.*) {
            .data_dir_not_made => |failure| try writer.print(
                "making the data directory {s} failed: {s}",
                .{ failure.path, @errorName(failure.err) },
            ),
            .index_unreadable, .credential_file_unreadable => |failure| try writer.print(
                "reading {s} failed: {s}",
                .{ failure.path, @errorName(failure.err) },
            ),
            .index_not_valid => |*failure| try writer.print(
                "{s} is not valid:\n{f}",
                .{ failure.path, &failure.zon },
            ),
            .no_value_for_name => |names| try writer.print(
                "the credential store names the instance {s} and holds no value for it. " ++
                    "Run: chock login --provider {s} --name {s}",
                .{ names.name, names.kind, names.name },
            ),
            .write_failed => |failure| switch (failure.step) {
                .in_the_nix_store => try writer.print(
                    "{s} is in the Nix store, which is read only and readable by every user on this machine, " ++
                        "so Chock will not write a credential there",
                    .{failure.path},
                ),
                .links_into_the_nix_store => try writer.print(
                    "{s} is a symbolic link into the Nix store ({s}), so home-manager owns it: it is read only, " ++
                        "it is readable by every user on this machine, and it is replaced on the next activation. " ++
                        "Chock will not write a credential there",
                    .{ failure.path, failure.link_target orelse "" },
                ),
                .name_too_long => try writer.print(
                    "the path {s} is too long to write beside",
                    .{failure.path},
                ),
                .create => try writer.print(
                    "creating a temporary file beside {s} failed: {s}",
                    .{ failure.path, errName(failure.err) },
                ),
                .set_mode => try writer.print(
                    "setting the mode of the temporary file for {s} failed: {s}",
                    .{ failure.path, errName(failure.err) },
                ),
                .write => try writer.print(
                    "writing the temporary file for {s} failed: {s}",
                    .{ failure.path, errName(failure.err) },
                ),
                .rename => try writer.print(
                    "renaming the temporary file for {s} into place failed: {s}",
                    .{ failure.path, errName(failure.err) },
                ),
            },
            .store_is_busy => |busy| try writer.print(
                "another chock login is running and it still held {s} after {d} seconds, " ++
                    "so nothing was stored. Wait for it to finish and run this again",
                .{ busy.file, busy.seconds },
            ),
            .store_lock_unusable => |failure| try writer.print(
                "the lock file {s} could not be opened ({s}), so no store write could be made safe " ++
                    "against a second chock login",
                .{ failure.path, @errorName(failure.err) },
            ),
            .name_is_reserved => |name| try writer.print(
                "\"{s}\" starts with \"{s}\", which Chock keeps for its own names, so no provider " ++
                    "instance can be stored under it. Choose another --name",
                .{ name, reserved_prefix },
            ),
            .name_already_stored => |names| try writer.print(
                "there is already a credential named \"{s}\", stored as kind {s}, and this login " ++
                    "was given no name of its own, so nothing was stored",
                .{ names.name, names.kind },
            ),
            .credential_file_not_valid => |path| try writer.print(
                "{s} is not valid, so no credential can be read from it",
                .{path},
            ),
            .credential_file_readable_by_others => |failure| try writer.print(
                "the credential file {s} has mode {o:0>4}, and a credential must be readable by its owner only. " ++
                    "Run: chmod 600 {s}",
                .{ failure.path, failure.mode, failure.path },
            ),
            .secretspec_refused => |failure| {
                try writer.print(
                    "secretspec would not {s} the credential",
                    .{if (std.mem.eql(u8, failure.verb, storing_verb)) "keep" else "give"},
                );
                if (failure.detail) |text| try writer.print(": {s}", .{text});
                if (secretspec_driver.adviceFor(failure.fault)) |advice| {
                    try writer.print(". {s}", .{advice});
                }
            },
            .secret_service_refused => |failure| {
                try writer.print(
                    "the secret service would not {s} the credential for {s}",
                    .{
                        if (std.mem.eql(u8, failure.verb, storing_verb)) "keep" else "give",
                        failure.name,
                    },
                );
                if (secret_fault.adviceFor(failure.fault)) |advice| {
                    try writer.print(": {s}", .{advice});
                }
            },
            .keychain_refused => |failure| {
                const storing = std.mem.eql(u8, failure.verb, storing_verb);
                try writer.print(
                    "the Keychain would not {s} the credential for {s}, and answered {d}",
                    .{ if (storing) "keep" else "give", failure.name, failure.status },
                );
                if (darwin_status.adviceFor(failure.status)) |advice| {
                    try writer.print(": {s}", .{advice});
                }
            },
        }
    }
};

pub const reading_verb = "reading";
pub const storing_verb = "storing";

fn errName(err: ?anyerror) []const u8 {
    return if (err) |e| @errorName(e) else "no reason given";
}

pub fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

pub fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

pub const Secrets = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        get: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            name: []const u8,
            diag: ?*?Diagnostic,
        ) Error!?[]u8,
        put: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            name: []const u8,
            value: []const u8,
            diag: ?*?Diagnostic,
        ) Error!void,
    };

    pub fn get(
        self: Secrets,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?Diagnostic,
    ) Error!?[]u8 {
        return self.vtable.get(self.ptr, gpa, io, name, diag);
    }

    pub fn put(
        self: Secrets,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?Diagnostic,
    ) Error!void {
        return self.vtable.put(self.ptr, gpa, io, name, value, diag);
    }
};

const driver_impl = switch (builtin.os.tag) {
    .linux, .macos => @import("driver.zig"),
    else => @compileError("chock-auth: no credential driver for target os " ++ @tagName(builtin.os.tag)),
};

pub const Driver = driver_impl.Driver;

pub const Stored = struct {
    gpa: std.mem.Allocator,
    name: []u8,
    kind: []u8,
    base_url: []u8,
    stored_ms: i64,
    token: []u8,

    pub fn deinit(self: *Stored) void {
        self.gpa.free(self.name);
        self.gpa.free(self.kind);
        self.gpa.free(self.base_url);
        // A freed but unzeroed credential is still readable in a crash dump, a swapped page, or a reused allocation, the same reason Client.zig zeroes its own Authorization header before freeing it.
        std.crypto.secureZero(u8, self.token);
        self.gpa.free(self.token);
        self.* = undefined;
    }
};

pub const NewEntry = struct {
    name: []const u8,
    kind: config.Kind,
    base_url: []const u8 = "",
    token: []const u8,
    stored_ms: i64,
    replace_existing: bool = true,
};

pub const Store = struct {
    data_dir: []const u8,
    secrets: Secrets,

    pub fn get(
        self: Store,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?Diagnostic,
    ) Error!?Stored {
        var index = try self.readIndex(gpa, io, diag);
        defer index.deinit(gpa);

        const entry = index.find(name) orelse return null;
        const token = try self.secrets.get(gpa, io, name, diag) orelse {
            if (wantsDiagnostic(diag)) {
                const name_copy = try gpa.dupe(u8, name);
                errdefer gpa.free(name_copy);
                const kind_copy = try gpa.dupe(u8, entry.kind);
                _ = note(diag, .{ .no_value_for_name = .{
                    .name = name_copy,
                    .kind = kind_copy,
                } });
            }
            return error.StoreCorrupt;
        };
        errdefer {
            std.crypto.secureZero(u8, token);
            gpa.free(token);
        }

        const owned_name = try gpa.dupe(u8, entry.name);
        errdefer gpa.free(owned_name);
        const owned_kind = try gpa.dupe(u8, entry.kind);
        errdefer gpa.free(owned_kind);
        const owned_url = try gpa.dupe(u8, entry.base_url);

        return .{
            .gpa = gpa,
            .name = owned_name,
            .kind = owned_kind,
            .base_url = owned_url,
            .stored_ms = entry.stored_ms,
            .token = token,
        };
    }

    pub fn put(
        self: Store,
        gpa: std.mem.Allocator,
        io: std.Io,
        entry: NewEntry,
        diag: ?*?Diagnostic,
    ) Error!void {
        // A name Chock reserves for itself is refused before the directory is even made, because the store must never write it at all.
        if (nameIsReserved(entry.name)) {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .name_is_reserved = try gpa.dupe(u8, entry.name) });
            }
            return error.StoreUnwritable;
        }

        try self.ensureDataDir(io, diag);

        // The lock taken here spans the credential and the index together, so two logins can never each read the same index and write back a copy missing the other's entry. The driver's own lock nests inside this one and never the other way, so the two can never wait on each other.
        var held = try takeStoreLock(gpa, io, self.data_dir, index_lock_name, diag);
        defer held.release(io);

        var index = try self.readIndex(gpa, io, diag);
        defer index.deinit(gpa);

        // The existing entry is checked before the driver is touched, so a refusal here leaves the credential it is protecting untouched.
        if (!entry.replace_existing) {
            if (index.find(entry.name)) |existing| {
                if (wantsDiagnostic(diag)) {
                    const name_copy = try gpa.dupe(u8, entry.name);
                    errdefer gpa.free(name_copy);
                    const kind_copy = try gpa.dupe(u8, existing.kind);
                    _ = note(diag, .{ .name_already_stored = .{
                        .name = name_copy,
                        .kind = kind_copy,
                    } });
                }
                return error.StoreUnwritable;
            }
        }

        // The value is written before the index entry: an index entry with no value is the corrupt case get already handles, and a value with no entry just reads back as not logged in.
        try self.secrets.put(gpa, io, entry.name, entry.token, diag);

        var list: std.ArrayList(IndexEntry) = .empty;
        defer list.deinit(gpa);
        for (index.entries()) |existing| {
            if (std.mem.eql(u8, existing.name, entry.name)) continue;
            try list.append(gpa, existing);
        }
        try list.append(gpa, .{
            .name = entry.name,
            .kind = entry.kind.wireName(),
            .base_url = entry.base_url,
            .stored_ms = entry.stored_ms,
        });

        try self.writeIndex(gpa, io, list.items, diag);
    }

    fn indexPath(self: Store, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        return std.fs.path.join(gpa, &.{ self.data_dir, index_file_name });
    }

    fn ensureDataDir(self: Store, io: std.Io, diag: ?*?Diagnostic) Error!void {
        return ensureDir(io, self.data_dir, diag);
    }

    fn readIndex(self: Store, gpa: std.mem.Allocator, io: std.Io, diag: ?*?Diagnostic) Error!Index {
        const path = try self.indexPath(gpa);
        defer gpa.free(path);

        const source = std.Io.Dir.cwd().readFileAllocOptions(
            io,
            path,
            gpa,
            .limited(max_index_bytes),
            .of(u8),
            0,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.FileNotFound, error.NotDir => return .{ .file = .{} },
            else => {
                if (wantsDiagnostic(diag)) {
                    _ = note(diag, .{ .index_unreadable = .{
                        .path = try gpa.dupe(u8, path),
                        .err = err,
                    } });
                }
                return error.StoreUnreadable;
            },
        };
        defer gpa.free(source);

        var diagnostics: std.zon.parse.Diagnostics = .{};
        var diagnostics_owned = true;
        defer if (diagnostics_owned) diagnostics.deinit(gpa);
        const file = std.zon.parse.fromSliceAlloc(IndexFile, gpa, source, &diagnostics, .{
            .ignore_unknown_fields = true,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseZon => {
                if (wantsDiagnostic(diag)) {
                    const path_copy = try gpa.dupe(u8, path);
                    if (note(diag, .{ .index_not_valid = .{
                        .path = path_copy,
                        .zon = diagnostics,
                    } })) {
                        diagnostics_owned = false;
                    } else {
                        gpa.free(path_copy);
                    }
                }
                return error.StoreCorrupt;
            },
        };
        return .{ .file = file, .owned = true };
    }

    fn writeIndex(
        self: Store,
        gpa: std.mem.Allocator,
        io: std.Io,
        entries: []const IndexEntry,
        diag: ?*?Diagnostic,
    ) Error!void {
        const path = try self.indexPath(gpa);
        defer gpa.free(path);

        const text = try serializeZon(gpa, IndexFile{ .version = 1, .instances = entries });
        defer gpa.free(text);

        try writePrivateFile(gpa, io, path, text, diag);
    }
};

pub fn ensureDir(io: std.Io, data_dir: []const u8, diag: ?*?Diagnostic) Error!void {
    makeDirAll(io, data_dir, 0o700) catch |err| {
        _ = note(diag, .{ .data_dir_not_made = .{ .path = data_dir, .err = err } });
        return error.StoreUnwritable;
    };
}

pub fn takeStoreLock(
    gpa: std.mem.Allocator,
    io: std.Io,
    data_dir: []const u8,
    lock_name: []const u8,
    diag: ?*?Diagnostic,
) Error!lock.Held {
    switch (lock.take(io, data_dir, lock_name, .{})) {
        .held => |held| return held,
        .busy => |seconds| {
            _ = note(diag, .{ .store_is_busy = .{ .file = lock_name, .seconds = seconds } });
            return error.StoreUnwritable;
        },
        .unusable => |err| {
            if (wantsDiagnostic(diag)) {
                const path = try std.fs.path.join(gpa, &.{ data_dir, lock_name });
                if (!note(diag, .{ .store_lock_unusable = .{ .path = path, .err = err } })) gpa.free(path);
            }
            return error.StoreUnwritable;
        },
    }
}

pub fn serializeZon(gpa: std.mem.Allocator, value: anytype) Error![]u8 {
    var allocating = std.Io.Writer.Allocating.init(gpa);
    errdefer allocating.deinit();
    std.zon.stringify.serialize(value, .{}, &allocating.writer) catch return error.OutOfMemory;
    allocating.writer.writeByte('\n') catch return error.OutOfMemory;
    return allocating.toOwnedSlice();
}

const Index = struct {
    file: IndexFile,
    owned: bool = false,

    fn deinit(self: *Index, gpa: std.mem.Allocator) void {
        if (self.owned) std.zon.parse.free(gpa, self.file);
        self.* = undefined;
    }

    fn entries(self: *const Index) []const IndexEntry {
        return self.file.instances;
    }

    fn find(self: *const Index, name: []const u8) ?IndexEntry {
        for (self.file.instances) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry;
        }
        return null;
    }
};

pub fn writePrivateFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    contents: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_fault: ?paths.Diagnostic = null;
    paths.refuseNixStore(io, path, &link_buffer, &path_fault) catch {
        // The path and the link target point at memory this function and its caller release, so the diagnostic keeps copies of both rather than pointers into them.
        if (path_fault) |fault| try noteNixStore(gpa, diag, path, fault);
        return error.StoreUnwritable;
    };

    // The temporary file carries this process's own number, so two logins writing at once never share one inode and mix their writes into a file that parses as neither credential.
    var temp_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const temp_path = std.fmt.bufPrint(
        &temp_buffer,
        "{s}.{d}.new",
        .{ path, std.posix.system.getpid() },
    ) catch {
        try noteWriteStep(gpa, diag, path, .name_too_long, null);
        return error.StoreUnwritable;
    };

    write: {
        var file = std.Io.Dir.createFileAbsolute(io, temp_path, .{
            .truncate = true,
            .permissions = .fromMode(0o600),
        }) catch |err| {
            try noteWriteStep(gpa, diag, path, .create, err);
            return error.StoreUnwritable;
        };
        defer file.close(io);

        file.setPermissions(io, .fromMode(0o600)) catch |err| {
            try noteWriteStep(gpa, diag, path, .set_mode, err);
            break :write;
        };
        file.writeStreamingAll(io, contents) catch |err| {
            try noteWriteStep(gpa, diag, path, .write, err);
            break :write;
        };
        std.Io.Dir.renameAbsolute(temp_path, path, io) catch |err| {
            try noteWriteStep(gpa, diag, path, .rename, err);
            break :write;
        };
        return;
    }

    std.Io.Dir.deleteFileAbsolute(io, temp_path) catch {};
    return error.StoreUnwritable;
}

fn noteWriteStep(
    gpa: std.mem.Allocator,
    diag: ?*?Diagnostic,
    path: []const u8,
    step: Diagnostic.WriteFailed.Step,
    err: ?anyerror,
) std.mem.Allocator.Error!void {
    if (!wantsDiagnostic(diag)) return;
    _ = note(diag, .{ .write_failed = .{
        .path = try gpa.dupe(u8, path),
        .step = step,
        .err = err,
    } });
}

fn noteNixStore(
    gpa: std.mem.Allocator,
    diag: ?*?Diagnostic,
    path: []const u8,
    fault: paths.Diagnostic,
) std.mem.Allocator.Error!void {
    if (!wantsDiagnostic(diag)) return;
    switch (fault) {
        .in_the_nix_store => try noteWriteStep(gpa, diag, path, .in_the_nix_store, null),
        .links_into_the_nix_store => |link| {
            const path_copy = try gpa.dupe(u8, path);
            errdefer gpa.free(path_copy);
            const target_copy = try gpa.dupe(u8, link.target);
            _ = note(diag, .{ .write_failed = .{
                .path = path_copy,
                .step = .links_into_the_nix_store,
                .link_target = target_copy,
            } });
        },
        .stat_failed, .readable_by_others => unreachable,
    }
}

fn makeDirAll(io: std.Io, path: []const u8, mode: std.posix.mode_t) !void {
    if (path.len == 0) return;
    std.Io.Dir.createDirAbsolute(io, path, .fromMode(mode)) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        error.FileNotFound => {
            const parent = std.fs.path.dirname(path) orelse return err;
            try makeDirAll(io, parent, mode);
            std.Io.Dir.createDirAbsolute(io, path, .fromMode(mode)) catch |second| switch (second) {
                error.PathAlreadyExists => return,
                else => return second,
            };
        },
        else => return err,
    };
}

const testing = std.testing;

const MemorySecrets = struct {
    gpa: std.mem.Allocator,
    names: std.ArrayList([]u8) = .empty,
    values: std.ArrayList([]u8) = .empty,

    fn deinit(self: *MemorySecrets) void {
        for (self.names.items) |name| self.gpa.free(name);
        for (self.values.items) |value| self.gpa.free(value);
        self.names.deinit(self.gpa);
        self.values.deinit(self.gpa);
    }

    fn secrets(self: *MemorySecrets) Secrets {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn getFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        diag: ?*?Diagnostic,
    ) Error!?[]u8 {
        _ = io;
        _ = diag;
        const self: *MemorySecrets = @ptrCast(@alignCast(ptr));
        for (self.names.items, self.values.items) |stored, value| {
            if (std.mem.eql(u8, stored, name)) return try gpa.dupe(u8, value);
        }
        return null;
    }

    fn putFn(
        ptr: *anyopaque,
        gpa: std.mem.Allocator,
        io: std.Io,
        name: []const u8,
        value: []const u8,
        diag: ?*?Diagnostic,
    ) Error!void {
        _ = gpa;
        _ = io;
        _ = diag;
        const self: *MemorySecrets = @ptrCast(@alignCast(ptr));
        for (self.names.items, self.values.items, 0..) |stored, old, index| {
            if (!std.mem.eql(u8, stored, name)) continue;
            self.gpa.free(old);
            self.values.items[index] = try self.gpa.dupe(u8, value);
            return;
        }
        try self.names.append(self.gpa, try self.gpa.dupe(u8, name));
        try self.values.append(self.gpa, try self.gpa.dupe(u8, value));
    }

    const vtable = Secrets.VTable{ .get = getFn, .put = putFn };
};

fn tmpDirPath(buffer: []u8, tmp: std.testing.TmpDir) ![]const u8 {
    const len = try tmp.dir.realPath(testing.io, buffer);
    return buffer[0..len];
}

test "the store round trips two instances of one kind under different names" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    try store.put(gpa, testing.io, .{
        .name = "work",
        .kind = .aiand,
        .token = "sk-work-not-a-real-key",
        .stored_ms = 1_700_000_000_000,
    }, null);
    try store.put(gpa, testing.io, .{
        .name = "personal",
        .kind = .aiand,
        .token = "sk-personal-not-a-real-key",
        .stored_ms = 1_700_000_000_001,
    }, null);

    var work = (try store.get(gpa, testing.io, "work", null)).?;
    defer work.deinit();
    var personal = (try store.get(gpa, testing.io, "personal", null)).?;
    defer personal.deinit();

    try testing.expectEqualStrings("sk-work-not-a-real-key", work.token);
    try testing.expectEqualStrings("sk-personal-not-a-real-key", personal.token);
    try testing.expectEqualStrings("aiand", work.kind);
    try testing.expectEqualStrings("aiand", personal.kind);
    try testing.expectEqual(@as(i64, 1_700_000_000_001), personal.stored_ms);
}

test "a missing store is not logged in, and not an error" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const missing = try std.fs.path.join(gpa, &.{ dir, "never", "made" });
    defer gpa.free(missing);
    const store = Store{ .data_dir = missing, .secrets = memory.secrets() };

    try testing.expect((try store.get(gpa, testing.io, "aiand", null)) == null);
}

test "storing the same name again replaces it rather than adding a second entry" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    try store.put(gpa, testing.io, .{ .name = "aiand", .kind = .aiand, .token = "sk-old", .stored_ms = 1 }, null);
    try store.put(gpa, testing.io, .{ .name = "aiand", .kind = .aiand, .token = "sk-new", .stored_ms = 2 }, null);

    var index = try store.readIndex(gpa, testing.io, null);
    defer index.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), index.entries().len);

    var stored = (try store.get(gpa, testing.io, "aiand", null)).?;
    defer stored.deinit();
    try testing.expectEqualStrings("sk-new", stored.token);
}

test "a provider stored under a name Chock keeps for itself is refused, and nothing is written" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    const taken = reserved_prefix ++ "seal-key-v1";
    try memory.secrets().put(gpa, testing.io, taken, "the-secret", null);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.StoreUnwritable,
        store.put(gpa, testing.io, .{
            .name = taken,
            .kind = .aiand,
            .token = "sk-mine",
            .stored_ms = 1,
        }, &diag),
    );

    const still_there = (try memory.secrets().get(gpa, testing.io, taken, null)).?;
    defer gpa.free(still_there);
    try testing.expectEqualStrings("the-secret", still_there);
    var index = try store.readIndex(gpa, testing.io, null);
    defer index.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), index.entries().len);

    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    try diag.?.format(&text.writer);
    try testing.expect(std.mem.indexOf(u8, text.written(), taken) != null);
    try testing.expect(std.mem.indexOf(u8, text.written(), "another --name") != null);

    try store.put(gpa, testing.io, .{ .name = "work", .kind = .aiand, .token = "sk-ok", .stored_ms = 2 }, null);
    var stored = (try store.get(gpa, testing.io, "work", null)).?;
    defer stored.deinit();
    try testing.expectEqualStrings("sk-ok", stored.token);
}

test "an index entry whose value is gone is reported, never read back as not logged in" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };
    try store.put(gpa, testing.io, .{ .name = "aiand", .kind = .aiand, .token = "sk-value", .stored_ms = 1 }, null);

    gpa.free(memory.names.items[0]);
    memory.names.items[0] = try gpa.dupe(u8, "some-other-name");

    try testing.expectError(error.StoreCorrupt, store.get(gpa, testing.io, "aiand", null));
}

test "the index file Chock writes is readable by its owner only" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const nested = try std.fs.path.join(gpa, &.{ dir, "share", "chock" });
    defer gpa.free(nested);
    const store = Store{ .data_dir = nested, .secrets = memory.secrets() };
    try store.put(gpa, testing.io, .{ .name = "aiand", .kind = .aiand, .token = "sk-value", .stored_ms = 1 }, null);

    const index_path = try std.fs.path.join(gpa, &.{ nested, index_file_name });
    defer gpa.free(index_path);
    try paths.requirePrivate(testing.io, index_path, null);

    const dir_stat = try std.Io.Dir.cwd().statFile(testing.io, nested, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o700), dir_stat.permissions.toMode() & 0o7777);
}

test "nothing the store writes ever lands under the configuration directory" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const config_dir = try std.fs.path.join(gpa, &.{ dir, "config", "chock" });
    defer gpa.free(config_dir);
    const data_dir = try std.fs.path.join(gpa, &.{ dir, "data", "chock" });
    defer gpa.free(data_dir);
    try makeDirAll(testing.io, config_dir, 0o700);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = data_dir, .secrets = memory.secrets() };
    try store.put(gpa, testing.io, .{ .name = "aiand", .kind = .aiand, .token = "sk-value", .stored_ms = 1 }, null);

    var config_entries = try std.Io.Dir.openDirAbsolute(testing.io, config_dir, .{ .iterate = true });
    defer config_entries.close(testing.io);
    var walker = config_entries.iterate();
    try testing.expect((try walker.next(testing.io)) == null);
}

test "a store the caller cannot write is reported and never left half written" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const in_store = paths.nix_store_prefix ++ "aaaa-chock/instances.zon";
    try testing.expectError(error.StoreUnwritable, writePrivateFile(gpa, testing.io, in_store, ".{}\n", null));

    var entries = try std.Io.Dir.openDirAbsolute(testing.io, dir, .{ .iterate = true });
    defer entries.close(testing.io);
    var walker = entries.iterate();
    try testing.expect((try walker.next(testing.io)) == null);
}

test {
    testing.refAllDecls(@This());
}

test "the temporary file a write goes through is this process's own, never a shared name" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const path = try std.fs.path.join(gpa, &.{ dir, "thing.zon" });
    defer gpa.free(path);

    const shared = try std.fs.path.join(gpa, &.{ dir, "thing.zon.new" });
    defer gpa.free(shared);
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = shared, .data = "not mine\n" });

    try writePrivateFile(gpa, testing.io, path, ".{ .version = 1 }\n", null);

    const untouched = try std.Io.Dir.cwd().readFileAlloc(testing.io, shared, gpa, .limited(64));
    defer gpa.free(untouched);
    try testing.expectEqualStrings("not mine\n", untouched);

    const written = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(64));
    defer gpa.free(written);
    try testing.expectEqualStrings(".{ .version = 1 }\n", written);
}

test "a login that arrives while another holds the index is refused, and names no credential" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);
    try ensureDir(testing.io, dir, null);

    var held = switch (lock.take(testing.io, dir, index_lock_name, .{})) {
        .held => |value| value,
        .busy, .unusable => return error.TestUnexpectedResult,
    };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(
        error.StoreUnwritable,
        takeStoreLock(gpa, testing.io, dir, index_lock_name, &diag),
    );

    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    try diag.?.format(&text.writer);
    try testing.expect(std.mem.indexOf(u8, text.written(), "another chock login is running") != null);
    try testing.expect(std.mem.indexOf(u8, text.written(), "sk-") == null);

    held.release(testing.io);
    var mine = try takeStoreLock(gpa, testing.io, dir, index_lock_name, null);
    mine.release(testing.io);
}

test "a login that is told the store is busy has written no credential either" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);
    try ensureDir(testing.io, dir, null);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    var held = switch (lock.take(testing.io, dir, index_lock_name, .{})) {
        .held => |value| value,
        .busy, .unusable => return error.TestUnexpectedResult,
    };
    defer held.release(testing.io);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.StoreUnwritable, store.put(gpa, testing.io, .{
        .name = "work",
        .kind = .aiand,
        .token = "sk-never-stored",
        .stored_ms = 1,
    }, &diag));
    try testing.expectEqual(
        std.meta.Tag(Diagnostic).store_is_busy,
        std.meta.activeTag(diag.?),
    );

    try testing.expectEqual(@as(usize, 0), memory.names.items.len);
    try testing.expect((try memory.secrets().get(gpa, testing.io, "work", null)) == null);
}

test "a login with no name of its own is refused over a name that is there, and writes nothing" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    try store.put(gpa, testing.io, .{
        .name = "aiand",
        .kind = .aiand,
        .token = "sk-the-first-one",
        .stored_ms = 1,
    }, null);

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.StoreUnwritable, store.put(gpa, testing.io, .{
        .name = "aiand",
        .kind = .aiand,
        .token = "sk-the-second-one",
        .stored_ms = 2,
        .replace_existing = false,
    }, &diag));

    var still_there = (try store.get(gpa, testing.io, "aiand", null)).?;
    defer still_there.deinit();
    try testing.expectEqualStrings("sk-the-first-one", still_there.token);
    try testing.expectEqual(@as(i64, 1), still_there.stored_ms);

    var index = try store.readIndex(gpa, testing.io, null);
    defer index.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), index.entries().len);

    try testing.expectEqualStrings("aiand", diag.?.name_already_stored.name);
    try testing.expectEqualStrings("aiand", diag.?.name_already_stored.kind);
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    try diag.?.format(&text.writer);
    try testing.expect(std.mem.indexOf(u8, text.written(), "already a credential named") != null);
    try testing.expect(std.mem.indexOf(u8, text.written(), "sk-") == null);

    try store.put(gpa, testing.io, .{
        .name = "aiand",
        .kind = .aiand,
        .token = "sk-the-third-one",
        .stored_ms = 3,
    }, null);
    var replaced = (try store.get(gpa, testing.io, "aiand", null)).?;
    defer replaced.deinit();
    try testing.expectEqualStrings("sk-the-third-one", replaced.token);
}

test "a name nothing holds is stored even when this login may not replace one" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    try store.put(gpa, testing.io, .{
        .name = "aiand",
        .kind = .aiand,
        .token = "sk-the-only-one",
        .stored_ms = 1,
        .replace_existing = false,
    }, null);

    var stored = (try store.get(gpa, testing.io, "aiand", null)).?;
    defer stored.deinit();
    try testing.expectEqualStrings("sk-the-only-one", stored.token);

    try store.put(gpa, testing.io, .{
        .name = "work",
        .kind = .aiand,
        .token = "sk-the-other-one",
        .stored_ms = 2,
        .replace_existing = false,
    }, null);
    var index = try store.readIndex(gpa, testing.io, null);
    defer index.deinit(gpa);
    try testing.expectEqual(@as(usize, 2), index.entries().len);
}

test "the driver's lock is taken inside the index's, and the two never wait on each other" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const driver = Driver{ .data_dir = dir };
    const store = Store{ .data_dir = dir, .secrets = driver.secrets() };

    try store.put(gpa, testing.io, .{
        .name = "work",
        .kind = .aiand,
        .token = "sk-work-not-a-real-key",
        .stored_ms = 1,
    }, null);
    try store.put(gpa, testing.io, .{
        .name = "personal",
        .kind = .aiand,
        .token = "sk-personal-not-a-real-key",
        .stored_ms = 2,
    }, null);

    var work = (try store.get(gpa, testing.io, "work", null)).?;
    defer work.deinit();
    var personal = (try store.get(gpa, testing.io, "personal", null)).?;
    defer personal.deinit();
    try testing.expectEqualStrings("sk-work-not-a-real-key", work.token);
    try testing.expectEqualStrings("sk-personal-not-a-real-key", personal.token);

    comptime {
        if (builtin.os.tag == .linux) {
            const linux_driver = @import("linux/secrets.zig");
            std.debug.assert(!std.mem.eql(u8, index_lock_name, linux_driver.lock_file_name));
        }
    }
}

test "a data directory that is not there is a lock fault with the path in it" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    try testing.expectError(error.StoreUnwritable, takeStoreLock(
        gpa,
        testing.io,
        "/chock-no-such-data-directory",
        index_lock_name,
        &diag,
    ));
    try testing.expectEqualStrings(
        "/chock-no-such-data-directory/" ++ index_lock_name,
        diag.?.store_lock_unusable.path,
    );
}

test "the lock is not one of the names the store reads or renames over" {
    try testing.expect(!std.mem.eql(u8, index_lock_name, index_file_name));
    try testing.expect(std.mem.endsWith(u8, index_lock_name, ".lock"));
    try testing.expect(!std.mem.endsWith(u8, index_file_name, ".lock"));
}

test "the store names the instance whose value is missing, and no longer only a terminal" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };
    try store.put(gpa, testing.io, .{
        .name = "work",
        .kind = .aiand,
        .token = "sk-work-not-a-real-key",
        .stored_ms = 1,
    }, null);

    var emptied = MemorySecrets{ .gpa = gpa };
    defer emptied.deinit();
    const half = Store{ .data_dir = dir, .secrets = emptied.secrets() };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.StoreCorrupt, half.get(gpa, testing.io, "work", &diag));
    try testing.expectEqualStrings("work", diag.?.no_value_for_name.name);
    try testing.expectEqualStrings("aiand", diag.?.no_value_for_name.kind);

    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "the credential store names the instance work and holds no value for it. " ++
            "Run: chock login --provider aiand --name work",
        try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?}),
    );
}

test "a write refused for the Nix store says which of the two reasons, with the path" {
    const gpa = testing.allocator;
    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);

    const in_store = paths.nix_store_prefix ++ "aaaa-chock/instances.zon";
    try testing.expectError(
        error.StoreUnwritable,
        writePrivateFile(gpa, testing.io, in_store, ".{}\n", &diag),
    );
    try testing.expectEqual(Diagnostic.WriteFailed.Step.in_the_nix_store, diag.?.write_failed.step);
    try testing.expectEqualStrings(in_store, diag.?.write_failed.path);

    var buffer: [512]u8 = undefined;
    const line = try std.fmt.bufPrint(&buffer, "{f}", .{&diag.?});
    try testing.expect(std.mem.indexOf(u8, line, "read only and readable by every user") != null);
}

test "a caller that wants no diagnostic allocates nothing extra for one" {
    const gpa = testing.allocator;
    try testing.expectError(error.StoreUnwritable, writePrivateFile(
        gpa,
        testing.io,
        paths.nix_store_prefix ++ "aaaa-chock/instances.zon",
        ".{}\n",
        null,
    ));
}

test "the first fault is kept, and a caller that wants none pays nothing" {
    var diag: ?Diagnostic = null;
    try testing.expect(note(&diag, .{ .data_dir_not_made = .{ .path = "/d", .err = error.AccessDenied } }));
    try testing.expect(!note(&diag, .{ .index_unreadable = .{ .path = "/i", .err = error.IsDir } }));
    try testing.expectEqualStrings("/d", diag.?.data_dir_not_made.path);

    try testing.expect(!note(null, .{ .data_dir_not_made = .{ .path = "/d", .err = error.AccessDenied } }));
    try testing.expect(!wantsDiagnostic(null));
    try testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    const cases: []const Diagnostic = &.{
        .{ .data_dir_not_made = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .index_unreadable = .{ .path = "/x", .err = error.AccessDenied } },
        .{ .no_value_for_name = .{ .name = "work", .kind = "aiand" } },
        .{ .write_failed = .{ .path = "/x", .step = .in_the_nix_store } },
        .{ .write_failed = .{ .path = "/x", .step = .links_into_the_nix_store, .link_target = "/nix/store/a" } },
        .{ .write_failed = .{ .path = "/x", .step = .name_too_long } },
        .{ .write_failed = .{ .path = "/x", .step = .create, .err = error.AccessDenied } },
        .{ .write_failed = .{ .path = "/x", .step = .set_mode, .err = error.AccessDenied } },
        .{ .write_failed = .{ .path = "/x", .step = .write, .err = error.AccessDenied } },
        .{ .write_failed = .{ .path = "/x", .step = .rename, .err = error.AccessDenied } },
        .{ .store_is_busy = .{ .file = index_lock_name, .seconds = 5 } },
        .{ .store_lock_unusable = .{ .path = "/x/instances.lock", .err = error.AccessDenied } },
        .{ .credential_file_unreadable = .{ .path = "/y", .err = error.AccessDenied } },
        .{ .credential_file_readable_by_others = .{ .path = "/y", .mode = 0o644 } },
        .{ .credential_file_not_valid = "/y" },
        .{ .name_is_reserved = reserved_prefix ++ "seal-key-v1" },
        .{ .name_already_stored = .{ .name = "aiand", .kind = "aiand" } },
        .{ .keychain_refused = .{ .verb = reading_verb, .name = "work", .status = darwin_status.auth_failed } },
        .{ .keychain_refused = .{ .verb = storing_verb, .name = "work", .status = darwin_status.auth_failed } },
        .{ .keychain_refused = .{ .verb = storing_verb, .name = "work", .status = darwin_status.interaction_not_allowed } },
        .{ .keychain_refused = .{ .verb = storing_verb, .name = "work", .status = darwin_status.no_default_keychain } },
    };
    var buffers: [cases.len][512]u8 = undefined;
    var lines: [cases.len][]const u8 = undefined;
    for (cases, 0..) |case, i| {
        lines[i] = try std.fmt.bufPrint(&buffers[i], "{f}", .{&case});
        try testing.expect(lines[i].len > 0);
    }
    for (lines, 0..) |line, i| {
        for (lines[i + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, line, other));
    }
}
