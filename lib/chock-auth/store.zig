//! The credential store: what `chock login` wrote, and source 3 of the
//! lookup order. **Chock alone writes this, and it lives in the data
//! directory, never the configuration one**, so a user can hand home-manager
//! their whole configuration directory and `chock login` still works.
//!
//! ## Three rules, and where each one lives
//!
//! 1. **The store is never mounted into the sandbox. Not read only, not at
//!    all.** Nothing here is ever put in a `sandbox.Config`. A path an agent
//!    cannot see beats a path an agent may only read.
//! 2. **The broker reads it, nothing else does.** `chock_core.Loop.Deps`
//!    fails its own build over a field whose name looks like a credential.
//! 3. **A credential never enters the log.** `lib/chock-broker/secrets.zig`
//!    redacts before the append.
//!
//! ## The store is an index plus a driver, and the split is the point
//!
//! A stored instance holds two different things: **what it is**, which is a
//! name, a kind, a base URL, and when it was stored, and **the secret
//! itself**. Only the second one needs the platform's own protection.
//!
//! * The **index** is a plain file in the data directory. It holds no secret.
//! * The **secret** goes to a `Secrets` driver, chosen at compile time:
//!   * **Linux**: a file in the same data directory, mode `0600`, in a
//!     directory `0700`. A file with wider permissions is refused and the
//!     message names the mode that was found. A wrong mode is a fault, never
//!     a warning.
//!   * **Darwin**: the Keychain, which is what a macOS user expects and what
//!     the system already protects.
//!
//! A later version seals the credential to a TPM, or puts it behind a keyring
//! unlock. **Both are then a change of driver and
//! not a change of caller**, because a driver's whole surface is "give me the
//! value for this name" and "keep this value under this name". Nothing above
//! it knows where a value is kept.

const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const config = @import("config.zig");
const lock = @import("lock.zig");

/// The index file, in the data directory. Holds no secret.
pub const index_file_name = "instances.zon";

/// The lock one login takes before it reads and rewrites the index.
///
/// **The index is a read of the whole file, a change, and a write of the whole
/// file**, so two logins with no exclusion each drop what the other added, and
/// the temporary files they write through can reach the published file in the
/// wrong order. See `lock.zig` for the bound and why it is short.
pub const index_lock_name = "instances.lock";

/// The largest index this reader accepts. Chock writes this file itself, so
/// this bounds a corrupted file rather than a hostile author.
pub const max_index_bytes: usize = 256 * 1024;

/// What a name Chock keeps for itself starts with. **A provider instance may
/// never be stored under such a name**: see `Store.put`.
///
/// The driver holds one flat set of names, and not every name in it is a
/// provider. `signing.zig` keeps the seal key there, because a signing secret
/// wants the same protection a credential wants. Without this rule a user who
/// typed the matching `--name` would overwrite it, and every seal written
/// before that would stop verifying with no message at all.
///
/// **A colon**, because no provider kind holds one and a person naming their
/// second work account does not reach for it.
pub const reserved_prefix = "chock:";

/// Whether `name` is one Chock keeps for itself. See `reserved_prefix`.
pub fn nameIsReserved(name: []const u8) bool {
    return std.mem.startsWith(u8, name, reserved_prefix);
}

/// One stored instance, without its secret. Keyed by the user's chosen name,
/// holding the kind, the base URL where one applies, the credential, and when
/// it was stored.
pub const IndexEntry = struct {
    name: []const u8,
    kind: []const u8,
    /// Empty for a kind that has an address of its own and was given no
    /// other one.
    base_url: []const u8 = "",
    /// Milliseconds since the epoch, when `chock login` stored this.
    stored_ms: i64,
};

const IndexFile = struct {
    version: u32 = 1,
    instances: []const IndexEntry = &.{},
};

pub const Error = std.mem.Allocator.Error || error{
    /// Something in the store could not be read. Pass a `Diagnostic` to
    /// learn what, and why.
    StoreUnreadable,
    /// Something in the store could not be written. Pass a `Diagnostic` to
    /// learn what, and why.
    StoreUnwritable,
    /// A file in the store can be read by somebody other than its owner.
    /// Pass a `Diagnostic` to learn the mode that was found.
    StoreIsReadable,
    /// A stored file is not valid. Pass a `Diagnostic` to learn which.
    StoreCorrupt,
};

/// Why the credential store could not be read or written.
///
/// **The driver's own faults are here too**, and not in the driver files,
/// because the two drivers are what a `Secrets` vtable hides and a caller
/// must not have to know which one this build has. A variant that names the
/// Keychain is filled only by the Darwin driver, and a variant that names a
/// credential file only by the Linux one.
///
/// **Every string in it is a copy, and `deinit` releases them.** The paths
/// come from `std.fs.path.join`, which each caller frees as soon as the call
/// returns, and the Keychain's own message is in a buffer the driver frees on
/// the way out.
///
/// **Three fields are not copies, and all are named here so the rule above can
/// be read as it is written.** `data_dir_not_made.path` is the directory
/// `ensureDir` was given, which that function cannot copy because it takes no
/// allocator, so a caller must keep it alive for as long as it holds the
/// message. `KeychainCommandFailed.verb` and `KeychainRefused.verb` are always
/// `reading_verb` or `storing_verb`, and `Busy.file` is always
/// `index_lock_name` or the Linux driver's own, all of them literals.
pub const Diagnostic = union(enum) {
    data_dir_not_made: Failed,
    index_unreadable: Failed,
    index_not_valid: NotValid,
    /// The index names an instance and the driver holds no value for it.
    /// That is a store somebody edited by hand, or a write that stopped part
    /// way. Both names are copies.
    no_value_for_name: NoValueForName,
    /// A write into the store failed. See `WriteFailed.Step`.
    write_failed: WriteFailed,
    /// Another `chock login` held a store file for longer than the bound.
    /// **This never names what was being stored**, because a person reads it
    /// off a terminal that other people can see.
    store_is_busy: Busy,
    /// The lock file that guards a store file could not be opened. The path is
    /// a copy.
    store_lock_unusable: Failed,
    /// An instance was offered under a name Chock keeps for itself. The name
    /// is a copy. See `reserved_prefix`.
    name_is_reserved: []const u8,
    /// The name is already in the index and the caller said it may not replace
    /// one. **The kind is the one that is stored, which is not always the one
    /// the caller offered.** Both strings are copies. See
    /// `NewEntry.replace_existing`.
    name_already_stored: NameAlreadyStored,
    /// The Linux driver could not read its credential file.
    credential_file_unreadable: Failed,
    /// The Linux driver's credential file can be read by somebody other than
    /// its owner. A wrong mode is a fault, never a warning.
    credential_file_readable_by_others: ReadableByOthers,
    /// The Linux driver's credential file is not valid ZON. **The message
    /// says where and never what is in it**, because that file's own text is
    /// the credential.
    credential_file_not_valid: []const u8,
    /// A `security` command could not be started, written to, or waited for.
    keychain_command_failed: KeychainCommandFailed,
    /// A `security` command ran and refused.
    keychain_refused: KeychainRefused,
    /// A `security` command was killed by a signal, or stopped.
    keychain_did_not_exit_normally: KeychainCommandFailed,

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
        /// The kind of the instance that is already there.
        kind: []const u8,
    };

    pub const Busy = struct {
        /// The lock file waited for, always a literal of this library.
        file: []const u8,
        seconds: i64,
    };

    pub const WriteFailed = struct {
        path: []const u8,
        step: Step,
        /// The fault the step gave. Null for a step that has none of its own.
        err: ?anyerror = null,
        /// Where a symbolic link goes, for `.links_into_the_nix_store`.
        link_target: ?[]const u8 = null,

        /// What the write was doing. The first three refuse before a byte is
        /// written; the last four are the temporary file and the rename that
        /// make a write atomic.
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

    pub const KeychainCommandFailed = struct {
        /// `reading` or `storing`, always a literal of this module.
        verb: []const u8,
        name: []const u8,
        err: ?anyerror = null,
    };

    pub const KeychainRefused = struct {
        verb: []const u8,
        name: []const u8,
        status: u8,
        /// What `security` wrote to its error stream, trimmed. Empty when
        /// the driver did not capture it.
        detail: []const u8,
    };

    /// Release what the diagnostic owns, with the allocator that filled it.
    /// Safe on every variant.
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
            .keychain_command_failed, .keychain_did_not_exit_normally => |failure| gpa.free(failure.name),
            .keychain_refused => |failure| {
                gpa.free(failure.name);
                gpa.free(failure.detail);
            },
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
                // **The temporary file is not named in any of these.** Its name
                // carries this process's own number, so a message that spelled
                // it would send a reader looking for a file that is already
                // gone. See `writePrivateFile`.
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
            // **This says what is there and never what to type.** The command
            // that gets past it is `chock login`'s own, and only that command
            // knows how the user spelled the provider, so it writes that
            // sentence itself. See `src/login.zig`.
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
            .keychain_command_failed => |failure| try writer.print(
                "running {s} failed while {s} {s}: {s}",
                .{ security_command, failure.verb, failure.name, errName(failure.err) },
            ),
            .keychain_refused => |failure| {
                const storing = std.mem.eql(u8, failure.verb, storing_verb);
                try writer.print(
                    "the Keychain would not {s} the credential for {s}: {s} exited {d}{s}{s}",
                    .{
                        if (storing) "keep" else "give",
                        failure.name,
                        security_command,
                        failure.status,
                        if (failure.detail.len == 0) "" else ": ",
                        failure.detail,
                    },
                );
                // Measured on macOS: this is the ordinary reason a store
                // fails on a machine reached over ssh, and an exit status
                // alone sends the reader nowhere.
                if (storing) try writer.writeAll(
                    ". A Keychain that is locked, for example on a machine reached over ssh with no " ++
                        "desktop session, refuses this.",
                );
            },
            .keychain_did_not_exit_normally => |failure| try writer.print(
                "{s} did not exit normally while {s} {s}",
                .{ security_command, failure.verb, failure.name },
            ),
        }
    }
};

/// The name of the macOS tool the Darwin driver runs. Spelled here, and not
/// taken from the driver, so `Diagnostic` compiles on a target whose driver
/// is not the Darwin one.
const security_command = "/usr/bin/security";

/// The two verbs a Keychain fault names. Spelled once, here, so a driver and
/// a message cannot disagree about which of the two happened.
pub const reading_verb = "reading";
pub const storing_verb = "storing";

fn errName(err: ?anyerror) []const u8 {
    return if (err) |e| @errorName(e) else "no reason given";
}

/// Fill `out` when the caller asked for one, and say whether it took `value`.
///
/// **The first fault is kept, not the last.** A write of the index can only
/// fail after the directory it goes in was made, so the first fault is the
/// one that explains the rest.
///
/// The answer matters because every variant but one owns memory: a site that
/// hands one over must release it itself when the answer is false.
pub fn note(out: ?*?Diagnostic, value: Diagnostic) bool {
    const slot = out orelse return false;
    if (slot.* != null) return false;
    slot.* = value;
    return true;
}

/// Whether a diagnostic is wanted and still empty, which is the one case in
/// which a site should copy a path for it. A caller that passes null must pay
/// no allocation at all.
pub fn wantsDiagnostic(out: ?*?Diagnostic) bool {
    const slot = out orelse return false;
    return slot.* == null;
}

/// Where a driver keeps the secret itself. See this file's own top comment
/// for why this is the whole surface a driver has.
///
/// A vtable, the shape `std.mem.Allocator` uses and `lib/chock-io.zig`
/// already follows, so a test can use a driver that touches neither a file
/// nor a Keychain.
pub const Secrets = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    /// `diag` is part of the vtable and not of one driver, so a caller says
    /// once that it wants a reason and gets the same answer from whichever
    /// driver this build has. See `Diagnostic`.
    pub const VTable = struct {
        /// The value stored under `name`, or null when this driver holds no
        /// such name. Caller owns the result.
        get: *const fn (
            ptr: *anyopaque,
            gpa: std.mem.Allocator,
            io: std.Io,
            name: []const u8,
            diag: ?*?Diagnostic,
        ) Error!?[]u8,
        /// Keep `value` under `name`, replacing whatever was there.
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

/// Selected once, at compile time, from `builtin.os.tag`, the same way
/// `lib/chock-io.zig` and `lib/chock-sandbox/Sandbox.zig` choose theirs. Only
/// the branch that matches the real build target is ever imported.
const driver_impl = switch (builtin.os.tag) {
    .linux => @import("linux/secrets.zig"),
    .macos => @import("darwin/secrets.zig"),
    else => @compileError("chock-auth: no credential driver for target os " ++ @tagName(builtin.os.tag)),
};

/// The driver this build was made for. `data_dir` is the data directory,
/// which the Linux driver keeps its file in and the Darwin driver ignores.
pub const Driver = driver_impl.Driver;

/// One stored instance, with its secret. Every field is owned by the caller
/// and released with `deinit`.
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
        // A credential sitting freed but unzeroed in the heap is still
        // readable in a crash dump, a swapped page, or a reused allocation,
        // the same reason `lib/chock-provider/Client.zig` zeroes its own
        // Authorization header buffer before freeing it.
        std.crypto.secureZero(u8, self.token);
        self.gpa.free(self.token);
        self.* = undefined;
    }
};

/// What `chock login` hands to `put`.
pub const NewEntry = struct {
    name: []const u8,
    kind: config.Kind,
    /// Empty when the kind's own default applies.
    base_url: []const u8 = "",
    token: []const u8,
    stored_ms: i64,
    /// Whether an instance already stored under this name may be replaced.
    ///
    /// **False is what a `chock login` with no `--name` passes.** A second
    /// unnamed instance of one kind must be refused rather than silently
    /// replace the first, and a user who typed a name meant that one.
    ///
    /// **The command line decides this and the store enforces it.** Only the
    /// command line knows whether `--name` was given, and only `put` can look
    /// at the index with the lock held. `chock login` looks once before it asks
    /// a person for anything, so a refusal costs no credential, and that look
    /// holds no lock: two logins can both pass it. This field is what makes the
    /// refusal true when they do.
    replace_existing: bool = true,
};

/// The store a caller uses. `data_dir` is where the index lives, and is not
/// owned: the caller keeps it alive for as long as this value is in use.
pub const Store = struct {
    data_dir: []const u8,
    secrets: Secrets,

    /// What is stored under `name`, or null when nothing is. **A missing
    /// store is "not logged in" and not a fault**, so a machine that has
    /// never run `chock login` reads back null rather than an error.
    ///
    /// **This takes no lock, and the one thing that costs is small.** A reader
    /// that arrived between the two writes of one `put` reads the index from
    /// before it and the credential from after it. The credential is written
    /// first, so a name that is new to the index cannot be read at all until
    /// its value is there: what a reader can see is the entry of a login that
    /// has been replaced beside the credential that replaced it, which is the
    /// kind, the base URL and the time of one login and the value of the next.
    ///
    /// A shared lock would close it and would cost more than it closes. Every
    /// reader would then need a data directory it may write, because a lock is
    /// a file that has to be made, and `chock run` reads this store on a
    /// machine where that directory may be read only.
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
            // Both names are copied: the kind lives in the index this
            // function releases on the way out.
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

    /// Keep `entry` under its own name, replacing whatever that name held
    /// unless `entry.replace_existing` says it may not.
    ///
    /// **Whether replacing is what the user meant is decided by the caller,
    /// and whether the name is free is decided here.** A second `--provider
    /// aiand` with no `--name` must be refused, and only the
    /// command line knows whether a name was given. It says so in
    /// `NewEntry.replace_existing`; this function is the only place that can
    /// look at the index with nobody else able to change it.
    ///
    /// **One lock, over the whole write.** See the body for why the driver now
    /// runs inside it.
    pub fn put(
        self: Store,
        gpa: std.mem.Allocator,
        io: std.Io,
        entry: NewEntry,
        diag: ?*?Diagnostic,
    ) Error!void {
        // **Before the directory is even made.** A name Chock keeps for itself
        // is not a store that failed to be written: it is a store that must not
        // be written, and nothing on disk changes over it.
        if (nameIsReserved(entry.name)) {
            if (wantsDiagnostic(diag)) {
                _ = note(diag, .{ .name_is_reserved = try gpa.dupe(u8, entry.name) });
            }
            return error.StoreUnwritable;
        }

        try self.ensureDataDir(io, diag);

        // **The lock spans everything this function writes**, which is the
        // credential and the index together.
        //
        // It spans the read and the write of the index because those are one
        // read-modify-write of a whole file: a lock around the write alone
        // would still let two logins read the same file and each write back a
        // copy with the other's instance missing.
        //
        // It spans the driver because the two files are one store. With the
        // driver outside, two logins for one name could leave the index entry
        // of the first beside the credential of the second. Both files are
        // whole and every field of the entry, its kind and its base URL as
        // much as its time, then belongs to a different login than the
        // credential does.
        //
        // It spans the look at the index below, which is the only way that look
        // can be true. See `NewEntry.replace_existing`.
        //
        // **The driver's own lock is a second name and is taken inside this
        // one, never the other way about.** `flock` locks an open file
        // description, so one name for both would be a lock this very process
        // holds. Nothing in this library ever takes them in the other order:
        // `signing.zig` goes straight to the driver and takes the driver's
        // alone.
        //
        // **What this costs is one wait.** On Linux the driver write is one
        // read of a file of a few hundred bytes and one rename, so the five
        // second bound in `lock.zig` is untouched. On Darwin the driver runs
        // `security`, and a Keychain that asks a person to unlock it now holds
        // this lock while it asks. A second login then reaches the bound and is
        // told another login is running, which is a true sentence and a login
        // it can run again. The state it replaces is a store that quietly held
        // two logins at once.
        var held = try takeStoreLock(gpa, io, self.data_dir, index_lock_name, diag);
        defer held.release(io);

        var index = try self.readIndex(gpa, io, diag);
        defer index.deinit(gpa);

        // **Before the driver, so a refusal writes nothing at all.** A look
        // made after the credential was stored would refuse this login and
        // still have replaced the credential of the login it is protecting.
        if (!entry.replace_existing) {
            if (index.find(entry.name)) |existing| {
                if (wantsDiagnostic(diag)) {
                    // Both are copies: the kind lives in the index this
                    // function releases on the way out, and the name is the
                    // caller's, which it frees as soon as this call returns.
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

        // The value first. A value with no index entry reads back as "not
        // logged in", which is a state a second `chock login` fixes. An
        // index entry with no value is the `StoreCorrupt` case in `get`
        // above, which is worse, so the write that can leave it happens
        // second.
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
            // Nothing stored yet is not a fault: see `get`.
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

/// Make the data directory, mode `0700`, so nobody else can even list what
/// this installation holds.
///
/// **A free function, because a caller that uses a `Secrets` driver on its own
/// still needs it.** `Store.put` makes the directory before it writes; a
/// caller that goes straight to the driver, which `signing.zig` does, has no
/// `Store` to do it for them, and a driver that made its own directory would
/// be a second place deciding the mode.
///
/// `data_dir` is borrowed. A diagnostic built here points at it and copies
/// nothing, so it must outlive the diagnostic.
pub fn ensureDir(io: std.Io, data_dir: []const u8, diag: ?*?Diagnostic) Error!void {
    makeDirAll(io, data_dir, 0o700) catch |err| {
        _ = note(diag, .{ .data_dir_not_made = .{ .path = data_dir, .err = err } });
        return error.StoreUnwritable;
    };
}

/// Take the lock named `lock_name` in `data_dir`, or say why not.
///
/// **A free function, for the reason `ensureDir` is one**: the Linux driver
/// guards its own file with a lock of its own name and has no `Store` to do it
/// for it.
///
/// **Hold it across the read and the write, and never across a prompt.** Every
/// file in this store is changed by reading it whole, editing, and writing it
/// whole, so a lock that covered only the write would still lose an instance.
/// See `lock.zig` for the bound.
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

/// One value, as ZON text with a closing newline. Caller owns the result.
/// Shared with the Linux driver, so the store's own two files are written the
/// same way.
pub fn serializeZon(gpa: std.mem.Allocator, value: anytype) Error![]u8 {
    var allocating = std.Io.Writer.Allocating.init(gpa);
    errdefer allocating.deinit();
    std.zon.stringify.serialize(value, .{}, &allocating.writer) catch return error.OutOfMemory;
    allocating.writer.writeByte('\n') catch return error.OutOfMemory;
    return allocating.toOwnedSlice();
}

/// A parsed index. `owned` is false for the empty one a missing file gives
/// back, which has nothing to free.
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

/// Write `contents` to `path` with mode `0600`, replacing whatever was
/// there, and never leaving a half written file behind: the bytes go to a
/// neighbouring temporary file first and the rename is what makes them
/// visible. A crash partway through therefore leaves the previous store, not
/// a truncated one.
///
/// Shared by this file and by the Linux driver, so the two can never disagree
/// about the mode a credential file gets.
pub fn writePrivateFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    contents: []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    // Say why, rather than fail with a permission error the user cannot
    // explain.
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var path_fault: ?paths.Diagnostic = null;
    paths.refuseNixStore(io, path, &link_buffer, &path_fault) catch {
        // The path and the link target both point at memory this function
        // and its caller release, so the store's own diagnostic keeps
        // copies. See `Diagnostic`.
        if (path_fault) |fault| try noteNixStore(gpa, diag, path, fault);
        return error.StoreUnwritable;
    };

    // **This process's own number is in the name, and that is not tidiness.**
    // A constant name is one inode for every writer: two logins open it with
    // `truncate`, each writes from offset zero, and the first rename publishes
    // whatever mixture is in it while the second writer carries on writing
    // through its descriptor into the file that is now the store. The result
    // parses as neither credential. A name of this process's own reduces the
    // worst case to one write winning, and `lock.zig` removes that too.
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

        // The process umask narrows the mode `createFileAbsolute` asks for,
        // and it can only ever narrow it, so this is here for the file that
        // already existed with a wider mode, which `truncate` reuses rather
        // than recreates.
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

/// Note one step of `writePrivateFile` that failed, with its own copy of the
/// path. Every caller of `writePrivateFile` frees the path it passed as soon
/// as the call returns.
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

/// Turn the borrowing diagnostic `paths.refuseNixStore` fills into the owning
/// one this module hands its callers.
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
        // `refuseNixStore` fills neither of these.
        .stat_failed, .readable_by_others => unreachable,
    }
}

/// Make `path` and every directory above it, each with `mode`. `std.Io.Dir`
/// has `createDirAbsolute` for one directory only, and a data directory is
/// two levels below `HOME` on a machine that has never had one.
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

/// A driver that keeps its values in memory. Nothing here reaches a file or
/// a Keychain, so the tests below prove what `Store` itself does, on every
/// platform, and the platform drivers prove their own halves in their own
/// files.
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
    // A directory that does not exist at all, which is a machine that has
    // never run `chock login`.
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

    // A key already in the driver, exactly where `signing.zig` puts one.
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

    // **Nothing changed**: the value the driver held is the value it still
    // holds, and no index entry was made for the refused name.
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

    // And an ordinary name still stores, so the rule is not refusing everything.
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

    // Take the value away and leave the index alone: the driver now holds
    // the value under a name nothing asks for.
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
    // A directory Chock has to make itself, so the 0700 rule is exercised
    // too.
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
    // Different directories, not merely different files. This
    // pins the fact structurally: `Store` is given one directory, it is the
    // data directory, and every path it builds is under that one.
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

    // A path in the Nix store, which is refused with a message
    // that says why rather than a permission error.
    const in_store = paths.nix_store_prefix ++ "aaaa-chock/instances.zon";
    try testing.expectError(error.StoreUnwritable, writePrivateFile(gpa, testing.io, in_store, ".{}\n", null));

    // **Nothing at all, rather than one name that is not there.** The temporary
    // file carries this process's own number now, so a test that looked for one
    // spelling would pass while a file of another spelling sat beside it.
    var entries = try std.Io.Dir.openDirAbsolute(testing.io, dir, .{ .iterate = true });
    defer entries.close(testing.io);
    var walker = entries.iterate();
    try testing.expect((try walker.next(testing.io)) == null);
}

test {
    testing.refAllDecls(@This());
}

test "the temporary file a write goes through is this process's own, never a shared name" {
    // **The whole fault in one line.** A constant `.new` is one inode for every
    // writer: two logins open it with `truncate`, each writes from offset zero,
    // and the first rename publishes the mixture while the second writer keeps
    // writing into what is now the store. The measurement with real processes
    // is `test/auth/concurrent.zig`.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);

    const path = try std.fs.path.join(gpa, &.{ dir, "thing.zon" });
    defer gpa.free(path);

    // A file at the shared name that a correct write must not touch. It stands
    // in for the other process's temporary file.
    const shared = try std.fs.path.join(gpa, &.{ dir, "thing.zon.new" });
    defer gpa.free(shared);
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = shared, .data = "not mine\n" });

    try writePrivateFile(gpa, testing.io, path, ".{ .version = 1 }\n", null);

    const untouched = try std.Io.Dir.cwd().readFileAlloc(testing.io, shared, gpa, .limited(64));
    defer gpa.free(untouched);
    try testing.expectEqualStrings("not mine\n", untouched);

    // And the write itself landed, so the name is unique and still correct.
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

    // Somebody else holds it for the whole of this test, which is what a login
    // that arrives mid write meets. A bound of zero, so the test does not sit
    // out the real one: what is checked is the answer, not the seconds.
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
    // **A person reads this off a terminal other people can see.** It says what
    // to do next and never what was being stored.
    try testing.expect(std.mem.indexOf(u8, text.written(), "sk-") == null);

    // And it is free again the moment the holder lets go, which is the whole
    // behaviour a waiting login depends on. `flock` gives this back even when
    // the holder was killed, so nothing here has to clean up after one.
    held.release(testing.io);
    var mine = try takeStoreLock(gpa, testing.io, dir, index_lock_name, null);
    mine.release(testing.io);
}

test "a login that is told the store is busy has written no credential either" {
    // **The message says nothing was stored, and now that is true of both
    // files.** The lock used to be taken after the driver, so a login that
    // reached the bound had already put its credential where the driver keeps
    // one, under a name the index does not carry. `get` reads that back as "not
    // logged in", so nobody sees it, and it sits there until some later login
    // for the same name writes over it. The lock is taken first now, so a busy
    // answer costs no write at all.
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir = try tmpDirPath(&dir_buffer, tmp);
    try ensureDir(testing.io, dir, null);

    var memory = MemorySecrets{ .gpa = gpa };
    defer memory.deinit();
    const store = Store{ .data_dir = dir, .secrets = memory.secrets() };

    // Somebody else holds it for the whole of this test, which is what a login
    // that arrives mid write meets. `Store.put` takes no options, so this test
    // sits out the real five second bound. That is the cost of measuring the
    // real call rather than a lock take on its own.
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

    // The driver holds nothing, so there is no credential left behind under a
    // name no index entry names.
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

    // **The credential is the first one's, and this is the whole point.** The
    // look is made before the driver is touched, so a refusal cannot have
    // replaced the credential of the login it is protecting. A check that only
    // read the error would pass against a store that had already lost it.
    var still_there = (try store.get(gpa, testing.io, "aiand", null)).?;
    defer still_there.deinit();
    try testing.expectEqualStrings("sk-the-first-one", still_there.token);
    try testing.expectEqual(@as(i64, 1), still_there.stored_ms);

    var index = try store.readIndex(gpa, testing.io, null);
    defer index.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), index.entries().len);

    // The message says what is there. It never says what to type, because the
    // command that gets past it is `chock login`'s and only that command knows
    // how the user spelled the provider.
    try testing.expectEqualStrings("aiand", diag.?.name_already_stored.name);
    try testing.expectEqualStrings("aiand", diag.?.name_already_stored.kind);
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    try diag.?.format(&text.writer);
    try testing.expect(std.mem.indexOf(u8, text.written(), "already a credential named") != null);
    // **And never the credential.** A person reads this off a terminal other
    // people can see.
    try testing.expect(std.mem.indexOf(u8, text.written(), "sk-") == null);

    // And a login that was given a name still replaces, so the rule is not
    // refusing every second login.
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
    // The first login of all, which is the ordinary case and must not meet the
    // refusal above.
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

    // A second name is a second instance and never a replacement, so it stores
    // too.
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
    // **The one way this could deadlock, with the real driver.** `Store.put`
    // holds `instances.lock` over the driver, and the Linux driver takes
    // `credentials.lock` inside it. `flock` locks an open file description, so
    // a driver that reached for the index's own name would wait on a lock this
    // very process holds and would never get it: the login would sit out the
    // five second bound and then say the store was busy with itself.
    //
    // Linux only, because `Driver` is chosen at compile time and the Darwin one
    // would write to the Keychain of whoever ran this.
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

    // And the two lock files are two names, which is what makes the nesting
    // legal at all. Read at compile time, so a target whose driver is not this
    // one never reaches the import.
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
    // A lock file the index reader picked up would be parsed as ZON, and one at
    // the index's own name would be renamed over on the very next login.
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

    // The value alone is dropped, which is what a hand edited store or an
    // interrupted write leaves behind.
    var emptied = MemorySecrets{ .gpa = gpa };
    defer emptied.deinit();
    const half = Store{ .data_dir = dir, .secrets = emptied.secrets() };

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(gpa);
    try testing.expectError(error.StoreCorrupt, half.get(gpa, testing.io, "work", &diag));
    try testing.expectEqualStrings("work", diag.?.no_value_for_name.name);
    // **The kind is a copy.** It lives in the index `get` releases on the way
    // out, so a diagnostic that borrowed it would dangle. The testing
    // allocator fails this test if `deinit` misses it.
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
    // The outer optional is what lets a caller opt out. The testing allocator
    // fails this test if the refusal leaks the copy it would have made for a
    // diagnostic that nobody asked for.
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

    // A caller that asked for no diagnostic must reach no store at all. The
    // false answer is what tells an owning site to release its own copies
    // rather than leak them into a slot that does not exist.
    try testing.expect(!note(null, .{ .data_dir_not_made = .{ .path = "/d", .err = error.AccessDenied } }));
    try testing.expect(!wantsDiagnostic(null));
    try testing.expect(!wantsDiagnostic(&diag));
}

test "no two faults of this module read the same" {
    // Every driver's faults are in this one union, so a caller never has to
    // know which driver this build has. `index_not_valid` is left out,
    // because it renders a syntax tree no literal here can build.
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
        .{ .keychain_command_failed = .{ .verb = reading_verb, .name = "work", .err = error.FileNotFound } },
        .{ .keychain_command_failed = .{ .verb = storing_verb, .name = "work", .err = error.FileNotFound } },
        .{ .keychain_refused = .{ .verb = reading_verb, .name = "work", .status = 1, .detail = "no" } },
        .{ .keychain_refused = .{ .verb = storing_verb, .name = "work", .status = 1, .detail = "" } },
        .{ .keychain_did_not_exit_normally = .{ .verb = reading_verb, .name = "work" } },
        .{ .keychain_did_not_exit_normally = .{ .verb = storing_verb, .name = "work" } },
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
