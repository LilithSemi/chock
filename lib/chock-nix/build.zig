//! The agent names an attribute to build, and the host builds it.
//!
//! ## A build is brokered, and it never happens inside the sandbox
//!
//! The sandbox has no daemon socket, no network and no writable cache
//! directory, so a real build cannot run there at all. What runs there is the
//! program afterwards. So the shape is the one `provision.zig` already has:
//! `nix` runs on the host, outside every sandbox, and answers with store
//! paths and `bin` directories, which is what a sandbox mounts and what goes
//! on the `PATH` of the next tool call.
//!
//! ## The produced set, and the one object it names
//!
//! A hand written derivation can name any builder, so a build of a path
//! nobody evaluated here would be host code execution with a content hash in
//! front of it. `backend.Driver` answers that: it records what an evaluation
//! put in the store and refuses a build of anything else.
//!
//! **The object the driver authorised is the object the host builds.** An
//! evaluation for a build runs against `Writing`, which puts the whole
//! derivation closure in the host's own store and records the path the store
//! itself answered with. A path that is not the one fix computed is refused
//! there, so every path in the produced set is one the host store confirmed.
//! `realise` then tells the host to build `<derivation path>^*`. The
//! attribute path and the flake reference are still what the policy was asked
//! about and what the model is told, because those are the words a person
//! reads, and they are no longer what `nix` resolves. So fix and the host's
//! Nix cannot read one attribute differently between the two moments, and an
//! unpinned reference cannot move between them: there is one object.
//!
//! ## A fetch is a connection, and it is decided before the build
//!
//! A fixed output derivation builds with the network open to it, on purpose,
//! because its output hash is checked afterwards. That check is integrity and
//! never egress: a URL that carries a secret in its query string with the hash
//! of an innocuous file passes it, and the request already happened. So
//! `Host.buildPaths` reads the whole derivation closure first, names every
//! host it would reach, and puts each one to `fetch.Gate`. A host nobody
//! allowed refuses the build before `nix` is told to build anything. The names
//! are the ordinary `net.connect` ones: see `lib/chock-nix/fetch.zig` for what
//! the reader finds and what it refuses to name.
//!
//! **What is still not proven.** The builder runs on the host, under the
//! host's Nix, and what it makes is its own business: this says what goes in,
//! and never what comes out. A substituter may answer for an output path
//! instead of building it. Nothing here says the attribute is the one the
//! person meant, or that the derivation is safe to run. And the write is a
//! real capability: the derivation stays in the host store after the session,
//! until the host collects it.
//!
//! **The fetch gate is a rule and it has no backstop under it.** `nix` on this
//! machine has no flag that keeps a fixed output builder off the network:
//! `--offline` turns the substituters off and a fixed output derivation still
//! fetches with it set. So the gate is the whole of it, and a host the reader
//! did not find is a host nobody was asked about. A host's Nix with `sandbox`
//! off gives every builder the network, not only a fixed output one, and
//! nothing here reads that setting.
//!
//! **A store that cannot take the derivation stops the build.** The write
//! goes through the host's Nix daemon, so a machine with no daemon builds
//! nothing here and is told so. Refusing is the answer, because the older
//! shape, handing `nix` the attribute instead, is the gap this closes.
//!
//! **This file adds no second check.** It calls `Driver.build`, which is the
//! same function the evaluator's own build goes through, so there is one
//! answer to what this session produced. A check written beside that one
//! could answer differently, and the weaker of the two would then be the real
//! rule.
//!
//! ## The seam that can build is installed last
//!
//! `Writing` writes objects and authorises no build, so import from
//! derivation is refused during an evaluation exactly as it is for an
//! ordinary `nix_eval`. `realise` installs the seam that runs `nix` only
//! after a person or the policy has answered, and takes it off again when the
//! build is over. An evaluation therefore cannot reach a build, whatever the
//! expression says.
//!
//! ## What one session may write
//!
//! `backend.Driver.max_object_bytes` bounds one object, and it is checked
//! before the seam, so an object over it never reaches the store. `Budget`
//! bounds the whole session across every object and every build, and it is
//! checked inside the seam, where the bytes are. Both numbers come from the
//! project, the operator and the org policy bundle.
//!
//! ## Nothing here talks to Nix
//!
//! `provision.Runner` and `StoreWriter` are the two seams: the real ones
//! spawn `nix` and talk to the host's daemon, and the ones the tests use
//! answer from a table. A test that builds a derivation is not a test, it is
//! a build, and a test against a real store is in `test/nix/real.zig`.

const std = @import("std");

const backend = @import("backend.zig");
const daemon = @import("store").daemon;
const fetch = @import("fetch.zig");
const proc = @import("proc.zig");
const provision = @import("provision.zig");
const store = @import("store.zig");

pub const Error = provision.Error;

/// What `nix` said when it would not build. Never leaves this file: `realise`
/// turns it into a sentence the model reads.
const NixRefused = error{NixRefusedTheBuild};

/// A host the build would reach that nobody permitted, or one nothing could
/// name. Never leaves this file either: `Host.refusal` holds the words.
const FetchRefused = error{FetchNotPermitted};

/// The most attributes one path may hold, and the longest one attribute may
/// be. A real path is three deep and its names are words.
pub const max_segments: usize = 8;
pub const max_segment_bytes: usize = 128;

/// The longest flake reference this accepts. A reference is a URL, and one
/// far longer than this names nothing a project really has.
pub const max_flake_ref_bytes: usize = 512;

/// Why a request was refused before anything was evaluated or built.
pub const RequestError = error{
    AttrPathEmpty,
    AttrPathTooDeep,
    /// A segment is empty, too long, or holds a character an attribute name
    /// may not have here. See `checkSegment`.
    AttrNotAName,
    FlakeRefEmpty,
    FlakeRefTooLong,
    /// The reference holds a character that would not survive being written
    /// into an expression or an argument. See `checkFlakeRef`.
    FlakeRefNotAReference,
};

/// True when `character` may appear in an attribute name here.
///
/// Letters, digits, `-`, `_` and `+`. **A dot is refused, and that is the one
/// exclusion worth stating**: the same attribute path is written twice, once
/// as an expression and once as the fragment of an installable, and a dot in
/// a name is a level boundary in the second spelling. A name that means two
/// things in two places is a name this file will not build.
fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '-', '_', '+' => true,
        else => false,
    };
}

/// Check one attribute name.
fn checkSegment(segment: []const u8) RequestError!void {
    if (segment.len == 0 or segment.len > max_segment_bytes) return error.AttrNotAName;
    if (!std.ascii.isAlphanumeric(segment[0])) return error.AttrNotAName;
    for (segment) |character| {
        if (!isNameCharacter(character)) return error.AttrNotAName;
    }
}

/// Check the whole attribute path the model sent.
pub fn checkAttrPath(attr_path: []const []const u8) RequestError!void {
    if (attr_path.len == 0) return error.AttrPathEmpty;
    if (attr_path.len > max_segments) return error.AttrPathTooDeep;
    for (attr_path) |segment| try checkSegment(segment);
}

/// Check a flake reference.
///
/// A reference is written into a Nix string literal and into an argument of
/// `nix`, so a quote, a backslash, a dollar sign, a `#` and any whitespace are
/// refused. What is left is a URL: letters, digits, and the punctuation a
/// reference really uses.
pub fn checkFlakeRef(flake_ref: []const u8) RequestError!void {
    if (flake_ref.len == 0) return error.FlakeRefEmpty;
    if (flake_ref.len > max_flake_ref_bytes) return error.FlakeRefTooLong;
    if (flake_ref[0] == '-') return error.FlakeRefNotAReference;
    for (flake_ref) |character| {
        if (std.ascii.isAlphanumeric(character)) continue;
        switch (character) {
            ':', '/', '.', '-', '_', '+', '~', '@', '%', '?', '=', '&', ',' => {},
            else => return error.FlakeRefNotAReference,
        }
    }
}

/// The installable `<flake ref>#<attribute>.<attribute>`, which names the
/// request for a person: the policy question, the log and what the model is
/// told. **Never an argument of `nix`**, which is given the derivation path
/// instead. The caller owns the result.
///
/// **Both arguments must already have passed their check**, which is
/// asserted: this is the one place they become arguments to `nix`, and a
/// caller that skipped the check is a programmer error.
pub fn installableFor(
    allocator: std.mem.Allocator,
    flake_ref: []const u8,
    attr_path: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    checkFlakeRef(flake_ref) catch unreachable;
    checkAttrPath(attr_path) catch unreachable;

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.appendSlice(allocator, flake_ref);
    try text.append(allocator, '#');
    for (attr_path, 0..) |segment, index| {
        if (index != 0) try text.append(allocator, '.');
        try text.appendSlice(allocator, segment);
    }
    return text.toOwnedSlice(allocator);
}

/// The expression that evaluates to the same thing the installable names, for
/// the evaluator inside Chock. The caller owns the result.
///
/// ```
/// (builtins.getFlake "/work")."packages"."x86_64-linux"."default"
/// ```
///
/// Every attribute is quoted, so the expression selects exactly the names the
/// caller sent and never reads a dot as a boundary of its own.
pub fn expressionFor(
    allocator: std.mem.Allocator,
    flake_ref: []const u8,
    attr_path: []const []const u8,
) std.mem.Allocator.Error![]u8 {
    checkFlakeRef(flake_ref) catch unreachable;
    checkAttrPath(attr_path) catch unreachable;

    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    try text.print(allocator, "(builtins.getFlake \"{s}\")", .{flake_ref});
    for (attr_path) |segment| try text.print(allocator, ".\"{s}\"", .{segment});
    return text.toOwnedSlice(allocator);
}

/// Where the host's Nix daemon listens when nobody named another socket.
pub const default_daemon_socket = daemon.default_socket_path;

/// The most one session may put in the host store when nothing named a
/// number. The same number as `chock_policy.nix.default_max_session_bytes`,
/// written a second time because this library imports no other chock library:
/// see `lib/chock-nix.zig`.
pub const default_max_session_bytes: u64 = 256 << 20;

/// Why an object of an evaluation did not reach the host store.
pub const WriteError = error{
    /// This session has already written `Budget.max_bytes`.
    SessionStoreFull,
    /// The store put the object somewhere other than the path fix computed
    /// for it, so the two do not hold the same object.
    StorePathNotExpected,
};

/// How much of the host store one session has taken, and the most it may.
///
/// **One per session and never one per call**, so a session that builds twice
/// counts the second build against the first. Every write counts, which means
/// an object written a second time is counted a second time: the store keeps
/// one copy, and this bounds the work asked of it rather than the disk.
pub const Budget = struct {
    max_bytes: u64 = default_max_session_bytes,
    written_bytes: u64 = 0,

    /// Take `bytes` out of what is left. A refusal takes nothing.
    pub fn take(self: *Budget, bytes: u64) WriteError!void {
        const total = std.math.add(u64, self.written_bytes, bytes) catch
            return error.SessionStoreFull;
        if (total > self.max_bytes) return error.SessionStoreFull;
        self.written_bytes = total;
    }
};

/// Where an object of an evaluation for a build is really written.
///
/// A seam for the same reason `provision.Runner` is one: what is on the other
/// side of it is the host's Nix daemon, and a test that writes to a real
/// store is not a test. `DaemonWriter` is the real one.
pub const StoreWriter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Write `object` and answer the path the store itself computed for
        /// it, owned by `allocator`.
        add_object: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            object: backend.AddObject,
        ) anyerror![]u8,
    };

    pub fn addObject(
        self: StoreWriter,
        allocator: std.mem.Allocator,
        object: backend.AddObject,
    ) anyerror![]u8 {
        return self.vtable.add_object(self.ptr, allocator, object);
    }
};

/// The `StoreWriter` that writes to the host's own store, through its Nix
/// daemon.
///
/// **On the host, outside every sandbox**, the same place `provision.Host`
/// runs `nix`: a sandbox has no daemon socket. The three kinds of object are
/// the three the daemon has operations for, and the daemon computes the path
/// of each from its content, which is what makes the answer worth checking.
pub const DaemonWriter = struct {
    store: *daemon.DaemonStore,

    /// Connect to the daemon at `endpoint`, which is a socket path or
    /// `default_daemon_socket`. The `io` must be one that can open a socket,
    /// and it must outlive this.
    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        endpoint: []const u8,
    ) !DaemonWriter {
        return .{ .store = try daemon.DaemonStore.connect(allocator, io, endpoint) };
    }

    pub fn deinit(self: *DaemonWriter) void {
        self.store.deinit();
        self.* = undefined;
    }

    pub fn writer(self: *DaemonWriter) StoreWriter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: StoreWriter.VTable = .{ .add_object = addObject };

    fn addObject(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        object: backend.AddObject,
    ) anyerror![]u8 {
        const self: *DaemonWriter = @ptrCast(@alignCast(ptr));
        return switch (object) {
            .text => |text| self.store.addTextToStore(
                allocator,
                text.name,
                text.bytes,
                text.references,
            ),
            .nar => |nar| self.store.addPath(allocator, nar.name, nar.bytes, &.{}),
            .flat => |flat| self.store.addFlatFile(allocator, flat.name, flat.bytes, &.{}),
        };
    }
};

/// The store seam an evaluation for a build runs against.
///
/// Every object goes to the host store, and the path the store answers with
/// is checked against the path fix computed before the driver records it. So
/// a path in the produced set is a path the host store holds, which is what
/// lets `realise` name the derivation rather than an installable.
///
/// **There is no `build_paths` here**, so an evaluation that reaches for one,
/// which is what import from derivation does, is refused with the path named,
/// exactly as an ordinary evaluation is.
pub const Writing = struct {
    writer: StoreWriter,
    /// This session's own, shared with every other build of it.
    budget: *Budget,

    pub fn seam(self: *Writing) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
    };

    /// False for every path, so the evaluation writes each object of the
    /// closure rather than taking one the store holds already. A write it
    /// skips is a path the produced set never records, and a build of that
    /// path would then be refused. Writing an object the store already holds
    /// answers the same path and changes nothing else.
    fn isValidPath(_: *anyopaque, _: []const u8) anyerror!bool {
        return false;
    }

    fn addObject(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        object: backend.AddObject,
    ) anyerror![]u8 {
        const self: *Writing = @ptrCast(@alignCast(context));
        const bytes = switch (object) {
            inline else => |one| one.bytes,
        };
        try self.budget.take(bytes.len);

        const written = try self.writer.addObject(allocator, object);
        errdefer allocator.free(written);
        // The whole worth of writing to the host store: the store computes
        // the path from the content it took, so an answer that is not the
        // path fix computed means the two do not hold the same object.
        if (!std.mem.eql(u8, written, object.expectedPath())) {
            return WriteError.StorePathNotExpected;
        }
        return written;
    }
};

/// The store seam that really builds, on the host.
///
/// **It builds the derivation the driver authorised**, and never the
/// installable: `<derivation path>^*`, which is every output of that one
/// derivation. The evaluation put that derivation in the host store, so there
/// is a path for `nix` to name and nothing is instantiated a second time.
///
/// **The hosts the build would reach are asked about here, and not before.**
/// The driver has already checked that this session produced the path by the
/// time this runs, so `nix derivation show` is never run for a path the model
/// made up. See `askAboutFetches`.
pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    /// `<derivation path>^*`, from `realise`.
    derivation_outputs: []const u8,
    /// Who answers for a host the build would reach. The default permits
    /// nothing, so a caller that wired none builds nothing that fetches.
    gate: fetch.Gate = fetch.Gate.refusing,
    /// What `nix` wrote when it would not build, borrowed from `allocator`.
    said: []const u8 = "",
    /// Why a fetch of this build was refused, borrowed from `allocator`.
    refusal: []const u8 = "",
    /// The outputs the build produced, empty until it has.
    out_paths: []const []const u8 = &.{},

    pub fn seam(self: *Host) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{ .build_paths = buildPaths };

    /// Put every host the closure of `derivation_path` would reach to the
    /// gate, and answer `FetchNotPermitted` on the first one nobody allowed.
    ///
    /// A fixed output derivation builds with the network open to it, and its
    /// output hash is checked after the request has already gone out. So the
    /// hash is integrity and never egress, and this is where egress is
    /// decided.
    fn askAboutFetches(self: *Host, derivation_path: []const u8) anyerror!void {
        switch (try fetch.fetchesOf(self.allocator, self.io, self.runner, derivation_path)) {
            .fetches => |list| for (list) |one| {
                switch (try self.gate.permit(self.allocator, one)) {
                    .permitted => {},
                    .refused => |why| {
                        self.refusal = why;
                        return FetchRefused.FetchNotPermitted;
                    },
                }
            },
            .unreadable => |one| {
                self.refusal = try fetch.unreadableRefusal(self.allocator, one);
                return FetchRefused.FetchNotPermitted;
            },
            .nix_said => |said| {
                self.refusal = try fetch.closureRefusal(self.allocator, derivation_path, said);
                return FetchRefused.FetchNotPermitted;
            },
        }
    }

    fn buildPaths(
        context: *anyopaque,
        paths: []const []const u8,
        _: ?backend.BuildSink,
        _: backend.BuildMode,
    ) anyerror!void {
        const self: *Host = @ptrCast(@alignCast(context));
        // `paths` is what the driver authorised a moment ago, so the closure
        // read below is of that object and of nothing the model named.
        try self.askAboutFetches(paths[0]);

        const built = try self.runner.run(self.allocator, self.io, &.{
            "build",
            // No result symbolic link, for the reason `provision.resolve`
            // gives: the root a session needs is made by its caller, and a
            // `result` link in the user's project directory is litter.
            "--no-link",
            "--print-out-paths",
            self.derivation_outputs,
        });
        if (!built.succeeded()) {
            self.said = provision.lastLine(built.stderr);
            return NixRefused.NixRefusedTheBuild;
        }
        self.out_paths = try store.parsePathList(self.allocator, built.stdout);
    }
};

/// One thing to realise.
pub const Request = struct {
    /// The derivation the evaluation of this very attribute produced and put
    /// in the host store. It is what the driver checks against its produced
    /// set and what `nix` is told to build.
    derivation_path: []const u8,
    /// `<flake ref>#<attribute path>`, from `installableFor`. What the policy
    /// was asked about and what the model is told, and never an argument of
    /// `nix`: see this file's own top comment.
    installable: []const u8,
};

/// A build that happened.
pub const Built = struct {
    /// What the sandbox mounts and what goes on the `PATH`, in the shape a
    /// provisioned program already answers with, so a built package joins the
    /// session's toolchain by the road that is already there.
    provided: provision.Provided,
    /// The build's own outputs, which is what the model is told about.
    out_paths: []const []const u8,
};

/// What one `realise` produced: a build, or one sentence saying why not.
///
/// A refusal is a fact about the request that the model reads and can act on,
/// the same way `provision.Answer` treats a package that is not there.
pub const Answer = union(enum) {
    built: Built,
    refused: []const u8,
};

/// Build `request` on the host, if `driver` produced its derivation.
///
/// **Give this an arena**, the same convention `provision.resolve` follows:
/// every string of the answer comes from `allocator`, and so does everything
/// the `nix` commands wrote.
pub fn realise(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    driver: *backend.Driver,
    gate: fetch.Gate,
    request: Request,
) Error!Answer {
    // Every output of that one derivation. `nix` reads a bare derivation path
    // as a request for its default output, and a package with more than one
    // would then lose the rest of what the model was told about.
    var host: Host = .{
        .allocator = allocator,
        .io = io,
        .runner = runner,
        .gate = gate,
        .derivation_outputs = try std.fmt.allocPrint(
            allocator,
            "{s}^*",
            .{request.derivation_path},
        ),
    };

    // Installed here and taken off below, so nothing that runs before or
    // after this call can reach a build through this driver.
    driver.seam = host.seam();
    defer driver.seam = backend.Seam.refusing;

    driver.build(&.{request.derivation_path}, .normal) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.RunnerFailed => return error.RunnerFailed,
        // The driver's own words, which name the path. Nothing ran.
        error.BuildRefused => return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was not built, and nothing ran: {s}",
            .{ request.installable, driver.lastError() orelse "the build was refused" },
        ) },
        NixRefused.NixRefusedTheBuild => return .{
            .refused = try explainFailure(allocator, request.installable, host.said),
        },
        // Nothing was fetched and nothing was built: the words name the host
        // and the derivation, so the model can ask for that host rather than
        // send the same attribute again.
        FetchRefused.FetchNotPermitted => return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was not built and nothing was fetched: {s}",
            .{ request.installable, host.refusal },
        ) },
        else => return error.RunnerFailed,
    };

    if (host.out_paths.len == 0) return .{ .refused = try std.fmt.allocPrint(
        allocator,
        "{s} was built and produced no output path, so there is nothing to use. Name an " ++
            "attribute that is a package rather than one that builds nothing.",
        .{request.installable},
    ) };

    var said: []const u8 = "";
    const mounts = try provision.mountsFor(allocator, io, runner, host.out_paths, &said) orelse
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was built and what it needs could not be read, so it is not available. Nix " ++
                "said: {s}",
            .{ request.installable, said },
        ) };

    return .{ .built = .{
        .provided = .{
            .program = request.installable,
            .installable = request.installable,
            .bin_dirs = mounts.bin_dirs,
            .store_paths = mounts.store_paths,
        },
        .out_paths = host.out_paths,
    } };
}

/// One sentence for a request this file refuses before it evaluates anything.
pub fn requestRefusal(
    allocator: std.mem.Allocator,
    err: RequestError,
) std.mem.Allocator.Error![]u8 {
    return switch (err) {
        error.AttrPathEmpty => allocator.dupe(u8, "nothing was built: no attribute was named. " ++
            "Send the attribute path as a list, such as [\"packages\", \"x86_64-linux\", " ++
            "\"default\"]."),
        error.AttrPathTooDeep => std.fmt.allocPrint(
            allocator,
            "nothing was built: an attribute path may hold at most {d} names. Name the " ++
                "package itself.",
            .{max_segments},
        ),
        error.AttrNotAName => std.fmt.allocPrint(
            allocator,
            "nothing was built: one of those is not an attribute name. A name holds letters, " ++
                "digits, \"-\", \"_\" and \"+\", starts with a letter or a digit, and is at " ++
                "most {d} bytes. Send one name per entry of the list rather than one dotted " ++
                "string.",
            .{max_segment_bytes},
        ),
        error.FlakeRefEmpty => allocator.dupe(u8, "nothing was built: the flake reference is " ++
            "empty. Leave it out to build from the project you are working in."),
        error.FlakeRefTooLong => std.fmt.allocPrint(
            allocator,
            "nothing was built: a flake reference may be at most {d} bytes.",
            .{max_flake_ref_bytes},
        ),
        error.FlakeRefNotAReference => allocator.dupe(u8, "nothing was built: that is not a " ++
            "flake reference. A reference is a URL such as \"github:NixOS/nixpkgs\" or a path, " ++
            "with no quote, no space and no \"#\": name the attribute in the attribute path " ++
            "instead."),
    };
}

/// One sentence for an evaluation the host store would not take. Null when
/// `err` is not a `WriteError`, which leaves the caller's own words for
/// everything else an evaluation can fail with.
pub fn writeRefusal(
    allocator: std.mem.Allocator,
    installable: []const u8,
    err: anyerror,
) std.mem.Allocator.Error!?[]u8 {
    return switch (err) {
        WriteError.SessionStoreFull => try std.fmt.allocPrint(
            allocator,
            "{s} was not built: this session has put as much in the Nix store as it may, so " ++
                "the derivation could not be written and nothing ran. Build fewer attributes " ++
                "in one session, or ask the user to raise max_session_bytes.",
            .{installable},
        ),
        WriteError.StorePathNotExpected => try std.fmt.allocPrint(
            allocator,
            "{s} was not built: the Nix store put the derivation at a path other than the one " ++
                "this session computed for it, so the two are not the same object. Nothing " ++
                "ran. Tell the user, because this is the machine and not your request.",
            .{installable},
        ),
        else => null,
    };
}

/// Why `nix` would not build, in the words of what to do next.
///
/// The two machine faults are told apart from a request fault, because they
/// are not the model's to fix and a model that reads them as its own mistake
/// sends a second attribute. Anything else is the last line Nix wrote, which
/// is where Nix puts its own message.
fn explainFailure(
    allocator: std.mem.Allocator,
    installable: []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    if (provision.saysNoDaemon(said)) return std.fmt.allocPrint(
        allocator,
        "the Nix daemon could not be reached, so {s} was not built and nothing else can be " ++
            "either in this session. Do the work with what the toolchain already has, and tell " ++
            "the user that a build is not available.",
        .{installable},
    );
    if (provision.saysNoNetwork(said)) return std.fmt.allocPrint(
        allocator,
        "{s} could not be downloaded or built, and that is the machine rather than your " ++
            "request. Do the work with what the toolchain already has.",
        .{installable},
    );
    return std.fmt.allocPrint(
        allocator,
        "{s} was not built. Nix said: {s}",
        .{ installable, said },
    );
}

/// A `fetch.Gate` that answers the same way about every host and records what
/// it was asked. **Not a policy table**: what the real one answers is
/// `lib/chock-broker/network.zig` and the project's own rules, and no test
/// here claims otherwise. What these tests pin is that the question is asked,
/// and that a no stops the build before `nix` is told to build.
const AnsweringGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool = true,
    asked: std.ArrayList([]const u8) = .empty,

    fn deinit(self: *AnsweringGate) void {
        for (self.asked.items) |one| self.gpa.free(one);
        self.asked.deinit(self.gpa);
    }

    fn gate(self: *AnsweringGate) fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: fetch.Gate.VTable = .{ .permit = permitFn };

    fn permitFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        one: fetch.Fetch,
    ) std.mem.Allocator.Error!fetch.Verdict {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        try self.asked.append(self.gpa, try self.gpa.dupe(u8, one.host));
        if (self.permitted) return .permitted;
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} fetches {s} from {s}, and this project allows no connection to it",
            .{ one.derivation, one.url, one.host },
        ) };
    }
};

/// What `nix derivation show -r` writes for a closure whose one input
/// fetches, and for one where nothing does.
const closure_that_fetches =
    \\{"derivations":{"b-src.drv":{"env":{"url":"https://files.example.com/src.tar.gz"},
    \\ "outputs":{"out":{"hash":"sha256-A","method":"flat"}}}}}
;
const closure_that_fetches_nothing =
    \\{"derivations":{"a-top.drv":{"env":{"name":"top"},
    \\ "outputs":{"out":{"path":"/nix/store/x-top"}}}}}
;

const testing = std.testing;

/// A `provision.Runner` that runs nothing, so every test here reaches no
/// daemon, no network and no store.
const FakeRunner = struct {
    gpa: std.mem.Allocator,
    replies: []const Reply,
    calls: usize = 0,
    seen: std.ArrayList([]const []const u8) = .empty,

    const Reply = struct {
        code: u8 = 0,
        stdout: []const u8 = "",
        stderr: []const u8 = "",
    };

    fn deinit(self: *FakeRunner) void {
        for (self.seen.items) |args| {
            for (args) |one| self.gpa.free(one);
            self.gpa.free(args);
        }
        self.seen.deinit(self.gpa);
    }

    fn runner(self: *FakeRunner) provision.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provision.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        _: std.Io,
        args: []const []const u8,
    ) provision.Error!proc.Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));

        const copy = try self.gpa.alloc([]const u8, args.len);
        errdefer self.gpa.free(copy);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        try self.seen.append(self.gpa, copy);

        const reply = self.replies[self.calls];
        self.calls += 1;
        return .{
            .term = .{ .exited = reply.code },
            .stdout = try allocator.dupe(u8, reply.stdout),
            .stderr = try allocator.dupe(u8, reply.stderr),
        };
    }
};

const example_drv = "/nix/store/00000000000000000000000000000000-example.drv";
const example_out = "/nix/store/11111111111111111111111111111111-example";

/// A `StoreWriter` that writes nowhere and answers the path the object says
/// it expects.
///
/// **It is not a store and no test here claims it is.** It records what the
/// evaluation handed it, so a test can ask what was written and how much,
/// while no test in this file reaches a daemon. What a real store does with a
/// real derivation is pinned in `test/nix/real.zig`.
const RecordingWriter = struct {
    gpa: std.mem.Allocator,
    /// Answered instead of the expected path, for the one test about a store
    /// that puts an object somewhere else.
    answer: ?[]const u8 = null,
    objects: usize = 0,
    bytes: usize = 0,

    fn writer(self: *RecordingWriter) StoreWriter {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: StoreWriter.VTable = .{ .add_object = addObject };

    fn addObject(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        object: backend.AddObject,
    ) anyerror![]u8 {
        const self: *RecordingWriter = @ptrCast(@alignCast(ptr));
        self.objects += 1;
        self.bytes += switch (object) {
            inline else => |one| one.bytes.len,
        };
        return allocator.dupe(u8, self.answer orelse object.expectedPath());
    }
};

/// A real evaluation of one derivation, through the seam an evaluation for a
/// build runs against. The driver is left holding what the evaluation wrote.
fn evaluateDerivation(allocator: std.mem.Allocator, driver: *backend.Driver) !void {
    const expr_mod = @import("expr");
    var engine = try expr_mod.Engine.init(allocator, .{ .worker_count = 1 });
    defer engine.deinit();
    try engine.setPureEval(true, &.{});
    try engine.setStoreBackend(driver.backend());
    engine.enableStoreWrites();

    const value = try engine.evaluate(
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    const path = (try engine.derivationDrvPath(value)).?;
    try engine.ensureDerivationClosure(path);
}

test "an attribute path and a flake reference build one installable and one expression" {
    const gpa = testing.allocator;
    const attr_path = [_][]const u8{ "packages", "x86_64-linux", "default" };

    const installable = try installableFor(gpa, "/work", &attr_path);
    defer gpa.free(installable);
    try testing.expectEqualStrings("/work#packages.x86_64-linux.default", installable);

    const expression = try expressionFor(gpa, "/work", &attr_path);
    defer gpa.free(expression);
    try testing.expectEqualStrings(
        "(builtins.getFlake \"/work\").\"packages\".\"x86_64-linux\".\"default\"",
        expression,
    );
}

test "an attribute name that is not a name is refused before anything is evaluated" {
    // The dot is the one that matters: `packages.a.b` as a single entry would
    // be two levels in the installable and one in the expression, so the two
    // spellings of one request would stop meaning the same thing.
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"a.b"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"has space"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"-option"}));
    try testing.expectError(error.AttrNotAName, checkAttrPath(&.{"/nix/store/x"}));
    try testing.expectError(error.AttrPathEmpty, checkAttrPath(&.{}));
    try checkAttrPath(&.{ "packages", "x86_64-linux", "default" });
}

test "a flake reference that would break out of a string or an argument is refused" {
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("a\"b"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("a\\b"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("${x}"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("nixpkgs#hello"));
    try testing.expectError(error.FlakeRefNotAReference, checkFlakeRef("--option"));
    try checkFlakeRef("github:NixOS/nixpkgs");
    try checkFlakeRef("/home/someone/project");
}

test "the host is told to realise the derivation this session wrote, and never an installable" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    try evaluateDerivation(gpa, &driver);

    // The whole of the gate: drop the `ensureDerivationClosure` call in
    // `evaluateDerivation` and this build is refused instead of run.
    const drv = drvPathOf(&driver).?;
    try testing.expect(driver.produced(drv));
    try testing.expect(recording.objects != 0);

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_that_fetches_nothing },
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n/nix/store/22222222222222222222222222222222-libc\n" },
    } };
    defer fake.deinit();

    var gate = AnsweringGate{ .gpa = gpa };
    defer gate.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .built);
    const built = answer.built;
    try testing.expectEqualStrings(example_out, built.out_paths[0]);
    try testing.expectEqual(@as(usize, 2), built.provided.store_paths.len);
    try testing.expectEqualStrings(example_out ++ "/bin", built.provided.bin_dirs[0]);

    // Nothing of this closure fetches, so nobody was asked about a host.
    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);

    // What was really asked of `nix`, rather than that something was. The
    // last argument is the object the driver authorised, with every output of
    // it, and no argument holds the attribute the model named: an installable
    // would let the host resolve the attribute a second time.
    try testing.expectEqualStrings("derivation", fake.seen.items[0][0]);
    try testing.expectEqualStrings("build", fake.seen.items[1][0]);
    try testing.expectEqualStrings("--no-link", fake.seen.items[1][1]);
    try testing.expectEqualStrings("--print-out-paths", fake.seen.items[1][2]);
    const realised = fake.seen.items[1][3];
    try testing.expect(std.mem.startsWith(u8, realised, drv));
    try testing.expectEqualStrings("^*", realised[drv.len..]);
    for (fake.seen.items[1]) |argument| {
        try testing.expect(std.mem.indexOfScalar(u8, argument, '#') == null);
    }
    try testing.expectEqualStrings("path-info", fake.seen.items[2][0]);

    // The model still reads the attribute it asked for.
    try testing.expectEqualStrings("/work#packages.x86_64-linux.default", built.provided.installable);

    // The seam that can build is off again, so nothing after this reaches one.
    try testing.expect(driver.seam.vtable.build_paths == null);
}

test "a derivation the store puts at another path is refused, and nothing is produced" {
    const gpa = testing.allocator;

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa, .answer = example_drv };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();

    // A store that answers a path of its own is a store holding something
    // other than what this session evaluated, so the evaluation stops there.
    try testing.expectError(WriteError.StorePathNotExpected, evaluateDerivation(gpa, &driver));
    try testing.expect(!driver.produced(example_drv));
    try testing.expectEqual(@as(usize, 0), driver.paths.count());

    const said = (try writeRefusal(gpa, "/work#a", WriteError.StorePathNotExpected)).?;
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "/work#a") != null);
    try testing.expectEqual(@as(?[]u8, null), try writeRefusal(gpa, "/work#a", error.OutOfMemory));
}

test "the object cap refuses a write, and the session total refuses a later write after earlier ones passed" {
    const gpa = testing.allocator;

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    // Smaller than one derivation text, so the object cap is what answers.
    driver.max_object_bytes = 8;

    try testing.expectError(backend.Error.ObjectTooLarge, evaluateDerivation(gpa, &driver));
    // The cap is checked before the seam, so the write never happened.
    try testing.expectEqual(@as(usize, 0), recording.objects);
    try testing.expectEqual(@as(u64, 0), budget.written_bytes);

    driver.max_object_bytes = backend.default_max_object_bytes;
    try evaluateDerivation(gpa, &driver);
    const first = budget.written_bytes;
    try testing.expect(first != 0);

    // The session total is what the second build spends against, and this
    // one has one byte less than it needs.
    budget.max_bytes = first * 2 - 1;
    var second = backend.Driver.init(gpa, writing.seam());
    defer second.deinit();
    try testing.expectError(WriteError.SessionStoreFull, evaluateDerivation(gpa, &second));
    try testing.expect(budget.written_bytes <= budget.max_bytes);

    const said = (try writeRefusal(gpa, "/work#a", WriteError.SessionStoreFull)).?;
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "max_session_bytes") != null);
}

/// The one path `driver` produced, for a test that needs the derivation path
/// the evaluator computed rather than one written out by hand.
fn drvPathOf(driver: *backend.Driver) ?[]const u8 {
    var keys = driver.paths.keyIterator();
    while (keys.next()) |key| {
        if (std.mem.endsWith(u8, key.*, ".drv")) return key.*;
    }
    return null;
}

test "a build of a store path this session never produced is refused by name, and nix is never run" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A driver that evaluated nothing, so its produced set is empty.
    var driver = backend.Driver.init(gpa, backend.Seam.refusing);
    defer driver.deinit();

    // A reply is here so that a runner that was reached would answer rather
    // than trap, and the assertion below is that it was not reached.
    var fake = FakeRunner{ .gpa = gpa, .replies = &.{.{ .stdout = example_out ++ "\n" }} };
    defer fake.deinit();

    const answer = try realise(
        arena,
        testing.io,
        fake.runner(),
        &driver,
        fetch.Gate.refusing,
        .{
            .derivation_path = example_drv,
            .installable = "/work#packages.x86_64-linux.default",
        },
    );

    // Not one `nix`, and the closure of a path nobody produced is not read
    // either: the driver answers first, so nothing this file runs takes a
    // path the model made up.
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expect(answer == .refused);
    // A model that reads a refusal with no subject sends the same request
    // again, so the path it asked for has to be in the words.
    try testing.expect(std.mem.indexOf(u8, answer.refused, example_drv) != null);
}

test "a nix that refused the build answers one sentence, and the machine faults are told apart" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    try evaluateDerivation(gpa, &driver);
    const drv = drvPathOf(&driver).?;

    var gate = AnsweringGate{ .gpa = gpa };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_that_fetches_nothing },
        .{ .code = 1, .stderr = "error: builder for '/nix/store/x.drv' failed with exit code 2" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });
    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "failed with exit code 2") != null);

    var no_daemon = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_that_fetches_nothing },
        .{ .code = 1, .stderr = "error: cannot connect to socket at '/nix/var/nix/daemon-socket'" },
    } };
    defer no_daemon.deinit();

    const stopped = try realise(arena, testing.io, no_daemon.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });
    try testing.expect(stopped == .refused);
    try testing.expect(std.mem.indexOf(u8, stopped.refused, "daemon could not be reached") != null);
}

test "the seam an evaluation runs against authorises no build and reads no store file" {
    const gpa = testing.allocator;

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };
    const seam = writing.seam();

    var driver = backend.Driver.init(gpa, seam);
    defer driver.deinit();

    // Import from derivation reaches `build_paths`, and this seam has none,
    // so an evaluation cannot build its own input however it is written.
    try testing.expect(seam.vtable.build_paths == null);
    try testing.expect(seam.vtable.read_file == null);
    try testing.expectError(
        backend.Error.BuildRefused,
        driver.build(&.{example_drv}, .normal),
    );
}

test "a build whose fetch host nobody allowed is refused, and nix is never told to build" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    try evaluateDerivation(gpa, &driver);
    const drv = drvPathOf(&driver).?;

    var gate = AnsweringGate{ .gpa = gpa, .permitted = false };
    defer gate.deinit();

    // Only the closure is answered. A reply for the build is here so that a
    // runner that was reached would answer rather than trap.
    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_that_fetches },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .refused);
    // The host and the derivation are both in the words, so the model can ask
    // for that host rather than send the same attribute again.
    try testing.expect(std.mem.indexOf(u8, answer.refused, "files.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "b-src.drv") != null);

    // One call, and it is the read. `nix` was never told to build.
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("derivation", fake.seen.items[0][0]);
    try testing.expectEqualStrings("show", fake.seen.items[0][1]);

    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings("files.example.com", gate.asked.items[0]);
}

test "a build whose fetch host is allowed runs, and the host was asked about first" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    try evaluateDerivation(gpa, &driver);
    const drv = drvPathOf(&driver).?;

    var gate = AnsweringGate{ .gpa = gpa, .permitted = true };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_that_fetches },
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .built);
    try testing.expectEqualStrings(example_out, answer.built.out_paths[0]);
    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings("files.example.com", gate.asked.items[0]);
    try testing.expectEqualStrings("build", fake.seen.items[1][0]);
}

test "a fixed output derivation with a scheme nothing can name refuses the build" {
    const gpa = testing.allocator;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var budget: Budget = .{};
    var recording: RecordingWriter = .{ .gpa = gpa };
    var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };

    var driver = backend.Driver.init(gpa, writing.seam());
    defer driver.deinit();
    try evaluateDerivation(gpa, &driver);
    const drv = drvPathOf(&driver).?;

    // A gate that says yes to everything, so what refuses is the reader and
    // never the policy: a fetch nobody can name is a fetch nobody can rule on.
    var gate = AnsweringGate{ .gpa = gpa, .permitted = true };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{
            .stdout =
            \\{"derivations":{"b-src.drv":{"env":{"url":"ftp://files.example.com/src.tar.gz"},
            \\ "outputs":{"out":{"hash":"sha256-A"}}}}}
            ,
        },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &driver, gate.gate(), .{
        .derivation_path = drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .refused);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "ftp://files.example.com") != null);
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);
}
