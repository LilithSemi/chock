//! The agent names an attribute to build, and the host builds it. The build
//! runs on the host, outside every sandbox, because a sandbox has no daemon
//! socket, no network and no writable cache directory.

const std = @import("std");

const backend = @import("backend.zig");
const daemon = @import("store").daemon;
const fetch = @import("fetch.zig");
const proc = @import("proc.zig");
const provision = @import("provision.zig");
const store = @import("store.zig");

pub const Error = provision.Error;

/// What `nix` said when it would not build. `realise` turns it into words.
const NixRefused = error{NixRefusedTheBuild};

/// A host the build would reach that nobody permitted, or one nothing could
/// name. `Host.refusal` holds the words.
const FetchRefused = error{FetchNotPermitted};

/// The most attributes one path may hold, and the longest one may be. A real
/// path is three deep and its names are words.
pub const max_segments: usize = 8;
pub const max_segment_bytes: usize = 128;

/// The longest flake reference this accepts.
pub const max_flake_ref_bytes: usize = 512;

pub const RequestError = error{
    AttrPathEmpty,
    AttrPathTooDeep,
    /// A segment is empty, too long, or holds a character `checkSegment`
    /// refuses.
    AttrNotAName,
    FlakeRefEmpty,
    FlakeRefTooLong,
    /// The reference holds a character that would not survive being written
    /// into an expression or an argument. See `checkFlakeRef`.
    FlakeRefNotAReference,
};

/// A dot is refused because the path is written twice, as an expression and as
/// the fragment of an installable, and a dot is a level boundary in the second
/// spelling.
fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '-', '_', '+' => true,
        else => false,
    };
}

fn checkSegment(segment: []const u8) RequestError!void {
    if (segment.len == 0 or segment.len > max_segment_bytes) return error.AttrNotAName;
    if (!std.ascii.isAlphanumeric(segment[0])) return error.AttrNotAName;
    for (segment) |character| {
        if (!isNameCharacter(character)) return error.AttrNotAName;
    }
}

pub fn checkAttrPath(attr_path: []const []const u8) RequestError!void {
    if (attr_path.len == 0) return error.AttrPathEmpty;
    if (attr_path.len > max_segments) return error.AttrPathTooDeep;
    for (attr_path) |segment| try checkSegment(segment);
}

/// A reference is written into a Nix string literal and into an argument of
/// `nix`, so a quote, a backslash, a dollar sign, a `#` and any whitespace are
/// refused.
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

/// The installable `<flake ref>#<attribute>.<attribute>`: the policy question,
/// the log and what the model is told. Never an argument of `nix`, which is
/// given the derivation path instead. The caller owns the result, and both
/// arguments must already have passed their check.
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

/// The expression that evaluates to what the installable names, for the
/// evaluator inside Chock. Every attribute is quoted, so it selects the names
/// the caller sent and reads no dot as a boundary of its own.
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

pub const default_daemon_socket = daemon.default_socket_path;

/// The most one session may put in the host store when nothing named a number.
/// The same number as `chock_policy.nix.default_max_session_bytes`, written
/// twice because this library imports no other chock library.
pub const default_max_session_bytes: u64 = 256 << 20;

pub const WriteError = error{
    /// This session has already written `Budget.max_bytes`.
    SessionStoreFull,
    /// The store put the object somewhere other than the path fix computed
    /// for it, so the two do not hold the same object.
    StorePathNotExpected,
};

/// How much of the host store one session has taken, and the most it may.
///
/// One per session and never one per call. Every write counts, so this bounds
/// the work asked of the store rather than the disk it keeps.
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

/// Where an object of an evaluation for a build is really written. A seam for
/// the same reason `provision.Runner` is one. `DaemonWriter` is the real one.
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
/// daemon, on the host. A machine with no daemon builds nothing here.
pub const DaemonWriter = struct {
    store: *daemon.DaemonStore,

    /// Connect to the daemon at `endpoint`, a socket path or
    /// `default_daemon_socket`. The `io` must open a socket and outlive this.
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
/// Every object goes to the host store, and the path the store answers with is
/// checked against the path fix computed before the driver records it. There
/// is no `build_paths` here, so import from derivation is refused.
pub const Writing = struct {
    writer: StoreWriter,
    /// This session's own, shared with every other build of it.
    budget: *Budget,
    /// The store paths this session fetched on the host, before the
    /// evaluation. See `lib/chock-nix/inputs.zig`.
    fetched_paths: []const []const u8 = &.{},

    pub fn seam(self: *Writing) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
    };

    /// True for a path of `fetched_paths` and false for every other path.
    ///
    /// False keeps the produced set whole: a write the evaluation skips is a
    /// path the produced set never records, and the build of it would be
    /// refused. A flake input must answer true, because fix takes a locked
    /// input from the store when the store says its path is valid. Nothing is
    /// built out of those.
    fn isValidPath(context: *anyopaque, path: []const u8) anyerror!bool {
        const self: *Writing = @ptrCast(@alignCast(context));
        for (self.fetched_paths) |one| {
            if (std.mem.eql(u8, one, path)) return true;
        }
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
        // The store computes the path from the content it took, so another
        // answer means the two do not hold the same object.
        if (!std.mem.eql(u8, written, object.expectedPath())) {
            return WriteError.StorePathNotExpected;
        }
        return written;
    }
};

/// The store seam that really builds, on the host.
///
/// It builds `<derivation path>^*`, every output of the derivation the driver
/// authorised, and never the installable. The hosts it would reach are asked
/// about here, after the driver has checked the path. See `askAboutFetches`.
pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    /// `<derivation path>^*`, from `realise`.
    derivation_outputs: []const u8,
    /// The default permits nothing, so a caller that wired none builds nothing
    /// that fetches.
    gate: fetch.Gate = fetch.Gate.refusing,
    /// What `nix` wrote when it would not build, borrowed from `allocator`.
    said: []const u8 = "",
    /// Why a fetch of this build was refused, borrowed from `allocator`.
    refusal: []const u8 = "",
    /// The outputs the build produced, empty until it has.
    out_paths: []const []const u8 = &.{},
    /// What `nix` is given on top of its own environment, so a builder cannot
    /// walk a mirror list past the one host that was allowed.
    ///
    /// A pin holds because the two nixpkgs `fetchurl` builders read
    /// `NIX_MIRRORS_<site>` and `NIX_HASHED_MIRRORS`, both of which are in the
    /// derivation's own `impureEnvVars`. Another fetcher would walk its own
    /// list and nothing here would know.
    pins: []const provision.Variable = &.{},

    pub fn seam(self: *Host) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{ .build_paths = buildPaths };

    /// Put every host the closure of `derivation_path` would reach to the gate,
    /// and answer `FetchNotPermitted` on the first one nobody allowed.
    ///
    /// A fixed output derivation builds with the network open to it and its
    /// output hash is checked after the request has gone out, so the hash is
    /// integrity and never egress. There is no backstop under this: `nix` has
    /// no flag that keeps such a builder off the network, `--offline` does not,
    /// and a host whose Nix has `sandbox` off gives every builder the network.
    fn askAboutFetches(self: *Host, derivation_path: []const u8) anyerror!void {
        const reached = switch (try fetch.fetchesOf(
            self.allocator,
            self.io,
            self.runner,
            derivation_path,
        )) {
            .reached => |one| one,
            .unreadable => |one| {
                self.refusal = try fetch.unreadableRefusal(self.allocator, one);
                return FetchRefused.FetchNotPermitted;
            },
            .nix_said => |said| {
                self.refusal = try fetch.closureRefusal(self.allocator, derivation_path, said);
                return FetchRefused.FetchNotPermitted;
            },
        };

        var wanted: std.ArrayList(fetch.Fetch) = .empty;
        try wanted.appendSlice(self.allocator, reached.hosts);

        var pins: std.ArrayList(provision.Variable) = .empty;
        var chosen: std.ArrayList(Chosen) = .empty;
        for (reached.sites) |one| {
            const mirror = try self.chooseMirror(one);
            try wanted.append(self.allocator, mirror.asking);
            try chosen.append(self.allocator, .{ .site = one.site, .host = mirror.asking.host });
            try pins.append(self.allocator, .{
                .name = try std.fmt.allocPrint(self.allocator, "NIX_MIRRORS_{s}", .{one.site}),
                .value = mirror.base,
            });
        }

        // One yes under `nix.fetch.hosts` covers every host no rule named. A
        // project narrows it with a `net.connect` rule per host, which is read
        // first and takes that host out of the question.
        switch (try self.gate.permitAll(self.allocator, wanted.items)) {
            .permitted => {},
            .refused => |why| {
                self.refusal = try withSites(self.allocator, why, chosen.items);
                return FetchRefused.FetchNotPermitted;
            },
        }

        // A fixed output derivation that says nowhere it fetches from has no
        // host a rule could cover, and `zig.fetchDeps`, npm deps and
        // `fetchCargoVendor` all take that shape. `chock-policy/defaults.zig`
        // ships `nix.fetch.opaque` as allow, because refusing them refuses
        // nearly every Rust, Node and Zig package.
        if (reached.opaque_subjects.len != 0) {
            switch (try self.gate.permitOpaque(self.allocator, reached.opaque_subjects)) {
                .permitted => {},
                .refused => |why| {
                    self.refusal = try fetch.opaqueRefusal(
                        self.allocator,
                        reached.opaque_subjects,
                        why,
                    );
                    return FetchRefused.FetchNotPermitted;
                },
            }
        }

        // The builder tries a hashed mirror on its own whatever the URLs say,
        // so a value left alone is a host nobody named and nobody allowed.
        if (reached.reads_mirrors) try pins.append(self.allocator, .{
            .name = "NIX_HASHED_MIRRORS",
            .value = try self.chooseHashedMirror(reached.hashed),
        });

        self.pins = try pins.toOwnedSlice(self.allocator);
    }

    const Chosen = struct {
        site: []const u8,
        host: []const u8,
    };

    /// The mirror of `one` this build would use, and the question it puts.
    ///
    /// A mirror a rule already permits is taken outright, and otherwise the
    /// first mirror of the file's own order that has a host at all is asked
    /// about. Two derivations of one closure can name the same site and two
    /// mirrors files, and the first file read answers for both, which can stop
    /// the second fetch. It cannot widen one: every pinned mirror was allowed.
    fn chooseMirror(self: *Host, one: fetch.MirrorSite) anyerror!struct {
        base: []const u8,
        asking: fetch.Fetch,
    } {
        for (one.mirrors) |mirror| {
            const target = mirror.target orelse continue;
            const asking = fetchOfMirror(one, mirror, target);
            if (self.gate.allowsByRule(asking)) return .{ .base = mirror.base, .asking = asking };
        }

        for (one.mirrors) |mirror| {
            const target = mirror.target orelse continue;
            return .{ .base = mirror.base, .asking = fetchOfMirror(one, mirror, target) };
        }

        self.refusal = try fetch.unreadableRefusal(self.allocator, .{
            .subject = one.subject,
            .url = one.url,
            .site = one.site,
            .why = .mirror_not_nameable,
        });
        return FetchRefused.FetchNotPermitted;
    }

    /// What `NIX_HASHED_MIRRORS` is pinned to. Nobody is asked, because no URL
    /// of the derivation names a hashed mirror and a question about a host the
    /// request never mentioned has no answer a person can weigh. A rule that
    /// already permits the host pins it, and everything else turns it off.
    fn chooseHashedMirror(self: *Host, mirrors: []const fetch.Mirror) anyerror![]const u8 {
        for (mirrors) |mirror| {
            const target = mirror.target orelse continue;
            const asking = fetch.Fetch{
                .subject = "the hashed mirrors of this build",
                .url = mirror.url,
                .host = target.host,
                .port = target.port,
            };
            if (!self.gate.allowsByRule(asking)) continue;
            switch (try self.gate.permitAll(self.allocator, &.{asking})) {
                .permitted => return mirror.base,
                .refused => break,
            }
        }
        return fetch.hashed_mirrors_off;
    }

    fn buildPaths(
        context: *anyopaque,
        paths: []const []const u8,
        _: ?backend.BuildSink,
        _: backend.BuildMode,
    ) anyerror!void {
        const self: *Host = @ptrCast(@alignCast(context));
        // `paths` is what the driver authorised, so the closure read below is
        // of that object and of nothing the model named.
        try self.askAboutFetches(paths[0]);

        const built = try self.runner.runPinned(self.allocator, self.io, &.{
            "build",
            // No result symbolic link: a `result` in the user's project
            // directory is litter. See `provision.resolve`.
            "--no-link",
            "--print-out-paths",
            self.derivation_outputs,
        }, self.pins);
        if (!built.succeeded()) {
            self.said = provision.lastLine(built.stderr);
            return NixRefused.NixRefusedTheBuild;
        }
        self.out_paths = try store.parsePathList(self.allocator, built.stdout);
    }
};

/// `why`, with the mirror sites of the build named after it. A refusal has to
/// name the site as well as the host: the site is what the derivation wrote,
/// and the host is what a rule would have to cover.
fn withSites(
    allocator: std.mem.Allocator,
    why: []const u8,
    chosen: []const Host.Chosen,
) std.mem.Allocator.Error![]const u8 {
    if (chosen.len == 0) return why;

    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(allocator, why);
    try text.appendSlice(allocator, " The mirror sites of this build were put to the policy as");
    for (chosen, 0..) |one, index| {
        try text.appendSlice(allocator, if (index == 0) " " else ", ");
        try text.print(allocator, "{s} at {s}", .{ one.site, one.host });
    }
    try text.append(allocator, '.');
    return text.toOwnedSlice(allocator);
}

fn fetchOfMirror(
    site: fetch.MirrorSite,
    mirror: fetch.Mirror,
    target: fetch.Target,
) fetch.Fetch {
    return .{
        .subject = site.subject,
        .url = mirror.url,
        .host = target.host,
        .port = target.port,
    };
}

pub const Request = struct {
    /// The derivation this attribute's own evaluation put in the host store.
    /// The driver checks it against its produced set.
    derivation_path: []const u8,
    /// `<flake ref>#<attribute path>`. What the policy was asked about and what
    /// the model is told, and never an argument of `nix`.
    installable: []const u8,
};

/// A build that happened.
///
/// It does not prove what came out. The builder ran under the host's Nix, a
/// substituter may have answered for an output path instead of building it,
/// and nothing says the attribute is the one the person meant or that the
/// derivation is safe to run. The write is a capability of its own: the
/// derivation stays in the host store until the host collects it.
pub const Built = struct {
    /// The shape a provisioned program already answers with, so a built
    /// package joins the toolchain by the road that is already there.
    provided: provision.Provided,
    out_paths: []const []const u8,
};

/// What one `realise` produced: a build, or one sentence saying why not.
pub const Answer = union(enum) {
    built: Built,
    refused: []const u8,
};

/// Build `request` on the host, if `driver` produced its derivation. It calls
/// `Driver.build`, the same function the evaluator's own build goes through,
/// so there is one answer to what this session produced. Give it an arena.
pub fn realise(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    driver: *backend.Driver,
    gate: fetch.Gate,
    request: Request,
) Error!Answer {
    // Every output of that one derivation. `nix` reads a bare derivation path
    // as a request for its default output.
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

    // Installed here and taken off below, so an evaluation cannot reach a
    // build whatever the expression says.
    driver.seam = host.seam();
    defer driver.seam = backend.Seam.refusing;

    driver.build(&.{request.derivation_path}, .normal) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.RunnerFailed => return error.RunnerFailed,
        error.BuildRefused => return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} was not built, and nothing ran: {s}",
            .{ request.installable, driver.lastError() orelse "the build was refused" },
        ) },
        NixRefused.NixRefusedTheBuild => return .{
            .refused = try explainFailure(allocator, request.installable, host.said),
        },
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
/// `err` is not a `WriteError`.
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

/// Why `nix` would not build, in the words of what to do next. The two machine
/// faults are told apart from a request fault, because a model that reads them
/// as its own mistake sends a second attribute.
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
/// it was asked. Not a policy table: the real answers come from
/// `lib/chock-broker/network.zig` and the project's own rules.
const AnsweringGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool = true,
    asked: std.ArrayList([]const u8) = .empty,
    /// The hosts a rule permits with nobody asked, which is what picks one
    /// mirror of a site out of ten.
    by_rule: []const []const u8 = &.{},
    /// How many questions reached somebody.
    prompted: usize = 0,
    /// Whether a build may fetch with no URL, and how often that was asked.
    opaque_permitted: bool = true,
    opaque_asks: usize = 0,
    opaque_count: usize = 0,

    fn deinit(self: *AnsweringGate) void {
        for (self.asked.items) |one| self.gpa.free(one);
        self.asked.deinit(self.gpa);
    }

    fn gate(self: *AnsweringGate) fetch.Gate {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: fetch.Gate.VTable = .{
        .permit_all = permitAllFn,
        .permit_opaque = permitOpaqueFn,
        .allows_by_rule = allowsByRuleFn,
    };

    fn permitOpaqueFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        subjects: []const []const u8,
    ) std.mem.Allocator.Error!fetch.Verdict {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        self.opaque_asks += 1;
        self.opaque_count = subjects.len;
        if (self.opaque_permitted) return .permitted;
        return .{ .refused = try allocator.dupe(u8, "this project answers deny for it") };
    }

    fn permitAllFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        wanted: []const fetch.Fetch,
    ) std.mem.Allocator.Error!fetch.Verdict {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));

        var refusing: ?fetch.Fetch = null;
        for (wanted) |one| {
            try self.asked.append(self.gpa, try self.gpa.dupe(u8, one.host));
            if (allowsByRuleFn(ptr, one)) continue;
            if (refusing == null) refusing = one;
        }
        if (refusing == null) return .permitted;

        self.prompted += 1;
        if (self.permitted) return .permitted;
        const one = refusing.?;
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "{s} fetches {s} from {s}, and this project allows no connection to it",
            .{ one.subject, one.url, one.host },
        ) };
    }

    fn allowsByRuleFn(ptr: *anyopaque, one: fetch.Fetch) bool {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        for (self.by_rule) |host| {
            if (std.mem.eql(u8, host, one.host)) return true;
        }
        return false;
    }
};

/// What `nix derivation show -r` writes for a closure whose one input fetches,
/// and for one where nothing does.
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
    seen_pins: std.ArrayList(provision.Variable) = .empty,

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
        for (self.seen_pins.items) |one| {
            self.gpa.free(one.name);
            self.gpa.free(one.value);
        }
        self.seen_pins.deinit(self.gpa);
    }

    fn pin(self: *const FakeRunner, name: []const u8) ?[]const u8 {
        for (self.seen_pins.items) |one| {
            if (std.mem.eql(u8, one.name, name)) return one.value;
        }
        return null;
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
        pins: []const provision.Variable,
    ) provision.Error!proc.Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));

        const copy = try self.gpa.alloc([]const u8, args.len);
        errdefer self.gpa.free(copy);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        try self.seen.append(self.gpa, copy);

        for (pins) |one| try self.seen_pins.append(self.gpa, .{
            .name = try self.gpa.dupe(u8, one.name),
            .value = try self.gpa.dupe(u8, one.value),
        });

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

/// A `StoreWriter` that writes nowhere and answers the path the object says it
/// expects. What a real store does is pinned in `test/nix/real.zig`.
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
/// build runs against.
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

    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);

    // The last argument is the object the driver authorised, and no argument
    // holds the attribute: an installable would let the host resolve it twice.
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

    // The session total is what the second build spends against, and this one
    // has one byte less than it needs.
    budget.max_bytes = first * 2 - 1;
    var second = backend.Driver.init(gpa, writing.seam());
    defer second.deinit();
    try testing.expectError(WriteError.SessionStoreFull, evaluateDerivation(gpa, &second));
    try testing.expect(budget.written_bytes <= budget.max_bytes);

    const said = (try writeRefusal(gpa, "/work#a", WriteError.SessionStoreFull)).?;
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "max_session_bytes") != null);
}

/// The one path `driver` produced, rather than one written out by hand.
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

    var driver = backend.Driver.init(gpa, backend.Seam.refusing);
    defer driver.deinit();

    // A reply so that a runner that was reached would answer rather than trap.
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

    // Not one `nix`: the driver answers before any closure is read.
    try testing.expectEqual(@as(usize, 0), fake.calls);
    try testing.expect(answer == .refused);
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

    // Import from derivation reaches `build_paths`, and this seam has none.
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
            \\{"derivations":{"b-src.drv":{"env":{"url":"s3://files.example.com/src.tar.gz"},
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
    try testing.expect(std.mem.indexOf(u8, answer.refused, "s3://files.example.com") != null);
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);
}

/// Write the real nixpkgs mirrors list into `tmp` and answer its absolute path.
fn writeMirrorsList(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "mirrors-list",
        .data = fetch.nixpkgs_mirrors_sample,
    });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/mirrors-list", .{buffer[0..len]});
}

/// A closure of one `fetchurl` derivation that fetches from the `gnu` mirror
/// site. The shape nixpkgs writes today, trimmed.
fn closureFetchingAMirror(allocator: std.mem.Allocator, mirrors_path: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{"derivations":{{"b-src.drv":{{"env":{{"out":"/nix/store/x-src"}},
        \\ "outputs":{{"out":{{"hash":"sha256-A","method":"flat"}}}},
        \\ "structuredAttrs":{{"urls":["mirror://gnu/hello/hello-2.12.3.tar.gz"],
        \\ "mirrorsFile":"{s}"}}}}}}}}
    ,
        .{mirrors_path},
    );
}

/// Everything a mirror test needs, with the closure `nix derivation show`
/// answers for it.
const MirrorCase = struct {
    budget: Budget = .{},
    recording: RecordingWriter,
    writing: Writing = undefined,
    driver: backend.Driver = undefined,
    tmp: std.testing.TmpDir,
    drv: []const u8 = "",
    closure: []u8 = "",

    fn start(gpa: std.mem.Allocator, arena: std.mem.Allocator) !*MirrorCase {
        const self = try arena.create(MirrorCase);
        self.* = .{ .recording = .{ .gpa = gpa }, .tmp = std.testing.tmpDir(.{}) };
        self.writing = .{ .writer = self.recording.writer(), .budget = &self.budget };
        self.driver = backend.Driver.init(gpa, self.writing.seam());
        try evaluateDerivation(gpa, &self.driver);
        self.drv = drvPathOf(&self.driver).?;
        self.closure = try closureFetchingAMirror(arena, try writeMirrorsList(arena, &self.tmp));
        return self;
    }

    fn deinit(self: *MirrorCase) void {
        self.driver.deinit();
        self.tmp.cleanup();
    }
};

test "the mirror a rule already permits is the one taken, and nobody is asked about the site" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var case = try MirrorCase.start(gpa, arena);
    defer case.deinit();

    // The third mirror the file names for `gnu`, so taking it proves the whole
    // list was read and not only its head.
    var gate = AnsweringGate{
        .gpa = gpa,
        .permitted = false,
        .by_rule = &.{"mirrors.kernel.org"},
    };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = case.closure },
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &case.driver, gate.gate(), .{
        .derivation_path = case.drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .built);
    try testing.expectEqual(@as(usize, 0), gate.prompted);
    try testing.expectEqualStrings(
        "https://mirrors.kernel.org/gnu/",
        fake.pin("NIX_MIRRORS_gnu").?,
    );
}

test "with no rule the first mirror that can be named is asked about, and a no names the site" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var case = try MirrorCase.start(gpa, arena);
    defer case.deinit();

    var gate = AnsweringGate{ .gpa = gpa, .permitted = false };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = case.closure },
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &case.driver, gate.gate(), .{
        .derivation_path = case.drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .refused);
    // One question for the site and never one for each of its eight mirrors.
    try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
    try testing.expectEqualStrings("ftpmirror.gnu.org", gate.asked.items[0]);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "gnu") != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "ftpmirror.gnu.org") != null);
    try testing.expectEqual(@as(usize, 1), fake.calls);
}

test "the environment nix is given pins the site to the allowed mirror and nothing else" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var case = try MirrorCase.start(gpa, arena);
    defer case.deinit();

    var gate = AnsweringGate{ .gpa = gpa, .permitted = true };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = case.closure },
        .{ .stdout = example_out ++ "\n" },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realise(arena, testing.io, fake.runner(), &case.driver, gate.gate(), .{
        .derivation_path = case.drv,
        .installable = "/work#packages.x86_64-linux.default",
    });

    try testing.expect(answer == .built);
    // The site and the hashed mirrors, and no other variable.
    try testing.expectEqual(@as(usize, 2), fake.seen_pins.items.len);
    try testing.expectEqualStrings(
        "https://ftpmirror.gnu.org/",
        fake.pin("NIX_MIRRORS_gnu").?,
    );
}

test "the hashed mirrors are turned off unless a rule allows their own host" {
    // A host that appears in no url of the derivation. The builder tries a
    // hashed mirror for every fetch, so a variable left alone reaches
    // tarballs.nixos.org with nobody asked.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var case = try MirrorCase.start(gpa, arena);
        defer case.deinit();

        var gate = AnsweringGate{ .gpa = gpa, .permitted = true };
        defer gate.deinit();

        var fake = FakeRunner{ .gpa = gpa, .replies = &.{
            .{ .stdout = case.closure },
            .{ .stdout = example_out ++ "\n" },
            .{ .stdout = example_out ++ "\n" },
        } };
        defer fake.deinit();

        const answer = try realise(arena, testing.io, fake.runner(), &case.driver, gate.gate(), .{
            .derivation_path = case.drv,
            .installable = "/work#a",
        });
        try testing.expect(answer == .built);
        // Not the empty string: both builder shapes read this variable only
        // when it is not empty, so empty would leave the file's own list in
        // force. See `fetch.hashed_mirrors_off`.
        try testing.expectEqualStrings(
            fetch.hashed_mirrors_off,
            fake.pin("NIX_HASHED_MIRRORS").?,
        );
        try testing.expect(fetch.hashed_mirrors_off.len != 0);
    }

    {
        var case = try MirrorCase.start(gpa, arena);
        defer case.deinit();

        var gate = AnsweringGate{
            .gpa = gpa,
            .permitted = true,
            .by_rule = &.{"tarballs.nixos.org"},
        };
        defer gate.deinit();

        var fake = FakeRunner{ .gpa = gpa, .replies = &.{
            .{ .stdout = case.closure },
            .{ .stdout = example_out ++ "\n" },
            .{ .stdout = example_out ++ "\n" },
        } };
        defer fake.deinit();

        const answer = try realise(arena, testing.io, fake.runner(), &case.driver, gate.gate(), .{
            .derivation_path = case.drv,
            .installable = "/work#a",
        });
        try testing.expect(answer == .built);
        try testing.expectEqualStrings(
            "https://tarballs.nixos.org",
            fake.pin("NIX_HASHED_MIRRORS").?,
        );
    }
}

test "a closure that reads no mirrors file pins nothing at all" {
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
        .installable = "/work#a",
    });

    try testing.expect(answer == .built);
    try testing.expectEqual(@as(usize, 0), fake.seen_pins.items.len);
}

/// A closure whose one fixed output derivation says nowhere it fetches from,
/// the shape `zig.fetchDeps` and npm deps take, and one that holds three.
const closure_that_fetches_opaquely =
    \\{"derivations":{"b-zig-deps.drv":{"env":{"name":"b"},
    \\ "outputs":{"out":{"hash":"sha256-A","method":"recursive"}}}}}
;
const closure_with_three_opaque_fetches =
    \\{"derivations":{
    \\ "b-zig-deps.drv":{"env":{"name":"b"},"outputs":{"out":{"hash":"sha256-A"}}},
    \\ "c-npm-deps.drv":{"env":{"name":"c"},"outputs":{"out":{"hash":"sha256-B"}}},
    \\ "d-cargo-vendor.drv":{"env":{"name":"d"},"outputs":{"out":{"hash":"sha256-C"}}}
    \\}}
;

/// Everything `realise` needs for a closure a test supplies.
fn realiseClosure(
    arena: std.mem.Allocator,
    fake: *FakeRunner,
    gate: *AnsweringGate,
    driver: *backend.Driver,
) !Answer {
    return realise(arena, testing.io, fake.runner(), driver, gate.gate(), .{
        .derivation_path = drvPathOf(driver).?,
        .installable = "/work#packages.x86_64-linux.default",
    });
}

test "a build that fetches with no url asks once, and a no names a derivation" {
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

    var gate = AnsweringGate{ .gpa = gpa, .opaque_permitted = false };
    defer gate.deinit();

    var fake = FakeRunner{ .gpa = gpa, .replies = &.{
        .{ .stdout = closure_with_three_opaque_fetches },
        .{ .stdout = example_out ++ "\n" },
    } };
    defer fake.deinit();

    const answer = try realiseClosure(arena, &fake, &gate, &driver);

    try testing.expect(answer == .refused);
    // One question for the three, because there is no host to tell them apart.
    try testing.expectEqual(@as(usize, 1), gate.opaque_asks);
    try testing.expectEqual(@as(usize, 3), gate.opaque_count);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "deps.drv") != null);
    try testing.expect(std.mem.indexOf(u8, answer.refused, "3 derivations") != null);
    try testing.expectEqual(@as(usize, 1), fake.calls);
    try testing.expectEqualStrings("derivation", fake.seen.items[0][0]);
    try testing.expectEqual(@as(usize, 0), gate.asked.items.len);
}

test "a yes to a fetch with no url builds, and a closure with none never asks it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var budget: Budget = .{};
        var recording: RecordingWriter = .{ .gpa = gpa };
        var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };
        var driver = backend.Driver.init(gpa, writing.seam());
        defer driver.deinit();
        try evaluateDerivation(gpa, &driver);

        var gate = AnsweringGate{ .gpa = gpa, .opaque_permitted = true };
        defer gate.deinit();

        var fake = FakeRunner{ .gpa = gpa, .replies = &.{
            .{ .stdout = closure_that_fetches_opaquely },
            .{ .stdout = example_out ++ "\n" },
            .{ .stdout = example_out ++ "\n" },
        } };
        defer fake.deinit();

        const answer = try realiseClosure(arena, &fake, &gate, &driver);
        try testing.expect(answer == .built);
        try testing.expectEqual(@as(usize, 1), gate.opaque_asks);
    }

    {
        var budget: Budget = .{};
        var recording: RecordingWriter = .{ .gpa = gpa };
        var writing: Writing = .{ .writer = recording.writer(), .budget = &budget };
        var driver = backend.Driver.init(gpa, writing.seam());
        defer driver.deinit();
        try evaluateDerivation(gpa, &driver);

        var gate = AnsweringGate{ .gpa = gpa, .opaque_permitted = false };
        defer gate.deinit();

        var fake = FakeRunner{ .gpa = gpa, .replies = &.{
            .{ .stdout = closure_that_fetches },
            .{ .stdout = example_out ++ "\n" },
            .{ .stdout = example_out ++ "\n" },
        } };
        defer fake.deinit();

        const answer = try realiseClosure(arena, &fake, &gate, &driver);
        try testing.expect(answer == .built);
        try testing.expectEqual(@as(usize, 0), gate.opaque_asks);
        try testing.expectEqual(@as(usize, 1), gate.asked.items.len);
        try testing.expectEqualStrings("files.example.com", gate.asked.items[0]);
    }
}
