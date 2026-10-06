//! The agent names an attribute to build, and the host builds it. The build

const std = @import("std");

const backend = @import("backend.zig");
const daemon = @import("store").daemon;
const fetch = @import("fetch.zig");
const proc = @import("proc.zig");
const provision = @import("provision.zig");
const store = @import("store.zig");

pub const Error = provision.Error;

const NixRefused = error{NixRefusedTheBuild};

const FetchRefused = error{FetchNotPermitted};

pub const max_segments: usize = 8;
pub const max_segment_bytes: usize = 128;

pub const max_flake_ref_bytes: usize = 512;

pub const RequestError = error{
    AttrPathEmpty,
    AttrPathTooDeep,
    AttrNotAName,
    FlakeRefEmpty,
    FlakeRefTooLong,
    FlakeRefNotAReference,
};

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

pub const default_max_session_bytes: u64 = 256 << 20;

pub const WriteError = error{
    SessionStoreFull,
    StorePathNotExpected,
};

pub const Budget = struct {
    max_bytes: u64 = default_max_session_bytes,
    written_bytes: u64 = 0,

    pub fn take(self: *Budget, bytes: u64) WriteError!void {
        const total = std.math.add(u64, self.written_bytes, bytes) catch
            return error.SessionStoreFull;
        if (total > self.max_bytes) return error.SessionStoreFull;
        self.written_bytes = total;
    }
};

pub const StoreWriter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
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

pub const DaemonWriter = struct {
    store: *daemon.DaemonStore,

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

pub const Writing = struct {
    writer: StoreWriter,
    budget: *Budget,
    fetched_paths: []const []const u8 = &.{},

    pub fn seam(self: *Writing) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
    };

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
        // The store computes the path from the content it took, so a different answer means the two do not hold the same object.
        if (!std.mem.eql(u8, written, object.expectedPath())) {
            return WriteError.StorePathNotExpected;
        }
        return written;
    }
};

pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    derivation_outputs: []const u8,
    gate: fetch.Gate = fetch.Gate.refusing,
    said: []const u8 = "",
    refusal: []const u8 = "",
    out_paths: []const []const u8 = &.{},
    pins: []const provision.Variable = &.{},

    pub fn seam(self: *Host) backend.Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable: backend.Seam.VTable = .{ .build_paths = buildPaths };

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

        switch (try self.gate.permitAll(self.allocator, reached.hosts)) {
            .permitted => {},
            .refused => |why| {
                self.refusal = why;
                return FetchRefused.FetchNotPermitted;
            },
        }

        var pins: std.ArrayList(provision.Variable) = .empty;
        for (reached.sites) |one| {
            const mirror = try self.chooseMirror(one);
            try pins.append(self.allocator, .{
                .name = try std.fmt.allocPrint(self.allocator, "NIX_MIRRORS_{s}", .{one.site}),
                .value = mirror.base,
            });
        }

        // A fixed output derivation that says nowhere it fetches from has no host a rule could cover. zig.fetchDeps, npm deps, and fetchCargoVendor all take this shape, so chock-policy/defaults.zig ships nix.net.build.opaque as allow: refusing them would refuse nearly every Rust, Node, and Zig package.
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

        if (reached.reads_mirrors) try pins.append(self.allocator, .{
            .name = "NIX_HASHED_MIRRORS",
            .value = try self.chooseHashedMirror(reached.hashed),
        });

        self.pins = try pins.toOwnedSlice(self.allocator);
    }

    const Picked = struct {
        base: []const u8,
        asking: fetch.Fetch,
    };

    fn chooseMirror(self: *Host, one: fetch.MirrorSite) anyerror!Picked {
        var nameable = false;
        var candidate: ?Picked = null;

        for (one.mirrors) |mirror| {
            const target = mirror.target orelse continue;
            nameable = true;
            const asking = fetchOfMirror(one, mirror, target);
            switch (self.gate.ruleFor(asking)) {
                .allow => return .{ .base = mirror.base, .asking = asking },
                .deny => continue,
                .unsettled => if (candidate == null) {
                    candidate = .{ .base = mirror.base, .asking = asking };
                },
            }
        }

        if (candidate) |picked| {
            switch (try self.gate.permitSite(self.allocator, one, picked.asking)) {
                .permitted => return picked,
                .refused => |why| {
                    self.refusal = try fetch.mirrorRefusal(
                        self.allocator,
                        one,
                        picked.asking.host,
                        why,
                    );
                    return FetchRefused.FetchNotPermitted;
                },
            }
        }

        self.refusal = try fetch.unreadableRefusal(self.allocator, .{
            .subject = one.subject,
            .url = one.url,
            .site = one.site,
            .why = if (nameable) .mirror_every_host_denied else .mirror_not_nameable,
        });
        return FetchRefused.FetchNotPermitted;
    }

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
        try self.askAboutFetches(paths[0]);

        const built = try self.runner.runPinned(self.allocator, self.io, &.{
            "build",
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
    derivation_path: []const u8,
    installable: []const u8,
};

pub const Built = struct {
    provided: provision.Provided,
    out_paths: []const []const u8,
};

pub const Answer = union(enum) {
    built: Built,
    refused: []const u8,
};

pub fn realise(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    driver: *backend.Driver,
    gate: fetch.Gate,
    request: Request,
) Error!Answer {
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
        // Both spellings reach here: proc.zig maps the standard library's own to OutputTooLong, and a path that has not mapped it yet arrives as StreamTooLong. Either way the evaluation finished and only the reading of its output stopped, so this is Chock's own bound and not a fault in the expression.
        error.OutputTooLong, error.StreamTooLong => try std.fmt.allocPrint(
            allocator,
            "{s} was not built: it evaluated, and its output was larger than this session " ++
                "reads, so nothing was built and the result was not kept. The expression is " ++
                "not at fault. Build one attribute rather than a set of them, or ask the user " ++
                "to raise the output bound.",
            .{installable},
        ),
        else => null,
    };
}

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

const AnsweringGate = struct {
    gpa: std.mem.Allocator,
    permitted: bool = true,
    asked: std.ArrayList([]const u8) = .empty,
    by_rule: []const []const u8 = &.{},
    denied: []const []const u8 = &.{},
    prompted: usize = 0,
    site_asks: usize = 0,
    site_action: [128]u8 = undefined,
    site_action_len: usize = 0,
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
        .rule_for = ruleForFn,
        .permit_site = permitSiteFn,
    };

    fn permitSiteFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        site: fetch.MirrorSite,
        chosen: fetch.Fetch,
    ) std.mem.Allocator.Error!fetch.Verdict {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        self.site_asks += 1;
        self.prompted += 1;
        try self.asked.append(self.gpa, try self.gpa.dupe(u8, chosen.host));

        const name = std.fmt.bufPrint(&self.site_action, "nix.net.build.mirrors.{s}.{s}", .{
            site.site,
            &site.hash(),
        }) catch return .{ .refused = "the mirror set could not be named" };
        self.site_action_len = name.len;

        if (self.permitted) return .permitted;
        return .{ .refused = try std.fmt.allocPrint(
            allocator,
            "this project answers no for {s}",
            .{name},
        ) };
    }

    fn siteAction(self: *const AnsweringGate) []const u8 {
        return self.site_action[0..self.site_action_len];
    }

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
            if (ruleForFn(ptr, one) == .allow) continue;
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

    fn ruleForFn(ptr: *anyopaque, one: fetch.Fetch) fetch.RuleAnswer {
        const self: *AnsweringGate = @ptrCast(@alignCast(ptr));
        for (self.by_rule) |host| {
            if (std.mem.eql(u8, host, one.host)) return .allow;
        }
        for (self.denied) |host| {
            if (std.mem.eql(u8, host, one.host)) return .deny;
        }
        return .unsettled;
    }
};

const closure_that_fetches =
    \\{"derivations":{"b-src.drv":{"env":{"url":"https://files.example.com/src.tar.gz"},
    \\ "outputs":{"out":{"hash":"sha256-A","method":"flat"}}}}}
;
const closure_that_fetches_nothing =
    \\{"derivations":{"a-top.drv":{"env":{"name":"top"},
    \\ "outputs":{"out":{"path":"/nix/store/x-top"}}}}}
;

const testing = std.testing;

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

const RecordingWriter = struct {
    gpa: std.mem.Allocator,
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
    driver.max_object_bytes = 8;

    try testing.expectError(backend.Error.ObjectTooLarge, evaluateDerivation(gpa, &driver));
    try testing.expectEqual(@as(usize, 0), recording.objects);
    try testing.expectEqual(@as(u64, 0), budget.written_bytes);

    driver.max_object_bytes = backend.default_max_object_bytes;
    try evaluateDerivation(gpa, &driver);
    const first = budget.written_bytes;
    try testing.expect(first != 0);

    budget.max_bytes = first * 2 - 1;
    var second = backend.Driver.init(gpa, writing.seam());
    defer second.deinit();
    try testing.expectError(WriteError.SessionStoreFull, evaluateDerivation(gpa, &second));
    try testing.expect(budget.written_bytes <= budget.max_bytes);

    const said = (try writeRefusal(gpa, "/work#a", WriteError.SessionStoreFull)).?;
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "max_session_bytes") != null);
}

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

fn writeMirrorsList(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "mirrors-list",
        .data = fetch.nixpkgs_mirrors_sample,
    });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/mirrors-list", .{buffer[0..len]});
}

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
    try testing.expectEqual(@as(usize, 2), fake.seen_pins.items.len);
    try testing.expectEqualStrings(
        "https://ftpmirror.gnu.org/",
        fake.pin("NIX_MIRRORS_gnu").?,
    );
}

test "the hashed mirrors are turned off unless a rule allows their own host" {
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

test "an output larger than this session reads is named as that, not as a failed evaluation" {
    const gpa = std.testing.allocator;

    for ([_]anyerror{ error.OutputTooLong, error.StreamTooLong }) |err| {
        const said = (try writeRefusal(gpa, "flake#formatter.aarch64-linux", err)).?;
        defer gpa.free(said);

        try std.testing.expect(std.mem.indexOf(u8, said, "it evaluated") != null);
        try std.testing.expect(std.mem.indexOf(u8, said, "not at fault") != null);
        try std.testing.expect(std.mem.indexOf(u8, said, "one attribute") != null);
    }

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try writeRefusal(gpa, "flake#thing", error.SomethingElseEntirely),
    );
}
