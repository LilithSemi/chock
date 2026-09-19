//! A Nix store for an evaluation that may not have one.
//!
//! fix asks a store backend seven questions, and a real backend answers them
//! against the host's `/nix/store` and its daemon. This driver answers none of
//! them itself. Every question goes to a seam the caller supplies, so the
//! caller, and not the expression under evaluation, decides what a Nix
//! evaluation may do. It is the shape `chock_core.tools.NetSeam` already has
//! for the network.
//!
//! ## A build is refused, and import from derivation with it
//!
//! `build_paths` is the one operation that runs somebody else's code. An
//! expression can reach it without a caller ever asking for a build: import
//! from derivation is an evaluation that stops, builds a derivation, and reads
//! the result back as Nix source. fix routes that through this same operation.
//! Chock authorises no build here, so both refuse, and the refusal names the
//! path. Nix says very little when a build does not happen, and a model that
//! reads "refused" with no subject retries the same expression.
//!
//! ## Why the produced set exists
//!
//! A build request names a store path. A hand written derivation can name any
//! builder and any input, so a build of a path this evaluation did not itself
//! produce is host code execution with a content hash in front of it. The
//! driver therefore records what `add_object` put in the store and refuses a
//! build of anything else, before the seam is asked at all. The seam then
//! answers the narrower question of whether this particular request is
//! allowed.

const std = @import("std");
const expr = @import("expr");
const store = @import("store");

pub const AddObject = store.backend.AddObject;
pub const BuildMode = store.backend.BuildMode;
pub const BuildSink = store.backend.BuildSink;
pub const MissingPlan = store.backend.MissingPlan;

pub const Error = error{
    /// The seam has no answer for this operation, so the driver refuses it
    /// rather than inventing one.
    OperationRefused,
    /// A build named a path this driver did not produce, or the seam
    /// authorises no build at all.
    BuildRefused,
    /// The object is longer than `Driver.max_object_bytes`.
    ObjectTooLarge,
};

/// The most bytes one store object may carry.
///
/// A Nix source file or a derivation text is a few kilobytes. Sixteen
/// mebibytes is far above anything an evaluation writes and far below the
/// memory a single object could otherwise take, because the whole object is
/// held as bytes while it is added.
pub const default_max_object_bytes: usize = 16 << 20;

/// Where a store operation really happens.
///
/// Every function pointer is optional and every absent one refuses. A caller
/// that sets nothing gets an evaluation that can compute a derivation path and
/// do nothing else, which is what `eval.Session` already does with no driver
/// at all.
pub const Seam = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        is_valid_path: ?*const fn (context: *anyopaque, path: []const u8) anyerror!bool = null,
        /// Returns the path the store computed, owned by `allocator`. The
        /// driver records it and a later build may name it.
        add_object: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, object: AddObject) anyerror![]u8 = null,
        read_file: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8 = null,
        /// Asked only after the driver has checked that this evaluation
        /// produced every path in the request. Import from derivation arrives
        /// here too, so a seam that sets this runs code the model chose.
        build_paths: ?*const fn (context: *anyopaque, paths: []const []const u8, sink: ?BuildSink, mode: BuildMode) anyerror!void = null,
        query_missing: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, paths: []const []const u8) anyerror!MissingPlan = null,
        add_indirect_root: ?*const fn (context: *anyopaque, link_path: []const u8, target: []const u8) anyerror!void = null,
    };

    /// The seam of a session that authorises nothing.
    pub const refusing: Seam = .{ .context = @constCast(&no_context), .vtable = &.{} };
};

const no_context: u8 = 0;

/// A `store.backend.Driver` over a `Seam`.
///
/// Build it, hand `backend()` to `expr.Engine.setStoreBackend`, and keep it
/// alive for as long as the engine is. It owns the set of paths it produced
/// and the text of its last refusal, so it holds an allocator.
///
/// **One engine, and one worker in it.** `run` and `submit` execute on the
/// thread that asked, and nothing here is locked, so the engine this is given
/// to is the engine `eval.Options.workers` builds with a count of one.
pub const Driver = struct {
    allocator: std.mem.Allocator,
    seam: Seam = Seam.refusing,
    /// A bound and not a rule. Whether an object may be added is the seam's
    /// answer. This is only how much of it there may be.
    max_object_bytes: usize = default_max_object_bytes,

    paths: std.StringHashMapUnmanaged(void) = .empty,
    message: ?[]u8 = null,

    pub fn init(allocator: std.mem.Allocator, seam: Seam) Driver {
        return .{ .allocator = allocator, .seam = seam };
    }

    pub fn deinit(self: *Driver) void {
        var keys = self.paths.keyIterator();
        while (keys.next()) |key| self.allocator.free(key.*);
        self.paths.deinit(self.allocator);
        if (self.message) |text| self.allocator.free(text);
        self.* = undefined;
    }

    /// What an engine is given. Borrows this driver, so it may not outlive it.
    pub fn backend(self: *Driver) store.backend.Driver {
        return .{ .ptr = self, .vtable = &driver_vtable };
    }

    /// True when `add_object` on this driver produced `path`. A build may name
    /// nothing else.
    pub fn produced(self: *Driver, path: []const u8) bool {
        return self.paths.contains(path);
    }

    /// Why the last operation refused, in words that name the path. Borrowed
    /// until the next operation on this driver.
    pub fn lastError(self: *Driver) ?[]const u8 {
        return self.message;
    }

    /// Build `paths`, if this driver produced every one of them.
    ///
    /// **The same function the engine's own build goes through**, so a
    /// caller outside the engine reaches no build the engine would be
    /// refused. A second check written beside this one could answer
    /// differently, and then the weaker of the two would be the real rule.
    ///
    /// The seam decides where the build happens, and a seam with no
    /// `build_paths` refuses. See `lib/chock-nix/build.zig`, which installs
    /// one only after a person or the policy has answered, so an evaluation
    /// can never reach it.
    pub fn build(self: *Driver, paths: []const []const u8, mode: BuildMode) anyerror!void {
        return buildPaths(self, paths, null, mode);
    }

    const driver_vtable: store.backend.Driver.VTable = .{
        .start = start,
        .run = run,
        .submit = submit,
        .connection = connection,
    };

    const connection_vtable: store.backend.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
        .read_file = readFile,
        .build_paths = buildPaths,
        .query_missing = queryMissing,
        .add_indirect_root = addIndirectRoot,
        .last_error = lastErrorOf,
    };

    fn from(raw: *anyopaque) *Driver {
        return @ptrCast(@alignCast(raw));
    }

    /// The driver, with the last refusal dropped. `last_error` is borrowed
    /// until the next operation, so an operation that starts ends the loan
    /// rather than leaving an older refusal for a later failure to wear.
    fn begin(raw: *anyopaque) *Driver {
        const self = from(raw);
        if (self.message) |old| {
            self.allocator.free(old);
            self.message = null;
        }
        return self;
    }

    fn start(_: *anyopaque) !void {}

    /// On the calling thread. A tool call runs inside a sandbox whose io
    /// cannot start a thread, so this driver starts none either.
    fn run(raw: *anyopaque, work: store.backend.WorkFn, context: *anyopaque) !void {
        work(raw, context);
    }

    fn submit(raw: *anyopaque, job: *store.backend.Job) !void {
        job.run(raw, job.ctx);
    }

    fn connection(_: *anyopaque, raw_connection: *anyopaque) store.backend.Connection {
        return .{ .context = raw_connection, .vtable = &connection_vtable };
    }

    fn isValidPath(raw: *anyopaque, path: []const u8) !bool {
        const self = begin(raw);
        const ask = self.seam.vtable.is_valid_path orelse {
            self.refuse("no store answers whether {s} exists", .{path});
            return Error.OperationRefused;
        };
        return ask(self.seam.context, path);
    }

    fn addObject(raw: *anyopaque, allocator: std.mem.Allocator, object: AddObject) ![]u8 {
        const self = begin(raw);
        const bytes = switch (object) {
            inline else => |one| one.bytes,
        };
        if (bytes.len > self.max_object_bytes) {
            self.refuse(
                "{s} is {d} bytes, over the {d} byte limit on one store object",
                .{ object.expectedPath(), bytes.len, self.max_object_bytes },
            );
            return Error.ObjectTooLarge;
        }
        const add = self.seam.vtable.add_object orelse {
            self.refuse("no store accepts {s}", .{object.expectedPath()});
            return Error.OperationRefused;
        };

        const written = try add(self.seam.context, allocator, object);
        errdefer allocator.free(written);
        try self.record(written);
        return written;
    }

    fn readFile(raw: *anyopaque, allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        const self = begin(raw);
        const read = self.seam.vtable.read_file orelse {
            self.refuse("no store holds {s} to read", .{path});
            return Error.OperationRefused;
        };
        return read(self.seam.context, allocator, path);
    }

    fn buildPaths(raw: *anyopaque, paths: []const []const u8, sink: ?BuildSink, mode: BuildMode) !void {
        const self = begin(raw);
        if (paths.len == 0) {
            self.refuse("a build that names no path is refused", .{});
            return Error.BuildRefused;
        }
        for (paths) |path| {
            if (!self.produced(path)) {
                self.refuse(
                    "a build of {s} is refused: this evaluation did not produce that path",
                    .{path},
                );
                return Error.BuildRefused;
            }
        }
        const run_build = self.seam.vtable.build_paths orelse {
            self.refuse(
                "a build of {s} is refused: this session authorises no build",
                .{paths[0]},
            );
            return Error.BuildRefused;
        };
        return run_build(self.seam.context, paths, sink, mode);
    }

    fn queryMissing(raw: *anyopaque, allocator: std.mem.Allocator, paths: []const []const u8) !MissingPlan {
        const self = begin(raw);
        const query = self.seam.vtable.query_missing orelse {
            self.refuse("no store says what {d} path or paths are missing", .{paths.len});
            return Error.OperationRefused;
        };
        return query(self.seam.context, allocator, paths);
    }

    fn addIndirectRoot(raw: *anyopaque, link_path: []const u8, target: []const u8) !void {
        const self = begin(raw);
        const add = self.seam.vtable.add_indirect_root orelse {
            self.refuse("no store keeps a root at {s}", .{link_path});
            return Error.OperationRefused;
        };
        return add(self.seam.context, link_path, target);
    }

    fn lastErrorOf(raw: *anyopaque) ?[]const u8 {
        return from(raw).message;
    }

    fn record(self: *Driver, path: []const u8) !void {
        if (self.paths.contains(path)) return;
        const owned = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(owned);
        try self.paths.put(self.allocator, owned, {});
    }

    /// The refusal a caller reads back. A driver that cannot allocate the text
    /// still refuses: the error is the answer, and the words are the detail.
    fn refuse(self: *Driver, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(self.allocator, format, args) catch return;
        if (self.message) |old| self.allocator.free(old);
        self.message = text;
    }
};

const testing = std.testing;

/// A store that keeps its objects in memory, for a test that asks what the
/// driver does and not what a store does.
const FakeStore = struct {
    allocator: std.mem.Allocator,
    objects: std.StringHashMapUnmanaged([]u8) = .empty,
    builds: usize = 0,

    fn deinit(self: *FakeStore) void {
        var entries = self.objects.iterator();
        while (entries.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.objects.deinit(self.allocator);
        self.* = undefined;
    }

    fn seam(self: *FakeStore) Seam {
        return .{ .context = self, .vtable = &vtable };
    }

    /// The same store, with no build in it.
    fn noBuildSeam(self: *FakeStore) Seam {
        return .{ .context = self, .vtable = &no_build_vtable };
    }

    const no_build_vtable: Seam.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
    };

    const vtable: Seam.VTable = .{
        .is_valid_path = isValidPath,
        .add_object = addObject,
        .build_paths = buildPaths,
    };

    fn isValidPath(context: *anyopaque, path: []const u8) !bool {
        const self: *FakeStore = @ptrCast(@alignCast(context));
        return self.objects.contains(path);
    }

    fn addObject(context: *anyopaque, allocator: std.mem.Allocator, object: AddObject) ![]u8 {
        const self: *FakeStore = @ptrCast(@alignCast(context));
        const path = object.expectedPath();
        const bytes = switch (object) {
            inline else => |one| one.bytes,
        };
        if (!self.objects.contains(path)) {
            const owned_path = try self.allocator.dupe(u8, path);
            errdefer self.allocator.free(owned_path);
            const owned_bytes = try self.allocator.dupe(u8, bytes);
            errdefer self.allocator.free(owned_bytes);
            try self.objects.put(self.allocator, owned_path, owned_bytes);
        }
        return allocator.dupe(u8, path);
    }

    fn buildPaths(context: *anyopaque, _: []const []const u8, _: ?BuildSink, _: BuildMode) !void {
        const self: *FakeStore = @ptrCast(@alignCast(context));
        self.builds += 1;
    }
};

/// The connection of `driver`, which is what every operation is asked through.
fn connectionOf(driver: store.backend.Driver) !store.backend.Connection {
    const Capture = struct {
        driver: store.backend.Driver,
        connection: ?store.backend.Connection = null,

        fn run(raw: ?*anyopaque, context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connection = self.driver.connection(raw.?);
        }
    };
    var capture: Capture = .{ .driver = driver };
    try driver.run(Capture.run, &capture);
    return capture.connection.?;
}

const example_path = "/nix/store/00000000000000000000000000000000-example.drv";

test "an object the driver added may then be built" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var driver = Driver.init(testing.allocator, fake.seam());
    defer driver.deinit();

    const connection = try connectionOf(driver.backend());
    const written = try connection.addObject(testing.allocator, .{ .text = .{
        .expected_path = example_path,
        .name = "example.drv",
        .bytes = "Derive([],[],[],\"x86_64-linux\",\"/bin/sh\",[],[])",
        .references = &.{},
    } });
    defer testing.allocator.free(written);

    // Drop the `record` call in `addObject` and the build below is refused,
    // because the produced set is the only thing that authorises it.
    try testing.expect(driver.produced(example_path));
    try connection.buildPaths(&.{example_path}, null, .normal);
    try testing.expectEqual(@as(usize, 1), fake.builds);
}

test "a build of a path this evaluation did not produce is refused by name" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var driver = Driver.init(testing.allocator, fake.seam());
    defer driver.deinit();

    const connection = try connectionOf(driver.backend());
    const other = "/nix/store/11111111111111111111111111111111-other.drv";
    try testing.expectError(Error.BuildRefused, connection.buildPaths(&.{other}, null, .normal));
    try testing.expectEqual(@as(usize, 0), fake.builds);

    // The seam has a build function here, so only the produced set refuses.
    // The path has to be in the words, because a model that reads a refusal
    // with no subject tries the same expression again.
    const said = connection.lastError().?;
    try testing.expect(std.mem.indexOf(u8, said, other) != null);
}

test "a build is refused when the session authorises none, and the refusal names the path" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var seam = fake.seam();
    seam.vtable = &.{ .is_valid_path = FakeStore.isValidPath, .add_object = FakeStore.addObject };
    var driver = Driver.init(testing.allocator, seam);
    defer driver.deinit();

    // Import from derivation reaches this operation, so this is the case that
    // stops an evaluation from building its own input.
    const connection = try connectionOf(driver.backend());
    const written = try connection.addObject(testing.allocator, .{ .text = .{
        .expected_path = example_path,
        .name = "example.drv",
        .bytes = "Derive([],[],[],\"x86_64-linux\",\"/bin/sh\",[],[])",
        .references = &.{},
    } });
    defer testing.allocator.free(written);

    try testing.expectError(Error.BuildRefused, connection.buildPaths(&.{example_path}, null, .normal));
    try testing.expect(std.mem.indexOf(u8, connection.lastError().?, example_path) != null);
}

test "an object over the cap is refused before the store sees it" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var driver = Driver.init(testing.allocator, fake.seam());
    defer driver.deinit();
    driver.max_object_bytes = 8;

    const connection = try connectionOf(driver.backend());
    try testing.expectError(Error.ObjectTooLarge, connection.addObject(testing.allocator, .{ .text = .{
        .expected_path = example_path,
        .name = "example.drv",
        .bytes = "123456789",
        .references = &.{},
    } }));

    // Refused before the seam, so nothing reached the store and nothing was
    // recorded. Move the cap check after the `add` call and both fail.
    try testing.expectEqual(@as(usize, 0), fake.objects.count());
    try testing.expect(!driver.produced(example_path));

    const smaller = try connection.addObject(testing.allocator, .{ .text = .{
        .expected_path = example_path,
        .name = "example.drv",
        .bytes = "12345678",
        .references = &.{},
    } });
    defer testing.allocator.free(smaller);
    try testing.expect(driver.produced(example_path));
}

test "an empty seam refuses every operation rather than answering a wrong one" {
    var driver = Driver.init(testing.allocator, Seam.refusing);
    defer driver.deinit();

    const connection = try connectionOf(driver.backend());
    // `is_valid_path` is the one that shows why an absent function may not
    // answer: false is a plausible answer and it is not this driver's to give.
    try testing.expectError(Error.OperationRefused, connection.isValidPath(example_path));
    try testing.expectError(Error.OperationRefused, connection.addObject(testing.allocator, .{ .text = .{
        .expected_path = example_path,
        .name = "example.drv",
        .bytes = "x",
        .references = &.{},
    } }));
    try testing.expectError(Error.OperationRefused, connection.readFile(testing.allocator, example_path));
    try testing.expectError(Error.BuildRefused, connection.buildPaths(&.{example_path}, null, .normal));
    try testing.expectError(Error.OperationRefused, connection.queryMissing(testing.allocator, &.{example_path}));
    try testing.expectError(Error.OperationRefused, connection.addIndirectRoot("/tmp/result", example_path));
    try testing.expect(driver.lastError() != null);
}

test "a real engine with this driver installed writes its derivation through the seam" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var driver = Driver.init(testing.allocator, fake.seam());
    defer driver.deinit();

    var engine = try expr.Engine.init(testing.allocator, .{ .worker_count = 1 });
    defer engine.deinit();
    try engine.setPureEval(true, &.{});
    try engine.setStoreBackend(driver.backend());
    engine.enableStoreWrites();

    const value = try engine.evaluate(
        \\derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; }
    );
    const path = (try engine.derivationDrvPath(value)).?;
    try engine.ensureDerivationClosure(path);

    // The derivation text went to the seam and not to the host store, and it
    // went through this driver, so the produced set now authorises a build of
    // it. Nothing here needs a daemon, a store mount or a network.
    try testing.expect(fake.objects.contains(path));
    try testing.expect(driver.produced(path));
}

test "import from derivation through a real engine is refused by name" {
    var fake: FakeStore = .{ .allocator = testing.allocator };
    defer fake.deinit();
    var driver = Driver.init(testing.allocator, fake.noBuildSeam());
    defer driver.deinit();

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var engine = try expr.Engine.init(testing.allocator, .{ .worker_count = 1 });
    defer engine.deinit();
    engine.setFileIo(threaded.io());
    try engine.setPureEval(true, &.{});
    try engine.setStoreBackend(driver.backend());
    engine.enableStoreWrites();

    const source =
        \\import (derivation { name = "x"; builder = "/bin/sh"; system = "x86_64-linux"; })
    ;
    try testing.expectError(Error.BuildRefused, engine.evaluate(source));

    // The refusal names the derivation the evaluation asked to build, which
    // is the only signal a reader gets: fix reports the store error text and
    // nothing else about why the import stopped.
    const said = driver.lastError().?;
    try testing.expect(std.mem.indexOf(u8, said, ".drv") != null);
    try testing.expect(std.mem.startsWith(u8, said, "a build of "));
}
