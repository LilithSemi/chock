//! A Nix store for an evaluation that may not have one. Every question fix

const std = @import("std");
const expr = @import("expr");
const store = @import("store");

pub const AddObject = store.backend.AddObject;
pub const BuildMode = store.backend.BuildMode;
pub const BuildSink = store.backend.BuildSink;
pub const MissingPlan = store.backend.MissingPlan;

pub const Error = error{
    OperationRefused,
    BuildRefused,
    ObjectTooLarge,
};

pub const default_max_object_bytes: usize = 16 << 20;

pub const Seam = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        is_valid_path: ?*const fn (context: *anyopaque, path: []const u8) anyerror!bool = null,
        add_object: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, object: AddObject) anyerror![]u8 = null,
        read_file: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, path: []const u8) anyerror![]u8 = null,
        build_paths: ?*const fn (context: *anyopaque, paths: []const []const u8, sink: ?BuildSink, mode: BuildMode) anyerror!void = null,
        query_missing: ?*const fn (context: *anyopaque, allocator: std.mem.Allocator, paths: []const []const u8) anyerror!MissingPlan = null,
        add_indirect_root: ?*const fn (context: *anyopaque, link_path: []const u8, target: []const u8) anyerror!void = null,
    };

    pub const refusing: Seam = .{ .context = @constCast(&no_context), .vtable = &.{} };
};

const no_context: u8 = 0;

pub const Driver = struct {
    allocator: std.mem.Allocator,
    seam: Seam = Seam.refusing,
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

    pub fn backend(self: *Driver) store.backend.Driver {
        return .{ .ptr = self, .vtable = &driver_vtable };
    }

    pub fn produced(self: *Driver, path: []const u8) bool {
        return self.paths.contains(path);
    }

    pub fn lastError(self: *Driver) ?[]const u8 {
        return self.message;
    }

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

    fn begin(raw: *anyopaque) *Driver {
        const self = from(raw);
        if (self.message) |old| {
            self.allocator.free(old);
            self.message = null;
        }
        return self;
    }

    fn start(_: *anyopaque) !void {}

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

    fn refuse(self: *Driver, comptime format: []const u8, args: anytype) void {
        const text = std.fmt.allocPrint(self.allocator, format, args) catch return;
        if (self.message) |old| self.allocator.free(old);
        self.message = text;
    }
};

const testing = std.testing;

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

    const said = driver.lastError().?;
    try testing.expect(std.mem.indexOf(u8, said, ".drv") != null);
    try testing.expect(std.mem.startsWith(u8, said, "a build of "));
}
