//! The store paths a dev shell needs, and the garbage collector root that
//! keeps them alive.

const std = @import("std");

const diagnostic = @import("diagnostic.zig");
pub const Diagnostic = diagnostic.Diagnostic;
const proc = @import("proc.zig");

pub const Error = proc.Error || error{
    QueryFailed,
};

pub const default_prefix = "/nix/store";

fn isNameCharacter(character: u8) bool {
    if (std.ascii.isAlphanumeric(character)) return true;
    return switch (character) {
        '+', '-', '.', '_', '?', '=' => true,
        else => false,
    };
}

const hash_alphabet = "0123456789abcdfghijklmnpqrsvwxyz";
const hash_length = 32;

fn isStorePathName(name: []const u8) bool {
    if (name.len < hash_length + 2) return false;
    for (name[0..hash_length]) |character| {
        if (std.mem.indexOfScalar(u8, hash_alphabet, character) == null) return false;
    }
    return name[hash_length] == '-';
}

fn nameIn(io: std.Io, prefix: []const u8, run: []const u8) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, run, '=') == null) {
        return if (isStorePathName(run)) run else null;
    }

    var candidate = run;
    while (true) {
        if (isStorePathName(candidate) and holdsName(io, prefix, candidate)) return candidate;
        const equals = std.mem.lastIndexOfScalar(u8, candidate, '=') orelse return null;
        candidate = candidate[0..equals];
    }
}

fn holdsName(io: std.Io, prefix: []const u8, name: []const u8) bool {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(&buffer, "{s}/{s}", .{ prefix, name }) catch return false;
    _ = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

pub fn prefixIn(records: []const []const u8) []const u8 {
    for (records) |record| {
        const equals = std.mem.indexOfScalar(u8, record, '=') orelse continue;
        if (!std.mem.eql(u8, record[0..equals], "NIX_STORE")) continue;
        const value = record[equals + 1 ..];
        if (value.len == 0) continue;
        return value;
    }
    return default_prefix;
}

pub fn pathsIn(allocator: std.mem.Allocator, io: std.Io, records: []const []const u8) Error![][]u8 {
    const prefix = prefixIn(records);

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);

    var found: std.ArrayList([]u8) = .empty;
    errdefer {
        for (found.items) |item| allocator.free(item);
        found.deinit(allocator);
    }

    for (records) |record| {
        var rest = record;
        while (std.mem.indexOf(u8, rest, prefix)) |at| {
            const after = rest[at + prefix.len ..];
            rest = after;
            if (after.len == 0 or after[0] != '/') continue;

            var end: usize = 1;
            while (end < after.len and isNameCharacter(after[end])) end += 1;
            const name = nameIn(io, prefix, after[1..end]) orelse continue;

            const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, name });
            const entry = try seen.getOrPut(allocator, path);
            if (entry.found_existing) {
                allocator.free(path);
            } else {
                entry.key_ptr.* = path;
                try found.append(allocator, path);
            }
            rest = after[1 + name.len ..];
        }
    }

    const result = try found.toOwnedSlice(allocator);
    std.mem.sort([]u8, result, {}, lessThanPath);
    return result;
}

fn lessThanPath(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

const max_closure_bytes: usize = 10 * 1024 * 1024;

const max_refusals: usize = 32;

pub fn closureOf(
    allocator: std.mem.Allocator,
    io: std.Io,
    nix_program: []const u8,
    host_env: *const std.process.Environ.Map,
    roots: []const []const u8,
    diag: ?diagnostic.Sink,
) Error![][]u8 {
    if (roots.len == 0) return allocator.alloc([]u8, 0);

    var answered: std.ArrayList(u8) = .empty;
    defer answered.deinit(allocator);

    var refused: Refused = .{ .allocator = allocator };
    defer refused.deinit();

    try askClosure(allocator, io, nix_program, host_env, roots, &answered, &refused);

    if (refused.roots == roots.len) {
        try diagnostic.noteRefusal(diag, .nix_path_info, refused.said orelse "");
        return error.QueryFailed;
    }
    if (refused.roots != 0) {
        try diagnostic.noteDropped(diag, refused.roots, refused.said orelse "");
    }
    return parsePathList(allocator, answered.items);
}

const Refused = struct {
    allocator: std.mem.Allocator,
    roots: usize = 0,
    calls: usize = 0,
    said: ?[]u8 = null,

    fn keep(self: *Refused, stderr: []const u8) std.mem.Allocator.Error!void {
        self.calls += 1;
        if (self.said != null) return;
        const tail = if (stderr.len > diagnostic.max_shown_bytes)
            stderr[stderr.len - diagnostic.max_shown_bytes ..]
        else
            stderr;
        self.said = try self.allocator.dupe(u8, tail);
    }

    fn deinit(self: *Refused) void {
        if (self.said) |said| self.allocator.free(said);
        self.* = undefined;
    }
};

fn askClosure(
    allocator: std.mem.Allocator,
    io: std.Io,
    nix_program: []const u8,
    host_env: *const std.process.Environ.Map,
    roots: []const []const u8,
    answered: *std.ArrayList(u8),
    refused: *Refused,
) Error!void {
    if (refused.calls >= max_refusals) {
        refused.roots += roots.len;
        return;
    }

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{ nix_program, "path-info", "-r", "--" });
    try argv.appendSlice(allocator, roots);

    var output = try proc.run(allocator, io, .{
        .argv = argv.items,
        .env = host_env,
        .max_output_bytes = max_closure_bytes,
    });
    defer output.deinit(allocator);

    if (output.succeeded()) {
        try answered.appendSlice(allocator, output.stdout);
        return;
    }

    try refused.keep(output.stderr);
    if (roots.len == 1) {
        refused.roots += 1;
        return;
    }

    const middle = roots.len / 2;
    try askClosure(allocator, io, nix_program, host_env, roots[0..middle], answered, refused);
    try askClosure(allocator, io, nix_program, host_env, roots[middle..], answered, refused);
}

pub fn parsePathList(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![][]u8 {
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);

    var paths: std.ArrayList([]u8) = .empty;
    errdefer {
        for (paths.items) |item| allocator.free(item);
        paths.deinit(allocator);
    }

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (seen.contains(line)) continue;

        const copy = try allocator.dupe(u8, line);
        const entry = try seen.getOrPut(allocator, copy);
        if (entry.found_existing) {
            allocator.free(copy);
            continue;
        }
        entry.key_ptr.* = copy;
        try paths.append(allocator, copy);
    }

    const result = try paths.toOwnedSlice(allocator);
    std.mem.sort([]u8, result, {}, lessThanPath);
    return result;
}

pub fn addRoots(
    allocator: std.mem.Allocator,
    io: std.Io,
    nix_store_program: []const u8,
    host_env: *const std.process.Environ.Map,
    link_prefix: []const u8,
    paths: []const []const u8,
    diag: ?*?Diagnostic,
) Error!void {
    if (paths.len == 0) return;

    const sink = diagnostic.sinkOf(allocator, diag);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        nix_store_program,
        "--realise",
        "--add-root",
        link_prefix,
        "--indirect",
        "--",
    });
    try argv.appendSlice(allocator, paths);

    var output = try proc.run(allocator, io, .{ .argv = argv.items, .env = host_env, .diag = sink });
    defer output.deinit(allocator);

    if (!output.succeeded()) {
        try diagnostic.noteRefusal(sink, .nix_store_add_root, output.stderr);
        return error.QueryFailed;
    }
}

test "a store path in a PATH entry is found, and cut at its own package" {
    const allocator = std.testing.allocator;
    const records = [_][]const u8{
        "PATH=/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0/bin:" ++
            "/nix/store/q3pvpkn0qmin7x572p3z32hxz9yny73i-git-2.55.0/bin",
    };

    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings("/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0", paths[0]);
    try std.testing.expectEqualStrings("/nix/store/q3pvpkn0qmin7x572p3z32hxz9yny73i-git-2.55.0", paths[1]);
}

test "the same package named twice is one mount" {
    const allocator = std.testing.allocator;
    const records = [_][]const u8{
        "PATH=/nix/store/dqxknsb71lsgzfzcdmn6x7fzssqbdyyx-coreutils-9.11/bin",
        "CC=/nix/store/dqxknsb71lsgzfzcdmn6x7fzssqbdyyx-coreutils-9.11/bin/cc",
    };

    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 1), paths.len);
}

test "a value that only mentions the store is not a store path" {
    const allocator = std.testing.allocator;
    const records = [_][]const u8{
        "NIX_STORE=/nix/store",
        "A=/nix/store/",
        "B=/nix/store/short-name",
        "C=/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-not-base32",
    };

    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 0), paths.len);
}

test "a store path inside a compiler flag ends where the flag does" {
    const allocator = std.testing.allocator;
    const records = [_][]const u8{
        "NIX_LDFLAGS=-rpath /nix/store/9k3l8v5p5zh9ai9hjjm45izbkhvlwfdd-glibc-2.42-67/lib " ++
            "-L/nix/store/wqqb6mbnrnm380adc0ry5hdm449xix4f-gcc-15.3.0/lib",
    };

    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings("/nix/store/9k3l8v5p5zh9ai9hjjm45izbkhvlwfdd-glibc-2.42-67", paths[0]);
    try std.testing.expectEqualStrings("/nix/store/wqqb6mbnrnm380adc0ry5hdm449xix4f-gcc-15.3.0", paths[1]);
}

const TestStore = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init(allocator: std.mem.Allocator, names: []const []const u8) !TestStore {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        for (names) |name| try tmp.dir.createDir(std.testing.io, name, .default_dir);

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(std.testing.io, &buffer);
        return .{ .allocator = allocator, .tmp = tmp, .path = try allocator.dupe(u8, buffer[0..len]) };
    }

    fn deinit(self: *TestStore) void {
        self.allocator.free(self.path);
        self.tmp.cleanup();
        self.* = undefined;
    }
};

test "a store path a compiler flag maps to another one ends at the flag's own separator" {
    const allocator = std.testing.allocator;

    // nixpkgs writes this flag for every dependency with an include directory whenever the compiler is not GCC, which covers every Mac and every clang project on Linux. Read with = as a name character, the path ends -libiconv-115.100.1-dev=, nix path-info refuses the whole closure, and the session silently takes the host toolchain.
    const name = "7783lm2vxch7v4v5pmlifkp91qdqdq6d-libiconv-115.100.1-dev";
    var store_dir = try TestStore.init(allocator, &.{name});
    defer store_dir.deinit();

    const flag = try std.fmt.allocPrint(
        allocator,
        "NIX_CFLAGS_COMPILE= -isystem {s}/{s}/include " ++
            "-fmacro-prefix-map={s}/{s}={s}/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-libiconv-115.100.1-dev",
        .{ store_dir.path, name, store_dir.path, name, store_dir.path },
    );
    defer allocator.free(flag);

    const prefix_record = try std.fmt.allocPrint(allocator, "NIX_STORE={s}", .{store_dir.path});
    defer allocator.free(prefix_record);

    const records = [_][]const u8{ prefix_record, flag };
    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    const expected = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ store_dir.path, name });
    defer allocator.free(expected);

    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expectEqualStrings(expected, paths[0]);
}

test "a store name that really holds an equals sign keeps it" {
    const allocator = std.testing.allocator;

    // Nix's own rule for a store name allows =, and a name taken from a URL with a query can carry one, so the ambiguity above is not settled by cutting at the last =.
    const name = "9k3l8v5p5zh9ai9hjjm45izbkhvlwfdd-source.tar.gz?raw=true";
    var store_dir = try TestStore.init(allocator, &.{name});
    defer store_dir.deinit();

    const prefix_record = try std.fmt.allocPrint(allocator, "NIX_STORE={s}", .{store_dir.path});
    defer allocator.free(prefix_record);
    const record = try std.fmt.allocPrint(allocator, "SOURCE={s}/{s}", .{ store_dir.path, name });
    defer allocator.free(record);

    const records = [_][]const u8{ prefix_record, record };
    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    const expected = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ store_dir.path, name });
    defer allocator.free(expected);

    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expectEqualStrings(expected, paths[0]);
}

test "a run with an equals sign the store holds nothing for names nothing" {
    const allocator = std.testing.allocator;

    var store_dir = try TestStore.init(allocator, &.{});
    defer store_dir.deinit();

    const prefix_record = try std.fmt.allocPrint(allocator, "NIX_STORE={s}", .{store_dir.path});
    defer allocator.free(prefix_record);
    const record = try std.fmt.allocPrint(
        allocator,
        "GONE={s}/9k3l8v5p5zh9ai9hjjm45izbkhvlwfdd-gone-1.0=suffix",
        .{store_dir.path},
    );
    defer allocator.free(record);

    const records = [_][]const u8{ prefix_record, record };
    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 0), paths.len);
}

const TestNix = struct {
    allocator: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    program: []u8,
    calls_path: []u8,
    host_env: std.process.Environ.Map,

    fn init(allocator: std.mem.Allocator) !TestNix {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(std.testing.io, &buffer);
        const dir_path = buffer[0..len];

        const calls_path = try std.fmt.allocPrint(allocator, "{s}/calls", .{dir_path});
        errdefer allocator.free(calls_path);

        const text = try std.fmt.allocPrint(allocator,
            \\#!/bin/sh
            \\echo call >> {s}
            \\shift 3
            \\for p in "$@"; do
            \\  case "$p" in *bad*) echo "error: path '$p' is not valid" >&2; exit 1;; esac
            \\done
            \\for p in "$@"; do echo "$p"; echo "$p-dep"; done
            \\
        , .{calls_path});
        defer allocator.free(text);
        {
            var file = try tmp.dir.createFile(std.testing.io, "nix", .{ .permissions = .fromMode(0o755) });
            defer file.close(std.testing.io);
            try file.writeStreamingAll(std.testing.io, text);
        }

        const program = try std.fmt.allocPrint(allocator, "{s}/nix", .{dir_path});
        errdefer allocator.free(program);

        return .{
            .allocator = allocator,
            .tmp = tmp,
            .program = program,
            .calls_path = calls_path,
            .host_env = std.process.Environ.Map.init(allocator),
        };
    }

    fn deinit(self: *TestNix) void {
        self.allocator.free(self.program);
        self.allocator.free(self.calls_path);
        self.host_env.deinit();
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn callCount(self: *TestNix) !usize {
        const text = std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            self.calls_path,
            self.allocator,
            .limited(64 * 1024),
        ) catch |err| switch (err) {
            error.FileNotFound => return 0,
            else => return err,
        };
        defer self.allocator.free(text);
        return std.mem.count(u8, text, "call");
    }

    fn closure(self: *TestNix, roots: []const []const u8, diag: ?diagnostic.Sink) Error![][]u8 {
        return closureOf(self.allocator, std.testing.io, self.program, &self.host_env, roots, diag);
    }
};

fn freePaths(allocator: std.mem.Allocator, paths: [][]u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

test "a closure every root answers for costs one command" {
    const allocator = std.testing.allocator;
    var nix = TestNix.init(allocator) catch return error.SkipZigTest;
    defer nix.deinit();

    const roots = [_][]const u8{ "/nix/store/aaa", "/nix/store/bbb", "/nix/store/ccc" };
    const paths = try nix.closure(&roots, null);
    defer freePaths(allocator, paths);

    try std.testing.expectEqual(@as(usize, 6), paths.len);
    try std.testing.expectEqual(@as(usize, 1), try nix.callCount());
}

test "one root nix will not answer for costs one mount and not the closure" {
    const allocator = std.testing.allocator;
    var nix = TestNix.init(allocator) catch return error.SkipZigTest;
    defer nix.deinit();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(allocator);

    const roots = [_][]const u8{
        "/nix/store/aaa", "/nix/store/bbb", "/nix/store/ccc", "/nix/store/ddd",
        "/nix/store/bad", "/nix/store/fff", "/nix/store/ggg", "/nix/store/hhh",
    };
    const paths = try nix.closure(&roots, diagnostic.sinkOf(allocator, &diag));
    defer freePaths(allocator, paths);

    try std.testing.expectEqual(@as(usize, 14), paths.len);
    for (paths) |path| try std.testing.expect(std.mem.indexOf(u8, path, "bad") == null);

    try std.testing.expectEqual(@as(usize, 1), diag.?.store_paths_dropped.count);
    var line: [512]u8 = undefined;
    const text = try std.fmt.bufPrint(&line, "{f}", .{&diag.?});
    try std.testing.expect(std.mem.indexOf(u8, text, "/nix/store/bad") != null);
}

test "a nix that answers for no root at all is a refusal, not a mount set of nothing" {
    const allocator = std.testing.allocator;
    var nix = TestNix.init(allocator) catch return error.SkipZigTest;
    defer nix.deinit();

    var diag: ?Diagnostic = null;
    defer if (diag) |*d| d.deinit(allocator);

    const roots = [_][]const u8{ "/nix/store/bad-one", "/nix/store/bad-two" };
    try std.testing.expectError(
        error.QueryFailed,
        nix.closure(&roots, diagnostic.sinkOf(allocator, &diag)),
    );
    try std.testing.expectEqual(Diagnostic.What.nix_path_info, diag.?.command_refused.what);
}

test "a path list from nix is sorted, deduplicated, and free of blank lines" {
    const allocator = std.testing.allocator;
    const text =
        \\/nix/store/q3pvpkn0qmin7x572p3z32hxz9yny73i-git-2.55.0
        \\
        \\/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0
        \\/nix/store/q3pvpkn0qmin7x572p3z32hxz9yny73i-git-2.55.0
        \\
    ;

    const paths = try parsePathList(allocator, text);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 2), paths.len);
    try std.testing.expectEqualStrings("/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0", paths[0]);
    try std.testing.expectEqualStrings("/nix/store/q3pvpkn0qmin7x572p3z32hxz9yny73i-git-2.55.0", paths[1]);
}

test "a store somewhere other than /nix/store is read from the dev shell itself" {
    const allocator = std.testing.allocator;
    const records = [_][]const u8{
        "NIX_STORE=/data/nix/store",
        "PATH=/data/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0/bin",
    };

    const paths = try pathsIn(allocator, std.testing.io, &records);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }

    try std.testing.expectEqual(@as(usize, 1), paths.len);
    try std.testing.expectEqualStrings(
        "/data/nix/store/91iv42f62ba2k52ry9pr25ygyf2h44b3-zig-0.16.0",
        paths[0],
    );
}
