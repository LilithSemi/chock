//! Batched rollout orchestration and dataset provenance for `chock eval suite`.

const std = @import("std");
const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const max_suite_bytes: usize = 1024 * 1024;
const max_artifact_bytes: usize = 256 * 1024 * 1024;

const usage_text =
    \\Usage: chock eval suite <suite.zon> [--output <dir>] [--parallel <n>]
    \\
    \\Runs provider-backed evaluations in bounded parallel batches. Each rollout
    \\gets an independent capture, report, and lossless trajectory. The output
    \\index records split, group, source digests, Chock version, reward, and
    \\whether the provider supplied enough token data for policy training.
    \\
;

const Split = enum { train, validation, @"test" };

const Case = struct {
    name: []const u8,
    spec: []const u8,
    project: ?[]const u8 = null,
    split: Split = .train,
    rollouts: u32 = 1,
    group_size: u32 = 1,
};

const Suite = struct {
    schema: []const u8 = "chock.rl-suite",
    version: u32 = 1,
    name: []const u8,
    output: []const u8 = "rollouts",
    parallelism: u32 = 1,
    cases: []const Case,
};

const Options = struct {
    suite_path: []const u8,
    output: ?[]const u8 = null,
    parallelism: ?u32 = null,
};

const Job = struct {
    case_name: []const u8,
    spec_path: []const u8,
    spec_sha256: []const u8,
    project: ?[]const u8,
    split: Split,
    group: u32,
    rollout: u32,
    capture: []const u8,
    report: []const u8,
    trajectory: []const u8,
};

const Entry = struct {
    case: []const u8,
    spec: []const u8,
    spec_sha256: []const u8,
    split: Split,
    group: u32,
    rollout: u32,
    capture: []const u8,
    capture_sha256: []const u8 = "",
    report: []const u8,
    report_sha256: []const u8 = "",
    trajectory: []const u8,
    trajectory_sha256: []const u8 = "",
    exit_code: u8,
    session_id: []const u8 = "",
    base_commit: []const u8 = "",
    config_sha256: []const u8 = "",
    sandbox_sha256: []const u8 = "",
    sandbox_driver: []const u8 = "",
    reward: f64 = 0,
    trainable: bool = false,
    model_profile: []const u8 = "",
    checkpoint: []const u8 = "",
    trainer: []const u8 = "",
    seed: ?u64 = null,
    intervention: []const u8 = "",
    intervention_sha256: []const u8 = "",
};

const Dataset = struct {
    schema: []const u8 = "chock.rl-dataset",
    version: u32 = 1,
    suite: []const u8,
    suite_sha256: []const u8,
    chock_version: []const u8,
    entries: []const Entry,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    args: []const []const u8,
) !u8 {
    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        error.BadArguments => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };
    const source = std.Io.Dir.cwd().readFileAlloc(io, options.suite_path, arena, .limited(max_suite_bytes)) catch |err| {
        tty.print(.err, "chock eval suite: {s} could not be read: {t}\n", .{ options.suite_path, err });
        return Exit.usage.code();
    };
    const source_z = try arena.dupeSentinel(u8, source, 0);
    var diagnostics: std.zon.parse.Diagnostics = undefined;
    const suite = std.zon.parse.fromSlice(Suite, .{
        .gpa = gpa,
        .arena = arena,
        .source = source_z,
        .diagnostics = &diagnostics,
    }) catch |err| {
        tty.print(.err, "chock eval suite: {s} is not a valid suite: {t}\n", .{ options.suite_path, err });
        return Exit.usage.code();
    };
    if (!validSuite(suite)) {
        tty.print(.err, "chock eval suite: the suite or one of its cases is invalid\n", .{});
        return Exit.usage.code();
    }

    const output = options.output orelse pathFromSuite(arena, options.suite_path, suite.output);
    try std.Io.Dir.cwd().createDirPath(io, output);
    const output_path = try realPath(arena, io, output);
    const index_path = try std.fmt.allocPrint(arena, "{s}/dataset.json", .{output_path});
    if (std.Io.Dir.cwd().statFile(io, index_path, .{})) |_| {
        tty.print(.err, "chock eval suite: {s} already exists; choose a fresh output directory\n", .{index_path});
        return Exit.usage.code();
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const parallelism: usize = @intCast(options.parallelism orelse suite.parallelism);
    const suite_sha256 = try sha256(arena, source);

    var jobs: std.ArrayList(Job) = .empty;
    for (suite.cases) |one| {
        const spec_path = pathFromSuite(arena, options.suite_path, one.spec);
        const spec_source = std.Io.Dir.cwd().readFileAlloc(io, spec_path, arena, .limited(max_suite_bytes)) catch |err| {
            tty.print(.err, "chock eval suite: case {s} spec could not be read: {t}\n", .{ one.name, err });
            return Exit.usage.code();
        };
        const spec_digest = try sha256(arena, spec_source);
        const project = if (one.project) |path| pathFromSuite(arena, options.suite_path, path) else null;
        for (0..one.rollouts) |rollout_index| {
            const rollout: u32 = @intCast(rollout_index);
            const stem = try std.fmt.allocPrint(arena, "case-{d}-rollout-{d}", .{ jobs.items.len, rollout });
            try jobs.append(arena, .{
                .case_name = one.name,
                .spec_path = spec_path,
                .spec_sha256 = spec_digest,
                .project = project,
                .split = one.split,
                .group = rollout / one.group_size,
                .rollout = rollout,
                .capture = try std.fmt.allocPrint(arena, "{s}/{s}.capture.json", .{ output_path, stem }),
                .report = try std.fmt.allocPrint(arena, "{s}/{s}.report.json", .{ output_path, stem }),
                .trajectory = try std.fmt.allocPrint(arena, "{s}/{s}.trajectory.json", .{ output_path, stem }),
            });
        }
    }

    var entries: std.ArrayList(Entry) = .empty;
    var offset: usize = 0;
    while (offset < jobs.items.len) {
        const batch = jobs.items[offset..@min(offset + parallelism, jobs.items.len)];
        const children = try arena.alloc(std.process.Child, batch.len);
        var started: usize = 0;
        errdefer for (children[0..started]) |*child| child.kill(io);
        for (batch, children) |job, *child| {
            var argv: std.ArrayList([]const u8) = .empty;
            try argv.appendSlice(arena, &.{ exe_path, "eval", "run", job.spec_path, "--format", "json", "--capture", job.capture, "--report", job.report, "--trajectory", job.trajectory });
            if (job.project) |project| try argv.appendSlice(arena, &.{ "--project", project });
            child.* = try std.process.spawn(io, .{
                .argv = argv.items,
                .environ_map = env,
                .stdin = .ignore,
                .stdout = .ignore,
                .stderr = .inherit,
            });
            started += 1;
        }
        for (batch, children) |job, *child| {
            const term = try child.wait(io);
            const code: u8 = switch (term) {
                .exited => |value| value,
                else => 255,
            };
            var entry = Entry{
                .case = job.case_name,
                .spec = job.spec_path,
                .spec_sha256 = job.spec_sha256,
                .split = job.split,
                .group = job.group,
                .rollout = job.rollout,
                .capture = job.capture,
                .report = job.report,
                .trajectory = job.trajectory,
                .exit_code = code,
            };
            readSummary(arena, io, &entry) catch {};
            try entries.append(arena, entry);
        }
        offset += batch.len;
    }

    const dataset = Dataset{
        .suite = suite.name,
        .suite_sha256 = suite_sha256,
        .chock_version = @import("chock-version").text,
        .entries = entries.items,
    };
    try writeJson(arena, io, index_path, dataset);
    var failed: usize = 0;
    var trainable: usize = 0;
    for (entries.items) |entry| {
        failed += @intFromBool(entry.exit_code != 0);
        trainable += @intFromBool(entry.trainable);
    }
    tty.out(if (failed == 0) .plain else .warn, "{d} rollouts written to {s}; {d} trainable; {d} failed evaluation\n", .{ entries.items.len, output_path, trainable, failed });
    return if (failed == 0) Exit.finished.code() else Exit.refused.code();
}

fn parseOptions(args: []const []const u8) error{ HelpWanted, BadArguments }!Options {
    if (args.len == 0 or std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) return error.HelpWanted;
    var out = Options{ .suite_path = args[0] };
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--output")) {
            i += 1;
            if (i >= args.len) return error.BadArguments;
            out.output = args[i];
        } else if (std.mem.eql(u8, args[i], "--parallel")) {
            i += 1;
            if (i >= args.len) return error.BadArguments;
            out.parallelism = std.fmt.parseInt(u32, args[i], 10) catch return error.BadArguments;
            if (out.parallelism.? == 0 or out.parallelism.? > 256) return error.BadArguments;
        } else return error.BadArguments;
    }
    return out;
}

fn validSuite(suite: Suite) bool {
    if (!std.mem.eql(u8, suite.schema, "chock.rl-suite") or suite.version != 1 or suite.name.len == 0 or suite.cases.len == 0 or suite.parallelism == 0 or suite.parallelism > 256) return false;
    for (suite.cases) |one| {
        if (one.name.len == 0 or one.spec.len == 0 or one.rollouts == 0 or one.group_size == 0 or one.rollouts % one.group_size != 0) return false;
    }
    return true;
}

fn pathFromSuite(arena: std.mem.Allocator, suite_path: []const u8, path: []const u8) []const u8 {
    if (std.fs.path.isAbsolute(path)) return path;
    return std.fs.path.join(arena, &.{ std.fs.path.dirname(suite_path) orelse ".", path }) catch path;
}

fn realPath(arena: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    return arena.dupe(u8, buffer[0..try dir.realPath(io, &buffer)]);
}

fn sha256(arena: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn readSummary(arena: std.mem.Allocator, io: std.Io, entry: *Entry) !void {
    const Provenance = struct {
        model_profile: []const u8 = "",
        checkpoint: []const u8 = "",
        trainer: []const u8 = "",
        seed: ?u64 = null,
        intervention: []const u8 = "",
        intervention_sha256: []const u8 = "",
    };
    const Report = struct {
        session_id: []const u8 = "",
        base_commit: []const u8 = "",
        config_sha256: []const u8 = "",
        sandbox_sha256: []const u8 = "",
        sandbox_driver: []const u8 = "",
        reward: f64 = 0,
        provenance: Provenance = .{},
    };
    const report_bytes = try std.Io.Dir.cwd().readFileAlloc(io, entry.report, arena, .limited(max_artifact_bytes));
    const report = try std.json.parseFromSliceLeaky(Report, arena, report_bytes, .{ .ignore_unknown_fields = true });
    const Trajectory = struct { trainable: bool = false };
    const trajectory_bytes = try std.Io.Dir.cwd().readFileAlloc(io, entry.trajectory, arena, .limited(max_artifact_bytes));
    const trajectory = try std.json.parseFromSliceLeaky(Trajectory, arena, trajectory_bytes, .{ .ignore_unknown_fields = true });
    const capture_bytes = try std.Io.Dir.cwd().readFileAlloc(io, entry.capture, arena, .limited(max_artifact_bytes));
    entry.capture_sha256 = try sha256(arena, capture_bytes);
    entry.report_sha256 = try sha256(arena, report_bytes);
    entry.trajectory_sha256 = try sha256(arena, trajectory_bytes);
    entry.session_id = report.session_id;
    entry.base_commit = report.base_commit;
    entry.config_sha256 = report.config_sha256;
    entry.sandbox_sha256 = report.sandbox_sha256;
    entry.sandbox_driver = report.sandbox_driver;
    entry.reward = report.reward;
    entry.trainable = trajectory.trainable;
    entry.model_profile = report.provenance.model_profile;
    entry.checkpoint = report.provenance.checkpoint;
    entry.trainer = report.provenance.trainer;
    entry.seed = report.provenance.seed;
    entry.intervention = report.provenance.intervention;
    entry.intervention_sha256 = report.provenance.intervention_sha256;
}

fn writeJson(arena: std.mem.Allocator, io: std.Io, path: []const u8, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(arena, value, .{});
    var file = try std.Io.Dir.createFileAbsolute(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, json);
    try file.writeStreamingAll(io, "\n");
    try file.sync(io);
}

const testing = std.testing;

test "suite options bound rollout concurrency" {
    const parsed = try parseOptions(&.{ "suite.zon", "--output", "out", "--parallel", "8" });
    try testing.expectEqualStrings("out", parsed.output.?);
    try testing.expectEqual(@as(u32, 8), parsed.parallelism.?);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "suite.zon", "--parallel", "0" }));
}

test "suite requires complete equal-sized groups" {
    try testing.expect(validSuite(.{ .name = "train", .cases = &.{.{ .name = "one", .spec = "one.zon", .rollouts = 8, .group_size = 4 }} }));
    try testing.expect(!validSuite(.{ .name = "train", .cases = &.{.{ .name = "one", .spec = "one.zon", .rollouts = 3, .group_size = 2 }} }));
}
