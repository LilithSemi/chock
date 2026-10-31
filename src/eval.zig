//! `chock eval`: run or score a reproducible evaluation against an audited session.

const std = @import("std");
const chock_proto = @import("chock-proto");

const session_paths = @import("session.zig");
const Exit = @import("exit.zig").Exit;
const tty = @import("tty.zig");

const event = chock_proto.event;
const state = chock_proto.state;

const max_spec_bytes: usize = 1024 * 1024;
const max_log_bytes: usize = 128 * 1024 * 1024;

const usage_text =
    \\Usage: chock eval <run|replay|check> <spec.zon> [options]
    \\       chock eval compare <baseline.json> <candidate.json> [options]
    \\
    \\run starts a provider-backed `chock run --output json` with the task and
    \\provider settings in the spec and records its fixture. replay runs the same
    \\harness against only that fixture. check scores an existing session. All
    \\three run repository tests unless --skip-tests is passed.
    \\
    \\The report distinguishes model/session, harness/audit, sandbox, fixture, policy,
    \\network, budget and test failures. JSON is versioned and suitable for CI.
    \\
    \\Options:
    \\  --session <id>      Session to score. Required by check; forbidden by run/replay.
    \\  --project <dir>     Repository to run and inspect. Overrides spec.fixture.
    \\  --format <kind>     human (default) or json.
    \\  --skip-tests        Score the audit and repository without executing tests.
    \\  --minimum-score <n> Candidate score required by compare (default 0).
    \\  --max-regression <n>
    \\                       How far below the baseline compare may fall (default 0).
    \\
    \\Example spec:
    \\
    \\  .{
    \\      .name = "parser regression",
    \\      .task = "reject an empty input",
    \\      .fixture = "fixtures/parser",
    \\      .provider = "local",
    \\      .model = "coder",
    \\      .capture = "captures/parser.json",
    \\      .expect = .{
    \\          .end_reason = "finished",
    \\          .max_turns = 8,
    \\          .max_cost = 1.0,
    \\          .currency = "USD",
    \\          .required_paths = &.{"src/parser.zig"},
    \\          .forbidden_paths = &.{"secrets.txt"},
    \\          .required_events = &.{"tool.call", "usage"},
    \\          .forbidden_tools = &.{"browser"},
    \\          .require_no_network = true,
    \\          .require_no_refusals = true,
    \\      },
    \\      .tests = &.{.{ .name = "unit", .argv = &.{"zig", "build", "test"} }},
    \\  }
    \\
++ tty.options_text;

const Action = enum { run, replay, check, compare };
const Format = enum { human, json };

const Options = struct {
    action: Action,
    spec_path: []const u8,
    candidate_path: []const u8 = "",
    session: []const u8 = "",
    project: ?[]const u8 = null,
    format: Format = .human,
    skip_tests: bool = false,
    minimum_score: f64 = 0,
    max_regression: f64 = 0,
};

const Test = struct {
    name: []const u8,
    argv: []const []const u8,
};

const FileExpectation = struct {
    path: []const u8,
    sha256: []const u8,
};

const RewardWeights = struct {
    model: f64 = 1,
    harness: f64 = 1,
    sandbox: f64 = 1,
    fixture: f64 = 1,
    policy: f64 = 1,
    network: f64 = 1,
    budget: f64 = 1,
    tests: f64 = 1,
};

const Expectations = struct {
    end_reason: []const u8 = "finished",
    max_turns: ?u64 = null,
    max_cost: ?f64 = null,
    currency: []const u8 = "",
    audit_sha256: []const u8 = "",
    config_sha256: []const u8 = "",
    sandbox_sha256: []const u8 = "",
    required_events: []const []const u8 = &.{},
    forbidden_events: []const []const u8 = &.{},
    required_paths: []const []const u8 = &.{},
    forbidden_paths: []const []const u8 = &.{},
    files: []const FileExpectation = &.{},
    forbidden_tools: []const []const u8 = &.{},
    forbidden_network_hosts: []const []const u8 = &.{},
    require_no_network: bool = false,
    require_no_refusals: bool = false,
    min_subagents: ?u64 = null,
    max_subagents: ?u64 = null,
    require_subagents_complete: bool = false,
};

const Spec = struct {
    schema: []const u8 = "chock.eval",
    version: u32 = 1,
    name: []const u8,
    task: []const u8,
    fixture: []const u8 = ".",
    provider: []const u8 = "",
    model: []const u8 = "",
    capture: []const u8 = "",
    expect: Expectations = .{},
    reward_weights: RewardWeights = .{},
    tests: []const Test = &.{},
};

const Finding = struct {
    name: []const u8,
    category: []const u8,
    passed: bool,
    expected: []const u8,
    actual: []const u8,
};

const Report = struct {
    schema: []const u8 = "chock.eval-report",
    version: u32 = 1,
    eval: []const u8,
    session_id: []const u8,
    passed: bool,
    checks: usize,
    failures: usize,
    score: f64,
    reward: f64 = 0,
    reward_components: []const RewardComponent = &.{},
    findings: []const Finding,
};

const RewardComponent = struct {
    category: []const u8,
    passed: usize,
    checks: usize,
    weight: f64,
    value: f64,
};

const Comparison = struct {
    schema: []const u8 = "chock.eval-comparison",
    version: u32 = 1,
    baseline_eval: []const u8,
    baseline_session: []const u8,
    baseline_score: f64,
    candidate_eval: []const u8,
    candidate_session: []const u8,
    candidate_score: f64,
    score_delta: f64,
    minimum_score: f64,
    max_regression: f64,
    passed: bool,
};

const Observed = struct {
    session: state.Session,
    kinds: std.EnumSet(event.Kind) = .empty,
    tools: std.ArrayList([]const u8) = .empty,
    hosts: std.ArrayList([]const u8) = .empty,
    network_granted: u64 = 0,
    refused: u64 = 0,
    config_sha256: []const u8 = "",
    sandbox_sha256: []const u8 = "",
    audit_sha256: [64]u8,
    chain: chock_proto.chain.Verdict,
};

pub fn main(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    environ: std.process.Environ,
    exe_path: []const u8,
    args: []const []const u8,
) anyerror!u8 {
    var threaded = std.Io.Threaded.init(arena, .{ .environ = environ });
    defer threaded.deinit();
    const io = threaded.io();
    var env = try environ.createMap(arena);
    defer env.deinit();

    const options = parseOptions(args) catch |err| switch (err) {
        error.HelpWanted => {
            tty.out(.plain, "{s}", .{usage_text});
            return Exit.finished.code();
        },
        else => {
            tty.print(.err, "{s}", .{usage_text});
            return Exit.usage.code();
        },
    };

    if (options.action == .compare) return compareReports(arena, io, options) catch |err| {
        tty.print(.err, "chock eval: reports could not be compared: {t}\n", .{err});
        return Exit.usage.code();
    };

    const source = std.Io.Dir.cwd().readFileAlloc(io, options.spec_path, arena, .limited(max_spec_bytes)) catch |err| {
        tty.print(.err, "chock eval: {s} could not be read: {t}\n", .{ options.spec_path, err });
        return Exit.usage.code();
    };
    const source_z = try arena.dupeSentinel(u8, source, 0);
    var diagnostics: std.zon.parse.Diagnostics = undefined;
    const spec = std.zon.parse.fromSlice(Spec, .{
        .gpa = gpa,
        .arena = arena,
        .source = source_z,
        .diagnostics = &diagnostics,
    }) catch |err| {
        tty.print(.err, "chock eval: {s} is not a valid evaluation spec: {t}\n", .{ options.spec_path, err });
        return Exit.usage.code();
    };
    if (!std.mem.eql(u8, spec.schema, "chock.eval") or spec.version != 1 or spec.name.len == 0) {
        tty.print(.err, "chock eval: the spec must name schema chock.eval version 1 and a non-empty evaluation\n", .{});
        return Exit.usage.code();
    }
    if (!validSpec(spec)) {
        tty.print(.err, "chock eval: paths must be relative and stay inside the fixture, tests need a name and argv, and event names must be known\n", .{});
        return Exit.usage.code();
    }

    const project = resolveProject(arena, io, options.project orelse fixtureFromSpec(arena, options.spec_path, spec.fixture)) catch |err| {
        tty.print(.err, "chock eval: the fixture could not be opened: {t}\n", .{err});
        return Exit.usage.code();
    };
    const capture_path = if (spec.capture.len == 0) "" else fixtureFromSpec(arena, options.spec_path, spec.capture);
    if ((options.action == .run or options.action == .replay) and capture_path.len == 0) {
        tty.print(.err, "chock eval: provider runs and replays require .capture in the spec\n", .{});
        return Exit.usage.code();
    }
    const session = switch (options.action) {
        .check => options.session,
        .run, .replay => runProvider(arena, gpa, io, &env, exe_path, project, spec, capture_path, options.action) catch |err| {
            tty.print(.err, "chock eval: the provider-backed run did not produce a session: {t}\n", .{err});
            return Exit.faulted.code();
        },
        .compare => unreachable,
    };

    const session_dir = session_paths.projectDir(arena, &env, project) catch |err| {
        tty.print(.err, "chock eval: the session directory is unknown: {t}\n", .{err});
        return Exit.usage.code();
    };
    const log_path = try std.fmt.allocPrintSentinel(arena, "{s}/{s}.jsonl", .{ session_dir, session }, 0);
    var observed = observe(arena, gpa, io, log_path, session) catch |err| {
        tty.print(.err, "chock eval: session {s} could not be replayed: {t}\n", .{ session, err });
        return Exit.audit_gap.code();
    };

    var findings: std.ArrayList(Finding) = .empty;
    try scoreAudit(arena, spec, &observed, &findings);
    try scoreFixture(arena, io, project, spec, &findings);
    if (!options.skip_tests) try scoreTests(arena, gpa, io, &env, project, spec.tests, &findings);

    var failures: usize = 0;
    for (findings.items) |finding| failures += @intFromBool(!finding.passed);
    const checks = findings.items.len;
    const reward_summary = try summarizeReward(arena, spec.reward_weights, findings.items);
    const report = Report{
        .eval = spec.name,
        .session_id = session,
        .passed = failures == 0,
        .checks = checks,
        .failures = failures,
        .score = if (checks == 0) 1 else @as(f64, @floatFromInt(checks - failures)) / @as(f64, @floatFromInt(checks)),
        .reward = reward_summary.value,
        .reward_components = reward_summary.components,
        .findings = findings.items,
    };
    writeReport(arena, options.format, report) catch return Exit.faulted.code();
    return if (report.passed) Exit.finished.code() else Exit.refused.code();
}

const RewardSummary = struct {
    value: f64,
    components: []const RewardComponent,
};

fn summarizeReward(arena: std.mem.Allocator, weights: RewardWeights, findings: []const Finding) !RewardSummary {
    const categories = [_][]const u8{ "model", "harness", "sandbox", "fixture", "policy", "network", "budget", "test" };
    var components: std.ArrayList(RewardComponent) = .empty;
    var weighted: f64 = 0;
    var total_weight: f64 = 0;
    for (categories) |category| {
        var checks: usize = 0;
        var passed: usize = 0;
        for (findings) |finding| {
            if (!std.mem.eql(u8, finding.category, category)) continue;
            checks += 1;
            passed += @intFromBool(finding.passed);
        }
        if (checks == 0) continue;
        const weight = rewardWeight(weights, category);
        const value = @as(f64, @floatFromInt(passed)) / @as(f64, @floatFromInt(checks));
        try components.append(arena, .{
            .category = category,
            .passed = passed,
            .checks = checks,
            .weight = weight,
            .value = value,
        });
        weighted += value * weight;
        total_weight += weight;
    }
    return .{
        .value = if (total_weight == 0) 0 else weighted / total_weight,
        .components = components.items,
    };
}

fn rewardWeight(weights: RewardWeights, category: []const u8) f64 {
    if (std.mem.eql(u8, category, "model")) return weights.model;
    if (std.mem.eql(u8, category, "harness")) return weights.harness;
    if (std.mem.eql(u8, category, "sandbox")) return weights.sandbox;
    if (std.mem.eql(u8, category, "fixture")) return weights.fixture;
    if (std.mem.eql(u8, category, "policy")) return weights.policy;
    if (std.mem.eql(u8, category, "network")) return weights.network;
    if (std.mem.eql(u8, category, "budget")) return weights.budget;
    if (std.mem.eql(u8, category, "test")) return weights.tests;
    unreachable;
}

fn parseOptions(args: []const []const u8) error{ HelpWanted, BadArguments }!Options {
    if (args.len == 0) return error.BadArguments;
    if (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h")) return error.HelpWanted;
    const action = std.meta.stringToEnum(Action, args[0]) orelse return error.BadArguments;
    if (args.len < 2 or args[1].len == 0 or args[1][0] == '-') return error.BadArguments;
    var out = Options{ .action = action, .spec_path = args[1] };
    var i: usize = 2;
    if (action == .compare) {
        if (args.len < 3 or args[2].len == 0 or args[2][0] == '-') return error.BadArguments;
        out.candidate_path = args[2];
        i = 3;
    }
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--skip-tests")) {
            out.skip_tests = true;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--session")) {
            i += 1;
            if (i >= args.len) return error.BadArguments;
            out.session = args[i];
            continue;
        }
        if (std.mem.eql(u8, args[i], "--project")) {
            i += 1;
            if (i >= args.len) return error.BadArguments;
            out.project = args[i];
            continue;
        }
        if (std.mem.eql(u8, args[i], "--format")) {
            i += 1;
            if (i >= args.len) return error.BadArguments;
            out.format = std.meta.stringToEnum(Format, args[i]) orelse return error.BadArguments;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--minimum-score") or std.mem.eql(u8, args[i], "--max-regression")) {
            const is_minimum = std.mem.eql(u8, args[i], "--minimum-score");
            i += 1;
            if (i >= args.len) return error.BadArguments;
            const value = std.fmt.parseFloat(f64, args[i]) catch return error.BadArguments;
            if (!std.math.isFinite(value) or value < 0 or value > 1) return error.BadArguments;
            if (is_minimum) out.minimum_score = value else out.max_regression = value;
            continue;
        }
        return error.BadArguments;
    }
    if (action == .check and !session_paths.isValidId(out.session)) return error.BadArguments;
    if ((action == .run or action == .replay) and out.session.len != 0) return error.BadArguments;
    if (action != .compare and (out.minimum_score != 0 or out.max_regression != 0)) return error.BadArguments;
    if (action == .compare and (out.session.len != 0 or out.project != null or out.skip_tests)) return error.BadArguments;
    return out;
}

fn compareReports(arena: std.mem.Allocator, io: std.Io, options: Options) !u8 {
    const baseline = try readReport(arena, io, options.spec_path);
    const candidate = try readReport(arena, io, options.candidate_path);
    const passed = candidate.score >= options.minimum_score and
        candidate.score + options.max_regression >= baseline.score;
    const comparison = Comparison{
        .baseline_eval = baseline.eval,
        .baseline_session = baseline.session_id,
        .baseline_score = baseline.score,
        .candidate_eval = candidate.eval,
        .candidate_session = candidate.session_id,
        .candidate_score = candidate.score,
        .score_delta = candidate.score - baseline.score,
        .minimum_score = options.minimum_score,
        .max_regression = options.max_regression,
        .passed = passed,
    };
    switch (options.format) {
        .json => {
            const json = try std.json.Stringify.valueAlloc(arena, comparison, .{});
            tty.out(.plain, "{s}\n", .{json});
        },
        .human => {
            tty.out(if (passed) .plain else .warn, "{s}  baseline {d:.3}; candidate {d:.3}; delta {d:.3}\n", .{
                if (passed) "pass" else "FAIL",
                comparison.baseline_score,
                comparison.candidate_score,
                comparison.score_delta,
            });
        },
    }
    return if (passed) Exit.finished.code() else Exit.refused.code();
}

fn readReport(arena: std.mem.Allocator, io: std.Io, path: []const u8) !Report {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_spec_bytes));
    const report = try std.json.parseFromSliceLeaky(Report, arena, bytes, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, report.schema, "chock.eval-report") or report.version != 1 or
        !std.math.isFinite(report.score) or report.score < 0 or report.score > 1)
    {
        return error.BadReport;
    }
    return report;
}

fn fixtureFromSpec(arena: std.mem.Allocator, spec_path: []const u8, fixture: []const u8) []const u8 {
    if (std.fs.path.isAbsolute(fixture)) return fixture;
    return std.fs.path.join(arena, &.{ std.fs.path.dirname(spec_path) orelse ".", fixture }) catch fixture;
}

fn resolveProject(arena: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{});
    defer dir.close(io);
    const len = try dir.realPath(io, &buffer);
    return arena.dupe(u8, buffer[0..len]);
}

fn validSpec(spec: Spec) bool {
    if (spec.task.len == 0) return false;
    for (spec.expect.required_paths) |path| if (!safeRelative(path)) return false;
    for (spec.expect.forbidden_paths) |path| if (!safeRelative(path)) return false;
    for (spec.expect.files) |file| {
        if (!safeRelative(file.path) or !validSha256(file.sha256)) return false;
    }
    for (spec.expect.required_events) |name| if (event.Kind.fromWireName(name) == null) return false;
    for (spec.expect.forbidden_events) |name| if (event.Kind.fromWireName(name) == null) return false;
    for (spec.tests) |one| if (one.name.len == 0 or one.argv.len == 0 or one.argv[0].len == 0) return false;
    if (spec.expect.max_cost != null and spec.expect.max_cost.? < 0) return false;
    if (spec.expect.config_sha256.len != 0 and !validSha256(spec.expect.config_sha256)) return false;
    if (spec.expect.sandbox_sha256.len != 0 and !validSha256(spec.expect.sandbox_sha256)) return false;
    if (spec.expect.min_subagents != null and spec.expect.max_subagents != null and spec.expect.min_subagents.? > spec.expect.max_subagents.?) return false;
    inline for (@typeInfo(RewardWeights).@"struct".field_names) |field| {
        const weight = @field(spec.reward_weights, field);
        if (!std.math.isFinite(weight) or weight < 0) return false;
    }
    return true;
}

fn validSha256(text: []const u8) bool {
    if (text.len != 64) return false;
    for (text) |byte| if (!std.ascii.isHex(byte)) return false;
    return true;
}

fn safeRelative(path: []const u8) bool {
    if (path.len == 0 or std.fs.path.isAbsolute(path)) return false;
    var parts = std.fs.path.componentIterator(path);
    while (parts.next()) |part| if (std.mem.eql(u8, part.name, "..")) return false;
    return true;
}

fn runProvider(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    exe_path: []const u8,
    project: []const u8,
    spec: Spec,
    capture_path: []const u8,
    action: Action,
) ![]const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ exe_path, "run", "--project", project, "--output", "json" });
    if (spec.provider.len != 0) try argv.appendSlice(gpa, &.{ "--provider", spec.provider });
    if (spec.model.len != 0) try argv.appendSlice(gpa, &.{ "--model", spec.model });
    try argv.appendSlice(gpa, &.{ if (action == .replay) "--eval-replay" else "--eval-record", capture_path });
    if (spec.expect.max_cost) |amount| {
        const text = try std.fmt.allocPrint(arena, "{d}", .{amount});
        try argv.appendSlice(gpa, &.{ "--max-cost", text });
        if (spec.expect.currency.len != 0) try argv.appendSlice(gpa, &.{ "--currency", spec.expect.currency });
    }
    try argv.appendSlice(gpa, &.{ "--", spec.task });
    const result = try std.process.run(gpa, io, .{ .argv = argv.items, .environ_map = env });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    const RunResult = struct { schema: []const u8 = "", session_id: ?[]const u8 = null };
    const parsed = try std.json.parseFromSliceLeaky(RunResult, arena, result.stdout, .{ .ignore_unknown_fields = true });
    if (!std.mem.eql(u8, parsed.schema, "chock.run-result")) return error.BadRunResult;
    const id = parsed.session_id orelse return error.NoSession;
    if (!session_paths.isValidId(id)) return error.NoSession;
    return id;
}

fn observe(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    path: [:0]const u8,
    id: []const u8,
) !Observed {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_log_bytes));
    var raw_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &raw_digest, .{});

    const log = try chock_proto.log.Log.open(io, path, id);
    var backing = chock_proto.storage.JsonLines{ .log = log };
    const storage = backing.storage();
    defer storage.close(io);
    const verified = try chock_proto.storage.verify(storage, gpa, io);

    var out = Observed{
        .session = state.Session.init(arena),
        .audit_sha256 = std.fmt.bytesToHex(raw_digest, .lower),
        .chain = verified.verdict,
    };
    var replay = try storage.replay(gpa, io, 0);
    defer replay.deinit();
    while (try replay.next(io)) |parsed| {
        defer parsed.deinit();
        try out.session.apply(parsed.value);
        const kind = std.meta.activeTag(parsed.value.event);
        out.kinds.insert(kind);
        switch (parsed.value.event) {
            .session_config => |one| {
                out.config_sha256 = if (one.config_hash) |hash| try arena.dupe(u8, hash) else "none";
                out.sandbox_sha256 = try arena.dupe(u8, one.sandbox_hash);
            },
            .tool_call => |one| try out.tools.append(arena, try arena.dupe(u8, one.tool)),
            .mcp_request => |one| if (one.host.len != 0) try out.hosts.append(arena, try arena.dupe(u8, one.host)),
            .network_summary => |one| out.network_granted += one.granted,
            .approval_response => |one| if (isRefusal(one.decision)) {
                out.refused += 1;
            },
            else => {},
        }
    }
    return out;
}

fn isRefusal(decision: event.ApprovalDecision) bool {
    return switch (decision) {
        .denied_by_policy, .refused_by_user, .expired, .refused_by_review, .review_unavailable, .unknown => true,
        .allowed_by_policy, .approved_by_user, .approved_by_user_for_session, .approved_by_review => false,
    };
}

fn scoreAudit(arena: std.mem.Allocator, spec: Spec, observed: *const Observed, out: *std.ArrayList(Finding)) !void {
    try add(arena, out, "audit chain", "harness", observed.chain == .intact, "intact", @tagName(observed.chain));
    const actual_end = if (observed.session.ended) observed.session.end_reason.wireName() else "no terminal session.end";
    try add(arena, out, "terminal outcome", "model", std.mem.eql(u8, actual_end, spec.expect.end_reason), spec.expect.end_reason, actual_end);
    if (spec.expect.audit_sha256.len != 0) try add(
        arena,
        out,
        "audit capture digest",
        "harness",
        std.mem.eql(u8, &observed.audit_sha256, spec.expect.audit_sha256),
        spec.expect.audit_sha256,
        &observed.audit_sha256,
    );
    if (spec.expect.config_sha256.len != 0) try add(arena, out, "configuration digest", "policy", std.mem.eql(u8, observed.config_sha256, spec.expect.config_sha256), spec.expect.config_sha256, observed.config_sha256);
    if (spec.expect.sandbox_sha256.len != 0) try add(arena, out, "sandbox digest", "sandbox", std.mem.eql(u8, observed.sandbox_sha256, spec.expect.sandbox_sha256), spec.expect.sandbox_sha256, observed.sandbox_sha256);
    if (spec.expect.max_turns) |limit| try addNumber(arena, out, "turn budget", "budget", observed.session.spend.turns <= limit, limit, observed.session.spend.turns);
    if (spec.expect.max_cost) |limit| {
        const usable = observed.session.spend.enforceable();
        try addFloat(arena, out, "cost budget", "budget", usable and observed.session.spend.amount <= limit, limit, observed.session.spend.amount);
    }
    if (spec.expect.currency.len != 0) try add(arena, out, "cost currency", "budget", std.mem.eql(u8, spec.expect.currency, observed.session.spend.currency), spec.expect.currency, observed.session.spend.currency);
    for (spec.expect.required_events) |name| {
        const kind = event.Kind.fromWireName(name).?;
        try add(arena, out, try std.fmt.allocPrint(arena, "required event {s}", .{name}), categoryFor(kind), observed.kinds.contains(kind), "present", "absent");
    }
    for (spec.expect.forbidden_events) |name| {
        const kind = event.Kind.fromWireName(name).?;
        try add(arena, out, try std.fmt.allocPrint(arena, "forbidden event {s}", .{name}), categoryFor(kind), !observed.kinds.contains(kind), "absent", "present");
    }
    for (spec.expect.forbidden_tools) |tool| try add(arena, out, try std.fmt.allocPrint(arena, "forbidden tool {s}", .{tool}), "policy", !contains(observed.tools.items, tool), "absent", "called");
    for (spec.expect.forbidden_network_hosts) |host| try add(arena, out, try std.fmt.allocPrint(arena, "forbidden network host {s}", .{host}), "network", !contains(observed.hosts.items, host), "absent", "contacted");
    if (spec.expect.require_no_network) try addNumber(arena, out, "network grants", "network", observed.network_granted == 0 and observed.hosts.items.len == 0, 0, observed.network_granted + observed.hosts.items.len);
    if (spec.expect.require_no_refusals) try addNumber(arena, out, "policy refusals", "policy", observed.refused == 0, 0, observed.refused);
    const child_count: u64 = @intCast(observed.session.children.items.len);
    if (spec.expect.min_subagents) |minimum| try addNumber(arena, out, "minimum subagents", "harness", child_count >= minimum, minimum, child_count);
    if (spec.expect.max_subagents) |maximum| try addNumber(arena, out, "maximum subagents", "harness", child_count <= maximum, maximum, child_count);
    if (spec.expect.require_subagents_complete) {
        var incomplete: u64 = 0;
        for (observed.session.children.items) |child| incomplete += @intFromBool(child.outcome == null);
        try addNumber(arena, out, "completed subagents", "harness", incomplete == 0, 0, incomplete);
    }
}

fn categoryFor(kind: event.Kind) []const u8 {
    return switch (kind) {
        .sandbox_open, .sandbox_supervisor, .sandbox_syscalls => "sandbox",
        .network_summary, .mcp_request => "network",
        .approval_request, .approval_response, .policy_self => "policy",
        .usage => "budget",
        else => "harness",
    };
}

fn scoreFixture(arena: std.mem.Allocator, io: std.Io, project: []const u8, spec: Spec, out: *std.ArrayList(Finding)) !void {
    for (spec.expect.required_paths) |relative| {
        const path = try std.fs.path.join(arena, &.{ project, relative });
        const exists = if (std.Io.Dir.cwd().statFile(io, path, .{})) |_| true else |_| false;
        try add(arena, out, try std.fmt.allocPrint(arena, "required path {s}", .{relative}), "fixture", exists, "present", "absent");
    }
    for (spec.expect.forbidden_paths) |relative| {
        const path = try std.fs.path.join(arena, &.{ project, relative });
        const exists = if (std.Io.Dir.cwd().statFile(io, path, .{})) |_| true else |_| false;
        try add(arena, out, try std.fmt.allocPrint(arena, "forbidden path {s}", .{relative}), "fixture", !exists, "absent", "present");
    }
    for (spec.expect.files) |expected| {
        const path = try std.fs.path.join(arena, &.{ project, expected.path });
        const actual = fileSha256(arena, io, path) catch |err| {
            try add(arena, out, try std.fmt.allocPrint(arena, "file digest {s}", .{expected.path}), "fixture", false, expected.sha256, @errorName(err));
            continue;
        };
        try add(arena, out, try std.fmt.allocPrint(arena, "file digest {s}", .{expected.path}), "fixture", std.mem.eql(u8, expected.sha256, actual), expected.sha256, actual);
    }
}

fn fileSha256(arena: std.mem.Allocator, io: std.Io, path: []const u8) ![]const u8 {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(max_log_bytes));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return arena.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

fn scoreTests(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    project: []const u8,
    tests: []const Test,
    out: *std.ArrayList(Finding),
) !void {
    for (tests) |one| {
        const result = std.process.run(gpa, io, .{ .argv = one.argv, .environ_map = env, .cwd = .{ .path = project } }) catch |err| {
            try add(arena, out, one.name, "test", false, "exit 0", @errorName(err));
            continue;
        };
        const code: u32 = switch (result.term) {
            .exited => |value| value,
            else => std.math.maxInt(u32),
        };
        gpa.free(result.stdout);
        gpa.free(result.stderr);
        try addNumber(arena, out, one.name, "test", code == 0, 0, code);
    }
}

fn contains(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |one| if (std.mem.eql(u8, one, needle)) return true;
    return false;
}

fn add(arena: std.mem.Allocator, out: *std.ArrayList(Finding), name: []const u8, category: []const u8, passed: bool, expected: []const u8, actual: []const u8) !void {
    try out.append(arena, .{ .name = name, .category = category, .passed = passed, .expected = expected, .actual = actual });
}

fn addNumber(arena: std.mem.Allocator, out: *std.ArrayList(Finding), name: []const u8, category: []const u8, passed: bool, expected: u64, actual: anytype) !void {
    try add(arena, out, name, category, passed, try std.fmt.allocPrint(arena, "{d}", .{expected}), try std.fmt.allocPrint(arena, "{d}", .{actual}));
}

fn addFloat(arena: std.mem.Allocator, out: *std.ArrayList(Finding), name: []const u8, category: []const u8, passed: bool, expected: f64, actual: f64) !void {
    try add(arena, out, name, category, passed, try std.fmt.allocPrint(arena, "{d:.6}", .{expected}), try std.fmt.allocPrint(arena, "{d:.6}", .{actual}));
}

fn writeReport(arena: std.mem.Allocator, format: Format, report: Report) !void {
    switch (format) {
        .json => {
            const json = try std.json.Stringify.valueAlloc(arena, report, .{});
            tty.out(.plain, "{s}\n", .{json});
        },
        .human => {
            tty.out(.plain, "eval {s}  session {s}\n", .{ report.eval, report.session_id });
            for (report.findings) |finding| tty.out(if (finding.passed) .plain else .warn, "{s}  [{s}] {s}: expected {s}; got {s}\n", .{
                if (finding.passed) "pass" else "FAIL",
                finding.category,
                finding.name,
                finding.expected,
                finding.actual,
            });
            tty.out(if (report.passed) .plain else .warn, "{d}/{d} checks passed; score {d:.3}; reward {d:.3}\n", .{ report.checks - report.failures, report.checks, report.score, report.reward });
        },
    }
}

const testing = std.testing;

test "eval command line separates provider runs from deterministic checks" {
    const id = "01JQ" ++ @as([22]u8, @splat('A'));
    const checked = try parseOptions(&.{ "check", "case.zon", "--session", id, "--format", "json", "--skip-tests" });
    try testing.expectEqual(Action.check, checked.action);
    try testing.expectEqual(Format.json, checked.format);
    try testing.expect(checked.skip_tests);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "check", "case.zon" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "run", "case.zon", "--session", id }));
    try testing.expectEqual(Action.replay, (try parseOptions(&.{ "replay", "case.zon" })).action);

    const compared = try parseOptions(&.{ "compare", "base.json", "candidate.json", "--minimum-score", "0.8", "--max-regression", "0.05" });
    try testing.expectEqual(Action.compare, compared.action);
    try testing.expectEqualStrings("candidate.json", compared.candidate_path);
    try testing.expectApproxEqAbs(@as(f64, 0.8), compared.minimum_score, 0.0001);
    try testing.expectApproxEqAbs(@as(f64, 0.05), compared.max_regression, 0.0001);
    try testing.expectError(error.BadArguments, parseOptions(&.{ "compare", "base.json" }));
    try testing.expectError(error.BadArguments, parseOptions(&.{ "compare", "base.json", "candidate.json", "--minimum-score", "1.1" }));
}

test "evaluation paths cannot leave their fixture" {
    try testing.expect(safeRelative("src/main.zig"));
    try testing.expect(!safeRelative("../secret"));
    try testing.expect(!safeRelative("/etc/passwd"));
    try testing.expect(!safeRelative(""));
    try testing.expect(validSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    try testing.expect(!validSha256("not-a-digest"));
}

test "audit scoring preserves failure ownership" {
    var backing = std.heap.ArenaAllocator.init(testing.allocator);
    defer backing.deinit();
    const arena = backing.allocator();
    var observed = Observed{
        .session = state.Session.init(arena),
        .audit_sha256 = @splat('a'),
        .chain = .intact,
    };
    defer observed.session.deinit();
    defer observed.tools.deinit(arena);
    defer observed.hosts.deinit(arena);

    try observed.session.apply(.{ .id = 1, .session = "01EVAL", .time_ms = 1, .event = .{
        .session_start = .{ .agent_kind = "coder", .model_alias = "main", .parent_session = "" },
    } });
    try observed.session.apply(.{ .id = 2, .session = "01EVAL", .time_ms = 2, .event = .{
        .session_end = .{ .reason = .finished, .detail = "" },
    } });
    observed.kinds.insert(.session_start);
    observed.kinds.insert(.session_end);
    observed.kinds.insert(.tool_call);
    try observed.tools.append(arena, "browser");

    const spec = Spec{
        .name = "ownership",
        .task = "do the thing",
        .expect = .{
            .required_events = &.{"tool.call"},
            .forbidden_tools = &.{"browser"},
            .require_no_network = true,
        },
    };
    var findings: std.ArrayList(Finding) = .empty;
    defer findings.deinit(arena);
    try scoreAudit(arena, spec, &observed, &findings);

    try testing.expectEqual(@as(usize, 5), findings.items.len);
    try testing.expect(findings.items[0].passed);
    try testing.expectEqualStrings("harness", findings.items[0].category);
    try testing.expect(findings.items[2].passed);
    try testing.expect(!findings.items[3].passed);
    try testing.expectEqualStrings("policy", findings.items[3].category);
    try testing.expect(findings.items[4].passed);
    try testing.expectEqualStrings("network", findings.items[4].category);

    const reward = try summarizeReward(arena, .{ .policy = 3, .network = 0 }, findings.items);
    try testing.expectApproxEqAbs(@as(f64, 0.4), reward.value, 0.0001);
    try testing.expectEqual(@as(usize, 4), reward.components.len);
}
