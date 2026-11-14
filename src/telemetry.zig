//! Optional OpenTelemetry export for Chock's native process.
//!
//! Nothing leaves the process unless an OTLP endpoint is explicitly set in the
//! standard OTEL_EXPORTER_OTLP_* environment variables. Browser and mobile
//! builds do not import this module.

const std = @import("std");
const sdk = @import("opentelemetry-sdk");

pub const Attribute = sdk.Attribute;

const Runtime = struct {
    config: *sdk.otlp.ConfigOptions,
    exporter: *sdk.logs.OTLPExporter,
    processor: *sdk.logs.BatchingLogRecordProcessor,
    provider: *sdk.logs.LoggerProvider,
    logger: *sdk.logs.Logger,

    fn deinit(self: *Runtime) void {
        self.provider.shutdown() catch {};
        self.provider.deinit();
        self.processor.deinit();
        self.exporter.deinit();
        self.config.deinit();
        self.* = undefined;
    }
};

var active: ?Runtime = null;

/// Initialize once at process startup. A malformed or unavailable telemetry
/// endpoint must never prevent Chock from starting or completing its work.
pub fn init(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) void {
    if (active != null or sdkDisabled(environ) or !hasEndpoint(environ)) return;
    initialize(allocator, io, environ) catch |err| {
        std.log.warn("OpenTelemetry export is unavailable: {}", .{err});
    };
}

fn initialize(allocator: std.mem.Allocator, io: std.Io, environ: *const std.process.Environ.Map) !void {
    var runtime: Runtime = undefined;
    runtime.config = try sdk.otlp.ConfigOptions.init(allocator, environ);
    // Crashes are best-effort exported during panic unwinding; keep their
    // bounded flush from delaying the normal crash report for long.
    runtime.config.timeout_sec = 2;
    errdefer runtime.config.deinit();

    runtime.exporter = try sdk.logs.OTLPExporter.init(allocator, io, runtime.config);
    errdefer runtime.exporter.deinit();

    runtime.processor = try sdk.logs.BatchingLogRecordProcessor.init(
        allocator,
        io,
        runtime.exporter.asLogRecordExporter(),
        .{},
    );
    errdefer {
        runtime.processor.asLogRecordProcessor().shutdown() catch {};
        runtime.processor.deinit();
    }

    const resource = [_]sdk.Attribute{
        .{ .key = "service.name", .value = .{ .string = "chock" } },
    };
    runtime.provider = try sdk.logs.LoggerProvider.init(allocator, io, &resource);
    errdefer runtime.provider.deinit();

    try runtime.provider.addLogRecordProcessor(runtime.processor.asLogRecordProcessor());
    runtime.logger = try runtime.provider.getLogger(.{ .name = "chock", .version = "0.1" });
    active = runtime;
}

pub fn deinit() void {
    if (active) |*runtime| {
        runtime.deinit();
        active = null;
    }
}

/// Forward a std.log record while keeping Chock's existing stderr behavior.
/// OTel's own exporter diagnostics are deliberately excluded to avoid feeding
/// exporter failures back into the same exporter.
pub fn log(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    const scope_name = @tagName(scope);
    if (comptime isInternalScope(scope_name)) return;
    const runtime = if (active) |*one| one else return;

    var message: [4096]u8 = undefined;
    const body = std.fmt.bufPrint(&message, format, args) catch return;
    const attributes = [_]sdk.Attribute{
        .{ .key = "code.scope", .value = .{ .string = scope_name } },
    };
    runtime.logger.emit(severity(level), body, .{
        .severity_text = level.asText(),
        .attributes = &attributes,
        .location = @src(),
    });
}

pub fn event(name: []const u8, severity_level: sdk.logs.Severity, attributes: []const sdk.Attribute) void {
    const runtime = if (active) |*one| one else return;
    runtime.logger.emit(severity_level, name, .{
        .event_name = name,
        .attributes = attributes,
    });
}

/// Best-effort crash reporting before Zig's usual panic handler prints its
/// diagnostic and stack trace. This is only active when OTLP was explicitly
/// configured, and the exporter timeout is deliberately short.
pub fn panic(message: []const u8, return_address: ?usize) noreturn {
    if (active) |*runtime| {
        const attributes = [_]sdk.Attribute{
            .{ .key = "exception.type", .value = .{ .string = "panic" } },
            .{ .key = "exception.message", .value = .{ .string = message } },
        };
        runtime.logger.emit(.fatal, message, .{
            .event_name = "exception",
            .attributes = &attributes,
            .location = @src(),
        });
        runtime.provider.forceFlush() catch {};
    }
    std.debug.defaultPanic(message, return_address);
}

fn severity(comptime level: std.log.Level) sdk.logs.Severity {
    return switch (level) {
        .err => .err,
        .warn => .warn,
        .info => .info,
        .debug => .debug,
    };
}

fn isInternalScope(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "otlp_") or
        std.mem.startsWith(u8, name, "BatchingLogRecordProcessor");
}

fn sdkDisabled(environ: *const std.process.Environ.Map) bool {
    const value = environ.get("OTEL_SDK_DISABLED") orelse return false;
    return std.ascii.eqlIgnoreCase(value, "true");
}

fn hasEndpoint(environ: *const std.process.Environ.Map) bool {
    return environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") != null or
        environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT") != null;
}

test "telemetry stays disabled unless an OTLP endpoint is configured" {
    var environ = std.process.Environ.Map.init(std.testing.allocator);
    defer environ.deinit();
    try std.testing.expect(!hasEndpoint(&environ));
    try environ.put("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "http://collector:4318/v1/logs");
    try std.testing.expect(hasEndpoint(&environ));
}

test "telemetry honors the standard SDK disabled switch" {
    var environ = std.process.Environ.Map.init(std.testing.allocator);
    defer environ.deinit();
    try std.testing.expect(!sdkDisabled(&environ));
    try environ.put("OTEL_SDK_DISABLED", "TrUe");
    try std.testing.expect(sdkDisabled(&environ));
}
