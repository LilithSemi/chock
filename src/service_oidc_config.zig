//! Daemon-private persistence for web-provisioned OIDC configuration.
//!
//! Provider credentials are deliberately kept out of Quarry records and out
//! of the browser gateway. The service state directory is owned by the daemon
//! account; this file adds a strict 0600 boundary and atomic replacement.

const std = @import("std");
const daemon_state = @import("chock-daemon");

pub const max_config_bytes = 16 * 1024;

pub const Config = struct {
    provider: daemon_state.Provider,
    issuer: []const u8,
    discovery_url: ?[]const u8 = null,
    client_id: []const u8,
    client_secret: ?[]const u8 = null,
    admin_subject: []const u8,

    pub fn deinit(self: *Config, gpa: std.mem.Allocator) void {
        gpa.free(self.issuer);
        if (self.discovery_url) |url| gpa.free(url);
        if (self.client_id.len != 0) gpa.free(self.client_id);
        if (self.client_secret) |secret| gpa.free(secret);
        if (self.admin_subject.len != 0) gpa.free(self.admin_subject);
        self.* = undefined;
    }

    pub fn validate(self: Config) error{InvalidConfiguration}!void {
        if (self.admin_subject.len == 0 or self.admin_subject.len > 512 or
            std.mem.indexOfAny(u8, self.admin_subject, "\t\r\n\x00") != null)
            return error.InvalidConfiguration;
        (daemon_state.Oidc{
            .provider = self.provider,
            .issuer = self.issuer,
            .client_id = self.client_id,
            .client_secret = self.client_secret,
            .discovery_url = self.discovery_url,
        }).validate() catch return error.InvalidConfiguration;
    }
};

pub fn load(gpa: std.mem.Allocator, io: std.Io, path: []const u8) anyerror!Config {
    var file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch |err| return switch (err) {
        error.FileNotFound => error.FileNotFound,
        else => err,
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file or stat.permissions.toMode() & 0o077 != 0)
        return error.InvalidPermissions;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_config_bytes)) catch |err| return switch (err) {
        error.FileNotFound => error.FileNotFound,
        error.FileTooBig => error.ConfigTooLarge,
        else => err,
    };
    defer gpa.free(bytes);
    const parsed = std.json.parseFromSlice(Config, gpa, bytes, .{ .ignore_unknown_fields = false }) catch
        return error.InvalidJson;
    defer parsed.deinit();
    parsed.value.validate() catch return error.InvalidConfiguration;
    var loaded: Config = .{
        .provider = parsed.value.provider,
        .issuer = try gpa.dupe(u8, parsed.value.issuer),
        .discovery_url = null,
        .client_id = "",
        .client_secret = null,
        .admin_subject = "",
    };
    errdefer loaded.deinit(gpa);
    loaded.discovery_url = if (parsed.value.discovery_url) |url| try gpa.dupe(u8, url) else null;
    loaded.client_id = try gpa.dupe(u8, parsed.value.client_id);
    loaded.client_secret = if (parsed.value.client_secret) |secret| try gpa.dupe(u8, secret) else null;
    loaded.admin_subject = try gpa.dupe(u8, parsed.value.admin_subject);
    return loaded;
}

pub fn save(gpa: std.mem.Allocator, io: std.Io, path: []const u8, config: Config) !void {
    try config.validate();
    const contents = try std.json.Stringify.valueAlloc(gpa, config, .{});
    defer gpa.free(contents);
    if (contents.len > max_config_bytes) return error.ConfigTooLarge;

    const temp_path = try std.fmt.allocPrint(gpa, "{s}.{d}.new", .{ path, std.posix.system.getpid() });
    defer gpa.free(temp_path);
    var file = try std.Io.Dir.createFileAbsolute(io, temp_path, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    errdefer std.Io.Dir.deleteFileAbsolute(io, temp_path) catch {};
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    try file.writeStreamingAll(io, contents);
    try file.sync(io);
    try std.Io.Dir.renameAbsolute(temp_path, path, io);
}

test "OIDC configuration persists only in private daemon state" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buffer);
    const path = try std.fs.path.join(gpa, &.{ dir_buffer[0..dir_len], "oidc.json" });
    defer gpa.free(path);

    const config: Config = .{
        .provider = .authentik,
        .issuer = "https://auth.example",
        .discovery_url = "https://auth.example/application/o/chock/.well-known/openid-configuration",
        .client_id = "chock-client",
        .client_secret = "daemon-only-secret",
        .admin_subject = "initial-admin-subject",
    };
    try save(gpa, std.testing.io, path, config);
    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, path, .{});
    try std.testing.expectEqual(@as(u64, 0o600), stat.permissions.toMode() & 0o777);

    const loaded = try load(gpa, std.testing.io, path);
    defer {
        gpa.free(loaded.issuer);
        if (loaded.discovery_url) |url| gpa.free(url);
        gpa.free(loaded.client_id);
        if (loaded.client_secret) |secret| gpa.free(secret);
        gpa.free(loaded.admin_subject);
    }
    try std.testing.expectEqual(config.provider, loaded.provider);
    try std.testing.expectEqualStrings(config.issuer, loaded.issuer);
    try std.testing.expectEqualStrings(config.discovery_url.?, loaded.discovery_url.?);
    try std.testing.expectEqualStrings(config.client_id, loaded.client_id);
    try std.testing.expectEqualStrings(config.client_secret.?, loaded.client_secret.?);
    try std.testing.expectEqualStrings(config.admin_subject, loaded.admin_subject);
}

test "OIDC configuration refuses group/world-readable files" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(std.testing.io, &dir_buffer);
    const path = try std.fs.path.join(gpa, &.{ dir_buffer[0..dir_len], "oidc.json" });
    defer gpa.free(path);

    const config: Config = .{
        .provider = .kanidm,
        .issuer = "https://id.example",
        .client_id = "chock-client",
        .admin_subject = "admin-subject",
    };
    try save(gpa, std.testing.io, path, config);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, path, .{});
    defer file.close(std.testing.io);
    try file.setPermissions(std.testing.io, .fromMode(0o640));
    try std.testing.expectError(error.InvalidPermissions, load(gpa, std.testing.io, path));
}
