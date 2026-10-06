//! Every host a build would reach while it runs, named before it runs.

const std = @import("std");

const provision = @import("provision.zig");

pub const Error = provision.Error;

pub const Fetch = struct {
    subject: []const u8,
    url: []const u8,
    host: []const u8,
    port: u16,
};

pub const Unreadable = struct {
    subject: []const u8,
    url: []const u8,
    why: Why,

    site: []const u8 = "",

    pub const Why = enum {
        scheme_unknown,
        no_host,
        port_not_a_port,
        no_mirrors_file,
        mirrors_unreadable,
        mirrors_not_produced,
        mirrors_needs_a_builder,
        mirror_site_unknown,
        mirror_not_nameable,
        mirror_every_host_denied,
    };
};

pub const Mirror = struct {
    base: []const u8,
    url: []const u8,
    target: ?Target,
};

pub const MirrorSite = struct {
    subject: []const u8,
    url: []const u8,
    site: []const u8,
    mirrors: []const Mirror,

    pub fn hash(self: MirrorSite) [mirror_hash_bytes]u8 {
        return mirrorSetHash(self.mirrors);
    }
};

pub const mirror_hash_bytes = 64;

pub fn mirrorSetHash(mirrors: []const Mirror) [mirror_hash_bytes]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (mirrors) |one| {
        hasher.update(one.base);
        hasher.update("\n");
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

pub const Reached = struct {
    hosts: []const Fetch = &.{},
    sites: []const MirrorSite = &.{},
    hashed: []const Mirror = &.{},
    opaque_subjects: []const []const u8 = &.{},
    reads_mirrors: bool = false,
};

pub const Closure = union(enum) {
    reached: Reached,
    unreadable: Unreadable,
    nix_said: []const u8,
};

pub const hashed_mirrors_off = " ";

pub const hashed_mirrors_site = "hashedMirrors";

pub const max_mirrors_bytes: usize = 256 * 1024;

pub const UrlError = error{
    UrlSchemeUnknown,
    UrlHasNoHost,
    UrlPortNotAPort,
};

pub const Target = struct {
    host: []const u8,
    port: u16,
};

pub const schemes = [_]struct { name: []const u8, port: u16 }{
    .{ .name = "https", .port = 443 },
    .{ .name = "http", .port = 80 },
    .{ .name = "ftp", .port = 21 },
    .{ .name = "git", .port = 9418 },
    .{ .name = "ssh", .port = 22 },
};

pub fn portOf(scheme: []const u8) ?u16 {
    for (schemes) |one| {
        if (std.ascii.eqlIgnoreCase(scheme, one.name)) return one.port;
    }
    return null;
}

pub fn withoutTransport(url: []const u8) []const u8 {
    const mark = std.mem.indexOf(u8, url, "://") orelse return url;
    const plus = std.mem.lastIndexOfScalar(u8, url[0..mark], '+') orelse return url;
    return url[plus + 1 ..];
}

pub fn targetOf(given: []const u8) UrlError!Target {
    const url = withoutTransport(given);
    const mark = std.mem.indexOf(u8, url, "://") orelse return error.UrlSchemeUnknown;
    const default_port = portOf(url[0..mark]) orelse return error.UrlSchemeUnknown;

    const rest = url[mark + 3 ..];
    const authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
    // A user name and a password belong to nobody's policy key.
    const after_user = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at|
        authority[at + 1 ..]
    else
        authority;
    if (after_user.len == 0) return error.UrlHasNoHost;
    // An address in brackets is the one host shape whose colons are not a port boundary, so it is refused rather than parsed: the action namer takes only letters, digits, hyphen and dot.
    if (after_user[0] == '[') return error.UrlHasNoHost;

    if (std.mem.lastIndexOfScalar(u8, after_user, ':')) |colon| {
        const host = after_user[0..colon];
        if (host.len == 0) return error.UrlHasNoHost;
        const port = std.fmt.parseInt(u16, after_user[colon + 1 ..], 10) catch
            return error.UrlPortNotAPort;
        if (port == 0) return error.UrlPortNotAPort;
        return .{ .host = host, .port = port };
    }
    return .{ .host = after_user, .port = default_port };
}

pub fn mirrorOf(url: []const u8) ?struct { site: []const u8, path: []const u8 } {
    const prefix = "mirror://";
    if (!std.mem.startsWith(u8, url, prefix)) return null;
    const rest = url[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const site = rest[0..slash];
    const path = rest[slash + 1 ..];
    if (site.len == 0 or path.len == 0) return null;
    if (!isSiteName(site)) return null;
    return .{ .site = site, .path = path };
}

fn isSiteName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| {
        if (!std.ascii.isAlphanumeric(character)) return false;
    }
    return true;
}

const SiteMap = std.StringHashMapUnmanaged([]const []const u8);

fn parseMirrors(
    allocator: std.mem.Allocator,
    text: []const u8,
) std.mem.Allocator.Error!SiteMap {
    const declared_prefix = "declare -a _mirror_";
    var sites: SiteMap = .empty;
    errdefer sites.deinit(allocator);

    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t");
        const declared = std.mem.startsWith(u8, line, declared_prefix);
        const body = if (declared) line[declared_prefix.len..] else line;

        const equals = std.mem.indexOfScalar(u8, body, '=') orelse continue;
        const site = body[0..equals];
        if (!isSiteName(site)) continue;

        var value = body[equals + 1 ..];
        if (declared) {
            if (value.len < 2 or value[0] != '(' or value[value.len - 1] != ')') continue;
            value = value[1 .. value.len - 1];
        } else {
            value = std.mem.trim(u8, value, "'\"");
        }

        var found: std.ArrayList([]const u8) = .empty;
        errdefer found.deinit(allocator);
        var each = std.mem.tokenizeAny(u8, value, " \t");
        while (each.next()) |one| try found.append(allocator, one);
        if (found.items.len == 0) continue;
        try sites.put(allocator, site, try found.toOwnedSlice(allocator));
    }
    return sites;
}

const MirrorFiles = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    store_dir: []const u8,
    producers: std.StringHashMapUnmanaged([]const u8) = .empty,
    read: std.StringHashMapUnmanaged(SiteMap) = .empty,

    const ReadError = Error || error{
        MirrorsUnreadable,
        MirrorsNotProduced,
        MirrorsNeedsABuilder,
    };

    fn sitesOf(self: *MirrorFiles, path: []const u8) ReadError!SiteMap {
        if (self.read.get(path)) |already| return already;

        const text = self.readFile(path) orelse text: {
            try self.realise(path);
            break :text self.readFile(path) orelse return error.MirrorsUnreadable;
        };

        const sites = try parseMirrors(self.allocator, text);
        try self.read.put(self.allocator, path, sites);
        return sites;
    }

    fn readFile(self: *MirrorFiles, path: []const u8) ?[]const u8 {
        return std.Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(max_mirrors_bytes),
        ) catch null;
    }

    fn realise(self: *MirrorFiles, path: []const u8) ReadError!void {
        const drv = self.producers.get(path) orelse return error.MirrorsNotProduced;
        const outputs = try std.fmt.allocPrint(self.allocator, "{s}^*", .{drv});
        const built = try self.runner.run(self.allocator, self.io, &.{
            "build",
            "--no-link",
            "--max-jobs",
            "0",
            "--builders",
            "",
            outputs,
        });
        if (!built.succeeded()) return error.MirrorsNeedsABuilder;
    }

    fn learn(
        self: *MirrorFiles,
        drv_name: []const u8,
        one: std.json.ObjectMap,
    ) std.mem.Allocator.Error!void {
        const outputs = one.get("outputs") orelse return;
        if (outputs != .object) return;
        const drv = try self.absolute(drv_name);

        var each = outputs.object.iterator();
        while (each.next()) |entry| {
            const name = entry.key_ptr.*;
            if (entry.value_ptr.* == .object) {
                if (entry.value_ptr.object.get("path")) |where| {
                    if (where == .string) {
                        try self.producers.put(
                            self.allocator,
                            try self.absolute(where.string),
                            drv,
                        );
                    }
                }
            }
            const env = one.get("env") orelse continue;
            if (env != .object) continue;
            const named = env.object.get(name) orelse continue;
            if (named != .string) continue;
            try self.producers.put(self.allocator, try self.absolute(named.string), drv);
        }
    }

    fn absolute(self: *MirrorFiles, one: []const u8) std.mem.Allocator.Error![]const u8 {
        if (std.fs.path.isAbsolute(one)) return one;
        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store_dir, one });
    }
};

fn whyOfMirrors(err: MirrorFiles.ReadError) Unreadable.Why {
    return switch (err) {
        error.MirrorsNotProduced => .mirrors_not_produced,
        error.MirrorsNeedsABuilder => .mirrors_needs_a_builder,
        else => .mirrors_unreadable,
    };
}

fn mirrorsFileOf(one: std.json.ObjectMap) ?[]const u8 {
    const names = [_][]const u8{ "mirrorsListFile", "mirrorsFile" };
    if (one.get("structuredAttrs")) |attrs| {
        if (attrs == .object) {
            for (names) |name| {
                const value = attrs.object.get(name) orelse continue;
                if (value == .string and value.string.len != 0) return value.string;
            }
        }
    }
    const env = one.get("env") orelse return null;
    if (env != .object) return null;
    for (names) |name| {
        const value = env.object.get(name) orelse continue;
        if (value == .string and value.string.len != 0) return value.string;
    }
    return null;
}

fn mirrorsFor(
    allocator: std.mem.Allocator,
    sites: SiteMap,
    site: []const u8,
    path: []const u8,
) std.mem.Allocator.Error!?[]const Mirror {
    const bases = sites.get(site) orelse return null;
    const found = try allocator.alloc(Mirror, bases.len);
    for (bases, found) |base, *slot| slot.* = .{
        .base = base,
        .url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ base, path }),
        .target = targetOf(base) catch null,
    };
    return found;
}

pub fn fetchesOf(
    allocator: std.mem.Allocator,
    io: std.Io,
    runner: provision.Runner,
    derivation_path: []const u8,
) Error!Closure {
    const shown = try runner.run(allocator, io, &.{
        "derivation",
        "show",
        "-r",
        "--",
        derivation_path,
    });
    if (!shown.succeeded()) return .{ .nix_said = provision.lastLine(shown.stderr) };

    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        shown.stdout,
        .{},
    ) catch return .{ .nix_said = "the derivation closure could not be read as JSON" };
    defer parsed.deinit();

    const listed = derivationsOf(parsed.value) orelse
        return .{ .nix_said = "the derivation closure holds no derivations" };

    var reached: Reached = .{};
    var fetches: std.ArrayList(Fetch) = .empty;
    var sites: std.ArrayList(MirrorSite) = .empty;
    var opaque_subjects: std.ArrayList([]const u8) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    var asked_sites: std.StringHashMapUnmanaged(void) = .empty;
    defer asked_sites.deinit(allocator);

    var files: MirrorFiles = .{
        .allocator = allocator,
        .io = io,
        .runner = runner,
        .store_dir = std.fs.path.dirname(derivation_path) orelse "/nix/store",
    };

    var producing = listed.iterator();
    while (producing.next()) |entry| {
        if (entry.value_ptr.* != .object) continue;
        try files.learn(entry.key_ptr.*, entry.value_ptr.object);
    }

    var each = listed.iterator();
    while (each.next()) |entry| {
        const one = entry.value_ptr.*;
        if (one != .object) continue;
        if (!isFixedOutput(one.object)) continue;

        const name = try allocator.dupe(u8, entry.key_ptr.*);

        const urls = try urlsOf(allocator, one.object) orelse {
            try opaque_subjects.append(allocator, name);
            continue;
        };

        // Read before the URLs and not because of one: the builder tries a hashed mirror whether or not any URL names a mirror site.
        const mirrors_path = mirrorsFileOf(one.object);
        if (mirrors_path) |path| {
            reached.reads_mirrors = true;
            const known = files.sitesOf(path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.RunnerFailed => return error.RunnerFailed,
                else => return .{ .unreadable = .{
                    .subject = name,
                    .url = try allocator.dupe(u8, path),
                    .why = whyOfMirrors(err),
                } },
            };
            if (reached.hashed.len == 0) {
                if (try mirrorsFor(allocator, known, hashed_mirrors_site, "")) |found| {
                    reached.hashed = found;
                }
            }
        }

        for (urls) |url| {
            if (mirrorOf(url)) |named| {
                const path = mirrors_path orelse return .{ .unreadable = .{
                    .subject = name,
                    .url = try allocator.dupe(u8, url),
                    .site = try allocator.dupe(u8, named.site),
                    .why = .no_mirrors_file,
                } };
                const known = files.sitesOf(path) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.RunnerFailed => return error.RunnerFailed,
                    else => return .{ .unreadable = .{
                        .subject = name,
                        .url = try allocator.dupe(u8, path),
                        .site = try allocator.dupe(u8, named.site),
                        .why = whyOfMirrors(err),
                    } },
                };

                const mirrors = try mirrorsFor(allocator, known, named.site, named.path) orelse
                    return .{ .unreadable = .{
                        .subject = name,
                        .url = try allocator.dupe(u8, url),
                        .site = try allocator.dupe(u8, named.site),
                        .why = .mirror_site_unknown,
                    } };

                if ((try asked_sites.getOrPut(allocator, named.site)).found_existing) continue;
                try sites.append(allocator, .{
                    .subject = name,
                    .url = try allocator.dupe(u8, url),
                    .site = try allocator.dupe(u8, named.site),
                    .mirrors = mirrors,
                });
                continue;
            }

            const target = targetOf(url) catch |err| return .{ .unreadable = .{
                .subject = name,
                .url = try allocator.dupe(u8, url),
                .why = switch (err) {
                    error.UrlSchemeUnknown => .scheme_unknown,
                    error.UrlHasNoHost => .no_host,
                    error.UrlPortNotAPort => .port_not_a_port,
                },
            } };

            const key = try std.fmt.allocPrint(
                allocator,
                "{s}:{d}",
                .{ target.host, target.port },
            );
            if ((try seen.getOrPut(allocator, key)).found_existing) continue;
            try fetches.append(allocator, .{
                .subject = name,
                .url = try allocator.dupe(u8, url),
                .host = try allocator.dupe(u8, target.host),
                .port = target.port,
            });
        }
    }

    reached.hosts = try fetches.toOwnedSlice(allocator);
    reached.sites = try sites.toOwnedSlice(allocator);
    reached.opaque_subjects = try opaque_subjects.toOwnedSlice(allocator);
    return .{ .reached = reached };
}

fn derivationsOf(root: std.json.Value) ?std.json.ObjectMap {
    if (root != .object) return null;
    if (root.object.get("derivations")) |wrapped| {
        if (wrapped != .object) return null;
        return wrapped.object;
    }
    return root.object;
}

fn isFixedOutput(one: std.json.ObjectMap) bool {
    const outputs = one.get("outputs") orelse return false;
    if (outputs != .object) return false;
    var each = outputs.object.iterator();
    while (each.next()) |entry| {
        const output = entry.value_ptr.*;
        if (output != .object) continue;
        if (output.object.contains("hash")) return true;
        if (output.object.contains("hashAlgo")) return true;
    }
    return false;
}

fn urlsOf(
    allocator: std.mem.Allocator,
    one: std.json.ObjectMap,
) std.mem.Allocator.Error!?[]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    errdefer found.deinit(allocator);

    if (one.get("structuredAttrs")) |attrs| {
        if (attrs == .object) {
            for ([_][]const u8{ "url", "urls" }) |name| {
                const value = attrs.object.get(name) orelse continue;
                switch (value) {
                    .string => |text| try found.append(allocator, text),
                    .array => |items| for (items.items) |item| {
                        if (item == .string) try found.append(allocator, item.string);
                    },
                    else => continue,
                }
                if (found.items.len != 0) return try found.toOwnedSlice(allocator);
            }
        }
    }

    const env = one.get("env") orelse return null;
    if (env != .object) return null;
    for ([_][]const u8{ "url", "urls" }) |name| {
        const value = env.object.get(name) orelse continue;
        if (value != .string) continue;
        var each = std.mem.tokenizeAny(u8, value.string, " \t\n");
        while (each.next()) |url| try found.append(allocator, url);
        if (found.items.len != 0) return try found.toOwnedSlice(allocator);
    }

    found.deinit(allocator);
    return null;
}

pub fn unreadableRefusal(
    allocator: std.mem.Allocator,
    one: Unreadable,
) std.mem.Allocator.Error![]u8 {
    return switch (one.why) {
        .scheme_unknown => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and that is not a scheme this reads. Only http and https can be " ++
                "named as a host and a port, so nothing was built. Use an input that fetches " ++
                "over https.",
            .{ one.subject, one.url },
        ),
        .no_host => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, which names no host this can put to a rule, so nothing was built.",
            .{ one.subject, one.url },
        ),
        .port_not_a_port => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, whose port is not a port, so nothing was built.",
            .{ one.subject, one.url },
        ),
        .no_mirrors_file => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s} and names no mirrors file, so where the site {s} is cannot be " ++
                "read and nothing was built.",
            .{ one.subject, one.url, one.site },
        ),
        .mirrors_unreadable => std.fmt.allocPrint(
            allocator,
            "{s} names the mirrors file {s}, which could not be read, so no host of it could " ++
                "be put to a rule and nothing was built.",
            .{ one.subject, one.url },
        ),
        .mirrors_not_produced => std.fmt.allocPrint(
            allocator,
            "{s} names the mirrors file {s}, which nothing of its own closure makes, so there " ++
                "is nothing this may realise to read it and nothing was built.",
            .{ one.subject, one.url },
        ),
        .mirrors_needs_a_builder => std.fmt.allocPrint(
            allocator,
            "{s} names the mirrors file {s}, which is not in the store and which no substituter " ++
                "has. Reading it would have run a builder before any rule answered, which this " ++
                "will not do, so nothing was built.",
            .{ one.subject, one.url },
        ),
        .mirror_site_unknown => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and its mirrors file names no site {s}, so nothing was built. " ++
                "Use an input that fetches over https.",
            .{ one.subject, one.url, one.site },
        ),
        .mirror_not_nameable => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and no mirror of the site {s} has a host a rule can be written " ++
                "for, so nothing was built.",
            .{ one.subject, one.url, one.site },
        ),
        .mirror_every_host_denied => std.fmt.allocPrint(
            allocator,
            "{s} fetches {s}, and this project denies every mirror of the site {s}, so nothing " ++
                "was built.",
            .{ one.subject, one.url, one.site },
        ),
    };
}

pub fn opaqueRefusal(
    allocator: std.mem.Allocator,
    subjects: []const []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(subjects.len != 0);
    if (subjects.len == 1) return std.fmt.allocPrint(
        allocator,
        "{s} fetches while it builds and says nowhere it fetches from, so no host of it can " ++
            "be put to a rule. {s}",
        .{ subjects[0], said },
    );
    return std.fmt.allocPrint(
        allocator,
        "{d} derivations of this build fetch while they build and say nowhere they fetch " ++
            "from, {s} among them, so no host of them can be put to a rule. {s}",
        .{ subjects.len, subjects[0], said },
    );
}

pub fn mirrorRefusal(
    allocator: std.mem.Allocator,
    one: MirrorSite,
    host: []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s} fetches {s}, and the site {s} was asked about as {s}. {s}",
        .{ one.subject, one.url, one.site, host, said },
    );
}

pub fn closureRefusal(
    allocator: std.mem.Allocator,
    derivation_path: []const u8,
    said: []const u8,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "what {s} would fetch could not be read, so nothing was built. Nix said: {s}",
        .{ derivation_path, said },
    );
}

pub const Verdict = union(enum) {
    permitted,
    refused: []const u8,
};

pub const RuleAnswer = enum {
    allow,
    deny,
    unsettled,
};

pub const Gate = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        permit_all: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            wanted: []const Fetch,
        ) std.mem.Allocator.Error!Verdict,
        permit_opaque: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            subjects: []const []const u8,
        ) std.mem.Allocator.Error!Verdict,
        rule_for: *const fn (ptr: *anyopaque, one: Fetch) RuleAnswer,
        permit_site: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            site: MirrorSite,
            chosen: Fetch,
        ) std.mem.Allocator.Error!Verdict,
    };

    pub fn permitAll(
        self: Gate,
        allocator: std.mem.Allocator,
        wanted: []const Fetch,
    ) std.mem.Allocator.Error!Verdict {
        if (wanted.len == 0) return .permitted;
        return self.vtable.permit_all(self.ptr, allocator, wanted);
    }

    pub fn permitOpaque(
        self: Gate,
        allocator: std.mem.Allocator,
        subjects: []const []const u8,
    ) std.mem.Allocator.Error!Verdict {
        return self.vtable.permit_opaque(self.ptr, allocator, subjects);
    }

    pub fn ruleFor(self: Gate, one: Fetch) RuleAnswer {
        return self.vtable.rule_for(self.ptr, one);
    }

    pub fn allowsByRule(self: Gate, one: Fetch) bool {
        return self.ruleFor(one) == .allow;
    }

    pub fn permitSite(
        self: Gate,
        allocator: std.mem.Allocator,
        site: MirrorSite,
        chosen: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return self.vtable.permit_site(self.ptr, allocator, site, chosen);
    }

    pub const refusing: Gate = .{ .ptr = undefined, .vtable = &refusing_vtable };

    const refusing_vtable: VTable = .{
        .permit_all = refuseFn,
        .permit_opaque = refuseOpaqueFn,
        .rule_for = settlesNothing,
        .permit_site = refuseSiteFn,
    };

    fn refuseFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return .{ .refused = "this session can ask nobody about a host" };
    }

    fn refuseOpaqueFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: []const []const u8,
    ) std.mem.Allocator.Error!Verdict {
        return .{ .refused = "this session can ask nobody about a fetch" };
    }

    fn refuseSiteFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: MirrorSite,
        _: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return .{ .refused = "this session can ask nobody about a mirror set" };
    }

    fn settlesNothing(_: *anyopaque, _: Fetch) RuleAnswer {
        return .unsettled;
    }
};

const testing = std.testing;

test "a url becomes a host and a port, and a scheme this does not know is refused" {
    const secure = try targetOf("https://example.com/a/b.tar.gz");
    try testing.expectEqualStrings("example.com", secure.host);
    try testing.expectEqual(@as(u16, 443), secure.port);

    const plain = try targetOf("http://example.com/a");
    try testing.expectEqualStrings("example.com", plain.host);
    try testing.expectEqual(@as(u16, 80), plain.port);

    const named = try targetOf("https://example.com:8443/a?q=1#f");
    try testing.expectEqualStrings("example.com", named.host);
    try testing.expectEqual(@as(u16, 8443), named.port);

    const with_user = try targetOf("https://someone:secret@example.com/a");
    try testing.expectEqualStrings("example.com", with_user.host);

    const plain_ftp = try targetOf("ftp://ftp.gmplib.org/pub/gmp-6.3.0/gmp-6.3.0.tar.bz2");
    try testing.expectEqualStrings("ftp.gmplib.org", plain_ftp.host);
    try testing.expectEqual(@as(u16, 21), plain_ftp.port);

    const git_daemon = try targetOf("git://sourceware.org/git/systemtap.git");
    try testing.expectEqualStrings("sourceware.org", git_daemon.host);
    try testing.expectEqual(@as(u16, 9418), git_daemon.port);

    const secure_shell = try targetOf("ssh://git@example.com/a.git");
    try testing.expectEqualStrings("example.com", secure_shell.host);
    try testing.expectEqual(@as(u16, 22), secure_shell.port);

    const over_https = try targetOf("git+https://git.example.com/a/b.git");
    try testing.expectEqualStrings("git.example.com", over_https.host);
    try testing.expectEqual(@as(u16, 443), over_https.port);

    const over_ssh = try targetOf("git+ssh://git@example.com/a.git");
    try testing.expectEqualStrings("example.com", over_ssh.host);
    try testing.expectEqual(@as(u16, 22), over_ssh.port);

    const over_http = try targetOf("git+http://git.example.com/a.git");
    try testing.expectEqual(@as(u16, 80), over_http.port);

    try testing.expectError(error.UrlSchemeUnknown, targetOf("sftp://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("s3://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("mirror://gnu/a.tar.gz"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("example.com/a"));

    try testing.expectError(error.UrlHasNoHost, targetOf("https:///a/b"));
    try testing.expectError(error.UrlHasNoHost, targetOf("https://[2001:db8::1]/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:http/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:0/a"));
}

const FakeRunner = struct {
    gpa: std.mem.Allocator,
    code: u8 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    build_code: u8 = 0,
    realises: ?struct { path: []const u8, data: []const u8 } = null,
    seen: std.ArrayList([]const []const u8) = .empty,

    fn deinit(self: *FakeRunner) void {
        for (self.seen.items) |args| {
            for (args) |one| self.gpa.free(one);
            self.gpa.free(args);
        }
        self.seen.deinit(self.gpa);
    }

    fn callsOf(self: *const FakeRunner, command: []const u8) usize {
        var count: usize = 0;
        for (self.seen.items) |args| {
            if (args.len != 0 and std.mem.eql(u8, args[0], command)) count += 1;
        }
        return count;
    }

    fn lastCarried(self: *const FakeRunner, flag: []const u8) bool {
        const args = self.seen.items[self.seen.items.len - 1];
        for (args) |one| {
            if (std.mem.eql(u8, one, flag)) return true;
        }
        return false;
    }

    fn runner(self: *FakeRunner) provision.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = provision.Runner.VTable{ .run = runFn };

    fn runFn(
        ptr: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        args: []const []const u8,
        _: []const provision.Variable,
    ) provision.Error!@import("proc.zig").Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.alloc([]const u8, args.len);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        try self.seen.append(self.gpa, copy);

        const building = args.len != 0 and std.mem.eql(u8, args[0], "build");
        if (building) {
            if (self.build_code == 0) {
                if (self.realises) |one| std.Io.Dir.cwd().writeFile(io, .{
                    .sub_path = one.path,
                    .data = one.data,
                }) catch {};
            }
            return .{
                .term = .{ .exited = self.build_code },
                .stdout = try allocator.dupe(u8, ""),
                .stderr = try allocator.dupe(u8, "error: Cannot build it. Reason: local builds are disabled"),
            };
        }

        return .{
            .term = .{ .exited = self.code },
            .stdout = try allocator.dupe(u8, self.stdout),
            .stderr = try allocator.dupe(u8, self.stderr),
        };
    }
};

const closure_with_one_fetch =
    \\{"version":4,"derivations":{
    \\ "a-top.drv":{"env":{"name":"top"},"outputs":{"out":{"path":"/nix/store/x-top"}}},
    \\ "b-src.drv":{"env":{"name":"src","url":"https://files.example.com/src.tar.gz"},
    \\  "outputs":{"out":{"hash":"sha256-AAAA","method":"flat"}}}
    \\}}
;

test "a closure that holds a fixed output derivation answers its host and its port" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{ .gpa = gpa, .stdout = closure_with_one_fetch };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-top.drv",
    );

    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 1), closure.reached.hosts.len);
    try testing.expectEqualStrings("files.example.com", closure.reached.hosts[0].host);
    try testing.expectEqual(@as(u16, 443), closure.reached.hosts[0].port);
    try testing.expectEqualStrings("b-src.drv", closure.reached.hosts[0].subject);

    try testing.expectEqualStrings("derivation", fake.seen.items[0][0]);
    try testing.expectEqualStrings("show", fake.seen.items[0][1]);
    try testing.expectEqualStrings("-r", fake.seen.items[0][2]);
    try testing.expectEqualStrings("/nix/store/a-top.drv", fake.seen.items[0][4]);
}

test "a closure with no fixed output derivation reaches no host at all" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"a-top.drv":{"env":{"name":"top"},"outputs":{"out":{"path":"/nix/store/x-top"}}},
        \\ "b-dep.drv":{"env":{"name":"dep"},"outputs":{"out":{"path":"/nix/store/y-dep"}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-top.drv",
    );

    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 0), closure.reached.hosts.len);
}

test "one host is answered once, however many derivations of the closure fetch it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{
        \\ "a.drv":{"env":{"url":"https://files.example.com/one.tar.gz"},
        \\  "outputs":{"out":{"hash":"sha256-A"}}},
        \\ "b.drv":{"env":{"url":"https://files.example.com/two.tar.gz"},
        \\  "outputs":{"out":{"hash":"sha256-B"}}},
        \\ "c.drv":{"env":{"urls":"https://other.example.org/three https://files.example.com/four"},
        \\  "outputs":{"out":{"hashAlgo":"sha256"}}}
        \\}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a.drv",
    );

    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 2), closure.reached.hosts.len);
    try testing.expectEqualStrings("files.example.com", closure.reached.hosts[0].host);
    try testing.expectEqualStrings("other.example.org", closure.reached.hosts[1].host);
}

test "a fetch this cannot name is a refusal, and it names the derivation and the url" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var unknown = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a.drv":{"env":{"url":"s3://files.example.com/one.tar.gz"},
        \\ "outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer unknown.deinit();

    const bad_scheme = try fetchesOf(arena, testing.io, unknown.runner(), "/nix/store/a.drv");
    try testing.expect(bad_scheme == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, bad_scheme.unreadable.why);

    const said = try unreadableRefusal(gpa, bad_scheme.unreadable);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "a.drv") != null);
    try testing.expect(std.mem.indexOf(u8, said, "s3://files.example.com") != null);

    var hostless = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"b.drv":{"env":{"url":"https:///one.tar.gz"},
        \\ "outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer hostless.deinit();

    const no_host = try fetchesOf(arena, testing.io, hostless.runner(), "/nix/store/b.drv");
    try testing.expect(no_host == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_host, no_host.unreadable.why);
}

test "a fixed output derivation that says nowhere it fetches from is named, not refused" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{
        \\ "c-zig-deps.drv":{"env":{"name":"c"},"outputs":{"out":{"hash":"sha256-A"}}},
        \\ "d-npm-deps.drv":{"env":{"name":"d"},"outputs":{"out":{"hash":"sha256-B"}}},
        \\ "e-src.drv":{"env":{"url":"https://files.example.com/a.tar.gz"},
        \\  "outputs":{"out":{"hash":"sha256-C"}}}
        \\}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/c.drv");
    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 2), closure.reached.opaque_subjects.len);

    try testing.expectEqual(@as(usize, 1), closure.reached.hosts.len);
    try testing.expectEqualStrings("files.example.com", closure.reached.hosts[0].host);

    const said = try opaqueRefusal(gpa, closure.reached.opaque_subjects, "nothing ran.");
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "deps.drv") != null);
    try testing.expect(std.mem.indexOf(u8, said, "2 derivations") != null);

    const one = try opaqueRefusal(gpa, &.{"c-zig-deps.drv"}, "nothing ran.");
    defer gpa.free(one);
    try testing.expect(std.mem.indexOf(u8, one, "c-zig-deps.drv") != null);
    try testing.expect(std.mem.indexOf(u8, one, "derivations of this build") == null);
}

test "a nix that would not read the closure answers its own last line" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .code = 1,
        .stderr = "error: path '/nix/store/a.drv' is not valid",
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a.drv",
    );
    try testing.expect(closure == .nix_said);
    try testing.expect(std.mem.indexOf(u8, closure.nix_said, "is not valid") != null);
}

test "the gate a caller wired none of permits nothing" {
    const answer = try Gate.refusing.permitAll(testing.allocator, &.{.{
        .subject = "a.drv",
        .url = "https://example.com/a",
        .host = "example.com",
        .port = 443,
    }});
    try testing.expect(answer == .refused);
}

test "a derivation with structured attributes holds its urls there, and they are read" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a-src.drv":{
        \\ "env":{"out":"/nix/store/x-src"},
        \\ "outputs":{"out":{"hash":"sha256-A","method":"flat"}},
        \\ "structuredAttrs":{"urls":["https://files.example.com/a.tar.gz",
        \\  "https://backup.example.org/a.tar.gz"],"postFetch":""}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(
        arena_state.allocator(),
        testing.io,
        fake.runner(),
        "/nix/store/a-src.drv",
    );

    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 2), closure.reached.hosts.len);
    try testing.expectEqualStrings("files.example.com", closure.reached.hosts[0].host);
    try testing.expectEqualStrings("backup.example.org", closure.reached.hosts[1].host);
}

pub const nixpkgs_mirrors_sample =
    \\declare -a _mirror_gnu=(https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/ https://mirrors.kernel.org/gnu/ https://mirror.ibcp.fr/pub/gnu/ https://mirror.dogado.de/gnu/ https://mirror.tochlab.net/pub/gnu/ https://ftp.gnu.org/pub/gnu/ ftp://ftp.funet.fi/pub/mirrors/ftp.gnu.org/gnu/)
    \\declare -a _mirror_hackage=(https://hackage.haskell.org/package/)
    \\declare -a _mirror_hashedMirrors=(https://tarballs.nixos.org)
    \\
;

fn mirrorsListPath(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/mirrors-list", .{buffer[0..len]});
}

fn writeMirrorsList(allocator: std.mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "mirrors-list",
        .data = nixpkgs_mirrors_sample,
    });
    return mirrorsListPath(allocator, tmp);
}

fn closureFetching(
    allocator: std.mem.Allocator,
    url: []const u8,
    mirrors_path: ?[]const u8,
    produced: bool,
) ![]u8 {
    const maker = if (produced and mirrors_path != null) try std.fmt.allocPrint(
        allocator,
        \\,"/nix/store/m-mirrors-list.drv":{{"env":{{"out":"{s}"}},
        \\ "outputs":{{"out":{{"path":"{s}"}}}}}}
    ,
        .{ mirrors_path.?, mirrors_path.? },
    ) else "";

    return std.fmt.allocPrint(
        allocator,
        \\{{"derivations":{{"a-src.drv":{{"env":{{"out":"/nix/store/x-src"}},
        \\ "outputs":{{"out":{{"hash":"sha256-A","method":"flat"}}}},
        \\ "structuredAttrs":{{"urls":["{s}"]{s}{s}{s}}}}}{s}}}}}
    ,
        .{
            url,
            if (mirrors_path == null) "" else ",\"mirrorsFile\":\"",
            mirrors_path orelse "",
            if (mirrors_path == null) "" else "\"",
            maker,
        },
    );
}

test "a git daemon url is a host and a port like any other, and the action carries it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"a-systemtap.drv":
        \\ {"env":{"url":"git://sourceware.org/git/systemtap.git"},
        \\  "outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a.drv");
    try testing.expect(closure == .reached);
    try testing.expectEqualStrings("sourceware.org", closure.reached.hosts[0].host);
    try testing.expectEqual(@as(u16, 9418), closure.reached.hosts[0].port);
}

test "a mirror url expands to the mirrors the file names, in the file's own order" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try writeMirrorsList(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            mirrors_path,
            true,
        ),
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 0), closure.reached.hosts.len);
    try testing.expectEqual(@as(usize, 1), closure.reached.sites.len);

    const site = closure.reached.sites[0];
    try testing.expectEqualStrings("gnu", site.site);
    try testing.expectEqualStrings("a-src.drv", site.subject);
    try testing.expectEqual(@as(usize, 8), site.mirrors.len);

    try testing.expectEqualStrings("https://ftpmirror.gnu.org/", site.mirrors[0].base);
    try testing.expectEqualStrings(
        "https://ftpmirror.gnu.org/hello/hello-2.12.3.tar.gz",
        site.mirrors[0].url,
    );
    try testing.expectEqualStrings("ftpmirror.gnu.org", site.mirrors[0].target.?.host);
    try testing.expectEqualStrings("mirrors.kernel.org", site.mirrors[2].target.?.host);

    try testing.expectEqualStrings("ftp.funet.fi", site.mirrors[7].target.?.host);
    try testing.expectEqual(@as(u16, 21), site.mirrors[7].target.?.port);

    try testing.expect(closure.reached.reads_mirrors);
    try testing.expectEqual(@as(usize, 1), closure.reached.hashed.len);
    try testing.expectEqualStrings("tarballs.nixos.org", closure.reached.hashed[0].target.?.host);
}

test "a site the mirrors file does not name is a refusal, and so is a url with no file at all" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try writeMirrorsList(arena, &tmp);

    var unknown = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "mirror://sourceforge/a/b.tar.gz", mirrors_path, true),
    };
    defer unknown.deinit();

    const missing_site = try fetchesOf(arena, testing.io, unknown.runner(), "/nix/store/a-src.drv");
    try testing.expect(missing_site == .unreadable);
    try testing.expectEqual(Unreadable.Why.mirror_site_unknown, missing_site.unreadable.why);
    try testing.expectEqualStrings("sourceforge", missing_site.unreadable.site);

    const said = try unreadableRefusal(gpa, missing_site.unreadable);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "sourceforge") != null);

    var nameless = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "mirror://gnu/hello/hello-2.12.3.tar.gz", null, false),
    };
    defer nameless.deinit();

    const no_file = try fetchesOf(arena, testing.io, nameless.runner(), "/nix/store/a-src.drv");
    try testing.expect(no_file == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_mirrors_file, no_file.unreadable.why);

    var gone = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            "/nix/store/0000000000000000000000000000000a-mirrors-list",
            false,
        ),
    };
    defer gone.deinit();

    const not_produced = try fetchesOf(arena, testing.io, gone.runner(), "/nix/store/a-src.drv");
    try testing.expect(not_produced == .unreadable);
    try testing.expectEqual(Unreadable.Why.mirrors_not_produced, not_produced.unreadable.why);
    try testing.expectEqual(@as(usize, 0), gone.callsOf("build"));
}

test "a mirrors list already in the store is read, and nothing is realised for it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try writeMirrorsList(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            mirrors_path,
            true,
        ),
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .reached);
    try testing.expectEqual(@as(usize, 8), closure.reached.sites[0].mirrors.len);
    try testing.expectEqual(@as(usize, 1), fake.seen.items.len);
    try testing.expectEqual(@as(usize, 0), fake.callsOf("build"));
}

test "a mirrors list that is absent is realised without a builder, and then read" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try mirrorsListPath(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            mirrors_path,
            true,
        ),
        .realises = .{ .path = mirrors_path, .data = nixpkgs_mirrors_sample },
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .reached);
    try testing.expectEqualStrings("gnu", closure.reached.sites[0].site);
    try testing.expectEqualStrings(
        "https://ftpmirror.gnu.org/",
        closure.reached.sites[0].mirrors[0].base,
    );

    try testing.expectEqual(@as(usize, 1), fake.callsOf("build"));
    const built = fake.seen.items[1];
    try testing.expectEqualStrings("build", built[0]);
    try testing.expectEqualStrings("/nix/store/m-mirrors-list.drv^*", built[built.len - 1]);
    try testing.expect(fake.lastCarried("--max-jobs"));
    try testing.expect(fake.lastCarried("0"));
    try testing.expect(fake.lastCarried("--builders"));
}

test "a mirrors list that needs a builder is refused, and the words say so" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try mirrorsListPath(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            mirrors_path,
            true,
        ),
        .build_code = 1,
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .unreadable);
    try testing.expectEqual(Unreadable.Why.mirrors_needs_a_builder, closure.unreadable.why);

    const said = try unreadableRefusal(gpa, closure.unreadable);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "a-src.drv") != null);
    try testing.expect(std.mem.indexOf(u8, said, "builder") != null);
}

test "a scheme that is still unknown after a mirror is expanded stays a refusal" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try writeMirrorsList(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "s3://files.example.com/a.tar.gz", mirrors_path, true),
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, closure.unreadable.why);

    var siteless = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "mirror://gnu", mirrors_path, true),
    };
    defer siteless.deinit();

    const no_path = try fetchesOf(arena, testing.io, siteless.runner(), "/nix/store/a-src.drv");
    try testing.expect(no_path == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, no_path.unreadable.why);
}

fn mirrorsOf(
    allocator: std.mem.Allocator,
    text: []const u8,
    site: []const u8,
) ![]const Mirror {
    var sites = try parseMirrors(allocator, text);
    defer sites.deinit(allocator);
    return (try mirrorsFor(allocator, sites, site, "hello/hello-2.12.3.tar.gz")).?;
}

test "a mirror set hashes its own parsed list, so the file's shape and another site cannot move it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const declared = try mirrorsOf(arena, nixpkgs_mirrors_sample, "gnu");
    const hash = mirrorSetHash(declared);
    try testing.expectEqual(@as(usize, mirror_hash_bytes), hash.len);
    for (hash) |character| try testing.expect(std.ascii.isHex(character) and !std.ascii.isUpper(character));

    const older = try mirrorsOf(
        arena,
        \\gnu='https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/ https://mirrors.kernel.org/gnu/ https://mirror.ibcp.fr/pub/gnu/ https://mirror.dogado.de/gnu/ https://mirror.tochlab.net/pub/gnu/ https://ftp.gnu.org/pub/gnu/ ftp://ftp.funet.fi/pub/mirrors/ftp.gnu.org/gnu/'
        \\hackage=https://hackage.haskell.org/package/
        \\
    ,
        "gnu",
    );
    try testing.expectEqualStrings(&hash, &mirrorSetHash(older));

    const hackage_bumped = try mirrorsOf(
        arena,
        \\declare -a _mirror_gnu=(https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/ https://mirrors.kernel.org/gnu/ https://mirror.ibcp.fr/pub/gnu/ https://mirror.dogado.de/gnu/ https://mirror.tochlab.net/pub/gnu/ https://ftp.gnu.org/pub/gnu/ ftp://ftp.funet.fi/pub/mirrors/ftp.gnu.org/gnu/)
        \\declare -a _mirror_hackage=(https://hackage.haskell.org/package/ https://hackage.example.org/)
        \\declare -a _mirror_hashedMirrors=(https://tarballs.nixos.org)
        \\
    ,
        "gnu",
    );
    try testing.expectEqualStrings(&hash, &mirrorSetHash(hackage_bumped));

    const one_gone = try mirrorsOf(
        arena,
        \\declare -a _mirror_gnu=(https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/)
        \\
    ,
        "gnu",
    );
    try testing.expect(!std.mem.eql(u8, &hash, &mirrorSetHash(one_gone)));

    const reordered = try mirrorsOf(
        arena,
        \\declare -a _mirror_gnu=(https://ftp.nluug.nl/pub/gnu/ https://ftpmirror.gnu.org/)
        \\
    ,
        "gnu",
    );
    const same_two = try mirrorsOf(
        arena,
        \\declare -a _mirror_gnu=(https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/)
        \\
    ,
        "gnu",
    );
    try testing.expect(!std.mem.eql(u8, &mirrorSetHash(reordered), &mirrorSetHash(same_two)));
}

test "a mirrors file is read in both shapes nixpkgs has written, and nothing else" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var sites = try parseMirrors(arena, nixpkgs_mirrors_sample);
    defer sites.deinit(arena);
    try testing.expectEqual(@as(usize, 8), sites.get("gnu").?.len);
    try testing.expectEqualStrings("https://hackage.haskell.org/package/", sites.get("hackage").?[0]);
    try testing.expectEqualStrings("https://tarballs.nixos.org", sites.get("hashedMirrors").?[0]);

    var older = try parseMirrors(arena,
        \\hackage='https://hackage.haskell.org/package/ https://hackage.example.org/'
        \\hashedMirrors=https://tarballs.nixos.org
        \\
    );
    defer older.deinit(arena);
    try testing.expectEqual(@as(usize, 2), older.get("hackage").?.len);
    try testing.expectEqualStrings("https://tarballs.nixos.org", older.get("hashedMirrors").?[0]);

    var strange = try parseMirrors(arena, "_mirror_gnu: https://ftpmirror.gnu.org/\n");
    defer strange.deinit(arena);
    try testing.expectEqual(@as(u32, 0), strange.count());
}
