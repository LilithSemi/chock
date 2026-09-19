//! Every host a build would reach while it runs, named before it runs.
//!
//! ## Why a fixed output derivation is not safe by itself
//!
//! Nix gives a fixed output derivation's builder the network, because the
//! output hash is checked afterwards. That check is worth something for
//! integrity and nothing at all for egress: a URL of
//! `https://somewhere/?d=<a secret of the workspace>` with the hash of an
//! innocuous file passes the check, and the request already happened. So "it
//! is fixed output, therefore the network is safe" is wrong, and a build that
//! reached the network with no rule consulted was a hole.
//!
//! ## A fetch is a connection
//!
//! There is one egress namespace, `net.connect`, and this library does not
//! build its names: `lib/chock-broker/network.zig` holds the builder, because
//! it holds the label reversal that makes a class rule safe. This file reads
//! the closure and answers a host and a port. The caller names it and asks.
//!
//! A second namespace would need that reversal written and tested again, and
//! would let a project allow a host in one namespace while denying it in the
//! other.
//!
//! ## The closure is read with `nix derivation show`
//!
//! The derivation closure is already in the host store by the time a build is
//! asked for, so it can be read. `nix derivation show -r` answers the whole
//! closure as JSON, through the same `provision.Runner` seam every other
//! command of this library goes through, so a test reads the argument vector
//! and reaches no store.
//!
//! **The alternative was reading the `.drv` files.** fix models a derivation
//! and writes the ATerm form, and it parses none, so that route needs a
//! parser of its own for a format Nix already reads. A parser that disagreed
//! with Nix about one field would name the wrong host, which is the one
//! failure this file must not have.
//!
//! ## What it asks about, and what it over asks
//!
//! Every fixed output derivation of the closure, whether or not its output is
//! in the store already. A derivation whose output is there fetches nothing,
//! so a question about it is a question nobody had to answer. Asking is the
//! safe direction: the store can lose that output between the question and
//! the build, and a reader that skipped it would then have let a fetch
//! through.
//!
//! Hosts are answered once each. One closure can hold twenty derivations that
//! fetch from the same host, and twenty questions with one answer is a person
//! trained to say yes.
//!
//! **A fixed output derivation that says nowhere it fetches from is a
//! refusal.** Some fetchers read their URLs out of a lock file while they
//! build, so they hold no `url` anywhere. The network is open to them and no
//! rule can name what they reach, so they are refused rather than run.
//!
//! ## `mirror://` names a site, and the derivation says where the sites are
//!
//! nixpkgs writes `mirror://hackage/...`, which names a site and not a host.
//! The derivation also carries `mirrorsFile`, a store path of its own closure
//! that holds one shell array per site:
//!
//!     declare -a _mirror_hackage=(https://hackage.haskell.org/package/)
//!
//! So the candidates are read out of that file rather than guessed, and the
//! site becomes a host the policy can answer for. **A site the file does not
//! name, and a derivation with no mirrors file, stay refusals**: this reads
//! what is there and invents nothing.
//!
//! One site becomes one question. The candidates are taken in the file's own
//! order, a candidate the policy already allows by rule is taken with nobody
//! asked, and otherwise the first candidate that can be named is what a person
//! is asked about. Twenty questions with one answer is a person trained to say
//! yes.
//!
//! ## The answer is pinned into the builder's environment
//!
//! Every `NIX_MIRRORS_<site>` is in the derivation's own `impureEnvVars`, so a
//! value in the environment `nix` runs with reaches the builder, and the
//! builder then uses that one mirror instead of walking its own list. Without
//! the pin the answer would be advisory: the build would ask about one host
//! and reach another. `build.Host` sets it.
//!
//! **`NIX_HASHED_MIRRORS` is pinned as well, and it must never be left
//! empty.** The builder tries a hashed mirror for every fetch, before all the
//! URLs or after them, so it can reach a host that appears in no URL of the
//! derivation at all. Both builder shapes read the variable only when it is
//! not empty, so an empty value leaves the list the mirrors file itself names
//! in force. See `hashed_mirrors_off`.

const std = @import("std");

const provision = @import("provision.zig");

pub const Error = provision.Error;

/// One host a build would reach.
pub const Fetch = struct {
    /// What asked for the host: the derivation that fetches it, or the
    /// input a lock names. Part of every refusal, because a person reading one
    /// wants to know what asked.
    subject: []const u8,
    url: []const u8,
    host: []const u8,
    port: u16,
};

/// A URL of a fixed output derivation that could not be turned into a host
/// and a port.
pub const Unreadable = struct {
    subject: []const u8,
    /// Empty when the derivation carried no URL at all.
    url: []const u8,
    why: Why,

    /// The mirror site the URL named, empty when it named none.
    site: []const u8 = "",

    pub const Why = enum {
        /// A fixed output derivation with no `url` and no `urls`.
        no_url,
        scheme_unknown,
        no_host,
        port_not_a_port,
        /// A `mirror://` URL on a derivation that names no mirrors file.
        no_mirrors_file,
        /// The mirrors file the derivation names could not be read.
        mirrors_unreadable,
        /// The mirrors file does not name this site.
        mirror_site_unknown,
        /// Every mirror of the site names a host no rule can be written for.
        mirror_not_nameable,
    };
};

/// One mirror of a site, read out of a mirrors file.
pub const Mirror = struct {
    /// The mirror as the file writes it, which is what pins the builder. It
    /// carries no file path of its own: the builder appends that.
    base: []const u8,
    /// `base` with the derivation's own path on the end, which is the URL a
    /// person is asked about.
    url: []const u8,
    /// Null when the mirror names no host a rule can be written for. Such a
    /// mirror is passed over rather than refused, because the file holds an
    /// `ftp://` entry beside the `https://` ones for many sites.
    target: ?Target,
};

/// One `mirror://` URL of the closure, and every mirror the file names for
/// its site.
pub const MirrorSite = struct {
    subject: []const u8,
    /// The `mirror://` URL as the derivation writes it.
    url: []const u8,
    site: []const u8,
    /// In the mirrors file's own order.
    mirrors: []const Mirror,
};

/// Every way this closure reaches the network.
pub const Reached = struct {
    /// One entry per host and port, in the order they were found.
    hosts: []const Fetch = &.{},
    /// One entry per `mirror://` site, in the order they were found, each
    /// answered once however many derivations name it.
    sites: []const MirrorSite = &.{},
    /// The hashed mirrors of the first mirrors file this closure names. The
    /// builder tries these whatever the URLs say, so they are a host nobody
    /// named and they still have to be answered for.
    hashed: []const Mirror = &.{},
    /// True when any fixed output derivation of the closure names a mirrors
    /// file. The builder then reaches a hashed mirror whatever it fetches, so
    /// `NIX_HASHED_MIRRORS` has to be pinned.
    reads_mirrors: bool = false,
};

/// What one closure says about the network.
pub const Closure = union(enum) {
    reached: Reached,
    /// The first URL this file could not name. **A refusal and never a skip**:
    /// a fetch nobody can name is a fetch nobody can rule on.
    unreadable: Unreadable,
    /// What `nix` wrote when it would not read the closure.
    nix_said: []const u8,
};

/// The value that turns the hashed mirrors off.
///
/// **One space, and never the empty string.** Both nixpkgs builder shapes read
/// `NIX_HASHED_MIRRORS` only when it is not empty, so an empty value leaves
/// the list the mirrors file names in force and the builder reaches a host
/// nobody allowed. A space is not empty and it splits into no words, so both
/// builders loop over nothing.
pub const hashed_mirrors_off = " ";

/// The site whose mirrors the builder tries for every fetch.
pub const hashed_mirrors_site = "hashedMirrors";

/// The most bytes a mirrors file may be. The nixpkgs one is near thirteen
/// thousand, and a file far over this is not the list this reads.
pub const max_mirrors_bytes: usize = 256 * 1024;

pub const UrlError = error{
    UrlSchemeUnknown,
    UrlHasNoHost,
    UrlPortNotAPort,
};

/// Where a URL points.
pub const Target = struct {
    host: []const u8,
    port: u16,
};

/// The host and the port of `url`, both borrowed from it.
///
/// **A scheme this does not know is a refusal and never a guess.** `https` is
/// 443 and `http` is 80. Anything else, `mirror:` and `ftp:` included, has no
/// port this file may invent, and a wrong port would put a question to the
/// policy about a connection that never happens while the real one goes
/// unasked.
pub fn targetOf(url: []const u8) UrlError!Target {
    const mark = std.mem.indexOf(u8, url, "://") orelse return error.UrlSchemeUnknown;
    const scheme = url[0..mark];
    const default_port: u16 = if (std.ascii.eqlIgnoreCase(scheme, "https"))
        443
    else if (std.ascii.eqlIgnoreCase(scheme, "http"))
        80
    else
        return error.UrlSchemeUnknown;

    const rest = url[mark + 3 ..];
    const authority = rest[0 .. std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len];
    // A user name and a password belong to nobody's policy key, and the `@`
    // is what tells the host apart from them.
    const after_user = if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at|
        authority[at + 1 ..]
    else
        authority;
    if (after_user.len == 0) return error.UrlHasNoHost;
    // An address in brackets is the one host shape whose colons are not a
    // port boundary. Refused rather than parsed: the action namer takes
    // letters, digits, hyphen and dot, so a name it cannot build is a
    // question nobody can answer.
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

/// The site and the path of a `mirror://` URL, both borrowed from it. Null
/// when the URL is not one, or names no site or no path.
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

/// True when `name` is a mirror site name. Letters and digits, which is what
/// nixpkgs writes and what a shell variable name may hold here.
fn isSiteName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| {
        if (!std.ascii.isAlphanumeric(character)) return false;
    }
    return true;
}

/// What one mirrors file says, site by site. Every string is borrowed from
/// the file text.
const SiteMap = std.StringHashMapUnmanaged([]const []const u8);

/// Read `text` as a mirrors file.
///
/// **Two shapes, because nixpkgs has written both.** The one in use today is
/// one bash array per site, `declare -a _mirror_<site>=(<url> <url>)`. The
/// older one is what `set | grep` wrote, `<site>=<url> <url>`, with the value
/// quoted when it holds a space. A line of neither shape is passed over, so a
/// file this does not understand names no site and every site of it is a
/// refusal.
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

/// The mirrors files one closure names, read once each.
///
/// A closure holds hundreds of derivations that name the same file, and the
/// file is on disk because it is an output of the same closure.
const MirrorFiles = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    /// Keyed by store path.
    read: std.StringHashMapUnmanaged(SiteMap) = .empty,

    const ReadError = std.mem.Allocator.Error || error{MirrorsUnreadable};

    fn sitesOf(self: *MirrorFiles, path: []const u8) ReadError!SiteMap {
        if (self.read.get(path)) |already| return already;
        const text = std.Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(max_mirrors_bytes),
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MirrorsUnreadable,
        };
        const sites = try parseMirrors(self.allocator, text);
        try self.read.put(self.allocator, path, sites);
        return sites;
    }
};

/// The mirrors file a derivation names, or null when it names none. Read from
/// `structuredAttrs` first and from the environment after it, the same two
/// places `urlsOf` reads.
///
/// **Two names, because the builder has been renamed once.** The builder in
/// use today reads `mirrorsListFile` and the older one reads `mirrorsFile`.
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

/// Every mirror the file names for `site`, with `path` on the end of each.
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

/// Every host the closure of `derivation_path` would reach.
///
/// **Give this an arena**: every string of the answer comes from `allocator`,
/// and so does the JSON `nix` wrote.
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
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(allocator);
    var asked_sites: std.StringHashMapUnmanaged(void) = .empty;
    defer asked_sites.deinit(allocator);

    var files: MirrorFiles = .{ .allocator = allocator, .io = io };

    var each = listed.iterator();
    while (each.next()) |entry| {
        const one = entry.value_ptr.*;
        if (one != .object) continue;
        if (!isFixedOutput(one.object)) continue;

        const name = try allocator.dupe(u8, entry.key_ptr.*);
        const urls = try urlsOf(allocator, one.object) orelse return .{ .unreadable = .{
            .subject = name,
            .url = "",
            .why = .no_url,
        } };

        // **Read before the URLs and not because of one.** The builder tries
        // a hashed mirror whether or not any URL names a mirror site, so a
        // derivation that reads mirrors at all reaches that host.
        const mirrors_path = mirrorsFileOf(one.object);
        if (mirrors_path) |path| {
            reached.reads_mirrors = true;
            const known = files.sitesOf(path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.MirrorsUnreadable => return .{ .unreadable = .{
                    .subject = name,
                    .url = try allocator.dupe(u8, path),
                    .why = .mirrors_unreadable,
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
                    error.MirrorsUnreadable => return .{ .unreadable = .{
                        .subject = name,
                        .url = try allocator.dupe(u8, path),
                        .site = try allocator.dupe(u8, named.site),
                        .why = .mirrors_unreadable,
                    } },
                };

                const mirrors = try mirrorsFor(allocator, known, named.site, named.path) orelse
                    return .{ .unreadable = .{
                        .subject = name,
                        .url = try allocator.dupe(u8, url),
                        .site = try allocator.dupe(u8, named.site),
                        .why = .mirror_site_unknown,
                    } };

                // One site is one question, however many derivations name it.
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
    return .{ .reached = reached };
}

/// The map of derivations, whichever shape this `nix` wrote.
///
/// Nix 2.36 and later wrap the map in a `derivations` member beside a version
/// number, and every earlier one puts the map at the top. Both are read,
/// because the Nix on a user's machine is theirs and not ours.
fn derivationsOf(root: std.json.Value) ?std.json.ObjectMap {
    if (root != .object) return null;
    if (root.object.get("derivations")) |wrapped| {
        if (wrapped != .object) return null;
        return wrapped.object;
    }
    return root.object;
}

/// True when one output of this derivation carries an output hash, which is
/// what makes a derivation fixed output and what gives its builder the
/// network.
fn isFixedOutput(one: std.json.ObjectMap) bool {
    const outputs = one.get("outputs") orelse return false;
    if (outputs != .object) return false;
    var each = outputs.object.iterator();
    while (each.next()) |entry| {
        const output = entry.value_ptr.*;
        if (output != .object) continue;
        // `hash` is what every Nix writes. `hashAlgo` is there as well on the
        // older shape, and a derivation with one and not the other is still
        // fixed output.
        if (output.object.contains("hash")) return true;
        if (output.object.contains("hashAlgo")) return true;
    }
    return false;
}

/// What the builder will fetch, in the order the derivation writes them, each
/// borrowed from the parsed JSON. Null when it says nowhere it fetches from.
///
/// **Two places hold this, and both are read.** An ordinary derivation puts
/// `url` or `urls` in its environment, where a list is one string joined with
/// spaces. A derivation with structured attributes puts them in
/// `structuredAttrs` instead, where a list is a real JSON array, and its
/// environment then holds only the output names. nixpkgs builds `fetchurl`
/// the second way today, so a reader of the environment alone finds no URL on
/// the very derivation a person asked to build.
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

/// One sentence for a URL this file could not name. The caller owns it.
pub fn unreadableRefusal(
    allocator: std.mem.Allocator,
    one: Unreadable,
) std.mem.Allocator.Error![]u8 {
    return switch (one.why) {
        .no_url => std.fmt.allocPrint(
            allocator,
            "{s} fetches over the network and says nowhere it fetches from, so no rule can " ++
                "cover it and nothing was built.",
            .{one.subject},
        ),
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
    };
}

/// One sentence for a mirror site nobody permitted. The caller owns it.
///
/// **It names the site and the host**, because a person reading it has to
/// know both: the site is what the derivation wrote and the host is what the
/// rule would have to cover.
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

/// One sentence for a closure `nix` would not read. The caller owns it.
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

/// Whether one fetch may happen.
pub const Verdict = union(enum) {
    permitted,
    /// Why not, in words the model reads. Borrowed from the allocator the
    /// gate was given.
    refused: []const u8,
};

/// Who answers for a host a build would reach.
///
/// **A seam, because the answer is the policy table's and this library holds
/// no policy.** `src/run.zig` fills it in with the action name
/// `chock_broker.network.actionInto` writes and the arbiter every other
/// mid-call question goes through.
pub const Gate = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        permit: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            one: Fetch,
        ) std.mem.Allocator.Error!Verdict,
        /// True when a rule already permits this host, with nobody asked.
        ///
        /// **A choice and never the decision.** It picks which mirror of a
        /// site is put to `permit`, and `permit` is still what says yes and
        /// what writes the answer into the log. A gate that reads no rule
        /// answers false, so the first mirror is asked about instead.
        allows_by_rule: *const fn (ptr: *anyopaque, one: Fetch) bool,
    };

    pub fn permit(
        self: Gate,
        allocator: std.mem.Allocator,
        one: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return self.vtable.permit(self.ptr, allocator, one);
    }

    pub fn allowsByRule(self: Gate, one: Fetch) bool {
        return self.vtable.allows_by_rule(self.ptr, one);
    }

    /// The gate a caller that wired none gets. It permits nothing, so a
    /// wiring somebody forgot refuses a build that fetches rather than
    /// letting it reach a host.
    pub const refusing: Gate = .{ .ptr = undefined, .vtable = &refusing_vtable };

    const refusing_vtable: VTable = .{ .permit = refuseFn, .allows_by_rule = allowsNothing };

    fn refuseFn(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: Fetch,
    ) std.mem.Allocator.Error!Verdict {
        return .{ .refused = "this session can ask nobody about a host" };
    }

    fn allowsNothing(_: *anyopaque, _: Fetch) bool {
        return false;
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

    // A user name is not part of the host, so it is not part of the key.
    const with_user = try targetOf("https://someone:secret@example.com/a");
    try testing.expectEqualStrings("example.com", with_user.host);

    // No port this file may invent, so none is invented.
    try testing.expectError(error.UrlSchemeUnknown, targetOf("ftp://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("mirror://gnu/a.tar.gz"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("git+ssh://example.com/a"));
    try testing.expectError(error.UrlSchemeUnknown, targetOf("example.com/a"));

    try testing.expectError(error.UrlHasNoHost, targetOf("https:///a/b"));
    try testing.expectError(error.UrlHasNoHost, targetOf("https://[2001:db8::1]/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:http/a"));
    try testing.expectError(error.UrlPortNotAPort, targetOf("https://example.com:0/a"));
}

/// A `provision.Runner` that answers one reply and records what it was asked.
const FakeRunner = struct {
    gpa: std.mem.Allocator,
    code: u8 = 0,
    stdout: []const u8 = "",
    stderr: []const u8 = "",
    seen: []const []const u8 = &.{},

    fn deinit(self: *FakeRunner) void {
        for (self.seen) |one| self.gpa.free(one);
        self.gpa.free(self.seen);
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
        _: []const provision.Variable,
    ) provision.Error!@import("proc.zig").Output {
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        const copy = try self.gpa.alloc([]const u8, args.len);
        for (args, copy) |one, *slot| slot.* = try self.gpa.dupe(u8, one);
        self.seen = copy;
        return .{
            .term = .{ .exited = self.code },
            .stdout = try allocator.dupe(u8, self.stdout),
            .stderr = try allocator.dupe(u8, self.stderr),
        };
    }
};

/// What `nix derivation show -r` writes for a closure of two derivations, one
/// of which fetches. The shape Nix 2.36 writes, with the map wrapped.
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

    // The whole closure and not the one derivation, so an input that fetches
    // is found however deep it is.
    try testing.expectEqualStrings("derivation", fake.seen[0]);
    try testing.expectEqualStrings("show", fake.seen[1]);
    try testing.expectEqualStrings("-r", fake.seen[2]);
    try testing.expectEqualStrings("/nix/store/a-top.drv", fake.seen[4]);
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
        \\{"derivations":{"a.drv":{"env":{"url":"ftp://files.example.com/one.tar.gz"},
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
    try testing.expect(std.mem.indexOf(u8, said, "ftp://files.example.com") != null);

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

    // A fixed output derivation that says nowhere it fetches from is the same
    // refusal: the network is open to it and no rule can cover it.
    var silent = FakeRunner{
        .gpa = gpa,
        .stdout =
        \\{"derivations":{"c.drv":{"env":{"name":"c"},"outputs":{"out":{"hash":"sha256-A"}}}}}
        ,
    };
    defer silent.deinit();

    const no_url = try fetchesOf(arena, testing.io, silent.runner(), "/nix/store/c.drv");
    try testing.expect(no_url == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_url, no_url.unreadable.why);
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
    const answer = try Gate.refusing.permit(testing.allocator, .{
        .subject = "a.drv",
        .url = "https://example.com/a",
        .host = "example.com",
        .port = 443,
    });
    try testing.expect(answer == .refused);
}

test "a derivation with structured attributes holds its urls there, and they are read" {
    // **The shape nixpkgs writes for `fetchurl` today.** Its environment holds
    // the output name and nothing else, and a reader of the environment alone
    // finds no URL on the very derivation a person asked to build. Trimmed
    // from what `nix derivation show` really answers.
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

/// Three lines of a real nixpkgs mirrors list, byte for byte from the file a
/// `fetchurl` derivation names. The order inside each one is the file's own
/// order, which is the order a build tries them in, so a test that reads this
/// reads what nixpkgs really says.
///
/// **Public for the tests of this library and for nothing else.**
/// `lib/chock-nix/build.zig` gates a mirror and needs the same real list, and
/// two copies of it would be two things to keep true.
pub const nixpkgs_mirrors_sample =
    \\declare -a _mirror_gnu=(https://ftpmirror.gnu.org/ https://ftp.nluug.nl/pub/gnu/ https://mirrors.kernel.org/gnu/ https://mirror.ibcp.fr/pub/gnu/ https://mirror.dogado.de/gnu/ https://mirror.tochlab.net/pub/gnu/ https://ftp.gnu.org/pub/gnu/ ftp://ftp.funet.fi/pub/mirrors/ftp.gnu.org/gnu/)
    \\declare -a _mirror_hackage=(https://hackage.haskell.org/package/)
    \\declare -a _mirror_hashedMirrors=(https://tarballs.nixos.org)
    \\
;

/// Write `nixpkgs_mirrors_sample` into `tmp` and answer its absolute path, which
/// the derivation of a test names as its own `mirrorsFile`.
fn writeMirrorsList(
    allocator: std.mem.Allocator,
    tmp: *std.testing.TmpDir,
) ![]u8 {
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "mirrors-list", .data = nixpkgs_mirrors_sample });
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/mirrors-list", .{buffer[0..len]});
}

/// A closure of one `fetchurl` derivation that fetches `url` and names
/// `mirrors_path`. The shape nixpkgs writes today, trimmed.
fn closureFetching(
    allocator: std.mem.Allocator,
    url: []const u8,
    mirrors_path: ?[]const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{"derivations":{{"a-src.drv":{{"env":{{"out":"/nix/store/x-src"}},
        \\ "outputs":{{"out":{{"hash":"sha256-A","method":"flat"}}}},
        \\ "structuredAttrs":{{"urls":["{s}"]{s}{s}{s}}}}}}}}}
    ,
        .{
            url,
            if (mirrors_path == null) "" else ",\"mirrorsFile\":\"",
            mirrors_path orelse "",
            if (mirrors_path == null) "" else "\"",
        },
    );
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

    // The file's own order, and the derivation's own path on the end of each.
    try testing.expectEqualStrings("https://ftpmirror.gnu.org/", site.mirrors[0].base);
    try testing.expectEqualStrings(
        "https://ftpmirror.gnu.org/hello/hello-2.12.3.tar.gz",
        site.mirrors[0].url,
    );
    try testing.expectEqualStrings("ftpmirror.gnu.org", site.mirrors[0].target.?.host);
    try testing.expectEqualStrings("mirrors.kernel.org", site.mirrors[2].target.?.host);

    // The last one is `ftp://`, which is not a scheme this names. It is passed
    // over rather than refused, because the seven before it can be named.
    try testing.expect(site.mirrors[7].target == null);

    // The builder reaches a hashed mirror whatever the urls say, so the file's
    // own hashed mirrors are read as well.
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
        .stdout = try closureFetching(arena, "mirror://sourceforge/a/b.tar.gz", mirrors_path),
    };
    defer unknown.deinit();

    const missing_site = try fetchesOf(arena, testing.io, unknown.runner(), "/nix/store/a-src.drv");
    try testing.expect(missing_site == .unreadable);
    try testing.expectEqual(Unreadable.Why.mirror_site_unknown, missing_site.unreadable.why);
    try testing.expectEqualStrings("sourceforge", missing_site.unreadable.site);

    const said = try unreadableRefusal(gpa, missing_site.unreadable);
    defer gpa.free(said);
    try testing.expect(std.mem.indexOf(u8, said, "sourceforge") != null);

    // nixpkgs writes `mirror://` on a derivation that always names a mirrors
    // file. One that does not says nowhere its site is, so it is refused.
    var nameless = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "mirror://gnu/hello/hello-2.12.3.tar.gz", null),
    };
    defer nameless.deinit();

    const no_file = try fetchesOf(arena, testing.io, nameless.runner(), "/nix/store/a-src.drv");
    try testing.expect(no_file == .unreadable);
    try testing.expectEqual(Unreadable.Why.no_mirrors_file, no_file.unreadable.why);

    // And a mirrors file that is not on disk at all.
    var gone = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(
            arena,
            "mirror://gnu/hello/hello-2.12.3.tar.gz",
            "/nix/store/0000000000000000000000000000000a-mirrors-list",
        ),
    };
    defer gone.deinit();

    const unreadable_file = try fetchesOf(arena, testing.io, gone.runner(), "/nix/store/a-src.drv");
    try testing.expect(unreadable_file == .unreadable);
    try testing.expectEqual(Unreadable.Why.mirrors_unreadable, unreadable_file.unreadable.why);
}

test "a scheme that is still unknown after a mirror is expanded stays a refusal" {
    // The mirror expansion widens `mirror://` and nothing else. An `ftp://`
    // url the derivation writes itself names a port this file may not invent.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const mirrors_path = try writeMirrorsList(arena, &tmp);

    var fake = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "ftp://files.example.com/a.tar.gz", mirrors_path),
    };
    defer fake.deinit();

    const closure = try fetchesOf(arena, testing.io, fake.runner(), "/nix/store/a-src.drv");
    try testing.expect(closure == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, closure.unreadable.why);

    // A `mirror://` url with no path is not one this reads either, so it
    // reaches the ordinary scheme check and is refused there.
    var siteless = FakeRunner{
        .gpa = gpa,
        .stdout = try closureFetching(arena, "mirror://gnu", mirrors_path),
    };
    defer siteless.deinit();

    const no_path = try fetchesOf(arena, testing.io, siteless.runner(), "/nix/store/a-src.drv");
    try testing.expect(no_path == .unreadable);
    try testing.expectEqual(Unreadable.Why.scheme_unknown, no_path.unreadable.why);
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

    // What `set | grep` wrote before the arrays: one scalar per site, quoted
    // when it holds more than one mirror.
    var older = try parseMirrors(arena,
        \\hackage='https://hackage.haskell.org/package/ https://hackage.example.org/'
        \\hashedMirrors=https://tarballs.nixos.org
        \\
    );
    defer older.deinit(arena);
    try testing.expectEqual(@as(usize, 2), older.get("hackage").?.len);
    try testing.expectEqualStrings("https://tarballs.nixos.org", older.get("hashedMirrors").?[0]);

    // A line of neither shape names no site, so every site of such a file is
    // a refusal rather than a guess.
    var strange = try parseMirrors(arena, "_mirror_gnu: https://ftpmirror.gnu.org/\n");
    defer strange.deinit(arena);
    try testing.expectEqual(@as(u32, 0), strange.count());
}
