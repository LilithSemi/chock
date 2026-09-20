//! Which credential a `git push` needs, read on the host. Every doubt answers
//! `unreadable`, and the caller prompts for a password, which a person can stop.

const std = @import("std");

pub const Credential = enum {
    password,
    agent,
    none,
    unreadable,
};

pub const default_remote = "origin";

pub const max_config_bytes: usize = 256 * 1024;

pub fn remoteNameIn(rest: []const []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < rest.len) {
        const arg = rest[index];
        if (arg.len == 0) return null;
        if (arg[0] != '-') return arg;

        if (std.mem.indexOfScalar(u8, arg, '=')) |at| {
            const name = arg[0..at];
            if (isOneOf(name, no_value_options) or isOneOf(name, value_options)) {
                index += 1;
                continue;
            }
            return null;
        }
        if (isOneOf(arg, no_value_options)) {
            index += 1;
            continue;
        }
        if (isOneOf(arg, value_options)) {
            index += 2;
            continue;
        }
        return null;
    }
    return default_remote;
}

/// Git refuses a colon and a slash in a remote name, so this is exact.
pub fn namesAUrl(named: []const u8) bool {
    if (named.len == 0) return false;
    return std.mem.indexOfAny(u8, named, ":/") != null or named[0] == '~';
}

const no_value_options: []const []const u8 = &.{
    "--all",       "--atomic",           "--delete",              "-d",
    "--dry-run",   "-n",                 "--follow-tags",         "--force",
    "-f",          "--force-with-lease", "--no-force-with-lease", "--ipv4",
    "-4",          "--ipv6",             "-6",                    "--mirror",
    "--no-atomic", "--no-progress",      "--no-signed",           "--no-thin",
    "--no-verify", "--porcelain",        "--progress",            "--prune",
    "--quiet",     "-q",                 "--set-upstream",        "-u",
    "--signed",    "--tags",             "--thin",                "--verbose",
    "-v",          "--verify",
};

const value_options: []const []const u8 = &.{
    "--exec",               "-o",     "--push-option",   "--receive-pack",
    "--recurse-submodules", "--repo", "--server-option",
};

fn isOneOf(needle: []const u8, list: []const []const u8) bool {
    for (list) |one| {
        if (std.mem.eql(u8, needle, one)) return true;
    }
    return false;
}

/// Runs no program: some configuration values make git run one.
pub fn remoteUrlIn(text: []const u8, name: []const u8) ?[]const u8 {
    // `insteadOf` and `include` both change the URL git really uses, and this
    // file cannot follow either, so a configuration with one is not read.
    if (containsIgnoreCase(text, "insteadof")) return null;
    if (containsIgnoreCase(text, "[include")) return null;

    var url: ?[]const u8 = null;
    var push_url: ?[]const u8 = null;
    var in_remote = false;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = trim(stripComment(raw));
        if (line.len == 0) continue;

        if (line[0] == '[') {
            in_remote = sectionIsRemote(line, name);
            continue;
        }
        if (!in_remote) continue;

        const at = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = trim(line[0..at]);
        const value = trim(line[at + 1 ..]);
        if (value.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(key, "url")) url = value;
        if (std.ascii.eqlIgnoreCase(key, "pushurl")) push_url = value;
    }
    // A push uses `pushurl` when the remote holds one.
    return push_url orelse url;
}

/// Git folds a section name for case and keeps a subsection name exact.
fn sectionIsRemote(line: []const u8, name: []const u8) bool {
    const close = std.mem.lastIndexOfScalar(u8, line, ']') orelse return false;
    const body = trim(line[1..close]);
    const quote = std.mem.indexOfScalar(u8, body, '"') orelse return false;
    const section = trim(body[0..quote]);
    if (!std.ascii.eqlIgnoreCase(section, "remote")) return false;
    const rest = body[quote + 1 ..];
    const end = std.mem.indexOfScalar(u8, rest, '"') orelse return false;
    return std.mem.eql(u8, rest[0..end], name);
}

fn stripComment(line: []const u8) []const u8 {
    const at = std.mem.indexOfAny(u8, line, "#;") orelse return line;
    return line[0..at];
}

fn trim(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t\r");
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var at: usize = 0;
    while (at + needle.len <= haystack.len) : (at += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[at..][0..needle.len], needle)) return true;
    }
    return false;
}

pub fn credentialFor(url: []const u8) Credential {
    if (url.len == 0) return .unreadable;

    if (startsWithIgnoreCase(url, "https://")) return .password;
    if (startsWithIgnoreCase(url, "http://")) return .password;
    if (startsWithIgnoreCase(url, "ssh://")) return .agent;
    if (startsWithIgnoreCase(url, "git+ssh://")) return .agent;

    if (startsWithIgnoreCase(url, "git://")) return .none;
    if (startsWithIgnoreCase(url, "file://")) return .none;
    if (url[0] == '/' or url[0] == '.' or url[0] == '~') return .none;

    if (std.mem.indexOf(u8, url, "://") != null) return .password;

    // A colon after a slash is part of a path, not the mark after a host.
    if (std.mem.indexOfScalar(u8, url, ':')) |at| {
        if (at > 0 and std.mem.indexOfScalar(u8, url[0..at], '/') == null) return .agent;
    }
    return .password;
}

/// Cut the path off first and the user information second. The other way round,
/// `https://evil.example/x@github.com` reads as the host `github.com`.
pub fn hostIn(url: []const u8) ?[]const u8 {
    var rest = url;

    if (std.mem.indexOf(u8, rest, "://")) |at| {
        rest = rest[at + 3 ..];
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| rest = rest[0..slash];
        if (std.mem.lastIndexOfScalar(u8, rest, '@')) |mark| rest = rest[mark + 1 ..];
        if (std.mem.lastIndexOfScalar(u8, rest, ':')) |mark| rest = rest[0..mark];
        return if (rest.len == 0) null else rest;
    }

    const colon = std.mem.indexOfScalar(u8, rest, ':') orelse return null;
    rest = rest[0..colon];
    if (std.mem.indexOfScalar(u8, rest, '/') != null) return null;
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |mark| rest = rest[mark + 1 ..];
    return if (rest.len == 0) null else rest;
}

fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..needle.len], needle);
}

const testing = std.testing;

test "a push names its remote, and an option this file cannot read stops the reading" {
    try testing.expectEqualStrings("origin", remoteNameIn(&.{}).?);
    try testing.expectEqualStrings("origin", remoteNameIn(&.{ "origin", "main" }).?);
    try testing.expectEqualStrings("upstream", remoteNameIn(&.{ "--force", "upstream", "main" }).?);
    try testing.expectEqualStrings("origin", remoteNameIn(&.{ "-u", "origin", "main" }).?);
    try testing.expectEqualStrings("b", remoteNameIn(&.{ "-o", "a", "b", "main" }).?);
    try testing.expectEqualStrings("b", remoteNameIn(&.{ "--push-option=a", "b" }).?);
    try testing.expectEqualStrings("https://x/y.git", remoteNameIn(&.{ "https://x/y.git", "main" }).?);

    try testing.expect(!std.mem.eql(u8, "a", remoteNameIn(&.{ "-o", "a", "b" }).?));

    try testing.expectEqual(@as(?[]const u8, null), remoteNameIn(&.{"--not-a-real-option"}));
    try testing.expectEqual(@as(?[]const u8, null), remoteNameIn(&.{ "--exec-but-longer=x", "origin" }));
    try testing.expectEqual(@as(?[]const u8, null), remoteNameIn(&.{""}));
}

test "the url of a remote is read out of a configuration, and a rewriting one is not read at all" {
    const config =
        \\[core]
        \\    bare = false
        \\[remote "origin"]
        \\    url = https://git.example.com/project.git
        \\    fetch = +refs/heads/*:refs/remotes/origin/*
        \\[remote "other"]
        \\    url = git@other.example.com:project.git
        \\
    ;
    try testing.expectEqualStrings(
        "https://git.example.com/project.git",
        remoteUrlIn(config, "origin").?,
    );
    try testing.expectEqualStrings(
        "git@other.example.com:project.git",
        remoteUrlIn(config, "other").?,
    );
    try testing.expectEqual(@as(?[]const u8, null), remoteUrlIn(config, "missing"));

    const with_push =
        \\[remote "origin"]
        \\    url = https://read.example.com/p.git
        \\    pushurl = https://write.example.com/p.git
        \\
    ;
    try testing.expectEqualStrings(
        "https://write.example.com/p.git",
        remoteUrlIn(with_push, "origin").?,
    );

    const rewritten =
        \\[url "git@evil.example:"]
        \\    insteadOf = https://git.example.com/
        \\[remote "origin"]
        \\    url = https://git.example.com/project.git
        \\
    ;
    try testing.expectEqual(@as(?[]const u8, null), remoteUrlIn(rewritten, "origin"));

    const included =
        \\[include]
        \\    path = ../elsewhere
        \\[remote "origin"]
        \\    url = https://git.example.com/project.git
        \\
    ;
    try testing.expectEqual(@as(?[]const u8, null), remoteUrlIn(included, "origin"));

    const commented =
        \\[REMOTE "origin"]
        \\    url = https://git.example.com/p.git # not part of the url
        \\
    ;
    try testing.expectEqualStrings("https://git.example.com/p.git", remoteUrlIn(commented, "origin").?);
    try testing.expectEqual(@as(?[]const u8, null), remoteUrlIn(commented, "Origin"));
}

test "a url where a remote name would go is read as a url" {
    try testing.expect(namesAUrl("https://host/p.git"));
    try testing.expect(namesAUrl("git@host:p.git"));
    try testing.expect(namesAUrl("/srv/p.git"));
    try testing.expect(namesAUrl("../p.git"));

    try testing.expect(!namesAUrl("origin"));
    try testing.expect(!namesAUrl("upstream"));
    try testing.expect(!namesAUrl("my-fork.2"));
    try testing.expect(!namesAUrl(""));
}

test "a scheme decides which credential is armed, and exactly one ever is" {
    try testing.expectEqual(Credential.password, credentialFor("https://git.example.com/p.git"));
    try testing.expectEqual(Credential.password, credentialFor("http://git.example.com/p.git"));
    try testing.expectEqual(Credential.agent, credentialFor("ssh://git@example.com/p.git"));
    try testing.expectEqual(Credential.agent, credentialFor("git@example.com:p.git"));
    try testing.expectEqual(Credential.agent, credentialFor("example.com:p.git"));
    try testing.expectEqual(Credential.none, credentialFor("git://example.com/p.git"));
    try testing.expectEqual(Credential.none, credentialFor("file:///srv/p.git"));
    try testing.expectEqual(Credential.none, credentialFor("/srv/p.git"));
    try testing.expectEqual(Credential.none, credentialFor("../p.git"));
    try testing.expectEqual(Credential.unreadable, credentialFor(""));

    try testing.expectEqual(Credential.password, credentialFor("weird://example.com/p.git"));
    try testing.expectEqual(Credential.password, credentialFor("not-a-url-at-all"));

    try testing.expectEqual(Credential.none, credentialFor("./sub/dir:name"));
}

test "the host of a remote is cut in the order that stops a crafted url" {
    try testing.expectEqualStrings("git.example.com", hostIn("https://git.example.com/p.git").?);
    try testing.expectEqualStrings("git.example.com", hostIn("https://you@git.example.com/p.git").?);
    try testing.expectEqualStrings("git.example.com", hostIn("https://git.example.com:8443/p.git").?);
    try testing.expectEqualStrings("example.com", hostIn("git@example.com:p.git").?);
    try testing.expectEqualStrings("example.com", hostIn("example.com:p.git").?);

    try testing.expectEqualStrings("evil.example", hostIn("https://evil.example/x@github.com").?);

    try testing.expectEqual(@as(?[]const u8, null), hostIn("/srv/p.git"));
    try testing.expectEqual(@as(?[]const u8, null), hostIn("https:///p.git"));
}
