//! Which credential a `git push` needs, read on the host before anybody is
//! asked.
//!
//! ## Why this is read here and not inside the sandbox
//!
//! A person is asked about a push before it runs, and the question has to say
//! where the push goes. `git push origin main` names `origin` and not a URL,
//! so the URL has to be resolved out of the repository's own configuration,
//! and the only process that can do that before the question is written is the
//! one writing the question. See `src/run.zig`'s own `GitToolRunner`.
//!
//! The scheme of that URL is what decides which of the two credential paths is
//! armed, and exactly one of them ever is:
//!
//! ```
//! https://host/project.git   a password, prompted live, never stored
//! git@host:project.git       the ssh agent, proxied, never copied
//! /a/local/path              neither, because nothing authenticates
//! ```
//!
//! ## Every doubt resolves to the prompt
//!
//! An option this file does not read, a remote with no URL, a configuration
//! this file will not trust: each one answers `unreadable`, and a caller turns
//! that into a password prompt. **A prompt is visible and refusable. An agent
//! proxy is neither, and it is the wider capability.** So the doubtful case
//! takes the one a person can see, which is the same direction every other
//! safe default in this project takes.
//!
//! ## The configuration is the agent's own file, so it is untrusted
//!
//! `.git/config` sits in the session workspace, which the agent writes. So
//! **the URL this file answers is shown to the person in the approval**, and
//! it is never treated as a fact about where the push really goes. An agent
//! that writes a remote pointing somewhere else has changed what the person
//! reads, and the person is the one who decides.
//!
//! **Nothing here runs a program.** `git config` would be authoritative and it
//! would also run the agent's own configuration, and several configuration
//! values make git run a program of the writer's choosing. So this reads the
//! bytes itself and runs nothing at all.
//!
//! **Two rewriting features are refused rather than read.** `insteadOf` and
//! `include` both make the URL git really uses different from the one written
//! next to the remote. This file cannot follow either one correctly, so a
//! configuration holding either is not read, and the caller prompts.

const std = @import("std");

/// What one remote needs before a push to it can work.
pub const Credential = enum {
    /// An `http` or `https` remote. A password is prompted live.
    password,
    /// An `ssh` remote. The person's own agent is proxied.
    agent,
    /// A local path or the anonymous git protocol. Nothing authenticates, so
    /// nothing is armed.
    none,
    /// The remote could not be read. The caller prompts: see this file's own
    /// top comment.
    unreadable,
};

/// The remote git falls back to when a push names none.
pub const default_remote = "origin";

/// The longest configuration file this reads. A `.git/config` is a few hundred
/// bytes. This is far above any real one and far below what a repository could
/// use to make this process hold memory on its behalf.
pub const max_config_bytes: usize = 256 * 1024;

/// Which remote a `git push` argument vector names, or null when this file
/// cannot tell.
///
/// `rest` is what follows the `push` subcommand, which is what
/// `git_shim.classify` already cut out of the whole vector. So there is one
/// reader of a git command line in this library and not two.
///
/// **An option this file does not read stops the reading there.** That is the
/// same safe default `git_shim.classify` keeps for an option before the
/// subcommand, and for the same reason: an option can change what the
/// arguments after it mean, so a vector this file cannot account for is one it
/// must not guess at.
pub fn remoteNameIn(rest: []const []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < rest.len) {
        const arg = rest[index];
        if (arg.len == 0) return null;
        if (arg[0] != '-') return arg;

        // `--name=value`, one argument, whichever list the name is on.
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
        // Everything else. See this function's own comment.
        return null;
    }
    // A push that names nothing pushes to the remote the branch tracks, which
    // is `origin` in every repository nobody has changed. A configuration with
    // no `remote.origin.url` then answers `unreadable`, and the caller
    // prompts, which is the right end for a guess that did not hold.
    return default_remote;
}

/// Whether these bytes are a URL rather than the name of a remote.
///
/// **A remote's name can hold neither a colon nor a slash**, which is what
/// makes this exact rather than a guess: git refuses both in a remote name. So
/// a push that names a URL where a name would go is recognised for what it is,
/// and one that names a remote is looked up in the configuration.
pub fn namesAUrl(named: []const u8) bool {
    if (named.len == 0) return false;
    return std.mem.indexOfAny(u8, named, ":/") != null or named[0] == '~';
}

/// Options of `git push` that carry no value of their own.
const no_value_options: []const []const u8 = &.{
    "--all",           "--atomic",         "--delete",             "-d",
    "--dry-run",       "-n",               "--follow-tags",        "--force",
    "-f",              "--force-with-lease", "--no-force-with-lease", "--ipv4",
    "-4",              "--ipv6",           "-6",                   "--mirror",
    "--no-atomic",     "--no-progress",    "--no-signed",          "--no-thin",
    "--no-verify",     "--porcelain",      "--progress",           "--prune",
    "--quiet",         "-q",               "--set-upstream",       "-u",
    "--signed",        "--tags",           "--thin",               "--verbose",
    "-v",              "--verify",
};

/// Options of `git push` that take the argument after them.
///
/// **Short, and every one of them is listed because it is common.** An option
/// absent from both lists stops the reading, which costs a prompt and never a
/// wrong answer.
const value_options: []const []const u8 = &.{
    "--exec",          "-o",               "--push-option",        "--receive-pack",
    "--recurse-submodules", "--repo",      "--server-option",
};

fn isOneOf(needle: []const u8, list: []const []const u8) bool {
    for (list) |one| {
        if (std.mem.eql(u8, needle, one)) return true;
    }
    return false;
}

/// The URL configured for `name`, out of the bytes of a `.git/config`, or null.
///
/// **A remote may hold a `pushurl` as well as a `url`, and a push uses the
/// `pushurl` when there is one.** Both are read, and `pushurl` wins, because
/// answering with the fetch URL would show the person a host the push never
/// reaches.
pub fn remoteUrlIn(text: []const u8, name: []const u8) ?[]const u8 {
    // See this file's own top comment. Neither feature can be followed here,
    // and a URL read past one of them would be the wrong URL.
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
    return push_url orelse url;
}

/// Whether a section header names the remote `name`. The header is
/// `[remote "origin"]`, and git folds the section name for case and keeps the
/// subsection name exactly as written.
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

/// Which credential a remote URL needs.
///
/// **Anything this cannot place answers `password`.** See this file's own top
/// comment: the doubtful case takes the capability a person can see.
pub fn credentialFor(url: []const u8) Credential {
    if (url.len == 0) return .unreadable;

    if (startsWithIgnoreCase(url, "https://")) return .password;
    if (startsWithIgnoreCase(url, "http://")) return .password;
    if (startsWithIgnoreCase(url, "ssh://")) return .agent;
    if (startsWithIgnoreCase(url, "git+ssh://")) return .agent;

    // The anonymous protocol authenticates nobody, and a local path has
    // nothing to authenticate to.
    if (startsWithIgnoreCase(url, "git://")) return .none;
    if (startsWithIgnoreCase(url, "file://")) return .none;
    if (url[0] == '/' or url[0] == '.' or url[0] == '~') return .none;

    // A scheme this file does not know. It is not an ssh remote as far as
    // anything here can tell, so it takes the visible path.
    if (std.mem.indexOf(u8, url, "://") != null) return .password;

    // The scp-like spelling, `user@host:path` or `host:path`. The colon has to
    // come after the host, and a colon that is part of a path is not one.
    if (std.mem.indexOfScalar(u8, url, ':')) |at| {
        if (at > 0 and std.mem.indexOfScalar(u8, url[0..at], '/') == null) return .agent;
    }
    return .password;
}

/// The host a remote URL names, for the action name a policy is keyed on, or
/// null when these bytes carry none.
///
/// **The order the parts are cut in is the whole defence**, exactly as
/// `chock-broker/askpass.zig`'s own `hostOf` argues at length. The path is cut
/// off first and the user information second. The other way round,
/// `https://evil.example/x@github.com` reads as the host `github.com`, because
/// the last `@` of the whole string is in the path.
pub fn hostIn(url: []const u8) ?[]const u8 {
    var rest = url;

    if (std.mem.indexOf(u8, rest, "://")) |at| {
        rest = rest[at + 3 ..];
        // The path first.
        if (std.mem.indexOfScalar(u8, rest, '/')) |slash| rest = rest[0..slash];
        // Then the user information.
        if (std.mem.lastIndexOfScalar(u8, rest, '@')) |mark| rest = rest[mark + 1 ..];
        // Then the port.
        if (std.mem.lastIndexOfScalar(u8, rest, ':')) |mark| rest = rest[0..mark];
        return if (rest.len == 0) null else rest;
    }

    // The scp-like spelling. The host ends at the first colon, and a slash
    // before that colon means these bytes are a path and not a remote.
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

    // **The fault this pins.** `-o a` takes the argument after it. A reader
    // that did not know so would answer `a`, and then read the URL of a remote
    // nobody named and show the person the wrong host.
    try testing.expect(!std.mem.eql(u8, "a", remoteNameIn(&.{ "-o", "a", "b" }).?));

    // Mutation check: delete the final `return null` below the two lists and
    // the next three expectations fail, because an unknown option is then
    // read as the remote name.
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

    // A push uses `pushurl` when the remote holds one, so reading `url` there
    // would show a host the push never reaches.
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

    // **Refused rather than read.** Both of these make the URL git really uses
    // different from the one written beside the remote, and a caller that got
    // null prompts, which is the safe end.
    //
    // Mutation check: delete either guard at the top of `remoteUrlIn` and the
    // matching expectation below fails.
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

    // A comment is not a value, and a subsection name keeps its case where a
    // section name does not.
    const commented =
        \\[REMOTE "origin"]
        \\    url = https://git.example.com/p.git # not part of the url
        \\
    ;
    try testing.expectEqualStrings("https://git.example.com/p.git", remoteUrlIn(commented, "origin").?);
    try testing.expectEqual(@as(?[]const u8, null), remoteUrlIn(commented, "Origin"));
}

test "a url where a remote name would go is read as a url" {
    // `git push https://host/p.git HEAD:main` is an ordinary spelling, and a
    // reader that looked `https://host/p.git` up in the configuration would
    // find nothing and answer unreadable.
    //
    // Mutation check: make `namesAUrl` answer false always and the first three
    // expectations fail.
    try testing.expect(namesAUrl("https://host/p.git"));
    try testing.expect(namesAUrl("git@host:p.git"));
    try testing.expect(namesAUrl("/srv/p.git"));
    try testing.expect(namesAUrl("../p.git"));

    // A remote's name holds neither a colon nor a slash, which git itself
    // refuses, so these are names and never URLs.
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

    // **The doubtful case takes the prompt and never the agent.** A prompt is
    // visible and refusable, and an agent proxy is neither.
    //
    // Mutation check: make the last line of `credentialFor` answer `.agent`
    // and both of these fail.
    try testing.expectEqual(Credential.password, credentialFor("weird://example.com/p.git"));
    try testing.expectEqual(Credential.password, credentialFor("not-a-url-at-all"));

    // A relative path with a colon in it is a path, not an scp-like remote:
    // the slash comes first.
    try testing.expectEqual(Credential.none, credentialFor("./sub/dir:name"));
}

test "the host of a remote is cut in the order that stops a crafted url" {
    try testing.expectEqualStrings("git.example.com", hostIn("https://git.example.com/p.git").?);
    try testing.expectEqualStrings("git.example.com", hostIn("https://you@git.example.com/p.git").?);
    try testing.expectEqualStrings("git.example.com", hostIn("https://git.example.com:8443/p.git").?);
    try testing.expectEqualStrings("example.com", hostIn("git@example.com:p.git").?);
    try testing.expectEqualStrings("example.com", hostIn("example.com:p.git").?);

    // **The fault this pins**, and it is the one `askpass.hostOf` names. Cut
    // the user information off before the path and this URL reads as the host
    // `github.com`, because the last `@` of the whole string is in the path.
    // The host it really names is `evil.example`.
    //
    // Mutation check: swap the two cuts in `hostIn` and this fails.
    try testing.expectEqualStrings("evil.example", hostIn("https://evil.example/x@github.com").?);

    try testing.expectEqual(@as(?[]const u8, null), hostIn("/srv/p.git"));
    try testing.expectEqual(@as(?[]const u8, null), hostIn("https:///p.git"));
}
