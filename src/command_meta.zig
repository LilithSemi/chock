//! The command names and summaries, without their implementations.
//!
//! Documentation checks import this small table instead of compiling the
//! whole executable. `main.zig` checks that its dispatch table agrees with it.

pub const Entry = struct {
    name: []const u8,
    summary: []const u8,
};

pub const entries = [_]Entry{
    .{ .name = "run", .summary = "Run one agent session in the current project." },
    .{ .name = "login", .summary = "Store a credential for a provider instance." },
    .{ .name = "config", .summary = "Check the user configuration without reading credentials." },
    .{ .name = "models", .summary = "List configured providers, models, and usable capabilities." },
    .{ .name = "daemon", .summary = "Own sessions, and answer every client that asks about one." },
    .{ .name = "serve", .summary = "Put a browser in front of a daemon. Owns no session itself." },
    .{ .name = "acp", .summary = "Speak the agent client protocol, so an editor can drive Chock." },
    .{ .name = "memory", .summary = "Read or clear the notes agents wrote about this project." },
    .{ .name = "cache", .summary = "Show or empty the toolchain cache this project's tool calls write." },
    .{ .name = "workspace", .summary = "Show or remove the workspaces sessions that ended badly left behind." },
    .{ .name = "usage", .summary = "Show what this project's sessions cost." },
    .{ .name = "plan", .summary = "Show the task list an agent kept while it worked." },
    .{ .name = "skills", .summary = "Check a directory of skills against the format a session reads." },
    .{ .name = "commands", .summary = "List the commands a person can run by name, read one, or check a directory of them." },
    .{ .name = "sessions", .summary = "List, inspect, fork, verify, export, or remove this project's sessions." },
    .{ .name = "eval", .summary = "Run or score a reproducible evaluation against an audited session." },
    .{ .name = "doctor", .summary = "Say whether this machine can contain a session, before one starts." },
    .{ .name = "migrate", .summary = "Read another AI coding harness's configuration and write a chock.zon for it." },
    .{ .name = "approve", .summary = "Answer the questions a running session asks." },
    .{ .name = "detach", .summary = "Hand a session to the daemon, which becomes its owner." },
    .{ .name = "askpass", .summary = "Answer a password prompt from git or ssh." },
    .{ .name = "guest", .summary = "Sandbox tool calls inside a microVM. Started by a guest's own init." },
};
