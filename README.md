# chock

Chock is a sandbox first AI coding harness. It runs a coding agent inside
kernel namespaces, Landlock and a seccomp filter, in a throwaway copy of your
project, and it writes every turn to a session log you can read afterwards.
Chock is written in Zig 0.16 and builds with `zig build`.

## Why

A coding agent runs commands, writes files, and wants to reach the network.
Most harnesses ask the agent to be careful. **Chock takes the boundary out of
the agent's hands.** A tool call gets a user namespace, a mount namespace, a
PID namespace, an IPC namespace and an empty network namespace, under Landlock
and a system call filter, in a workspace that is a copy. Your real project is
never written by a tool call, and a machine that cannot give a layer says so
before a session starts.

The other half is that **every action is reviewable**. The session log is the
session: every turn, every tool call, every approval and every cost is an
event in it. What an agent may do is a static table in `chock.zon` that the
agent cannot reach, and the answer is written into the log before the act
happens. An approval nobody answers is a refusal.

## Features

- Every tool call inside namespaces, Landlock and seccomp, with a throwaway
  workspace. See [docs/sandbox.md](docs/sandbox.md).
- A declarative policy table, per project, that the agent cannot edit, plus an
  organisation's bundle above it. See [docs/policy.md](docs/policy.md).
- An agent that can narrow its own policy and cannot widen it again. See
  [docs/policy.md](docs/policy.md).
- Nix aware tool calls: every call runs with this project's dev shell, and the
  agent can ask for one more program. See
  [docs/toolchains.md](docs/toolchains.md) and [docs/tools.md](docs/tools.md).
- Subagents, bounded in depth and width by the project. See
  [docs/subagents.md](docs/subagents.md).
- Notes an agent keeps between sessions, outside your project. See
  [docs/memory.md](docs/memory.md).
- Tools you supply yourself, as WebAssembly. See
  [docs/plugins.md](docs/plugins.md).
- A daemon that owns sessions, and a browser in front of it. See
  [docs/daemon.md](docs/daemon.md).

## Providers

- [ai&](https://aiand.com)
- Anthropic
- Any OpenAI compatible endpoint

## Getting started

```
chock doctor                        # can this machine contain a session
chock login --provider aiand        # store a credential
cd ~/some-project
chock run "add a test for the parser"
chock -- add a test for the parser  # the same task, with no subcommand
chock                               # the interface, which asks for the task
```

`chock doctor` measures each sandbox layer for real and says which are on.
`chock run` prints the session log's path before it starts. Bare `chock`
brings up a full screen interface and asks for the task in it.

**A first word is read as a command name**, so a task given on the line goes
after `--`. `chock fix the parser` is refused, because a typed `chock rnu`
that quietly became a task would spend money on a typo. `chock -- fix the
parser` runs, and so does `echo "fix the parser" | chock`.

Name your providers in `~/.config/chock/config.zon`, which Chock reads and
never writes. See [docs/configuration.md](docs/configuration.md).

Chock is an early prototype. See [docs/status.md](docs/status.md) for what
works and what does not.

## Documentation

Build with `zig build`. See [docs/](docs/README.md) for how Chock works, one
page per subject.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) has the repository layout, the coding
standards, and the four rules that hold the security model together.

Read [SECURITY.md](SECURITY.md) first. It says what Chock protects, what it
does not, and how to report a hole in the boundary. The
[Code of Conduct](CODE_OF_CONDUCT.md) applies to everyone here.
