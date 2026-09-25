# Documentation

Start with [running.md](running.md) for a session end to end, and
[status.md](status.md) for what is not built yet.

- [running.md](running.md) - `chock run` from the command line to the exit
  code: the session log, devices, getting the work back out of the workspace,
  cost, the task list, and `chock doctor`.
- [status.md](status.md) - what is not built yet, and the faults Chock is known
  to have.

## Using a session

- [using/tools.md](using/tools.md) - the 22 tools, what each one asks for, how
  every call is gated, and `provide_tool` for a program the session has not
  got.
- [using/nix.md](using/nix.md) - `nix_eval` and `nix_build`, what a build may
  fetch while it runs, mirrors, and where your flake inputs come from.
- [using/approvals.md](using/approvals.md) - what a session asks a person, how
  the question reaches them, where an approved apply lands, and what happens
  when nobody is there.
- [using/subagents.md](using/subagents.md) - `spawn_agent`, the depth and width
  limits, the budget slice, and a spawn that waits or carries on.
- [using/memory.md](using/memory.md) - the notes an agent keeps between
  sessions, their bounds, and the hazard a writable memory directory is.
- [using/instructions.md](using/instructions.md) - the three layers of
  `AGENTS.md`, why they are never flattened, and how they differ from a note.

## Configuring a project

- [configure/configuration.md](configure/configuration.md) - `config.zon`,
  provider instances, how much context a model holds, and every block of the
  project's own `chock.zon`.
- [configure/policy.md](configure/policy.md) - how a rule is read: the fields,
  the decisions, precedence, wildcards, `deny_read`, and the ratchet an agent
  cannot lift.
- [configure/actions.md](configure/actions.md) - the reference for every action
  name a rule can carry, and what Chock ships for each.
- [configure/search.md](configure/search.md) - the web search engine: the three
  kinds, the key in the credential store, and the org ceiling over both.
- [configure/org.md](configure/org.md) - the org policy bundle, the budget, the
  subagent limits, and the `limits` and `nix` ceilings.

## Security

- [security/threat-model.md](security/threat-model.md) - what the sandbox is
  built against, one attack walked end to end, and what is not covered.
- [security/sandbox.md](security/sandbox.md) - the layers a tool call runs
  inside, the workspace, the mount tree, the limits, device passthrough, what
  macOS gives, and what `chock doctor` reports.
- [security/red-team.md](security/red-team.md) - the red team harness, what two
  models proved, and the one boundary that moved.

## Running the tooling

- [operate/daemon.md](operate/daemon.md) - `chock daemon`, `chock serve`, the
  control protocol, and handing a session over with `chock detach`.
- [operate/toolchains.md](operate/toolchains.md) - the dev shell, a container
  image instead, where a compiler writes, and every path in a tool call's mount
  tree.
- [operate/credentials.md](operate/credentials.md) - `chock login`, where a
  credential goes, where a lookup goes, and why there is no argument and no
  environment variable for one.

## Extending Chock

- [extend/plugins.md](extend/plugins.md) - tools you supply yourself, as
  WebAssembly, and how each one is gated.
