# Documentation

- [sandbox.md](sandbox.md) - the layers a tool call runs inside, the throwaway
  workspace, the limits, and what the macOS sandbox holds and cannot.
- [running.md](running.md) - `chock run`, the seventeen tools, the session log,
  getting the work back out of the workspace, the exit codes, cost, the task
  list, and `chock doctor`.
- [configuration.md](configuration.md) - `config.zon`, provider instances, how
  much context a model holds, and how the project's own `chock.zon` differs
  from it.
- [credentials.md](credentials.md) - `chock login`, where a credential goes,
  and why there is no argument and no environment variable for one.
- [approvals.md](approvals.md) - what a session asks a person, and what happens
  when nobody is there.
- [policy.md](policy.md) - the policy table in `chock.zon`, the paths a project
  denies, the ratchet, and an organisation's bundle above a project.
- [tools.md](tools.md) - `provide_tool`, and getting a program the session has
  not got.
- [plugins.md](plugins.md) - tools you supply yourself, as WebAssembly.
- [subagents.md](subagents.md) - `spawn_agent`, the depth and width limits, and
  a spawn that waits or carries on.
- [instructions.md](instructions.md) - the three layers of `AGENTS.md`, and why
  they are never flattened.
- [memory.md](memory.md) - the notes an agent keeps between sessions, and the
  hazard a writable memory directory is.
- [toolchains.md](toolchains.md) - the dev shell, the container image and its
  shared cache, where a compiler writes, and every path in a tool call's mount
  tree.
- [daemon.md](daemon.md) - `chock daemon`, `chock serve`, and handing a session
  over with `chock detach`.
- [status.md](status.md) - what works, what is not built yet, and the open
  items.
