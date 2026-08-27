# Toolchains, and where the compiler writes

Every tool call runs with the environment of this project's Nix dev shell, and
the mount set of a call is that shell's closure, read only, each store path at
its own path. So the agent gets the project's own compiler, and it gets nothing
else from the store. What a project needs every time belongs in `flake.nix`.
For one program in one session, see [tools.md](tools.md).

**The answer does not depend on the caller.** Chock reads the dev shell the way
nix-direnv does, and it takes the difference between two shells rather than one
shell's whole environment. So a person whose direnv has already loaded the dev
shell gets the same mount set as a person who has not.

## A container image instead of a dev shell

A project that names a container image in the `container` block of `chock.zon`
gets its toolchain from that image and never from Nix. The image is read on the
host, before any sandbox exists, and its root filesystem is written once into
`~/.local/share/chock/images/<image>/`. Every tool call then binds that tree,
read only. Nothing is fetched during a session, so an image that is not on the
machine is refused at the start with the `pull` command to run.

**One directory per image reference, shared by every session on it.** That is
what makes the second terminal on a project cheap: it reads the tree the first
one wrote, instead of extracting the image again.

Two locks keep that directory safe, and each answers a different question. The
first covers the extraction, so two sessions that both start cold cannot write
over each other. The second says that a session is using the tree right now.
Every session holds the second one, shared with all the others, from its start
until it ends. A session that is killed still lets go, because the kernel
releases the lock when the process ends.

**So a tag that moves is not picked up until the last session using the old tree
has ended.** A session that asks for a different image in that directory is
refused at its first second, with a line naming the image and saying to run it
again later. This is a trade and it was chosen:

- A tree replaced under a running session takes every remaining tool call of it
  with no warning, perhaps an hour into the work, and that session cannot
  recover.
- A session refused at its first second has lost nothing, and the sentence says
  what to do.

Two sessions on the same image are unaffected, which is the ordinary case. Only
a session that needs *different* files in the same directory waits, and it waits
by being told rather than by standing still.

A tree named after the digest would remove the wait, because two digests would
be two directories. Chock does not do that for one reason: a tree that nothing
removes grows without bound, and the process that would remove one needs this
same lock to know that no session is on it.

## The writable directory

A toolchain needs a writable directory that is not your project. Without one
`zig build-exe` answers `AppDataDirUnavailable`, and Cargo, Go, npm and pip
each fail in their own words. Chock gives a `run_command` call one, at
`/run/chock/cache` inside the sandbox, with `HOME` and `XDG_CACHE_HOME` in it.
Those two names are all it sets: every toolchain reads one of them, so a
compiler Chock has never heard of works too.

The host's own `HOME` never reaches a tool call, and that is deliberate. It is
what keeps an API key in your own shell away from the agent. The fault this
directory fixes was that nothing was put in its place.

The directory is `~/.local/share/chock/cache/<project>/`, **never inside your
project**, so nothing of it reaches your diff. It is kept between sessions,
because an agent that compiles the world again every session is not usable,
and `chock run` says so the first time a project gets one.

At most 2 GiB per project. A cache over that is emptied at the start of the
next session, and the session says so: a cache is rebuildable by definition,
so the only cost is building it again.

```
chock cache                         # what it holds, and the bound
chock cache clear
```

**It is writable for every `run_command`, and it outlives the session**, which
makes it a place an agent can leave data. No other tool call carries it: a
`write_file`, a `grep` or a `read_file` call is built with a mount tree that
has no cache in it at all.

## The other writable paths

| Path in the sandbox | What it is | Mode |
|---|---|---|
| the project's own path | the throwaway workspace | read and write |
| `/run/chock/cache` | the toolchain cache above | read and write |
| `/run/chock/scratch` | this session's scratchpad | read and write |
| `/run/chock/tmp` | a capped tmpfs, and `TMPDIR` | read and write |
| `/run/chock/tasks` | the session's task records | **read only** |
| `/run/chock/memory` | the knowledgebase, on two tool calls only | see [memory.md](memory.md) |
| `/run/chock/tool-bin/<name>` | the one program this call runs | read only |
| each store path of the dev shell | the toolchain | read only |
| `chock.zon` | the project's own rules | read only |

`/run/chock/tasks` is read only on purpose, so an agent cannot edit its own
evidence.

**On macOS every path in that table below `/run/chock/` is the host path it
really is.** macOS has no bind mount, so nothing can be made to appear
somewhere else, and the mount list becomes a set of path rules instead. The
modes above are unchanged, the task records are still read only, and the
environment still names each directory, so nothing has to be learned twice: a
program reads `HOME`, `XDG_CACHE_HOME`, `TMPDIR` or `CHOCK_SCRATCHPAD` and gets
the right answer on both platforms. Two differences a person can see. An
absolute path a program writes into a file, such as a `compile_commands.json`
or a debug binary's `DW_AT_comp_dir`, names a session directory that is deleted
when the session ends. And there is no `/run/chock/tmp`, because an ordinary
user on macOS cannot mount a filesystem and so no area can be capped: `TMPDIR`
names the scratchpad there, so a temporary file survives the call that wrote
it. `chock doctor` reports the second as `disk cap tmpfs: NONE`.

Free space is checked before a session starts, against a floor of 1 GiB. See
`chock doctor` in [sandbox.md](sandbox.md).
