# The threat model

**Chock assumes a hostile model, not a careless one.** `SECURITY.md` says it in
one line: "Chock runs a language model that writes and runs code. The model is
not trusted." The sandbox is not built to catch a mistake. It is built for a
model that means to escape, whatever put that intent there: a prompt hidden in
a file the model read, a dependency that talks back, or the model's own
behaviour with no outside cause at all. The document does not try to tell those
apart, and neither does the sandbox. It treats every tool call as if it might
be adversarial and holds the same layers either way.

**A hostile repository is in scope only through the model.** Chock does not
defend a maintainer against a pull request. It defends the rest of the machine,
and the user's real project, against what a model does after it reads one. The
repository itself is never trusted with more than the workspace copy it is
given, and the real project is never the thing a tool call writes to. See
"Where the boundary is" in `SECURITY.md` and "The workspace" in
`docs/sandbox.md`.

**A person approving an action is trusted, and the log that records the
approval is the evidence, not the model's account of what happened.** See "A
model's own statement about what it did is not evidence" in `SECURITY.md`.

## One attack, walked end to end

This is a real fault, found and fixed in this project, not a hypothetical.

`applyDenyMounts`, in `lib/chock-sandbox/linux/namespace.zig`, is what turns a
project's `deny_read` entry into a mount that hides a path from a tool call. A
project writes `deny_read: [".env"]` in `chock.zon` because it does not want an
agent to read that file even inside the throwaway workspace, and Chock answers
by binding an empty notice file over it, so a read returns a fixed message
instead of the file's contents.

The function used to do this in two steps, each one by name:

1. Call `existingPathKind` on the path `.env` resolves to, to learn whether
   something is there and what kind it is.
2. Call `mountCall` to bind the notice file onto that same path, again by name.

**The window is between those two calls, and `mount` is what makes it
dangerous.** `mount` follows a symbolic link at its target the same way `open`
does. If `.env` is a symlink whose target lies outside the workspace, either
because the project shipped it that way or because a tool call earlier in the
same session created it, the bind lands on whatever that link points to, not
on the name the project wrote. A directory the project never asked to touch
gets a notice file mounted into it, and mounting is a write. The two calls
being sequential does not by itself create the hole. What creates it is that
each call resolves the name freshly, so nothing guarantees the second
resolution lands on what the first one inspected.

**Checking twice does not close this.** A caller might try `statx` before the
mount and `lstat` after, comparing the two, and conclude the mount is safe
because both readings agree. That comparison only detects a change that
already happened. It cannot stop the mount from being issued in the first
place, because `mount` itself still resolves the name a third time when it
runs, independent of either check. Two name based checks around a
name based mount are three name resolutions of the same mutable path, not one.
Nothing pins any of them to the same inode.

**The fix pins the inode before the mount, and never resolves the name
again.** `pinDenyTarget` opens the target once with
`O_PATH | O_CLOEXEC | O_NOFOLLOW`. `O_PATH` gets a descriptor without reading
through the file. `O_NOFOLLOW` is supposed to refuse a symlink, and mostly
does, but not at the last path component when `O_PATH` is also set:

**`open` with `O_PATH | O_NOFOLLOW` on a symlink leaf succeeds.** It hands back
a descriptor on the link itself, not on whatever the link points to, and it
does not fail. A caller that treats a clean return from that `open` as proof
the target is an ordinary file is wrong, because a symlink leaf gives a clean
return too. The refusal has to come from a second call: `statx` on the
descriptor, with `AT_EMPTY_PATH`, reading the mode of what the descriptor
itself names rather than looking the path up again. Only that call's `S_IFLNK`
check catches the symlink, and it catches it without ever resolving the
original path a second time, because it asks the descriptor about itself.

Once the descriptor is confirmed to be a regular file (or freshly created,
through `O_CREAT | O_EXCL` on the parent directory, when nothing was there
yet), `applyDenyMounts` mounts through `/proc/self/fd/N` rather than through
the original path string. `/proc/self/fd/N` names the exact inode the
descriptor holds, so whatever the path `.env` resolves to by the time `mount`
actually runs, the bind lands on the file that was checked and nothing else.

**The source has no second name. The target still does.** `applyDenyMounts`
passes the target path as a name, both to the `mount` call that makes the
bind and again to `markReadOnly`, which remounts it read only afterward. A
target renamed between those two calls does not reopen the hole this section
describes, because a target name only decides where the fixed, already
checked source lands. `markReadOnly`'s own lookup either finds the mount
`applyDenyMounts` just made or finds nothing there at all, and the second
case answers `EINVAL`, which this code reads as a fault and aborts on rather
than pressing ahead. Fails safe, not free of a second name.

The lesson generalises past this one function: a security check on a path
name and an operation on that same path name are two different lookups unless
something pins them together. Comparing the results of two lookups after the
fact is not the same as making a third lookup impossible.

## Boundary and hardening are not the same claim

A boundary is enforced by the kernel and a defeated boundary is a security
bug. Hardening raises the cost of an attack that has another way through, and
a relaxed hardening setting is a known, named trade a project made on purpose,
not a broken sandbox.

The write-and-execute rule in the seccomp filter is hardening, and
`docs/sandbox.md` and `SECURITY.md`'s own scope list say so directly: a page
that is both writable and executable is not, by itself, an escape. `chock
doctor` reports a `write^execute` row in state `OFF`, with a note that this
project's policy allowed it, when a project turns the rule off for a JIT
runtime such as V8, and the red team oracle in `test/redteam/scope.zig` is
written to agree: a session
that relaxed this rule and did nothing else must never be scored the same as
a session that broke out. Landlock, the namespaces, and the 30 seccomp calls
that kill the process outright are boundaries. Their absence, or a kernel that
degrades one of them, is what `chock doctor` reports as a blocking row, and
what a real defeat of one of them is a security bug under `SECURITY.md`'s own
definition.

Reading a relaxed boundary and a relaxed piece of hardening as the same kind
of fact is the mistake this section exists to prevent. A project that allows
`sandbox.jit` has made one specific, logged, reviewable trade. A project whose
Landlock ruleset failed to load has no sandbox at all.

## What is not covered

A threat model that only lists what holds is marketing. These are measured
gaps, not a hedge.

**macOS has no system call filter, and this is permanent, not a missing
feature.** `(deny syscall-unix (syscall-number 26))` compiles in a Seatbelt
profile, applies with no error, and `ptrace` still returns 0. Only the
blanket `(deny syscall-unix)` has any effect, and that also blocks `execve`,
which every tool call needs to start a program at all. So the layer that
caught an io_uring bypass on Linux, `docs/sandbox.md`'s own seccomp section,
has nothing that plays its role on macOS.

**macOS has no bind mount, so there is no capped scratch area.** Every path
Chock would place under a mount point on Linux instead appears at its own
real host path on macOS, because there is no `pivot_root` and no ordinary
user can mount a filesystem to cap it. A file a tool call writes through
`TMPDIR` or `CHOCK_SCRATCHPAD` survives the call. `lib/chock-core/scratchpad.zig`
names both.

**`sysctl-read` is granted by default on macOS, and a program can read the
host process table through it.** `KERN_PROC_ALL` names every process on the
machine, in one call, and the answer runs to roughly 192 kilobytes on an
ordinary desktop. Darwin has no PID namespace to hide that table behind, and
taking `sysctl-read` away breaks ordinary software that expects to enumerate
processes, so it stays granted. The program still cannot act on any process
it sees this way. It can only see that the process exists, under what name.

**An MCP or plugin tool is gated once, at session start, and never again.**
`chock_core.mcp.Session.admit` decides each declared tool against
`mcp.<server>.<tool>` before `Loop.run` ever takes the session log's lock, and
it never consults an arbiter, because there is nobody to ask yet. A policy row
of `ask` for one of these tools is not deferred to a person. It is read as a
refusal, once, for the rest of the session, and the tool is never offered. A
`restrict_self` call made mid session cannot narrow this either, in either
direction: the admission already ran before the loop started, and nothing
about an MCP or plugin tool call reaches `Broker.request` a second time to
read a fresher answer. `lib/chock-core/Loop.zig`'s own `gateToolCall` states
both limits next to the code.

**As of this milestone, a foreground tool call holds a network descriptor
whether or not any policy rule grants a host.** `lib/chock-core/tools.zig`
gives every foreground tool call `Network.filtered` unconditionally, so the
sandboxed process always has the one connected descriptor a filtered process
uses to ask for a connection, even in a session whose policy table grants no
host at all. The descriptor being present does not mean a connection happens
on its own, but it does not mean a host with no rule stays out of reach
either. A host no rule names resolves to `ask`, the same as any other
unnamed action, and that `ask` reaches a person, through the same wait every
other mid session approval uses. A person who answers yes makes the
connection happen, so a foreground call on a project with an empty policy
table can still reach any host at all, one approval at a time. The file
descriptor itself is there from the first foreground call onward, on every
project, whether or not the project has ever named a host. A background
`run_command` call and a language server do not get this. A background call
is reset to `Network.none` before it starts, because nothing today can carry
an `ask` question out of a task with no turn of the loop waiting on it, and a
language server gets `Network.none` because nothing it does needs a socket.

If any of the five points above stop being true, this document is wrong until
it is corrected. Each one was checked against the code, not carried forward
from an earlier note.
