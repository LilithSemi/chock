# The sandbox

Every tool call runs inside a sandbox, in a throwaway copy of the project. Your
real project is never written by a tool call. This page says what the boundary
is made of.

**The layers below are the Linux ones.** macOS builds the boundary a different
way, out of Seatbelt, and it gives less. See
[The sandbox on macOS](#the-sandbox-on-macos-and-what-it-does-not-do) for what
it holds and what it cannot.

**The layers are separate on purpose.** Each one is measured, each one can be
absent on a given machine, and `chock doctor` says which are on. A red team run
on 2026-08-22 set up an io_uring ring inside a tool call, which is the classic
way past a system call filter, and the paths were still refused by Landlock and
the network was still unreachable. That is what layers are for.

## Namespaces

One `unshare` call takes them all.

| Namespace | When |
|---|---|
| user | always, with no option to turn it off |
| PID | always |
| IPC | always |
| mount | on by default |
| network | on by default, and a policy rule is what opens it |

There is no UTS namespace and no cgroup namespace. `sethostname` is refused by
the seccomp filter instead.

After the `unshare`, Chock writes `setgroups=deny`, then maps your uid to
itself and your gid to itself. **Nothing maps to root.**

The mount namespace is what lets the workspace appear at the project's own
path, so a compiler that writes an absolute path into an error message writes
the path you would expect, and nothing else of the machine is in the tree.

## The network

A tool call gets a fresh network namespace. **Nothing brings an interface up in
it.** Chock configures no interface at all, so a call reaches no host.

There are three modes, and a tool call gets the first:

- `none`, the default. No route out at all.
- `filtered`. The same closed namespace, plus one descriptor to a broker
  passed in over a socket, so a named connection can be brokered against the
  policy table. In practice this is set only when a rule allows an MCP
  server's `net.connect`.
- `host`. The host's own namespace, with nothing removed. `chock doctor` uses
  this for its own probes.

`fetch_url` does not work by opening the sandbox. The broker reads the page in
a process the agent cannot reach, and the host is a row on the policy table.
See [policy.md](policy.md).

So a program that opens a socket in a tool call fails. `ping` answers
`socktype: SOCK_RAW` and exits 2, and `curl` cannot resolve a name. **That is
the boundary and not a fault in the command.** Chock says so in a line of its
own beside the result, because the program's own words do not.

## Landlock

Landlock is the kernel naming which paths a tool call may open, in the kernel
rather than in Chock.

Chock asks the kernel which ABI it has and takes the answer, rather than
requesting a version. The ruleset then handles **every filesystem right that
kernel knows**, masked to the ABI it reported, because an unhandled right stays
permitted everywhere. Rights the running kernel does not have are masked out of
each rule and reported back, so a session on an older kernel says what it did
not get.

Three grant sets are used: read only, read only for one regular file, and read
and write. Only `LANDLOCK_RULE_PATH_BENEATH` rules are written.
`PR_SET_NO_NEW_PRIVS` is set first.

**A kernel with no Landlock is a hard failure, and not a quiet downgrade.**
`Sandbox.spawn` refuses rather than running a tool call with one layer silently
missing.

## seccomp

The filter is a denylist. It reads the audit architecture first and kills a
foreign one before it reads a system call number, and on x86_64 it kills an x32
call as well.

**33 calls are blocked, and a blocked call kills the process.** Not an errno: a
program that meant to escape does not get to handle the failure. The groups
are:

- namespace escape: `unshare`, `setns`
- the whole mount family, `mount` through `open_tree_attr`, and `pivot_root`
  and `chroot`
- modules and kexec: `init_module`, `finit_module`, `delete_module`,
  `kexec_load`, `kexec_file_load`
- keyrings, after a fresh session keyring is joined: `add_key`, `keyctl`,
  `request_key`
- process introspection and injection: `ptrace`, `process_vm_readv`,
  `process_vm_writev`, `bpf`, `userfaultfd`
- the machine: `reboot`, `syslog`, `sethostname`
- **io_uring**: `io_uring_setup`, `io_uring_enter`, `io_uring_register`

io_uring is blocked outright because a ring lets a kernel worker perform the
operation, so the filter never sees the system call at all.

Four rules inspect an argument and answer `EPERM` instead of killing, so a
program can recover: `personality` asking for `READ_IMPLIES_EXEC`, `shmat` with
`SHM_EXEC`, and `mmap`, `mprotect` or `pkey_mprotect` asking for a page that is
both writable and executable. **That last one raises a cost and is not a
boundary**, and the code says so with three measured ways past it. io_uring
being blocked is the stronger statement.

## The workspace

The workspace is a throwaway copy, and the caller never chooses which kind it
gets:

- **A git project gets a linked git worktree**, detached at HEAD. A linked
  worktree records nothing about the process that made it, so it costs no git
  command to hand one to another process.
- **Anything else gets an overlay**, with your project as the read only lower
  layer. On Linux that is overlayfs. On Darwin it is a `clonefile` copy.

By default the agent sees the committed state. `chock run --allow-dirty` copies
your uncommitted work in as well.

Work reaches your project only when the agent commits it in the workspace
**and** the policy permits the apply. See [approvals.md](approvals.md).

## What is in the tree, and what is not

The mount set of a tool call is built per call, and the tools do not share one.
The read only toolchain is this project's Nix dev shell closure, each store
path at its own path, so the rest of the Nix store is not there. `/proc` is a
fresh procfs, read only, with 22 entries masked. `/run/chock/tasks` is read
only, so an agent cannot edit its own evidence.

**The credential store is never mounted in.** It is a file in the data
directory, and no mount ever names that directory. Two per project
subdirectories below it are mounted, the knowledgebase and the toolchain cache,
and binding a subdirectory does not expose its parent. The knowledgebase is
mounted for `read_memory` and `write_memory` and for no other call, so it is
not merely read only to the rest of the sandbox: it is not there.

The full list is in [toolchains.md](toolchains.md). Paths a project denies by
name are covered before the workspace is built, and their bytes are not in the
tree at all. See [policy.md](policy.md).

## Limits

Two mechanisms, and the smaller one always applies.

**cgroup v2** is the better answer, and it needs the `memory` and `pids`
controllers, both, delegated to a directory Chock can make its own below.
Chock never writes `subtree_control` itself. It sets `memory.max`,
`memory.swap.max` to zero, and `pids.max`. After a call ends it reads
`memory.events` and `pids.events`, so a bare SIGKILL can be named for what it
was.

`cpu.max` is deliberately not set. It throttles rather than refuses, which
turns a clear failure into a slow program that dies on the wall clock deadline
instead.

**cgroups are best effort and never a refusal to run.** A machine without them
still gets the second mechanism, and `chock doctor` says which half it did not
get.

**The rlimit floor** needs nothing at all, so it always applies. It is set last
in the child, immediately before the program runs.

| Limit | Default |
|---|---|
| core dump | 0 |
| data segment | 16 GiB |
| open files | 1024 |
| file size | 1 GiB |
| CPU seconds | 3600 soft, 3630 hard |
| processes | 256, on kernel 5.14 and above |
| memory, through cgroup | 2 GiB |
| a scratch tmpfs | 256 MiB |

Soft equals hard everywhere except CPU, because `prlimit64` is not blocked and
a soft only limit would be raised back in one call. CPU keeps a 30 second gap
so the first signal is `SIGXCPU` and not `SIGKILL`.

`RLIMIT_AS`, `RLIMIT_STACK`, `RLIMIT_RSS`, `RLIMIT_MEMLOCK`,
`RLIMIT_SIGPENDING` and `RLIMIT_MSGQUEUE` are not set, each for a reason
written next to it in the code.

A project's `chock.zon` can lower any of these and can never raise one. It is
the same ratchet the policy table keeps.

## The sandbox on macOS, and what it does not do

**A session runs on macOS, with four layers on.** Seatbelt holds the paths, the
network including unix sockets, the signals and shared memory. Darwin's own
resource limits bound what a program can consume. The driver declares exactly
four guarantees, and a test on a real Mac tries to break each one. See
`test/sandbox/darwin_escape.zig`:

| Guarantee | On macOS |
|---|---|
| `network_isolated` | yes |
| `signal_isolated` | yes |
| `ipc_isolated` | yes |
| `path_restricted` | yes |
| `syscall_restricted` | **no, and it is permanent** |
| `workspace_mounted` | **no, and it is permanent** |

**A layer this driver reports as on, and does not enforce, is worse than a
refusal.** A refusal cannot mislead anybody. Chock compares a policy against a
driver and refuses a driver that claims too little, but it trusts a driver that
claims too much. So every claim above comes from a measurement on Apple
Silicon, macOS 15.7.9, arm64. Two layers were tried and then dropped:

- **There is no system call filter.** `(deny syscall-unix (syscall-number 26))`
  compiles, applies, and `ptrace` still returns 0. Only the blanket
  `(deny syscall-unix)` has an effect, and that stops `execve`, so it cannot be
  used.
- **The other processes of the machine are not hidden.** A sandboxed program
  reads the whole host process table through `sysctl KERN_PROC_ALL`, and taking
  `sysctl-read` away stops ordinary software starting. Darwin has no PID
  namespace. The program still cannot **act** on any process it sees.

### What `spawn` refuses, and why a session still runs

macOS has no bind mount. A path means the same thing inside the sandbox and
outside it only when nothing was remapped, and remapping is what a mount
namespace does. So `spawn` refuses a config that needs a mount tree, by name,
before it allocates anything and before it forks:

| Refused | Because |
|---|---|
| a root that is not `/` | there is no `pivot_root` |
| a bind whose target is not its source | this is the mount gap itself |
| an overlay mount | macOS has no overlayfs |
| a procfs mount | macOS has no procfs, and no PID namespace |
| a capped scratch area | an ordinary user cannot mount a filesystem, so there is nothing to cap |

The capped scratch area is refused and not quietly left out. A caller that asked
for a bounded writable area and got an unbounded one would learn nothing until
the disk filled.

**A config whose every path stays where it is does run.** That is what
`Layout.in_place` builds in `lib/chock-workspace/layout.zig`: the checkout, the
project's own `.git` and the scratch object store each keep their real path, so
the workspace becomes a set of rules instead of a set of mounts. This is why
`workspace_mounted` is absent and a tool call still works.

Two things follow from having no mount tree. An absolute path that a program
writes into a file names a directory that is deleted with the session. `TMPDIR`
and `CHOCK_SCRATCHPAD` name one directory, and a file written through either
survives the call. `chock doctor` reports both.

## Checking a machine

```
chock doctor
```

`chock doctor` measures each layer for real, in a forked child, because a user
namespace and a seccomp filter cannot be undone. It does not infer anything
from a kernel version.

| Row | Blocks a session |
|---|---|
| user namespace | yes |
| mount namespace | yes |
| pid namespace | yes |
| ipc namespace | yes |
| net namespace | yes |
| landlock, with its ABI number | yes |
| seccomp | yes |
| pidfd | yes |
| disk cap tmpfs | yes |
| overlayfs | no, only a project with no git needs it |
| cgroup v2, with the vantage it found | no, it degrades |
| nix | no |
| dev shell | no |
| credential | yes, when one is configured and unreadable |
| toolchain cache | no |
| workspace space, against a 1 GiB floor | no |
| card seal | no |
| audit sink, one row per required sink | no |

It exits `0` when a first run can work here, even with a row degraded, and `2`
when a blocking row is off. A machine that works with a layer missing gets one
answer for a script and the whole report for a person.

`pidfd` is there so a cancelled tool call is signalled by handle. A late cancel
then reaches nothing, rather than a stranger that took the same process id.
