# The microVM driver

A way of sandboxing is a driver, and a driver is a value: `Sandbox.Driver` in
`lib/chock-sandbox/Sandbox.zig` holds a name, what it guarantees, what it can
express, and four calls. `native_driver` is the one for the machine Chock was
built for, and it is what every caller that names none gets.

## A guest is a layer, not an alternative

A microVM driver does not replace the Linux driver. It runs it.

A guest has a kernel of its own, so namespaces, seccomp, Landlock and cgroups all
work inside it, and `lib/chock-sandbox/linux/driver.zig` runs in there unchanged.
Mirage's own design says a guest is root inside itself, which is exactly why Chock
still sandboxes in there. The boundary a tool call gets inside a guest is built
from the same `Config` by the same code.

Two things follow.

**It is less work than it looks.** The driver boots a guest, gets the dev shell
closure into it, and then runs the driver that already exists. It is not a second
implementation of the boundary.

**macOS gains the Linux sandbox.** The native Darwin driver expresses none of the
five things `Sandbox.Expresses` names: it has no bind mount, no capped area, no
`procfs`, no cgroup placement and no device passthrough. A Mac running a Linux
guest has all five. That is why the table in
[sandbox.md](sandbox.md#what-spawn-refuses-and-why-a-session-still-runs) is the
native driver's limit and not the platform's, and it is the strongest reason to
want this at all.

## What runs inside: `chock guest`

The guest's initrd carries a Linux build of the one `chock` binary and runs
`chock guest` in it. Not a second program: Chock installs one artifact and no
helper beside it, which `test/plugin/one_binary.zig` pins.

`chock guest` reads one request a line on descriptor 3, builds the `Config` that
request describes, runs the driver, and answers. That is all it does.

- **It resolves no name and opens no socket.** A tool call that reaches the
  network is handed a connected descriptor, made on the host. The guest writes a
  name; that crosses as Mirage's own `reaching` message; the host decides,
  resolves and connects. So a guest cannot ask for one host and be handed
  another, and a refusal reaches it as its stream ending and nothing else.
- **It holds no policy.** Every question was answered on the host before a
  request was written.
- **It must never grow a copy of `addressIsReachable`.** That check runs on the
  host, after a name resolves and after policy said yes:
  `lib/chock-broker/network.zig`.
- **One thread.** The driver forks, and a fork carries only the calling thread.

## What crosses, and what stays

`lib/chock-sandbox/vm/wire.zig` carries a `Config`'s geometry: the root, the
mounts, the rules, the areas, the working directory, the environment, the argv,
the limits, the seccomp options and the network mode. One JSON object a line, with
the message and its newline written together.

The rest of `Config` stays on the host, and none of it is a gap:

| Left behind | Why |
|---|---|
| `net_broker`, `net_router`, `device_source` | function tables in the host's own address space |
| `stdout_fd`, `stderr_fd`, `stdin_fd` | the streams are carried by the channel the request came on |
| `containment` | a supplied cgroup names a directory of the host's, so it is refused |
| `landlock_report`, `limits_report`, `supervisor_audit`, `syscall_audit` | pointers the host reads after the call; the contents come back in the answer |

A field added to `Config` and forgotten there fails a test rather than silently
not crossing.

The seccomp trap set crosses **by name and never as a bit mask**. A
`std.EnumSet`'s shape is one build's own member order, and two builds that
disagreed about that order would agree about the number. A name the reader has no
member for is refused, because running a call with a smaller trap set than the
host asked for is a weaker boundary than the caller believes it has.

## Where a host path is inside a guest

A guest mounts one virtiofs filesystem, and every directory the host offered it
appears as a name inside it. So `/nix/store` on the host is `<root>/store` in
there, and `lib/chock-sandbox/vm/shares.zig` rewrites one into the other.

**The share set is given and never derived.** `Config.mounts` holds one entry per
store path, which is thousands for a real dev shell closure, and a guest takes 32
offers. So the set is what the session already knows: the store read only, the
workspace writable, the cache writable. Deriving it from the mounts would either
exceed the bound or merge paths of different writability into one name, and the
second is worse.

Two things are refused rather than run, both before anything reaches the wire:

- **A path no share holds.** Left as it was it would name a path the guest does
  not have. Worse, it could name one the guest does have for another reason, and
  then the sandbox would bind something nobody offered.
- **A mount that writes into a read only share.** A share's writability is what
  the guest's own kernel may do; a mount's `read_only` is what the sandboxed
  program may do. A writable mount inside a read only share is a sandbox that
  cannot come up, and answering it silently would surface as a permission error
  inside a tool call that nobody could trace back to here.

An overlay's upper layer and work directory must be writable **whatever the mount
says**, because overlayfs writes to both regardless.

**Targets are never rewritten.** A path inside the sandbox means the same thing in
a guest, which is what keeps the path in a compiler message one the user can open.

## What the host driver refuses

`lib/chock-sandbox/vm/driver.zig` is one `Sandbox.Driver` over the stream `chock
guest` opened. Its `guarantees` is read from the Linux driver rather than written
again, because that is the code which will run. Besides the two share faults it
refuses three things:

| Refused | Because |
|---|---|
| a supplied cgroup | the descriptor names a directory of the host's, and a guest places a call in one of its own |
| a device tree | a host device node is not in a guest |
| a `Middle` handle | the process to signal is in the guest, and this driver holds no handle on it |

The last one is a refusal rather than a handle that signals nothing.

## The tier this does not raise

Mirage's run path is tier 0: the VMM maps guest memory, so a compromised VMM can
read the guest. **Nothing here promises otherwise.** `Containment` is cgroup
placement and not a security level, and the six `Sandbox.Guarantee` values are
network, signal and IPC isolation, path and syscall restriction, and workspace
mounting. There is no memory confidentiality guarantee to break, and Chock's
threat model is an untrusted agent inside a trusted host:
[threat-model.md](threat-model.md).

## Who chooses the driver

**Not the project.** A project may only narrow what it may do, and a project that
could name its own sandbox driver could name a weaker one, which widens. So the
choice is the operator's, in `config.zon`, and an organisation bundle can pin or
forbid it the way it already does for a search engine's kind. A `chock.zon`
setting here would be a hole: see [policy.md](../configure/policy.md) for the
ratchet.
