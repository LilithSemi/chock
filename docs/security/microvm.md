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

## The guest image, and two things measured about it

`pkgs/chock/guest.nix` builds two derivations, `packages.guest-kernel` and
`packages.guest-initrd`, after the shape of
DeterminateSystems/cloud-hypervisor-guest's own `bootinfo.nix`: a 6.1 LTS kernel
and an uncompressed initrd from `makeInitrdNG`.

**The guest-side drivers are modules, not built in.** On this machine's own kernel
`CONFIG_VIRTIO_FS`, `CONFIG_VSOCKETS` and `CONFIG_VIRTIO_VSOCKETS` are all `m`, so
an initrd that carries no modules boots a guest that can neither mount a share nor
open a channel. The initrd carries them, and the init loads them by name. A name
built into the kernel rather than shipped as a module is not an error: on this
kernel the virtio mmio transport is built in and the mount works anyway.

**Only the modules the guest needs.** A root holding a kernel's whole module tree
is a 146MB initramfs, and one that size does not unpack: the guest came up,
`/lib/modules` was present, and every file under it was missing. The same root
with six modules in it, 2.4MB, mounted its share and got its vsock device. So the
initrd is built with `makeModulesClosure` over five names rather than the tree.

Both mechanisms are proven on aarch64 under KVM: a guest read a file the host
offered through the virtiofs share, by the name the host gave it, and `/dev/vsock`
appeared once the three vsock modules loaded.

## What runs the guest: a thread of the daemon's

Mirage is a library, so Chock is the process that runs a guest, and that process is
`chock daemon`. A guest is one thread of it: one CPU, a console, a channel, and the
directories the guest may mount. There is no subcommand and no second process, and
nobody starts a guest by hand.

**The tick is what made a separate process look necessary.** A guest blocked on its
channel exits for nothing, so the host loop needs interrupting or a waiting guest
waits for ever. Mirage arms a process wide `setitimer`, which is right for a program
that is only a VMM and wrong inside the daemon: every accept and every file read
there would answer `EINTR`. So Chock's copy runs a ticker thread that signals **one**
thread by its own id, with `tgkill`. Nothing else in the process is touched, and the
handler does nothing: the interruption is the whole point of it.

**This is a copy of Mirage's own machine setup, and that is a cost taken
deliberately.** Mirage's `run` is 628 lines in its `src/` that nothing in its
`lib/` wraps, so a caller either copies it or asks Mirage for a library entry
point. Two things bound the cost:

- **The copy is smaller than the original on purpose.** Chock needs a machine, a
  console, a channel and shares. It does not need snapshots, firmware, a security
  chip, a balloon, a disk or a network device, because a tool call reaches the
  network by naming a host and that crosses as Mirage's own `reaching` message.
  Each one left out is one less thing to keep in step.
- **The drift is detected, because it cannot be prevented.** `mirage_surface` in
  `src/vmm.zig` names every Mirage declaration the copy reaches, and a test
  asserts each still exists. An upgrade that renames or moves one fails a build
  rather than leaving two versions of one loop that differ quietly.

A build that cannot run a guest compiles all the same: the module behind it answers
`available = false`, and the daemon reads that before it offers a session a guest. A
guest needs KVM and the aarch64 device layout.

Proven on aarch64 under KVM: a guest booted, mounted the share, listed it by the name
the host gave it and read the file inside, `/dev/vsock` was there, and the run
answered 0. The session socket exists while the guest runs and is unlinked when it
ends.

Then through the daemon: it started the guest on its own thread, bound the session
socket, and answered ten control requests in a row while that guest was being ticked
a hundred times a second. That last part is what the thread targeted tick is for.

**A guest socket goes beside the daemon's own and not beside the session's log.** A
unix socket path is bounded at 108 bytes and a log path is a state directory, a
project directory and a session identifier: one real path came to 132 and `bind`
refused it, saying only that nothing could hold a session there. The daemon now
measures the path and names the number.

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

## Who owns the guest, and for how long

A session started by `chock run` on its own owns its guest: that process lives for
the whole session. Under the daemon it does not, because a `chock run` child exits
at the end of every turn, so there the daemon owns it and hands the child a socket.

**`chock run` reads `.sandbox.driver` itself.** It has to: a session that answered
`native` because nobody handed it a socket would be sandboxed more weakly than the
operator asked for, silently, which is the one thing every refusal here exists to
stop.

A guest's console goes to `<session>.guest-console` beside the session's log, and
never to standard output: the agent's transcript is there, a kernel boot interleaved
with it is unreadable for both, and a session whose display owns that stream threw
the whole boot away.


`chock run` exits at the end of every turn, so a guest it owned would boot and die
each time. The daemon owns it instead. That also keeps the vCPU threads out of the
process that dispatches tool calls: that one forks, and a fork carries one thread.

- The daemon starts the guest's thread before the turn's child, waits for the guest
  to say its socket is bound, and passes the child `--guest <socket>`.
- The child connects, offers the guest this session's own directories, takes one
  stream into it, and every tool call from then on goes through that stream.
- **A guest that cannot be reached is a refusal and never a fallback.** Falling
  back to the native driver would sandbox the session more weakly than the
  operator asked for, and on a Mac far more weakly, with nothing saying so.

**The guest is kept for a while after a turn and then let go.** Five minutes, unless
another turn arrives first. That is a window and not a session end event, because the
daemon has none: `session.end` is written at the end of every turn and a session can
be taken up again with `--adopt`, so nothing in the log says a session will never run
another. The window covers the turns of one conversation, and letting it go bounds
what a daemon left running holds. A daemon holds at most four guests at once, since
each is a kernel and its memory.

## Two things that starve a guest

**A tick on every entry.** `setitimer` is delivered to whichever thread has the
signal unblocked, which is often not the one inside `KVM_RUN`; `tgkill` always hits
the one it names. That accuracy is a hazard: a guest signalled every 10ms answered
`EINTR` on all thirteen of its entries and executed no instruction at all. So the
ticker watches the loop's own count of turns and signals only a guest that has not
moved.

**Asking for the stream in a loop.** The session socket is bound before the guest
runs, so a caller that connects the moment it appears is talking to a guest that has
not booted. Retrying `channel` is worse than useless: every ask is work the guest's
own loop does instead of running the guest. A session that asked every 100ms starved
its guest to two productive entries in thirty seconds, where one left alone managed
371 in the same window. Mirage says when a guest is up, which is the first stream it
opens, so the host waits for that and then asks once.

Both were found by tracing `ioctl` and counting how many `KVM_RUN` calls came back
`EINTR`. Neither is visible from the outside: the guest simply produces nothing.

## How big a guest is

A guest gets processors and memory from the machine it runs on. `config.zon` can
name either, and a number in the file is used as it is.

```zon
.{
    .sandbox = .{ .driver = "microvm", .cores = 4, .memory_mb = 4096 },
}
```

With neither named, two curves choose:

```
processors = min(the core curve, the memory share / 512MB), and at least 1
memory     = max(512MB, min(processors * 1GB, the memory share))
```

The memory share is one eighth of the machine. The core curve is 12 processors at
24 cores or more, then 6 at 16, 4 at 12, 2 at 8, and 1 below that.

| The machine | Processors | Memory |
|---|---|---|
| 128 cores, 511GB | 12 | 12GB |
| 16 cores, 32GB | 6 | 4GB |
| 8 cores, 8GB | 2 | 1GB |
| 24 cores, 8GB | 2 | 1GB |
| nothing could be read | 1 | 512MB |

**One eighth, because the host keeps working while the guest runs.** The model
call, the terminal and the agent's own harness are all on the host. An eighth
leaves room for them on every size of machine one ratio has to cover.

**One gigabyte for each processor, because a build runner starts one job for each
processor.** A flat size does not say how many compilers can run at once, and that
is the number which decides if a build fits.

**The core curve alone was not enough.** A machine with 24 cores and 8GB gave a
guest 12 processors and an eighth of 8GB. A build then started 12 compiler jobs
into 1GB, and the kernel killed a compiler for memory instead of the build running
slowly. So the processor count is also limited by what the guest's share of memory
can feed.

**A guest with more than one processor must be woken before it is left.** Every
processor but the first waits inside the hypervisor until the guest starts it, and
the host hook which reads the stop flag only runs between exits. A processor the
guest never started therefore never sees the flag, and a join on its thread does
not return: `chock run` printed the end of the session and then hung. The host now
signals each waiting processor with the same signal the ticker uses, which makes
the hypervisor call return.

## What this does not do yet

**Tool calls are serialised.** One guest holds one stream and `chock guest` answers
one request at a time, so a background task waits for a foreground call where it
would have run beside it under the native driver. A guest answering several at once
needs a stream each, which `Client.channel` can give and this does not yet ask for.

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
refuses two things:

| Refused | Because |
|---|---|
| a supplied cgroup | the descriptor names a directory of the host's, and a guest places a call in one of its own |
| a device tree | a host device node is not in a guest |

Each refusal has an error of its own, and none of them is `Unexpected`: the tool
path shows a person the name of the error, and a refusal with a reason is the one
thing that is not unexpected.

## What the guest is offered, and who works it out

`shares.offersFor` walks the session's `Config` and offers one directory per
source it binds. **A set written out beside the mounts goes stale the moment a
mount is added**: the first one named the store, the workspace and the cache,
and a worktree session binds four more, so every call failed on the
repository's own git directory.

Two things keep the count inside a guest's 32 offers. Every path under the store
folds into one offer, which is what makes a dev shell closure of thousands of
entries a single name. And a source already inside an offer of the same
writability adds none.

**The store is offered whether or not the session's config names a path in it.**
The closure is bound per call, by `withStore`, so a set derived from the session
alone would hold no store when the first call arrived.

**Writability is never merged.** A writable directory inside a read only one
stays an offer of its own, because the share's writability is what the guest's
kernel may do and widening it to save a name widens the boundary.

## The two things a guest makes for itself

**The sandbox root.** `Config.root` names a directory the session made on this
host, and `namespace.buildRoot` binds it onto itself before it pivots. It is not
in a guest. The host sends `wire.guest_root` and the guest makes it.

**The files a call writes to.** A call's `stdout_fd` and `stderr_fd` are open
files of the host's. The guest gives the call two files of its own, and when the
call ends it writes one frame a descriptor, each naming a length and followed by
that many raw bytes, before its answer. The host passes them to the two
descriptors the caller gave.

Raw and not a field of the answer: a tool that reads a file keeps 4MB, and that
much text inside a JSON string is a line no reader here takes. A file and not a
pipe inside the guest, because the driver blocks until the process it forked has
ended and a full pipe would stop the call for good. **So output arrives when the
call ends and not while it runs.**

## How a call is cancelled

The tool path asks for a `Middle` on every call and ends a call through it, both
when a timeout runs out and when a person interrupts. So the driver fills one:
`fd` is the stream and `pid` is `Middle.elsewhere`, which says a call began and
that its process is not this kernel's to name.

`signalMiddle` writes one constant line on the stream, `chock guest` reads it
while the call runs, and the guest signals the process it forked.

**One stream and no second channel.** Between a request and its answer the host
writes nothing else, so anything the guest reads in that window is a cancel. The
guest reads it on a watcher thread, because the driver inside blocks until the
process it forked has ended. The thread is started once, before any call and so
before any fork, and it allocates nothing.

A cancel is written to the stream and not to a call, so with two calls queued it
reaches the one that is running. There is one guest and one stream, which is the
same reason calls are serialised at all.

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
could name its own sandbox driver could name a weaker one, which widens. A
`chock.zon` setting here would be a hole: see
[policy.md](../configure/policy.md) for the ratchet.

The choice is the operator's, in `config.zon`, which lives in the configuration
directory the sandbox puts beyond an agent's reach:

```zon
.{
    .sandbox = .{ .driver = "microvm" },
}
```

`native` is the other value and is the default, so a file that says nothing gets
today's behaviour. A driver this build has no name for is **refused**, and the
message lists the ones it has. A typo is never read as a choice: answering
`native` for `"microvms"` would run a session with a boundary the author did not
ask for.

An organisation narrows it in its bundle, the way it already does for a search
engine's kind:

```zon
.{
    .sandbox = .{ .drivers = .{ .microvm } },
}
```

A bundle naming only `microvm` means a session on a machine that cannot boot one
does not start, which is what requiring a guest means. **A bundle that says
nothing permits every driver**: absent is not empty, and an empty list would
forbid the driver every session uses today.

Choosing a driver adds a layer and takes nothing away. A guest has a kernel of its
own, so the driver that already exists runs inside it.
