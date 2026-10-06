# The microVM driver

A way of sandboxing is a driver, and a driver is a value: `Sandbox.Driver` in
`lib/chock-sandbox/Sandbox.zig` holds a name, what it guarantees, what it can
express, and four calls. `native_driver` is the one for the machine Chock was
built for, and it is what every caller that names none gets.

## A guest is a layer, not an alternative

A microVM driver does not replace the Linux driver, it runs it. A guest has a
kernel of its own, so namespaces, seccomp, Landlock and cgroups all work
inside it, and `lib/chock-sandbox/linux/driver.zig` runs there unchanged,
built from the same `Config` by the same code. Mirage treats a guest as root
inside itself, which is exactly why Chock still sandboxes inside it too.

Two things follow. It is less work than it looks: the driver boots a guest,
moves the dev shell closure into it, and runs the driver that already
exists, rather than building a second implementation of the boundary. And
macOS gains the Linux sandbox: the native Darwin driver expresses none of
the five things `Sandbox.Expresses` names, while a Mac running a Linux guest
has all five. The table in
[sandbox.md](sandbox.md#what-spawn-refuses-and-why-a-session-still-runs) is
the native driver's limit, not the platform's, and that is the strongest
reason to want this at all.

### Three places to get through, and two of them are not independent

Count the places, not the layers. A tool call told to escape has three to
get through. First, the sandbox inside the guest, `lib/chock-sandbox/linux/driver.zig`,
built from the same `Config` a native call uses. Second, the guest itself,
where escaping gives root in a kernel of its own with nothing of the host
inside it, needing a fault in the virtio devices Mirage places or in the
hypervisor under them. Third, the sandbox around the VMM,
`lib/chock-sandbox/vm/confine.zig`, which confines the process that runs the
machine to the directories it was granted and the calls it still needs.

The first and third are not independent. On a Linux host both are seccomp and
Landlock, so a bypass against Landlock could apply at both ends, and calling
them two layers would say more than is there. On a Mac the third is a
Seatbelt profile and the first is still the guest's own Linux, so there they
really are different mechanisms. The claim conceded here is the Linux one,
because that is the host every number on this page was taken on.

The middle place is independent either way, because it is a different kernel:
a hole in the guest's own Linux is not a hole in the host's. So the honest
claim is two independent steps rather than three layers, and the guest is the
step that adds the independence.

## The guest image

`pkgs/chock/guest.nix` builds two derivations, `guest-kernel` and
`guest-initrd`, shaped after DeterminateSystems' cloud-hypervisor-guest: a 6.1
LTS kernel and an uncompressed initrd from `makeInitrdNG`.

`CONFIG_VIRTIO_FS`, `CONFIG_VSOCKETS` and `CONFIG_VIRTIO_VSOCKETS` are modules
in that kernel, so the initrd must carry them and the init load them by name,
or a guest can mount no share and open no channel. `CONFIG_VIRTIO_MMIO` is
built in instead, and the mount works all the same: a name built in rather
than shipped as a module is not an error.

The initrd carries only the modules a guest needs, not a kernel's whole
module tree: the whole tree makes a 146MB initramfs that fails to unpack at
all, while a short named list comes to a few megabytes. `guest-initrd` is
built with `makeModulesClosure` over such a list, eighteen names today
covering the vsock channel, the virtiofs mount, `overlay`, the virtio
transports, and the netfilter modules a routed tool call's filtered network
needs. `modules-closure.sh` fails the build on a name that is neither a
module nor built in, so a wrong name breaks the build rather than shipping a
guest with a driver missing.

Two things in the image follow the guest's architecture rather than being
fixed: the kernel's own name, `bzImage` on x86 and `Image` on arm64, and its
console, `ttyS0` on x86 and `ttyAMA0` on arm, matching `src/vmm.zig`'s own
default cmdline. An architecture neither file names is refused rather than
given arm's.

### Where the images are built

A guest is Linux whatever the host is, which is why the microVM driver closes
the Darwin gap, but a Mac cannot build `x86_64-linux`'s module closure
itself: that needs an `x86_64-linux` remote builder in `nix.buildMachines`,
or the CI `ubuntu-latest` runner, which builds its own images natively.

A Mac instead takes the images from a release or a configured Linux builder,
naming the two files by their architecture's own names, `Image` and
`initrd`:

```zon
.{
    .sandbox = .{
        .driver = "microvm",
        .kernel = "/nix/store/<hash>-linux-6.1.182/Image",
        .initrd = "/nix/store/<hash>-initrd/initrd",
    },
}
```

Nothing reads the store path as a store path. The one test that boots a guest
takes the same two paths, because a build script cannot guess them:

```bash
zig build test-guest -Dguest-kernel=./result/Image -Dguest-initrd=./result-1/initrd
```

Without them, or with no `/dev/kvm` this user may open, it skips rather than
claiming a pass, inside `nix build` too rather than failing a branch there.
`whyNoGuest` in `test/cli/guest.zig` names every fact that can stop it.

## What runs the guest: a forked process of the harness's

Mirage is a library, so Chock is the process that runs a guest. Both `chock
run` and `chock daemon` fork one for it: one CPU, a console, a channel, and
the directories the guest may mount.

It runs in a process rather than a thread because a seccomp filter and a
Landlock domain go on a whole process and cannot be taken off again, so a
guest hosted on a thread would be confined only by confining the harness
alongside it. `vmm.forkHost` is the only way in, private to `src/vmm.zig` and
refusing a process that was not forked for it.

The host also needs to interrupt one thread rather than the whole process,
since this process also holds the virtiofs thread and the session thread, and
a process wide timer would answer every one of their reads with `EINTR` too.
So a ticker thread signals one thread by its own id instead, `tgkill` on
Linux and `pthread_kill` on macOS, which names a thread by its pthread
handle.

A build that cannot run a guest still compiles: the module behind it answers
`available = false`, and the daemon reads that before offering a session a
guest. `src/vmm.zig` names neither a hypervisor nor an architecture, so which
hypervisor, where the devices sit, and which interrupt controller the guest
gets all come from the target the build is for.

### Which platforms run a guest, and what each one has done

Three targets compile `src/vmm.zig`. Two have booted a guest.

- `aarch64-linux` boots a guest, against KVM, with the devices stated in a
  device tree. This is the development machine, every number on this page
  with no platform named was taken here, and it is the one platform where
  `chock daemon` has booted a guest for a real session.
- `x86_64-linux` compiles the VMM and has never booted a guest. The build
  targets KVM, which on x86 means its ACPI tables, its 16550 behind an I/O
  port, and the virtio-mmio-over-ACPI path. Nothing in this repository has run
  one: the development machine is aarch64, emulating a userspace proves
  nothing about a hypervisor, and a GitHub hosted runner exposes no
  `/dev/kvm`. So the x86 machine setup is held only by the compiler and the
  drift guards.
- `aarch64-darwin` boots a guest, given an ad hoc signature, against
  Hypervisor.framework. The binary must carry `com.apple.security.hypervisor`
  or the call that makes a machine answers `HV_DENIED` and says nothing more.
  See [what a Mac can do](#what-a-mac-can-do-and-what-it-cannot-yet) before
  trusting that a Mac runs your own toolchain in a guest.

A target Mirage has neither a machine nor an architecture for is refused at
compile time rather than given arm64 Linux's, so widening the set cannot
quietly place a guest in the wrong memory.

### Memory encryption, tried but never required

On `x86_64-linux` the guest's memory can be encrypted by the processor with
AMD SEV. It is attempted and never required, because the launch commands go
through `/dev/sev`, which usually only root may open. If it does not open, or
the processor refuses to make an encrypted machine, the guest comes up the
ordinary way and runs in the clear. Once an encrypted machine exists, a
failure ends the guest rather than falling back, because carrying on would
run it unencrypted while still reporting it as encrypted.

The launch policy is zero, which refuses guest debugging and key sharing, and
it is reported only when it is on: `chock run` and `chock daemon` print one
line naming the feature when a guest comes up encrypted, and nothing
otherwise, so a line never reads as a promise on a machine that has none.

Two limits stand out. This is `x86_64` only, and nothing here has run: no
machine in this project has booted an x86 guest, and no AMD machine with
`/dev/sev` has been available. And SEV-ES is not selected, on purpose: it
also encrypts register state and needs the guest to handle `#VC` exceptions
the guest kernel here is unverified for, so taking it automatically could
swap a guest that boots for one that does not, so choosing it is left to
whoever can test it. A daemon is the useful place to enable any of this,
since the forked process that runs a guest inherits its credentials.

### What Apple's hypervisor does not do that KVM does

`src/vmm.zig` names three gaps against KVM, each built rather than left out.
It makes no memory, so the VMM `mmap`s memory the calling process already
owns and hands it to the guest, the same tier 0 the Linux side is at. It
starts no other processor, so the VMM answers the power interface itself:
every processor but the first waits on a thread of its own and runs once the
guest says where to begin. And it holds no interrupt controller, so a
version 2 controller is built into the VMM, its two halves on the guest's bus
like any other device.

### The entitlement that makes it possible

The call that makes a machine needs `com.apple.security.hypervisor`, and
without it answers `HV_DENIED` (`0xfae94007`) and nothing else. An ad hoc
signature carries it, confirmed on macOS 15 arm64: the same binary answered
`HV_DENIED` unsigned and `HV_SUCCESS` after

```bash
codesign --sign - --entitlements <plist> --force <binary>
```

with the plist naming one key, `<key>com.apple.security.hypervisor</key>
<true/>`. No Developer ID is needed to run a guest on the machine the binary
was built on.

### The Seatbelt profile does not need widening

The Darwin arm of `lib/chock-sandbox/vm/confine.zig` closes the network
completely, and `(deny network*)` refuses a unix socket as well as IP, so
whether the session socket a guest is held on could still be reached was
worth checking directly.

It can. The socket is bound and listening before `sandbox_init` runs, and
Seatbelt checks `network-bind` and `network-outbound` rather than every later
use of a socket that already exists, so a guest driven by hand on macOS
15.8.1 dialled the host and ran a tool call under the profile with no change
needed to it. Neither `chock run` nor `chock daemon` has driven that path on
a Mac yet.

### What a Mac can do, and what it cannot yet

A Mac boots a guest and confines it, but a Mac has no Linux toolchain. A tool
call inside the guest needs Linux programs that a Mac's store does not have,
and nothing answers where they come from. The one tool call proven on a Mac
ran a static aarch64 Linux `busybox` that the host had put in the share on
purpose: a session's own `Config` on a Mac names the Darwin binaries of a
Darwin dev shell, and a Linux guest cannot execute one of those, so a reader
on a Mac should not finish this page believing their own toolchain runs in a
guest today.

Two routes toward answering it exist in part already: a Linux dev shell
closure built on a Linux builder and copied over, and a container image,
which `lib/chock-container.zig` already reads. Neither is wired to the
microVM driver yet. Also untested on a Mac: a tool call that reaches the
network, the five minute window and one turn a guest limit, and `nix build
.#default`, which cannot pass its own check phase there.

## What runs inside: `chock guest`

The guest's initrd carries a Linux build of the one `chock` binary and runs
`chock guest` in it. Not a second program: Chock installs one artifact and no
helper beside it, which `test/plugin/one_binary.zig` pins.

`chock guest` reads one request a line on descriptor 3, builds the `Config`
that request describes, runs the driver, and answers. That is all it does.

- It resolves no name and opens no socket. A tool call that reaches the
  network is handed a connected descriptor made on the host: the guest writes
  a name, that crosses as Mirage's own `reaching` message, and the host
  decides, resolves and connects, so a refusal reaches the guest as its
  stream ending and nothing else.
- It holds no policy. Every question was answered on the host before a
  request was written.
- It must never grow a copy of `addressIsReachable`, the check that runs on
  the host after a name resolves and policy says yes, in
  `lib/chock-broker/network.zig`.
- One thread. The driver forks, and a fork carries only the calling thread.

## What crosses, and what stays

`lib/chock-sandbox/vm/wire.zig` carries a `Config`'s geometry (root, mounts,
rules, areas, working directory, environment, argv, limits, seccomp options,
network mode, and whether to audit paths) and the time, as one JSON object a
line.

The time crosses because a guest has no clock: nothing in the machine Mirage
builds is a real time clock, so a guest starts at the epoch and a tool call
not told the time sees 1970, stamping a commit wrong or writing files older
than their sources. The host sends what its own clock says, in nanoseconds.

The rest of `Config` stays on the host, and none of it is a gap:

| Left behind | Why |
|---|---|
| `net_broker`, `net_router`, `device_source` | function tables in the host's own address space |
| `stdout_fd`, `stderr_fd`, `stdin_fd` | the streams are carried by the channel the request came on |
| `containment` | a supplied cgroup names a directory of the host's, so it is refused |
| `landlock_report`, `limits_report`, `supervisor_audit`, `syscall_audit` | pointers the host reads after the call, and the contents come back in the answer |

A field added to `Config` and forgotten here fails a test rather than
silently not crossing.

The seccomp trap set crosses by name and never as a bit mask, because a
`std.EnumSet`'s shape is one build's own member order, and two builds that
disagreed about that order would still agree about the number. A name the
reader has no member for is refused, because running a call with a smaller
trap set than the host asked for is a weaker boundary than the caller
believes it has.

## Who owns the guest, and for how long

A session started by `chock run` on its own owns its guest for the whole
session. Under the daemon it does not: a `chock run` child exits at the end of
every turn, so the daemon owns the guest instead and hands the child a socket,
which is also why `chock run` reads `.sandbox.driver` itself rather than
trusting the child to fall back to `native` silently if no socket arrives.

A guest `chock run` forked writes its console to `<session>.guest-console`
beside the session's log and never to standard output, because a kernel boot
interleaved with the agent's own transcript is unreadable for both. A guest
the daemon forked writes to the daemon's own output instead. `chock run` exits
every turn, so a guest it owns boots and dies with it, while the daemon owning
one is meant to save that boot and today does not, for the reason below, but
it does keep the vCPU threads out of the process that dispatches tool calls.

### How the daemon forks a guest

The daemon forks the guest before the turn's child, waits for its socket to
bind, and passes the child `--guest <socket>`. The fork runs on a thread whose
life is exactly the guest's, because `PR_SET_PDEATHSIG` fires when that thread
ends and not when its process does.

The grant is derived rather than written out, because the directories a
session offers do not exist yet when the guest is forked and a Landlock
domain can only be narrowed: `guestShares` in `src/daemon.zig` names the
roots those offers sit under instead. Every granted root is a path a
compromised VMM may mount, so the set stays small, fifteen roots at most:

- the toolchain, the store read only or up to nine system directories when
  there is no store (`max_granted_roots` in `src/daemon.zig`);
- the session's working directory, writable;
- the project's git directory, read only, or the project itself when it is no
  repository;
- the toolchain cache and the scratchpad, both writable;
- the knowledgebase, writable, when its notes directory could be made;
- the tree of an image a project names, when its `container` block names one.

A directory outside that set is refused where it is offered, with the path
named. A few roots are never granted at all. A project at or above Chock's
own configuration, data or state directory gets no session, because that
would put `credentials.zon` inside the grant: `chockOwnInProject` in
`src/run.zig` checks for it, and both the daemon and `chock run` refuse
before anything starts. A `workspace.binds` entry is refused outright under
the daemon too, since whether a session may have that host path is a policy
question the daemon does not answer, and `chock run` is offered instead. And
the dev shell's own temporary directory is granted to nothing, since its
evaluation runs on the host before any guest exists.

The session's socket itself sits beside the daemon's own rather than beside
the session's log, since a unix socket path is bounded at 108 bytes and a log
path can run well past that.

### Handing the guest to the child

The child connects, waits for the guest to say it is up, offers it this
session's own directories, and takes one stream into it that every tool call
then uses.

Waiting comes before offering, and the order is load bearing: the guest says
`up` on its first connection, and Mirage's `Client.share` reads every message
looking for that one answer. A child that offered first would lose `up`
whenever the guest had already dialled in, wait the full thirty seconds, and
refuse with `no stream into the guest`. The offers lose nothing by coming
second, since the guest mounts one filesystem and each offer is just a name
inside it.

A guest that cannot be reached is a refusal and never a fallback, because
falling back to the native driver would sandbox the session more weakly than
the operator asked for, on a Mac far more weakly, with nothing saying so.

### How long a guest's process lives

The guest's process is kept for five minutes after a turn, unless another
arrives first, then let go. That is a window and not a session end event: the
daemon has no such event, `session.end` is written after every turn, and
`--adopt` can take a session up again, so nothing says it will never run
another. A daemon holds at most four guests at once, since each is a kernel
and its memory.

The window keeps the process and not a usable guest, and a second turn of the
same session cannot reach it. `chock guest` is the guest's `init`: it dials
the host once and returns when that stream ends, and `chock run` closes the
stream at the end of every turn, so `init` returns and the guest kernel
panics with `Attempted to kill init!`. The VMM process stays up for the rest
of the window holding a dead guest, and the next turn finds no stream and
refuses. So a daemon-backed session runs exactly one turn in a guest today.
Making the window worth having needs `chock guest` to take more than one
stream, or the daemon to reboot the guest between turns, and neither is
built. `zig build test-guest` drives exactly that one turn.

## Two things that starve a guest

A tick lands on whatever thread has the signal unblocked, which is often not
the one inside `KVM_RUN`, while `tgkill` always hits the thread it names. A
guest signalled every 10ms once answered `EINTR` on every entry and executed
no instruction at all, so the ticker instead watches the loop's own count of
turns and signals only a guest that has stopped moving.

Asking for the stream in a loop starves a guest the same way. The session
socket is bound before the guest runs, so a caller that connects the moment it
appears is talking to a guest that has not booted yet, and retrying `channel`
is worse than useless: every ask is work the guest's own loop does instead of
running the guest. Mirage says when a guest is up through the first stream it
opens, so the host now waits for that message once instead of polling for it.

## How big a guest is

A guest gets processors and memory from the machine it runs on. `config.zon`
can name either, and a number in the file is used as it is.

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

The memory share is one eighth of the machine, leaving room for the model
call, the terminal and the harness. The core curve is 12 processors at 24
cores or more, then 6 at 16, 4 at 12, 2 at 8, and 1 below that, and memory
gets one gigabyte per processor, since a build runner starts one job per
processor. On a Mac the curve clamps at eight, because the interrupt
controller there has no CPU interface past eight (`darwin_max_cores` in
`lib/chock-policy/sandbox.zig`), and Mirage refuses in words rather than
booting something broken. The table below is a Linux host's.

| The machine | Processors | Memory |
|---|---|---|
| 128 cores, 511GB | 12 | 12GB |
| 16 cores, 32GB | 6 | 4GB |
| 8 cores, 8GB | 2 | 1GB |
| 24 cores, 8GB | 2 | 1GB |
| nothing could be read | 1 | 512MB |

The core curve alone is not enough, since a guest with plenty of cores and
little memory would starve a build instead of merely slowing it down, so
processor count is also limited by what the guest's share of memory can feed.

A guest with more than one processor must also be woken before it is left,
or a join on its thread never returns, since a processor the guest never
started never sees the host's stop flag between exits. The host now signals
each waiting processor with the same signal the ticker uses.

## What this does not do yet

Tool calls are serialised: one guest holds one stream, and `chock guest`
answers one request at a time, so a background task waits for a foreground
call where it would run beside it under the native driver.

Answering several at once is a change at both ends, not one missing call. The
host would need to ask for a stream for each call, and `chock guest` would
need to serve several calls side by side instead of dialling one stream and
running it in order.

## Where a host path is inside a guest

A guest mounts one virtiofs filesystem, and every directory the host offered
appears as a name inside it. So `/nix/store` on the host is `<root>/store`
inside the guest, and `lib/chock-sandbox/vm/shares.zig` rewrites one into the
other.

The share set is given rather than derived. `Config.mounts` holds one entry
per store path, thousands for a real dev shell closure, and a guest takes 32
offers at most, so the set comes instead from what the session already knows:
the store read only, the workspace writable, the cache writable. Deriving it
from the mounts would either exceed that bound or merge paths of different
writability into one name, and merging is the worse of the two.

Two things are refused before anything reaches the wire: a path no share
holds, which could otherwise name one the guest has for another reason, and a
mount that writes into a read only share, since a share's writability is the
guest kernel's to grant while a mount's `read_only` is the sandboxed
program's, and a writable mount inside a read only share cannot come up. An
overlay's upper layer and work directory must still be writable whatever the
mount says, because overlayfs writes to both regardless.

Targets are never rewritten, so a path inside the sandbox means the same
thing in a guest, which keeps the path in a compiler message the user can
still open.

## What the host driver refuses

`lib/chock-sandbox/vm/driver.zig` is one `Sandbox.Driver` over the stream
`chock guest` opened. Its `guarantees` is read from the Linux driver rather
than written again, because that is the code which will run. Besides the two
share faults above, it refuses two more things:

| Refused | Because |
|---|---|
| a supplied cgroup | the descriptor names a directory of the host's, and a guest places a call in one of its own |
| a device tree | a host device node is not in a guest |

Each refusal has an error of its own, and none of them is `Unexpected`: the
tool path shows a person the name of the error, and a refusal with a reason is
the one thing that is not unexpected.

## What the guest is offered, and who works it out

`shares.offersFor` walks the session's `Config` and offers one directory per
source it binds, derived fresh each time rather than kept as a separate list
that could drift as the mounts change.

Two rules keep the count inside a guest's 32 offers: every path under the
store folds into one offer, which is what makes a dev shell closure of
thousands of entries a single name, and a source already inside an offer of
the same writability adds none. The store is offered whether or not the
session's own config names a path in it, because the closure is bound per
call by `withStore`, and a set derived from the session alone would hold no
store when the first call arrived.

Writability is never merged: a writable directory inside a read only one
stays an offer of its own, because the share's writability is what the
guest's kernel may do, and widening it to save a name would widen the
boundary instead.

## The two things a guest makes for itself

The sandbox root. `Config.root` names a directory the session made on the
host, and `namespace.buildRoot` binds it onto itself before it pivots, but
that directory is not inside a guest, so the host instead sends
`wire.guest_root` and the guest makes it there.

The files a call writes to. A call's `stdout_fd` and `stderr_fd` are open
files of the host's, but the guest gives the call two files of its own, and
writes one frame a descriptor before its answer, each naming a length and
followed by that many raw bytes. Raw rather than a field of the answer,
since a tool that reads a file keeps 4MB, more than a reader here takes
inside a JSON string. A file rather than a pipe, since the driver blocks
until the process it forked has ended and a full pipe would stop the call
for good, so output arrives when the call ends and not while it runs.

## How a call is cancelled

The tool path asks for a `Middle` on every call and ends a call through it,
both when a timeout runs out and when a person interrupts. The driver fills
one with `fd` as the stream and `pid` as `Middle.elsewhere`, which says a
call began and that its process is not this kernel's to name.

`signalMiddle` writes one constant line on the stream, `chock guest` reads it
while the call runs, and the guest signals the process it forked.

One stream carries this and there is no second channel: between a request and
its answer the host writes nothing else, so anything the guest reads in that
window is a cancel. The guest reads it on a watcher thread, started once
before any call and so before any fork, because the driver inside blocks
until the process it forked has ended, and the thread allocates nothing. A
cancel is written to the stream rather than to a call, so with two calls
queued it reaches whichever one is running, the same reason calls are
serialised at all.

## The tier this does not raise

Mirage's run path is tier 0: the VMM maps guest memory, so a compromised VMM
can read the guest. Nothing here promises otherwise. `Containment` is cgroup
placement and not a security level, and the six `Sandbox.Guarantee` values are
network, signal and IPC isolation, path and syscall restriction, and
workspace mounting. There is no memory confidentiality guarantee to break, and
Chock's threat model is an untrusted agent inside a trusted host:
[threat-model.md](threat-model.md).

## Who chooses the driver

Not the project. A project may only narrow what it may do, and a project that
could name its own sandbox driver could name a weaker one, which widens
instead. A `chock.zon` setting here would be a hole: see
[policy.md](../configure/policy.md) for the ratchet.

The choice is the operator's, in `config.zon`, which lives in the
configuration directory the sandbox keeps beyond an agent's reach:

```zon
.{
    .sandbox = .{ .driver = "microvm" },
}
```

`native` is the other value and is the default, so a file that says nothing
gets today's behaviour. A driver this build has no name for is refused, with
the ones it has named in the message, so a typo such as `"microvms"` is never
silently read as `native`.

An organisation can narrow it in its bundle:

```zon
.{
    .sandbox = .{ .drivers = .{ .microvm } },
}
```

A bundle naming only `microvm` means a session on a machine that cannot boot
one does not start, which is what requiring a guest means. A bundle that
says nothing permits every driver, since absent is not empty.

Choosing a driver adds a place to get through and takes nothing away: a
guest has a kernel of its own, so the driver that already exists still runs
inside it.
