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

### Three places to get through, and two of them are not independent

Count the places, not the layers. A tool call told to escape has three to get
through, in this order:

1. **The sandbox inside the guest.** `lib/chock-sandbox/linux/driver.zig`, built
   from the very same `Config` a native call is built from: namespaces, seccomp,
   Landlock, and a root it has pivoted into.
2. **The guest itself.** Getting out of that sandbox gives root in a kernel of the
   guest's own, and nothing of the host is inside it. Leaving needs a fault in the
   virtio devices Mirage places or in the hypervisor under them.
3. **The sandbox around the VMM.** `lib/chock-sandbox/vm/confine.zig` confines the
   process that runs the machine to the directories it was granted and to the
   calls it still needs.

**The first and the third are not independent of each other.** On a Linux host
both are made of seccomp and Landlock, so one bypass technique against Landlock
could apply at both ends, and calling them two layers would say more than is
there. On a Mac the third is a Seatbelt profile and the first is still the guest's
Linux, so there the two really are different mechanisms. The claim conceded here
is the Linux one, because that is the host every measurement on this page was
taken on.

The middle place is the independent one either way, and it is independent because
it is a different kernel: a hole in the guest's own Linux is not a hole in the
host's.

So the honest claim is two independent steps rather than three layers, and the
guest is the one that adds the independent step.

## The guest image, and two things measured about it

`pkgs/chock/guest.nix` builds two derivations, `packages.guest-kernel` and
`packages.guest-initrd`, after the shape of
DeterminateSystems/cloud-hypervisor-guest's own `bootinfo.nix`: a 6.1 LTS kernel
and an uncompressed initrd from `makeInitrdNG`.

**The guest-side drivers are modules, not built in.** In the configuration the
kernel `guest.nix` builds carries, `CONFIG_VIRTIO_FS`, `CONFIG_VSOCKETS` and
`CONFIG_VIRTIO_VSOCKETS` are all `m`, so an initrd that carries no modules boots a
guest that can neither mount a share nor open a channel. The initrd carries them,
and the init loads them by name. A name built into the kernel rather than shipped
as a module is not an error: in that same configuration `CONFIG_VIRTIO_MMIO` is
`y`, so the mmio transport is built in and the mount works anyway.

**Only the modules the guest needs.** A root holding a kernel's whole module tree
is a 146MB initramfs, and one that size does not unpack: the guest came up,
`/lib/modules` was present, and every file under it was missing. The same root
with six modules in it, 2.4MB, mounted its share and got its vsock device. Those
two sizes were measured on aarch64 in September 2026, when the list was six names
long, and they are what settled the question rather than a size the list has
today.

So the initrd is built with `makeModulesClosure` over a named list rather than
over the tree. The list is eighteen names today: the vsock channel, the one
virtiofs mount, `overlay`, the two virtio transports, and the netfilter modules
and expressions a routed tool call's own filtered network is made of.

Both mechanisms are proven on aarch64 under KVM: a guest read a file the host
offered through the virtiofs share, by the name the host gave it, and `/dev/vsock`
appeared once the three vsock modules loaded.

### Two things in the image are the architecture's own

The module list is not one of them, and that was built rather than assumed. Every
driver named is generic, so one list serves both architectures. What the two
kernels disagree about is whether a name is a module or built in: on arm64 the
virtio transports are built into the kernel, and on x86_64 they are modules, so
the x86 closure carries files the arm one does not. Measured once at 920K against
750K, both more than a hundred times smaller than the 146MB that does not unpack.
**Neither number has been measured since the list grew**, and the x86 one cannot
be measured on an aarch64 machine at all, for the reason the section below gives.
`modules-closure.sh` takes a `builtin` answer from `modprobe --show-depends` and
carries on, and exits 1 on a name that is neither, so a wrong name is a build
failure and not a guest with a driver missing.

Two things do follow the architecture, and `pkgs/chock/guest.nix` reads both from
the guest platform rather than writing either down:

- **The image's name.** nixpkgs installs the kernel as `$out/${kernel.target}`,
  which is `bzImage` on x86 and `Image` on arm64. Mirage's x86 boot path reads a
  real mode bzImage header, so the name and the format go together.
- **The console's name.** `console=ttyS0` for the 16550 behind an I/O port on x86,
  `console=ttyAMA0` for the memory mapped PL011 on arm. A kernel told to print to a
  port it has not got prints nowhere, and the symptom is a guest that boots and
  says nothing. `src/vmm.zig`'s own default cmdline follows the same rule, and an
  architecture neither file has a name for is refused rather than given arm's.

### Where the images are built

**On Linux, and on a machine of the guest's own architecture.** A guest is Linux
whatever the host is, which is the whole reason the microVM driver closes the
Darwin gap, but a Mac cannot build a Linux kernel's module closure without a Linux
builder, and `guest-kernel` for `x86_64-linux` is a derivation for `x86_64-linux`.
So `nix build .#packages.x86_64-linux.guest-kernel` on an aarch64 machine needs one
of three things, and the project does not have the first:

- an `x86_64-linux` remote builder in `nix.buildMachines`, which is the normal
  answer and the only one that gives the same closure a native build gives;
- the CI `ubuntu-latest` runner, which is `x86_64-linux` and builds its own images
  natively;
- `pkgsCross`, which cross compiles the kernel on the aarch64 host. nixpkgs
  supports this for a kernel, but it is a different closure from the native one and
  nothing here has built it, so it is named as an option and not as the answer.

A Mac takes the images from a release or from a Linux builder it is configured
with, exactly as before. The route that was used for the first boot on an Apple
Silicon Mac is the second one, as two store paths and nothing else:

```bash
# on the Linux builder, for the guest's own architecture
nix build .#guest-kernel .#guest-initrd
nix copy --to ssh://<the mac> --no-check-sigs ./result ./result-1
```

The Mac then names the two files inside those paths, and the names are the
architecture's own: `Image` for the kernel on arm64 and `initrd` for the initrd.

```zon
.{
    .sandbox = .{
        .driver = "microvm",
        .kernel = "/nix/store/<hash>-linux-6.1.182/Image",
        .initrd = "/nix/store/<hash>-initrd/initrd",
    },
}
```

An operator with no Linux builder copies the same two files out of a release and
names wherever they put them. Nothing reads the store path as a store path.

The same two paths are what the one test that boots a guest is given, because a
build script cannot honestly guess them:

```bash
zig build test-guest -Dguest-kernel=./result/Image -Dguest-initrd=./result-1/initrd
```

Without them, and on a machine with no `/dev/kvm` this user may open, **that test
skips**, and the build says `2 skipped` rather than saying anything passed.
`zig build --help` names what it needs, and `whyNoGuest` in `test/cli/guest.zig`
names every fact that can stop it. It is on `zig build test` as well, so
`nix build` runs it and it skips in the Nix builder rather than failing a branch.
A skip there is the honest answer, and it must never be read as a pass.

## What runs the guest: a forked process of the harness's

Mirage is a library, so Chock is the process that runs a guest. Both `chock run` and
`chock daemon` fork one for it: one CPU, a console, a channel, and the directories
the guest may mount. There is no subcommand, and nobody starts a guest by hand.

**A process and not a thread, because of what the boundary is made of.** A seccomp
filter and a Landlock domain go on a whole process and cannot be taken off again, so
a guest hosted on a thread would be confined only by confining the harness with it.
`vmm.forkHost` is the only way in: the function that runs a machine is private to
`src/vmm.zig` and refuses a process that was not forked for it.

**The tick is aimed at one thread.** A guest blocked on its channel exits for
nothing, so the host loop needs interrupting or a waiting guest waits for ever.
Mirage arms a process wide `setitimer`, and this process holds more than the guest's
own processor: the virtiofs thread and the session thread are in it too, and a timer
aimed at the process would have every read of theirs answer `EINTR`. So Chock's copy
runs a ticker thread that signals **one** thread by its own id, with `tgkill` on
Linux and `pthread_kill` on macOS, which has no `tgkill` and names a thread by its
pthread handle. Nothing else in the process is touched, and the handler does
nothing: the interruption is the whole point of it.

A build that cannot run a guest compiles all the same: the module behind it answers
`available = false`, and the daemon reads that before it offers a session a guest. A
guest needs a hypervisor, and `src/vmm.zig` names neither it nor an architecture:
which hypervisor, where the devices sit and which interrupt controller the guest
gets all come from the target the build is for.

### Which platforms run a guest, and what each one has done

Three targets compile `src/vmm.zig`. Two have booted a guest. Taken one at a
time, because this is the claim a reader checks first:

- **`aarch64-linux` boots a guest.** Against KVM, with the devices stated in a
  device tree. This is the development machine, it is where every measurement
  below without a platform named was taken, and it is the one platform where
  `chock daemon` has booted a guest for a real session.
- **`x86_64-linux` compiles the VMM and has never booted a guest.** The build is
  against KVM, which on x86 means its ACPI tables, its 16550 behind an I/O port
  and the virtio-mmio-over-ACPI path. Nothing in this repository has run one:
  the development machine is aarch64, emulating a userspace proves nothing about
  a hypervisor, and a GitHub hosted runner exposes no `/dev/kvm`. So the x86
  machine setup is held by the compiler and the drift guards and by nothing else.
- **`aarch64-darwin` boots a guest, given an ad hoc signature.** Against
  Hypervisor.framework, and the binary must carry
  `com.apple.security.hypervisor` or the call that makes a machine answers
  `HV_DENIED` and says nothing more. See the entitlement below, and read
  [what a Mac can and cannot do](#what-a-mac-can-do-and-what-it-cannot-yet)
  before believing a Mac runs your toolchain in a guest.

A target Mirage has neither a machine nor an architecture for is refused at
compile time rather than given arm64 Linux's, so widening the set cannot quietly
place a guest in the wrong memory.

### Memory encryption, which is tried and not required

On `x86_64-linux` the guest's memory can be encrypted by the processor with AMD
SEV. It is attempted and never required, because the launch commands issue
through `/dev/sev`, which usually only root may open.

What happens, in order. The descriptor is opened beside `/dev/kvm`, above the
confinement seam, because nothing below it may open a path. If it does not open,
or if the processor will not make an encrypted machine, the guest is made in the
ordinary way and runs in the clear. Once an encrypted machine exists the
behaviour changes: the C-bit position is read from the processor and goes into the
page tables, the launch is started, and the memory is measured and sealed. **A
failure from there ends the guest rather than falling back.** Carrying on would
run the guest unencrypted and still report encryption, which is worse than not
starting.

The launch policy is zero, which refuses guest debugging and key sharing. A
policy that allowed debugging would let whoever holds the host read the guest it
is supposed to protect.

**It is reported only when it is on.** `chock run` and `chock daemon` each print
one line naming the feature when a guest comes up encrypted, and print nothing
when it does not. A line either way would read as a promise on a machine that has
none. The state crosses the control channel on the readiness line, so a line from
a build without the field reads back as off rather than as a refusal.

Two limits worth stating plainly:

- **Nothing here has run.** This is `x86_64` only, no machine in this project has
  booted an x86 guest at all, and no AMD machine with `/dev/sev` has been
  available. The code compiles for the target and that is the whole of what is
  established.
- **SEV-ES is not selected, on purpose.** Mirage supports it, and it also
  encrypts register state. It needs the guest to handle `#VC` exceptions, which
  the guest kernel here is unverified for, so taking it automatically could
  replace a guest that boots with one that does not. Choosing it is left to
  whoever can test it.

A daemon is the useful place for this. The forked process that runs a guest
inherits the daemon's credentials, so an operator who starts `chock daemon` with
access to `/dev/sev` gives every session's guest encrypted memory, and one that
does not still gets guests.

### The three things Apple's hypervisor does not do that KVM does

`src/vmm.zig` names each one, and each is a piece of work and not a rename.

- **It makes no memory.** KVM is told to make a region and holds it. The
  framework maps memory the calling process already owns, so the guest's RAM is
  `mmap`ed by the VMM and handed over. That is the same tier 0 the Linux side is
  at: the VMM can read the guest either way.
- **It starts no other processor.** A guest starts its other processors through
  the power interface, which the kernel answers on KVM. Here the VMM answers it:
  every processor but the first waits on a thread of its own, makes its own
  processor on that thread, because the framework binds one to whoever created
  it, and runs once the guest has said where to begin.
- **It holds no interrupt controller.** KVM holds a GIC for an arm64 guest. Here
  a version 2 controller is built in the VMM, its two halves go on the guest's
  bus like any other device, and the guest is told where they sit.

The console also needs its interrupt line named where the controller is built
here: the real driver waits to be told there is room to send, and without a line
to wait on, output stops the moment the early console hands over.

**The boot entry goes through the backend, with a shim of Chock's own.** A
processor belongs to the framework and the VMM holds nothing of it, so the entry
cannot take one. `core.Launch.enter` is Mirage's seam for exactly this and does
not compile: the shim it builds keeps its one method private. So `src/vmm.zig`
passes `arch.boot.enter` a shim of four lines instead.

### The entitlement, which is the whole of what makes it possible

The call that makes a machine needs `com.apple.security.hypervisor`, and without
it that call answers `HV_DENIED` (`0xfae94007`) and nothing else. **An ad hoc
signature carries it**, which was the open question and is now measured on macOS
15.8.1 arm64: the same binary answered `HV_DENIED` unsigned and `HV_SUCCESS` after

```bash
codesign --sign - --entitlements <plist> --force <binary>
```

So no Developer ID is needed to run a guest on the machine the binary was built
on. The plist is one key:

```xml
<key>com.apple.security.hypervisor</key><true/>
```

### The outer layer holds, and it needed nothing added

The Darwin arm of `lib/chock-sandbox/vm/confine.zig` closes the network
completely, and `(deny network*)` refuses a unix socket as well as IP. The
session socket a guest is held up on is a unix socket, so whether a guest could
be reached at all under the profile was an open question.

It can, and the profile is unchanged. The socket is bound and listening **before**
`sandbox_init` is called, and Seatbelt checks `network-bind` and
`network-outbound` rather than every later use of a socket that already exists.
A guest ran a tool call over that socket with the profile on.

Proved by behaviour from inside the confined VMM, which is the only way on a
platform with no `/proc` to read: `open("/etc/hosts")` answered `EPERM`,
`open` of the offered share succeeded, and `execve("/usr/bin/true")` answered
`EPERM`.

Proven on aarch64 under KVM: a guest booted, mounted the share, listed it by the name
the host gave it and read the file inside, `/dev/vsock` was there, and the run
answered 0. The session socket exists while the guest runs and is unlinked when it
ends.

Proven on aarch64 under Hypervisor.framework, on macOS 15.8.1: a guest booted,
loaded its modules, mounted the virtiofs share, dialled the host, and a tool call
inside it ran a program out of that share and exited 0 with Landlock applied at
ABI 2. With two processors asked for, the guest brought the second up through the
power interface the VMM answers, and the run still ended 0. **That run was driven
by hand through the entry points a session uses**, `forkHost`, `attach` and
`vm_driver.Guest.spawn`, and not by `chock run` or `chock daemon`: neither has
started a guest on a Mac.

Then through the daemon, **on aarch64 Linux**: it forked the guest, which bound
the session socket, and a session's tool call ran in it and answered 0. That is
what `zig build test-guest` boots, so it is a claim a committed test holds rather
than one a person ran once. The daemon answering ten control requests in a row
while a guest was ticked a hundred times a second was proved before the guest
moved into a process of its own, so it says nothing about the fork path: what the
thread targeted tick does there is leave the guest's own virtiofs and session
threads alone.

### What a Mac can do, and what it cannot yet

**A Mac boots a guest and confines it. A tool call needs Linux programs, and a
Mac's store has none.** The one tool call proven on a Mac ran a static aarch64
Linux `busybox` that the host had put in the share on purpose. A session's own
`Config` on a Mac names the Darwin binaries of a Darwin dev shell, and a Linux
guest cannot execute one of those. **Nothing answers where a Mac's Linux
toolchain comes from yet.** So a reader on a Mac should not finish this page
believing their own toolchain runs in a guest today: what is proved there is the
VMM, the guest, the share, the stream, the confinement, and one call to a program
somebody placed by hand.

The two routes that would answer it both already exist in part. A Linux dev shell
closure, built on a Linux builder and copied over, is one. A container image is
the other, and `lib/chock-container.zig` already reads one. Neither is wired to
the microVM driver.

Three more things are unmeasured on a Mac, and each is named rather than assumed.
A tool call that reaches the network, which crosses as Mirage's own `reaching`
message and is answered by a thread of the host's. The five minute window and the
one turn a guest limit, because no guest has run there through the daemon. And
`nix build .#default`, which cannot pass its own check phase on a Mac.

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
the limits, the seccomp options, the network mode, whether to audit paths, and
the time. One JSON object a line, with the message and its newline written
together.

**The time crosses because a guest has no clock.** Nothing in the machine Mirage
builds is a real time clock, so a guest starts at the epoch and a tool call that
was not told the time sees 1970: a commit is stamped wrong, a certificate is not
yet valid, and a build writes files older than their sources. The host sends what
its own clock says, in nanoseconds.

The rest of `Config` stays on the host, and none of it is a gap:

| Left behind | Why |
|---|---|
| `net_broker`, `net_router`, `device_source` | function tables in the host's own address space |
| `stdout_fd`, `stderr_fd`, `stdin_fd` | the streams are carried by the channel the request came on |
| `containment` | a supplied cgroup names a directory of the host's, so it is refused |
| `landlock_report`, `limits_report`, `supervisor_audit`, `syscall_audit` | pointers the host reads after the call, and the contents come back in the answer |

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

A guest `chock run` forked has its console at `<session>.guest-console` beside the
session's log, and never on standard output: the agent's transcript is there, a
kernel boot interleaved with it is unreadable for both, and a session whose display
owns that stream threw the whole boot away. A guest the daemon forked writes to the
daemon's own output, which is where the operator reads it.


`chock run` exits at the end of every turn, so a guest it owns boots and dies each
time. The daemon owning one is meant to save that boot, and today it does not: see
the window further down. What it does buy is the vCPU threads staying out of the
process that dispatches tool calls.

- The daemon forks the guest before the turn's child, waits for the guest to say its
  socket is bound, and passes the child `--guest <socket>`. The fork is on a thread
  whose life is exactly the guest's, because `PR_SET_PDEATHSIG` fires when the
  thread that forked ends and not when its process does.
- **The daemon's grant is derived and not written out.** The directories a session
  offers do not exist when the guest is forked, and a Landlock domain can only ever
  be narrowed, so `guestShares` in `src/daemon.zig` names the roots those offers sit
  under. **Every granted root is a path a compromised VMM may mount**, and the
  grant is also the guest's own offer list, so the set is kept as small as the
  session allows. Fifteen roots at most, and this is all of them:
  - the toolchain: the store, read only, or up to nine of this machine's own
    system directories when there is no store. The nine is where the fifteen
    comes from, and `src/daemon.zig`'s own `max_granted_roots` is the number.
  - the session's own working directory, writable. It is the one entry that
    covers the attempt directory, its object store, its worktree metadata and
    its pointer file.
  - the project's git directory, read only, or the project itself when the
    project is no repository.
  - the toolchain cache, writable.
  - the scratchpad, writable, which is also where a tool call stages a file.
  - the knowledgebase, writable, **and only when its notes directory could be
    made**.
  - the tree of the image a project names, read only, **and only for a project
    whose `container` block names one**, because that directory holds every
    project's images.

  A directory outside that set is refused where it is offered, with the path
  named. The last two are the only conditional ones, and they are conditional
  because a root beyond what the session offers is a root an escape inside the
  guest reaches for nothing.
- **Where a tool call stages a file is one directory and not two.** A routed call
  stages the host trust store and a granted secret stages its value, and both go in
  a `stage` leaf of the session scratchpad, which is already in the set above. A
  project with a dev shell gets the same leaf: the dev shell's own temporary
  directory is read on the host before any guest exists, so staging there would
  have bought one more granted root for half the projects on the machine.
- **A project that holds Chock's own directories gets no session, by name.** Whoever
  starts a session names the project and nothing bounds where it is, so a project at
  or above the configuration, data or state directory would put `credentials.zon`
  inside a read grant. The daemon turns such a session away before it starts the
  child, and `chock run` refuses one of its own for the same project, which is what
  makes it a refusal rather than a choice of which process holds the grant: a daemon
  that answered no socket would have the child fork a guest itself. One function
  answers for both, `chockOwnInProject` in `src/run.zig`, and it checks the one
  directory that reaches the grant: the project's own `.git` when it is a
  repository, and the project itself otherwise. A refusal names both paths, and is
  never a set with the backing quietly left out, which would be a session whose
  every git read fails.
- **This covers where the project is and not where Chock's directories are.** An
  operator whose `XDG_DATA_HOME` points under `/usr` or `/etc` has
  `credentials.zon` inside the toolchain read grant, which is granted to every
  session of every project. `chock run` on its own has always done the same, so it
  is nothing the guest changed, and it is the other way the credential store can
  land in a grant.
- **A `workspace.binds` entry is not granted either, and that door is closed rather
  than open.** The bind names a host path the project's own `chock.zon` asked for,
  and whether a session may have it is a policy question about the child's spawn
  chain that the daemon does not answer. So a daemon-backed session of a project
  with a `read_only` or `write` bind is refused, with the path named and with
  `chock run` offered as the way to run it; a `copy` or `temp_copy` bind becomes no
  mount and is unaffected.
- **The dev shell's own temporary directory is named by Chock and granted to
  nothing.** The environment `nix print-dev-env` writes ends in
  `mktemp -d -t nix-shell.XXXXXX`, so the evaluation is run with a `TMPDIR` under
  the dev shell cache directory, which keeps that directory findable and lets an
  old one be swept. The evaluation itself happens on the host before a guest
  exists, and a tool call stages into the scratchpad instead, so no guest is
  granted that root. It was granted once, to every project with a `flake.nix`, and
  that was surface and nothing else.
- The child connects, waits for the guest to say it is up, offers the guest this
  session's own directories, takes one stream into it, and every tool call from then
  on goes through that stream.
- **It waits before it offers, and that order is load bearing.** The guest says `up`
  once a connection, and Mirage's `Client.share` waits for its own answer by reading
  every message that arrives and dropping the ones it has no use for, `up` among
  them. A child that offered first therefore lost the message whenever the guest had
  already dialled, which is every session whose own startup outlasted a boot: it then
  waited the full thirty seconds and refused with `no stream into the guest` after a
  console that said the guest was up. Waiting first makes the wait the only reader of
  that message. The offers lose nothing by coming second: the guest mounts one
  filesystem and each offer is a name inside it.
- **A guest that cannot be reached is a refusal and never a fallback.** Falling
  back to the native driver would sandbox the session more weakly than the
  operator asked for, and on a Mac far more weakly, with nothing saying so.

**The guest's process is kept for a while after a turn and then let go.** Five
minutes, unless another turn arrives first. That is a window and not a session end
event, because the daemon has none: `session.end` is written at the end of every turn
and a session can be taken up again with `--adopt`, so nothing in the log says a
session will never run another. Letting it go bounds what a daemon left running
holds. A daemon holds at most four guests at once, since each is a kernel and its
memory.

**The window keeps the process and not a usable guest, and a second turn of one
session does not reach it.** It is structural and not a race. `chock guest` is the
guest's `init`, it dials the host once, and it returns
when that stream ends. `chock run` exits at the end of every turn and closes the
stream, so the guest's `init` returns and the guest kernel panics with `Attempted to
kill init!` and a clean exit code. The VMM process stays up for the rest of the
window holding a dead guest, and the next turn of that session reads no stream and
refuses, because a guest that cannot be reached is never a fallback. So a
daemon-backed session runs one turn in a guest today. `chock guest` itself answers
request after request on the one stream it has, so the limit is the stream's life
and not the loop's. Making the window worth having needs `chock guest` to be given
more than one stream, or the daemon to reboot the guest between turns. Neither is
built, and the same two-turn sequence fails the same way on the commit before the
guest moved into a process of its own: confining the VMM neither caused this nor
fixed it. One turn is also what `zig build test-guest` drives, for that reason.

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

**On a Mac the curve is clamped at eight, and the interrupt controller is why.**
A guest there gets a version 2 controller, and that version has no CPU interface
past eight processors. Asked for more, Mirage refuses in words when the guest
starts rather than booting something lame, so the clamp sits where the number is
chosen: `darwin_max_cores` in `lib/chock-policy/sandbox.zig`. The table below is
a Linux host's.

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
would have run beside it under the native driver.

Answering several at once is a change at both ends, not one missing call. The host
would ask for a stream for each call, and `chock guest` dials one stream and serves
it in order, so it would have to serve several and run their calls side by side.

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

Choosing a driver adds a place to get through and takes nothing away. A guest has
a kernel of its own, so the driver that already exists runs inside it.
