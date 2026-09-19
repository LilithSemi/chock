# Policy

What an agent may do is a static table in `chock.zon`, in the project root.
The table is declarative on purpose. A policy that a reader must execute to
understand is a bad property for a security control.

Chock binds `chock.zon` into the workspace **read only**, so the agent works
under rules it cannot edit.

This is a complete file. The outer `.{ }` is the whole of `chock.zon`, and
every rule goes inside `.policy.rules`:

```zon
.{
    .policy = .{
        .agents = .{
            .{ .kind = "main" },
            .{ .kind = "reviewer", .parent = "main" },
        },
        .rules = .{
            .{ .action = "git.*", .decision = .ask },
            .{ .action = "git.push", .decision = .deny },
            .{ .agent_kind = "main", .action = "git.commit", .decision = .allow },
        },
    },
}
```

**A rule written directly under `.policy` is a syntax error.** `.policy` holds
named fields, so a rule beside `.agents` gives:

```
chock run: the workspace for /home/you/site could not be built: chock.zon is
not valid:
4:9: error: expected field initializer
```

That message is about the file and not about one block, because Chock has to
read the whole file before it can tell which block the fault is in. The line
and the column say where to look. See
[configuration.md](configuration.md) for a complete `chock.zon` with every
block in it.

## The key and the answer

A rule has five fields. `agent_kind`, `model`, `tool` and `action` name the
key, and each of the four is optional. A field that is absent matches every
value. `decision` is the answer, and it is required.

The five decisions, from the most restrictive to the least: `deny`,
`agent_then_human`, `ask`, `agent_review`, `allow`. `ask` puts the question to
a person. `agent_review` needs one yes from a reviewer agent.
`agent_then_human` needs both. See [approvals.md](approvals.md).

A name that ends in `.*` matches every name below that prefix. `git.*` matches
`git.push` and `git.branch.delete`, and it does not match `git` itself. Any
other name matches only itself. A bare `"*"` is an error: leave the field out
instead, so one meaning keeps one spelling.

**The most specific rule wins.** Specificity is compared one field at a time,
in this order: the action, then the tool, then the model, then the agent kind.
The action comes first because the action is what happens to the machine. The
tool is only how the agent asked for it, and the model and the agent kind are
only who asked. Inside one field, an exact name beats a `.*` name, and a
longer prefix beats a shorter one. Both beat an absent field.

Two rules can reach the same score and still both match. The more restrictive
decision then wins, so the answer never depends on the order the rules have in
the file.

**An action no rule names, and no shipped default names either, answers
`ask`.** A session with nobody at the keyboard is refused there.

**Chock ships default rules for the ordinary tool calls, so a project with no
`chock.zon` at all still runs them without a prompt.** Reading a file, listing
a directory, a glob, a grep, writing a file, editing a file, the workspace and
toolchain paths a `run_command` call may execute, the guidance and memory
tools, and `nix_eval`, all answer `allow` out of the box. A shipped default is a lower class
of rule than anything in `chock.zon`: it is read only when a project's own
rules name nothing that matches the key at all. **A project rule that matches
wins outright**, whatever it names and however wide it is next to a default,
because the entire reason a default exists is to answer for a key the project
did not. Writing `.{ .action = "call.write_file", .decision = .ask }` in your
own `chock.zon` puts that call back behind a prompt, even though a shipped
default would otherwise let it through.

A store path the session did not start with asks. `run_command` names a
program by the class it belongs to, and the store is two of those classes.
`exec.devshell.*` is a program inside the Nix dev shell closure this session
mounted at its start, and it is allowed: the toolchain was known before the
model said anything. `exec.nix.store.*` is every other store path, and it is
the one shipped rule that is not an `allow`. A store path is immutable, so it
names one program forever, but the set of store paths is not: the agent can
have an expression evaluated and the result built, and a path it made that way
is not the toolchain it was given. `exec.path.*`, a bare name looked up on
`PATH`, and `exec.workspace.*`, a path inside the project, are both unchanged.

`net.connect.*` and `net.fetch.*` hold no shipped default, on purpose: a
project that named nothing about a host still meets `ask` there, never
`allow`. See [threat-model.md](threat-model.md) for what an `ask` on
`net.connect.*` can now reach.

## Whether a session has a network at all

`net.connect` and `net.fetch` rules say **which hosts** a session may reach.
What decides whether it is given a network namespace, a kernel ruleset and a
resolver at all is `.policy.net.router`:

```zon
.{
    .policy = .{
        .net = .{ .router = .auto },
        .rules = .{
            .{ .action = "net.connect.com.github", .decision = .allow },
        },
    },
}
```

* `.auto` is the default and reads the rules. A project that permits
  something under `net` is given a router. A project that permits nothing
  there is not, and pays for none of it.
* `.none` refuses a router whatever the rules say.
* `.filtered` gives one even when no rule permits a host yet, which suits a
  session where a person answers for each host as it comes up.

**A router is a mechanism and never a permission.** It grants no host by
itself: every connection is still decided at `net.connect.*`, and a router
with nothing permitted reaches nothing. That is why an organisation's bundle
needs no ceiling over this field. The bundle caps the rules, and a project
that turns a router on without them has turned on a road to nowhere.

**A rule that only denies is not a reason to build one.** A road nobody may
take is not a road to build.

`.policy.net.background` says what a command started in the background gets,
and takes the same three words. `.auto`, the default, is whatever the session
itself has.

**A session with a network is given a trust store.** Chock copies the host's
own certificate bundle into the sandbox, points `SSL_CERT_FILE` at that copy,
and links the conventional path, `/etc/ssl/certs/ca-certificates.crt`, to it
too, so an https host can be verified without every project remembering to
put `cacert` in its dev shell. A project that sets `SSL_CERT_FILE` itself
keeps its own.

**A background command never asks you anything.** It runs after the tool call
that started it has returned, and a question needs the session to be waiting
on it. So a background command reaches what this policy **allows** outright,
and a host that would have asked you is refused instead of queued. Set
`.background = .none` for a project where a background command should reach
nothing at all.

## The actions

| Action | What it does |
|---|---|
| `git.commit` | make a commit in a repository on the host |
| `git.push` | move a ref on a remote |
| `git.branch.delete` | delete a branch |
| `net.fetch` | read one page over http or https |
| `nix.build` | realise a package, outside the sandbox |
| `file.write` | write a file on the host |
| `workspace.apply` | carry the session's commit into your repository |
| `model.select` | which provider instance and which model a session uses |
| `policy.widen` | let a session out of a promise it made to itself |
| `sandbox.jit` | run with the sandbox's write and execute rule off |
| `workspace.integrate` | let an approved apply move the branch you have checked out |

The three `git` actions have a shim in front of them. It reads the argument
vector of every `run_command` call whose first word is `git`, and it sorts each
subcommand into one that only reads and one that changes state. **The shim
prevents a mistake and it does not prevent an attack.** The sandbox layers are
the boundary. An agent that wants to avoid the shim has several ways and none
of them is difficult, so nothing in Chock is built as though the shim were a
control.

**The shim's approval half is wired.** Every subcommand it classifies is asked
about while the loop runs, through the same arbiter an MCP tool call and a
plugin tool call already go through. A read only subcommand asks nobody and
runs the real git, so `git status`, `git log` and `git diff` cost what they
always did. So `git.commit`, `git.push` and `git.branch.delete` are rows a
session really asks, and a subcommand the shim does not know asks under its own
name, such as `git.frobnicate`. An option the shim cannot read stops it reading
the subcommand at all, and that asks as `git.unknown`.

Chock ships `allow` for every git action name that changes only the session's
own workspace, `git.commit` among them, so a project with no `chock.zon` gains
no new prompt. It ships none for `git.push`, `git.clone`, `git.fetch`,
`git.pull` or `git.unknown`, so each of those asks.

**An approved `git push` runs.** It is the one subcommand that reaches another
host and is carried out: the real git runs inside the sandbox, reaches the
remote through the network router, and gets its credential over a socket for
that one call. An `https` remote prompts a person for a password, an `ssh`
remote arms the agent proxy, and both are closed again when the call ends. See
[credentials.md](credentials.md).

**Every other subcommand that reaches another host is asked about and still
does not run, even when a person says yes.** `git clone`, `git fetch` and
`git pull` have no act that carries the effect out, so the agent is told what
is missing rather than told no. `file.write` is still a row nothing in a
session asks.

`net.fetch` is `fetch_url`'s action, and the host is part of the name, with
the labels reversed: `docs.ziglang.org` becomes `net.fetch.org.ziglang.docs`.
Reversal is what makes a class rule safe, because `net.fetch.org.ziglang.*`
then means "any host under ziglang.org" and cannot be matched by a host
somebody else registered.

```zon
.{ .action = "net.fetch.org.ziglang.*", .decision = .allow }
.{ .action = "net.fetch.*", .decision = .deny }
```

A redirect is followed only while every host along the way is allowed too, and
a site's own `robots.txt` is honoured. There is no way to send a header, a
credential, or a body: `fetch_url` reads, and it never writes to a remote
service.

**Only `allow` reads a host.** A host that no rule names answers `ask`, and for
a fetch `ask` is a refusal. Chock cannot put the question to you while a turn
runs, because the turn holds the session log. So a page you want the agent to
read needs an `allow` rule in `chock.zon` before the session starts. The
refusal on your screen names the rule to add, and the block it goes in.

`model.select` reads two rows: `provider.<instance>` is the instance by its
name in your `config.zon`, and `provider.<instance>.<model>` is one model at
that instance by the id that goes on the wire. The narrower of the two is the
answer. A session picks its model before the first turn, when nobody is waiting
to be asked, so **only `allow` lets a model be used** and every other answer is
a refusal.

`nix.build` is read once, also before the first turn, and it decides whether
the `provide_tool` tool exists at all. Only `allow` gives the session that
tool, and `ask` is a refusal there for the same reason.

`sandbox.jit` is read once too, and it is **the one row that widens rather than
narrows**. It turns off the sandbox rule that refuses a page which is writable
and executable at the same time, which a run time with a just in time compiler
needs: V8 asks for such a page over a 268 MB range, so Node, Deno and Bun cannot
work without it. Only `allow` turns the rule off, for the same reason as the two
rows above: the filter is built before the first turn and there is nobody to
ask.

**It is a row here and not a key in `chock.zon` precisely because it widens.**
Every other setting a project writes for the sandbox narrows, and a widening
setting needs an answer to "who may do this, and who authorises it". The table
already has that answer: an organisation writes
`.{ .action = "sandbox.jit", .decision = .deny }` in its bundle and no project
can raise it, because the answer is a minimum over both layers. The same fold
means a subagent cannot give up hardening its parent kept.

What is given up is documented hardening and it is not a boundary. See
`docs/sandbox.md` for the three measured ways past the rule, and for the three
places a session that gave it up says so.

`workspace.integrate` is the second row of that shape, and it is read the other
way round from `sandbox.jit`. A project says in its `chock.zon` how an approved
apply should land, with `.apply = .{ .mode = .rebase }` and the four modes
[approvals.md](approvals.md) lists. This row says whether an approved apply may
move a branch of yours at all. There is no mode that means "move nothing", so
this row and a `n` at the prompt are the two ways to say it.

```zon
.{ .action = "workspace.integrate", .decision = .deny }
```

**A row nobody wrote answers `allow` here**, unlike every action above, because
this is a question about a capability and not about an act: a project on an
installation whose organisation has never heard of the row gets the mode it
configured, and the default `merge` where it configured none. That is the same
reading `provider.<instance>` gets, and it is what keeps a permission model from
breaking every configuration the day it ships. One
`deny` in an organisation's bundle closes the road for every project under it,
and the same fold means a subagent moves no branch its parent could not.

**This row decides whether, and `.apply.mode` decides where.** `deny` is the one
decision that takes the capability away, so it is the one decision that parks the
work at the ref. `ask`, `agent_review` and `agent_then_human` each say that
integration is permitted once somebody says yes, and none of them names a
landing, so they keep the mode the project configured. The one question an apply
puts is the `workspace.apply` approval, which is a different row.

The answer is read once, when the session starts, before an apply is described,
because the description is what a person reads and it has to say what the apply
does. So the mode is settled before the prompt exists, and a yes at that prompt
carries the work in the mode the prompt named.

**A rule that names nothing reaches this row.** A catch all
`.{ .decision = .ask }` and a `workspace.*` rule both match
`workspace.integrate`, while a rule that names `workspace.apply` alone does not.
Until this was corrected, one broad rule about anything silently took away
`.apply.mode` without ever naming an apply.

## Files the agent may not read

A `deny_read` block in `chock.zon` names files that are kept out of the
session altogether:

```zon
.{
    .deny_read = .{
        ".env",
        "config/production-secrets.zon",
    },
}
```

Each name is a path relative to the project root. Chock reads the block from
**your** copy of `chock.zon`, on your machine, before the workspace is built,
and then covers each named path inside the sandbox with a file that says only:

```
chock: this file is denied by the project. Its bytes are not in this sandbox.
```

**This is the one protection that actually holds.** The bytes are not in the
mount tree a tool call reads through, so no tool, no shell command and no
program the agent runs can reach them. There is nothing to filter and nothing
to miss.

That is the Linux mechanism. macOS has no bind mount, so the denial there is a
Seatbelt rule that refuses a read and a write of the named path. The bytes stay
where they are and the kernel refuses every open of them, which gives the same
answer to a tool call by a different road.

A few things are refused by name rather than half supported, and the refusal
happens when the session starts, not later:

- **A directory.** `~/.aws` is a directory, and a covered directory would read
  as "this project keeps no credentials here", which sends a model looking for
  something that is not missing. Name the files.
- **An absolute path.** The sandbox holds your project and a read only
  toolchain and very little else, so anything outside the project is already
  absent, and accepting the path would promise a protection this does not give.
- **A glob.** A pattern that matches nothing reads exactly like a pattern that
  protects something.
- **`chock.zon` itself.** It is already bound read only, and denying it would
  only hide the project's rules from the agent working under them.

A path you name that does not exist yet is covered anyway, so a `.env` that is
in `.gitignore` today is still unreadable on the day somebody makes one. The
cost is one empty file of that name left in the throwaway workspace, which
reaches your repository through nothing but a commit.

`read_file`, `write_file` and `edit_file` refuse a denied path with a sentence
that names the file and this block, so the model reads it once and carries on
instead of spending turns on a file it will never see.

## Devices

A project reaches a USB or serial device only when it is named twice: once in
a `devices` block of `chock.zon`, and once in a `policy` rule for the action
that block names. Chock ships no default for `device.*`, so a device named in
the `devices` block and nowhere in `policy.rules` still answers `ask`, and
`ask` refuses here: there is nobody at the keyboard to ask while a session is
already running.

```zon
.{
    .devices = .{
        .{ .action = "device.usb.1d50.6018" },
    },
    .policy = .{
        .rules = .{
            .{ .action = "device.usb.1d50.6018", .decision = .allow },
        },
    },
}
```

**The action name is the device's identity and never its path.**
`/dev/ttyUSB0` changes with plug order and after a reboot, so a rule written
against it stops being true the moment the board is unplugged and plugged
back in. A USB device is named `device.usb.<vendor>.<product>`, in lower case
hex. A serial adapter with a serial of its own is named
`device.tty.serial.<serial>`, because a whole run of USB-to-serial chips from
one factory can share a vendor and product id, and the serial is what tells
two of them apart. A serial adapter with none is named
`device.tty.<vendor>.<product>`, the same shape as a USB device.

Naming a device in the `devices` block only says the project wants it. The
`policy` rule beside it is what lets a session reach the node. See
[running.md](running.md) for what the `devices` block does and when a device
that arrives is picked up, and [sandbox.md](sandbox.md) for what the grant
itself does and does not bound.

## The ratchet

**An agent may propose policy, for a subagent it spawns and for itself.
Narrowing is free. Widening needs authorisation.**

The moment of clearest thinking is before the work. An agent that says "this
task needs no network" while it is planning is more trustworthy than one
deciding the same thing with a failing test in front of it, because nothing is
at stake yet. The `restrict_self` tool is how it says so. It names one action,
or a class of them, and the most the agent may still do with it.

**A restriction held only in the model's attention is not a restriction.** It
is lost to a compaction, to a resume, to a handover, and to a subagent that
never saw the turn it was written on. So a restriction is an event in the
session log, and it is folded back out of the log exactly the way the task
list is.

The agent cannot lift it alone, and that is structural rather than a check:

1. **The effective ceiling is the minimum over every restriction that covers
   the action.** Adding one more can only lower it.
2. **The fold appends.** There is no event an agent can write that removes a
   restriction.
3. **A proposal that asks for more than the agent holds is refused before
   anything is written.** Nothing reaches the log, so there is nothing for the
   minimum to read, and the agent is told, rather than carrying on believing
   it was lifted.

**The one way out is `policy.widen`, which is an ordinary row of the table.**
An agent that wants more than it promised must name the promise exactly as it
wrote it, and the broker then weighs the request the way it weighs any other
act. A project that writes no rule for `policy.widen` gets `ask`, so a session
with nobody to ask is refused. An authorised widening writes one more event,
and the fold reads that one as a replacement of the named promise rather than
as one more term of the minimum. Every other promise is untouched. **The agent
cannot mark the event itself**: the loop writes the mark, and only after an
answer from the broker.

**And the agent does not enforce this on itself.** A check an agent performs on
itself is worth nothing. The broker reads the folded restrictions and narrows
the decision there, in the one process the agent cannot reach.

**A promise binds the children too**, or one spawn undoes it. An agent that
promised not to apply its work and then started a subagent to apply it has
kept the letter of the promise and none of it. A child's own log holds none of
its parent's promises, so the chain is folded again over every ancestor.

## An organisation above a project

`chock.zon` is written by the developer who owns the directory. That is the
right shape for a developer deciding what an agent may do to their own
repository, and the wrong shape for an organisation deciding what an agent may
do to anything. An organisation decides once and every project receives, so
the outermost layer cannot be a file inside the thing it is meant to bound.

An **org policy bundle** is that outer layer. It lives in the data directory,
written by whatever installed Chock and beyond the reach of the project.
`chock run --org-bundle <path>` reads one instead.

It is the same ratchet one level up, with the same arithmetic and no second
policy system:

- A bundle holds the same rules, with the same four key fields, the same
  dotted patterns, and the same rule that wins.
- The bundle is folded in as one more term of the same minimum.
- **A rule of `chock.zon` can lower an answer and can never raise one.**

That last line is why `sandbox.jit` is a row here rather than a key in
`chock.zon`. One rule in the bundle,
`.{ .action = "sandbox.jit", .decision = .deny }`, forbids the sandbox
hardening being given up in every project of the installation, and no project
can take that back.

**A bundle is read as a ceiling and never as a decision.** An action no bundle
rule names answers `allow`, which is no ceiling at all, and not `ask`, which is
what `chock.zon` answers for an action nobody named. Reading a bundle as a
decision would cap every action in every project at `ask` the moment an
installation was given one.

**Chock builds no identity system.** The organisation issues the credential, so
the hub that issued it already knows who the subject is. The bundle travels
with the credential and states that subject. Chock reads it and never checks
it: a bundle is trusted exactly as far as the file it was written into. The
subject is a record, so a session log says whose credential the session ran
under, and it is not a control.

**An expired bundle keeps binding, in full and for ever**, and it is said out
loud on every start. A bundle only narrows, so dropping an expired one can only
widen. Failing shut would turn an organisation's control into an outage every
time a network is missing. Falling open would let a bundle be retired by
keeping a machine off a network for long enough. A bundle that has already
expired when it is first given to Chock is refused instead.

A bundle can also require an audit sink. A session whose required sink still
held none of the tail of the log at the end exits `9`, which is a status and
never a refusal to run. See [running.md](running.md).

`lsp.<program>` is the action for starting a project's language server, named
after the last part of the program's path: a `command` of
`/nix/store/aaa/bin/zls` asks about `lsp.zls`. Chock ships `lsp.*` as `allow`,
so a project that already has one is unchanged, and an organisation that wants
none writes one rule:

```zon
.{ .action = "lsp.*", .decision = .deny }
```

**A label is not an identity.** A project writes its own `chock.zon`, so a
project that wanted to could point the name `zls` at another binary. `lsp.*` is
the rule to trust, and `lsp.zls` is a convenience. What bounds the damage is
not the name: the server runs inside the same sandbox a tool call gets, and
reaches nothing a tool call cannot. A program whose name cannot be one label of
a rule does not start at all, and says so.

### The ceilings that are fields and not rules

Some things a project sets are numbers rather than decisions, and a rule cannot
narrow a number. A bundle therefore carries four blocks of its own:

- `budget` sets the most a session of this installation may spend. A project
  that asks for more is **refused when it starts**, and both numbers are in
  what the person reads. It is not lowered quietly, because a session that ran
  at the lower number would stop in the middle of the work with nothing said
  about why.
- `subagents` sets the largest spawn tree any project may ask for, with
  `max_depth` and `max_width`. Each is optional on its own. A project above
  either one is **held to the bundle's number** and is not refused, because a
  spawn this stops says so at the moment it happens. The message names the
  bundle as the source, so nobody is sent to edit a `chock.zon` that does not
  hold that limit.
- `limits` sets the most a sandboxed program of this installation may use: how
  many processes and threads, and how much resident memory. See
  [Sandbox resource limits](#sandbox-resource-limits) below for the block
  itself. The same shape as `subagents`: a project above the bundle's number
  is **held to it and is not refused**, because `/proc/meminfo` reports the
  whole machine and `/sys/fs/cgroup` is hidden from the program the limit
  bounds, so a project this narrows has no way to see the cap from inside its
  own sandbox. `chock doctor` reports the ceiling, resolved against the
  machine it runs on, so a person can read the number before a session ever
  starts.
- `nix` sets the most a session of this installation may add to the Nix
  store: how large one object may be, and how much a whole session may add in
  total. See [Nix store byte caps](#nix-store-byte-caps) below for the block
  itself. The same shape as `limits`: a project above the bundle's number is
  **held to it and is not refused**.

The budget ceiling differs from the other three on purpose. A refusal is right
when the narrowing would otherwise be discovered late and without a reason,
and a quiet minimum is right when the narrowing announces itself where it
lands: a spawn that is refused says so, and `chock doctor` says so for a
sandbox held to a lower number than a project asked for.

## Sandbox resource limits

A `limits` block in `chock.zon` sets how many processes and threads, and how
much resident memory, one tool call's sandbox may use:

```zon
.{
    .limits = .{
        .processes = "50%",
        .memory = "4GiB",
    },
}
```

**Either field takes a percentage of what the machine has, or an absolute
value.** `processes` resolves a percentage against this machine's own cpu
count; `memory` resolves one against its total memory. A percentage above 100
is refused when the file is read, with a message that names the field. An
absolute value is a bare number, or a number with a unit this reader knows:
`B`, `KiB`, `MiB`, `GiB`, `TiB`. `.processes = 300` and `.processes = "300"`
say the same thing; `chock.zon` accepts both, and a bare number needs no
quotes.

**Chock's own default is sized to the machine, and not one fixed number for
every machine.** The sandbox used to set a flat ceiling of 256 processes and
2 GiB of memory everywhere. On a 128 cpu machine, `cargo` defaults to about
128 parallel `rustc`, each wanting several threads of its own, and Linux
counts threads against a process limit, so that budget was exhausted at once
and every `rustc` died with `EAGAIN` on thread spawn. Two crates were also
`SIGKILL`ed at the memory ceiling, and the sandboxed program could not see why:
`/proc/meminfo` reported the whole machine's memory, because `/sys/fs/cgroup`
is hidden from the program a limit bounds. So the built in default now scales
with the machine: an ordinary 8 cpu, 16 GiB machine still gets exactly 256
processes and 2 GiB, and a 128 cpu machine gets 1024 processes without a
project configuring anything at all.

**A project's own block wins over that default, and an operator's own default
wins over Chock's.** `~/.config/chock/config.zon` takes the same `limits`
block, in the same shape, and sets the machine's own default: every project on
that machine which names no `limits` field of its own gets the operator's
number instead of Chock's built in one. The order, from the number a session
actually uses back to where it may have come from:

1. The project's own `chock.zon`, if it names the field.
2. The operator's own `config.zon`, if it names the field and the project did
   not.
3. Chock's own machine sized default, if neither did.
4. The org policy bundle's own `limits` ceiling, over whichever of the above
   won, if the bundle sets one. See
   [The ceilings that are fields and not rules](#the-ceilings-that-are-fields-and-not-rules).

A misspelled field inside a `limits` block, in either file, is refused rather
than read as the default: `.{ .limits = .{ .procceses = "50%" } }` stops the
file being read, the same rule every other block in `chock.zon` keeps.

The numbers this fold answers are what every tool call of the session runs
under: `chock run` reads the two files once, before the first call, and writes
the result into the sandbox it builds. A session the org ceiling lowered says
so on its own output, once, with the number it was held to, because the
program the number bounds cannot read it from inside the sandbox.

## Nix store byte caps

A `nix` block in `chock.zon` sets how much a Nix evaluation may add to the
store:

```zon
.{
    .nix = .{
        .max_object_bytes = "16MiB",
        .max_session_bytes = "256MiB",
    },
}
```

`max_object_bytes` bounds one object the store accepts: a Nix source file, a
derivation, or a build output. It is checked against
`chock_nix.backend.Driver` before the object reaches a store at all.
`max_session_bytes` bounds the total a whole session may add across every
object, and every build of one session spends against the same number. A
build whose derivation would pass it is refused while it is being written, so
nothing is built.

Neither field takes a percentage. `limits.processes` and `limits.memory`
each resolve one against something the machine reports, a cpu count or a
total, and a store object has no such quantity to be a share of. A percentage
here is refused when the file is read, with a message that says why. Each
field is a bare number, or a number with a unit this reader knows: `B`, `KiB`,
`MiB`, `GiB`, `TiB`.

The fold is the same order `limits` uses:

1. The project's own `chock.zon`, if it names the field.
2. The operator's own `config.zon`, if it names the field and the project did
   not.
3. Chock's own built in default, if neither did.
4. The org policy bundle's own `nix` ceiling, over whichever of the above
   won, if the bundle sets one. See
   [The ceilings that are fields and not rules](#the-ceilings-that-are-fields-and-not-rules).

A misspelled field inside a `nix` block, in either file, is refused rather
than read as the default, the same rule `limits` keeps.
