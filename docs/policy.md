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
toolchain paths a `run_command` call may execute, and the guidance and memory
tools, all answer `allow` out of the box. A shipped default is a lower class
of rule than anything in `chock.zon`: it is read only when a project's own
rules name nothing that matches the key at all. **A project rule that matches
wins outright**, whatever it names and however wide it is next to a default,
because the entire reason a default exists is to answer for a key the project
did not. Writing `.{ .action = "call.write_file", .decision = .ask }` in your
own `chock.zon` puts that call back behind a prompt, even though a shipped
default would otherwise let it through.

`net.connect.*` and `net.fetch.*` hold no shipped default, on purpose: a
project that named nothing about a host still meets `ask` there, never
`allow`. See [threat-model.md](threat-model.md) for what an `ask` on
`net.connect.*` can now reach.

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

**Only part of the shim is wired in this release.** A subcommand that has to
reach another host, such as `git push`, is refused with a sentence that says
why. Every other subcommand, `git commit` included, runs the real git inside
the sandbox, and no approval request is sent. So `git.commit`, `git.push` and
`git.branch.delete` are rows the table can answer, and nothing in a session
asks them yet. The same is true of `file.write`.

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
apply should land, with `.apply = .{ .mode = .merge }` and the four modes
[approvals.md](approvals.md) lists. This row says whether that mode may be
anything but `ref`, which is the mode that moves no branch of yours.

```zon
.{ .action = "workspace.integrate", .decision = .deny }
```

**A row nobody wrote answers `allow` here**, unlike every action above, because
this is a question about a capability and not about an act: a project that wrote
`merge` and an installation whose organisation has never heard of the row gets
`merge`. That is the same reading `provider.<instance>` gets, and it is what
keeps a permission model from breaking every configuration the day it ships. One
`deny` in an organisation's bundle closes the road for every project under it,
and the same fold means a subagent moves no branch its parent could not.

Only `allow` keeps the mode. The answer is read once, when the session starts,
before an apply is described, because the description is what a person reads and
it has to say what the apply does. So `ask` here holds the work at the ref
exactly as `deny` does.

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
