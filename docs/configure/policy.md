# Policy

What an agent may do is written as a static table in `chock.zon`, in the
project root. The table is declarative, so you can read the rules without
running them.

Chock binds `chock.zon` into the workspace read only, so the agent works under
rules it cannot edit.

Here is a complete file. The outer `.{ }` is the whole of `chock.zon`, and
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

A rule written directly under `.policy` is a syntax error, because `.policy`
holds named fields. A rule beside `.agents` gives:

```
chock run: the workspace for /home/you/site could not be built: chock.zon is
not valid:
4:9: error: expected field initializer
```

The message names the file rather than one block, because Chock has to read
the whole file before it can tell which block the fault is in. The line and the
column say where to look. You can find a complete `chock.zon`, with every block
in it, in [configuration.md](configuration.md).

This page explains how a rule is read. Every action a rule can name, and the
rules Chock ships, are in [actions.md](actions.md), and the layer an
organisation puts above a project is in [org.md](org.md).

## The key and the answer

A rule has five fields. Four of them, `agent_kind`, `model`, `tool` and
`action`, name the key, and each one is optional: a field you leave out matches
every value. `decision` is the answer, and it is required.

There are five decisions, from the most restrictive to the least: `deny`,
`agent_then_human`, `ask`, `agent_review`, `allow`. `ask` puts the question to
a person, and `agent_review` needs one yes from a reviewer agent.
`agent_then_human` needs both, and [approvals.md](../using/approvals.md) shows
what each one looks like while a session runs.

A name that ends in `.*` matches every name below that prefix, so `git.*`
matches `git.push` and `git.branch.delete` but not `git` itself. Any other name
matches only itself. A bare `"*"` is an error: leave the field out instead, so
that one meaning keeps one spelling.

The most specific rule wins. Specificity is compared one field at a time, in
this order: the action, then the tool, then the model, then the agent kind.
Inside one field, an exact name beats a `.*` name, a longer prefix beats a
shorter one, and both beat a field that is not there at all.

Two rules can reach the same score and still both match. When that happens, the
more restrictive decision wins, so the answer never depends on the order the
rules happen to sit in the file.

An action that no rule names, and no shipped default names either, answers
`ask`. A session with nobody at the keyboard is refused there.

## A rule for one run

`--policy-rule "<action>=<decision>"` adds one rule for this session alone:

```
chock run --policy-rule "net.fetch.*=allow" "read the changelog"
```

You can repeat it. Each one names an action and a decision and nothing else,
because a rule that narrows by tool, model or agent kind belongs in a file
somebody can read back later.

The flag sits between the two layers that already exist. It answers instead of
the project's `chock.zon`, and the org bundle still holds it, so a rule here
cannot reach past a ceiling an organisation set. In the other direction, a
project that denies an action does not stop you allowing it for one run on
your own machine.

It is a layer of its own, never a rule appended to the file's. When two rules
of one list name the same action, the narrower decision settles it, so a
`git.push=allow` merged into a file that denies `git.push` would lose and do
nothing at all.

Every rule you give this way is printed at session start, because it is the one
part of a session's policy that no file records. It reaches no subagent: a
child reads the project's file and the org bundle alone, so a rule you give
the agent you are talking to is not one its children get.

An action this build cannot read is refused before the session starts, under
the same rule the file gets: `*` is allowed as the last part alone, so
`net.fetch.*` is a pattern and `net.*.fetch` is a fault.

## Files the agent may not read

A `deny_read` block in `chock.zon` names files that are kept out of the session
altogether:

```zon
.{
    .deny_read = .{
        ".env",
        "config/production-secrets.zon",
    },
}
```

Each name is a path relative to the project root. Chock reads the block from
your copy of `chock.zon`, on your machine, before the workspace is built, and
then covers each named path inside the sandbox with a file that says only:

```
chock: this file is denied by the project. Its bytes are not in this sandbox.
```

The bytes are not in the mount tree a tool call reads through, so no tool, no
shell command and no program the agent runs can reach them. There is nothing to
filter and nothing to miss.

That is the Linux mechanism. macOS has no bind mount, so the denial there is a
Seatbelt rule that refuses both a read and a write of the named path. The bytes
stay where they are and the kernel refuses every open of them, which gives a
tool call the same answer by a different road.

A few things are refused outright rather than half supported, and the refusal
happens when the session starts, not later:

- A directory. `~/.aws` is a directory, and a covered directory would read as
  "this project keeps no credentials here", which would send a model looking
  for something that is not missing. Name the files instead.
- An absolute path. The sandbox holds your project, a read only toolchain, and
  very little else, so anything outside the project is already absent.
  Accepting the path would promise a protection this does not give.
- A glob. A pattern that matches nothing reads exactly like a pattern that
  protects something.
- `chock.zon` itself. It is already bound read only, and denying it would only
  hide the project's rules from the agent that works under them.

A path you name that does not exist yet is covered anyway, so a `.env` that is
in `.gitignore` today is still unreadable on the day somebody makes one. The
cost is one empty file of that name left in the throwaway workspace, and it
reaches your repository through nothing but a commit.

`read_file`, `write_file` and `edit_file` refuse a denied path with a sentence
that names the file and this block, so the model reads it once and carries on,
instead of spending turns on a file it will never see.

## The ratchet

An agent may propose policy, both for a subagent it spawns and for itself.
Narrowing is free, and widening needs authorisation.

The `restrict_self` tool is how an agent narrows its own ceiling. It names one
action, or a class of them, and the most the agent may still do with it.

A restriction is an event in the session log, so it survives a compaction, a
resume, a handover, and even a subagent that never saw the turn it was written
on. It is folded back out of the log the same way the task list is.

The agent cannot lift it alone, and that is a property of the design rather
than a check somebody runs:

1. The effective ceiling is the minimum over every restriction that covers the
   action, so adding one more can only lower it.
2. The fold appends. There is no event an agent can write that removes a
   restriction.
3. A proposal that asks for more than the agent holds is refused before
   anything is written. Nothing reaches the log, so there is nothing for the
   minimum to read, and the agent is told rather than left believing the
   promise was lifted.

The one way out is `policy.widen`, which is an ordinary row of the table. An
agent that wants more than it promised must name the promise exactly as it
wrote it, and the broker then weighs the request the way it weighs any other
act. A project that writes no rule for `policy.widen` gets `ask`, so a session
with nobody to ask is refused. An authorised widening writes one more event,
and the fold reads that event as a replacement of the named promise rather than
as one more term of the minimum, which leaves every other promise untouched.
The agent cannot mark the event itself: the loop writes the mark, and only
after an answer from the broker.

The agent does not enforce this on itself. The broker reads the folded
restrictions and narrows the decision there, in the one process the agent
cannot reach.

A promise binds the children too, because otherwise one spawn would undo it. A
child's own log holds none of its parent's promises, so the chain is folded
again over every ancestor.
