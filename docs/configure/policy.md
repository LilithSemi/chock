# Policy

What an agent may do is a static table in `chock.zon`, in the project root.
The table is declarative, so a reader sees the rules without running them.

Chock binds `chock.zon` into the workspace read only, so the agent works under
rules it cannot edit.

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

A rule written directly under `.policy` is a syntax error. `.policy` holds
named fields, so a rule beside `.agents` gives:

```
chock run: the workspace for /home/you/site could not be built: chock.zon is
not valid:
4:9: error: expected field initializer
```

The message names the file and not one block, because Chock reads the whole
file before it can tell which block the fault is in. The line and the column
say where to look. There is a complete `chock.zon` with every block in it in
[configuration.md](configuration.md).

This page says how a rule is read. Every action a rule can name, and the rules
Chock ships, are in [actions.md](actions.md), and the layer an organisation
puts above a project is in [org.md](org.md).

## The key and the answer

A rule has five fields. `agent_kind`, `model`, `tool` and `action` name the
key, and each of the four is optional. A field that is absent matches every
value. `decision` is the answer, and it is required.

The five decisions, from the most restrictive to the least: `deny`,
`agent_then_human`, `ask`, `agent_review`, `allow`. `ask` puts the question to
a person. `agent_review` needs one yes from a reviewer agent.
`agent_then_human` needs both, and [approvals.md](../using/approvals.md) shows
what each one looks like while a session runs.

A name that ends in `.*` matches every name below that prefix. `git.*` matches
`git.push` and `git.branch.delete`, and it does not match `git` itself. Any
other name matches only itself. A bare `"*"` is an error: leave the field out
instead, so one meaning keeps one spelling.

The most specific rule wins. Specificity is compared one field at a time, in
this order: the action, then the tool, then the model, then the agent kind.
Inside one field, an exact name beats a `.*` name, and a longer prefix beats a
shorter one. Both beat an absent field.

Two rules can reach the same score and still both match. The more restrictive
decision then wins, so the answer never depends on the order the rules have in
the file.

An action no rule names, and no shipped default names either, answers `ask`. A
session with nobody at the keyboard is refused there.

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
Seatbelt rule that refuses a read and a write of the named path. The bytes stay
where they are and the kernel refuses every open of them, which gives the same
answer to a tool call by a different road.

A few things are refused by name rather than half supported, and the refusal
happens when the session starts, not later:

- A directory. `~/.aws` is a directory, and a covered directory would read as
  "this project keeps no credentials here", which sends a model looking for
  something that is not missing. Name the files.
- An absolute path. The sandbox holds your project and a read only toolchain
  and very little else, so anything outside the project is already absent, and
  accepting the path would promise a protection this does not give.
- A glob. A pattern that matches nothing reads exactly like a pattern that
  protects something.
- `chock.zon` itself. It is already bound read only, and denying it would only
  hide the project's rules from the agent working under them.

A path you name that does not exist yet is covered anyway, so a `.env` that is
in `.gitignore` today is still unreadable on the day somebody makes one. The
cost is one empty file of that name left in the throwaway workspace, which
reaches your repository through nothing but a commit.

`read_file`, `write_file` and `edit_file` refuse a denied path with a sentence
that names the file and this block, so the model reads it once and carries on
instead of spending turns on a file it will never see.

## The ratchet

An agent may propose policy, for a subagent it spawns and for itself.
Narrowing is free. Widening needs authorisation.

The `restrict_self` tool is how an agent narrows its own ceiling. It names one
action, or a class of them, and the most the agent may still do with it.

A restriction is an event in the session log, so it survives a compaction, a
resume, a handover, and a subagent that never saw the turn it was written on.
It is folded back out of the log the way the task list is.

The agent cannot lift it alone, and that is structural rather than a check:

1. The effective ceiling is the minimum over every restriction that covers the
   action. Adding one more can only lower it.
2. The fold appends. There is no event an agent can write that removes a
   restriction.
3. A proposal that asks for more than the agent holds is refused before
   anything is written. Nothing reaches the log, so there is nothing for the
   minimum to read, and the agent is told rather than left believing it was
   lifted.

The one way out is `policy.widen`, which is an ordinary row of the table. An
agent that wants more than it promised must name the promise exactly as it
wrote it, and the broker then weighs the request the way it weighs any other
act. A project that writes no rule for `policy.widen` gets `ask`, so a session
with nobody to ask is refused. An authorised widening writes one more event,
and the fold reads that one as a replacement of the named promise rather than
as one more term of the minimum. Every other promise is untouched. The agent
cannot mark the event itself: the loop writes the mark, and only after an
answer from the broker.

The agent does not enforce this on itself. The broker reads the folded
restrictions and narrows the decision there, in the one process the agent
cannot reach.

A promise binds the children too, or one spawn undoes it. A child's own log
holds none of its parent's promises, so the chain is folded again over every
ancestor.
