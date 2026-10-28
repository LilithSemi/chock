# Commands

A command is a message somebody wrote once, under a name. `chock run /review`
sends that message instead of making you type it again.

```
$ chock run /review src/main.zig
chock: command review (project, .chock/commands/review.md)
```

A command is a file with YAML frontmatter, and `description` is the only field
it must carry. The name is the name of the file.

```markdown
---
description: Review a file the way this repository reviews one.
argument-hint: <path>
---

Read the whole of $1 before you say anything about any part of it.
Then say what it does, and what you would change.
```

## Where Chock looks

| Layer | Where | Written by |
|---|---|---|
| operator | `<config dir>/commands/` | you |
| project | a directory this project's `chock.zon` names | whoever wrote the repository |

A project says where its own are:

```zon
.{
    .commands = .{ ".chock/commands" },
}
```

The path must be under the project and must not climb out of it. A symbolic
link is followed and then checked, the same rule
[skills.md](skills.md) states and for the same reason: a repository can ship a
link that reads as ordinary.

Two commands cannot share a name. The layer that comes first keeps it, so your
own command wins over a repository's, and the one that lost is reported rather
than dropped without a word. At most 32 commands are read, and a file larger
than 16KB is refused, because a command is a message rather than a document.

## What the agent is told

The message says which command ran and who wrote its text:

```
The person running you ran this project's command `review`. Whoever wrote this
repository wrote the text that follows, and the person chose to run it.
```

A repository's command is a stranger's words that you chose to send, so the
agent weighs it the way it weighs that repository's `AGENTS.md`. Read one
before you run it:

```
chock commands show review
```

## Arguments

Everything after the name is the command's arguments.

| In the text | Becomes |
|---|---|
| `$ARGUMENTS` | everything you typed after the name |
| `$1` to `$9` | one word each, counting from the first |
| `$$` | one dollar sign, and takes nothing |

A text that names none of these still gets what you typed, on a line of its
own, because an argument you typed is not one to throw away.

Nothing is interpolated into a program's arguments. A command becomes a
message and nothing else, so there is no shell to read a quote, a semicolon, or
a backtick, and a command cannot name a tool to run. What the agent may do
comes from the policy, which [policy.md](../configure/policy.md) covers, and a
command cannot reach it.

## What a command cannot do

The agent cannot run a command, cannot list them, and cannot read their text.
Only a person at the command line can, by typing the name. So a command is a
shortcut for you and not a capability for the agent, and a repository that
ships one has written a message you may choose to send.

A message that begins with a slash and a name is read as a command. A name that
is not one Chock found stops the session and lists the names that exist, rather
than sending the slash to the model. `/home/ross/chock is broken` is not a
command, because its first word holds characters a name cannot.

## Checking one before a session reads it

```
chock commands validate .chock/commands
chock commands validate .chock/commands/review.md
```

Each line says one of three words, the same three
[skills.md](skills.md#checking-one-before-a-session-reads-it) uses: `ok`,
`problem`, and `note`. A problem exits 2. A note alone exits 0, because a field
this build does not read is not a refusal.

`chock commands` on its own lists what a session would find, with the layer and
the description of each.

A session reads a command directory only when the message names a command. A
project with a mistake in its `commands` block hears about it at that moment,
and `chock commands` is how to find one before then.
