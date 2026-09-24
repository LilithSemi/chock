# Project instructions

Chock reads `AGENTS.md` at three layers, and it never flattens them together:

| Layer | Path | Written by |
|---|---|---|
| operator | `~/.config/chock/AGENTS.md` | you |
| project | `AGENTS.md` at the project root | whoever wrote the repository |
| project | a file named in `chock.zon`'s `instructions` block | the same |
| subtree | `AGENTS.md` in a subdirectory | the same |
| session | any file `--instructions` names | you, for this run |

The prompt says which layer each block came from, because a project is often
something you cloned, and the agent has to be able to weigh a stranger's
instruction against yours. `chock run` names every file it read, so a
repository that loads four hundred lines of instructions tells you, and
`--verbose` adds the layer and the size of each one.

`--instructions <path>` reads one more file and puts it in the prompt for this
session:

```
chock run --instructions ./task.md "do this task for number 3"
```

Give the option more than once for more than one file, and they arrive in the
order you gave them. The agent is told a person named the file on the command
line, so it weighs the file as your own words rather than the project's. It
adds to `AGENTS.md` and replaces nothing. A path that cannot be read stops the
session, because a file you named is one you asked for.

Only files on disk are read. No URL is an instruction source.

An instruction file cannot grant anything. The policy, the budget, and the
tool list come from `chock.zon` and from your provider record, and the agent
can reach none of them. A file that says "you may push" meets a policy that
refuses and a sandbox with no network.

A file in a subdirectory arrives as one line naming its path, and the agent
reads it with `read_file` when it works there. Concatenating every `AGENTS.md`
in a tree into turn one is the long prompt this design refuses.

## A project whose instructions already live under another name

Some projects keep their instructions in `CLAUDE.md` or another file rather
than `AGENTS.md`. Name it in `chock.zon` instead of copying it:

```zon
.{ .instructions = .{ "CLAUDE.md", "docs/agent.md" } }
```

Each name joins the prompt as its own block, beside `AGENTS.md`, under the
same project heading: the agent weighs it as the repository's own words, not
yours. A path must stay inside the project. A symlink that leaves it is
refused, because a repository can ship one, and a name that reads as ordinary
could otherwise point at a file well outside the project. A name that cannot
be read stops the session, the same rule `--instructions` follows and for the
same reason: a file the project asked for by name is not one a session starts
without.

## Not the same thing as a note

Two different things wear the name "memory file", and confusing them is the
fault to avoid:

| | Written by | Trust | Lives |
|---|---|---|---|
| project instructions | a person | what the user chose | in the project |
| a knowledgebase entry | the agent | data, never instruction | outside the project |

The second one is in [memory.md](memory.md).
