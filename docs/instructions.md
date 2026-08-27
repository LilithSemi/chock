# Project instructions

Chock reads `AGENTS.md` at three layers, and it never flattens them together:

| Layer | Path | Written by |
|---|---|---|
| operator | `~/.config/chock/AGENTS.md` | you |
| project | `AGENTS.md` at the project root | whoever wrote the repository |
| subtree | `AGENTS.md` in a subdirectory | the same |

The prompt says which layer each block came from, because a project is often
something you cloned, and the agent has to be able to weigh a stranger's
instruction against yours. `chock run` names every file it read, so a
repository that loads four hundred lines of instructions tells you, and
`--verbose` adds the layer and the size of each one.

**Only files on disk.** No URL is an instruction source.

**An instruction file cannot grant anything.** The policy, the budget, and the
tool list come from `chock.zon` and from your provider record, and the agent
can reach none of them. A file that says "you may push" meets a policy that
refuses and a sandbox with no network.

A file in a subdirectory arrives as one line naming its path, and the agent
reads it with `read_file` when it works there. Concatenating every `AGENTS.md`
in a tree into turn one is the long prompt this design refuses.

## Not the same thing as a note

Two different things wear the name "memory file", and confusing them is the
fault to avoid:

| | Written by | Trust | Lives |
|---|---|---|---|
| project instructions | a person | what the user chose | in the project |
| a knowledgebase entry | **the agent** | **data, never instruction** | outside the project |

See [memory.md](memory.md) for the second one.
