# Notes an agent keeps between sessions

`write_memory` saves one fact, and a later session gets an index of one line
per note in its prompt and calls `read_memory` for the ones that apply. The
bodies are never in the prompt, so two hundred notes cost two hundred lines.

**This is not a notes directory.** It is a knowledgebase: one fact per entry,
fetched by name, with an index of one line descriptions in the prompt. That is
the other half of making a small model effective, because re-deriving is what a
small model is worst at.

Each entry carries a kind, and the kind is not decoration. It is what tells a
reader how fast the entry goes stale: `insight`, `code_fact`, `convention`,
`gotcha`, `dead_end` and `environment`. A convention outlives a fact about the
code, and a dead end outlives both. "We tried X, it does not work, because Y"
saves the next agent the whole detour, and nobody ever thinks to write it down.

## Where notes go, and how many

Notes go to `~/.local/share/chock/memory/<project>/`, **never into your
project**.

| Bound | Value |
|---|---|
| names per project | 128 |
| bytes per version | 16 KiB |
| versions per name | 16 |
| bytes in a name | 64 |

Writing a name that already exists **supersedes** that note rather than making
a second one, and the older version stays in the file. So correcting a fact
never meets the cap on names, and the whole history of one name is something a
person reads in one sitting.

```
chock memory                        # one line per note
chock memory show <name>
chock memory forget <name>
chock memory clear
```

## The hazard, which is real

A writable memory directory is two things at once: a place to keep notes, and a
channel out of the sandbox that does not pass through `workspace.apply`. It is
also a persistence mechanism, because a note written this session is read next
session.

**An agent that writes its own instructions has written its own prompt for next
time**, which is the same fault as an agent editing `chock.zon` reached by a
slower route. A memory written by a compromised session is a persistent
injection into every future session, and it survives the sandbox by
construction, because outliving the sandbox is what memory is for.

Three rules hold it:

1. **A note is data, and never an instruction.** It arrives labelled as
   something the agent wrote, and the prompt says the user's request wins when
   the two disagree.
2. **It is bounded**, by the table above. A memory directory is not a place to
   move a repository through one file at a time, and a name is a plain name.
3. **It is mounted for those two tool calls and for no other.** The
   knowledgebase directory is the one writable path outside the workspace, and
   `run_command` cannot reach it, because it is not in that call's mount tree
   at all. It is not merely read only to the rest of the sandbox: it is not
   there.

Read them. A note written by a session that went wrong is read by every
session after it.
