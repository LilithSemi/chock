# Running a session

```
cd ~/some-project
chock run "add a test for the parser"
chock -- add a test for the parser      # the same task, with no subcommand
chock                                   # the interface, which asks for the task
echo "add a test for the parser" | chock
```

**A first word is read as a command name**, so a task given to bare `chock`
goes after `--`. `chock fix the parser` is refused and says so, because a
mistyped `chock rnu` that quietly became a task would spend money on a typo.
The words after `--` are joined with one space, so `chock -- fix the parser`
and `chock run "fix the parser"` ask for the same thing. Bare `chock` with no
task at all brings the interface up and asks for one there.

With no message on the command line the message comes from standard input, so
a pipe works. `--continue` continues the newest session of the project, and
`--session <id>` continues the one you name.

A quiet start says which session this is and warns about anything that changes
what the agent can see. Every other fact a start used to print is one command
away: `chock sessions`, `chock cache`, `chock usage`, and `chock memory` answer
them, and `--verbose` puts them back on screen. Every command takes `--verbose`
and `--color=auto|always|never`. Colour says how much a line matters and never
what it is about, and it is used only on a terminal that can show it: a pipe, a
file, `NO_COLOR`, and `TERM=dumb` all get plain text.

Every tool call runs inside the sandbox, in a throwaway copy of the project:
a linked git worktree for a git project and an overlay otherwise. Your real
project is never written by a tool call. See [sandbox.md](sandbox.md).

By default the agent sees the committed state of the project. `--allow-dirty`
copies your uncommitted work into the workspace as well.

## The tools

The agent has fifteen tools, and every one that touches the machine goes
through that sandbox: `read_file`, `list_directory`, `glob`, `grep`,
`write_file`, `edit_file`, `run_command`, `read_memory` and `write_memory`.
Only `run_command` takes a command. The rest name a path, a pattern, or the
text to write, because a person can review a change and cannot review a shell
line.

`read_guidance` reads a document compiled into Chock, so it reaches nothing on
the machine at all. The other five are described on pages of their own:

| Tool | What it asks for | Page |
|---|---|---|
| `provide_tool` | a program the session has not got | [tools.md](tools.md) |
| `spawn_agent` | a subagent | [subagents.md](subagents.md) |
| `restrict_self` | a promise the agent cannot take back | [policy.md](policy.md) |
| `fetch_url` | one page over http or https | [policy.md](policy.md) |
| `update_plan` | a task list you can watch | below |

## What the harness tells the agent

The loop knows things the model can only estimate, and it says them at the end
of a turn's context: the time, the task restated, a call the agent has already
made, a file it has already read and that has not changed, the budget, and the
work it cannot see. `chock run --no-notices` turns all of it off, for measuring
whether any of it helps.

## The session log

The session log is the session. It goes to
`~/.local/state/chock/sessions/<project>/<session id>.jsonl`, and `chock run`
prints its path before it starts.

**Which sessions are running comes from the lock, never from a timestamp.** The
process holding a session log's lock is the one that owns that session, which is
the same fact `chock detach` moves from one process to another. So asking the
kernel whether the lock is held is exact and free, and it is right about the case
every rule over a modification time gets wrong: a session that was killed leaves
a log written a moment ago and no process at all.

```
chock sessions                          # every session, oldest first
chock sessions verify [<session>]       # read the hash chain, and the seal
chock sessions seal [<session>]         # sign the head of a log's chain
chock sessions seal --require-card      # sign on a card, or write nothing
chock sessions export [<session>] --to <dir>
chock sessions remove <session id>
chock sessions prune --older-than 30
```

The listing needs no index, because a session identifier starts with the
millisecond it was made and sorts in that order, so the directory is already the
list. The same identifier is where the start time comes from, rather than a
file's modification time, which a copy or a restore moves.

Every event holds the hash of the line before it, so `verify` finds an event
that was changed after the fact and names it. **A hash chain is not a
signature.** Whoever can rewrite the whole file can write a chain that agrees
with it, and what the chain finds is an edit in the middle. `seal` signs the
head of the chain into a file beside the log, which a rewrite of the whole log
cannot forge. A log with no seal is never reported as passing.

**`seal` signs with a card key when a card gives one, and says which key signed
every time.** A machine with no reader gets a software seal, and the line at the
end of the run says so. A person who answers the PIN prompt and does not get a
card seal gets no seal at all and a non-zero exit: they asked for the card, it
did not happen, and a weaker file written quietly is a downgrade they would not
see. Pressing Enter at the prompt is a choice and gives a software seal. Pass
`--require-card` to refuse every software seal, which is what a public release
wants.

**Removing a session asks first, and `chock cache clear` does not.** A cache is
rebuilt by the next build. A session log is the only record of what an agent did,
nothing else holds a copy, and no step makes it again. So a removal names the log,
the workspace and the sandbox root it would take, says that plainly, and waits for
a yes. A caller with nobody at the keyboard gets no removal unless it passes
`--yes` and takes the decision itself. **A session that is running is never
removable**, and neither is one whose lock could not be tested.

## Getting the work back

Work reaches your project only when the agent commits it in the workspace
**and** the policy in your `chock.zon` permits the apply. It lands on
`refs/chock/<session id>`, never on a branch of yours, so `git log` reads it
and `git merge` takes it. See [approvals.md](approvals.md).

**A session that does not end cleanly keeps its workspace**, and prints where
it is. Errored, refused, budget reached, no progress, interrupted: whatever
the agent wrote is still on disk, so a run that went wrong is something you
can salvage rather than a total loss. A clean run removes its own workspace as
it always did.

```
chock workspace                     # every kept workspace, with its size
chock workspace clear
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | finished |
| 1 | the command line was not understood, or the session could not start |
| 2 | a fault |
| 3 | refused or canceled |
| 4 | the turn limit from `--max-turns` |
| 5 | a subcommand that is not built |
| 6 | the agent gave up, because it stopped making progress |
| 7 | the budget in `chock.zon` |
| 8 | handed over to another process, so the work is not over |
| 9 | a required audit sink still held none of the tail of the log |
| 10 | the model backend answered a turn with nothing, so there is no answer |

A session that changed files and never committed them exits `2`, and says so:
only a commit is carried back. **A refusal is not a crash and must not look
like one**, which is why `3` is a code of its own: a script that treated it as
a fault would retry something a person already said no to.

## What a session cost

**What a session cost comes out of its own log**, because every turn's usage
is an event in it. So the number survives a handover, a reconnect and a
replay, and it is the same number a budget in `chock.zon` is enforced against.

```
chock usage                         # every session, and the total
chock usage show <session id>       # one session, model by model
```

Free, priced and unknown are three answers and never two. A local model costs
nothing, which is a fact. A model no price table names costs a number nobody
has, and **unknown is not zero**: those turns are counted and reported apart,
and no figure is invented for them.

## The task list

**An agent can keep a task list, and you watch it get crossed off.** It is not
mandatory and most work needs none: a one step task with a task list is noise.
When an agent does keep one, each step that moves is one line on your terminal
while the session runs, and the list is in the session log rather than in a
scratch file, so it replays, it survives a compaction and a handover, and a
phone that attaches sees the same list the terminal does.

```
chock plan                          # every session that kept a list
chock plan show <session id>        # one session, step by step
```

**A step the agent decided not to do reads as "abandoned" and stays on the
list.** Nothing is ever removed, so a step that was given up can never be
mistaken for one that was finished, and a step the agent simply stopped
mentioning is still there at the status it last had. That is the fact this is
worth keeping for: a list where work quietly disappears reads as complete when
it is not.

## A rate limit

**A rate limit is waited out, not a way for a session to die.** A 429 or a 5xx
is a transport fault: Chock honours the provider's own `Retry-After` when it
sends one, backs off exponentially with jitter when it does not, and says on
screen that it is waiting. Six attempts, with waits of about 2, 4, 8, 16 and
32 seconds, so a bad minute costs a minute. A session that runs out of them
ends saying how many were made and what the provider last said. A full context
is a different fault with a different answer, compaction, and the two are
never joined.

A stream that broke in the middle of a reply is **not** retried. The turn half
happened, and sending it again is a larger change than the wait was.

## Shipping the log elsewhere

`chock run --export-dir <dir>` writes the log into a second directory as it is
written, one file per session, byte for byte, so `chock sessions verify` reads
it there too. `--export-syslog <path>` sends each line to a unix datagram
socket as an RFC 5424 message. A syslog message is not a copy of the log: use
`--export-dir` for one that verifies. An org policy bundle can require a sink
of either kind. See [policy.md](policy.md).

## Whether this machine can run a session

```
chock doctor
```

`chock doctor` measures each sandbox layer for real, in a forked child, and
says which are on. It exits `0` when a first run can work here, even with a
layer missing, and `2` when it cannot. See [sandbox.md](sandbox.md) for what
the rows mean.
