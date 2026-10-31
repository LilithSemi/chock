# Running a session

```
cd ~/some-project
chock run "add a test for the parser"
chock -- add a test for the parser      # the same task, with no subcommand
chock                                   # the interface, which asks for the task
echo "add a test for the parser" | chock
```

A first word is read as a command name, so a task given to bare `chock` goes
after `--`. `chock fix the parser` is refused and says so, because a mistyped
`chock rnu` that quietly became a task would spend money on a typo. The words
after `--` are joined with one space, so `chock -- fix the parser` and
`chock run "fix the parser"` ask for the same thing. Bare `chock` with no task
at all brings the interface up and asks for one there.

With no message on the command line the message comes from standard input, so a
pipe works. `--continue` continues the newest session of the project, and
`--session <id>` continues the one you name. `--instructions <path>` puts a
file of your own in the prompt for this run, alongside the project's
`AGENTS.md`: see [instructions.md](using/instructions.md).

A quiet start says which session this is and warns about anything that changes
what the agent can see. Every other fact is one command away: `chock sessions`,
`chock cache`, `chock usage`, and `chock memory` answer them, and `--verbose`
puts them back on screen. Every command takes `--verbose` and
`--color=auto|always|never`. Colour says how much a line matters and never what
it is about, and it is used only on a terminal that can show it: a pipe, a file,
`NO_COLOR`, and `TERM=dumb` all get plain text.

Every tool call runs inside the sandbox, in a throwaway copy of the project: a
linked git worktree for a git project and an overlay otherwise. Your real
project is never written by a tool call, and
[sandbox.md](security/sandbox.md) says what the boundary is made of.

By default the agent sees the committed state of the project. `--allow-dirty`
copies your uncommitted work into the workspace as well.

## Structured runs

`chock run --output json "fix the parser"` reserves standard output for one
JSON object. Progress and diagnostics stay on standard error. JSON mode never
reads an approval or another answer from the terminal, even when one is
attached; an action without a policy, reviewer, or remote approval answer is
refused. The process exit code and the object's `exit_code` are always the
same.

The contract is named `chock.run-result`, version `1`:

```json
{
  "schema": "chock.run-result",
  "version": 1,
  "session_id": "01M...",
  "status": "finished",
  "exit_code": 0,
  "final_answer": "The parser now rejects an empty field.",
  "usage": {
    "input_tokens": 1200,
    "output_tokens": 180,
    "cache_creation_input_tokens": 0,
    "cache_read_input_tokens": 800,
    "turns": 2,
    "cost": 0.0042,
    "currency": "USD"
  },
  "approvals": {
    "requested": 1,
    "approved": 0,
    "refused": 1,
    "unanswered": 0
  },
  "workspace": {
    "outcome": "landed",
    "changed_files": ["src/parser.zig", "test/parser.zig"]
  },
  "audit_log": "/home/you/.local/state/chock/sessions/.../01M....jsonl"
}
```

`status` uses the exit-code names in the table below. `final_answer` is null
when the model produced no textual answer. Cost and currency are null when
any turn was unpriced or currencies were mixed. `changed_files` is the sorted
set of paths represented by diff events in the audit log. Approval counts
include policy, reviewer, remote, and terminal answers; an expired, unknown,
or unavailable answer is refused, while a request with no response is
unanswered. The workspace outcome says whether work landed, was refused,
remained uncommitted, failed, or had nothing to apply. A setup failure after
machine-output options have been accepted still emits the same schema with
null session, answer, and audit-log fields.

`--output jsonl` writes live `chock.run-event` version `1` objects as the
session records them, then writes the `chock.run-result` object as the final
line. Each event line carries `session_id`, the byte-offset `event_id` used by
the audit log, and the typed event payload. Provider text fragments and
human-facing notices are not separate records: the completed, redacted message
and every policy/tool event come from the authoritative log instead. A consumer
can distinguish the final line by its `schema` field.

## The tools

Every tool the agent has, what each one asks for, and how a call is gated are
in [tools.md](using/tools.md). `provide_tool` is there too, and the two Nix
tools are in [nix.md](using/nix.md).

## Devices

A project can name a USB or serial device it wants a session to reach, in a
`devices` block of `chock.zon`, one entry per device, named by the action
`chock doctor` and a policy rule both use:

```zon
.{
    .devices = .{
        .{ .action = "device.usb.1d50.6018" },
    },
}
```

Naming a device here is not enough on its own. `chock.zon` still needs a
`policy` rule for the same action, because Chock ships no default for
`device.*`. The action names and the rule are in
[actions.md](configure/actions.md), and what the grant does and does not bound
is in [sandbox.md](security/sandbox.md).

A device is picked up at the start of each tool call, and never in the middle of
one. A sandbox is built fresh for every tool call and the call blocks until the
sandboxed program exits, so the machine is scanned once, at the moment that call
starts, for every device a project named and a policy rule allows. If you plug
a board in while a long running call is already going, that call does not see
it. The next tool call does, because it scans the machine again from nothing.
There is no live watch inside a call that is already running.

A program must wait for the device to answer, never for its path to appear.
The device is bound over a file that has to exist first, so for a moment the
path opens and reads nothing at all. A program that takes a successful open as
the signal can read an empty file where it expects the device.

## What the harness tells the agent

The loop knows things the model can only estimate, and it says them at the end
of a turn's context: the time, the task restated, a call the agent has already
made, a file it has already read and that has not changed, the budget, the work
it cannot see, and its own task list after a compaction folded it away.
`chock run --no-notices` turns all of it off.

## The session log

The session log is the session. It goes to
`~/.local/state/chock/sessions/<project>/<session id>.jsonl`. A quiet start
names the session and not the path, and `chock run --verbose` prints the path
before it starts.

Which sessions are running comes from the lock, never from a timestamp. The
process holding a session log's lock is the one that owns that session, which is
the same fact `chock detach` moves from one process to another. So asking the
kernel whether the lock is held is exact and free, and it is right about the
case every rule over a modification time gets wrong: a session that was killed
leaves a log written a moment ago and no process at all.

```
chock sessions                          # every session, oldest first
chock sessions show <session>           # conversation and tool timeline
chock sessions tree <session>           # recursive subagent status and budgets
chock sessions verify [<session>]       # read the hash chain, and the seal
chock sessions seal [<session>]         # sign the head of a log's chain
chock sessions seal --require-card      # sign on a card, or write nothing
chock sessions export [<session>] --to <dir>
chock sessions fork <session id> [--at <session.end event>]
chock sessions remove <session id>
chock sessions prune --older-than 30
```

The full-screen interface accepts `/fork`, and each completed message offers a
fork control for its exact turn. The child keeps an audited copy of the chosen
transcript prefix and restores that turn's Git workspace when one was saved.
[forks.md](using/forks.md) covers lineage, historical turns, microVM snapshots,
and the cases that deliberately cold boot.

`chock sessions show` reads only the JSONL log and puts every event's byte
offset beside it, so an audit finding can name the exact record. Its default
human view previews large tool results and diffs; add `--full` to expand them,
or choose `--format compact` for one line per event. `--format json` writes one
complete JSON event per line with the real offset in its `id` field.

Use `--only` with a comma-separated set of `lifecycle`, `messages`, `tools`,
`approvals`, `policy`, `diffs`, `subagents`, `usage`, `context`, `workspace`,
`sandbox`, and `network` to narrow the view. Unknown event kinds are still
shown and make the command return the audit-gap exit status; a filter never
hides something this Chock does not understand. Torn records, undecodable
records, and broken hash chains are likewise printed at their byte offset and
return an audit gap.

`chock sessions tree <session>` follows every `session.spawn` from that root.
Each row keeps a branch separate and shows its agent kind, current or terminal
status, delegated cost budget, actual token use and priced cost. A child whose
process died can have no complete child log; the parent's durable
`agent.complete` record still makes that branch terminal. A spawned branch
with neither a live log nor a terminal parent record is instead reported as an
audit gap. `--format compact` and `--format json` write one row per session for
scripts that need to inspect or total one branch without mixing in siblings.

### What reached the model

`chock sessions show <session> --only context` is the context inspection view.
For every provider attempt it shows the effective system prompt, tool schemas,
messages, compaction summaries and transient harness notices as separate rows.
A transcript row points back to the byte offset of the event it came from.
The view also names the instruction files, skill indexes, memory index and
guidance index that contributed to the system prompt, and shows the context
limit and the threshold that would cause compaction.

The log records sizes and an intentionally rough estimate of one token per
four encoded bytes. It does not record another copy of prompt text, message
text, tool arguments or secrets: those either already have an audited source
event or remain represented only by their source name and size. `--format
json` exposes the same `context.request` records for other inspection tools.
Retries get their own record and attempt number because each one is a real
provider request even when its effective context is unchanged.

Every run writes a `session.config` event, holding what a person put on the
command line and the SHA-256 of the `chock.zon` the policy came from:

```json
{"session.config":{"config_hash":"9f2a...","sandbox_hash":"41c8...",
 "instructions":["./task.md"],"policy_rules":["net.fetch.*=allow"],
 "context_sources":["harness chock","instruction given ./task.md"],
 "dev_shell":"ci","allow_dirty":true,"context_limit_tokens":65536,
 "context_policy":{"warn_at_percent":60,"compact_at_percent":75,
 "keep_recent_entries":6,"keep_recent_kib":16,"summary_max_kib":16}}}
```

It holds what the session had, and nothing about what it did not: a field you
see is one somebody set. The hash is there because a `chock.zon` can be edited
and never committed, so git is not enough to say which rules a session ran
under. `config_hash` is the one field always written, and `null` means the
project has no `chock.zon` at all. An absent file and an empty one would
otherwise hash the same.

A flag leaves no trace in any file, so two sessions on one commit that were
given different rules write different bytes here, and the chain over them
differs. That is the point of the event.

`sandbox_hash` is over what the sandbox of that run lets a tool call reach:
every mount with its source, target and read only flag, every Landlock rule
with its access bits, the scratch areas, the limits, the network mode and the
devices. The environment is left out, because it decides what a program does
and not what it may reach, and it carries paths that move between machines.

It is written on every run, including resumes. `chock run --continue` can
be given different flags from the run before it, and a resumed session is
where someone would try to alter the sandbox: the run that resumes builds its
sandbox again from that run's files and flags. Two `session.config` events in
one log whose `sandbox_hash` differs are two different sandboxes, and the log
says so without anybody having to reconstruct either.

A session started from another harness's transcript writes one
`session.imported` event, and never the imported turns themselves:

```json
{"session.imported":{"from":"other-harness","source_path":"/home/you/.other/sessions/01H0.jsonl",
 "content_hash":"9f2a...","imported_ms":1700000000000,"messages":42}}
```

Writing another tool's history into the chain as `message` events would sign
a document asserting turns Chock never saw, so the import runs the other way:
a new session log is opened, and this one event says that on this date a
transcript was brought in from there. The turns themselves are loaded as
context for the agent, not appended to the log. `content_hash` is the SHA-256
of the bytes that were read, and it is what ties the event to exactly that
transcript: a source file swapped after the fact hashes differently, and the
chain over the event would not match a re-import of the swap.

Every run writes a `sandbox.open` event before its first turn, naming the run
and whether the sandbox's write and execute rule was on for it. It is written on
every run, whether or not that run is the one that gave the rule up, so an absent line means
an older Chock and never a session nobody recorded.
[sandbox.md](security/sandbox.md) has the row a project writes to give it up,
and `chock doctor` reports the same fact before a session starts.

The listing needs no index, because a session identifier starts with the
millisecond it was made and sorts in that order, so the directory is already the
list. The same identifier is where the start time comes from, rather than a
file's modification time, which a copy or a restore moves.

Every event holds the hash of the line before it, so `verify` finds an event
that was changed after the fact and names it. A hash chain is not a signature.
Whoever can rewrite the whole file can write a chain that agrees with it, and
what the chain finds is an edit in the middle. `seal` signs the head of the
chain into a file beside the log, which a rewrite of the whole log cannot forge.
A log with no seal is never reported as passing.

`seal` signs with a card key when a card gives one, and says which key signed
every time. A machine with no reader gets a software seal, and the line at the
end of the run says so. A person who answers the PIN prompt and does not get a
card seal gets no seal at all and a non-zero exit: they asked for the card, it
did not happen, and a weaker file written quietly is a downgrade they would not
see. Pressing Enter at the prompt is a choice and gives a software seal. Pass
`--require-card` to refuse every software seal, which is what a public release
wants.

Removing a session asks first, and `chock cache clear` does not. A cache is
rebuilt by the next build. A session log is the only record of what an agent
did, nothing else holds a copy, and no step makes it again. So a removal names
the log, the workspace and the sandbox root it would take, says that plainly,
and waits for a yes. A caller with nobody at the keyboard gets no removal unless
it passes `--yes` and takes the decision itself. A session that is running is
never removable, and neither is one whose lock could not be tested.

## Getting the work back

Work reaches your project only when the agent commits it in the workspace and
the policy in your `chock.zon` permits the apply. It lands on
`refs/chock/<session id>`, so `git log` reads it and `git merge` takes it.
Before taking it, `chock workspace review <session id>` shows the binary-aware
patch from the base commit recorded by the session to that ref. Repeat
`--path <file>` to limit the patch to exact project-relative names; the names
are literal, so Git wildcard and pathspec syntax is not evaluated.

`/review` opens the same structured diff in the session interface. Because the
interface is one Phantom widget tree, its file and hunk switches are the same in
the browser, desktop window, and terminal. Applying the switches creates
`refs/chock/selected/<session id>` as one auditable commit whose parent is the
recorded base. It does not move `HEAD` or any branch. The command-line form is:

```
chock workspace select 01K2... --path src/parser.zig
chock workspace select 01K2... --hunk src/parser.zig:2
chock workspace select 01K2... --reject-path generated.bin
chock workspace select 01K2... --reject-hunk src/parser.zig:3
chock workspace select 01K2... --patch /tmp/edited.patch
```

Selectors use the hunk numbers shown by review. With no accept selector, all
changes are accepted except explicit rejects. An edited patch is checked and
applied against the recorded base in a private index; it cannot be combined
with selectors. The session log records every accepted and rejected selector,
the result ref, its immutable commit ID, and whether the result came from an
edited patch.

Ordinary modified text can be selected by hunk. Binary files, additions,
deletions, renames, copies, symlinks, type changes, and permission changes are
file-atomic: review labels them as whole-file decisions and refuses a hunk
selector. Their bytes, names, modes, and link targets are taken from the
session commit rather than from the checked-out tree.

Creating a selection uses compare-and-swap when replacing an earlier selected
ref. A running session is refused, a changed destination is never silently
overwritten, and no checked-out file is touched. Branch integration remains the
existing policy-controlled apply or an explicit Git operation by the user.
Return to the pre-selection state with one command:

```
chock workspace undo 01K2...
```

An approved apply merges the work into the branch you have checked out, and the
prompt names that branch and that merge before you answer. A project can say
`rebase` or `squash` in the `apply` block of `chock.zon` instead, or `ask` to be
asked each time. Chock refuses the integration rather than leave your repository
in the middle of one, and the work is at the ref either way. An organisation
that wants no branch touched writes one policy row, which
[approvals.md](using/approvals.md) shows.

A session that does not end cleanly keeps its workspace, and prints where it is.
Errored, refused, budget reached, no progress, interrupted: whatever the agent
wrote is still on disk, so a run that went wrong is something you can salvage. A
clean run removes its own workspace.

```
chock workspace                     # every kept workspace, with its size
chock workspace review 01K2...      # inspect work parked at the session's ref
chock workspace review 01K2... --path src/parser.zig
chock workspace select 01K2... --hunk src/parser.zig:1
chock workspace undo 01K2...
chock workspace clear
```

A project that is not a git repository gets its work back a different way. There
is no commit and no ref, because the workspace is an overlay over your project
rather than a worktree of it. `chock workspace adopt <session id>` copies what
the session changed into `.chock-adopted/<session id>/files` inside the project.

Nothing of yours is written over, and nothing of yours is removed. The changed
files sit there for you to read with `diff -r` and take with `cp`, and every
path the session deleted is named in `.chock-adopted/<session id>/deleted` for
you to act on. A destination that already holds something is refused by name,
and a path that could not be carried is named with its reason in `skipped`.
Before copying, `chock workspace review <session id>` lists the overlay paths as
added, modified, or deleted. It accepts the same repeatable literal `--path`
filter as Git review and does not write into the project.

Selection works for overlays too. It writes only the accepted result beneath
`.chock-selected/<session id>`; it never overlays that result onto the project.
Ordinary modified text exposes hunks. Added and deleted paths, binaries,
symlinks, replacements, and permission changes remain file-atomic. An existing
selection directory is a conflict and is not merged or overwritten. The same
`chock workspace undo <session id>` command removes only that recorded result;
the original kept workspace remains available until `workspace clear`.
An overlay has no rename identity, so a rename is shown explicitly as one
deleted path and one added path; each is a separate whole-file decision.

```
chock workspace adopt 01K2...       # take the work out of one kept overlay
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
| 11 | the model backend refused the request, and said why |
| 12 | the model backend rate limited this credential, and every retry was spent |

A session that changed files and never committed them exits `2`, and says so:
only a commit is carried back. A refusal is not a crash and must not look like
one, which is why `3` is a code of its own. A script that treated it as a fault
would retry something a person already said no to.

`11` is the model backend saying no, which is not `3` and not `2`. `3` is a
person, or an approval nobody answered, refusing one act, and nothing broke.
Asking again gets the same answer, so Chock stops and never retries, changes
model, or resets the context on its own. The session log holds the provider's
own category and explanation, when it sent them.

`12` is the opposite advice, and it is the one code where asking again is right.
The session was rate limited, and it already waited: the retry policy spends
about a minute of backoff before it gives up, so `12` is the far end of that
queue and not a single refused request. Nothing broke, so it is not `2`.

A subagent that ends this way reaches its parent as the outcome `rate_limited`,
not as `refused`. A parent told `refused` reads that the child failed, and gives
up on work that the same request a few minutes later would have finished.
Spawning several subagents at once is what usually causes this, because they
share one credential's limit.

## What a session cost

What a session cost comes out of its own log, because every turn's usage is an
event in it. So the number survives a handover, a reconnect and a replay, and it
is the same number a budget in `chock.zon` is enforced against.

```
chock usage                         # every session, and the total
chock usage show <session id>       # one session, model by model
```

Free, priced and unknown are three answers and never two. A local model costs
nothing, which is a fact. A model no price table names costs a number nobody
has, and unknown is not zero: those turns are counted and reported apart, and no
figure is invented for them.

## The task list

An agent can keep a task list, and you watch it get crossed off. It is not
mandatory and most work needs none. When an agent does keep one, each step that
moves is one line on your terminal while the session runs, and the list is in
the session log rather than in a scratch file, so it replays, it survives a
compaction and a handover, and a phone that attaches sees the same list the
terminal does.

```
chock plan                          # every session that kept a list
chock plan show <session id>        # one session, step by step
```

A step the agent decided not to do reads as "abandoned" and stays on the list.
Nothing is ever removed, so a step that was given up can never be mistaken for
one that was finished, and a step the agent simply stopped mentioning is still
there at the status it last had.

## A rate limit

A rate limit is waited out and is not a way for a session to die. A 429 or a 5xx
is a transport fault: Chock honours the provider's own `Retry-After` when it
sends one, backs off exponentially with jitter when it does not, and says on
screen that it is waiting. Six attempts, with waits of about 2, 4, 8, 16 and 32
seconds, so a bad minute costs a minute. A session that runs out of them ends
saying how many were made and what the provider last said. A full context is a
different fault with a different answer, compaction, and the two are never
joined.

A stream that broke in the middle of a reply is not retried. The turn half
happened, and sending it again is a larger change than the wait was.

## Shipping the log elsewhere

`chock run --export-dir <dir>` writes the log into a second directory as it is
written, one file per session, byte for byte, so `chock sessions verify` reads
it there too. `--export-syslog <path>` sends each line to a unix datagram socket
as an RFC 5424 message. A syslog message is not a copy of the log: use
`--export-dir` for one that verifies. An org policy bundle can require a sink of
either kind, which [org.md](configure/org.md) describes.

## Whether this machine can run a session

```
chock doctor
```

`chock doctor` tries each sandbox layer for real, in a forked child, and says
which are on. It exits `0` when a first run can work here, even with a layer
missing, and `2` when it cannot. [sandbox.md](security/sandbox.md) says what
the rows mean.

On an installation an organisation manages, it also reports what that
organisation's policy bundle imposes: the audit sinks it requires, and every
ceiling it sets on spending, on how far a spawn tree may grow, and on the paths
kept out of every sandbox. These rows are facts and never faults, so a managed
machine that is well still reads ready. A machine with no bundle gains no rows
at all. They are there because a cap is otherwise invisible until it bites: a
session that stops at a number nobody wrote in `chock.zon` reads as a fault
until you know where the number came from.
