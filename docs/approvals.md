# Approvals

An action a rule answers `ask` is put to a person before it happens, wherever
there is a moment at which a person can be asked. The broker knows eight
actions: `git.commit`, `git.push`, `git.branch.delete`, `net.fetch`,
`nix.build`, `file.write`, `workspace.apply` and `model.select`. It answers one
more, `policy.widen`, which is a session asking to be let out of a promise it
made to itself. What each one is allowed, denied or asked is the policy table
in `chock.zon`. See [policy.md](policy.md).

**Two of these nine really put a question to a person in this release, and no
more.** `workspace.apply` is asked at the end of a session, and again during
one when the agent asks for it with `request_action`. `policy.widen` is asked
during one. `net.fetch`, `nix.build` and `model.select` are each read before
the work they govern, at a moment when nobody is waiting to answer, so `ask`
is a refusal for all three. `git.commit`, `git.push`, `git.branch.delete` and
`file.write` are rows the table can answer and nothing in a session asks them
yet. See [status.md](status.md).

**A tool call is a different question, and it is gated too.** `gateToolCall`
asks the same arbiter about every ordinary tool call now, so a project rule of
`ask` on `call.write_file`, `exec.*`, or any other action `Tool.actionInto`
names reaches a person mid session, not only `workspace.apply` and
`policy.widen`. See [policy.md](policy.md) for the actions a tool call itself
can name. A filtered tool call's own `net.connect.*` question reaches the same
person too: a host no rule names answers `ask`, and that `ask` is a live
question, not the refusal `net.fetch` still is. See
[threat-model.md](threat-model.md) for the network descriptor every foreground
tool call now holds, whether or not any host has been named.

## The one every project meets

The agent works in a throwaway copy of the project, so its commit has to be
carried back into your repository before you can read it. That carry is
`workspace.apply`, and it is asked at the end, when the session is over:

```
chock: this needs your approval before it can happen.

  action   workspace.apply
  asked by main
  summary  move 4 objects and set refs/chock/01K2...
  reason   the session made a commit, and the workspace it is in is about to
           be removed

  what it changes

  a1b2c3 add a test for the parser

Allow this once, or for the rest of the session? [y/N/a]
```

`y` or `yes`, in any case, answers yes for this apply alone. `a` or `always`
answers yes and remembers this exact action for the rest of the session, so a
later `workspace.apply` in the same session does not ask again. Anything
else, a bare Enter included, is a no, and a no leaves your repository exactly
as it was. The work is still in the session's workspace either way, and the
line printed after a refusal says where. `chock approve`, answering over a
socket instead of a keyboard, is never offered the session letter: only the
terminal that holds the session's own lock can keep that promise.

Ctrl-C at the prompt ends the run with the question unanswered, which is a
refusal, and keeps the workspace.

### Where the work lands, and how to change it

By default the work stops at `refs/chock/<session>`. **No branch of yours
moves**, and you take the work with `git merge refs/chock/...` when you want it.

A project that would rather not run that merge by hand says so in `chock.zon`:

```zon
.{
    .apply = .{ .mode = .merge },
}
```

Four modes and one question:

| mode | what an approved apply does |
| --- | --- |
| `ref` | the default. Parks the work at the ref. No branch of yours moves. |
| `merge` | parks the work, then merges it into the branch you have checked out. |
| `rebase` | parks the work, then replays it on top of the branch you have checked out. |
| `squash` | parks the work, then puts all of it on that branch as one commit. |
| `ask` | Chock asks you which of the four, at the moment of the apply. |

**The prompt says which one you are approving.** The `summary` line names the
mode and the branch, and the detail has a paragraph of its own about your
branch: which branch, where it is, where it moves to, and what happens to your
working tree. A `ref` apply says in the same place that no branch of yours
moves. The four questions do not read alike, because the same `y` no longer
means the same thing.

Every mode parks the work at the ref first, so the ref is there whatever else
happened.

**Chock never leaves your repository in the middle of a merge.** The merge, the
rebase and the squash are all built inside the session's own object store, with
no index and no working tree involved, and the only thing that ever runs in your
repository is a fast forward onto a clean tree. There is nothing to abort,
because nothing was started.

That means Chock decides **before it asks you** whether the integration is
possible at all. When it is not, the prompt says so and the work waits at the
ref instead. It refuses for these reasons, and each one is named in the prompt
and in the log:

- your working tree holds changes that are not committed, or files that are not
  tracked;
- the work and your branch change the same lines, so it would stop on a
  conflict;
- no branch is checked out;
- a merge, a rebase, a cherry pick or a revert is unfinished there;
- your branch moved between the question and your answer.

**A refusal never loses the work and never refuses the apply.** The objects and
the ref land exactly as they do in `ref` mode, which is the behaviour you
already have a `git merge` for. Chock checks the same facts again immediately
before it moves your branch, so a working tree you dirtied while reading the
question parks the work rather than integrating into it.

`ask` needs somebody at the keyboard. A subagent, a session the daemon started,
a `chock run` behind a pipe and a session with the full screen interface up all
have nobody to ask, and all of them keep the work at the ref.

`chock run` prints what happened either way, and says how to put your branch
back:

```
chock run: 21 objects and the ref refs/chock/01M17... were applied to /home/you/site.
chock run: your branch refs/heads/main moved from a1b2c3d to 9f8e7d6 (merge), and
your working tree is there now.
chock run: put it back with `git reset --hard a1b2c3d...`.
```

The session log carries the same fact as a `workspace.integrate` record: the
mode, the policy answer that permitted it, the branch, where it moved from and
to, and, when no branch moved, why. **A session is distinguishable afterwards by
what happened to your branch.**

An organisation can close this road for every project at once with one policy
rule. See [policy.md](policy.md).

### The agent can ask for the same thing

`request_action` is the one act an agent may ask for by name, and it takes
`workspace.apply` and nothing else. An agent that believes it has finished calls
it, and you get the question above, with the agent's own reason in it, without
waiting for the session to end. Everything else is identical: the same table
decides, the same diff is shown, and the work lands on the same
`refs/chock/<session>` ref. **An agent gains nothing by asking**, and in
particular **it cannot choose how the work lands**. The mode comes from
`chock.zon` and from the policy row above it, both read outside the sandbox, and
the one thing an agent fills in for an apply is its reason. There is no field of
the request a mode could arrive in, and the build fails if one is ever added.

Two answers never reach you at all. An agent that asks for any other action is
refused by name, and an agent that asks having made no commit is told how many
files it has left uncommitted, because there is nothing to put in front of you.

## How a question reaches a person

The session log is the truth of a session, and the loop holds that log's
exclusive lock from the first turn to the last. So an answer cannot be
appended by another process, and for a long time that meant no question could
be asked while a session ran at all. The way through is the seam the broker
already has: the wait for an answer happens **inside** the process that holds
the lock, and the answer is appended through the same handle the question was
written with. There is no second lock and no second open of the log.

Three things can answer, and a session may have more than one of them:

- **The terminal.** An interactive `chock run` prompts, as above.
- **A unix socket beside the log.** `chock approve <session id>` attaches to a
  running session and answers what it asks. The socket serves the user that
  started the session and refuses every other peer, by the credential the
  kernel puts on the connection.
- **The display.** Bare `chock` brings up a full screen interface, which reads
  the log and writes the answer the same way the terminal path does.

```
chock approve                 # the newest session of this project
chock approve <session id>
```

A session only asks while it is running. Attaching to one that has ended says
so and exits.

## Nobody at all is a refusal

**A session with nobody at the keyboard and nobody attached is refused instead
of asked.** A subagent and a session the daemon started are both spawned with
no terminal, and a `chock run` whose standard input is a pipe has none either.
With no client attached to its socket, such a session gets no waiting period
at all: the question is refused at once rather than held open for five
minutes. A hang would be worse than any of the available answers, because the
session lock is held while it hangs.

The rule holds throughout: **an approval nobody answers
is a refusal.**

The way to say yes without a person there is a rule in `chock.zon`:

```zon
.{
    .policy = .{
        .rules = .{
            .{ .action = "workspace.apply", .decision = .allow },
        },
    },
}
```

`.decision = .agent_review` has a reviewer agent decide instead, and
`.decision = .agent_then_human` asks the reviewer first and then asks you,
with the reviewer's verdict shown above the question.

The agent cannot reach `chock.zon`. Chock binds it into the workspace read
only, so the file that says what the agent may do is not a file the agent can
edit.
