# Approvals

An action a rule answers `ask` is put to a person before it happens. Eight
actions go through the broker: `git.commit`, `git.push`, `git.branch.delete`,
`net.fetch`, `nix.build`, `file.write`, `workspace.apply` and `model.select`.
Which of them are asked about, and which are answered before the session
starts, is the policy table in `chock.zon`. See [policy.md](policy.md).

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

Allow this? [y/N]
```

Only `y` or `yes` is a yes. Anything else, a bare Enter included, is a no, and
a no leaves your repository exactly as it was. The work is still in the
session's workspace either way, and the line printed after a refusal says
where.

Ctrl-C at the prompt ends the run with the question unanswered, which is a
refusal, and keeps the workspace.

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
