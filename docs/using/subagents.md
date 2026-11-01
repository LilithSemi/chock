# Subagents

An agent can start another agent with `spawn_agent`. A subagent is a child
process with a session log of its own, not a thread, because `fork` carries
only the calling thread and the tool path forks.

## The limit is yours

A `subagents` block in `chock.zon` says how large a tree of agents this
project allows:

```zon
.{
    .subagents = .{
        .max_depth = 6,
        .max_width = 6,
    },
}
```

`max_depth` is the longest chain of agents, counting the agent you started as
one. `max_width` is the most subagents any one agent may start. Both default
to 6, and `max_width = 0` refuses every subagent, which is how you turn them
off. A refused `spawn_agent` call names the limit it passed, so the agent reads
the reason and does the work itself.

The agent cannot change these. `chock.zon` is bound into the workspace read
only, the same way the policy table and the budget are.

The budget is divided and never copied. A parent hands each child a slice of
what the parent has left, and the project's own cap in `chock.zon` still binds
every session, so the answer is the smaller of the two. Each agent is a process
of its own with no shared memory, and a cap has to be applied before a request
goes out, so a slice is what makes one cap cover a whole tree. A child that
spends its whole slice ends, and its parent is told that the budget ran out
rather than that the work finished.

A child also holds no more policy than its parent, whatever the file says about
that child alone, and no more than any promise an ancestor made with
`restrict_self`, which [policy.md](../configure/policy.md) describes.

## A spawn waits, or it carries on, and the agent says which

A `spawn_agent` call answers in the call itself by default: the agent has
nothing to do until the subagent answers, so its turn stops until it does.
That is "review this and tell me".

Pass `"background": true` and the call comes straight back instead. The agent
keeps working, and it is told what the subagent answered at the start of a
later turn, which is where a finished background command is delivered too.
That is "go and do that while I work", and it is what makes a tree of agents
worth more than a sequence of them.

Either way the parent writes the record. A subagent keeps a log of its
own, and its parent's log holds two events around it: one when the child was
asked for, and one saying how it ended and what it answered. So an agent that
acts on a subagent's answer always leaves a trace of having been told it.

Read the whole delegation tree with `chock sessions tree <parent>`. It follows
the child identifiers recursively and puts each branch's promised budget,
actual use and terminal outcome on its own row. A missing terminal record is
an audit gap rather than an apparently idle child; a recorded crash remains a
terminal outcome even when the crashed process could not finish its own log.

Background subagents have a durable lease beside the parent session. The
subagent runs in a supervisor process group, so `chock detach` can hand the
parent to another process without waiting for it. The next owner adopts the
lease, observes the same completion receipt, and may call `cancel_work` with
the child session identifier. Only the current lease owner can cancel it.

The child's own log stands on its own. Its first event names the parent
session, and it also names every agent kind above it, root first. A child holds
no more policy than its parent, so the answer the policy table gives depends on
all of those kinds. A person who reads one exported log can see which rules
applied to it, and does not need the parent log as well. `chock sessions export`
is in [running.md](../running.md).

## A subagent has nobody at the keyboard

A subagent is spawned with no terminal, so a question it would ask reaches
nobody by default and is refused at once. `chock approve` can attach to it, and
a rule in `chock.zon` is the way to answer without a person there, which
[approvals.md](approvals.md) shows.

A background subagent does not keep a handover waiting. Its durable supervisor
and output receipt outlive the session process, and the daemon adopts its lease.

The process-tree, policy-ratchet, budget, concurrency, reviewer, resume, and
durable-lease paths are exercised with real child processes in the test suite.
Those tests use deterministic provider stand-ins rather than spending hosted
model calls: they prove Chock's tree mechanics, not the quality or behavior of
a particular model when several real agents collaborate. Provider-backed tree
behavior belongs in versioned evaluations, whose model and harness findings
are kept separate as [evals.md](evals.md) describes.
