# Forking a session

A fork starts a new session from a completed turn of an old one. Use one when
the conversation has reached a useful point and you want to try another route
without giving up the route you already have.

Inside the terminal, desktop app, or browser, enter:

```
/fork
```

That forks the latest completed turn. A message in the transcript also has a
`fork` control once its turn has ended. Selecting the message forks at that
turn, not at whichever turn happened to finish most recently.

The command-line form works without opening the interface:

```
chock sessions fork <session id>
chock sessions fork <session id> --at <event offset>
```

The offset must name a `session.end` event. `chock sessions` prints the child
identifier, and `chock run --session <child>` continues it. A source owned by
another running process is refused; Chock never reads a live log while its
owner may still append to it.

## What the child inherits

The child's log begins with the source bytes through the chosen `session.end`,
unchanged. Chock then appends one `session.fork` event containing:

- the direct parent session;
- the chosen event offset; and
- the digest of the source log at that boundary.

That event makes the branch point auditable without making the child depend on
the parent. The parent can be removed later and the child still has its complete
inherited transcript. A fork of a fork records its immediate parent; the older
fork events remain in the copied prefix.

Usage and cost after the branch begin at zero. The inherited messages remain
model context, but work done after the branch is charged only to the child.
`chock sessions` and every session picker show `fork of <parent> at <event>` so
siblings with the same inherited title remain distinguishable.

The child is a new, idle session. Creating it does not send an empty prompt or
spend a model turn. The browser changes to the child's `/s/<id>` location, and
the first message sent there starts the divergent turn.

## Workspace restoration

After every completed turn, a Git worktree workspace gets a checkpoint of:

- its visible files, including unstaged changes;
- its index, including staged changes;
- its private Git objects, including commits made by the agent;
- its `HEAD` and base commit.

A fork copies the checkpoint at the selected event and restores it when the
child first runs. It also copies earlier checkpoints in the inherited prefix,
so a later fork of the child can branch at an older inherited turn without the
original session still existing.

Overlay workspaces are not checkpointed. A fork from one keeps the transcript
but starts with a fresh workspace, and the command says so. A missing or
unsupported checkpoint has the same explicit fallback; it is never described
as restored.

## MicroVM restoration

When the microVM driver supports snapshots and memory encryption is off, Chock
can also retain the guest's tool-side state. This includes the warm guest and
its virtual devices; host share paths are rebound to the receiving session when
the snapshot is restored.

Only a fork of the latest completed turn can inherit this snapshot, and only
when its workspace was restored at the same boundary. A historical transcript
with a latest guest would combine two different moments, so historical forks
cold boot instead.

The source and child receive independent checkpoint files. Resuming either one
does not consume the other's copy. Under `chock daemon`, an idle guest is
checkpointed after five minutes, and a quiescent checkpoint survives a daemon
restart. Once restoration succeeds, the old file is consumed; a crash cannot
roll the session back to that earlier guest state.

SEV guests cold boot because their encrypted memory cannot be snapshotted by
this path. A failed or incompatible restore is removed and retried as a cold
boot, with a warning.

## Failure and removal

Fork creation commits only after the child log and workspace checkpoint are
complete. A failure removes the partial child log, workspace, sandbox root, and
temporary checkpoint copies. It does not alter the source.

`chock sessions remove` and `prune` count and remove a quiescent VM checkpoint
along with the log, workspace, and sandbox root. Workspace and VM snapshots are
full independent copies today, so a branch can consume substantial disk space.

A seal belongs to one exact log head. The copied prefix still verifies against
the digest recorded by `session.fork`, but the new child is not covered by the
parent's seal. Seal or export the child separately when its new history needs
the same external proof.
