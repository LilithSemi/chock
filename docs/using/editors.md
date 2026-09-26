# Driving Chock from an editor

An editor that speaks the Agent Client Protocol can drive Chock: you type in the
editor, the work happens in Chock's sandbox, and approvals reach you where you
are already looking.

```
chock acp
```

The editor launches that itself. You point the editor at the `chock` binary and
it starts one for each project.

## What it is, and what owns what

`chock acp` speaks the protocol on standard input and output. It owns nothing:
`chock daemon` owns the sessions, exactly as it does for `chock serve`. So a
daemon has to be running, and the same sessions are visible to `chock sessions`,
to a browser, and to the editor at once.

| Option | What it says |
|---|---|
| `--daemon <address>` | Which daemon. Defaults to the local socket. |
| `--project <dir>` | The project a session that names no directory uses. Defaults to the working directory. |

## Both protocol versions

Version 1 and version 2 are both spoken. The editor says which versions it has
and Chock answers with the newest both sides know.

Version 1 is what editors speak today. Version 2 is an alpha whose own fields
moved between releases, so Chock answers it when an editor asks for it and never
chooses it over a version the editor offered.

## What the editor is told

| While a turn runs | What Chock sends |
|---|---|
| The model writes | a message chunk |
| The model reasons | a thought chunk, which an editor can hide separately |
| A tool starts | a tool call, with a kind so the editor draws the right thing |
| A tool ends | a tool call update carrying what it produced |
| The plan changes | the whole plan |
| A request is priced | a context gauge: how full the window is, and the cost |
| The turn ends | a stop reason on the reply |

A tool call reports a kind, so an editor shows a read differently from a command.
An MCP tool or a plugin tool reports `other`, because its name belongs to the
server and guessing a shape from it would draw something nobody declared.

## An approval arrives in the editor

When Chock asks about an action, the editor gets the question and your answer
goes back. The question carries the whole effect, never a command string, which
is the same rule [approvals.md](approvals.md) describes for every other way of
answering one.

Every option is answered for that one call. An editor offers "always" and Chock
does not take it as a standing permission: a standing permission is a policy
rule, and [policy.md](../configure/policy.md) is where one is written, where it
can be reviewed. An editor cannot widen what a project allows.

## What Chock does not take from an editor

* **Reading and writing files, and running terminals.** The protocol lets an
  editor offer to do these for an agent. Chock does neither: a tool call runs in
  Chock's own sandbox, which is the thing Chock is for, and handing the work to
  the editor would put it outside every layer. What that costs is real: Chock
  does not see an unsaved buffer, and works from what is on disk.
* **MCP servers.** A session request may name servers for the agent to use.
  Chock refuses one and says so. A server is named in the project's own
  `chock.zon`, where it is reviewable and the agent cannot change it. See
  [../configure/configuration.md](../configure/configuration.md).
* **Deleting a session.** The log is the session's audit trail. Removing one is
  `chock sessions remove`, which is asked about under the `session.remove`
  action, and an editor is not where that decision belongs.
* **Logging in.** Chock's provider credentials come from `chock login`, which
  runs where a person can type one. No authentication method is offered on this
  wire.

## Cancelling

Cancelling a turn in the editor interrupts the session, so it writes its own end
to the log and the reply says `cancelled`. It is an interrupt and not a kill: a
killed session would leave a log that stops mid turn with nothing saying why.

## Taking a session up again

An editor can ask for a session that already exists, and Chock replays what the
log holds as updates before answering, so the editor ends up with the
conversation it would have had. The same session can be picked up later, by the
editor or by anything else, because the daemon still has it.

Closing a session in the editor forgets it there. It does not end it, and the log
stays.
