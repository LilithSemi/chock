# The daemon

```
chock daemon
```

The daemon owns sessions, and it is the only thing a frontend ever talks to.

**It runs a child per session and never runs the agent loop itself.** That one
decision is what makes it cheap. The daemon does not reimplement the loop, the
sandbox, or the tool runner, so if `chock run` works, the daemon works. The
tool path forks, and `fork` carries only the calling thread, so it needs a
single threaded process: each child **is** that process, the same `chock run` a
person types by hand, which leaves this one free to use threads for its own
sockets. And a session that crashes takes down one child, not the daemon.

## What it listens on

The default listener set is **exactly one address, the unix socket** at
`<state dir>/daemon.sock`. `--socket <path>` names a different one.

**There is no TCP listener unless `--host <addr>` names one.** The unix socket
is the default because the kernel puts a credential on the connection: the
daemon reads the peer's uid and refuses every uid that is not its own. A peer
the kernel will not name is refused too, because an absent answer is never a
permissive answer.

**A TCP connection carries no peer identity**, so there is nothing on that
transport to check, and Chock does no authentication of its own. Anything that
can route to a `--host` address can drive the daemon. Put a reverse proxy such
as Authelia in front of it. `--host 0.0.0.0` is accepted unguarded, because a
person who types it has chosen to be reachable.

**`--port` with no `--host` is refused by name**, rather than obeyed, because
obeying it would open a listener nobody asked for. `--port 0` asks the system
for a port and prints it.

## The interface is the log

The session log is the truth of a session, and replay from an offset already
works, so the daemon serves the log and invents no message format. If a client
needs something the events cannot say, the event types need a field.

The test of every verb: **would this still work if the client were on another
machine?** Nothing here hands out a path, and nothing here takes one except
the project directory a person already typed.

```
hello chock-control <protocol number>
    -> ok chock-control <protocol number>

start  <project directory>\t<message>
    -> ok <session id>\t<log path>

adopt  <project directory>\t<session id>
    -> ok <session id>\t<log path>

read   <session id> <last event id>
    -> one line per event, then the connection closes.

list   <project directory>
    -> one line per session, <started at>\t<the row as JSON>.

watch  <project directory>\t<session id>\t<last event id>
    -> the header line, then one line per event, and it keeps sending as the
       session appends. Ends when the session does.

answer <project directory>\t<session id>\t<request id>\t<yes|no>
    -> ok answered
```

`<last event id>` means "I already have this one", so a client that reconnects
with the last identifier it saw resumes with no gap and no repeat.

## Every connection opens with a number

The daemon can be on another machine, so the two ends are installed at two
times and one of them is older. The client greets with the control protocol
number it was built against, the daemon answers with its own, and **both check
the numbers and not the shape of the reply**. They have to be equal. Nothing
below the greeting is read or written until they are, so a daemon this client
cannot speak to is never asked to do anything.

The number is the protocol's own and is not the number `chock --version`
prints. The wire moves far less often than the program, and a wire number tied
to the release would make every release read as a break, which teaches a person
to ignore the refusal. It moves when a client built against the old number would
misread the new one, and at no other time. A field added to a session row is not
such a change: every field has a default and an unknown one is ignored, so both
directions already hold.

A refusal names both numbers, from either side, so a person knows which end to
update. A client built before the greeting existed opens with a verb, which is
not a greeting, and is told so.

The daemon cannot write into a session's log, so `answer` lands only by that
session's own socket taking it. **A connect that failed is reported as a
failure**, never as `ok answered`, because an approval nobody could deliver
must not read as one that was given.

## A browser in front of it

```
chock serve
```

`chock serve` puts a browser in front of a daemon. It **owns nothing**: it is a
client of `chock daemon`, and every fact it shows came out of the daemon's own
API. It never reads a session log, never takes a lock, and never resolves a
session directory.

`--daemon <address>` says where the daemon is, as `unix:/path` or `host:port`.
The default is the socket in the state directory, or `$CHOCK_DAEMON` when that
is set. Nothing in `serve` branches on whether that address is local, because
in a hosted world the daemon is somewhere else.

Its own browser facing listener is a unix socket by default, `serve.sock` in the
state directory. `--socket <path>` names another one. `serve` checks the peer's
user id on that socket and refuses anybody else with `403 Forbidden`.

`--host <addr>` swaps the socket for a TCP listener. **TCP carries no peer
identity**, so `serve` checks nobody there and authentication is the job of a
proxy in front of it. A browser cannot speak a unix socket, but nginx, Caddy and
Authelia all proxy to one, which is why the socket is the default.

**A proxy that runs under its own account cannot open that socket**, because
the check is the peer's user id. Run the proxy as the user that started `chock
serve`, or give the proxy a `--host 127.0.0.1` address and accept what that
address means. A person who wants a browser pointed straight at Chock types the
same `--host 127.0.0.1`. `--port` with no `--host` is refused by name.

## Handing a session over

```
chock detach                # hand over the newest session of this project
chock detach <session id>
```

`--daemon <address>` names the daemon, as `unix:/path` or `host:port`,
otherwise `$CHOCK_DAEMON`, otherwise the socket in the state directory.
`--port <n>` survives as shorthand for `127.0.0.1:<n>`, which only a
`chock daemon --host` listens on. Naming both `--daemon` and `--port` is
refused.

**Ownership is the session log's exclusive lock**, so a handover is that lock
changing hands and there is no transfer protocol. One process lets go, the
daemon's child takes the lock, and it folds the log to recover the state. That
fold is not new machinery: compaction, `chock usage`, `chock plan` and
`chock sessions` all rebuild state the same way, and the agent loop folds the log
at its own start before it appends anything. The daemon runs
`chock run --adopt`, which carries on from the conversation the log holds and
adds no message of its own.

**A session that is still running is asked, and it answers at its next turn
boundary.** The ask goes over a second unix socket beside the log, under the same
rule the approval socket keeps: the socket carries a question and an answer and
never a log write. It takes two round trips, and the second one is what makes a
client that gave up safe. The session says it is ready, waits for the client to
confirm, and only then stops. A client that pressed Ctrl-C in between never sends
that confirm, so the session carries on and nothing about it changes.

A turn is as long as a model call plus its tool calls, so `chock detach` waits.
`--wait <seconds>` bounds that, and defaults to 300. A session that does not
answer in time keeps running, unchanged.

**The workspace moves with the session.** Every run writes a `workspace.open`
event naming the directory it works in and the commit that checkout started at,
which are the two facts a second process cannot work out for itself. A run that
hands over leaves the directory on disk, and the next owner adopts the same
checkout instead of building a new one from committed state. Measured with real
git: a linked worktree records nothing about the process that made it, so taking
one costs no git command at all. The scratchpad moves the same way, because it is
keyed on the session identifier.

**Two things still do not move, and a handover refuses while either exists.** A
background command and a background subagent both live in the process that
started them, and that process is what writes their record into the log. So a
session running one says no, names the counts, and carries on. Wait for them and
ask again.

A session that ended some other abnormal way also keeps its workspace, and that
one is still refused: `chock detach` names the kept workspace and points at
`chock workspace` rather than leaving that work behind.

**A workspace is taken over only when the log proves nobody is in it.** The
event that names it has to be older than the ending that handed it over, which
a workspace the current owner opened never is. Without that test a
`chock run --continue` against a session the daemon had just adopted would have
taken the checkout that session was working in, and the first owner's own
teardown would then have removed it. `--allow-dirty` is refused on a workspace
that moved, for the same reason: it copies your uncommitted files over the
files in the workspace, and on an adopted one those are the agent's own edits.

**With no daemon listening, this refuses and says to start one.** It never waits
and never reports a handover that did not happen. For a running session the
daemon is proved to be there **before** the session is asked, because the ask
cannot be taken back: a session that agreed has ended, and finding out
afterwards would leave it stopped for nothing. A daemon that goes away in the
moment between says so by name, and names `chock run --continue` as the way to
take the session back.

A detached session asks its questions the same way every other session does,
over the unix socket beside its log. `chock approve <session id>` attaches to
that socket directly, and the daemon's `answer` verb reaches the same socket for
a client that only speaks to the daemon. **`chock approve` has to run on the
machine that holds the session**, because that socket is a unix socket and no
remote transport for it is built. A client somewhere else uses the daemon. A session that hands over exits `8`, because
the work is not over and it is not that process's any more.
