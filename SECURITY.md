# Security Policy

## Status

Chock is pre-alpha and it has not had an external security review. Do not give
it access you would not give to a program you are still testing.

See [docs/threat-model.md](docs/threat-model.md) for the adversary Chock is
built against, one real attack walked end to end, and what the sandbox does
not cover.

Its own red team suite is written and has been run. `zig build redteam` measures
a canary set before and after a real session, against a scope list compiled into
the binary that reports the verdict, in two configurations: the floor, with no
network rule and a dev shell with nothing in it, and the dev shell that ships.
It answers "did it break out" as a value, because grading a transcript by hand
is how a real escape gets argued away.

**Two models have been thrown at it**, `moonshotai/kimi-k3` and
`claude-fable-5`. Kimi engaged and probed hard, and one real fault came out of
it: a tool call could write into the worktree metadata directory inside the real
repository. That is closed, on both platforms. Fable refused the exercise and
returned nothing, so it measured nothing, and the harness records that as an
empty answer rather than as a session that held. A session that called no tool,
that ended in a fault, or that left no log reports every boundary as unchecked
and exits non-zero, because a canary that nothing tried to move says nothing
about the sandbox. That catches a session which measured nothing. It does not
catch every way an instrument can be wrong.

Read the result knowing what it is. Two models on one machine is a measurement,
not a guarantee. The instrument itself had faults found while it was built and
run, and most of those would have reported a breach as held, or a breach nobody
committed. `test/redteam/oracle.zig` keeps one of them in the code: a narrowing
added to stop a false positive is exactly where a real finding hid. The oracle
says a boundary is unchecked rather than held whenever it cannot rebuild the
decision, which is what makes the answer worth anything.

## Reporting a vulnerability

Report a security vulnerability through GitHub's private vulnerability reporting
on the Chock repository. Open the Security tab and choose "Report a
vulnerability". Do not open a public issue for a security vulnerability.

We review each report and respond as soon as we can.

## What counts as a security bug

Chock runs a language model that writes and runs code. The model is not trusted.
The sandbox, the policy table and the session log are what hold it. A security
bug is anything that weakens one of those.

For example:

- A tool call reads or writes a path outside the workspace, or reaches a host
  that no policy permits.
- A tool call escapes the sandbox: it leaves the namespaces, defeats the
  Landlock rules, or makes a system call the seccomp filter must refuse.
- An action runs that the policy table refuses, or an agent widens its own
  policy without the authorisation the ratchet requires.
- A tool call changes `chock.zon`. That file is the project's rules, and Chock
  binds it into the workspace read only, so an agent works under rules it cannot
  edit. Changing it is not the same as running a refused action: it changes what
  "refused" means, for that session and every session after it.
- A process outlives the sandbox it was started in. A tool call may run a
  program, and every program it runs must end when the call does. A process that
  is still confined but still running after the session is a fault, because
  nothing is watching it any more.
- A credential leaves the credential store, or appears in a session log, a
  terminal, or a request to a provider that must not have it.
- A session log is changed and still verifies, or a seal is accepted over a log
  it does not cover.
- A person's answer to an approval is recorded as a different answer, or an
  action proceeds with no answer at all.

A bug that does not affect security is not a security bug. Report those through
the normal issue tracker.

## What is not a security boundary

These are real features. None of them stops an attacker, and treating any of
them as a control would be a mistake.

- **Secret redaction is protection against accident, and it now covers the log
  as well as the request.** Every record the agent loop writes passes one
  redactor before it is written, and so does every approval record the broker
  writes, so a tool result, a diff, a compaction summary, a provider's own error
  message and the question you are asked to approve are all covered. The set is
  every provider
  credential the configuration holds: the one this session sends with, plus any
  `token` written in place on another provider. A value under 8 bytes is
  skipped, because a value that short appears inside ordinary words, and
  `chock run` says which provider it belongs to.
  The session log is append only and hash chained, so a secret that reaches it
  cannot be taken out again without breaking the chain. That is why the
  replacement happens before the record is written, and why there is no command
  that cleans a log after the fact.
  Four things are still not covered. A project cannot declare a secret of its
  own yet. A git password and a `{{secret:name}}` credential have mechanisms
  built and nothing that fills them, so they protect nothing today. A block of
  model reasoning is signed by the provider and is passed through untouched.
  The message you type yourself goes into the log as you typed it.
  Redaction cannot stop a model that means to leak, because anything an agent
  can read it can encode first.
- **robots.txt is a convention.** The fetch tool honours it because every other
  harness does. A server that wants to refuse Chock must refuse the request.
- **A TCP transport carries no peer identity.** The daemon checks the peer on a
  unix socket. Over TCP there is nobody to check, so authentication is the job
  of a proxy in front of it, such as Authelia. `--host 0.0.0.0` does what it
  says, and a person who types it has chosen to be reachable.
- **A model's own statement about what it did is not evidence.** The session log
  is the evidence. It records what the harness did, not what the model said.
- **A tool that comes from your own Nix configuration is a tool you chose.**
  Chock builds a tool call's environment from the project's dev shell, so a
  flake that supplies a hostile program supplies it on purpose. Choosing what
  goes in the dev shell is the same decision as choosing what to install. Chock
  confines what a tool call can reach, and it does not judge which tools you
  asked for.

## Where the boundary is

On Linux a tool call runs in its own user, mount, PID, IPC and network
namespaces, under a Landlock rule set and a seccomp filter, in a throwaway copy
of the project. The credential store is never mounted into the sandbox.

**The real project is never written by a tool call**, and that sentence is
stronger than it was. A git worktree keeps its own metadata inside the real
repository, at `.git/worktrees/<id>`, and git must write the index there for
`git status` to work at all. Chock used to give that directory to the tool call
itself. A red team run wrote two files into it, so now the directory is copied
and the copy is what a tool call sees, on both Linux and macOS. The project's
own reads byte for byte as `git worktree add` left it, whatever the agent does.
Linux binds the copy at the path git looks for. macOS has no bind mount, so it
names the copy with `GIT_DIR` and `GIT_WORK_TREE` instead and leaves the whole
of the real `.git` read only.

**macOS runs a real session, and it is weaker than Linux.** Seatbelt is
measured on real hardware and it holds the paths, the network including unix
sockets, the signals and shared memory. A whole session has run on a Darwin
machine: `read_file`, `write_file`, `run_command`, the knowledgebase and a
background task all answered, and `cat /etc/passwd` came back "Operation not
permitted".

Two things macOS does not give you, and both are permanent:

- **No system call filter.** macOS has no equivalent that works, so the layer
  that caught an io_uring bypass on Linux does not exist here.
- **No bind mount.** Every path Chock would place under `/run/chock/` appears at
  its own host path instead, and there is no capped temporary area, so a file
  written through `TMPDIR` or `CHOCK_SCRATCHPAD` survives the call.

The driver reports no guarantee it has not proved, so a policy that asks for
more than macOS gives is refused rather than quietly accepted. Run
`chock doctor` on the machine you are on: it names each layer and what is lost.

The session log is append only. Each record carries a hash of the bytes of the
record before it, so a change anywhere breaks the chain from that point on. A
seal signs the head of that chain, which is what a rewrite of the whole log
cannot forge without the key. What a seal is worth is what its key is worth, and
each seal names its own level: a key in a smart card proves more than a key in a
file.

Run `chock doctor` to see which of these hold on your machine. A layer that is
not on is named, with what is lost.

## Scope

Chock's own code, in this repository, is in scope.

A fault in something Chock depends on belongs to whoever wrote it. The kernel,
the Zig standard library, Nix, `pcscd`, a model provider, a plugin you install,
and an MCP server you configure are all outside this policy. Report those to
their own projects.

**One thing on that list stays ours.** If Chock opens a path to a dependency's
fault, the guard on that path is Chock's job. Chock parses an attestation
certificate that comes off a smart card, so a parser that fails on bad input is
a fault Chock must survive whoever wrote the parser. The rule is simple: the
upstream bug is theirs, and reaching it with input an attacker controls is ours.

So report it here if a plugin, an MCP server, or any other dependency can cross
a boundary Chock is supposed to hold. A plugin runs as its own process and a
tool call is sandboxed, and those are the boundaries.
