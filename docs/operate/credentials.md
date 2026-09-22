# Credentials

```
chock login --provider aiand
chock login --provider anthropic --name work
chock login --provider openai-compat=http://127.0.0.1:5000/v1 --name local
printf '%s' "$KEY" | chock login --provider aiand --password-method stdin
```

The credential goes to `~/.local/share/chock`, which Chock alone writes, in a
file with mode `0600` on Linux and in the Keychain on macOS. It is checked
against the provider before it is stored, so a mistyped key fails at login
rather than on your first turn.

`--password-method` says where the credential comes from: `prompt` is a hidden
prompt and the default at a terminal, `stdin` is one line of standard input
and the default otherwise, and `file=<path>` reads it from a file.

There is no option that takes the credential as an argument, and no environment
variable for one. A command line is visible to every other user through `ps` and
it lands in your shell history.

## Two logins at once

`chock login` takes a lock while it writes, and it holds that lock over the
credential and the index together, so a second login that starts while the
first is writing waits for it. One login writes both files or neither. The wait
is five seconds, which is thousands of times what a store write takes.

If that runs out, the second login says `another chock login is running` and
stores nothing. Wait for the first one to finish and run it again. The message
never names the credential or the instance, because you read it off a terminal
other people can see.

The lock is the kernel's own, so a login you kill releases it at once. There is
nothing to clean up by hand.

The name of an instance you did not name is its kind, so a second `chock login
--provider aiand` is a second login for one name. At a terminal it asks before
it replaces anything, and no is the default:

```
chock login: there is already a credential named "aiand", stored as kind aiand.
Replace it? [y/N]
```

The question comes before the credential is read, so answering no costs you
nothing and you never type a secret for a login that will not happen.

A run with nobody to ask is refused instead, because silence is not a yes.
That is a pipe, a `--password-method` that reads a file, and any continuous
integration job. Those say which they meant:

```
chock login --provider aiand --replace
chock login --provider aiand --name <a name of your own>
```

`--replace` also works at a terminal, and skips the question.

The same check is made again while the index lock is held, so a login that
started while another one sat at its prompt is told the name is taken rather
than writing over what that one stored.

On macOS the lock is also held while the Keychain is written. If your Keychain
asks you to unlock it, a second login can reach the five second bound while you
answer. Answer it, then run the second login again.

## Where a lookup goes

A session that needs a credential asks for the instance by name and takes the
first of these that answers:

| | Path | Owner |
|---|---|---|
| 1. the instance's own `token` or `token_file` | the configuration directory | you, or home-manager |
| 2. `tokens.zon`, a name to a token | the configuration directory | you, always |
| 3. what `chock login` wrote | the data directory | Chock, always |

First match wins, and a lookup that finds nothing sends no credential. That last
case is not a failure. It is what a local llama.cpp server needs, and it is the
reason there is no `none` spelling and no placeholder string pretending to be a
secret.

`chock run` still refuses one shape of it, before it builds a workspace or
opens a log: an instance of kind `anthropic` or `aiand` that still talks to
that kind's own address, with nothing in any of the three sources. Those two
addresses refuse every request that carries no credential, so the session can
only end in a 401 after the setup is already done. The refusal names the
instance and the address, never any part of a value. An instance of either
kind pointed somewhere else keeps running with no credential, because Chock
knows nothing about that address.

Sources 2 and 3 stay two different files even though both hold tokens. Chock
rewrites 3 and must never rewrite 2, because a program that edits a file a
person maintains will one day reformat it, drop a comment, or lose an entry.

All three sources are checked for their mode. A token file that another
user can read is refused by name. `.token` written in place is allowed because
of that check, not in spite of it.

## The store is never in the sandbox

The credential store is a file in the data directory, and nothing mounts that
directory into a sandbox. Two per project subdirectories below it are mounted,
the knowledgebase and the toolchain cache, and binding a subdirectory does not
expose its parent. So no tool call, no shell command and no program the agent
runs can read the file your key is in.

The session's own environment is built the same way. `HOME` from your shell
never reaches a tool call, which is what keeps a key in your own environment
away from the agent. [toolchains.md](toolchains.md) says what is put in its
place.
