# A program the agent has not got

An agent in a sandbox that wants a program it has not got runs `apt install` or
`npm install -g`. Neither can work here, and the agent spends turns finding
that out. Chock is built on Nix, so it answers the question instead: the agent
names a package, Chock realises it, and the program is on the `PATH` of every
tool call after that one.

```
$ run_command {"argv":["rg","token","notes.txt"]}
! rg was not found on the host PATH ... To get it, call provide_tool with the
  package name, which is often not the program name.
$ provide_tool {"program":"ripgrep"}
  ripgrep is now in this session's toolchain, from nixpkgs#ripgrep.
$ run_command {"argv":["rg","token","notes.txt"]}
  hello token here
```

## It is off until you turn it on

Realising a package runs `nix build` on your machine, outside the sandbox, so
it is measured against the same policy key the broker already has for that,
`nix.build`. **The answer decides whether the tool exists at all**, so it has
to be read before the tool list the model sees is built, which is before the
session starts. A project with no `chock.zon` answers `ask` for every key, and
an `ask` at that moment reaches nobody, so the tool is not offered. Turn it on
with a rule:

```zon
.{
    .policy = .{
        .rules = .{
            .{ .action = "nix.build", .decision = .allow },
        },
    },
}
```

This is not asked about later. The answer is read once, at the start, and a
session that started without the tool does not gain it.

## What a name may be

The agent names a package and never anything else. A name holds letters,
digits, `-`, `_`, `+` and `.` and nothing more, so it cannot be a path, a URL,
or a flake reference, and where names are looked up is your own Nix flake
registry.

A program provisioned this way lasts for that session only. What a project
needs every time belongs in `flake.nix`. See [toolchains.md](toolchains.md).

## What it costs

A request holds the turn and has no deadline. `nix build` on a cache miss is
minutes, and the turn waits for it, because the answer has to reach the mount
set the very next tool call is built from and not the model. A line is printed
before the wait so the terminal is not silent, and Ctrl-C reaches the `nix`
child the same way it reaches a subagent. A build that never ends holds the
session. See [status.md](status.md).

# Asking Nix what something is

`provide_tool` above puts a program in the session. `nix_eval` answers a
different question: what does an expression say? The agent sends one Nix
expression and reads the value back.

```
$ nix_eval {"expression":"(import <nixpkgs> {}).hello.version"}
! the expression reads something a pure evaluation may not ...
$ nix_eval {"expression":"builtins.attrNames { a = 1; b = 2; }"}
  [ "a" "b" ]
```

## Nothing is built

The expression is evaluated inside Chock, by the Nix evaluator it is built
with, so no `nix` process starts and no store is opened. A derivation answers
what it is and where its derivation file would be, because that path is
computed from the derivation itself and is not looked up anywhere.

A build is a different act, and this tool does none. An expression that needs
the result of a build, such as an import of a derivation, is refused, and the
refusal names the derivation it wanted, so the agent can ask about the
derivation instead of sending the same expression again.

## What it can read

The evaluation is pure. The environment is empty, `NIX_PATH` and channels
answer nothing, and a path outside the workspace is refused. The workspace is
the throwaway copy of the project the agent already works in, so an expression
reads the same tree every other tool call reads.

## What bounds it

An evaluation runs in Chock's own process and not in the sandbox, so it is
bounded where it runs. A recursion deeper than the call depth stops with an
error, the collector holds the memory an evaluation keeps, and the rendered
answer stops at 16384 bytes. **Nothing bounds how long an evaluation runs**,
so an expression that loops runs until the session is stopped with Ctrl-C.

## The store caps

A `nix` block in `chock.zon` bounds what an evaluation may put in a store.

```zon
.{
    .nix = .{
        .max_object_bytes = "16MiB",
        .max_session_bytes = "256MiB",
    },
}
```

`max_object_bytes` bounds one object. The operator's own `config.zon` names
the same block and the project wins over it, and an organisation's policy
bundle is the last word over both. `max_session_bytes` is read and folded the
same way, and it bounds what every build of one session puts in your store
between them.

# Building one attribute

`nix_eval` says what a derivation is. `nix_build` makes it. The agent names an
attribute path, a person or your policy answers, and the host builds it.

```
$ nix_build {"attribute":["packages","x86_64-linux","default"]}
? nix.build.packages.x86_64-linux.default
  /nix/store/...-myproject was built. It produced /nix/store/...-myproject.
$ run_command {"argv":["myproject","--version"]}
  0.1.0
```

The attribute path is a list with one name per entry, never one dotted string.
A Nix attribute name may itself hold a dot, so one string would leave the tool
guessing where a level ends. `flake` is optional: left out, the build is of the
workspace the agent is already working in.

**A `flake` that is not your project is refused.** The agent may write any
reference, and fetching one means fetching its whole input graph. What that
graph reaches is written in a lock file inside the flake, which nobody can read
until the flake has already been fetched, so there is no moment at which your
rules could answer for those hosts first. The agent is told so in one sentence
and builds an attribute of your project instead.

## Two rules, because a build asks two questions

What is being built is asked under `nix.build` followed by the attribute path.
A build of your own project asks that and nothing else:

```zon
.{
    .policy = .{
        .rules = .{
            .{ .action = "nix.build.packages.*", .decision = .allow },
        },
    },
}
```

A call that names a `flake` asks a second question, for the reference itself,
and **both have to be allowed before anything is built**:

```zon
.{ .action = "nix.build.flake.github.NixOS.*", .decision = .allow },
```

A reference that is not your project is refused whatever those rules say, so
the second rule narrows a subdirectory of your own tree and never widens to a
foreign flake. One name holding both questions would not be a name: an
attribute path and a flake reference are both dotted paths, and joined into one
string a reference of four parts with an attribute of two writes exactly what a
reference of three with an attribute of three writes.

**The derivation hash is deliberately in neither name.** It changes on every
edit of the Nix, so a rule keyed on one would have to be rewritten daily, and
within a week everybody would write `nix.build.*` instead. The rows answer the
questions a person keeps: may this agent build this attribute, and from where.
A revision or a `#fragment` on the reference is dropped before the name is
built, because what a row grants is the repository and never the content.

## What stops a build of anything else

The attribute is evaluated inside Chock first, and that evaluation is what
registers the derivation. A build of a store path this session did not itself
produce is refused, by name, before `nix` is run at all. That check matters
because a hand written derivation can name any builder, so building a path
nobody evaluated here would be running a program of the model's choosing on
your machine with a content hash in front of it.

**What that evaluation authorised is what your machine builds.** The
derivation it computed is written into your own store first, through your Nix
daemon, and the store is asked where it put it: an answer that is not the path
Chock computed is refused there and then. Chock then hands `nix` that
derivation path and never the attribute, so the attribute is read once. Your
Nix and Chock's evaluator cannot read one expression differently between the
two moments, and an unpinned reference cannot move between them.

It says what goes into the build, and never what comes out. The builder runs
under your Nix, and a substituter may answer for an output instead of building
it.

## What a build may fetch while it runs

A fixed output derivation builds with the network open to it, because Nix
checks its output hash afterwards. That check is worth something for integrity
and nothing for egress: a URL that carries a secret in its query string, with
the hash of an innocuous file, passes the check, and the request has already
gone out.

So Chock reads the whole derivation closure first, finds every fixed output
derivation in it, and asks about each host under the same `net.connect` rules
every other connection uses:

```zon
.{ .action = "net.connect.org.nixos.cache.*", .decision = .allow },
```

The labels are reversed there for the reason [policy.md](policy.md) gives,
and there is no second namespace for a fetch: one rule says whether your
agent may reach a host, whether a tool call, an MCP server or a build is what
reaches it.

This is the rule and not the router. A build runs on your machine, outside the
sandbox, so `.policy.net.router` says nothing about it: the rules are what
answer.

A host nobody allowed refuses the build before `nix` is told to build anything,
and the refusal names the host and the derivation, so the agent can ask you for
that host rather than try the same attribute again. A URL whose scheme is not
`http`, `https` or `ftp`, and one with no host in it, are both refusals too:
Chock will not guess a port, and a fetch nobody can name is a fetch nobody can
rule on. An `ftp://` URL is named at port 21, so a rule for it looks like any
other: `net.connect.org.gmplib.ftp.21`.

A `mirror://` URL names a site and not a host, and nixpkgs writes plenty of
them. The derivation also names its own mirrors file, a store path that holds
the mirrors of every site, so Chock reads that file and turns the site into the
hosts it really names. That file is itself a derivation output, so it is often
not in your store yet. Chock realises it first, with local and remote builds
both turned off, so Nix either takes it from a substituter or refuses: no
builder runs for it, and a derivation that named a path of its own cannot be
built before a rule has answered. A mirrors file no substituter has is a
refusal that says so. One site is one question: the mirrors are taken in the
file's own order, one your rules already allow is taken with nothing asked, and
otherwise you are asked about the first of them. A site the file does not name,
and a derivation with no mirrors file, stay refusals.

The answer is then pinned into the environment `nix` runs with, as
`NIX_MIRRORS_<site>`, so the builder uses the mirror you allowed instead of
walking its own list. `NIX_HASHED_MIRRORS` is pinned beside it, because a
nixpkgs fetcher tries a hashed mirror for every fetch and would otherwise reach
a host that appears in no URL of the derivation. Only a rule can turn that one
on, and it is off for every other build.

A fixed output derivation that says nowhere it fetches from is a different
question, `nix.fetch.opaque`. Some fetchers read their URLs out of a lock file
at build time, `zig.fetchDeps`, npm deps and `fetchCargoVendor` among them, and
those hold no URL anywhere in the derivation. There is no host, so there is
nothing `net.connect` can name.

**Chock ships that one as `allow`**, because that is how every vendored
dependency fetch works: refusing them refuses nearly every Rust, Node and Zig
package. The question is one per build and never one per derivation, and the
derivation names go in the words you read, never in the action, so one answer
covers a session.

What you give up is stated plainly: the output hash proves the bytes are the
ones the derivation expected, and proves nothing about where the request went.
If you want the question back, write it in your own `chock.zon`:

```zon
.{ .action = "nix.fetch.opaque", .decision = .ask },
```

`.deny` refuses such a build outright. Every derivation that does name a URL is
unaffected either way and still goes to `net.connect` per host.

**The rule is all of it, and there is no backstop under it.** Nix has no flag
that keeps a fixed output builder off the network. `--offline` turns your
substituters off and a fixed output derivation still fetches with it set, so
Chock does not pass it and your binary cache keeps working. A host Chock's
reader did not find is a host nobody was asked about.

A build needs your Nix daemon, because that is what takes the derivation in. A
machine with no daemon builds nothing here and says so.

## Where your flake inputs come from

Chock's evaluator has no fetcher. It cannot open a connection, whatever an
expression asks for, so a flake input reaches it one way: it is in your store
before the session starts.

`chock run` reads your project's `flake.lock` at startup, names every host the
inputs would be fetched from, and puts each one to the same `net.connect` rules
above. One question per host, whatever number of inputs share it. A `github`
input with no host of its own is fetched from `api.github.com`, which redirects
to `codeload.github.com`, so both are named. A lock file sits in your project
directory beside `chock.zon`, and Chock reads a file there as something an
attacker may have written, which is why the hosts in it are asked about at all.
Only `allow` fetches at startup: a session is starting up, so there is nobody
to prompt, and `ask` is off there the same way it is for a language server.

Everything it fetched goes in your store, and the evaluation takes each input
from there, by the hash the lock pins. A node Chock cannot turn into a host is
a refusal rather than a guess: an `indirect` input names a registry entry and
not a host, and an `ssh://` URL is not a scheme that can be named as a host and
a port.

**A startup `ask` is not a permanent no.** A build is a turn the agent took, so
there is somebody at the prompt. When the evaluation for a build finds an input
missing, Chock puts that input's hosts to you under the same `net.connect`
rules, fetches what you allow, and evaluates once more. One retry, never a
loop: a second miss is the answer. That is why a project that has written no
`net.connect` rule can still build, and why one that has written its rules pays
nothing at build time, because its inputs arrived at startup and the build never
asks.

**A session whose inputs did not arrive still starts.** A project with no flake
at all is the ordinary case, and nothing else a session start does refuses the
session because an optional thing was missing. A build that then wants an input
you said no to says which input and which host, and tells the agent to work with
what is there rather than to ask you again for the host you just refused.

Import from derivation stays refused, here as in `nix_eval`. A build the agent
asked for is not the same act as an evaluation that quietly needs one.
`nix_eval` itself still writes nothing at all: it answers through a store that
takes no object.

## Where it runs, and what it costs

The build runs on your machine, outside the sandbox, because the sandbox has no
daemon, no network and no writable cache directory. What it produced is mounted
by every tool call after that one and is on their `PATH`, which is the same road
a provisioned program takes. A background task or a subagent that was already
running does not get it, and nothing survives the session.

A program out of a build still asks under `exec.nix.store.*` when the agent runs
it, and not under `exec.devshell.*`. The dev shell is the toolchain your project
declared; a build is something the agent asked for, and the two are not the same
class. See [policy.md](policy.md).

The turn waits for the build, with no deadline, exactly as `provide_tool` does.
