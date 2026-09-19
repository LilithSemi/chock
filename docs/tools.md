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
same way, and nothing enforces it yet.
