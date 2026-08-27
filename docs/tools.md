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
