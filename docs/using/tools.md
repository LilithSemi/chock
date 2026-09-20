# The tools

The agent has 21 tools, and every one that touches the machine goes through the
sandbox: `read_file`, `list_directory`, `glob`, `grep`, `write_file`,
`edit_file`, `run_command`, `read_memory` and `write_memory`. Only
`run_command` takes a command. The rest name a path, a pattern, or the text to
write, because a person can review a change and cannot review a shell line.
[sandbox.md](../security/sandbox.md) says what the boundary is made of.

`read_image` reads a picture out of the workspace, a screenshot, a diagram, a
rendered chart, and gives it to the model as an image. It is the one tool that
is not always offered. A model that cannot read a picture never hears the name,
so it cannot spend a turn calling it: the wire format must have a shape for an
image, and the provider instance must say it takes one, which is the
`.capabilities = .{ .images = true }` block of that instance in your
configuration. The kind of file is read from the content and never from the
name, so a text file called `plot.png` is refused. At most 3145728 bytes.

`read_guidance` reads a document compiled into Chock, so it reaches nothing on
the machine at all. `ask_user` puts one question to the person who started the
session, and it grants nothing: a yes there permits no act. `set_title` names
the session, so `chock sessions` reads as more than a list of identifiers.

The last eight are described here or on a page of their own:

| Tool | What it asks for | Page |
|---|---|---|
| `provide_tool` | a program the session has not got | below |
| `nix_eval` | what one Nix expression says | [nix.md](nix.md) |
| `nix_build` | one attribute of a flake, built | [nix.md](nix.md) |
| `spawn_agent` | a subagent | [subagents.md](subagents.md) |
| `restrict_self` | a promise the agent cannot take back | [policy.md](../configure/policy.md) |
| `fetch_url` | one page over http or https | [actions.md](../configure/actions.md) |
| `request_action` | your work carried back into your repository | [approvals.md](approvals.md) |
| `update_plan` | a task list you can watch | [running.md](../running.md) |

## Every call is gated

Every ordinary tool call carries an action name and is put to the same arbiter
every other approval goes through. The shipped defaults answer `allow` for
almost all of those names, so a project with no `chock.zon` of its own gains no
prompt, and a project rule of `ask` on one of them reaches a person mid
session. [actions.md](../configure/actions.md) has every name and what ships
with it.

`request_action` is the one act an agent can ask for by name, and it takes
`workspace.apply` and nothing else. An agent that believes it is finished calls
it, and your policy, or you, answer. It never moves a branch of yours: the work
lands on a ref of the session's own, which you read with `git log` and take
with `git merge`. An agent that has made no commit is told so and nobody is
asked, because only a commit is carried back. [status.md](../status.md) lists
what an agent still cannot ask for.

## A program the agent has not got

An agent in a sandbox that wants a program it has not got runs `apt install`
or `npm install -g`. Neither can work here. Chock is built on Nix, so the agent
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

### It is off until you turn it on

Realising a package runs `nix build` on your machine, outside the sandbox, so
it is checked against the `nix.build` policy key. The answer decides whether
the tool exists at all, so it is read before the tool list the model sees is
built, which is before the session starts. A project with no `chock.zon`
answers `ask` for every key, and an `ask` at that moment reaches nobody, so the
tool is not offered. Turn it on with a rule:

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

### What a name may be

The agent names a package and never anything else. A name holds letters,
digits, `-`, `_`, `+` and `.` and nothing more, so it cannot be a path, a URL,
or a flake reference, and where names are looked up is your own Nix flake
registry.

A program provisioned this way lasts for that session only. What a project
needs every time belongs in `flake.nix`. See
[toolchains.md](../operate/toolchains.md).

### What it costs

A request holds the turn and has no deadline. `nix build` on a cache miss is
minutes, and the turn waits for it, because the answer has to reach the mount
set the very next tool call is built from and not the model. A line is printed
before the wait so the terminal is not silent, and Ctrl-C reaches the `nix`
child the same way it reaches a subagent. A build that never ends holds the
session, which [status.md](../status.md) lists as an open item.
