# The tools

The agent has 25 tools, and every one that touches the machine goes through the
sandbox: `read_file`, `list_directory`, `glob`, `grep`, `write_file`,
`edit_file`, `run_command`, `read_memory` and `write_memory`. Only
`run_command` takes a command. The rest name a path, a pattern, or the text to
write, because a person can review a change and cannot review a shell line.
[sandbox.md](../security/sandbox.md) says what the boundary is made of.

`read_image` reads a picture out of the workspace, a screenshot, a diagram, a
rendered chart, and gives it to the model as an image. It is the one tool that
is not always offered, because a model that cannot read a picture never hears
the name, so it cannot spend a turn calling it: the wire format must have a
shape for an image, and the provider instance must say it takes one, which is
the `.capabilities = .{ .images = true }` block of that instance in your
configuration. The kind of file is read from the content and never from the
name, so a text file called `plot.png` is refused. At most 3145728 bytes.

A foreground `run_command` is stopped when it reaches the session's time limit.
A call can ask for less with `timeout_ms`, and never for more: a number past
the session's own limit changes nothing. Anything longer than a couple of
minutes belongs in the background instead.

`cancel_work` stops a background command or subagent by the identifier returned
when it started. It checks the durable lease before signaling, so a process that
already handed the session over cannot cancel work its successor owns. The
supervisor has a process group of its own, and cancellation reaches descendants
as well as the first program. The terminal result arrives through the same
ordered completion path as an ordinary finish.

`read_guidance` reads either a document compiled into Chock or one declared by
the project's `guidance` block. Project guidance is read once at session start,
bounded to 64 KiB per document, and is labeled as repository-authored in the
prompt. `ask_user` puts one question to the person who started the session, and
it grants nothing: a yes there permits no act. `set_title` names the session,
so `chock sessions` reads as more than a list of identifiers.

`edit_file` only replaces text a successful `read_file` result actually showed
for that path. The guard is rebuilt from the durable session log, so compaction,
resume and handover do not forget it. Hook notes attached to a read are outside
the byte range in the read header and do not count as file text. The existing
uniqueness and optional `file_hash` checks still apply after this guard.

`read_skill` reads one skill: somebody's written procedure for a task, found on
disk at session start. It is offered only to a session that found at least one,
and the answer says who wrote it, because a skill from a repository or a package
is a stranger's writing. [skills.md](skills.md) is the whole of it.

The last eleven are described here or on a page of their own:

| Tool | What it asks for | Page |
|---|---|---|
| `provide_tool` | a program the session has not got | below |
| `serve_port` | a port of its own, reachable from your machine | below |
| `nix_eval` | what one Nix expression says | [nix.md](nix.md) |
| `nix_build` | one attribute of a flake, built | [nix.md](nix.md) |
| `spawn_agent` | a subagent | [subagents.md](subagents.md) |
| `cancel_work` | a background command or subagent to stop | above |
| `restrict_self` | a promise the agent cannot take back | [policy.md](../configure/policy.md) |
| `fetch_url` | one page over http or https | [actions.md](../configure/actions.md) |
| `web_search` | one query against a search engine | [search.md](../configure/search.md) |
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
or `npm install -g`. Neither can work here, because Chock is built on Nix: the
agent names a package, Chock realises it, and the program is on the `PATH` of
every tool call after that one.

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

### Where it came from

A provisioned program is realised by the Nix on your machine, which either
builds it here or copies it from a store. Which of the two happened, and where
from, is a record Nix keeps. A project can demand that record:

```zon
.{
    .nix = .{
        .provenance = .{
            .required = true,
            .from = .{"https://cache.flakehub.com"},
            .built_by = .{"builder-one"},
        },
    },
}
```

| Field | What it asks of a path |
|---|---|
| `required` | it says where it came from, rather than nothing |
| `from` | every copy in the record names one of these stores |
| `built_by` | every build in the record ran on one of these machines |

A field left out asks nothing, and a block with no fields asks nothing at all,
so Nix is never questioned and a session pays no call for it. Each field is read
over the whole record: a path built on one machine and then copied through two
caches holds one link for each step, and every link has to answer.

A path that fails keeps the program out of the toolchain, and the agent is told
what the path says beside what the project asked for. Three cases are refusals
rather than warnings: a path Nix holds no record of, a build whose record names
no machine while `built_by` names which machines may build, and a Nix that
cannot answer at all. The last one needs Determinate Nix 3.16 or later, which
is the first to hold both this record and the flag that asks for it.

What is checked is the path the program is, and not the whole closure it links
against. A tool's dependencies arrive from whichever stores your Nix is set to
use, so one store named for every path in a closure would refuse every ordinary
nixpkgs build. `.from` is a statement about the tool.

Your own `chock.zon` and the project's are read the way every other field in
the nix block is read: the project's block wins when it has one. An org bundle
cannot set this.

### A port you can open in a browser

A web project's agent starts a dev server and the person wants to look at the
page. `serve_port` asks for that: the agent starts the server in a background
`run_command`, then names the port it is listening on.

```
$ run_command {"argv":["npm","run","dev"],"background":true}
  started in the background
$ serve_port {"port":3000}
  http://127.0.0.1:3000 now reaches port 3000 inside this session's background
  commands.
```

The port is answered under `net.serve.3000`, so the project's policy decides,
and where it says `ask` a person does.
[actions.md](../configure/actions.md#netserveport) has the rule and what a
refusal says. The tool is offered only where a rule could permit a port, the
same way `provide_tool` appears only where `nix.build` is answered: a project
that says nothing about serving is not offered it at all.

A server in a foreground call cannot be published. That call holds the turn
until the command ends, so there is no moment at which the page exists and
somebody could open it.

The tool is Linux only. On macOS a session says that no port is open, because
the path inward is a network namespace the platform does not have.

### What it costs

A request holds the turn while Nix works, because the answer has to reach the
mount set of the very next tool call, not the model. A line is printed before
the wait so the terminal is not silent, and Ctrl-C reaches the `nix` child the
same way it reaches a subagent. Each Nix process has a fifteen-minute deadline;
one resolution may use a build, a provenance check and a closure query, each
under that same bound. A timeout refuses the request and adds nothing to the
toolchain.
