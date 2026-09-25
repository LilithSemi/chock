# The actions

Every question Chock asks carries an action name. A rule in `chock.zon` names
one of them, or a class of them, and answers it. How a rule is read is in
[policy.md](policy.md). This page is the reference for the names themselves.

## What Chock ships

Chock ships default rules for the ordinary tool calls, so a project with no
`chock.zon` at all still runs them without a prompt.

| Namespace | What it names | Shipped |
|---|---|---|
| `call.<tool>` | one ordinary tool call | `allow`, for the tools below |
| `exec.devshell.*` | a program in the dev shell closure | `allow` |
| `exec.nix.store.*` | any other store path | `ask` |
| `exec.workspace.*` | a path inside the project | `allow` |
| `exec.path.*` | a bare name looked up on `PATH` | `allow` |
| `exec.unparsed` | a path Chock would not resolve | none, so `ask` |
| `net.connect.*` | the sandbox opening a socket | none, so `ask` |
| `net.fetch.*` | the `fetch_url` tool | none, so `ask` |
| `web.search` | the `web_search` tool | `ask` |
| `nix.build.*` | one attribute, built on your machine | none, so `ask` |
| `nix.net.*` | a host a Nix build reaches | none, so `ask` |
| `nix.net.build.opaque` | a build that names no URL at all | `allow` |
| `git.<subcommand>` | one git subcommand | `allow` where it changes only the workspace |
| `lsp.*` | starting a language server | `allow` |
| `device.*` | a USB or serial device | none, so `ask` |
| `mcp.*` | an MCP server and its tools | none, so `ask` |
| `plugin.*` | a plugin and its tools | none, so `ask` |

A shipped default is read only when nothing in the project's own rules matches
the key. A project rule that matches wins outright, whatever it names and
however wide it is. Writing
`.{ .action = "call.write_file", .decision = .ask }` in your own `chock.zon`
puts that call back behind a prompt.

## `call.*`, the ordinary tool calls

One action per tool, named after the tool. These ship as `allow`: `read_file`,
`read_image`, `list_directory`, `glob`, `grep`, `write_file`, `edit_file`,
`read_guidance`, `read_memory`, `write_memory`, `provide_tool` and `nix_eval`.

`run_command` has no `call.` action of its own, because a command is named by
the program it runs. `spawn_agent`, `update_plan`, `restrict_self`,
`fetch_url`, `ask_user`, `set_title` and `request_action` are decided at a key
that fits them better, so a `call.` rule for one of those would read as a
control and do nothing.

## `exec.*`, running a program

`run_command` names a program by the class it belongs to, and the store is two
of those classes. `exec.devshell.*` is a program inside the Nix dev shell
closure this session mounted at its start, and it is allowed. `exec.nix.store.*`
is every other store path, and it is the one shipped rule that is not an
`allow`.

A store path is immutable, so it names one program for ever, but the set of
store paths is not: the agent can have an expression evaluated and the result
built, and a path it made that way is not the toolchain it was given.

`exec.unparsed` is the class for a path Chock refuses to resolve lexically,
most often one holding a `..`. It holds no shipped rule, so it asks.

## `net.connect.*`, `net.fetch.*` and `nix.net.*`

Each of the three names one source. `net.connect` is the sandbox opening a
socket, `net.fetch` is the `fetch_url` tool, and `nix.net` is a Nix build,
which runs on your machine rather than in the sandbox. A host allowed for one
is not allowed for the others.

None of the three holds a shipped default, so a project that named nothing
about a host meets `ask` there and never `allow`. What an `ask` on
`net.connect.*` can reach is in
[threat-model.md](../security/threat-model.md), and the phases a build fetches
in are in [nix.md](../using/nix.md).

`net.fetch` is `fetch_url`'s action, and the host is part of the name, with the
labels reversed: `docs.ziglang.org` becomes `net.fetch.org.ziglang.docs`.
Reversal is what makes a class rule safe: `net.fetch.org.ziglang.*` means any
host under ziglang.org, and a host somebody else registered cannot match it.

```zon
.{ .action = "net.fetch.org.ziglang.*", .decision = .allow }
.{ .action = "net.fetch.*", .decision = .deny }
```

A redirect is followed only while every host along the way is allowed too, and
a site's own `robots.txt` is honoured. There is no way to send a header, a
credential, or a body: `fetch_url` reads, and it never writes to a remote
service.

Only `allow` reads a host with no question. A host that no rule names answers
`ask`, and for the host the agent itself named that `ask` reaches you while the
agent waits: you answer once and the fetch goes on.

**A redirect hop is not asked.** A fetch follows redirects, and each hop is a
new host. A hop a rule does not name is refused, because a page that could ask
at every hop would let whoever wrote it chain redirects and turn the prompt
into a way to tire you out. So you approve reading the host you were told
about, and never wherever it forwards you.

A rule in `chock.zon` still reads a host with no question at all, which is what
you want for a host the agent visits often. The refusal on your screen names
the rule to add, and the block it goes in.

### Whether a session has a network at all

`net.connect` and `net.fetch` rules say which hosts a session may reach.
`.policy.net.router` decides whether it is given a network namespace, a kernel
ruleset and a resolver at all:

```zon
.{
    .policy = .{
        .net = .{ .router = .auto },
        .rules = .{
            .{ .action = "net.connect.com.github", .decision = .allow },
        },
    },
}
```

* `.auto` is the default and reads the rules. A project that permits something
  under `net` is given a router. A project that permits nothing there is not,
  and pays for none of it.
* `.none` refuses a router whatever the rules say.
* `.filtered` gives one even when no rule permits a host yet, which suits a
  session where a person answers for each host as it comes up.

A router is a mechanism and never a permission. It grants no host by itself:
every connection is still decided at `net.connect.*`, and a router with nothing
permitted reaches nothing. A rule that only denies does not make `.auto` build
one.

`.policy.net.background` says what a command started in the background gets,
and takes the same three words. `.auto`, the default, is whatever the session
itself has.

A session with a network is given a trust store. Chock copies the host's own
certificate bundle into the sandbox, points `SSL_CERT_FILE` at that copy, and
links the conventional path, `/etc/ssl/certs/ca-certificates.crt`, to it too. A
project that sets `SSL_CERT_FILE` itself keeps its own.

A background command never asks you anything. It runs after the tool call that
started it has returned, and a question needs the session to be waiting on it.
So a background command reaches what this policy allows outright, and a host
that would have asked you is refused instead of queued. Set
`.background = .none` for a project where a background command should reach
nothing at all.

## `web.search`

One name, with no host under it, for the `web_search` tool. It ships as `ask`,
and the question reaches you at the tool call while the agent waits.

That timing is what lets it be `ask` at all. Two actions, `nix.build` and
`model.select`, are read before the work they govern, when nobody is there to
answer, so an `ask` on one of those means "never". `web.search` is not one of
them.

The engine's own host is not gated under `net.fetch`. You name the engine in
your own `config.zon` and a project does not get to pick it, so a project does
not have to permit it either. [search.md](search.md) has the block, the kinds,
and where the key lives.

A result the agent then wants to read is an ordinary `net.fetch` on a host your
rules probably do not name. Chock asks about that host, once, for the host the
agent named.

## The acts

| Action | What it does |
|---|---|
| `git.commit` | make a commit in a repository on the host |
| `git.push` | move a ref on a remote |
| `git.branch.delete` | delete a branch |
| `net.fetch` | read one page over http or https |
| `web.search` | put one query to the configured search engine |
| `nix.build` | realise a package, outside the sandbox |
| `file.write` | write a file on the host |
| `workspace.apply` | carry the session's commit into your repository |
| `model.select` | which provider instance and which model a session uses |
| `policy.widen` | let a session out of a promise it made to itself |
| `sandbox.jit` | run with the sandbox's write and execute rule off |
| `workspace.integrate` | let an approved apply move the branch you have checked out |
| `workspace.bind.<name>` | expose a path the git worktree does not carry |

### `git.*`

The three `git` actions have a shim in front of them. It reads the argument
vector of every `run_command` call whose first word is `git`, and it sorts each
subcommand into one that only reads and one that changes state. The shim
prevents a mistake and it does not prevent an attack. The sandbox layers are
the boundary. An agent that wants to avoid the shim has several ways and none
of them is difficult, so nothing in Chock is built as though the shim were a
control.

Every subcommand the shim classifies is asked about while the loop runs,
through the same arbiter an MCP tool call and a plugin tool call go through. A
read only subcommand asks nobody and runs the real git, so `git status`,
`git log` and `git diff` cost what they always did. A subcommand the shim does
not know asks under its own name, such as `git.frobnicate`. An option the shim
cannot read stops it reading the subcommand at all, and that asks as
`git.unknown`.

Chock ships `allow` for every git action name that changes only the session's
own workspace, `git.commit` among them, so a project with no `chock.zon` gains
no new prompt. It ships none for `git.push`, `git.clone`, `git.fetch`,
`git.pull` or `git.unknown`, so each of those asks.

An approved `git push` runs. It is the one subcommand that reaches another host
and is carried out: the real git runs inside the sandbox, reaches the remote
through the network router, and gets its credential over a socket for that one
call. An `https` remote prompts a person for a password, an `ssh` remote arms
the agent proxy, and both are closed again when the call ends.
[credentials.md](../operate/credentials.md) has the rest.

Every other subcommand that reaches another host is asked about and still does
not run, even when a person says yes. `git clone`, `git fetch` and `git pull`
have no act that carries the effect out, so the agent is told what is missing
rather than told no. Nothing in a session asks `file.write`.

### `model.select` and `nix.build`

`model.select` reads two rows: `provider.<instance>` is the instance by its
name in your `config.zon`, and `provider.<instance>.<model>` is one model at
that instance by the id that goes on the wire. The narrower of the two is the
answer. A session picks its model before the first turn, when nobody is waiting
to be asked, so only `allow` lets a model be used and every other answer is a
refusal.

`nix.build` is read once, also before the first turn, and it decides whether
the `provide_tool` tool exists at all. Only `allow` gives the session that
tool, and `ask` is a refusal there for the same reason.

### `sandbox.jit`

`sandbox.jit` is read once too, and it is the one row that widens rather than
narrows. It turns off the sandbox rule that refuses a page which is writable
and executable at the same time, which a run time with a just in time compiler
needs: V8 asks for such a page over a 268 MB range, so Node, Deno and Bun
cannot work without it. Only `allow` turns the rule off, because the filter is
built before the first turn and there is nobody to ask.

It is a row here and not a key in `chock.zon` because it widens. An
organisation writes `.{ .action = "sandbox.jit", .decision = .deny }` in its
bundle and no project can raise it, because the answer is a minimum over both
layers. The same fold means a subagent cannot give up hardening its parent
kept.

What is given up is documented hardening and it is not a boundary.
[sandbox.md](../security/sandbox.md) lists the three ways past the rule, and the
three places a session that gave it up says so.

### `workspace.integrate`

`workspace.integrate` is the second row of that shape, and it is read the other
way round from `sandbox.jit`. A project says in its `chock.zon` how an approved
apply should land, with `.apply = .{ .mode = .rebase }` and the four modes
[approvals.md](../using/approvals.md) lists. This row says whether an approved
apply may move a branch of yours at all. There is no mode that means "move
nothing", so this row and a `n` at the prompt are the two ways to say it.

```zon
.{ .action = "workspace.integrate", .decision = .deny }
```

A row nobody wrote answers `allow` here, unlike every action above, because
this is a question about a capability and not about an act. That is the same
reading `provider.<instance>` gets. One `deny` in an organisation's bundle
closes the road for every project under it, and the same fold means a subagent
moves no branch its parent could not.

This row decides whether, and `.apply.mode` decides where. `deny` is the one
decision that takes the capability away, so it is the one decision that parks
the work at the ref. `ask`, `agent_review` and `agent_then_human` each say that
integration is permitted once somebody says yes, and none of them names a
landing, so they keep the mode the project configured. The one question an
apply puts is the `workspace.apply` approval, which is a different row.

The answer is read once, when the session starts, before an apply is described,
because the description is what a person reads and it has to say what the apply
does. So the mode is settled before the prompt exists, and a yes at that prompt
carries the work in the mode the prompt named.

A rule that names nothing reaches this row. A catch all
`.{ .decision = .ask }` and a `workspace.*` rule both match
`workspace.integrate`, while a rule that names `workspace.apply` alone does
not.

### `workspace.bind.*`

A path the git worktree does not carry reaches the agent only when it is named
twice: once in a `workspace` block of `chock.zon`, and once here. The name a
bind is asked under is the name as the block spells it, so
`.{ .name = "scripts/release" }` asks under
`workspace.bind.scripts/release`.

```zon
.{ .action = "workspace.bind.*", .decision = .deny }
```

That row refuses the whole mechanism, and an organisation that writes it in its
bundle refuses it for every project under it. A row naming one path refuses
that path alone.

For a bind that copies nothing back, `read_only` and `temp_copy`, the answer
decides whether the bind is made at all. For `write` and `copy`, the answer is
folded with the block's own `write` field and the narrower of the two wins. A
`write` bind is read only until that fold answers `allow`. A `copy` bind is
written back only when the `workspace.apply` prompt that names it is permitted.

The block itself is in
[configuration.md](configuration.md#paths-the-worktree-does-not-carry).

## `device.*`

A project reaches a USB or serial device only when it is named twice: once in a
`devices` block of `chock.zon`, and once in a `policy` rule for the action that
block names. Chock ships no default for `device.*`, so a device named in the
`devices` block and nowhere in `policy.rules` still answers `ask`, and `ask`
refuses here: there is nobody at the keyboard while a session is already
running.

```zon
.{
    .devices = .{
        .{ .action = "device.usb.1d50.6018" },
    },
    .policy = .{
        .rules = .{
            .{ .action = "device.usb.1d50.6018", .decision = .allow },
        },
    },
}
```

The action name is the device's identity and never its path. `/dev/ttyUSB0`
changes with plug order and after a reboot, so a rule written against it stops
being true the moment the board is unplugged and plugged back in. A USB device
is named `device.usb.<vendor>.<product>`, in lower case hex. A serial adapter
with a serial of its own is named `device.tty.serial.<serial>`, because a whole
run of USB-to-serial chips from one factory can share a vendor and product id.
A serial adapter with none is named `device.tty.<vendor>.<product>`, the same
shape as a USB device.

Naming a device in the `devices` block only says the project wants it. The
`policy` rule beside it is what lets a session reach the node. See
[running.md](../running.md) for when a device that arrives is picked up, and
[sandbox.md](../security/sandbox.md) for what the grant does and does not bound.

## `lsp.*`

`lsp.<program>` is the action for starting a project's language server, named
after the last part of the program's path: a `command` of
`/nix/store/aaa/bin/zls` asks about `lsp.zls`. Chock ships `lsp.*` as `allow`,
so a project that already has one is unchanged, and an organisation that wants
none writes one rule:

```zon
.{ .action = "lsp.*", .decision = .deny }
```

A label is not an identity. A project writes its own `chock.zon`, so a project
that wanted to could point the name `zls` at another binary. `lsp.*` is the
rule to trust, and `lsp.zls` is a convenience. What bounds the damage is not
the name: the server runs inside the same sandbox a tool call gets, and reaches
nothing a tool call cannot. A program whose name cannot be one label of a rule
does not start at all, and says so.

## `mcp.*` and `plugin.*`

A tool a third party supplies is decided twice: once at session start, and then
on every call. Only a `deny` is spent at the start, and it keeps the tool out
of the session entirely, so a denied tool costs no context and asks nobody.
Every other answer leaves the tool offered and puts the same key to the broker
one call at a time, so a promise the session makes with `restrict_self` binds
the very next call.

```zon
.{ .action = "mcp.*", .decision = .deny },                            // no MCP tool at all
.{ .action = "mcp.time.tool.*", .decision = .allow },                 // every tool of that server
.{ .action = "mcp.time.tool.get_current_time", .decision = .ask },    // that one tool, per call
.{ .action = "plugin.hello.tool.greet", .decision = .agent_review },  // that one plugin tool
```

The `tool` segment is there so that a tool a third party names `network` cannot
become a rule about `mcp.<server>.network`, which is a separate key about
whether that server's process reaches a host at all.

A plugin tool is also priced against each capability it declares, under that
capability's own ordinary action name such as `fs.write`. A capability has to
be `allow` outright, because the capabilities of every offered tool decide the
set of host functions the plugin is built with, once, before any guest code
runs. [plugins.md](../extend/plugins.md) has the plugin side of it.
