# Configuration

Chock reads `~/.config/chock/config.zon` and never writes it, so you can give
the whole directory to home-manager.

```zon
.{
    .providers = .{
        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
        .{ .name = "work", .kind = "aiand" },
    },
    .defaults = .{ .provider = "local", .model = "glm4.7-flash:A3B" },
}
```

The kinds are `anthropic`, `aiand`, and `openai-compat`. An `openai-compat`
instance also needs a `base_url`.

## The name is the identity

The name is the key and the kind is a property, so two accounts of one kind sit
side by side with different names. Leave `.name` out and the kind becomes the
name. Two instances of one kind with no name are refused, and the message says a
name is needed, because silently replacing the first is how somebody loses a
credential they cannot get back.

## How much the model holds

Add `.context_tokens` to say how much the model behind an instance can hold:

```zon
.{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1", .context_tokens = 65536 }
```

Chock then folds the middle of the context into a summary at three quarters
of that, before a turn is sent. It tells the agent at three fifths, which is a
turn or more earlier, so the agent can save what it learned first. Leave it out
and only the backstop runs: a provider that refuses a request as too
large is compacted and the turn is taken again, rather than ending the
session. Either way the session log keeps every turn, so a compaction shortens
what the model reads and nothing else.

## What one instance can do

`.capabilities` says what an instance can do beyond answering with words.
Every field of it defaults to false, and two instances of one kind may differ:

```zon
.{ .name = "personal", .kind = "aiand", .capabilities = .{ .images = true } }
```

A tool is offered to the model only when the adapter can express it and the
provider instance does it.

## Naming a credential

A provider names its credential one of three ways:

```zon
.{ .name = "work", .kind = "aiand", .token_file = "/run/secrets/aiand" }  // sops-nix, agenix
.{ .name = "work", .kind = "aiand", .token = "sk-..." }                   // in place, mode 0600 only
.{ .name = "work", .kind = "aiand" }                                      // look it up, and send none if there is none
```

An instance that gives both `.token` and `.token_file` is refused, because
which one to read is not decided. A field that is present and holds nothing is
refused too: absence already means "look it up", so "the field is not there"
and "the field is there and holds nothing" stay two different facts.

The third line above is what a local endpoint needs. `chock run` still refuses
it for an instance of kind `anthropic` or `aiand` that talks to that kind's
own address, because those two refuse every request that carries no
credential. It refuses before it builds anything, so no workspace and no log
are left behind.

Where a lookup goes, and what `chock login` writes, is in
[credentials.md](../operate/credentials.md).

## The machine's own resource limits

`config.zon` also takes a `limits` block, in the same shape a project's own
`chock.zon` takes one:

```zon
.{
    .limits = .{
        .processes = "50%",
        .memory = "4GiB",
    },
}
```

This is the machine's own default: every project run from this machine which
names no `limits` field of its own gets the number here instead of Chock's
own machine sized default. A project's own `chock.zon` still wins over it, the
same way a project's own choices win over everything this file sets. See
[Sandbox resource limits](org.md#sandbox-resource-limits) for the field
syntax and the full order the layers fold in.

## The machine's own Nix store caps

`config.zon` also takes a `nix` block, in the same shape a project's own
`chock.zon` takes one:

```zon
.{
    .nix = .{
        .max_object_bytes = "16MiB",
        .max_session_bytes = "256MiB",
    },
}
```

This is the machine's own default for how much a Nix evaluation may add to
the store: every project run from this machine which names no `nix` field of
its own gets the number here instead of Chock's own built in default. A
project's own `chock.zon` still wins over it. See
[Nix store byte caps](org.md#nix-store-byte-caps) for the field syntax and
the full order the layers fold in.

## The project's own file

`config.zon` is yours and it is about providers. `chock.zon`, in the project
root, is the project's own file and it is about what an agent may do there.
What an agent may do lives in it: the policy table, the budget, the subagent
limits and the denied paths. So do the plugin list, the MCP servers, the
language servers and the container image. Chock binds it into the workspace
read only, so the agent works under rules it cannot edit.

The whole file is one struct literal, and each block is one field of it. This
is a complete `chock.zon` with every block a first project needs:

```zon
.{
    .policy = .{
        .agents = .{
            .{ .kind = "main" },
        },
        .rules = .{
            .{ .action = "net.fetch.org.ziglang", .decision = .allow },
            .{ .action = "git.push", .decision = .deny },
        },
    },
    .budget = .{ .max_cost = 5.0, .currency = "USD" },
    .deny_read = .{
        ".env",
    },
    .subagents = .{ .max_width = 2 },
    .apply = .{ .mode = .merge },
}
```

`.subagents` also takes `.max_depth`. Both default to 6. See
[subagents.md](../using/subagents.md).

`.apply.mode` says how an approved apply lands. It defaults to `merge`, which
parks the work at `refs/chock/<session>` and then merges it into the branch you
have checked out. The approval prompt names the branch and the landing before
you answer, so the `y` you give is a `y` to that act. There is no mode that
means "move nothing": say `n` to the apply, or write the policy row below.
[approvals.md](../using/approvals.md) shows both prompts.

A rule goes under `.policy.rules`, and never directly under `.policy`.
`.policy` is a struct with named fields, so a rule written beside `.agents` is
a syntax error and the session does not start. Every block is optional: leave
out the ones you do not want.

Every block of this file narrows what an agent may do, and two rows of the
policy table widen: `sandbox.jit` and `workspace.integrate`. Each is a row and
not a block of its own, because the table is where an organisation can forbid
what a project cannot take back. [actions.md](actions.md) has both.

- [policy.md](policy.md) for how a rule is read, and for the denied paths.
- [actions.md](actions.md) for every action name a rule can carry.
- [secrets.md](secrets.md) for the `secrets` block, which says what a tool call
  may be given without the agent ever seeing it.
- [org.md](org.md) for the bundle an organisation puts above the project.
- [subagents.md](../using/subagents.md) for the subagent limits.
- [plugins.md](../extend/plugins.md) for the plugin list.

### The dev shell the agent gets

The `nix` block of `chock.zon` names which `devShells` attribute the tool
environment comes from:

```zon
.{
    .nix = .{
        .dev_shell = "ci",
    },
}
```

Leave it out and Chock reads `default`, which is what `nix develop` reads.
`--dev-shell <name>` overrides it for one run. A name no flake carries stops
the session with Nix's own message. See
[toolchains.md](../operate/toolchains.md#which-dev-shell).

### Paths the worktree does not carry

The agent works in a git worktree at HEAD, so a file git ignores is invisible
to it. A generated configuration and an automation directory are the two a real
project needs anyway. The `workspace` block names them:

```zon
.{
    .workspace = .{
        .binds = .{
            .{ .name = "config.local.*", .mode = .read_only },
            .{ .name = "scripts/release", .mode = .copy, .write = .ask },
            .{ .name = "vendor/cache", .mode = .temp_copy },
            .{ .name = "generated/maybe", .mode = .read_only, .required = false },
        },
    },
}
```

Each bind names a path under the project root. The mode says how it reaches
the agent and what happens to a change the agent makes to it:

| Mode | How it arrives | What happens to a change |
|---|---|---|
| `read_only` | a bind mount, read only | impossible |
| `write` | a bind mount, read write | lands on your real file as it is written |
| `copy` | copied into the workspace | written back when the work applies |
| `temp_copy` | copied into the workspace | discarded with the workspace |

`mode` is required and has no default. Every value of it decides how much of
your own disk the agent reaches, and a default would make that invisible.

A bind can name a directory. `read_only` and `write` bind the directory and the
two copying modes copy it whole.

#### What may be written back

`write` carries the same three answers a policy rule carries: `allow`, `ask`
and `deny`. It is meaningful for `write` and `copy` alone. On `read_only` or
`temp_copy` it is refused when the file is read, because neither of those
reaches your files at all. Leave it out and it is `ask`.

The policy table decides beside it, under the action
`workspace.bind.<name>`, and the narrower of the two answers wins. So an
organisation can refuse the whole mechanism with one row, and you can deny one
path without editing a file somebody else wrote. See
[actions.md](actions.md#workspacebind).

The moment the question is asked differs by mode, because it is asked where it
can be:

- A `write` bind is decided at session start, before the bind is made. It is
  read only until something answers `allow`, and the session start says so.
- A `copy` bind is decided at the end, in the `workspace.apply` prompt, which
  names every file that is copied back. Refuse that apply and your files stay
  as they are, with the session's copies left in the workspace.

#### Names, patterns and what is refused

A name holding `*` or `?` is a pattern. `*` matches inside one path component,
`**` matches any run of components, and `?` matches one character that is not a
separator. Every other character matches itself. The patterns run against the
project directory, and never against git's list of ignored files, so a name
that happens to be tracked already is simply in the workspace twice over.

`required` says whether a name matching nothing stops the session. Its default
is derived: true for a name with no pattern character, false for a pattern. A
person who wrote `scripts/release` asked for that path, and a pattern matching
nothing is ordinary. Write `.required` yourself to say otherwise, in either
direction.

A match may be a symbolic link. Chock resolves it and binds the real file,
because a mount source cannot be a link. Every resolved path has to stay inside
the project: a name holding `..`, an absolute name, and a link that reaches out
of the project are each refused by name, and the session does not start. So are
`chock.zon` and anything under `.git`, which Chock holds for itself.

The session start names every bind it made, with what the name resolved to and
the mode it arrived under.

### When Chock refuses the file

A fault in `chock.zon` stops the session before the agent runs. The message
names the file, the line and the column.

Chock reads the file as a whole, and reads the `deny_read` block, before it
builds the workspace. A fault that early is named against the workspace:

```
chock run: the workspace for /home/you/site could not be built: chock.zon is
not valid:
4:9: error: expected field initializer
```

Every other block names its own block instead. The `policy` and `workspace`
blocks are read before the workspace is built, because a bind is decided
against the policy table. The `budget`, `subagents` and `plugins` blocks are
read after it is there:

```
chock run: the budget in chock.zon could not be read: chock.zon: the budget
block is not valid:
1:18: error: unexpected field
```

A message that says `chock.zon is not valid` is about the whole file, and
the fault can be in any block of it. A message that names a block, such as
`the deny_read block is not valid` or `the budget block is not valid`, is
about that block alone.

A project with no `chock.zon` has no spend cap. The two defaults run in
opposite directions on purpose. An action no rule names resolves to `ask`, so a
project that wrote no policy permits nothing by itself. A budget nobody wrote is
no budget, so a session runs until it finishes. Write a `budget` block to bound
what a session may spend:

```zon
.{ .budget = .{ .max_cost = 5.0, .currency = "USD" } }
```

The cap lives in that file and nowhere else, so the model cannot raise it. A
misspelled field inside the block is refused rather than read as no cap.
