# Configuration

Chock reads `~/.config/chock/config.zon` and **never writes it**, so you can
give the whole directory to home-manager.

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

The **name** is the key and the kind is a property, so two accounts of one
kind sit side by side with different names. Leave `.name` out and the kind
becomes the name. **Two instances of one kind with no name are refused**, and
the message says a name is needed, because silently replacing the first is how
somebody loses a credential they cannot get back.

## How much the model holds

Add `.context_tokens` to say how much the model behind an instance can hold:

```zon
.{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1", .context_tokens = 65536 }
```

Chock then folds the middle of the context into a summary at three quarters
of that, before a turn is sent. It tells the agent at three fifths, which is a
turn or more earlier, so the agent can save what it learned first. **Leave it
out and only the backstop runs**: a provider that refuses a request as too
large is compacted and the turn is taken again, rather than ending the
session. Either way the session log keeps every turn, so a compaction shortens
what the model reads and nothing else.

## What one instance can do

`.capabilities` says what an instance can do beyond answering with words.
Every field of it defaults to false, and two instances of one kind may differ:

```zon
.{ .name = "personal", .kind = "aiand", .capabilities = .{ .images = true } }
```

A tool is offered to the model only when the adapter can express it **and**
the provider instance does it.

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

See [credentials.md](credentials.md) for where a lookup goes and what
`chock login` writes.

## The project's own file

`config.zon` is yours and it is about providers. `chock.zon`, in the project
root, is the project's own file and it is about what an agent may do there.
The policy table, the budget, the subagent limits, the denied paths and the
plugin list all live in it. Chock binds it into the workspace read only, so
the agent works under rules it cannot edit.

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
}
```

**A rule goes under `.policy.rules`, and never directly under `.policy`.**
`.policy` is a struct with named fields, so a rule written beside `.agents` is
a syntax error and the session does not start. Every block is optional: leave
out the ones you do not want.

- [policy.md](policy.md) for the policy table and the denied paths.
- [subagents.md](subagents.md) for the subagent limits.
- [plugins.md](plugins.md) for the plugin list.

### When Chock refuses the file

Chock reads `chock.zon` before it builds the workspace, so a fault in it stops
the session at the start. The message names the file, the line and the column:

```
chock run: the workspace for /home/you/site could not be built: chock.zon is
not valid:
4:9: error: expected field initializer
```

A message that says **`chock.zon is not valid`** is about the whole file, and
the fault can be in any block of it. A message that names a block, such as
`the deny_read block is not valid` or `the budget block is not valid`, is
about that block alone.

**A project with no `chock.zon` has no spend cap.** The two defaults run in
opposite directions on purpose. An action no rule names resolves to `ask`, so a
project that wrote no policy permits nothing by itself. A budget nobody wrote is
no budget, so a session runs until it finishes. Write a `budget` block to bound
what a session may spend:

```zon
.{ .budget = .{ .max_cost = 5.0, .currency = "USD" } }
```

The cap lives in that file and nowhere else, so the model cannot raise it. A
misspelled field inside the block is refused rather than read as no cap.
