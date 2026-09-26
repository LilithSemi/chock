# Secrets for a tool

An agent can be useful with the GitHub CLI without ever holding a GitHub token.
The `secrets` block says which secret one tool call may be given, and Chock
gives the value to the program and not to the agent.

## The mapping is yours to write

The block goes in the project's own `chock.zon`, beside the policy:

```zon
.{
    .secrets = .{
        .{ .name = "GITHUB_TOKEN", .to = "exec.path.gh" },
    },
}
```

Nothing is discovered. An agent has no way to ask for a secret this block does
not name, and no way to add one: it reads the file it cannot write.

There is no operator layer and no org layer for this block. An org bundle is a
ceiling and can only narrow what a project may do, so nobody else can add an
entry that gives a project's tools something new.

## What an entry says

| Field | What it means |
|---|---|
| `name` | The secret, under the name the credential store knows it by. |
| `to` | The action name this secret may be given to. |
| `bind` | How it arrives: `env`, or `file`. `env` is the default. |
| `as` | The variable it arrives under. Left out, the secret's own name. |

`to` is an action name pattern, read by the same table every other permission
uses. See [actions.md](actions.md). So `exec.path.gh` reaches one program, and
`exec.*` reaches every program the agent may run. An entry names an action and
never a command string, because a command string says nothing about what the
command will do.

Letters, digits and underscore make a name. A name becomes part of the action
`secret.use.<name>`, so a dot would let one entry name a class of actions
nobody wrote.

## Using one is asked about

Every use is a brokered action, under `secret.use.<name>`. The block says the
secret may reach `gh`; the policy says whether that is a standing permission or
a question every time:

```zon
.{
    .policy = .{
        .allow = .{"secret.use.GITHUB_TOKEN"},
        .ask = .{"secret.use.DEPLOY_KEY"},
    },
}
```

One action per secret, so the one that matters can be a question while the rest
are not. [policy.md](policy.md) has the rest of the table.

## Putting the value where Chock reads it

The secret goes in the credential store, under the name the block gives:

```
chock login --tool-secret GITHUB_TOKEN
```

There is no option that takes the value itself. A command line is visible to
every other user through `ps`, and it lands in the shell history.

The name has no prefix of Chock's own, so the store holds it under exactly the
name a SecretSpec profile would. If your `credentials` block names
`secretspec`, name the secret in your profile and there is nothing to log in
for. See [credentials.md](../operate/credentials.md) for the stores.

## What the agent sees

The value reaches the environment of one tool call and nothing else. It is not
in the prompt, and the environment of the next call does not have it.

The environment is not what hides it. An agent picks the argument list, so it
can ask a program to print its own token. What hides the value is redaction:
every tool result is read for it before the result reaches the log or the
model, and it is replaced. Chock keeps a redaction slot for every secret a call
may hold, and a call granted more secrets than there are slots is refused
rather than run unprotected.

## What is written down

Each use appends a `secret.used` event to the session log: the secret's name,
the action it was given to, how it bound, and the variable it arrived under.
The value is not in the event, and there is no field it could travel in.

```json
{"kind":"secret.used","name":"GITHUB_TOKEN","action":"exec.path.gh","bind":"env","variable":"GITHUB_TOKEN"}
```

## What this does not do yet

* `bind = "file"` is refused. A call that asks for one is refused and says so,
  rather than putting the value where the program expects a path.
* An MCP server and a plugin are given nothing. They hold a secret for their
  whole life rather than for one call, so a per-call grant is the wrong shape
  for them, and an entry naming `mcp.*` reaches nothing today.
* A background command is given nothing. It outlives the call it was started
  from, and a grant that outlived its call would reach work nobody approved it
  for.
