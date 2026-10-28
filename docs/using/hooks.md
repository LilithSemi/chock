# Hooks

A hook is a program a project runs at a point in a session: a check before the
agent writes a file, a formatter after it, a test suite before a session
starts.

```zon
.{
    .hooks = .{
        .{
            .name = "tests-pass",
            .on = "tool.before",
            .tool = "request_action",
            .run = .{ "zig", "build", "test" },
            .timeout_ms = 120000,
            .output = "refuse",
        },
    },
}
```

That one runs the tests before the agent may ask for its work to be applied,
and refuses the ask if they fail.

## A hook is not a way around anything

A hook runs as a command, through the gate every tool call goes through. The
same `exec.*` rule decides it, the same sandbox holds it, the same redaction
covers what it wrote, and the log holds its call and its result beside the
agent's own.

| What a hook can do | What it cannot do |
|---|---|
| refuse something that has not happened | permit anything |
| tell the agent what it found | reach a path the sandbox does not grant |
| end a session before the first turn | run a program the policy refuses |

There is no `output` that permits. A hook may narrow what the policy decided
and never widen it, which is the rule
[policy.md](../configure/policy.md) states for everything else an agent or a
project can say.

`run` is a list and never a line, so nothing parses a quote, a semicolon or a
backtick:

```zon
.run = .{ "./scripts/check", "--strict" },
```

A shell is yours to ask for by name, and it is then a program like any other,
under the same `exec.*` rule:

```zon
.run = .{ "sh", "-c", "test -z \"$(git status --porcelain)\"" },
```

**A hook that cannot run refuses.** If the policy refuses its program, or the
program cannot start, a hook whose output is `refuse` refuses what it fired
on. A check that did not happen is not a check that passed.

## The fields

| Field | Meaning |
|---|---|
| `name` | what a refusal and the log call it. Lowercase letters, digits and single hyphens, and two hooks cannot share one |
| `on` | `session.start`, `session.end`, `tool.before` or `tool.after` |
| `tool` | the one tool this is about, for the two tool triggers. Leave it out for every tool |
| `run` | the program and its arguments, as a list |
| `inputs` | which facts reach the program, from `trigger`, `tool`, `action` and `session` |
| `timeout_ms` | give up after this long. At most 600000, and 30000 by default |
| `output` | `ignore`, `refuse` or `note` |

At most eight hooks, and at most sixteen words in a `run`.

## When each one runs

| Trigger | When | `refuse` | `note` |
|---|---|---|---|
| `session.start` | before the first turn | ends the session | no |
| `tool.before` | before a tool call is decided | the call never runs | yes |
| `tool.after` | once a tool call has run | no | yes |
| `session.end` | after the last turn, and after every subagent | no | no |

A call that never ran fires no `tool.after` hook, whether a hook refused it,
the policy refused it, or the agent holds no tools at all. There is nothing for
such a hook to be about.

An output a trigger cannot carry is refused when the file is read, rather than
doing nothing at runtime. `refuse` needs a moment where something has not
happened yet, and `note` needs a tool result to carry the words.

## What a hook is told

A hook is told only what it asked for, as arguments:

```zon
.{
    .name = "check-a-write",
    .on = "tool.before",
    .tool = "write_file",
    .inputs = .{ "tool", "action" },
    .run = .{ "./scripts/check" },
}
```

runs `./scripts/check --tool write_file --action call.write_file`.

The arguments the agent gave the tool are not among the inputs. A hook decides
by the kind of call and by the state of the workspace it can read, and not by
text the model wrote.

| Input | What it holds |
|---|---|
| `trigger` | `tool.before`, and so on |
| `tool` | the tool the moment was about |
| `action` | the action name the call is gated under, the same name a policy rule is written against |
| `session` | this session's identifier |

An input with nothing in it is left out, so a program never has to tell an
empty value from a missing one.

## What the log holds

Each run appends a `hook.run` event, beside the ordinary `tool.call` and
`tool.result` for the program itself:

```json
{"kind":"hook.run","name":"tests-pass","trigger":"tool.before","tool":"request_action","action":"exec.devshell.zig","outcome":"ran","errored":true,"refused":true}
```

`outcome` is `ran`, `refused_by_policy` or `could_not_run`. `chock sessions
show` prints a line for each.

The program's own call carries the id `hook:<name>:<what it was about>`, which
is the call it fired on or the trigger where there was none. So one hook that
fires on many calls writes an id for each, and the terminal says `hook <name>:`
rather than `$` on that line.

A session that a `session.start` hook refused ends with the reason
`refused_by_hook` and exits 3, the code a refusal takes.

## What this is not for

A hook is the project's own check, so a refusal is not a question and there is
nothing to approve. Where you want a person to decide, write a policy rule
that says `ask`: [actions.md](../configure/actions.md) has the names, and
[approvals.md](approvals.md) has what a person sees.
