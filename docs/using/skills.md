# Skills

A skill is a directory holding a `SKILL.md` file: somebody's written procedure
for one task. Chock finds them at session start, puts one line for each in the
system prompt, and gives the agent the whole of one when it asks. The format is
[Agent Skills](https://agentskills.io/specification), and a skill written for
another agent works here unchanged.

```
review-a-diff/
  SKILL.md        the procedure, with its frontmatter
  scripts/        programs it tells the agent to run
  references/     longer documents it points at
  assets/         templates and data
```

`SKILL.md` opens with YAML frontmatter. `name` and `description` are required.
The name must be 1 to 64 characters of lowercase letters, digits and single
hyphens, must not start or end with one, and must be the name of the directory
it is in. `license`, `compatibility`, `metadata` and `allowed-tools` are
optional.

```markdown
---
name: review-a-diff
description: How this repository reviews a diff. Use before opening a pull request.
---

# Review a diff

1. Read the whole diff before commenting on any part of it.
2. ...
```

## Where Chock looks

| Layer | Where | Written by | Default |
|---|---|---|---|
| operator | `<config dir>/skills/` | you | `allow` |
| project | a directory this project's `chock.zon` names | whoever wrote the repository | `ask` |
| packaged | `share/agent-skills/` in the dev shell's closure | a package author | `ask` |

A project says where its own are:

```zig
.{
    .skills = .{ ".chock/skills" },
}
```

The path must be under the project and must not climb out of it, and a symbolic
link is followed and then checked, because a repository can ship a link that
reads as ordinary.

A package puts its skills in `share/agent-skills/`, and Chock reads that one
name out of every store path the dev shell brought in. Nothing else about a
package is guessed at.

At most 32 skills reach the prompt, and `chock run` says how many were found,
how many were left out, and every directory that holds a `SKILL.md` and is not a
skill. A directory that appeared with eleven skills in it is worth knowing
about.

Two skills cannot share a name. The layer that comes first keeps it, so your own
skill wins over a repository's, and the one that lost is reported rather than
dropped in silence.

## What a skill cannot do

A skill is an instruction file, and an instruction file grants nothing. The
rule is the same one [instructions.md](instructions.md) states: the policy, the
budget and the tool list come from `chock.zon`, which the sandbox puts beyond
the agent's reach.

So:

- `allowed-tools` is never a grant. The field exists in the format and is
  marked experimental. Chock keeps the text and acts on none of it. Read as a
  narrowing, meaning the skill saying it needs no more than these, it is free
  and costs nothing; read as a permission it would let a downloaded directory
  widen what an agent may do.
- A skill reaches the prompt as one line until the agent asks for it. The
  ask is a `read_skill` call, which is a line in the session log, so "the agent
  read a stranger's instructions" is a fact somebody can find afterwards.
- A skill is never fetched. Only directories on disk. There is no URL here.
- A skill's `scripts/` are programs like any other. A `SKILL.md` that says
  to run `scripts/extract.py` produces an ordinary gated `run_command`, under
  `exec.path.*` or `exec.workspace.*` like anything else. A project that has
  not permitted it gets a refusal, and the skill saying to run it changes
  nothing.

## The three action names

Reading a skill is a question about who wrote it, so the action names the layer
and never the skill:

```
skill.read.operator    allow
skill.read.project     ask
skill.read.packaged    ask
```

Per layer, because a name a package chose must not become part of the action
namespace. A project that trusts its own skills writes one rule:

```zig
.{
    .policy = .{
        .rules = .{
            .{ .action = "skill.read.project", .decision = .allow },
        },
    },
}
```

## What is not supported

- Agent Plugins. Chock has plugins and they are a different thing: a
  WebAssembly module with its metadata in a custom section. See
  [../extend/plugins.md](../extend/plugins.md).
- Agent Stacks. It is draft 0.1.0 and pins two untagged specifications by
  commit.
- `compatibility` as a check. It is prose, up to 500 characters. Chock reads
  it and shows it, and a harness that guessed at its meaning would refuse a
  skill that would have worked.
