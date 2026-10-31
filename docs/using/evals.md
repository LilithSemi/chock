# Evaluating a session

`chock eval` turns the audit log and the repository left by a session into a
versioned pass or fail report. A provider-backed run and a check of an existing
session use the same evaluator:

```console
chock eval run evals/parser.zon
chock eval replay evals/parser.zon
chock eval check evals/parser.zon --session 01M...
chock eval check evals/parser.zon --session 01M... --format json
chock eval compare baseline.json candidate.json --minimum-score 0.9
chock eval check evals/parser.zon --session 01M... --trajectory rollout.json
chock eval suite evals/train.zon --output rollouts/run-001 --parallel 8
```

`run` starts `chock run --output json` with the task, provider and model from
the spec and records the neutral provider and tool exchanges named by
`capture`. `replay` runs a fresh Chock session against only those exchanges: it
does not send a provider request, dispatch a captured generic tool call, start
a captured subagent, repeat a network request, or perform another captured
Chock-owned tool action. The redacted log effects of Chock-owned tools are
restored in order, so child completion, plans, policy, and other session state
remain visible to evaluation scoring. Every request is matched by digest, the
capture itself has an integrity digest, and an exhausted, divergent, truncated,
reordered, or partly unused capture fails closed.

`check` does not contact a provider. It replays the named audit log, checks its
hash chain, inspects the resulting repository, and runs the declared commands.
This makes `check` suitable for regression CI after an interesting session has
already been captured. Pass `--skip-tests` when the repository commands are
deliberately being run elsewhere.

## The spec

An evaluation is a versioned ZON value. Relative fixture paths are resolved
from the directory containing the spec, while `--project <dir>` overrides the
fixture for either command.

```zig
.{
    .schema = "chock.eval",
    .version = 1,
    .name = "parser rejects empty input",
    .task = "Make the parser reject an empty input and add a regression test.",
    .fixture = "fixtures/parser",
    .provider = "local",
    .model = "coder",
    .base_commit = "refs/tags/eval-fixture-v1",
    .capture = "captures/parser.json",
    .provenance = .{
        .model_profile = "qwen3.5-4b",
        .checkpoint = "Qwen/Qwen3.5-4B",
        .trainer = "verl-grpo",
        .seed = 42,
        .intervention = "residual-stream personality vector, layer 20, strength 0.75",
        .intervention_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    .expect = .{
        .end_reason = "finished",
        .max_turns = 8,
        .max_cost = 1.0,
        .currency = "USD",
        .config_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .sandbox_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        .sandbox_driver = "microvm",
        .required_events = &.{ "tool.call", "usage" },
        .forbidden_tools = &.{"browser"},
        .required_paths = &.{"src/parser.zig"},
        .forbidden_paths = &.{"secrets.txt"},
        .files = &.{
            .{ .path = "src/parser.zig", .sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" },
        },
        .forbidden_network_hosts = &.{"example.invalid"},
        .require_no_network = true,
        .require_no_refusals = true,
        .min_subagents = 1,
        .max_subagents = 4,
        .require_subagents_complete = true,
    },
    .reward_weights = .{
        .model = 1,
        .harness = 0,
        .sandbox = 1,
        .fixture = 2,
        .policy = 2,
        .network = 2,
        .budget = 0.5,
        .tests = 3,
    },
    .tests = &.{
        .{ .name = "unit", .argv = &.{ "zig", "build", "test" } },
    },
}
```

Repository paths must be relative and cannot leave the fixture. Test commands
are argument arrays rather than shell strings and run with the fixture as their
working directory. A missing required path, a present forbidden path, or a
nonzero command exit is a finding rather than a malformed evaluation.

Provider runs resolve `base_commit` (which defaults to `HEAD`) to a full object
ID before creating the session workspace. Every grouped rollout therefore
starts at the same immutable Git tree even if the source branch moves while a
suite is running. Reports and dataset entries retain that resolved commit. Pin
a tag or full object ID in committed training suites; the `HEAD` default is
mainly convenient for an ad-hoc local evaluation.

`files` pins exact repository bytes by SHA-256. `config_sha256` pins the
project configuration recorded by `session.config`, while `sandbox_sha256`
pins the effective sandbox rather than merely its source file. Subagent bounds
and completion checks are folded from the parent log, so an evaluation can
distinguish a successful root answer from a lost child.

Set `sandbox_driver` to `native` or `microvm` when the isolation implementation
is part of the case. The selected driver is recorded in `session.config`, so a
microVM evaluation fails rather than silently passing under the native sandbox.

`required_events` and `forbidden_events` use the event names stored in the
JSONL log, such as `tool.call`, `usage`, `network.summary`, and
`approval.response`. `audit_sha256` may pin the exact bytes of a captured log;
the hash-chain check still runs whether or not that field is present.

## Reports and failure ownership

The human report labels every finding with one of `model`, `harness`,
`sandbox`, `fixture`, `policy`, `network`, `budget`, or `test`. This distinction
matters in a model regression suite: an unreadable log is not evidence that the
model failed, and a broken fixture is not a bad answer.

JSON output has schema `chock.eval-report` version 1. It includes the session
identifier, resolved base commit, actual configuration and sandbox digests,
sandbox driver, aggregate score, and every finding with its category, expected
value, and actual value. A report with any failed finding exits with Chock's
refused status. A malformed spec is usage failure, and a log which cannot be
verified is an audit gap.

The aggregate score is the fraction of checks which passed. It is a convenient
CI summary, not a training reward: consumers that turn reports into rewards
should keep the individual findings and their categories so a harness failure
cannot accidentally train the model.

The report also carries a scalar `reward` and `reward_components` grouped by
category. `reward_weights` controls their weighted mean; a zero weight keeps a
component visible without letting it alter the scalar. This is the stable
boundary for an RL trainer: Chock owns the named measurements and the spec owns
their composition, while the trainer receives both the scalar and its parts.

`--trajectory <path>` writes `chock.rl-trajectory` version 1. The object binds
the exact audit JSONL bytes and SHA-256, the verified provider/tool capture,
the complete report, and the Chock version which produced it. Provider turns
may additionally carry `prompt_token_ids`, `response_token_ids`,
`response_mask`, and `old_logprobs`. A trajectory is marked `trainable` only
when every provider turn has all four arrays and the response-shaped arrays
have identical lengths. Ordinary hosted-provider captures therefore remain
valid evaluation evidence without pretending to be policy-gradient input; an
RL rollout adapter supplies the token-level fields at generation time.

`provenance` keeps policy and inference interventions separate from the task.
Use `model_profile` for the tokenizer/chat/tool protocol, `checkpoint` for the
exact weights or adapter revision, and `trainer` for the optimization recipe.
An activation-steering run should name the layer, representation and strength
in `intervention`, and pin the actual vector or configuration bytes with
`intervention_sha256`. Reports, trajectories and dataset entries retain these
fields, so a steered rollout cannot silently join an unsteered comparison.

## Batched RL rollouts

`chock eval suite` expands evaluation cases into bounded parallel rollouts. It
writes an independent integrity-checked capture, report, and lossless
trajectory for each rollout, followed by `dataset.json` with schema
`chock.rl-dataset` version 1. The index records the train, validation, or test
split, group and rollout numbers, the evaluation-spec SHA-256, Chock version,
session, resolved base commit, configuration and sandbox fingerprints, model
provenance, reward, exit status, and whether the trajectory contains complete
token-level training data. An external trainer can therefore reject a group
whose environment or policy does not match its peers. An existing dataset
index is never overwritten; use a fresh output directory for every collection
run.

```zig
.{
    .schema = "chock.rl-suite",
    .version = 1,
    .name = "parser policy train v1",
    .output = "rollouts/run-001",
    .parallelism = 8,
    .cases = &.{
        .{
            .name = "reject empty input",
            .spec = "parser.zon",
            .split = .train,
            .rollouts = 8,
            .group_size = 8,
        },
        .{
            .name = "preserve comments",
            .spec = "comments.zon",
            .split = .validation,
            .rollouts = 2,
            .group_size = 1,
        },
    },
}
```

`group_size` must divide `rollouts`. Group identifiers let an external trainer
compute within-prompt relative advantages for GRPO while retaining each
rollout's component rewards. `parallelism` limits live Chock processes; every
one still receives its own session worktree or microVM and starts from the
fixture rather than another rollout's result.

`chock eval compare` reads two JSON reports without opening either session. It
fails when the candidate score is below `--minimum-score` or more than
`--max-regression` below the baseline. Both bounds are fractions from zero to
one; the default permits no regression and sets no absolute floor. The command
writes a versioned `chock.eval-comparison` object with `--format json`, so CI can
keep both the decision and the numbers which produced it.
