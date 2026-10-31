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
```

`run` starts `chock run --output json` with the task, provider and model from
the spec and records the neutral provider and tool exchanges named by
`capture`. `replay` runs a fresh Chock session against only those exchanges: it
does not send a provider request or dispatch a captured generic tool call.
Every request is matched by digest, the capture itself has an integrity digest,
and an exhausted, divergent, truncated, or partly unused capture fails closed.

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
    .capture = "captures/parser.json",
    .expect = .{
        .end_reason = "finished",
        .max_turns = 8,
        .max_cost = 1.0,
        .currency = "USD",
        .config_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        .sandbox_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
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
    .tests = &.{
        .{ .name = "unit", .argv = &.{ "zig", "build", "test" } },
    },
}
```

Repository paths must be relative and cannot leave the fixture. Test commands
are argument arrays rather than shell strings and run with the fixture as their
working directory. A missing required path, a present forbidden path, or a
nonzero command exit is a finding rather than a malformed evaluation.

`files` pins exact repository bytes by SHA-256. `config_sha256` pins the
project configuration recorded by `session.config`, while `sandbox_sha256`
pins the effective sandbox rather than merely its source file. Subagent bounds
and completion checks are folded from the parent log, so an evaluation can
distinguish a successful root answer from a lost child.

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
identifier, the aggregate score, and every finding with its category, expected
value, and actual value. A report with any failed finding exits with Chock's
refused status. A malformed spec is usage failure, and a log which cannot be
verified is an audit gap.

The aggregate score is the fraction of checks which passed. It is a convenient
CI summary, not a training reward: consumers that turn reports into rewards
should keep the individual findings and their categories so a harness failure
cannot accidentally train the model.

`chock eval compare` reads two JSON reports without opening either session. It
fails when the candidate score is below `--minimum-score` or more than
`--max-regression` below the baseline. Both bounds are fractions from zero to
one; the default permits no regression and sets no absolute floor. The command
writes a versioned `chock.eval-comparison` object with `--format json`, so CI can
keep both the decision and the numbers which produced it.
