# Migrating from another harness

`chock migrate` reads configuration from Claude Code, Codex, OpenCode, Zed, or
oh-my-pi and writes a proposed `chock.zon`. It is a one-shot offline command:
there is no session, model, network, or sandbox.

```
chock migrate --from claude-code
```

It never overwrites an existing `chock.zon`. When one exists, it prints what
it would carry and writes nothing.

## Permissions are translated narrowly

A foreign deny stays `.deny`. A foreign allow normally becomes `.ask`, never
`.allow`, because an allow under another harness's tool and threat model is not
automatically an allow here. `--permission net.fetch` is the one explicit
exception: it carries only a host the source named itself as `.allow`, never a
wider host class. The report and generated file both say which rows used that
exception.

Most foreign command rules cannot be translated faithfully. Claude Code's
`Bash(cargo test:*)`, Zed's command regular expressions, and the tool names of
OpenCode and oh-my-pi do not denote Chock action keys, so they are refused and
named instead of guessed at. OpenCode `webfetch` and `lsp`, and Claude Code
`WebFetch(domain:<host>)`, do reach real actions. Host labels are reversed in
the generated `net.fetch` key, and a `*.` host prefix becomes the trailing
`.*` Chock uses for a domain subtree.

Whole-session modes do not become rows. Codex `sandbox_mode` and
`approval_policy`, and Claude Code `defaultMode`, are listed as refusals.
Plugins and skills have no migration field. Foreign hooks are refused with the
replacement shape explained, because a Chock hook is an argv governed by exec
policy, not a host shell line. Environment variable values are never read;
only their names can appear in the report.

Every candidate action passes the same policy-key validator Chock uses when it
loads a project, so a reader added later cannot accidentally emit an inert or
malformed permission.

## Commands, sessions, and memory

A directory of commands carries by name, without copying its files. Any file
the current build would not read is a named refusal.

`--sessions` imports a Claude Code transcript. Chock creates a new session log
with `session.start` and `session.imported`, then copies the foreign transcript
beside it and records its SHA-256. Foreign turns never become `message` events:
the Chock log is a hash chain that can be sealed, and it must not sign a claim
that Chock performed another harness's work. The agent can read the copied
transcript as a file. Other harnesses are refused for this option until their
source locations and formats are pinned rather than guessed.

`--memory` brings supported foreign notes into the knowledgebase as data, not
instructions. An agent wrote those notes, so promoting them to mandatory
guidance would let earlier model output order a later session around.

Transcript and memory imports are the only readers that reach under the user's
home. Project configuration readers deliberately do not.

## Audit header

The generated file starts with the Chock version, date, and every source path
with the SHA-256 of the bytes read. The same list appears in the report. That
makes it possible to tell whether the source configuration changed after the
migration was reviewed.

All five configuration readers are implemented. Session transcript import is
currently pinned only for Claude Code.
