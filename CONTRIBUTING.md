# Contributing to Chock

Thank you for working on Chock. This guide covers the repository layout, the
coding standards, the rules that hold the security model together, and how we
test.

## Code of conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By taking part, you
agree to uphold it.

## Repository layout

- `lib/` - the libraries, one module for each concern. `chock-sandbox` holds the
  boundary, `chock-proto` the event log, `chock-policy` the rules, `chock-core`
  the agent loop, `chock-broker` the arbitration, and `chock-nix` the toolchain.
  `chock-auth`, `chock-container`, `chock-cost`, `chock-io`, `chock-pcsc`,
  `chock-provider`, `chock-workspace`, `chock-plugin-core` and
  `chock-plugin-sdk` complete the set.
- `src/` - the command line. One file for each command, with `main.zig` above
  them.
- `test/` - the tests that need more than one process, by area: `auth`,
  `broker`, `cli`, `container`, `core`, `pcsc`, `plugin`, `proto`, `redteam`,
  `sandbox` and `workspace`.
- `docs/` - the documentation. Start at [docs/README.md](docs/README.md).

## The rules that hold the model together

Chock runs a language model that writes and runs code. Four rules keep that
safe, and a change that breaks one of them is wrong even when it compiles and
passes.

**A library never prints.** Nothing under `lib/` writes to a terminal. A library
carries detail back through a `diag: ?*?Diagnostic` out parameter, and only
`src/` prints, through the writers threaded down from `std.process.Init`. A
library that prints cannot be used by the daemon, by a subagent, or by a test
that must keep the build log silent.

**The log is the truth.** The session log is append only. Each record carries a
hash of the bytes of the record before it. Code that records what happened must
write it before it is used, because a record written afterwards is a claim and
not evidence.

**A refusal is the safe answer.** An approval nobody answers is a refusal. A
policy that cannot be read is a refusal. When you add a decision, make the
failure path the one that does less.

**Narrowing is free and widening is not.** The policy ratchet lets an agent give
up permission by itself. Taking permission back needs authorisation. Keep that
direction.

## Coding standards

### Zig style: IronStyle

Chock follows Midstall's IronStyle. The backbone rule is:

> Assert on programmer errors. Recover from runtime faults. Never assume I/O
> succeeds.

In short:

- Assert broken invariants and impossible states. Return errors for malformed
  input, protocol faults, and I/O.
- Bound every loop and allocation.
- Use exhaustive switches. Do not reach for `else` where the compiler could catch
  a missed case.
- Sanitize untrusted input. A tool result, a fetched page, and a plugin's answer
  are all written by somebody else.
- Prefer `std.Io` over `std.posix` over `std.os.linux`.

See the `ironstyle` repository for the full guide and the rationale.

### Platform code

A platform difference lives in a `linux/` or a `darwin/` directory, and the
driver is selected at compile time on `builtin.os.tag`. Both drivers expose the
same interface, so a caller never asks which platform it is on.

A layer a platform cannot give answers `unsupported`, and a layer that is
present but off answers `off`. **Never report that a layer holds when it does
not.** A false report is worse than an honest refusal, because a refusal cannot
mislead anybody.

### Documentation and comments: ASD-STE100

Write comments, doc comments, and documentation in ASD-STE100, the aerospace and
defence industry's Simplified Technical English standard:

- One meaning per word. Active voice. Simple present tense.
- Short sentences. One instruction per sentence.
- No em-dashes. No semicolons in prose. Plain words.
- Comment the why, not the what. Spend comments on a measured number, a kernel
  behaviour, an ordering, or an invariant the types do not capture.

## How we test

Chock has caught the same few faults many times. Each one passed review and
passed its tests. Read this section before you write a test.

**A test that asserts nothing.** More than a dozen have been found here. Prove
your test can fail: break the behaviour, watch the test fail, name it, then put
the behaviour back. Put that mapping in your pull request.

**A fake that is too kind.** Chock once shipped a client that had never worked
against a real server, because both test servers accepted what no real one
would. Test against the real thing where a real thing exists. A loopback server,
a real language server, or a real card is worth more than a stand-in that agrees
with you.

**Built, tested, never wired.** A mechanism ships with green tests and no caller.
No test catches this, because the tests all pass. When you add something, show
where it is reached from.

**Prose that expired.** A comment that was true when written and is false now.
Nothing catches this either. When you change behaviour, read the comments around
it and the documentation that describes it.

## Before you submit

- `zig build` succeeds.
- `zig build test --summary all` passes, and a skip says why it skipped.
- `zig fmt --check build.zig lib src test` names no file. Give it the source
  directories, because a bare `.` also walks the fetched packages under
  `zig-pkg/`, which are not ours to format.
- The build log is silent. `zig build` prints `failed command:` for any step that
  writes to standard error, whatever its exit status, so a stray print makes
  every other result in the run look doubtful. `zig build test` therefore fails
  outright when a test binary writes one byte there. Give the code under test a
  writer the test owns, as `src/tty.zig`'s `Capture` does.
- A bug fix comes with a test that fails before the fix and passes after.
- A security relevant change says what it changes in [SECURITY.md](SECURITY.md),
  or says why that file still reads true.

## Commits

Chock uses short, imperative commit subjects with a type prefix, such as
`feat: seal a session with a card` or `fix: doctor reports the machine, not the
namespace`. Keep each commit focused and the tree building.
