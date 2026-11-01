# Roadmap

What Chock does not do yet, and the faults it is known to have. This is a
snapshot and not a promise. Chock is an early prototype.

This page holds no list of what works. Read the pages in
[README.md](README.md) for what each part does, and treat anything absent from
them as not built.

## What is not built yet

- Delegating a web search to the provider is not built. All three engine kinds
  run harness side, which is what keeps the egress in the broker and the result
  cleaned. Both Anthropic and OpenAI accept an allowed-domains list on their own
  search tools, and Chock's policy already says which hosts an agent may read as
  `net.fetch.<reversed host>`, so the allowlist would come off the policy table
  rather than being configured a second time. Until that exists, a delegated
  search would hand the agent content from hosts nobody approved by a path the
  broker never sees, which is the one thing this design will not do.

  **And it could not honour its own policy default.** The tool list is built
  once in `start()`, so whether a provider-side search tool is offered is
  decided before any work, when nobody is waiting to answer. `web.search` ships
  `ask`, and an `ask` read at that moment means never, which is exactly why the
  harness-side tool is gated at the call instead. So delegation is reachable
  only for a project that sets `web.search` to `allow` outright, and that has to
  be a decision somebody makes rather than a surprise they meet.

- The work of an overlay session is reachable, and it is never applied for you.
  `chock workspace adopt <session>` rebuilds the overlay, reads the upper layer
  with `Overlay.changedFiles`, and copies what changed into
  `.chock-adopted/<session>/files` inside the project. Nothing of yours is
  written over and nothing of yours is deleted: a destination that already
  holds something is refused by name, and every path the session deleted is
  written to `.chock-adopted/<session>/deleted` for you to act on rather than
  removed. The act is recorded as a `workspace.adopt` event on the session's
  own log, with the three counts. This is the overlay's answer to
  `refs/chock/<session>`: inert, complete, and yours to take with one `cp`.

- A session that ended some other abnormal way still rebuilds from committed
  state. Those sessions keep their workspace too, and adopting one is a
  separate decision with its own refusal.

- macOS runs a real session, and two limits there are permanent. Seatbelt holds
  the paths, the network including unix sockets, the signals and shared memory.
  A whole session ran on the Darwin box on 2026-08-25: `read_file`,
  `write_file`, `run_command`, the knowledgebase and a background task all
  answered, and `cat /etc/passwd` came back "Operation not permitted". Two
  things macOS cannot do: there is no system call filter, because macOS has none
  that works, and there is no bind mount. Every path Chock would place under
  `/run/chock/` appears at its own host path there instead, so an absolute path
  a program writes into a file names a directory that is deleted when the
  session ends. There is also no capped temporary area, so `TMPDIR` and
  `CHOCK_SCRATCHPAD` name one directory and a file written through either
  survives the call. `chock doctor` reports both. See
  [sandbox.md](security/sandbox.md).

- Two CI runs touch macOS, and only one of them proves the sandbox. Nix on
  macOS puts every builder under `sandbox-exec`, and macOS refuses to put one
  profile inside another. So the `aarch64-darwin` part of `nix flake check`
  proves that the code compiles for macOS, and it proves nothing at all about
  Seatbelt: each test that needs a profile of its own asks
  `seatbelt.confinedAlready`, finds one already there, and skips.

  On a real Mac, macOS 15.7.9 with Nix 2.34.8 and `sandbox = relaxed`, on
  2026-08-26, both ways on the one machine: from a login shell the suite ran
  103 of 103 steps with 2168 of 2192 tests passed and 24 skipped, and the two
  Darwin escape suites ran 17 and 3 tests with nothing skipped. Inside
  `nix build` the same suite skipped 46, and the two escape suites skipped
  whole. Every figure in this paragraph but the escape suite counts is that one
  run and is not taken again here. The counts are read from the files
  themselves: `test/sandbox/darwin_escape.zig` holds 17 tests and
  `test/workspace/darwin_escape.zig` holds 3, and the first of those was 13
  until `fff60fe` added four Mach tests.

  The `test-sandbox` job runs the same suite on a macOS runner, outside any Nix
  builder, which is also how a person runs Chock. That job first proves the
  runner can enter a profile, and it fails rather than skips when it cannot,
  because a check that was not made is never a pass. A green `aarch64-darwin`
  check and a green `test-sandbox` run must not be read the same way. See
  [.github/workflows/ci.yml](../.github/workflows/ci.yml).

- A tree of agents runs, and the agents in it are `chock run` only at one
  level. Real trees are driven in tests: a chain four levels deep, two children
  of one parent alive at the same time, a reviewer counted among a parent's
  children, a slice of a slice of a budget, and a parent that resumed and did
  not hand out the money it had already promised. Every agent in those trees is
  a real process with a log of its own, and a subagent is a child process, not
  a thread, because `fork` carries only the calling thread. What those trees do
  not have is a model in them: each agent is a test program that reads the
  command line `chock run` would read and writes the log `chock run` would
  write. A tree of real `chock run` sessions, with a provider behind each one,
  has never been run.

- A stream that broke in the middle of a reply is not retried. A 429 or a 5xx
  is answered with the same request sent again after a wait, up to six attempts
  spanning about a minute, honouring `Retry-After` when the provider sends one.
  A broken stream is a different fault: the turn half happened, and sending it
  again is a larger change than the wait was.

- `chock migrate` reads a Claude Code, Codex, OpenCode, Zed or oh-my-pi
  configuration. It is a one shot, offline command: no session, no model, no
  network, no sandbox. `--from <harness>` names a harness, and a name this
  build does not read is refused against the list in `readers` in
  `src/migrate.zig`. A foreign deny renders at `.deny`. A
  foreign allow renders at `.ask`, never `.allow`, because an allow read
  against one tool's threat model does not become an allow under this one. A
  plugin and a skill carry into no field: a reader puts each in
  `Found.refused` with the reason instead. A directory of commands does carry,
  by name and never by copying, and every file in it that this build would not
  read becomes one refusal naming that file. A foreign hook is refused and the
  reason says what to write instead, because a hook here is an argv under the
  same exec policy as a tool call and not a shell line on the host. An environment
  variable's value is never read, only its name, through `envName`. It never
  overwrites a `chock.zon` that is already there: it prints the rows it would
  have added and writes nothing instead.

  A setting that covers a whole session becomes no row. Codex's
  `sandbox_mode` and `approval_policy`, and Claude Code's `defaultMode`, are
  each refused and named in the report. A row for an action this build does
  not define would read as a carried stance and match nothing, which is worse
  than refusing it, because the file then looks faithful.

  `migrate.vet` is the net under that. It runs on every read and moves a hint
  naming an action this build does not define into the refusals, so a reader
  added later cannot put an inert row in the file by forgetting. A test holds
  every name the guard admits to what `chock_policy.table.patternIsWellFormed`
  accepts, because a name the table refuses would stop the generated file
  loading at all.

  Most foreign permissions do not survive this. A Claude Code rule names a
  tool and an argument pattern, as in `Bash(cargo test:*)`; Zed's are regular
  expressions over command text; oh-my-pi's and OpenCode's are their own tool
  names. None of those is an action name here, so each is refused and named
  rather than guessed at. `webfetch` and `lsp` in OpenCode reach a real
  action, and so does `WebFetch(domain:<host>)` in Claude Code: a host is
  exactly what `net.fetch` names, the labels reverse, and a `*.` prefix
  becomes the trailing `.*` this table already reads as any host under a
  name. A host that cannot be read exactly is refused, because a wrongly
  reversed name would grant reach to a host nobody chose.

  `--sessions` brings a transcript from another harness across. It makes a
  new session log and writes two events into it, `session.start` then
  `session.imported`, and nothing else. The foreign turns are never written as
  `message` events: this log is a hash chain that `chock sessions seal` signs,
  and writing another tool's history into it would sign a claim about work
  Chock never saw. The transcript is copied beside the session and the event
  names it with the SHA-256 of its bytes, so a copy swapped afterwards is
  visible. The agent reads it with `read_file` when it needs to, the same way
  an `AGENTS.md` in a subdirectory arrives as a path and not as pasted text.
  A real transcript runs to megabytes, so there is no other workable shape.
  Only Claude Code has a pinned location today; every other harness is
  refused rather than guessed at.

  `--memory` brings another harness's notes into the knowledgebase, as data
  and never as instructions. Those files are written by an agent and often
  read like orders, so promoting them would turn a note an agent wrote to
  itself into something it must obey.

  Both read under the user's home, which the config readers deliberately do
  not. A transcript and a notebook live nowhere else, unlike a project's own
  configuration.

  `--permission <class>` carries an allow under that class as `.allow`
  instead of `.ask`. It takes `net.fetch`, and nothing else today. It exists
  because `ask` is a refusal for a fetch: only `allow` reads a host, so a
  fetch rule written at `ask` is the same as no rule. Without the flag
  nothing is carried as an allow at all. With it, only a host the source
  named itself is carried, never a wider one, and both the report and the
  generated file say which rows came in that way and why.

  The generated file opens with a header comment naming the version that
  wrote it, the date, and every file a reader read with the SHA-256 of the
  bytes as read, so an auditor can run `sha256sum` on the same paths and tell
  whether the project has moved since. `Found.sources` is where a reader
  states that list, so carrying it is not a habit one reader can keep and
  another forget. The same list is in the report too, under "carried", so it
  is visible even when the header is trimmed from a copy somebody keeps.

  All five readers are built: Claude Code, Codex, OpenCode, Zed and oh-my-pi.
  `--sessions` reads a Claude Code transcript and refuses every other harness
  by name, because only that one has been read at the source.

## Known open items

- A style rule has two parsers, and the second one is slow to start and
  narrower than the first. The wasm parser is tree-sitter's runtime and one
  grammar in a single freestanding module with no imports at all, 780 KB and
  269 functions, run by Chock's own engine. The engine compiles every function
  before the first answer: 29 seconds on the aarch64 dev box on 2026-10-29,
  against 18 milliseconds for a parse once it has. That cost is paid once a
  session and never a write, because the parser is a process that stays alive,
  and it is why the default stays the command at a quarter of a second a parse.

  Two limits come with it. A module carries one grammar, so a session has one
  language and a write in any other is not checked, which the `style.check`
  row says and the session says once. And the test that puts both parsers over
  one file is the slowest in the suite: it is built where
  `CHOCK_PARSER_MODULES` names a directory, which is the dev shell and so is
  CI, and the host it drives is a debug build of Chock, where the engine takes
  eight minutes over the same module it compiles in half a minute when it is
  built for release.

- A style rule is about the agent's writes and not about the repository. A
  person's own commit reaches no rule, and neither does a file the agent
  writes through a program it ran: `run_command` writes through the program's
  own file descriptors, and the gate is in the one function the structured
  write tools funnel through. A rule is a guard on what the model produces in
  the turn, so it is not a substitute for a formatter or a check in CI.

- A remote MCP server gets no OAuth. Chock carries a token from the credential
  store, under `bind = "header"`, and runs no browser flow: no protected
  resource metadata, no dynamic client registration and no PKCE. The
  specification makes authorization optional, so a token is a legal way to hold
  one, and a server that will take nothing else cannot be reached today.
  [remote-mcp.md](using/remote-mcp.md) says what else that transport leaves
  out, including the listening stream and a server on this machine.

- The DNS rebinding window is closed for IPv4 and open for an IPv6-only name.
  `fetch_url` resolves a permitted host, checks every address it answers with,
  and then holds the connection to a checked address, so the HTTP client cannot
  resolve the name a second time and reach an answer nobody checked. That pin
  needs the address written where the client wants a host name, and Zig 0.16
  refuses a colon there, so an IPv6 address cannot be written into one. A name
  that answers with IPv6 addresses only is therefore read by the ordinary path,
  and the window is open for it. Whoever runs the zone decides which records it
  answers, so an attacker picks when this applies. It is allowed because
  refusing such a name leaves Chock unable to read anything on an IPv6-only or
  a NAT64 network.

  The address check still runs over every address, IPv6 included, before
  anything opens, and it reads the two IPv6 spellings of an IPv4 address that a
  NAT64 network makes real: `64:ff9b::/96` is unwrapped and answered by the
  IPv4 rules, and `fd00:ec2::254` is refused by name. The rest of `fc00::/7`
  stays reachable, because unique local addressing is the IPv6 form of the
  private IPv4 ranges a permitted host is most often on. Only the well known
  NAT64 prefix is read that way. RFC 6052 lets a network pick its own prefix at
  several lengths, and such a prefix cannot be told from an ordinary global
  address by its bytes alone, so reading one needs the network to say what it
  is. Until that is configuration, a site with its own prefix gets no unwrap.
