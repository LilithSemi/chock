# Status

What Chock does today, and what it does not. This is a snapshot and not a
promise. Chock is an early prototype.

## Working

Every command works.

`run`, `login`, `daemon`, `serve`, `memory`, `cache`, `workspace`, `usage`,
`plan`, `sessions`, `doctor`, `approve`, `detach`, `askpass`, `migrate`. Bare
`chock` brings up a full screen interface, and it prints the usage page when
nothing can be drawn.

Instructions reach the prompt from four sources, and the prompt says which
layer each block came from. `AGENTS.md` at the operator, project and subtree
layers; any file `--instructions` names, at a layer of its own; and any file
the `instructions` block of `chock.zon` names, which arrives beside the
project's own `AGENTS.md`. A project whose instructions already live under
another name says so there rather than copying them. A named path must stay
inside the project: it is refused if it is absolute or climbs out, and it is
refused again after the links are resolved, because a repository can ship a
link and the prompt is where the bytes would land.

Every run writes a `session.config` event holding what a person put on the
command line and two hashes: the SHA-256 of the `chock.zon` the policy came
from, and one over what the sandbox of that run lets a tool call reach. It is
written on every run and not only the first, because a session that resumes
can be given different flags. `session.imported` records that a transcript
from another harness was brought in as context. It never claims Chock
witnessed the imported work, and the imported turns are not written as
`message` events: that row and its hash are the whole record.

`read_image` reads a picture out of the workspace and gives it to the model as
an image. It is offered only where both halves of the gate say yes: every
adapter can encode an image, so the answer turns on the provider instance's own
`.capabilities = .{ .images = true }`, and a session without it never hears the
name. The kind is read from the content and never from the name of the file,
four kinds are carried and every other kind is refused by name, and a picture
over 3 MiB is refused with nothing sent. The session log holds the description
of an image and never a second copy of the bytes. The `message` event carries
them, because the context is folded from `message` events, and the
`tool.result` event carries the media type, the size and a hash.

A plugin tool states the arguments it takes. A tool declares a Zig type and the
SDK lowers it into a schema the metadata carries, so the model is offered the
field names and kinds rather than a free text box. The host bounds what it will
carry: a schema larger than `max_schema_bytes` and a schema holding a field
name the host will not put in front of a model are both refused by name. The
tool is refused with them rather than offered with an empty schema, because an
empty schema would tell the model the tool takes nothing while the guest still
reads fields.

A declared device reaches a session. A project names a USB or serial device in
a `devices` block of `chock.zon`, by identity and never by a path:
`device.usb.1d50.6018` names a USB device by vendor and product, and
`device.tty.serial.<serial>` names a serial adapter by its serial. Naming it is
not enough on its own, because Chock ships no default for `device.*`, so
`chock.zon` needs a policy rule for the same action as well. Chock never grants
a device a person could not open themselves: the node is bound and the kernel
answers the sandboxed program's own `open` on the mode, exactly as it would
answer that person's. The machine is scanned at the start of each tool call and
never in the middle of one, so a board plugged in while a long call is already
running is seen by the next call and not by that one. `chock doctor` carries a
row saying how many devices this machine could pass. The block is in
[running.md](running.md), the action names and the rule are in
[actions.md](configure/actions.md), and what the grant does not bound is in
[sandbox.md](security/sandbox.md).

## The red team harness

The red team harness is built, and two models have been thrown at it.
`zig build redteam` runs the exercise: a canary set read before and after a
session, a scope list compiled into the binary that reports the verdict, and
the two configurations, which are maximum hardening and the dev shell that
ships. It answers "did it break out" as a value rather than as a paragraph
somebody reads. It is not part of `zig build test`, because it is an exercise
run on purpose and not a build gate. The step exists on Linux only, because
every canary reads `/proc` and the sandbox a run tests is the Linux driver.

What it has proved is itself. `zig build redteam-oracle` forges eleven escapes
and checks each verdict against the one boundary that forge names, because a
forge that tripped the wrong canary would otherwise pass. Two of the eleven are
a pair: one registers the git worktree a session builds for itself and must
report nothing, and the other registers a second worktree no log accounts for
and must report the real project. Building it found faults in the instrument
itself, and most of those would have reported a breach as held.

What it has proved about Chock is two runs. `moonshotai/kimi-k3` engaged and
probed hard. `claude-fable-5` refused the exercise and returned nothing, so it
tested nothing, and the harness records that as an empty answer rather than as
a session that held.

One boundary moved, and it is closed on both platforms. A tool call wrote two
files into the real repository, under `.git/worktrees/<attempt>/`: one in
`logs/` and one in `refs/`. The second went unreported at first, because the
check that had just been taught to accept the session's own worktree accepted
every name under `refs/` with it. Every ref and every object was unchanged,
`chock.zon` was unchanged, nothing outside the workspace moved, no connection
reached the listener, and no process outlived the sandbox.

That directory is bound read write because git writes the worktree `index`
there, and a read only one breaks `git status` and every tool call that touches
git. Against git 2.55, a read only mount there answers `EROFS` on the first
`git add`, and pre-creating the lock files does not help, because git opens
each one with `O_CREAT|O_EXCL` and then renames it over the file it locks. So
the fix is a different directory instead of a read only one. The session works
in its own copy of `.git/worktrees/<attempt>`, under the workspace scratch
directory, and the project's own copy reads byte for byte as `git worktree add`
left it when the session ends. `git status`, `git add`, and `git commit` are
unchanged inside the sandbox.

macOS reaches that copy a different way, because it has no bind mount. Linux
binds the copy at the path git looks for. macOS cannot, so the copy is named
directly with `GIT_DIR` and `GIT_WORK_TREE`. Both are needed: with `GIT_DIR`
alone git reads the working directory as the work tree root, so `git status` in
a subdirectory reports every file outside it as deleted. The checkout's own
`.git` file is left alone on both, because rewriting it breaks
`git worktree remove` and the worktree id `adopt` reads out of it. Checked on
macOS 15.7.9. See `lib/chock-workspace/worktree.zig`.

Everything else the model tried was refused: writing at refs, `git push`,
copying a shell out of the store and renaming it to `git` to get past the git
shim, symlinks out of the workspace, three ways to change `chock.zon`, and
three backgrounded processes meant to outlive the sandbox.

One run against one model is evidence and not a guarantee. Ad hoc red teaming
before this harness existed found nine faults, and this run found a tenth.

## What is not built yet

- One act is agent-requestable and the rest are not. This is the largest
  remaining gap in the approval model, so read it before the rest. An ordinary
  tool call is asked about: `gateToolCall` in `Loop.run` builds the action name
  `Tool.actionInto` names for the call and asks `deps.arbiter`, the same seam
  `runRestrictSelf` uses for a widening. The shipped defaults answer `allow`
  for almost every one of those action names, so a project with no `chock.zon`
  of its own gains no new prompt.

  There are two deliberate exceptions. The first is `exec.unparsed`, which
  `run_command` answers for a path it refuses to resolve lexically, most often
  one holding a `..`. It holds no shipped default at all, the same as
  `net.connect.*` and `net.fetch.*`, so a project with no `chock.zon` gains a
  new prompt the first time such a path runs. A default of `allow` there let
  such a path escape every exec rule a project wrote, naming none of its four
  classes. See `lib/chock-policy/defaults.zig`'s own top comment, "What is
  deliberately absent". The second is `exec.nix.store.*`, a store path this
  session did not start with, which ships as `ask` while the dev shell closure
  it split off, `exec.devshell.*`, ships as `allow`.
  [actions.md](configure/actions.md) has both.

  Seven tool names are skipped by this gate and decided elsewhere, at the key
  that actually works. `spawn_agent` is bounded by `chock.zon`'s own
  `subagents` block, `max_width` and `max_depth`. `restrict_self` needs
  nobody's permission to narrow, and asks about `ratchet.widen_action` only to
  widen. `fetch_url` is decided per host, once the URL is known, at
  `net.fetch.*` and `net.connect.*`. `request_action` is decided at the
  requested act's own name. `update_plan`, `ask_user` and `set_title` grant no
  capability and need no key at all.

  An MCP or plugin tool is not asked about by this gate either, and is gated at
  its own door instead. `chock_core.mcp.Session.dispatch` and
  `chock_core.plugin.Session.dispatch` ask `chock_core.arbiter.Asker` on every
  call, through the same broker every other mid-session question goes through.
  Session start still reads the table once, and a `deny` there keeps the tool
  out of the session entirely, so a denied tool costs no context and nobody a
  question. An `.ask`, `agent_review` or `agent_then_human` row is put to the
  broker, which answers each the way its row says, and a mid-session
  `restrict_self` narrowing binds the very next call. A session with nobody to
  ask runs no such tool at all.

  The two key shapes are written out here, because a rule that matches nothing
  looks exactly like a rule that allows. An MCP tool is
  `mcp.<server>.tool.<tool>` and a plugin tool is `plugin.<plugin>.tool.<tool>`.
  The `tool` segment is there so that a tool a third party names `network`
  cannot become a rule about `mcp.<server>.network`, which is a separate key
  about whether that server's process reaches a host at all. A plugin tool is
  also priced against each capability it declares, under that capability's own
  ordinary action name such as `fs.write`, and those are asked about per call
  too. So:

  ```zon
  .{ .action = "mcp.*", .decision = .deny },                            // no MCP tool at all
  .{ .action = "mcp.time.tool.*", .decision = .allow },                 // every tool of that server
  .{ .action = "mcp.time.tool.get_current_time", .decision = .ask },    // that one tool, per call
  .{ .action = "plugin.hello.tool.greet", .decision = .agent_review },  // that one plugin tool
  ```

  What is missing is a way for the agent to ask about a wider act.
  `request_action` is in `chock_core.tools.Tool`, and it takes
  `workspace.apply` and nothing else: an agent that believes it is finished can
  ask for its commit to be carried into the user's repository, and the policy
  table, or a person, answers. Every other action name is refused by name,
  before anybody is asked. An agent cannot ask about `net.fetch` as an act,
  `nix.build` or `file.write`, and the table can answer those rows while
  nothing in a session asks them.

  Four callers reach the broker. Two are the harness itself: `chock run` asks
  for `workspace.apply` after the loop has ended, and the session arbiter asks
  for `policy.widen` while it runs. The third is the agent, through
  `request_action`, for that one act. The fourth is the git shim, which asks
  about every subcommand it classifies, so `git.commit`, `git.push` and
  `git.branch.delete` are rows a session really does ask. `git commit` runs with
  no prompt on a project that wrote no `chock.zon`, because Chock ships `allow`
  for every git action name that changes only the session's own workspace. A
  subcommand that reaches another host is asked about and still does not run,
  even approved: the act that leaves the sandbox has no caller yet.

- A handover cannot carry a background command or a background subagent, so it
  waits for one. Both live in the process that started them, and that process
  is what writes their record into the log, so a handover that took the session
  would drop the record and tell the person who asked that the work carried on.
  A background command cannot move by any means: its thread reads the command's
  output in this process, and the session's own teardown ends the command. A
  background subagent could in principle be adopted, because its process and
  its log both outlive the parent and its log's lock says whether it still
  runs, but that costs the property every replay reads, that each
  `session.spawn` has an `agent.complete` after it. So the ask is held open
  instead and the session hands over once the work is recorded. What is missing
  is a handover that does not make the person wait for a long build.

- Only a git project's workspace moves to a second process. A project with no
  git of its own gets the overlay backing, and `overlay.create` cannot be
  called twice on the same scratch directory: the Linux driver refuses a
  directory that exists, and Darwin's clone refuses the same. `overlay.adopt`
  stands beside `overlay.create`, one per driver, and rebuilds the four paths
  over a layout that is already on disk. What is missing is the rest of a live
  handover for that backing. `Workspace.adopt` takes a `base_commit` a project
  with no git does not have, and `src/run.zig`'s own `takenOver` reads only a
  worktree `workspace.open`. So `chock detach` refuses a running overlay
  session by name, and names `chock workspace adopt` in the same sentence.

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

- There is no seen-line guard on `edit_file`. An edit is anchored two ways: the
  text it replaces must be unique in the file, and the `file_hash` that
  `read_file` printed must still match, so a file that changed after the model
  read it is refused before anything is written. The hash is optional, so an
  edit that sends none is held by the uniqueness rule alone. What is missing is
  the stronger rule, that the line being edited was one a tool actually showed
  the model. That needs a record of what each read returned, and the tool
  runner is a fresh process per call, so the record belongs at the loop's tool
  seam.

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

- A provisioning request holds the turn and has no deadline. `nix build` on a
  cache miss is minutes, and the turn waits for it, because the answer has to
  reach the mount set the very next tool call is built from and not the model.
  A line is printed before the wait so the terminal is not silent, and Ctrl-C
  reaches the `nix` child the same way it reaches a subagent, but a build that
  never ends holds the session. It is also not asked about: the policy answer
  is read once, at the start, and decides whether the tool exists at all.

- A project cannot ship guidance of its own. The shelf `read_guidance` reads is
  compiled into Chock, which is why no tool call can write it. Letting a
  project add to it needs the read only path into the project that `chock.zon`
  already has.

- A stream that broke in the middle of a reply is not retried. A 429 or a 5xx
  is answered with the same request sent again after a wait, up to six attempts
  spanning about a minute, honouring `Retry-After` when the provider sends one.
  A broken stream is a different fault: the turn half happened, and sending it
  again is a larger change than the wait was.

- An approved `git push` runs. The real git runs inside the sandbox, reaches
  the remote through the network router, and is given its credential over a
  socket for that one call: git runs `chock askpass`, which carries the prompt
  to the broker and carries one answer back. Which credential is chosen by the
  remote's own scheme, read on the host at approval time. An `https` remote
  prompts a person for a password, an `ssh` remote arms the agent proxy, and a
  remote that cannot be read refuses the push rather than guessing. Both are
  closed again when the call ends, so the capability lasts as long as the act
  and no longer. Every other subcommand that reaches another host is asked
  about and still does not run.

  A password is prompted live and never stored. There is no credential store
  entry for one, no configuration field, and nothing written to disk. The value
  is held for one tool call, covered by the redaction funnel for exactly as
  long as it exists, and overwritten when the call ends. A private key is never
  copied: an ssh agent signs and never hands a key out, so the sandbox gets
  "can sign with this key" and not the key.

  The agent cannot use the socket as a credential oracle. A helper reachable
  from any tool call would let the agent ask for a password for any host
  `secret.password.*` permits, as often as it likes, with no git involved. Live
  prompting is what removes that: nothing can be had without a person seeing a
  prompt, so the worst an agent can do is make noise, which is visible and
  refusable.

- `chock migrate` reads a Claude Code, Codex, OpenCode, Zed or oh-my-pi
  configuration. It is a one shot, offline command: no session, no model, no
  network, no sandbox. `--from <harness>` names a harness, and a name this
  build does not read is refused against the list in `readers` in
  `src/migrate.zig`. A foreign deny renders at `.deny`. A
  foreign allow renders at `.ask`, never `.allow`, because an allow read
  against one tool's threat model does not become an allow under this one. A
  hook, a plugin, a skill and a slash command carry into no field: a reader
  puts each in `Found.refused` with the reason instead. An environment
  variable's value is never read, only its name, through `envName`. It never
  overwrites a `chock.zon` that is already there: it prints the rows it would
  have added and writes nothing instead.

  A stance that covers a whole session carries into no row. Codex's
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
  rather than guessed at. `webfetch` and `lsp` in OpenCode are the two that
  reach a real action.

  The generated file opens with a header comment naming the version that
  wrote it, the date, and every file a reader read with the SHA-256 of the
  bytes as read, so an auditor can run `sha256sum` on the same paths and tell
  whether the project has moved since. `Found.sources` is where a reader
  states that list, so carrying it is not a habit one reader can keep and
  another forget. The same list is in the report too, under "carried", so it
  is visible even when the header is trimmed from a copy somebody keeps. What
  is missing is every harness reader itself.

## Known open items

- A wasm plugin does not run on x86_64. The engine answers `error.Unsupported`
  when it instantiates a module, so no plugin tool can be called on that
  architecture. aarch64 is unaffected, and nothing else in Chock is.

  The cause is in Vulcan and not in Chock. Its register allocator records the
  clobber a call makes in the same place it records an ordinary occupant's next
  use, so a register a call destroys at a position cannot be told from one an
  occupant merely wants back at that position. A value that is both an argument
  of a call and live across that same call then finds every register tied, and
  the allocator gives up rather than spilling. x86_64 has 5 callee-saved
  general registers to aarch64's 10, which is why one architecture meets this
  and the other never does.

  Only a release build meets it. A `ReleaseSafe` guest lowers to more functions
  than a debug one, and the function that meets it is `std.Io.Writer.writeAll`,
  which is standard library code and not a shape a plugin author chose. A debug
  build of the same plugin compiles, so `zig build test` on a development
  machine does not see this.

  A fix exists on a Vulcan branch. Chock pins Vulcan by commit, and the pin has
  not moved to it.

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

- A reverse proxy talks to `chock serve` over `--host`, not over the socket.
  The socket check is the peer's user id, so a proxy under its own account,
  such as nginx as `www-data`, cannot open it. That is deliberate. Access by
  group is not built, and the answer for a proxy is `--host 127.0.0.1`. Bind
  the proxy to that address, and keep the port closed to everything else. The
  socket stays the default because it is what makes a bare `chock serve` safe
  with no proxy at all.
