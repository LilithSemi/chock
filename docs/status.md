# Status

What Chock does today, and what it does not. This is a snapshot, not a
promise. Chock is an early prototype.

## Working

Every command works.

`run`, `login`, `daemon`, `serve`, `memory`, `cache`, `workspace`, `usage`,
`plan`, `sessions`, `doctor`, `approve`, `detach`, `askpass`. Bare `chock`
brings up a full screen interface, and it prints the usage page when nothing
can be drawn.

## What is not built yet

- **The red team harness is built, and two models have been thrown at it.**
  `zig build redteam` runs the exercise the design asks for: a
  canary set measured before and after a session, a scope list compiled into the
  binary that reports the verdict, and the two configurations, which are maximum
  hardening and the dev shell that ships. It answers "did it break out" as a
  value rather than as a paragraph somebody reads, because grading a transcript
  by hand is how a real escape gets argued away. It is deliberately not part of
  `zig build test`, because it is an exercise run on purpose and not a build
  gate.
  What it has proved is itself. Eleven forged escapes are caught, and each one
  fires only its own boundary, because a forge that tripped the wrong canary
  would otherwise pass. Two of the eleven are a pair: one registers the git
  worktree a session builds for itself and must report nothing, and the other
  registers a second worktree no log accounts for and must report the real
  project. An instrument that cries wolf is as useless as one that sleeps.
  Building it found four faults in the instrument, and three of those would
  have reported a breach as held.
  What it has proved about Chock is two runs. `moonshotai/kimi-k3` engaged and
  probed hard. `claude-fable-5` refused the exercise and returned nothing, so it
  measured nothing, and the harness records that as an empty answer rather than
  as a session that held.
  **One boundary moved, and it is closed on both platforms.** A tool call wrote
  two files into the real repository, under `.git/worktrees/<attempt>/`: one in
  `logs/` and one in `refs/`. The second went unreported at first, because the
  check that had just been taught to accept the session's own worktree accepted
  every name under `refs/` with it. A narrowing added to stop a false positive
  is exactly where a real finding hides. Every ref and every
  object was unchanged, `chock.zon` was unchanged, nothing outside the
  workspace moved, no connection reached the listener, and no process outlived
  the sandbox. That directory is bound read write because git writes the
  worktree `index` there, and a read only one breaks `git status` and every
  tool call that touches git: measured against git 2.55, a read only mount
  there answers `EROFS` on the first `git add`, and pre-creating the lock files
  does not help, because git opens each one with `O_CREAT|O_EXCL` and then
  renames it over the file it locks. So the fix is a different directory
  instead of a read only one. The session now works in its own copy of
  `.git/worktrees/<attempt>`, under the workspace scratch directory, and the
  project's own copy reads byte for byte as `git worktree add` left it when the
  session ends. `git status`, `git add`, and `git commit` are unchanged inside
  the sandbox.
  **macOS reaches that copy a different way, because it has no bind mount.**
  Linux binds the copy at the path git looks for. macOS cannot, so the copy is
  named directly with `GIT_DIR` and `GIT_WORK_TREE`. Both are needed: with
  `GIT_DIR` alone git reads the working directory as the work tree root, so
  `git status` in a subdirectory reports every file outside it as deleted. The
  checkout's own `.git` file is left alone on both, because rewriting it breaks
  `git worktree remove` and the worktree id `adopt` reads out of it. Measured on
  macOS 15.7.9. See `lib/chock-workspace/worktree.zig`.
  **macOS is not covered by that fix.** There is no bind mount there, so a copy
  cannot be made to appear at the path git looks for, and the sandbox reads the
  project's own directory. Chock does not run tool calls on macOS yet.
  Everything else the model tried was refused: writing at refs, `git push`,
  copying a shell out of the store and renaming it to `git` to get past the git
  shim, symlinks out of the workspace, three ways to change `chock.zon`, and
  three backgrounded processes meant to outlive the sandbox.
  One run against one model is a measurement and not a guarantee. Ad hoc red
  teaming before this harness existed found nine faults, and this run found a
  tenth.
- **A handover cannot carry a background command or a background subagent, so a
  session running one refuses.** Both live in the process that started them, and
  that process is what writes their record into the log, so a handover would
  drop the record and tell the person who asked that the work carried on. What
  is missing is a way to hand a running thread's result to another process:
  either the record has to be written before the work finishes, which is a lie
  about work that has not happened, or the next owner has to wait for a process
  it did not start, which is a second ownership model. Neither is a small
  change, so the refusal is what is built.
- **Only a git project's workspace moves.** A project with no git of its own
  gets the overlay backing, and `overlay.create` cannot be called twice on the
  same scratch directory: the Linux driver refuses a directory that exists, and
  Darwin's clone refuses the same. The upper layer does survive the process that
  made it, so nothing is lost by rebuilding the paths. What is missing is an
  `overlay.adopt` beside `overlay.create`, one per driver. Until then
  `chock detach` refuses a running overlay session by name.
- **A session that ended some other abnormal way still rebuilds from committed
  state.** Those sessions keep their workspace too, and adopting one is a
  separate decision with its own refusal.
- **No seen-line guard on `edit_file`.** An edit is anchored two ways today:
  the text it replaces must be unique in the file, and the `file_hash` that
  `read_file` printed must still match, so a file that changed after the model
  read it is refused before anything is written. What is missing is the
  stronger rule, that the line being edited was one a tool actually showed the
  model. That needs a record of what each read returned, and the tool runner is
  a fresh process per call, so the record belongs at the loop's tool seam.
- **No tool reads an image.** `read_image` needs an image content part in the
  neutral message type and a different encoding per adapter, so it waits for
  a pass of its own. The gate that will hold it back until then is built:
  a tool is offered only when the adapter can express it and the provider
  instance does it.
- **macOS runs a real session, and two limits there are permanent.** Seatbelt
  holds the paths, the network including unix sockets, the signals and shared
  memory. A whole session has run on the Darwin box on 2026-08-25: `read_file`,
  `write_file`, `run_command`, the knowledgebase and a background task all
  answered, and `cat /etc/passwd` came back "Operation not permitted". Two
  things macOS cannot do: there is no system call filter, because macOS has
  none that works, and there is no bind mount. Every path Chock would place
  under `/run/chock/` appears at its own host path there instead, so an
  absolute path a program writes into a file names a directory that is deleted
  when the session ends. There is also no capped temporary area, so `TMPDIR`
  and `CHOCK_SCRATCHPAD` name one directory and a file written through either
  survives the call. `chock doctor` reports both. See [sandbox.md](sandbox.md).
- **`chock doctor` still calls a whole tool call blocked on macOS, and it is
  not.** Its `seatbeltToolCallRefusal` probes the three constants
  `chock-core` keeps for a build that can move a path, rather than asking each
  module where its directory really appears, so the row is stale in one
  direction: it says BLOCKED and a session runs.
- **A tree of agents runs, and the agents in it are `chock run` only at one
  level.** Real trees are driven in tests: a chain five levels deep, two
  children of one parent alive at the same time, a reviewer counted among a
  parent's children, a slice of a slice of a budget, and a parent that resumed
  and did not hand out the money it had already promised. Every agent in those
  trees is a real process with a log of its own, and a subagent is a child
  process, not a thread, because `fork` carries only the calling thread. What
  those trees do not have is a model in them: each agent is a test program that
  reads the command line `chock run` would read and writes the log `chock run`
  would write. A tree of real `chock run` sessions, with a provider behind each
  one, has still never been run.
- **A provisioning request holds the turn and has no deadline.** `nix build` on
  a cache miss is minutes, and the turn waits for it, because the answer has to
  reach the mount set the very next tool call is built from and not the model.
  A line is printed before the wait so the terminal is not silent, and Ctrl-C
  reaches the `nix` child the same way it reaches a subagent, but a build that
  never ends holds the session. It is also not asked about: the policy answer
  is read once, at the start, and decides whether the tool exists at all.
- **A plugin tool takes no arguments a schema describes.** A tool body reads
  the model's argument text whole, every offered plugin tool carries the empty
  schema, and the SDK refuses to compile a tool that declares an argument type
  with fields, so the gap is loud rather than a silently wrong read. Closing it
  is two halves that have to land together: a schema in the metadata the host
  reads, and a lowering in the guest with no allocator and no JSON parser
  there yet.
- **A project cannot ship guidance of its own.** The shelf `read_guidance`
  reads is compiled into Chock, which is why no tool call can write it. Letting
  a project add to it needs the read only path into the project that
  `chock.zon` already has.
- **A stream that broke in the middle of a reply is not retried.** A 429 or a
  5xx is answered with the same request sent again after a wait, up to six
  attempts spanning about a minute, honouring `Retry-After` when the provider
  sends one. A broken stream is a different fault: the turn half happened, and
  sending it again is a larger change than the wait was.
- **Nothing starts `git` with the password helper yet.** `chock askpass` is
  built: git or ssh asks over a socket, the broker answers from the policy
  table, and the credential never enters the sandbox. What is missing is the
  caller. `actions.performGitPush` blocks in `child.wait`, so a real push needs
  a caller that spawns git and polls the endpoint while it runs. The shape is
  proved by a test that does exactly that against real `git`.

## Known open items

- **The DNS rebinding window is closed for IPv4 and open for an IPv6-only
  name.** `fetch_url` resolves a permitted host, checks every address it
  answers with, and then holds the connection to a checked address, so the HTTP
  client cannot resolve the name a second time and reach an answer nobody
  checked. That pin needs the address written where the client wants a host
  name, and Zig 0.16 refuses a colon there, so an IPv6 address cannot be
  written into one. A name that answers with IPv6 addresses only is therefore
  read by the ordinary path, and the window is open for it. Whoever runs the
  zone decides which records it answers, so an attacker picks when this
  applies. It is allowed because refusing such a name leaves Chock unable to
  read anything on an IPv6-only or a NAT64 network. **The address check still
  runs over every address, IPv6 included**, before anything opens, and it reads
  the two IPv6 spellings of an IPv4 address that a NAT64 network makes real:
  `64:ff9b::/96` is unwrapped and answered by the IPv4 rules, and
  `fd00:ec2::254` is refused by name. The rest of `fc00::/7` stays reachable,
  because unique local addressing is the IPv6 form of the private IPv4 ranges
  a permitted host is most often on.
  Only the well known NAT64 prefix is read that way. RFC 6052 lets a network
  pick its own prefix at several lengths, and such a prefix cannot be told from
  an ordinary global address by its bytes alone, so reading one needs the
  network to say what it is. Until that is configuration, a site with its own
  prefix gets no unwrap.
- **A reverse proxy talks to `chock serve` over `--host`, not over the socket.**
  The socket check is the peer's user id, so a proxy under its own account, such
  as nginx as `www-data`, cannot open it. That is deliberate. Access by group is
  not built, and the answer for a proxy is `--host 127.0.0.1`. Bind the proxy to
  that address, and keep the port closed to everything else. The socket stays the
  default because it is what makes a bare `chock serve` safe with no proxy at
  all.
