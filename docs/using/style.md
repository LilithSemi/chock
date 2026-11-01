# Style rules

A style rule is a tree-sitter query of the project's own plus one bound. A
write that breaks the bound is refused before a byte reaches the disk, and the
agent is told which rule, which number and which line.

```zon
.{
    .style = .{
        .parsers = "TREE_SITTER_PARSERS",
        .grammars = .{
            .{ .language = "zig", .extensions = .{".zig"} },
        },
        .rules = .{
            .{
                .name = "comment-block",
                .query = "style/comments.scm",
                .max_lines = 10,
            },
        },
    },
}
```

`style/comments.scm` is a file in the project, in tree-sitter's own query
language:

```scheme
(comment) @c
```

Together those say: no comment in a `.zig` file covers more than ten lines.
The agent that writes an eleven line comment gets this back, and the file is
unchanged:

```
write_file was refused by the style rule comment-block: a match covers 11
lines, and the rule permits 10, first at line 1.
```

## The project writes the rules

Chock knows nothing about any language. A project says which grammars it has,
writes its own queries, and picks the numbers. So a rule can be about anything
a query can match, and nothing has to be added to Chock to enforce a house
style it has never heard of.

## One bound a rule

A rule with two bounds is two rules, so exactly one of these is written:

| Bound | What it counts |
|---|---|
| `max_matches` | matches in the file. Zero refuses on the first one. |
| `max_lines` | lines one match covers. A match on one row covers one line, so zero cannot be met and is refused when the block is read. |
| `max_share` | lines at least one match covers, against the file's own line count, as a percentage. |

`max_share` counts a line once however many matches cover it. A query cursor
walks a tree, so a parent's match arrives before a child's and a later row
before an earlier one. The lines are sorted and swept before they are counted,
which is why a nested match is not counted twice.

## Refusing and reporting

A rule refuses by default. A rule the project is still adopting reports
instead: the write lands and the agent is told anyway.

```zon
.{ .name = "long-function", .query = "style/fn.scm", .max_lines = 60, .decision = "report" },
```

A reported rule's sentence is appended to what the tool call answers, under the
line that says what was written.

## What is checked, and what is not

| Checked | Not checked |
|---|---|
| `write_file` | `write_memory`, because a note an agent keeps is not the project's source |
| `edit_file`, against the content the edit would leave behind | a file no grammar of this project covers |
| | a file a person edits, because Chock gates the agent and not the person |
| | a file changed by `run_command`, because the program writes through its own file descriptors |

The content is checked, not the file on disk, so an edit is measured against
what it would leave behind and not against what was there.

A style rule is a pre-write guard on structured model output. It is not a
repository invariant: Chock cannot refuse a program's write before that
program makes it, and rolling a command's arbitrary filesystem effects back
afterward would be a different transaction model. Formatters, compiler checks,
hooks, and CI remain the right controls for `run_command` and human writes.

## A check that cannot finish refuses

A parser that fails, a parser that runs out of time, and a query file that
cannot be read all refuse the write. A write Chock could not check is a write
it will not make, and zero matches would otherwise read as a file that breaks
no rule.

A grammar this host has not got is the one case that does not refuse. The rule
did not run, the write goes ahead, and the `style.check` row says `no_parser`.
That is a setup this host is missing rather than a check that failed, and a
missing grammar would otherwise stop every write of that language.

The two parsers differ after a timeout. The command runs once a parse, so a
timeout costs that one write. The wasm parser is one process a session, and a
check it gave up on is still being worked on inside it, so a timeout stops
that parser for the rest of the session and every write after it is refused by
name. A parse that cannot finish in ten seconds is doing something no file in
this repository does.

## The parsers directory

`parsers` names an environment variable and never a path, because the paths
change between setups. The shell exports it, and Chock looks under it for one
file a language:

```
$TREE_SITTER_PARSERS/zig.so
```

Chock's own dev shell builds that directory from nixpkgs and exports the
variable. A project sets it up for its own shell, because a store path in
`chock.zon` would change every time the grammar package is bumped. A variable
that names no directory turns the rules off for the session and says so, and a
directory with no file for one language leaves that language unchecked.

## The parser runs in the sandbox

The parser is a program, and it runs where `cat` and `grep` run: the staged
source, the query and an empty configuration file are bound read only, the
grammar directory is bound read only, and nothing of anybody's home directory
decides which grammar answers. The command is given `--config-path`,
`--lib-path` and `--lang-name`, so it reads no configuration of its own.

## Whether a rule runs at all

One action covers the whole block:

```zon
.{ .action = "style.parse", .decision = .allow }
```

Chock ships no default for it, so a project that writes rules writes this rule
too. Anything other than `allow` turns the rules off for the session and says
so in one line, naming the decision and the action.

## What the log holds

Each rule that ran appends a `style.check` event:

```json
{"kind":"style.check","rule":"comment-block","path":"src/main.zig","language":"zig","count":1,"line":1,"outcome":"refused"}
```

`outcome` is `permitted`, `refused`, `reported`, `no_parser`, `no_answer` or
`no_query`.
The query text and the matched source are not in the event: the rule's name
says which query ran, and the matched text is the file itself. `chock sessions
show` prints a line for each.

## Bounds this has

| Limit | Value |
|---|---|
| Rules in a block | 32 |
| Grammars in a block | 16 |
| Extensions a grammar | 8 |
| Matches a query may answer with | 4096, and more is a refusal |
| A query file | 64KB |
| A file that is parsed | 1MB |

## The other engine

The `engine` key picks the parser. `command` is the default and runs
`tree-sitter` as a program. `wasm` runs a parser compiled to WebAssembly
inside Chock's own engine, which needs no `tree-sitter` on the host:

```zon
.style = .{
    .engine = "wasm",
    .grammars = .{ .{ .language = "zig", .extensions = .{".zig"} } },
    .rules = .{ .{ .name = "comment-block", .query = ".chock/style/comment.scm", .max_lines = 10 } },
}
```

A rule means the same thing whichever parser answered it. One test puts both
over one file, with the same rules, and fails when the two answers differ.

Three things about this engine are worth knowing before turning it on.

**The first write waits.** The engine compiles every function in the module
before the first answer, which is about half a minute on the machine this was
built on, and the module holds 269 functions. The cost is paid once a session,
because the parser is one process that stays alive, so later writes are
answered in milliseconds. A write that arrives during the wait waits with it.

**One language a session.** A module carries tree-sitter's runtime plus one
grammar. `modules` names an environment variable holding a directory of
`<language>.wasm` files, and the session takes the first grammar this project
names that has one. A language with no module is a rule that did not run: that
write is not checked, it is not refused, the `style.check` row says
`no_parser`, and the session says so once. The command engine covers every
grammar under its own directory, so a project with rules for several languages
wants that one.

**The module is built on its own.** Chock's dev shell builds it from nixpkgs
and exports `CHOCK_PARSER_MODULES`. A variable that names no directory, or a
directory with a module for none of the project's grammars, turns the rules
off for the session and says which.

The parser runs in the same sandbox the command runs in, started the way a
plugin host is started: Chock itself and the module are each bound read only
at one path, and the parse has no network and no other file. A host needs a
sandbox of its own, and macOS has none that nests, so this engine is Linux
only and a Mac takes the command. The session says so at the start.
