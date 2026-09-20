# An organisation above a project

`chock.zon` is written by the developer who owns the directory. An organisation
decides once and every project receives, so the outermost layer cannot be a
file inside the thing it is meant to bound.

An org policy bundle is that outer layer. It lives in the data directory,
written by whatever installed Chock and beyond the reach of the project.
`chock run --org-bundle <path>` reads one instead.

It is the same ratchet one level up, with the same arithmetic and no second
policy system:

- A bundle holds the same rules, with the same four key fields, the same dotted
  patterns, and the same rule that wins. [policy.md](policy.md) has all three.
- The bundle is folded in as one more term of the same minimum.
- A rule of `chock.zon` can lower an answer and can never raise one.

That last line is why `sandbox.jit` is a policy row rather than a key in
`chock.zon`. One rule in the bundle,
`.{ .action = "sandbox.jit", .decision = .deny }`, forbids the sandbox
hardening being given up in every project of the installation, and no project
can take that back. [actions.md](actions.md) has that row and every other one.

A bundle is read as a ceiling and never as a decision. An action no bundle rule
names answers `allow`, which is no ceiling at all, and not `ask`, which is what
`chock.zon` answers for an action nobody named.

Chock builds no identity system. The organisation issues the credential, so the
hub that issued it already knows who the subject is. The bundle travels with
the credential and states that subject. Chock reads it and never checks it: a
bundle is trusted exactly as far as the file it was written into. The subject
is a record, so a session log says whose credential the session ran under, and
it is not a control.

An expired bundle keeps binding, in full and for ever, and it is said out loud
on every start. A bundle only narrows, so dropping an expired one can only
widen. A bundle that has already expired when it is first given to Chock is
refused instead.

A bundle can also require an audit sink. A session whose required sink still
held none of the tail of the log at the end exits `9`, which is a status and
never a refusal to run. The exit codes are in [running.md](../running.md).

## The ceilings that are fields and not rules

Some things a project sets are numbers rather than decisions, and a rule cannot
narrow a number. A bundle therefore carries four blocks of its own:

- `budget` sets the most a session of this installation may spend. A project
  that asks for more is refused when it starts, and both numbers are in what
  the person reads. It is not lowered quietly, because a session that ran at
  the lower number would stop in the middle of the work with nothing said about
  why.
- `subagents` sets the largest spawn tree any project may ask for, with
  `max_depth` and `max_width`. Each is optional on its own. A project above
  either one is held to the bundle's number and is not refused, because a spawn
  this stops says so at the moment it happens. The message names the bundle as
  the source, so nobody is sent to edit a `chock.zon` that does not hold that
  limit.
- `limits` sets the most a sandboxed program of this installation may use: how
  many processes and threads, and how much resident memory.
  [Sandbox resource limits](#sandbox-resource-limits) below has the block
  itself. A project above the bundle's number is held to it and is not refused,
  because `/proc/meminfo` reports the whole machine and `/sys/fs/cgroup` is
  hidden from the program the limit bounds, so a project this narrows has no
  way to see the cap from inside its own sandbox. `chock doctor` reports the
  ceiling, resolved against the machine it runs on.
- `nix` sets the most a session of this installation may add to the Nix store:
  how large one object may be, and how much a whole session may add in total.
  [Nix store byte caps](#nix-store-byte-caps) below has the block itself. A
  project above the bundle's number is held to it and is not refused.

## Sandbox resource limits

A `limits` block in `chock.zon` sets how many processes and threads, and how
much resident memory, one tool call's sandbox may use:

```zon
.{
    .limits = .{
        .processes = "50%",
        .memory = "4GiB",
    },
}
```

Either field takes a percentage of what the machine has, or an absolute value.
`processes` resolves a percentage against this machine's own cpu count, and
`memory` resolves one against its total memory. A percentage above 100 is
refused when the file is read, with a message that names the field. An absolute
value is a bare number, or a number with a unit this reader knows: `B`, `KiB`,
`MiB`, `GiB`, `TiB`. `.processes = 300` and `.processes = "300"` say the same
thing, and a bare number needs no quotes.

Chock's own default is sized to the machine rather than one fixed number for
every machine. An ordinary 8 cpu, 16 GiB machine gets 256 processes and 2 GiB.
A 128 cpu machine gets 1024 processes with nothing configured at all.

A project's own block wins over that default, and an operator's own default
wins over Chock's. `~/.config/chock/config.zon` takes the same `limits` block,
in the same shape, and sets the machine's own default. The order, from the
number a session actually uses back to where it may have come from:

1. The project's own `chock.zon`, if it names the field.
2. The operator's own `config.zon`, if it names the field and the project did
   not.
3. Chock's own machine sized default, if neither did.
4. The org policy bundle's own `limits` ceiling, over whichever of the above
   won, if the bundle sets one. See
   [The ceilings that are fields and not rules](#the-ceilings-that-are-fields-and-not-rules).

A misspelled field inside a `limits` block, in either file, is refused rather
than read as the default: `.{ .limits = .{ .procceses = "50%" } }` stops the
file being read, the same rule every other block in `chock.zon` keeps.

The numbers this fold answers are what every tool call of the session runs
under. `chock run` reads the two files once, before the first call, and writes
the result into the sandbox it builds. A session the org ceiling lowered says
so on its own output, once, with the number it was held to, because the program
the number bounds cannot read it from inside the sandbox.

## Nix store byte caps

A `nix` block in `chock.zon` sets how much a Nix evaluation may add to the
store:

```zon
.{
    .nix = .{
        .max_object_bytes = "16MiB",
        .max_session_bytes = "256MiB",
    },
}
```

`max_object_bytes` bounds one object the store accepts: a Nix source file, a
derivation, or a build output. It is checked against
`chock_nix.backend.Driver` before the object reaches a store at all.
`max_session_bytes` bounds the total a whole session may add across every
object, and every build of one session spends against the same number. A build
whose derivation would pass it is refused while it is being written, so nothing
is built.

Neither field takes a percentage, because a store object has no quantity on the
machine to be a share of. A percentage here is refused when the file is read,
with a message that says why. Each field is a bare number, or a number with a
unit this reader knows: `B`, `KiB`, `MiB`, `GiB`, `TiB`.

The fold is the same order `limits` uses:

1. The project's own `chock.zon`, if it names the field.
2. The operator's own `config.zon`, if it names the field and the project did
   not.
3. Chock's own built in default, if neither did.
4. The org policy bundle's own `nix` ceiling, over whichever of the above won,
   if the bundle sets one. See
   [The ceilings that are fields and not rules](#the-ceilings-that-are-fields-and-not-rules).

A misspelled field inside a `nix` block, in either file, is refused rather than
read as the default, the same rule `limits` keeps.
