# Plugins

Tools you supply yourself, as WebAssembly. A `plugins` block in `chock.zon`
names a module and what this project calls it:

```zon
.{
    .plugins = .{
        .{ .name = "hello", .module = "plugins/chock-plugin-hello.wasm" },
    },
}
```

Every tool the module declares lands on the policy table under
`plugin.<plugin>.tool.<tool>`, beside every other rule you write, so a plugin
tool reaches the model only when a rule says so:

```zon
.{ .action = "plugin.hello.tool.*", .decision = .allow },
```

Only `deny` keeps a tool out of the session. Every other decision leaves
the tool offered and puts the question to the same broker every other approval
in Chock goes through, once per call, so `ask` reaches a person and
`agent_review` reaches a reviewer rather than reading as a silent refusal. A
promise the session makes with `restrict_self` after the plugin loaded binds
the very next call.

The name is yours and never the plugin's. A plugin states its own name in its
metadata, and Chock builds every rule out of the name you wrote, so a plugin
cannot choose which rules apply to it. A tool that declares a capability, such
as `fs.read`, is priced against that action as well, and it is asked about on
every call too. A capability has to be `allow` outright, and anything short of
that keeps the tool out of the session: the capabilities of every offered tool
decide the set of host functions the whole plugin is built with, once, before
any guest code runs, and one supplied that way cannot be taken back. A plugin
whose tool is named after one of Chock's own tools is not loaded at all, none
of its other tools included.

The tool list, the capabilities and the decisions are all read out of the
module's own file with no engine, before any of it runs. A plugin whose tools
are never called starts no process. The first call starts one, and it is a
sandbox of its own with no network. It reads three things, and all three read
only: the `chock` program that hosts it, its own module, and the toolchain the
session runs under. It reaches neither the project nor the workspace.

## Writing one

`plugins/hello.zig` is a whole plugin, and `lib/chock-plugin-sdk` is what an
author imports.

A tool declares a Zig type for its arguments and the SDK lowers it into a
schema the metadata carries, so the model sees field names and kinds rather
than a free text box. The host refuses a tool whose schema is too large or
names a field it will not show a model, instead of offering it with an empty
one.
