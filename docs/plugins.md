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

**The name is yours and never the plugin's.** A plugin states its own name in
its metadata, and Chock builds every rule out of the name you wrote, so a
plugin cannot choose which rules apply to it. A tool that declares a
capability, such as `fs.read`, is priced against that action as well, and one
capability your project denies is enough to keep the tool out of the session.
A plugin whose tool is named after one of Chock's own tools is **not loaded at
all**, none of its other tools included.

The tool list, the capabilities and the decisions are all read out of the
module's own file with no engine, before any of it runs. A plugin whose tools
are never called starts no process. The first call starts one, and it is a
sandbox of its own with no network and no path but its own module.

## Writing one

`plugins/hello.zig` is a whole plugin, and `lib/chock-plugin-sdk` is what an
author imports.

Argument lowering is not built yet. A tool reads the model's argument text as
text, every offered plugin tool carries the empty schema, and the SDK refuses
to compile a tool that declares an argument type with fields, so the gap is
loud rather than a silently wrong read. See [status.md](status.md).
