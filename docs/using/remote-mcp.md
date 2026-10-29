# A remote MCP server

An MCP server supplies tools the model can call. Chock runs one itself, as a
program in the sandbox, and it reaches one over HTTP:

```zon
.{
    .mcp_servers = .{
        .{ .name = "notion", .url = "https://mcp.notion.com/mcp" },
        .{ .name = "time", .command = .{ "mcp-server-time" } },
    },
}
```

An entry names a `command` or a `url`, and never both. The first is a server
this host runs. The second is a server somebody else runs, which Chock reaches
over the streamable HTTP transport.

The rules above a remote server's tools are the rules above a local one's. A
tool goes on the policy table as `mcp.<server>.tool.<name>`, a tool whose name
is one of Chock's own keeps the whole server out of the session, a result is
untrusted text, and a server cannot add a tool once the session has started.
[actions.md](../configure/actions.md) has the keys.

## The three rules

| Rule | Says |
|---|---|
| `mcp.<server>.host.<host>` | Chock may reach that host for that server |
| `mcp.<server>.tool.<name>` | the model may call that tool |
| `secret.use.<name>` | that credential may reach that server |

The host is written last label first, so a rule about a domain is a rule about
every name under it:

```zon
.{ .action = "mcp.notion.host.com.notion.*", .decision = .allow },
```

That is the same shape `net.fetch.<host>` takes, built by the same code, so one
host reads one way wherever it appears in a rule.

**Only `allow` reaches a host.** A server starts before the first turn, when
there is nobody to put a question to, so `ask` refuses and says which rule
would have permitted it. The server is then left out of the session and the
model is never offered its tools.

The host rule alone gets a tool list. A tool rule is needed on top of it before
the model may call anything, so a project can look at what a server offers
without granting the use of any of it.

`mcp.<server>.network` is about a server this host runs reaching the network
from inside its sandbox. It says nothing about a remote server, where the
destination rule is the one that matters.

## The credential

A remote server usually wants a token. It goes in the `secrets` block, which is
the same block that gives a tool call a secret, with the bind that means a
request header:

```zon
.{
    .secrets = .{
        .{ .name = "NOTION_TOKEN", .to = "mcp.notion.*", .bind = "header" },
    },
}
```

The value goes in the credential store, never in the file:

```
chock login --tool-secret NOTION_TOKEN
```

Every use is still asked under `secret.use.NOTION_TOKEN`, and the log records
it. [secrets.md](../configure/secrets.md) has the block in full.

`Authorization` carries `Bearer ` before the value, because that is what the
scheme means. A server that wants its own header names it, and that header
carries the value by itself:

```zon
.{ .name = "KEY", .to = "mcp.probe.*", .bind = "header", .as = "X-Api-Key" },
```

The credential is read once, before the first request. A refused or missing one
drops the server with a line saying why, rather than failing a call later in
the turn. A credential holding a byte a header cannot carry, such as a line
break, is not sent at all: the server starts without it.

The model never sees the value. It is held by Chock and not by the sandbox, it
is masked in everything the session writes, and no event of the log carries it.

## What the log records

Each exchange appends one `mcp.request`, beside the ordinary `tool.call` and
`tool.result` for the call itself:

```json
{"kind":"mcp.request","server":"notion","host":"mcp.notion.com","about":"search","status":200,"outcome":"answered"}
```

`about` is the tool the call was about, or `discover` for the one exchange that
reads a server's tool list. `outcome` is `answered`, `refused_by_policy`,
`refused_by_address`, `redirected` or `no_answer`. `chock sessions show` prints
a line for each.

## What it does when something goes wrong

| Case | What happens |
|---|---|
| The session times out | 10 seconds to read a server's tools and 60 seconds a call, the budgets a local server has |
| A session the server dropped | a 404 opens a session again and puts the question once more. Twice is a server that holds no session, and the call fails |
| The stream ends early | the call fails and says so. A reply that did not arrive is never a half answer handed to the model |
| The server will not stop sending | refused at the reply bound, which is a megabyte, so a server cannot stream the context away |
| The server asks Chock for something | counted and never answered. Sampling, elicitation and a changed tool list reach no session |
| The server redirects | refused. An endpoint is configuration, not a page somebody asked to read |
| A proxy is set in the environment | none is ever configured, and the connection is pinned to an address that was checked, so a proxy variable cannot move it |

A host that resolves onto this machine is refused whatever a policy says about
the name: the loopback interface, the cloud metadata address and the
unspecified address. Every address a name answers with is checked, and a name
answering more addresses than Chock checks is a refusal rather than a
truncation.

## What this does not do

- **No OAuth.** Chock carries a token from the credential store and runs no
  browser flow. A server that answers 401 is reported, and the specification
  makes authorization optional, so a token is a legal way to hold one.
- **No listening stream.** Chock opens no long-lived GET, because every message
  such a stream can carry is one the harness refuses or counts.
- **No server on this machine.** The address check refuses loopback, so a
  server you run yourself is a `command` and not a `url`.
- **No plain `http`.** A credential and a tool result must not cross a network
  in the clear.
- **No cap of its own.** The bounds are the ones a local server has: eight
  servers in a session, and sixty four declarations from each of them.

A reply is read by Chock itself, in the process that holds the credentials,
which is where the provider client and `fetch_url` already read theirs. A
hostile server reaches a JSON reader there and nothing else: it has no tool, no
path and no process in the session.
