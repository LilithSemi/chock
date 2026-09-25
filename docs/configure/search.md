# Web search

An agent that can read a page it was given a link to still cannot find the
link. The `web_search` tool is how it looks something up, and this page is how
you say which engine answers.

## The engine is yours, so it is named in your own file

The search block goes in `~/.config/chock/config.zon`, beside your provider
instances, and never in a project's `chock.zon`.

```zon
.{
    .providers = .{
        .{ .name = "local", .kind = "openai-compat", .base_url = "http://127.0.0.1:5000/v1" },
    },
    .search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org" },
}
```

The split is the same one the providers already keep.
[configuration.md](configuration.md) has it in full: your file says where Chock
talks to, and the project's file says what an agent may do there. A search
engine is your own infrastructure, so a repository you cloned this morning does
not get to name it.

There is no project layer to fold in. A `search` block in a `chock.zon` is not
read.

## The kinds

| Kind | What it talks to | State |
|---|---|---|
| `self_hosted` | a SearXNG instance of your own | built |
| `api` | a keyed vendor | built, Brave and Kagi |
| `scrape` | a results page, read as HTML | not built |

Leave the block out and the tool is still offered. It answers that no engine is
configured and says which file sets one, because "no engine" and "no results"
must not read the same to an agent.

### self_hosted

```zon
.search = .{ .kind = "self_hosted", .base_url = "https://searx.example.org" }
```

Chock calls `GET {base_url}/search?q=...&format=json`.

**SearXNG answers 403 to that until you turn JSON on.** The format is off by
default. Add it to `settings.yml`:

```yaml
search:
  formats:
    - html
    - json
```

Chock names this setting whenever a reply does not parse, because an instance
that will not speak JSON and a query that found nothing otherwise read alike.

An `http` base URL is refused unless the host is loopback. A search query says
what somebody is working on, and in the clear it says it to every hop on the
way.

### api

```zon
.search = .{
    .kind = "api",
    .provider = "brave",
    .base_url = "https://api.search.brave.com",
    .credential = "brave",
}
```

`provider` names the vendor. A keyed vendor answers in its own shape under its
own field names, so the kind alone does not say enough to read a reply, and a
reader that guessed would hand the agent zero results rather than an error.
`brave` and `kagi` are the values today.

`credential` is a **name in the credential store**, never the key itself. A
`key`, `token`, `api_key` or `secret` field in this block is refused by name.

Put the key in the store with:

```
chock login --search brave
```

The name you pass is the name the block reads it under. There is no option that
takes the key on the command line, for the reason
[configuration.md](configuration.md) gives for a provider: a command line is
visible through `ps` and it lands in your shell history.

Unlike a provider login, this one does not ask the engine whether the key
works. A provider credential that does not work ends a session before it
starts. A search key that does not work costs one tool call, which comes back
naming the status the engine answered with.

Brave bounds a query to 600 characters and 75 words. Chock refuses a longer one
before the request, and says which bound was passed, so the agent can shorten
the query rather than read a 422.

Kagi is configured the same way, with its own base URL:

```zon
.search = .{
    .kind = "api",
    .provider = "kagi",
    .base_url = "https://kagi.com/api/v1",
    .credential = "kagi",
}
```

**Kagi's own documentation disagrees with itself about the credential header.**
Its API specification says `Authorization: Bearer`, and two of its help pages
say the literal word `Bot`. This build sends `Bearer`, which the specification
and the quick-start page both show. If Kagi answers 401 on a key you know is
good, that disagreement is the first thing to suspect, and the refusal message
says so.

Kagi bills per search, and a spent balance answers with the same 429 a rate
limit does, so the refusal names both causes.

A title or snippet from Kagi can hold HTML entities such as `&#39;`, because
Kagi sends them and documents no way to turn them off. They reach the agent as
written. Chock does not decode them: undoing markup that may not be there would
corrupt a snippet that legitimately holds one.

### scrape

Not built. It is in the kind list because an organisation may want to forbid it
before it exists.

It will never be the default, and not on principle. A results page changes
shape without notice, so a scraper works until it quietly does not, and the
failure reads to an agent as "the web has nothing about this". Of the four
harnesses read while this was designed, the one that scrapes needed a headless
browser with stealth patches to keep it working.

## Asking before it searches

`web.search` ships as `ask`, and the question reaches you **at the tool call**,
while the agent waits. [actions.md](actions.md) has every action name and what
ships with it.

That timing is the whole reason it can be `ask` at all. Three actions are read
before the work they govern, when nobody is waiting, and for those an `ask`
means "never". `web.search` is not one of them.

Allow it outright in a project that does a lot of reading:

```zon
.{ .policy = .{ .rules = .{ .{ .action = "web.search", .decision = "allow" } } } }
```

The engine's own host is not gated separately. You chose the engine, so a
project does not have to name it in `net.fetch`.

## Reading a result

A search gives back a title, a URL, and a bounded snippet, at most 8 results. It
never gives back page text: reading a page stays `fetch_url`'s job, which is
what keeps reachability a decision made outside the sandbox.

Results are marked as text a stranger wrote, and they go through the same
cleaning a fetched page does. **A ranked list is more attacker shaped than an
ordinary page**, because whoever ranks decides what the agent reads first. That
you chose the engine says something about where the bytes come from and nothing
about who wrote them.

A result the agent then wants to read is a `net.fetch` on a host your policy
probably does not name. Chock asks you about that host, once, for the host the
agent named. Every redirect after it keeps the ordinary refusal.
[approvals.md](../using/approvals.md) says why the scope stops there.

## Pinning it for an installation

An org policy bundle narrows what a user may choose, and never widens it:

```zon
.{
    .search = .{
        .kinds = .{ .self_hosted, .api },
        .base_url = "https://searx.corp.example",
    },
}
```

`kinds` is the set a user may pick from, so the bundle above forbids `scrape`.
`base_url` pins the exact address. Either one is a refusal and never a silent
narrowing: a kind and an address are categorical, so a user config that names
one the bundle excludes is refused when the session starts, with the reason.
[org.md](org.md) has the rest of the bundle.
