# Chock service

`chock daemon` starts Chock's session-owning process. Run without OIDC and
multi-user configuration, it serves the user who launched it; that setup is
called the daemon. When configured for multi-user access, the deployment is
called the Chock service. The service may delegate authentication to an OIDC
provider or manage its own user accounts. Both use the `chock daemon` command;
the configured access model determines the term used here.

## Sources of truth

The append-only Chock log remains the ordered transcript and audit record for
one session. Quarry-backed SQL stores facts that span logs:

- an identity with a daemon-owned UUID, optionally linked to an exact OIDC
  issuer and subject;
- a project registered and provisioned through the daemon;
- a session's owner and its owner, editor, and viewer memberships;
- whether a registered session is assigned to client or daemon placement; and
- the generation and expiry of an owner-controlled execution-host lease.

The first schema is portable across SQLite and PostgreSQL. A personal daemon
can keep an embedded SQLite database in its state directory. A hosted daemon
can use PostgreSQL without changing its repository or authorization rules.
`chock daemon` opens `<state directory>/daemon.sqlite` by default. A hosted
deployment selects another Quarry database with `--database <url>` or
`CHOCK_DATABASE_URL`; an explicit command-line value wins over the environment.

## Telemetry

OpenTelemetry export is disabled unless `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is set. Chock exports its standard log
records, a process-start event, and low-cardinality events for session creation,
queued turns, project provisioning and status, provider configuration, ACL
changes, team creation, invitation lifecycle, membership changes, and
execution-host lease transitions, and successful sign-ins. Lifecycle attributes
are limited to bounded categories such as authentication mode, placement,
project source/status, provider scope, access resource/capability/effect,
membership resource/action/role, and invitation role. They do not include
account, team, project, session, provider, or invitation identifiers, repository
URLs, provider names, credential values, invitation bearers, or prompt text. A
panic also makes a best-effort fatal
exception event before the normal crash report.
Set `OTEL_SDK_DISABLED=true` to disable export even when an endpoint is set.

The collector receives Chock's log messages and panic text, which can contain
operational details. Configure an endpoint trusted to receive those records;
telemetry does not replace the session log or database audit history. Normal
shutdown drains the batch processor, while crash export is best-effort and
limited to a short timeout.

## Authentication

The service has two mutually exclusive account modes: an external OIDC
provider, or accounts managed by Chock. In either mode, the service owns local
UUID identities, memberships, ACLs, and authorization decisions. OIDC uses the
provider's exact `(issuer, sub)` pair as the stable external identity; a
service-managed account uses its locally assigned UUID. Email and display name
are profile attributes, never authorization keys. The web gateway offers a
first-run page for creating the initial local administrator when no OIDC
provider or prior identity has been configured. Setup is one-time, passwords
are stored as Argon2id PHC hashes, and sign-in creates the same opaque
daemon-owned session used by the OIDC path. Instance administrators can add
member accounts from the People screen; each receives a UUID identity and no
access until teams or ACLs grant it. The setup endpoint refuses requests after
initialization. Administrators can set a temporary password or disable a local
account from People; both operations revoke current credentials, while
disabling retains the identity and history. A signed-in local account can
change its own password from Account settings; the current browser remains
signed in while other browser and worker credentials are revoked. OIDC account
credentials remain managed by the identity provider.

Kanidm, Authentik, and Authelia are OpenID Connect providers, not three bespoke
authentication implementations. `oauth.zig` performs discovery and verifies
the ID token against the discovered issuer, audience, nonce, expiry, and JWKS.
Authentik may name an application-specific discovery URL; the advertised
issuer must still exactly match the configured issuer.

OIDC issuer, discovery, and metadata endpoints require HTTPS. This matches the
OAuth transport's URL checks; loopback HTTP is supported only for the
browser-facing `CHOCK_EXTERNAL_URL` during local development. OIDC discovery,
token exchange, and signing-key requests use the host's configured TLS trust
store, so private identity-provider CAs must be installed in the service host's
system trust configuration. On NixOS the service reads `security.pki.caBundle`;
on other systems it also honors `SSL_CERT_FILE` before scanning native roots.
The stable local identity is `(issuer, sub)`;
email and display name are attributes and never authorization keys.
Daemon-internal records use random UUIDs as local identifiers; the unique
`(issuer, sub)` pair maps each external account to its local UUID and remains
the only identity-linking key.
Browser login sessions are opaque random bearers: only a SHA-256 digest is
stored, and the daemon checks expiry and revocation on resolution. The raw
bearer belongs in an HttpOnly cookie, never in Phantom's ordinary settings or
the Quarry database. State-changing cookie-authenticated requests must carry the
same browser origin as `CHOCK_EXTERNAL_URL`; mismatched or cross-site origins
are rejected before logout or an application mutation is handled. Bearer-only
client-worker requests remain a separate credential path.
`--host` is only the network bind address; `--external-url` is the exact
browser-facing origin (scheme, host, and port), including the reverse proxy's
public address when one is used. Never use a wildcard bind such as
`https://0.0.0.0:7474` as the external URL: browsers connect using the public
hostname, so setup and sign-in mutations will be rejected as an origin
mismatch. For example, if people open `https://chock.example/`, use
`--host 0.0.0.0 --external-url https://chock.example`.

Cleartext HTTP external URLs are accepted only for loopback by default. An
operator may explicitly pass `--allow-http` to `chock serve` when the
browser-facing URL itself is intentionally HTTP on a trusted private network.
This opt-in permits non-loopback HTTP origins for
browser origin checks and OIDC callbacks; it does not add transport security.
Without HTTPS, session cookies are not marked `Secure`, credentials and
session tokens can be observed or modified in transit, and OIDC authorization
codes/callbacks are exposed (and an identity provider may refuse a non-HTTPS
redirect URI). Do not use it on an untrusted network. When TLS terminates at a
reverse proxy, configure the browser-facing `https://` URL; HTTP between that
proxy and the local Unix socket does not need this option. The NixOS
module exposes the same opt-in as
`services.chock-daemon.web.allowHttp = true`.

Configure `chock daemon` with the `CHOCK_OIDC_PROVIDER`, `CHOCK_OIDC_ISSUER`,
and `CHOCK_OIDC_CLIENT_ID` environment variables. `chock serve` needs only the
public `CHOCK_EXTERNAL_URL` (or `--external-url`) to establish the callback
URI; it does not need provider configuration or a client secret. For a
confidential client, set
`CHOCK_OIDC_CLIENT_SECRET` only in the daemon's protected environment file; it
is used by the daemon during the authorization-code token exchange and is
never sent to the browser, gateway, or stored in Quarry. Without it, the daemon
uses a public PKCE client. `CHOCK_OIDC_DISCOVERY_URL` optionally supports
provider-specific metadata paths. The
daemon validates the provider name and issuer, then discovers and checks the
advertised issuer at startup. Issuers and metadata URLs require HTTPS;
lookalike hostnames, malformed hostnames, and URL user-info are refused. The
browser-facing external URL may use HTTP only on exact `localhost`,
`127.0.0.1`, or `[::1]` hosts during local development.
Set `--oidc-admin-subject` / `CHOCK_OIDC_ADMIN_SUBJECT` to the exact `sub` of
the operator who should receive the initial instance-admin role. This is an
explicit OIDC bootstrap mapping, never an email or provider-group mapping; the
role is persisted locally and profile updates cannot grant or remove it.

### Register an OIDC client

Register a dedicated web client with the identity provider. Set its exact
redirect URI to `<CHOCK_EXTERNAL_URL>/auth/callback` (one trailing slash is
removed when Chock builds the callback), enable the authorization-code grant,
and require PKCE with `S256`. Do not use an implicit grant or a wildcard
redirect. Chock requests `openid profile email`; profile and email claims are
optional attributes, not access grants. The provider authenticates people;
Chock teams and ACL rules still decide what each authenticated person may do.

For environment-configured OIDC, set the provider name, issuer, client ID, and
optional discovery URL on `chock daemon`; `chock serve` needs only the external
callback origin. The first-run setup in the Phantom web application can instead
send provider configuration to the daemon, which persists it in private state
after validating discovery. The daemon alone performs the back-channel token
exchange and ID-token verification. Keep environment-configured client
secrets in a protected daemon environment file or secret manager, not in Nix
source, the gateway environment, the database, or browser settings. A public
PKCE client may omit the secret.

- **Kanidm:** create a dedicated OAuth2 client, add the exact callback URI, and
  grant the `openid` scope (plus `profile` and `email` when those attributes
  should be provided). Kanidm uses a client-specific issuer:
  `https://<kanidm-host>/oauth2/openid/<client-id>`. Use that exact issuer and
  leave the discovery override unset unless the deployment serves metadata at
  a nonstandard location. The Kanidm client must support PKCE `S256` and an
  ID-token signing algorithm accepted by its OIDC metadata. See the
  [Kanidm OAuth2 client guide](https://kanidm.github.io/kanidm/stable/integrations/oauth2.html).
- **Authentik:** create an OAuth2/OpenID Connect provider and application,
  select the authorization-code grant and a signing key, then add the exact
  callback as a strict authorization redirect URI. With authentik's usual
  per-provider issuer mode, set issuer to
  `https://<authentik-host>/application/o/<application-slug>/` and set
  `CHOCK_OIDC_DISCOVERY_URL` to
  `https://<authentik-host>/application/o/<application-slug>/.well-known/openid-configuration`.
  The discovered `issuer` must exactly equal the configured issuer. See
  authentik's [provider setup](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/create-oauth2-provider/)
  and [issuer-mode reference](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).
- **Authelia:** register a dedicated OIDC client with the exact callback URI,
  authorization-code grant, and `code` response type. Use the Authelia
  issuer (the public URL of its OIDC provider) and the standard discovery URL
  `<issuer>/.well-known/openid-configuration`. For a confidential client,
  store the configured client secret using the format Authelia expects; for a
  public client, configure it as public and omit Chock's client secret. See
  Authelia's [OIDC client configuration](https://www.authelia.com/configuration/identity-providers/openid-connect/clients/)
  and [discovery endpoints](https://www.authelia.com/integration/openid-connect/introduction/).

After the client is registered, configure `CHOCK_OIDC_PROVIDER`,
`CHOCK_OIDC_ISSUER`, and `CHOCK_OIDC_CLIENT_ID` on the daemon. Add
`CHOCK_OIDC_DISCOVERY_URL` there for Authentik's application-specific discovery
path. Put `CHOCK_OIDC_CLIENT_SECRET` only in the daemon's protected environment
file for confidential clients, and set `CHOCK_EXTERNAL_URL` on the browser
gateway. Set `CHOCK_OIDC_ADMIN_SUBJECT` on the daemon explicitly
before first sign-in. Exact discovery issuer matching is intentional: do not
“fix” a mismatch by weakening issuer verification.

With OIDC, `chock serve` asks the daemon to start login and handles only the
browser redirect/callback and cookies; the daemon creates the authorization
URL, retains state/nonce/PKCE material, then exchanges the callback code and
verifies the ID token. Set `CHOCK_EXTERNAL_URL` (or `--external-url`) to the
public base URL and register `<base>/auth/callback` with the provider. Use
HTTPS outside loopback. Each browser attempt uses state, nonce, and PKCE; state
is bound to a short-lived HttpOnly cookie and is validated/consumed by the
daemon. With local accounts, `/setup` opens Phantom's first-run form to create
the initial administrator and `/auth/login` opens Phantom's sign-in form for
subsequent users.
The resulting daemon session is in an HttpOnly cookie, not Phantom settings.
The gateway must reach the daemon over its restricted Unix socket. In the
NixOS module, the separate `chock-web` user receives access through the
configured Chock service group; ordinary local users do not. Binding
`chock serve` to TCP with `--host` requires an explicit `CHOCK_EXTERNAL_URL`
(HTTPS except on loopback, unless `--allow-http` is explicitly set), whether authentication is local or OIDC; the
gateway checks browser mutation origins against it. Keep the daemon's control
listener on its restricted Unix socket, accessible to the daemon owner and
explicitly configured service group.

The gateway asks the daemon which authentication mode is in force. Only the
daemon's own answer `single-user`, which is a daemon with no database, turns
gateway authentication off; every other answer turns it on. A gateway that
cannot read the mode, or that gets a word it does not know, stops and says so
rather than serve without authentication. While it is serving without
authentication it asks again at most once every two seconds, so a daemon that
later gains a database does not leave an open gateway behind it.

When OIDC or local service accounts are enabled, app pages and API routes
resolve the session cookie through the daemon; invalid sessions are rejected and
`/auth/logout` revokes the session. Each route requests its project/session
capability from the daemon's ACL evaluator. Project ACLs use daemon-owned UUIDs;
the local execution root is a locator mapped to that UUID and is not the
project's authorization identity. Session records still use the existing
transcript session IDs. The Teams route supports creation and owner-managed
membership. The authenticated `/api/acl-rules` endpoint lists, replaces, and
removes rules for a resource; the daemon verifies resource-management
permission and validates UUID-backed principals. The Teams screen edits
team-management rules, and each registered project now has an **Access rules**
view for project-level grants and denies. Project rules also affect sessions
bound to that project. Provider records also have an **Access rules** view for
`provider_use` and `provider_manage`. Session owners can also manage
session-scoped grants and denies from the Share view, alongside membership.
The Share view also offers a per-session transcript download at
`GET /api/export/session?session=<session-id>`. It requires `session_view`,
returns a versioned JSON envelope of ordered log events, and refuses exports
over 8 MiB or at 100,000 events rather than returning a possibly partial file. This is a
transcript export; it does not include project files, provider credentials, or
identity-provider credentials. The Projects screen also offers
`GET /api/export/account`, a portable JSON bundle of project metadata visible to
the requester and complete transcripts for every session they can view. Both
exports refuse oversized or incomplete data rather than returning a partial
archive. The account bundle is limited to 32 MiB, 200,000 events, and 10,000
session records; each included transcript must also fit the single-session
limit. It is a point-in-time read, not a cross-database snapshot, and does not
include instance-wide identity, team, or ACL records.
An unverified identity header is never accepted directly from a network
client. The raw TCP control listener must not remain anonymously reachable
when remote multi-user access is enabled.

The control protocol remains version 1. Its additive login/session/authorization
verbs are accepted only over the daemon owner's Unix socket, where the local
gateway forwards one-time OIDC codes and PKCE values for daemon-side exchange
and verification, resolves opaque session bearers, and requests
resource-specific ACL decisions. OIDC session creation
uses one daemon request that checks the project grant, records the owner,
project UUID, and placement in Quarry, then creates the idle transcript; if
filesystem initialization fails, the daemon compensates by removing the new
registry record. With OIDC enabled, the daemon refuses legacy unauthenticated
control requests from other OS users and network peers. Raw TCP never accepts
caller-asserted identities.

## Where a session runs

A daemon-hosted session is the current model: the daemon launches and owns the
agent worker. A client-hosted session reverses only execution. The daemon still
owns identity, membership, ordering, and durable coordination. Quarry stores
an owner-controlled host lease with a monotonically increasing generation,
expiry, single-active-host conflict protection, and stale-release protection.
The authenticated HTTP gateway exposes owner-only lease claim and release at
`POST /api/session-host`; a browser may use its session cookie, while a client
process may use an `Authorization: Bearer` worker credential. The session
owner can mint that credential from the session's **Share** screen or through
`POST /api/worker/token` while logged into the browser, with
`{"session":"<session-id>"}`. The Share screen displays it once in memory;
leaving the screen or switching sessions clears that display. The credential
expires after 24 hours and is restricted to that one session's client lease,
command-read, and event-ingress operations. It cannot call ordinary user APIs.
The Share screen's **Hide credential** action revokes it before clearing the
display; if revocation fails, the credential remains visible so it can be
retried. A client can also revoke its own bearer with an empty `POST
/api/worker/revoke` request carrying that credential as its bearer token.
Use HTTPS when requesting or presenting it, and do not put it in logs or source
control. Repeat a claim from
the same host UUID to renew it, and retain its generation to release it. For example, a claim body is
`{"action":"claim","session":"<session-id>","placement":"client","host_id":"<UUID>"}`;
the response contains `generation` and `expires_ms`. A release body has
`action: "release"` and includes that generation. Claims are checked against
the session's registered placement and only its owner can claim or release.
The `chock worker` command releases its latest lease generation during normal
shutdown, so another worker can take over immediately; an unclean process loss
still relies on lease expiry.
`POST /api/worker/events` is the first fenced event-ingress path. It requires a
worker bearer credential plus the session UUID, host UUID, lease generation, and
the worker's expected byte offset. The daemon validates the active client
lease, rejects human-authored messages, approvals, and agent-question answers,
then appends agent events to the canonical session log. A stale offset is a conflict, not
an implicit retry, so the worker must resynchronize before sending more events.
Use HTTPS at the public boundary; this endpoint carries a bearer credential.
Client-placed prompts are appended as attributed user-message events rather
than run by a daemon worker. The lease holder reads ordered session events from
`GET /api/worker/commands?session=<id>&host_id=<UUID>&generation=<n>&after=<event-id>`
using the same bearer credential; the `after` cursor is the last event ID the
worker has processed. Its response contains `events` and `end_offset`; the
response is bounded to 64 events. Continue reading from the last returned
event's `id`; `end_offset` is the exact byte position to submit as the next
event's `event_id`. Event ingress returns both the appended event ID and the
next `next_offset`. This poll is fenced by the same active lease as event
ingress, and offsets keep concurrent human prompts from being overwritten by a
worker.
Client-hosted turns are admitted one at a time: another prompt receives a
conflict until the worker appends its terminal `session_end` event. This keeps a
later human message from appearing before the earlier turn's assistant output.
People with `session_prompt` can cancel a running turn from the Share screen.
Daemon-hosted turns use the daemon's scoped interrupt. For a client-hosted turn,
the daemon appends a cancellation command to the canonical log; the worker
observes it through its fenced event poll and stops at the runner's next safe
point. This preserves event order and does not signal the worker process or
cancel its other sessions.
For an active client-hosted turn, an authorized approval response is appended
to the canonical transcript under the session-log lock. The worker mirrors
that response into its local log, where the existing runner's approval broker
observes it. The daemon accepts only the newest unanswered approval request;
stale and duplicate responses are refused.
Appending `session_end` closes the busy marker and advances the host lease
generation while holding the session log lock. The worker must claim the next
generation before processing another turn; delayed events from the completed
turn are refused even if a later prompt has already opened a new busy window.
If a host lease expires mid-turn, the busy marker remains set so a later human
prompt cannot overtake that unfinished turn. A replacement host generation can
read the durable log and continue the pending turn; it must append the terminal
`session_end` event before the daemon admits another prompt. The current
`chock worker` claims and renews this lease, polls for pending turns, and
adopts the same session log locally. While the run is active, it polls the
local append-only log and forwards new agent events to the daemon; the daemon
therefore makes in-progress output available to collaborators without waiting
for turn completion. After a local run it reconciles the full event history;
a restarted worker can resume a pending turn from the shared transcript.

The authenticated `POST /api/create` endpoint accepts `placement=daemon` (the
default) or `placement=client`; the Projects screen offers both choices for a
specific registered project, and the selected value is stored on the session
record. Client-hosted agent questions
are now transcript events: the worker appends a typed `agent.question`, waits
for a matching answer to arrive through normal log synchronization, and gives
that answer back to the agent. The app renders the question in the session and
routes the next composer submission to an authenticated `POST
/api/agent-answer` action. The daemon checks `session_prompt`, records the
responder identity UUID, and rejects duplicate, stale, or ended questions.
These answers remain in the transcript and its export. They provide information
only; they do not approve tools or grant authority. The daemon refuses to start
a daemon worker for a client-placed session rather than silently ignoring its
placement.

This is not `chock detach` over a network filesystem. A hosted client cannot
hand the daemon a local path and assume it exists there. The client-hosted
protocol must carry session events and worker commands, while daemon hosting
needs an explicit project provisioning mechanism.

Messages from several editors are accepted by the daemon and serialized into
one order before the agent sees them. Viewers cannot prompt or answer an
approval. OIDC-authenticated prompts now resolve their author from the daemon
login token and store that identity UUID on the user message event;
OIDC-authenticated approval responses likewise store the responder UUID. The
protocol remains at version 1. Messages and approvals entered through legacy
local CLI flows remain unattributed; other human actions still need equivalent
attribution before the transcript is a complete audit record.

Client-hosted workers continue to use the existing control protocol version 1
and its version check. Multi-user coordination must be added without moving
that protocol off version 1; incompatible future changes need a compatible
extension or another explicitly negotiated mechanism, not a version bump as
part of this work.

## Projects

A project is provisioned from the UI, not by editing daemon configuration.
The Projects list's **New project** flow can register an existing daemon-local
directory or clone an HTTPS Git repository into the daemon's managed
`<state directory>/projects` area. Set `CHOCK_GIT_ALLOWED_HOSTS` to a
comma-separated allowlist of exact HTTPS Git hostnames before cloning is
available; the URL host must match exactly. With no allowlist set, every clone
is refused. The clone runs `git` on the daemon, so a hand-written unit must put
it on the service path; the NixOS module already does. Local-path registration is
restricted to instance administrators, since a remote user must not be able
to point an agent at an arbitrary readable path on the daemon.
Git URLs with embedded credentials, query strings, or non-HTTPS schemes are
rejected; private-repository credential management remains future work. The
daemon creates a stable UUID-backed project record and grants its creator
project access. The UUID is the authorization identity; the execution root is
a locator mapped to that UUID. The project row reports its current `ready`
status.
The database keeps the source kind and repository URL separate from the
daemon-managed execution root, so the project UUID and Git provenance survive
restarts without treating a checkout path as the repository identity.

Project managers may archive and restore projects from this list. Archiving
prevents new service-managed sessions from starting, but deliberately leaves
the workspace, existing sessions, transcripts, memberships, and ACL rules in
place. Restore makes the project available for new sessions again. This is a
reversible lifecycle action, not deletion or a retention timer.

The Projects screen offers **New daemon session** and **New client session**
for each registered project. Session creation names the project's execution
root, which the gateway checks against project ACLs before launching the
session; the session is then registered against that project's UUID and its
creator is made owner. For daemon placement, the configured root is the
daemon's workspace. For client placement, the worker uses its local checkout,
but the session still binds to the registered project record for membership
and history. Additional source kinds should preserve that UUID so changing a
locator does not change project identity. Uploading snapshots remains future
work.

For browser-created sessions, the authenticated creator and UUID-backed
project association are now recorded in Quarry, with the creator seeded as
the session owner. The database also supports owner-controlled editor/viewer
membership updates. Owners can view, prompt, approve, and share; editors can
view, prompt, and approve; viewers can view. Matching ACL denies override
these role grants. The session's **Share** view shows an owner-only list of
identities that have signed in to this daemon and their current membership;
the owner can add or change an editor/viewer role, or remove a non-owner's
session membership. Removal affects only the role membership; explicit ACL
rules remain independent and must be changed separately if they should also
be withdrawn. The shared-session header shows active collaborators. Clients
refresh their presence lease every 15 seconds; a lease expires after 60 seconds
without refresh and is pruned on the next presence read. Presence is ephemeral
coordination state: it is not part of transcript history, audit records, or
session exports. The corresponding API is
`GET /api/session-members?session=<session-id>` and
`POST /api/session-members?session=<session-id>` with JSON
`{"identity_id":"<UUID>","role":"editor|viewer|remove"}`. Older or
Sessions created by `chock` directly on the daemon before a project was
registered can be attached from the Projects screen using **Import a local
session**. The operator supplies the exact registered project directory and
session ID shown by `chock sessions`. The caller needs `project_manage`; the
daemon verifies that a readable, complete log with that ID exists in that
project's own session directory before recording the caller as owner. Import
does not move, rewrite, or delete the log. A session that lives on a different
machine is not importable this way; create a client-hosted service session and
run `chock worker` on that machine instead.

## Teams and access control

People can create teams and manage team membership. Access to projects,
sessions, provider configurations, and team administration is expressed as ACL
rules for an identity, a team, or everyone. Capabilities are resource-specific,
including viewing or managing a project, prompting or approving in a session,
and using or managing a provider. Access is denied when no rule allows it, and
a matching deny overrides matching allows, including a project-level session
capability deny over a session member role or a session-level allow. Project
ACLs for session capabilities also apply to sessions registered under that
project; a session rule or membership role may grant more specific access, but
cannot override a matching project deny. Instance administrators are an
explicit role and may repair ACL configuration.

Quarry provider records support three scopes: one user, one team, or the whole
daemon instance. Scope determines where a configuration is managed; it does
not grant use by itself. `provider_use` and `provider_manage` ACLs decide who
can invoke or change it. Records store only non-secret JSON configuration and
an opaque `secret://<UUID>` or `env://NAME` credential reference, never a raw
API key or refresh token. The most recently created record in each scope is
that scope's default; a turn uses the user's default, then an accessible team
default, then an accessible instance default. `env://NAME` resolves from the
daemon environment. `secret://<UUID>` resolves to the daemon environment
variable `CHOCK_SECRET_<lowercase UUID>`; inject that value through the host's
service manager or secret manager. Neither credential value is stored in
Quarry, returned to the browser, or sent over the control protocol. Provider
configuration JSON must include a model and may include a base URL, context
limit, and image capability.

Authentication and authorization are separate: the OIDC provider establishes
the person's identity, while daemon-local teams and ACLs decide what that
person can do. Team owners can issue member invitations and add already
signed-in identities. An invitation grants membership only after the recipient
signs in with the configured provider; it never creates a password or an
identity outside OIDC. Current invitations are unbound, random, single-use
bearers scoped to one team and the member role, expire after seven days, and
are stored only as a SHA-256 digest. The UI warns that any authenticated person
who obtains the token can redeem it before expiry, and shows the raw token only
once. Redemption consumes the invite in the same database transaction that
creates the membership, so concurrent attempts cannot claim it twice. Owners
may revoke an unused invite; revocation does not remove memberships already
granted. Team owners can remove non-owners from the Team members list; this
removes team-derived access without changing independent identity ACL rules.
The owner membership is protected. Binding an invitation to an exact OIDC
issuer and subject and manager-role invitations remain future work.

Provider group claims do not silently grant daemon roles or team membership.
Initial access is managed with local teams and ACLs. If group mapping is added,
it must be opt-in per exact issuer and claim name, map only to selected team
UUIDs, and be visible to administrators. A configured mapping is authoritative
only for memberships explicitly marked as mapping-managed; it may add or remove
those memberships at sign-in without changing locally managed memberships.
Group claims never grant instance-admin status. This keeps the identity
provider responsible for authentication while leaving authorization policy
explicit at the daemon.

The authenticated **People** screen is an instance-administrator-only
directory of identities that have signed in. `GET /api/people` returns local
UUID, display name, email, and instance role; it does not expose OIDC issuer or
subject values. Team owners use the narrower team-members endpoint when adding
people to a team. An instance administrator can use **Revoke active sessions**
to invalidate that person's currently valid browser and client-worker login
credentials. This preserves the identity, sessions, and collaboration history;
it does not disable future sign-in, so disable or remove the account at the
identity provider as part of offboarding. Revoked credentials cannot be restored.

Instance administrators can grant or remove the instance-admin role for any
identity in the directory. The service refuses to demote the last instance
administrator, and role changes do not delete the identity or its history.
This is an explicit local authorization decision; OIDC group claims do not
grant instance-wide administration.

When local accounts are enabled, an instance administrator may also set a new
temporary password for a local account from the People screen. Password reset
replaces the Argon2id hash and revokes all of that account's browser and worker
login credentials in one transaction. The user must sign in again with the new
password; OIDC identities cannot be reset this way.

An instance administrator may disable a local account without deleting its
identity or history. Disabling prevents future password sign-in and revokes
current credentials; re-enabling permits a fresh sign-in but does not restore
old credentials. The service refuses to disable the last enabled local
instance administrator.

## Mobile servers

The Android shell stores a bounded, most-recent-first server list through
Phantom's platform settings API. Entries may be a host or an `http://` or
`https://` origin; use HTTPS outside a trusted local network. Credentials,
paths, and query strings are rejected so API calls stay rooted at the selected
server. The connected shell keeps a **Change server** action available above
the shared application, so a person can switch to another saved server without
restarting the app. Server addresses are non-secret. OAuth access and refresh
tokens must use an OS-backed secret facility rather than that settings value.

## Nix deployment

The flake exports `nixosModules.chock-daemon` and
`homeManagerModules.chock` (also available as `homeManagerModules.default`).
Import `overlays.default` from the Chock flake so `pkgs.chock` is available to
both modules.
The NixOS module runs `chock daemon` as the dedicated `chock` system user,
stores state under `/var/lib/chock`, and listens only on a restricted Unix
socket. It does not expose the unauthenticated daemon TCP listener. The
browser gateway is opt-in with `services.chock-daemon.web.enable`; it runs as
the separate `chock-web` user and creates a group-restricted Unix socket at
`/run/chock-web/serve.sock`. The web user can reach the daemon control socket
but cannot traverse daemon state or read OIDC secrets. A local reverse proxy
can be given access with `web.socketGroup`. Give it a group of its own: control
socket access is equal to the daemon owner, so a proxy that holds the daemon's
service group can drive the daemon directly and answer to no ACL. Configure
`web.externalUrl` so
browser origins can be checked (and register its callback path with the
provider when using OIDC). The NixOS VM test checks cross-user socket access,
private state, OIDC setup and restart persistence, and that the raw daemon
port stays closed.

Set `services.chock-daemon.oidcProvider`, `oidcIssuer`, and `oidcClientId`
together when enabling daemon-side OIDC authorization. Put database and
environment-configured OIDC credentials in daemon `environmentFiles`; do not
place OIDC secrets in `web.environmentFiles`. UI-provisioned OIDC secrets are
stored in daemon private state. Set
`oidcAdminSubject` only to the exact subject that should bootstrap as an
instance administrator. `gitAllowedHosts` configures the exact HTTPS Git host
allowlist. Put database URLs with passwords and other sensitive environment
values in `environmentFiles`, not inline in a Nix expression. The OIDC NixOS
test boots the daemon and gateway against PostgreSQL, checks schema and state
persistence, verifies environment isolation and private sockets, and confirms
that the raw daemon port stays closed. A second NixOS test exercises local
first-admin setup, repeated-setup rejection, bad-password rejection, persisted
password hashes, and login after a daemon restart. The database library tests
also exercise SQLite for the personal-daemon default.

The Home Manager module installs `pkgs.chock`, can set `CHOCK_DAEMON` for a
non-default socket, and can declaratively install a `config.zon` through
Home Manager's regular `xdg.configFile` support. Such a managed config is
stored in the Nix store and must not contain credentials; use Chock's private
token file or a daemon-side secret manager for those.

## Browser setup

For OIDC, the daemon is the owner of the provider configuration and client
secret. The browser gateway may initiate a login redirect and maintain the
short-lived browser state cookie, but it must not receive the client secret or
perform the token exchange. Additive protocol-v1 requests over the
owner- and configured-group-checked Unix socket ask the daemon to create the
authorization URL and later send the callback target and cookie state for
exchange and ID-token verification. The daemon retains the verifier, nonce, and one-time state,
resolves the identity, and creates the application session; the gateway
receives the daemon login result and places the opaque session token in the
HttpOnly cookie. The first-run web setup flow writes OIDC configuration
through the daemon, which validates discovery and the exact issuer before
enabling OIDC. It requires the externally reachable callback origin and the
exact initial administrator subject. Client secrets belong in daemon-private
state (or a configured OS secret manager), never in Quarry rows, browser
storage, gateway environment, logs, or exports. The current durable file is
protected by filesystem permissions and remains inside the daemon's private
state directory. The NixOS module runs the gateway under a separate
`chock-web` user and grants it access to the daemon control socket through the
restricted Chock group; the web user cannot traverse the daemon state
directory or read the client secret file. Keep that group limited to the
service processes that need control-socket access.

## Data lifecycle and cryptographic boundaries

The default posture is to retain useful project, session, membership, and
audit history rather than deleting it on a short timer. Deletion should be an
intentional, authorized operation with clear scope and consequences; where
records must remain for referential integrity or audit, removal should revoke
access and redact or tombstone content instead of silently rewriting history.
Users can export accessible project metadata and session transcripts through
`/api/export/account`; this intentionally excludes workspace files and provider
secrets. Instance administrators can export the people directory, visible
provider configuration, project metadata, session transcripts, teams, team
membership, invitation lifecycle metadata, session sharing, and ACL rules from
the People screen. Invitation token hashes and bearers, provider credential
references, repository source URLs, workspace files, and live worker leases are
omitted. Session metadata may include daemon project paths. The archive is
bounded to 32 MiB, 200,000 events, and 10,000 sessions; if a transcript is
incomplete or a bound is exceeded, the export fails instead of returning a
partial archive. It is a logical data export, not a full service backup:
operators must also back up QuarryDB and configured session/project storage.
The export endpoint requires an authenticated instance administrator (through
OIDC or a Chock-managed account) and sends downloads with `no-store` caching.
Instance-wide deletion controls and explicit deletion semantics for sessions,
projects, and identities are not currently implemented. Deleting database
records without corresponding stored content can leave dangling files, so
operators should preserve both sides until those semantics are implemented.
The service does not currently expose automatic retention or purge settings.
Operators with legal or operational retention requirements must account for
both QuarryDB and the session/project storage, including backups, before
applying an external retention policy.

Use established cryptography at the boundary that owns each secret: TLS for
network traffic, the operating system or deployment secret manager for tokens
and provider credentials, and the database/filesystem or managed storage
encryption provided by the deployment for persisted data. Do not invent a
custom encryption or signing scheme for user identity. A service-managed
account is keyed by its local UUID; an OIDC-linked account is mapped by the
exact `(issuer, sub)` pair. Cryptographic signatures or per-user keys should
be introduced only for a concrete protocol feature with a defined key
lifecycle and threat model.

## The browser interface

`chock serve` carries the interface inside its own binary and serves it from
the daemon it is pointed at, so there is no asset directory to deploy. A
browser with no session is sent to `/auth/login`. `/setup` answers only until
the first administrator exists.

A signed-in person reaches the interface. That is the only gate on the page
itself, because each screen asks the daemon separately for what it shows, so
somebody with no project yet still gets the interface. The screens are:

- Sessions, the navigation list, with a session page at `/s/<session>` for
  anybody who holds `session_view` on it. The page names who else is reading
  it, and a message carries the UUID of the identity that wrote it. A prompt
  needs `session_prompt`, an answer to an approval needs `session_approve`,
  and sharing needs `session_share`. A viewer can therefore read a session
  and nothing more.
- Projects, which lists what the person can see. Creation needs
  `project_manage`. An existing project can be archived and restored.
- Teams, with membership and invitations.
- People, the identity directory and the instance export, which the daemon
  gives to instance administrators only.
- Providers, for LLM provider records at user, team, and instance scope.
- ACL rules for a project, a team, or a provider, which the daemon lists to
  that resource's manager only.
- Account settings at `/account`, where a Chock-managed account changes its
  own password.

These are Phantom components shared with the Android shell, which adds only
the server list described under **Mobile servers**.
