---
status: Proposed
implementation_status: Not implemented
author: mrunalp
---

# Proposal: Connect a user's OAuth account to a personal Agent from the console

- **ID:** RFC-0023
- **Created:** 2026-10-20
- **Last updated:** 2026-10-20
- **RFC PR:** [#3068](https://github.com/openclaw/openclaw-enterprise/pull/3068)
- **Implementation plan:** Not yet written; the next step is `$spec plan RFC-0023`
- **Related:** [RFC-0016](0016-sandbox-credential-injection/index.md) and its
  [Credential Refresh companion](0016-sandbox-credential-injection/credential-refresh.md);
  [RFC-0010 personal access](0010-agent-access.md#access-contract);
  [credential sources](../../docs/reference/credential-sources.md);
  [per-Agent sandbox policies](../../docs/reference/sandbox-policies.md);
  open [PR #2484](https://github.com/openclaw/openclaw-enterprise/pull/2484)

## Summary

A user signs in to the OCE console, opens their personal Agent, selects
**Connect Google**, approves access on Google's consent page, and then deploys the
Agent. The Agent's tool, such as `gog`, can then read that user's Gmail. Only that
user can use the Agent.

Installation administrators define connections as Installation-wide **connection
templates**, which Presets can reference. The Credential Refresh Driver exchanges
the authorization code and gives the refresh grant to the Credential Gateway, and
OpenShell refreshes the access token. The browser, OCC storage, and the Agent never
receive the refresh token; the tool receives only a placeholder. OCE core contains
no provider-specific endpoints, scopes, or binaries.

## Motivation

Today a user who wants an Agent to read their Gmail must export a refresh token
with a local sign-in tool, store it and the client secret as Namespace Secrets,
register an `oauth2-refresh-token` source, bind it, grant the Agent's service
principal `operate`, and deploy
([credential sources](../../docs/reference/credential-sources.md)). The refresh
token passes through the user's terminal and the OCC Secret store, and anyone with
access to the Agent can use the mailbox.

Device login, used only by the experimental `codex-oauth` model source, does not
help: Google's device-code flow does not permit Gmail scopes. Gmail needs the
browser authorization-code flow, with an OCC callback.

This proposal reuses the custody model of
[device login](../../apps/controller/src/drivers/credential-refresh/openshell.ts),
which hands the grant to OpenShell without persisting the refresh token.

## Goals

- A user connects their own account in the console without handling a client
  secret, refresh token, or access token, then deploys their Agent.
- Only the connecting user can use, deploy, or open an Agent that holds their
  connection.
- Administrators add a provider by creating a connection template, not by
  changing OCE code or Installation configuration.
- The credential reaches only the connection template's binary, endpoint, and
  allowed HTTP methods.
- Revocation, a denied consent, and an uncertain exchange each produce a visible
  state and one recovery action.

## Non-goals

- Shipping `gog` or any provider tool in the OCE runtime image. Operators supply an
  image that contains the connection template's binary.
- Device-code connections for tool credentials, and changes to model
  authentication (`harnessAuth`).
- Service-account or domain-wide delegation.
- Reducing what the approved scope can read. `gmail.readonly` exposes the whole
  mailbox to the tool.
- Shared Agents with connections, and per-message user identity inside an Agent.
- Namespace-owned connection templates. Start with the Installation-wide catalog;
  add Namespace templates later only if Namespaces need different providers or
  OAuth clients.

## Proposal

### Connection templates

A connection template is an Installation-scoped resource with IAM kind
`connection_template` and actions `create`, `read`, `update`, `delete`, and `use`.
Installation administrators manage the catalog through the API, CLI, and console.
They grant `use` on an exact connection template to the people or Namespaces that
may connect it. A user needs `use` to see a connection template under **Connect**
and to start a connection from it. Credential sources created from it stay in the
Agent's Namespace.

| Field                               | Why it is needed                                                                                                                                |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `displayName`                       | The label on the **Connect** button and consent warning.                                                                                        |
| `authorizationUrl`, `tokenUrl`      | Where OCC sends the user, and where the Driver exchanges the code. Exact `https` URLs.                                                          |
| `clientId`, `clientSecret`          | The administrator's OAuth client. OCC passes `clientSecret` to the Refresh Driver once and stores no value; see the contract changes.           |
| `scopes`, `authorizationParameters` | The fixed access the user approves. Users cannot add scopes. Google needs `access_type=offline` and `prompt=consent` to return a refresh token. |
| `endpoint`                          | The API `host`, `port`, `path`, and `access` (`read-only` or `full`) that receive the credential.                                               |
| `envVar`, `binary`                  | The placeholder variable and the one executable that may send it.                                                                               |
| `accountIdentity`                   | `none` (default) or `oidc`. With `oidc`, OCC also requests `openid email` and shows the connected address.                                      |

OCC rejects a connection template whose URLs are not `https` or whose `binary` is
not in the Gateway's `toolBinaries`. Startup configuration keeps `toolBinaries` and
`drivers.credential_refresh`, which describe the runtime image and Drivers.

The callback URI is derived from the console origin as
`https://<console-host>/oauth/callback`. Administrators register that exact URI
with the provider. The connection template response shows it.

With `accountIdentity: oidc`, the issuer must be an OpenID Connect provider. The
Refresh Driver verifies the ID token from the code exchange against the issuer's
signing keys, `aud` (the client ID), `iss`, expiry, and nonce, and returns only the
verified `email`. OCC stores that address on the credential source and shows
"Connected as alice@example.com" in Agent details and the connection list. The
consent screen lists the two extra scopes. Use it to catch a user who approved the
wrong account; it does not affect who may use the Agent.

### Versions and consent

An edit never changes what an existing connection does. Changing any field except
`displayName` creates a new connection template version. The credential source
records the version and the values its owner approved: issuer URLs, client ID,
scopes, authorization parameters, endpoint and access, variable, binary, and
`accountIdentity`. OCC and both Drivers use only that record, so an administrator
cannot redirect a user's refresh grant or credential. Source configuration is
already immutable.

After a new version, existing connections keep working and Agent details show
**Reconnect to apply changes**. Reconnecting asks for consent again and creates a
new source. To stop an old version, for example after an endpoint compromise,
administrators disconnect the affected sources. OCC refuses to delete a connection
template while any source references one of its versions.

Rotating the client secret for the same client ID is not a consent change; see
`registerClient`. A new client ID creates a new version.

### Personal Agents

A connection belongs to the human who completed consent. OCC records that
identity on the credential source. It applies the
[RFC-0010 personal choice](0010-agent-access.md#access-contract) to every Agent
that lists the source:

- Only the connection owner can bind the source to an Agent, and only to an Agent
  where the owner is the only human grantee.
- While the binding exists, OCC refuses Agent grants to other humans and refuses
  Slack, Teams, or other channel bindings, because channel members could invoke
  the tool.
- Deploying, opening the native admin UI, and starting a chat require the owner's
  signed-in session. Service keys cannot deploy the Agent.
- Installation administrators can stop the Agent, delete it, and disconnect the
  source. They cannot deploy it or use it.

An administrator, or a user with `agent:create`, creates the Agent for the owner.
The Agent's `connections` list names each required connection template, and
deployment returns `409` until each has a `ready` source. OCE has no per-message
identity, so this boundary covers access paths, not individual messages.

### Presets and connection templates

A [Preset](../../docs/reference/presets.md) is a Namespace copy of Agent launch
settings that the creator edits; later Preset changes never affect the Agent. A
connection template defines how one person's account is connected and where its
credential may go, and only Installation administrators change it. A Preset
therefore references connection templates instead of copying them.

Add `agent.connections` to the Preset template, a list of
`{ "connectionTemplateId": "…" }` entries. Creating an Agent from the Preset copies
that list into the Agent's `connections`; the console shows one **Connect** button
per entry. One Preset can combine several connection templates, such as Gmail and
Calendar read-only, with the Configuration and instructions that use those tools.
An unknown or unusable connection template fails Agent creation with `400`; the
Preset stays valid.

### Driver contract changes

These changes require review of this RFC before implementation.

1. **`CredentialRefreshDriver`** gains optional methods beside the device methods:
   - `startBrowserAuthorization(context, { connectionTemplateVersion, redirectUri })`
     returns `{ authorizationUrl, privateState }`. The Driver creates the PKCE
     verifier, a random `state`, and a nonce for `accountIdentity: oidc`.
   - `completeBrowserAuthorization(context, privateState, { code, state })`
     verifies `state`, exchanges the code, configures Gateway refresh custody, and
     mints the first token. It returns `ready` with an optional verified
     `accountEmail`, or a failure code, and never returns a token.
   - `registerClient(clientId, clientSecret)` and `removeClient(clientId)`, because
     OCE has no Installation-owned Secrets. The Driver stores the secret durably
     for every API replica and across restarts. Registering again replaces it and
     updates the refresh material of each source using that client ID, reporting
     per-source failure in refresh status. OCC removes a client only when no
     connection template version or source uses it, and stores no secret value.
2. **`CredentialGatewayDriver`** accepts an `access` field on tool-source
   endpoints. OpenShell maps `read-only` to its enforced REST access, which permits
   only `GET`, `HEAD`, and `OPTIONS`.
3. **The OpenShell tool profile** uses the connection template's `binary` instead
   of every `toolBinaries` entry, so other tool binaries cannot send the credential.
4. **Attachment opens the endpoint.** The model source's provider profile already
   allows `api.openai.com`
   ([OpenShell Sandbox](../../docs/reference/drivers/openshell-sandbox.md)). Tool
   sources must do the same for their endpoint and binary, without a per-Agent
   addition or a ceiling change.

Connections create sources of the existing `oauth2-refresh-token` type. The type
keeps its Secret-backed registration path for manual use.

### Console and API flow

```mermaid
sequenceDiagram
  participant User as Owner browser
  participant API as OCC API and console
  participant Refresh as Credential Refresh Driver
  participant Issuer as OAuth issuer
  participant Gateway as Credential Gateway
  User->>API: Connect on the personal Agent
  API->>Refresh: startBrowserAuthorization
  Refresh-->>API: authorizationUrl, privateState
  API-->>User: Consent warning, then popup to authorizationUrl
  User->>Issuer: Approve the fixed scopes
  Issuer->>API: GET /oauth/callback with code and state
  API->>Refresh: completeBrowserAuthorization
  Refresh->>Issuer: Exchange code with PKCE verifier
  Refresh->>Gateway: Configure refresh custody and mint
  alt Exchange and mint succeed
    Refresh-->>API: ready
    API-->>User: Connected; Deploy becomes available
  else Consent denied, state invalid, or exchange refused
    Refresh-->>API: failure code
    API-->>User: Show the failure; remove the pending source
  end
```

_Proposed flow; none of these paths is implemented._

1. `POST /namespaces/:namespaceId/agents/:agentId/connections` with a connection
   template ID. OCC checks connection template `use`, confirms the caller is the
   Agent's personal grantee, registers an empty source as `registering`, and calls
   `startBrowserAuthorization`. It stores `privateState` in a Namespace Secret, as
   device login does, and returns the source ID and `authorizationUrl`.
2. The console shows which account data the tool can read, then opens the URL in a
   popup. When a browser blocks popups, it redirects the page.
3. `GET /oauth/callback` requires the session that started the connection. OCC
   finds the session by a hash of `state`, rejects reuse or an age above ten
   minutes, and calls `completeBrowserAuthorization` once. The response sets
   `Referrer-Policy: no-referrer` and redirects without the query string. OCC
   excludes the code from logs and audit.
4. On `ready`, OCC adds the source to the Agent's `credentialSources` and grants
   the Agent's service principal exact source `operate`.
5. Agent details show the connection with **Reconnect** and **Disconnect**.
   Reconnect creates a new source and replaces the binding. Disconnect uses the
   existing withdrawal and deletion paths.

Audit records connection start, completion, failure, reconnect, and disconnect
with the actor, connection template ID, Agent ID, and source ID. It never records
codes, tokens, or provider account content.

### Failure and recovery

| Condition                                                | Result                                           | Recovery                                       |
| -------------------------------------------------------- | ------------------------------------------------ | ---------------------------------------------- |
| Consent denied, popup closed, or session expired         | Pending source deleted                           | Connect again                                  |
| `state` mismatch, reuse, or another user's session       | `400`; no exchange                               | The owner connects again                       |
| Exchange refused or no refresh token returned            | Source deleted; `fix_configuration`              | Administrator corrects the connection template |
| Timeout after the exchange started                       | Source stays `registering`                       | Delete and reconnect; OCC never replays a code |
| Issuer revokes the grant                                 | `status.refresh.recoveryAction: reauthorize`     | **Reconnect** and redeploy                     |
| Gateway or Refresh Driver unavailable                    | `503`; no source created                         | Retry                                          |
| ID token missing or invalid with `accountIdentity: oidc` | Source deleted; `fix_configuration`              | Administrator corrects the connection template |
| Connection template edited after consent                 | Source unchanged; **Reconnect to apply changes** | Owner reconnects; administrator can disconnect |

### Provider limitations

OpenShell refreshes access tokens. The operator guide documents provider rules,
such as Google's: `gmail.readonly` is a restricted scope that public applications
must verify, and External Testing applications issue seven-day refresh tokens.

## Delivery and verification

An implementation plan will order the resource and IAM, Driver contracts,
connection API and enforcement, console with Storybook coverage, and a Google Gmail
operator guide.

Required outcomes:

- **HTTP and PostgreSQL integration.** Use a real Keycloak issuer with
  authorization code, PKCE, and refresh tokens. Prove success, denied consent,
  state reuse, a cross-session callback, an expired session, and a missing grant.
  Prove that a second user cannot connect, deploy, chat with, or receive grants on
  a connected Agent, that channel bindings are refused, and that codes and tokens
  are absent from responses, logs, and audit.
- **Real k3d and OpenShell.** Through the regular Agent create path, connect via
  Keycloak and prove: a tool reaches its endpoint with no added network policy; a
  write fails under `read-only`; another tool binary cannot send the placeholder;
  rotate, revoke, and reconnect work; `accountIdentity: oidc` shows the address and
  rejects a wrong audience or nonce; an edited `tokenUrl` or endpoint leaves an
  existing source unchanged; client secret rotation keeps sources refreshing.
- **Live Google proof.** Run manually with an authorized account: `gog` reads Gmail
  through a dedicated Codex Agent, and a write method is denied. This proof is
  outside CI.
- **Dedicated Codex environment.** Verify that Codex shell commands receive the
  connection template's variable. Codex may filter variable names that contain
  `TOKEN`; if it does, Compute must allow exactly the connected variables.

## Rationale and alternatives

- **Connection templates in Installation configuration.** Startup configuration
  describes the installation's Drivers and images. Providers change more often and
  need IAM, so they fit an API-managed resource.
- **Connection settings inside Presets.** A Preset copy is editable by the Agent
  creator, which would let a creator change scopes, endpoints, or the OAuth client.
  It would also copy client secrets into every Namespace that holds the Preset.
- **OCC exchanges the code and stores the refresh token as a Secret.** This needs no
  new Refresh Driver methods, but it puts a rotating refresh token in OCC storage
  and inherits the `issuerRotated` update hazards.
- **A Google-specific Gateway type.** Each new provider would need an OCE release.
- **Shared Agents with a warning.** Anyone with access could read the mailbox.
- **Wait for the Credential Proxy in PR #2484.** That RFC replaces the Credential
  Gateway but keeps `CredentialRefreshDriver`, so the browser methods remain valid.
  The endpoint `access` field, per-connection-template binary, and attachment
  egress would move to its proxy contract.

## Unresolved questions

- **Client secret custody.** This proposal gives the client secret to the
  Credential Refresh Driver. Adding Installation-owned Secrets to the Secret Driver
  is the alternative; it keeps the Refresh Driver contract smaller but adds a new
  Secret scope. Driver contract reviewers decide.

## References

- [Credential sources](../../docs/reference/credential-sources.md)
- [CredentialRefreshDriver contract](../../docs/reference/drivers/credential-refresh.md)
- [OpenShell Credential Gateway](../../docs/reference/drivers/openshell-credential-gateway.md)
- [Console Agent creation](../../docs/reference/console/create-and-deploy.md)
- [Per-Agent sandbox policies](../../docs/reference/sandbox-policies.md)
- [Shared Driver contracts](../../packages/contracts/src/index.ts)
- [Google limited-input device scopes](https://developers.google.com/identity/protocols/oauth2/limited-input-device)
