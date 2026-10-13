---
status: Proposed
implementation_status: Implemented
author: freeqaz
status_note: "Retroactive record. The design below is implemented on main (PRs #696 through #811, with follow-ups through #2153) and awaits human review. No acceptance decision has been recorded; Proposed is the closest allowed status."
---

# Proposal: Agent runtime status and log reads

- **ID:** RFC-0019
- **Created:** 2026-10-01
- **Last updated:** 2026-10-13
- **RFC PR:** https://github.com/openclaw/openclaw-enterprise/pull/854
- **Implementation:** [#696], [#711], [#726], [#730], [#737], [#739], [#741], [#742], [#745],
  [#747], [#793], [#807], [#811] (with the event from [#806]). Follow-ups: [#863], [#869],
  [#876], [#879], [#896], [#928], [#933], [#939], [#967], [#969], [#973], [#1096], [#1102],
  [#1108], [#1187], [#1354], [#1362], [#1371], [#1591], [#1896], [#1918], [#1922], [#1934],
  [#1938], [#1946], [#1981], [#1994], [#2076], [#2089], [#2110], [#2139], [#2147], [#2153]
- **Related:** [Default production observability](0012-production-observability.md) (the
  Collector boundary), [Agent access](0010-agent-access.md) (native admin audience),
  [RFC-0001](0001-oidc-sign-in.md) (sign-in provider outages)
- **Source baseline:** `main` at `07590c64e`. Symbols below were checked there.

<a id="problem-and-decision"></a>

## Summary

An Agent administrator can see why a deployed Agent version crashes, restarts or stops
serving, without cluster access. OpenClaw Control Plane (OCC) exposes two routes: runtime
status (Pods, containers, restarts, Pod Events, log sources and, for an OpenShell Harness,
the Harness Sandbox's state) and one bounded, redacted page of log text per request. The
console has a Logs tab, and the CLI has `occ agent runtime` and `occ agent logs`. Sources
are the Gateway and Agent (Harness) Pods' containers, init containers included, and, for
OpenShell Harnesses, the sandbox's policy decisions. OCC stores no log text and the routes
export nothing; the Collector gained only the bounded additions listed below. Every log view and download is audited before the read, as audit
kind `access`. A delegable `read_logs` Agent permission grants log text without full
administration.

Step-by-step behaviour lives in the [runtime logs flow](../../docs/flows/agent-runtime-logs.md);
this record covers the design, its trade-offs and its guarantees.

## Motivation

Before [#696], diagnostics did not inspect Pods, Events or logs, and the bundled Collector
strips text by design. A failing Agent's cause (a bad model key, a crash loop, a blocked
egress request) needed `kubectl`.

## Decision as landed

### Routes and tiers

| Route (`GET`, under `…/agents/:agentId/deployments/:deploymentId`) | Grants                                                                         |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `/runtime`                                                         | Agent `operate` + `read`, revision `read`                                      |
| `/runtime/logs`                                                    | Agent `read_logs` (or `administer`) + Agent `read`, any revision of that Agent |

`OpenClawController.describeAgentRuntime` and `readAgentRuntimeLogs`
([packages/occ/src/index.ts](../../packages/occ/src/index.ts)) own the decisions;
`runtimeLogTarget` resolves the revision inside the exact Agent and Namespace.
`authorizeRuntimeLogRead` tries `read_logs` first. It falls back to `administer` only when
no Restriction applies to `read_logs`, so a `read_logs` Restriction blocks an
administrator too. [#745] dropped the revision `read` requirement for log text so a
delegated reader keeps access across redeploys; status still needs it.

`read_logs` is in `PERMISSION_ACTIONS` ([packages/contracts/src/index.ts](../../packages/contracts/src/index.ts)).
It is orthogonal: it implies nothing and nothing implies it, and bootstrap does not grant
it ([#737]). Migration
[`0041_restriction_read_logs.sql`](../../migrations/0041_restriction_read_logs.sql) widened
the Restriction action CHECK so such a Restriction can be stored ([#739]).

The log query (`AgentRuntimeLogsQuery`) is closed: `source` (`gateway`, `agent`,
`sandbox`), `pod`, `container`, `previous`, `tailLines` (1 to 1000), `sinceSeconds`,
`cursor`, `download`, `minLevel`. Failures map to fixed `RUNTIME_LOGS_*` codes
([apps/controller/src/http/errors.ts](../../apps/controller/src/http/errors.ts)); Driver
and cluster error text never reaches a client.

### Sources and Driver contract

- `ComputeDriver.describeAgentRuntime?` and `readAgentRuntimeLogs?` return raw lines. Only
  the Kubernetes Driver implements them; Docker and SSH omit them, and
  `runtimeLogging: "driver"` gets `501`. The Kubernetes Driver lists at most 8 Pods per
  role by the revision's labels, advertises every main and init container ([#1994]), and
  keeps each Pod's newest 100 Events by `involvedObject.uid` across continuation pages
  ([#1938]). A log read re-checks Pod ownership and the container, reads `pods/log` (1 MiB
  limit, timestamps), then re-reads the Pod so a replaced instance is detected. A
  container still being prepared yields an empty page, not an error ([#1922]).
- `validRuntimeDescription` rejects malformed, impossible or offset Driver timestamps:
  status becomes unavailable rather than showing a different instant ([#2139], [#2153]). The
  OpenShell client refuses an impossible `since_time` before calling ([#2147]).
  Kubelet's numeric offsets are converted to UTC without losing precision ([#1934]).
- `SandboxDriver.readSandboxLogs?` ([#726]) calls OpenShell's read-only `GetSandboxLogs`
  through a reader that exposes only that method. The source is listed only when the
  selected Sandbox Driver provisioned the revision. OpenShell `NOT_FOUND` (absent, still
  provisioning, or concealed by Workspace membership) becomes
  `RUNTIME_LOGS_SANDBOX_NOT_FOUND` and never says which.
- For a dedicated OpenShell Harness, status also carries `harness` from
  `SandboxDriver.observeHarness`: `running`, `starting`, `lost` or `unknown`, with a fixed
  code. `lost` means OCC will not restart it ([#2076]); `starting` with
  `HARNESS_RESTARTING` adds the last exit code and restart number, so a crash loop no
  longer reads as a first start ([#2089]).
- Helm `agentRuntimeLogs.enabled` (default `true`, in both charts) grants `pods/log get`
  and `events get,list` to the tenant API, Gateway observer and execution tenant API
  roles. Off, both routes answer `501`. Those roles hold `pods get,list` and `pods/proxy
get` either way, for diagnostics ([#967] for the execution role).

### Sanitization: one chokepoint

`sanitizeRuntimeLogChunk` and `sanitizeSandboxLogLines`
([packages/occ/src/runtime-logs/sanitize.ts](../../packages/occ/src/runtime-logs/sanitize.ts))
are the only producers of the branded `SanitizedRuntimeLogRecord`. The JSON serializer
and the download writer
([apps/controller/src/http/runtime-logs.ts](../../apps/controller/src/http/runtime-logs.ts))
accept only that type.

- **Classify by allowlist.** Kept: runtime wrapper events with per-event fields; OpenClaw
  JSON console records with a fixed key list (without a `subsystem`, only at warn or
  error: below that it is a `runtime.log` write such as a chat reply, [#869]); Codex
  tracing records; and plain text up to 4 KiB. A Codex record keeps its message only for
  reviewed targets (`CODEX_MESSAGE_TARGET`) and fixed formats (`CODEX_FIXED_MESSAGES`);
  otherwise it reads `Codex message withheld` ([#928], [#969]). Payload keys such as
  `prompt`, `content`, `messages`, `body` and `headers` are never kept. Other JSON,
  including Codex JSON-RPC and pretty-printed JSON ([#742]), is withheld and counted.
- **Redact every kept string.** PEM blocks are masked on every line, also across pages
  ([#741]). Also masked: auth and cookie headers, JWTs, known token prefixes, cloud keys,
  URL userinfo, query values, credential-named key/value pairs, `Bearer` tokens and
  base64 or hex runs of 40+ characters. Argv credentials (`-u user:pass`, `-p pass`) are
  masked first ([#869]). Replacements are `[redacted:<pattern>]`, keeping nothing of the value.
- **Content classes.** Container lines are `operational`, sandbox lines `activity`.
  `content` (prompts, responses, tool output) has no producer; the serializer throws on it.
- **Bounds.** 32 KiB in and 8 KiB out per line, at most 1000 lines, 10 s per request.
  Since [#1981] the 512 KiB response limit is measured on the serialized page, signed
  cursor and HTTP envelope; the reader returns a fitting prefix, not a maximal one.
  `RuntimeLogLimiter` adds a per-principal, per-Agent token bucket (2/s, burst 10) and 16
  concurrent Driver reads per API replica, applied after authorization ([#1187]).
- Pod Event messages pass `maskRuntimeEventText`, which masks node, image, Secret and
  ConfigMap names in standard kubelet and scheduler shapes.
- The console and `occ agent logs` show invisible or direction-changing characters in kept
  text as escapes such as `\u202e` ([#1362], [#1371]).

### Views, cursors and audit

A page carries a cursor, HMAC-signed with the auth secret under purpose
`occ-runtime-logs-cursor`, bound to principal, Agent, revision and source, and valid for
1 h ([cursor.ts](../../packages/occ/src/runtime-logs/cursor.ts)). Polling with a cursor was
chosen over streaming, so continuity is reconstructed from re-reads:

- **Container resume.** `@kubernetes/client-node` has no `sinceTime`, so
  `readRuntimeLogPage` resumes with `sinceSeconds` plus 2 s of overlap and drops lines it
  already delivered. The cursor stores the frontier timestamp, a count of lines delivered
  at it, whether that count is complete, and the last 16 line hashes ([#1896], [#1918]), so
  a same-timestamp group larger than the hash history neither replays nor hides lines.
- **Sandbox resume.** OpenShell batches lines, so a resume reads 5 s behind the newest
  delivered line and consumes one stored hash per re-read line (up to 48).
- **Cuts.** A page cut by the 1 MiB read or the response limit carries a signed checkpoint
  of the raw window, so the next poll continues inside it ([#1981]). PEM masking and
  withholding learned from fetched but undelivered lines carry forward; delivered rows
  alone advance the cursor.
- **Uncertainty is visible.** When the cursor cannot prove its position, OCC keeps
  matching text suppressed until time advances, or resets with a gap and may replay.
  Loss the API can see becomes a `gap`: `stream_replaced`, `window_exceeded`,
  `cursor_expired`, `truncated`, or `buffer_lost` (one per sandbox buffer loss). A quiet
  view resumes from its previous read ([#933], [#939], [#973]); a view stuck behind one
  over-long line skips it with `window_exceeded` ([#1102], [#1108]).

A view is audited once, before its first Driver read, as
`openclaw.agents.runtime_logs.view` (or `.download` per download) with kind `access`.
`authorization.action` records whether `read_logs` or `administer` admitted the reader;
details name the source, Pod, container, `previous` and tail, never text. Changing stream
starts a new view. If the audit write fails, the request returns `503` with no content.
Cursor polls are re-authorized but not re-audited. Status reads are not audited, like
diagnostics.

### Failure surfacing and noise ([#747], [#793], [#807])

- Runtime Events carry `container` (from `involvedObject.fieldPath`). `occ agent runtime`
  prints Events and the Harness Sandbox state; the console shows a record's `code` on the
  collapsed row. A terminated container reports its current termination, otherwise the
  prior one ([#1946]). The wrapper's `Harness model authentication probe failed.` is an
  error record. Since [#1096], failed `openclaw.model_probe` and `codex.model_probe`
  events keep `causeKind` and `causeDetail` from the closed `runtimeFailureCause`
  vocabulary.
- The Kubernetes Driver drops one scheduler `FailedScheduling` Event from runtime status:
  the PVC binding conflict retry, once the Pod has a node ([#1354]).
- Codex prints span records at INFO, burying real events. The Harness wrapper pipes Codex
  stderr through `CODEX_STDERR_FILTER_HELPER`
  ([runtime-entrypoints.ts](../../apps/controller/src/drivers/compute/kubernetes/runtime-entrypoints.ts)).
  Unless `RUST_LOG` starts at `debug` or `trace`, it drops span lifecycle records (except
  the `turn` span's `new`/`close`) and a fixed list of idle or expected lines: loopback
  WebSocket connects, repeated remote-control waits and proxy warnings, the
  missing-bubblewrap ERROR (the image runs Codex's bundled `bwrap` on purpose) and, since
  [#876], the untrusted workspace `.codex` ERROR.
- `minLevel` is a server-side floor (`runtimeLogPageAtLevel`), applied after the page is
  read, sanitized and its cursor signed. Unknown-level lines, gaps and withheld counts are
  always kept. The console reads `minLevel=info` with an **Include debug** checkbox; the
  CLI has `--level`. The CLI refuses an explicit zero or sub-second `--since` ([#2110]).

### Collector export ([#793], [#811], [#863], [#879], [#896])

RFC-0012's Collector boundary is unchanged, apart from these bounded additions:

- `codex.turn` and `codex.tool_call` are exported with fixed bodies. A `codex.operational`
  body keeps Codex's own message only for `codex_app_server` targets and two fixed retry
  messages, and only when it is short plain text with no credential words, argv
  credential flag or `user:password` pair ([#879]). A Codex warning without such a body
  is dropped ([#863]).
- `gateway.startup_failed` ([#879]) exports OpenClaw's subsystem-less startup failure
  under the same plain-text rules.
- A failed `runtime.startup_phase` keeps its cause as `occ.code` ([#863]).
  `runtime.gateway_settings_overridden` is exported as WARN with no attributes ([#896]).
- `authentication.provider-unavailable-warning` (from [#806]) is allowlisted with
  `occ.sign_in.provider`, `step`, `cause` and `status`, each from a fixed value list.

## Security and threat model

| Threat                             | Control as landed                                                                                                                                                                                                                          |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A reader sees another Agent's logs | Exact-Agent grants; the Driver reads only Pods carrying the revision's labels and re-checks them and the container. RBAC cannot separate Agents, so this check carries the weight.                                                         |
| Credentials in output              | Allowlist classification, then pattern redaction. Masking state survives page cuts. Canary tests run planted credentials through the real handler and download.                                                                            |
| Chat content in output             | Payload keys dropped; Codex protocol output and subsystem-less OpenClaw records below warn withheld; Codex messages keep text only for reviewed targets and formats; `content` has no producer. Plain text is still kept (see Known gaps). |
| Forged or replayed cursors         | HMAC binding to principal, Agent, revision and source; mismatch is `400`.                                                                                                                                                                  |
| Unaudited reads                    | Audit before the read; audit failure means no content.                                                                                                                                                                                     |
| Lateral cluster actions            | Log reads add only read grants: `pods/log get`, `events get,list`, OpenShell `sandbox:read`.                                                                                                                                               |
| Resource abuse                     | Byte, line and time bounds, plus the token bucket and the concurrency cap.                                                                                                                                                                 |

The `501` switch runs before authorization, so a principal with no grants learns only
whether the feature is on. The rate and concurrency limits wrap only the Driver reads
([#1187]): every denial is refused and audited, and spends no token.

## Rationale and alternatives

- **Gateway `logs.tail` RPC.** Rejected: needs a live Gateway; misses crash loops.
- **Read from Loki or another log store.** Rejected for text. The Collector strips bodies
  by design, and OCE keeps no store; the backend stays a link.
- **Streaming (SSE).** Deferred. Polling every 2 s with a cursor reuses normal request
  authorization and holds no kubelet connection per viewer. The cost is the resume
  machinery, the most intricate part of this design.
- **`administer` only.** Slice 1 used it, following the native admin precedent: that
  audience already reaches Gateway logs through the native admin UI. `read_logs` lets log
  reading be delegated.
- **Audit as `mutation`.** Slice 1 did this; [#737] moved views and downloads to `access`.
- **`RUST_LOG` to quiet Codex.** It cannot drop span events alone.
- **Client-side level filtering only.** Debug lines filled the page before
  `turn completed` was reached ([#807]).

## Known gaps and residual risk

- Redaction is pattern-based. Opaque tokens under 40 characters, with no known prefix, key
  name or `Bearer`, can still appear. Plain text up to 4 KiB is kept after redaction.
- Following is not lossless. Identical replacement windows are unobservable, and
  uncertainty resets with a gap that may replay lines ([#1981]).
- Harness stdout and stderr inside an OpenShell sandbox are not readable without attach
  (`sandbox:write`). This needs an upstream read-only RPC.
- Sandbox decisions often show policy generation "unknown": OpenShell does not stamp it on
  CONNECT allows. The 2000-line ring is lost on gateway restart, and push drops are
  inferred, not reported. Sandbox tests use synthetic lines and loopback gRPC, not a live
  OpenShell.
- Kubernetes keeps only the current and previous container instance.
- `occ agent logs` has no container flag; it reads the default first main container.
- The Codex stderr filter is keyed to Codex 0.158 message shapes; the image ships
  0.163.0-alpha.2 since [#2029], filter unchanged. A rename lets noise back rather than
  hiding other lines.
- Rate and concurrency limits are per API replica.
- Operators must refresh the Collector config Secret on upgrade to get the export changes.

## Open questions for reviewers

1. Should `agentRuntimeLogs.enabled` default to on? **Implemented:** `true` in both charts.
2. Should `administer` keep admitting log text? **Implemented:** yes, unless a `read_logs`
   Restriction applies.
3. Should log text cover every revision of an Agent while status needs revision `read`?
   **Implemented:** yes ([#745]).
4. Is one audit row per view enough, with polls and status reads unaudited?
   **Implemented:** yes.
5. Should Codex message text be exported to the backend under the plain-text pattern?
   **Implemented:** yes, for `codex_app_server` targets and fixed retry messages.
6. Should `minLevel` read more lines to fill the page? **Implemented:** no. It is a display
   floor applied after the tail, so a page can show fewer lines than requested.
7. Is a best-effort follow, with visible resets, acceptable without a backend sequence
   number? **Implemented:** yes; no sequence or public query field was added.
8. Should the OpenShell gaps above be filed upstream? **Implemented:** not filed; the
   limits are documented.
9. Should the console offer a log-only share? **Implemented:** no; `read_logs` is granted
   through the Namespace IAM Role API only.

## Delivery history

Slices 1 to 3 ([#696] to [#811]) landed on 2026-09-30 and 2026-10-01. Hardening of
redaction, resume and limits followed through 2026-10-05. From 2026-10-09 to 2026-10-12,
follow-ups counted same-timestamp lines, bounded the serialized response ([#1981]), added
container selection ([#1994]) and Harness Sandbox state, and tightened timestamps. [#1591]
moved the CLI to `internal/occcli/agent_runtime.go`; [#1213] split out `logs-view.mjs`.

## References

- Guide: [Agent logs](../../docs/guides/topics/agent-logs.md); flow:
  [Agent runtime logs](../../docs/flows/agent-runtime-logs.md); security:
  [Console and API runtime log reads](../../docs/reference/security.md#console-and-api-runtime-log-reads).
- Code: [packages/occ/src/runtime-logs/](../../packages/occ/src/runtime-logs/index.ts),
  [apps/controller/src/http/runtime-logs.ts](../../apps/controller/src/http/runtime-logs.ts),
  [apps/controller/src/console/agents/logs.mjs](../../apps/controller/src/console/agents/logs.mjs),
  [internal/occcli/agent_runtime.go](../../internal/occcli/agent_runtime.go),
  [deploy/logging/collector.yaml](../../deploy/logging/collector.yaml).
- Tests: [runtime-logs-content](../../tests/conformance/runtime-logs-content.test.mjs),
  [occ-api-security](../../tests/conformance/occ-api-security.test.mjs).

[#696]: https://github.com/openclaw/openclaw-enterprise/pull/696
[#711]: https://github.com/openclaw/openclaw-enterprise/pull/711
[#726]: https://github.com/openclaw/openclaw-enterprise/pull/726
[#730]: https://github.com/openclaw/openclaw-enterprise/pull/730
[#737]: https://github.com/openclaw/openclaw-enterprise/pull/737
[#739]: https://github.com/openclaw/openclaw-enterprise/pull/739
[#741]: https://github.com/openclaw/openclaw-enterprise/pull/741
[#742]: https://github.com/openclaw/openclaw-enterprise/pull/742
[#745]: https://github.com/openclaw/openclaw-enterprise/pull/745
[#747]: https://github.com/openclaw/openclaw-enterprise/pull/747
[#793]: https://github.com/openclaw/openclaw-enterprise/pull/793
[#806]: https://github.com/openclaw/openclaw-enterprise/pull/806
[#807]: https://github.com/openclaw/openclaw-enterprise/pull/807
[#811]: https://github.com/openclaw/openclaw-enterprise/pull/811
[#863]: https://github.com/openclaw/openclaw-enterprise/pull/863
[#869]: https://github.com/openclaw/openclaw-enterprise/pull/869
[#876]: https://github.com/openclaw/openclaw-enterprise/pull/876
[#879]: https://github.com/openclaw/openclaw-enterprise/pull/879
[#896]: https://github.com/openclaw/openclaw-enterprise/pull/896
[#928]: https://github.com/openclaw/openclaw-enterprise/pull/928
[#933]: https://github.com/openclaw/openclaw-enterprise/pull/933
[#939]: https://github.com/openclaw/openclaw-enterprise/pull/939
[#967]: https://github.com/openclaw/openclaw-enterprise/pull/967
[#969]: https://github.com/openclaw/openclaw-enterprise/pull/969
[#973]: https://github.com/openclaw/openclaw-enterprise/pull/973
[#1096]: https://github.com/openclaw/openclaw-enterprise/pull/1096
[#1102]: https://github.com/openclaw/openclaw-enterprise/pull/1102
[#1108]: https://github.com/openclaw/openclaw-enterprise/pull/1108
[#1187]: https://github.com/openclaw/openclaw-enterprise/pull/1187
[#1213]: https://github.com/openclaw/openclaw-enterprise/pull/1213
[#1354]: https://github.com/openclaw/openclaw-enterprise/pull/1354
[#1362]: https://github.com/openclaw/openclaw-enterprise/pull/1362
[#1371]: https://github.com/openclaw/openclaw-enterprise/pull/1371
[#1591]: https://github.com/openclaw/openclaw-enterprise/pull/1591
[#1896]: https://github.com/openclaw/openclaw-enterprise/pull/1896
[#1918]: https://github.com/openclaw/openclaw-enterprise/pull/1918
[#1922]: https://github.com/openclaw/openclaw-enterprise/pull/1922
[#1934]: https://github.com/openclaw/openclaw-enterprise/pull/1934
[#1938]: https://github.com/openclaw/openclaw-enterprise/pull/1938
[#1946]: https://github.com/openclaw/openclaw-enterprise/pull/1946
[#1981]: https://github.com/openclaw/openclaw-enterprise/pull/1981
[#1994]: https://github.com/openclaw/openclaw-enterprise/pull/1994
[#2029]: https://github.com/openclaw/openclaw-enterprise/pull/2029
[#2076]: https://github.com/openclaw/openclaw-enterprise/pull/2076
[#2089]: https://github.com/openclaw/openclaw-enterprise/pull/2089
[#2110]: https://github.com/openclaw/openclaw-enterprise/pull/2110
[#2139]: https://github.com/openclaw/openclaw-enterprise/pull/2139
[#2147]: https://github.com/openclaw/openclaw-enterprise/pull/2147
[#2153]: https://github.com/openclaw/openclaw-enterprise/pull/2153
