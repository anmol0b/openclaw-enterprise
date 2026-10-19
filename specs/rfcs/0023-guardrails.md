---
status: Proposed
implementation_status: Not implemented
author: kevinlin-openai
---

# Proposal: Guardrails for permissions and configuration ceilings

- **ID:** RFC-0023
- **Created:** 2026-10-19
- **Last updated:** 2026-10-19
- **Related:** [shared configuration definitions](0022-driver-configuration-contributions.md), [managed runtime](0021-managed-runtime-mode/index.md)

## Decision and motivation

Add an OCC-owned **Guardrail** resource that can deny operations and constrain
configuration across all Namespaces or one Namespace. A Guardrail grants nothing.
Operations retain existing IAM permissions, Restrictions, and platform invariants.
Except for the Installation administrator bypass below, every applicable Guardrail
must pass; Namespace policy cannot relax a global ceiling.

Today [IAM Restrictions](../../docs/reference/authorization.md) deny exact actions
but have no public management API. [Sandbox policies](../../docs/reference/sandbox-policies.md)
have a startup delegation ceiling and a temporary per-Agent editing switch.
Neither provides reusable, inspectable configuration ceilings. RFC-0022 supplies
the proposed schema and validation foundation; it remains unimplemented.

This RFC selects the resource, targeting, and Driver interfaces. It covers OCC
admission, not an AWS firewall or a claim that native runtime settings cannot be
changed out of band. Runtime protection depends on RFC-0021 and qualified Drivers.
Inspection of existing resources for Guardrail compliance is out of scope,
including on-demand scans, background reevaluation, and compliance status views.
Implementation needs a separate plan after review.

## Resource and policy model

`Guardrail` has server-owned `id`, `generation`, timestamps, `name`, `scope`,
`policy`, and `configurations`. Its scope is immutable:

| Scope       | Meaning                                                                             |
| ----------- | ----------------------------------------------------------------------------------- |
| `global`    | All current and future Namespaces in this Installation; `namespaceId` is forbidden. |
| `namespace` | Exactly one server-validated `namespaceId`, which is required.                      |

Global does not mean cross-Installation or all AWS accounts. Installation
administration is outside this Namespace policy boundary.

Keep two lists because permission denial and value constraints have different
inputs and enforcement points. Require at least one nonempty list.

```json
{
  "name": "Restricted operators",
  "scope": "namespace",
  "namespaceId": "<namespace-id>",
  "policy": [
    {
      "effect": "deny",
      "actions": ["delete", "administer"],
      "resourceKind": "agent",
      "accessBindings": [{ "roleId": "<operator-role-id>" }]
    }
  ],
  "configurations": [
    {
      "capability": "sandbox",
      "driverId": "<selected-sandbox-driver-id>",
      "target": "networking",
      "configuration": {
        "maxAdditions": 4,
        "ceiling": [
          {
            "id": "approved-api",
            "binary": "/usr/bin/python3.11",
            "host": "api.example.com",
            "ports": [{ "from": 443, "to": 443 }]
          }
        ]
      }
    }
  ]
}
```

These are proposed wire fields; placeholders stand for real validated IDs.
`actions` is a nonempty, duplicate-free list of existing action names for the
given kind. Any listed action matches. Initially support only `effect: deny`;
reject wildcards, unknown actions, arbitrary condition expressions, and
`resourceId` filters. Rules constrain the whole selected scope, not individual
resources. Use ordinary IAM bindings for resource-specific grants.

### Binding selectors are conditions, not grants

Either kind of entry may have `accessBindings`. Omission matches everyone in
scope. An empty array is invalid, avoiding accidental confusion between everyone
and nobody. Entries are ORed; fields within an entry are ANDed.

A selector accepts a `subjectKind`/`subjectId` pair, a `roleId`, or both. Require
at least one of those choices. Resolve IDs through the selected IAM authority;
reject unknown or cross-scope references. Global selectors may reference only
Installation-wide identities, Groups, or Roles. No binding ID, resource kind,
or resource ID belongs in a selector.

**Confirmed targeting decision:** inspect all current bindings for the identity or its
current Groups that belong to this Namespace or the Installation. Match their
subject/Role fields, regardless of which binding granted this request. A second
grant cannot evade a matching deny. Consequently, a Role bound to one Agent can
select its holder for restrictions throughout the Namespace; the binding's
resource target is deliberately not a Guardrail filter. Restriction removal by
changing membership is an administrative policy change and must be audited.

Unbound configuration ceilings follow the target Namespace. Bound ceilings are
checked against the requesting actor; non-bypassed Agent deployment and application
also check the Agent's own ServicePrincipal, applying the union of matching ceilings.
Shared Configuration saves check the actor; each later Agent use checks its own
context again. Agents inherit neither their creator's identity nor an administrator's
bypass. Unbound ceilings cover the Namespace, subject to the administrator bypass.

## Configuration interface

Extend RFC-0022 definitions at their owning configuration surface:

```ts
interface GuardrailCapableDefinition<TValue, TCeiling> extends ConfigurationDefinition<TValue> {
  readonly guardrailsConfiguration: GuardrailsConfigurationDefinition<TValue, TCeiling>;
}

interface GuardrailsConfigurationDefinition<
  TValue,
  TCeiling,
> extends ConfigurationDefinition<TCeiling> {
  readonly scope: "guardrail";
  candidateSchema(ceilings: readonly TCeiling[]): JSONSchema;
  validateCandidate(value: TValue, ceilings: readonly TCeiling[]): ConfigurationResult<TValue>;
}
```

`scope: guardrail` identifies the administrative configuration definition, not
whether a Guardrail is global or Namespace-scoped. Its inherited schema and
`validateConfiguration` describe and validate **ceiling documents**.
`candidateSchema` projects structural constraints on **candidate values**;
`validateCandidate` checks those values plus domain semantics and returns the
unchanged value or RFC-0022 field errors. All methods are deterministic,
side-effect-free, and fail closed on malformed results or unexpected exceptions.

Bind each definition explicitly to its caller: Sandbox
`networkPolicyConfiguration` for `networking`, and a new native-values definition
on ConfigurationDriver for `openclaw`. Composition resolves the selected
capability/Driver/target tuple. This adds neither a general configuration store
nor arbitrary plugin dispatch. Unsupported targets refuse policy creation;
changing Drivers must validate existing ceilings rather than silently orphan them.
Installation startup values are not made hot-editable by this contract.

### Structural choices and semantic ceilings

For native OpenClaw values, the proposed ceiling contains `fields`: approved JSON
Pointers with a TypeBox-compatible schema and an explicit presence requirement:

```json
{
  "fields": [
    {
      "path": "/plugins/entries/codex/config/appServer/sandbox",
      "required": true,
      "schema": { "enum": ["read-only", "workspace-write"] }
    }
  ]
}
```

The Configuration Driver validates supported paths and assertions against its
native-values contract. Do not accept arbitrary unknown paths, remote references,
secret-value inspection, or schema annotations as enforcement. `required: false`
means optional; `schema: false` forbids presence. A required path
must exist, including its parents; removing a parent cannot evade its rule.
This example applies to Codex configurations, not a mixed-Harness global policy.
Guardrails select a deployment population through scope and bindings; reject an
incompatible deployment rather than infer that a missing path disables the rule.

| Constraint                  | Composition across applicable ceilings                            |
| --------------------------- | ----------------------------------------------------------------- |
| `enum` / fixed `const`      | Candidate must satisfy every set/value.                           |
| `maximum`, `maxItems`       | Smallest upper bound wins.                                        |
| `minimum`                   | Largest lower bound wins.                                         |
| Required or forbidden field | Enforce presence/absence, not a default or hidden input.          |
| Network ceiling             | Every requested executable/host/port range must fit each ceiling. |

Combine constraints conjunctively, never by last-writer replacement or list union.
An empty intersection denies candidates with field diagnostics rather than
falling back. Saving validates each ceiling; it does not promise a general schema
satisfiability solver. Preview checks a concrete candidate against all ceilings.
Omitted constraints add no limit; an empty network ceiling permits
no additions. Existing Driver capabilities and platform limits remain binding.
No Guardrail can enable an unsupported feature or create an IAM grant.

Network containment reuses the [existing matcher](../../packages/contracts/src/sandbox-policy.ts):
exact executable paths, its defined DNS wildcard semantics, and complete range
coverage. JSON Schema alone cannot prove this relationship. `maxAdditions` bounds
array length; it does not bound the authority of a wildcard entry. Defaults and
generated transport rules remain separately owned and are not silently described
as covered by an additions ceiling.

## Ownership and enforcement

An **Installation administrator** is an actor currently allowed `administer` on
the exact singleton Installation by base IAM authorization, including existing
Restrictions but excluding Guardrails. This avoids recursive evaluation; a role
name or Namespace/Agent administration alone does not qualify. Such actors bypass
all global and Namespace Guardrail denies and configuration ceilings for their
operations, including prerequisite and additional Agent-identity checks. Ordinary
IAM grants, Restrictions, base validation, startup ceilings, and platform limits
still apply. This exemption grants no permanent authority to a deployed Agent.

OCC owns Guardrail CRUD, scope, policy versions, persistence and attributable
audit. The selected IAM Driver owns identity/Group/Role resolution and evaluates
deny rules alongside existing Restrictions. Extend its decision evidence with
matched Guardrail IDs/generations and require a complete targeting result for
configuration checks; a missing capability is unavailable, never an empty match.
Do not derive targeting from the first successful grant alone.

Configuration Drivers validate their domain; they cannot choose which Guardrails
apply or grant an exemption. API and worker use the same admission path:

1. Authenticate; resolve server-owned scope; authorize the exact operation and
   determine the original actor's current administrator status through base IAM.
2. Load current global/Namespace Guardrails and IAM targeting in the policy-consistent
   State unit. Unless bypassed, a matching deny stops the operation before effects.
3. Build the complete effective configuration after defaults, Presets, overlays,
   Secret references and Driver contributions. Validate base schemas and every
   non-bypassed matching ceiling. Inspect references, never secret plaintext.
4. Persist only under a current policy/version check. Record the applied policy
   generations and any bypass with its administrator-authority evidence in the
   audit record. Preview is not an authorization token.
5. Recheck queued work before effects against current policy and the original
   actor's current administrator status, never the worker's identity. Without a
   current bypass, recheck Agent identity where applicable and reject violations.

Cover Configuration create/update, Preset materialization, provisioning,
deployment/redeployment/rollback, SandboxPolicy save/apply, and worker retries.
Templates with unresolved variables receive structural checks at save and full
checks at materialization; never label them preapproved. No later transformation
may widen a validated candidate. Repair identity-access-coverage checks too:
their current assumption that Restrictions affect everyone equally becomes false
with targeted Guardrails.

**Confirmed first-release boundary:** new decisions and pending effects use current
policy; tightening does not inspect, change, or terminate running Agents.
Subsequent operations on existing resources, including configuration saves,
deployments, and live SandboxPolicy applications, still pass through admission.
This RFC provides no assessment of whether existing deployed configuration meets
current Guardrails. Resource inspection, compliance reporting, and automatic
remediation require separate scope; admission evidence is not current compliance.

Replace the temporary sandbox editing switch with ordinary exact `manage_policy`
and policy `update` grants plus Guardrail denials. Preserve the startup network
ceiling as an additional operator-owned bound initially. Fresh bootstrap must
explicitly deny delegated SandboxPolicy updates until an administrator configures
the intended policy; removing a deny still grants no permissions. Do not preserve
a hidden per-Agent exception or present defaults as mutable ceilings.

## API, IAM, and console

Proposed routes use the existing `{ data, meta }` and error envelopes:

| Routes                                             | Operations                                              |
| -------------------------------------------------- | ------------------------------------------------------- |
| `/installation/guardrails` and `/{id}`             | Global collection GET/POST; item GET/PUT/DELETE.        |
| `/namespaces/{namespaceId}/guardrails` and `/{id}` | Namespace equivalents; route and body scope must agree. |

PUT replaces content with `expectedGeneration`; DELETE also requires the current
generation. Scope changes require a new resource. Invalid policies return field
errors; stale generations return conflict. Policy state and mutation audit commit
atomically. Namespace deletion removes only its own Guardrails and audits cleanup.
Referenced IAM identity/Group/Role deletion returns conflict until selectors are
removed or changed; it must not silently disable them.

Add `guardrail` permissions `create`, `read`, `update`, `delete`: create checks the
parent scope; item operations check the exact Guardrail. Initially all mutations
additionally require Installation `administer`, and Namespace operations require
Namespace `read`. Exclude Guardrail administration from deny-rule targets. The
administrator bypass also covers prerequisite Guardrail denials, including
Namespace reads, so a policy cannot block its own repair. Base IAM permissions
remain required. Delegated Namespace policy administration is deferred.

Extend existing configuration/policy views with effective schema, safe ceiling
details, policy generations and field errors. Return these only to authorized
configuration readers; complete Guardrail documents require Guardrail read.
An effective view shows inherited global constraints separately from local ones.
Non-bypassed editors explain disabled choices and read-only fields with their
limiting rule. Administrator editors show base-schema choices and the bypass.
These views describe candidate admission limits, not existing-resource compliance.
JSON, CLI and HTTP have identical admission.
Do not silently clamp values or erase an invalid draft. A read-only field is a
constraint, not merely a disabled widget.

## Alternatives, decisions, and proof

Reusing only Restrictions cannot express configuration containment. Copying the
whole AWS condition language adds unsupported resource semantics. Arbitrary
JSON Schema alone handles field values but not network containment. A generic
Driver configuration registry is unnecessary for these two explicit callers.

The author confirmed matching-binding constraints, a blanket Installation
administrator bypass, and prospective enforcement. Existing-resource inspection
and compliance reporting are explicitly deferred.
The RFC remains Proposed; these choices do not constitute architecture acceptance.

Required implementation proof must use real API, IAM and PostgreSQL paths: global
plus Namespace composition, alternate grants, Group changes, cross-Namespace
denials, policy-version races, stale previews, safe errors, and zero effects after
denial. Extend the normal Agent workflow to prove allowed save/deploy/application
and refused widening, including wildcard/range and removed-parent cases. Prove
final native values and actual sandbox behavior with a qualified runtime. Include
policy cleanup and that tightening alone leaves running Agents unchanged. Prove
administrator repair despite a
Namespace-read deny, bypassed configuration admission, continued base/startup
limits, and loss of bypass before queued effects. After tightening a ceiling,
prove that a subsequent non-bypassed save, deployment, or live application that
exceeds it is denied. Console changes require rebuilt Storybook, screenshots, and video;
fixtures do not prove backend enforcement.

No implementation or runtime proof is included in this RFC. Source baseline:
`5f494a0fdf8f36f5b4cdf0a2886987ca49a5248c`. This single decision document keeps
targeting, the ceiling interface, and enforcement boundaries together for review.

## Manual Notes

[keep this for the user to add notes. do not change between edits]

## Changelog

- 2026-10-19: Deferred existing-resource inspection and compliance reporting; retained admission enforcement and the administrator bypass.
- 2026-10-19: Drafted Guardrail scope, binding selectors, configuration ceilings, and admission boundaries from the proposed outline and current contracts.
