---
rfc: index.md
---

# Proposed amendment: named workspace first installation

**Status: Proposed — awaiting decision.**

Offer a fresh, single-namespace installation in which the operator provisions
the physical Kubernetes Namespace. Enabling the usual authorized GitHub sign-in
does not expand Kubernetes Namespace permissions. The default installation and its cluster-wide Namespace
permissions remain unchanged. Profiles with a declared startup dependency also
need the ordering below to run their first work.

## Two-stage installation and identity

1. Run only the existing database initialization. Its genuine bootstrap
   transaction creates the Installation, local recovery administrator and
   logical OCE Namespace, records audit events, and queues Namespace work. Do
   not deploy the API or worker or grant their RBAC in this stage. Record the
   actual OCE Namespace ID from the committed result. If the result is
   uncertain, read authoritative state and resolve the outcome; do not rerun
   the transaction while it remains uncertain.
2. The operator creates a new physical Kubernetes Namespace using the name
   derived from that OCE ID and records the server-assigned UID. Bind only
   after verifying the name, UID and OCE ID together, ownership and restrictions.
   Do not adopt an existing Namespace. Attach the API and worker to the existing
   database; do not replay initialization or pre-upgrade work.

For this option, the API and worker receive Namespace `get` only for the exact
named resource, plus ordinary `/version` access. They receive no Namespace
`list`, `watch`, creation or mutation permissions. Tenant permissions are
separate and must be scoped and verified independently. Verify effective
permissions, including grants from other bindings, before use. Missing,
mismatched or forbidden Namespace access fails closed; do not create or adopt a
replacement.

Keep the existing recovery administrator, federated login and authorization
controls, and public host rules. GitHub sign-in authenticates an eligible user;
it does not itself grant access or administrative authority.

## Start without consuming queued work

Some profiles have a startup cycle: the gateway needs an authenticated service
hosted with the worker before the gateway is usable, while the first queued
reconcile needs the gateway. For a profile that declares such a dependency,
start with the worker's claim gate closed, before recovery or claiming begins.
The worker may load database and IAM state, run its compute preflight, and serve
restricted authenticated admission and a healthy broker so the dependency can
come up. Separately deny unwanted work and provider actions while gated.
Publish a ready Service endpoint only when that transport can actually serve;
do not publish unready endpoints or report reconciliation as complete.

An independent read-only check must confirm the declared dependency is ready
before the normal worker and claim path is enabled. Report missing identity or
forbidden access separately from a dependency that is merely not ready. The
gate applies only to profiles declaring a startup dependency, not general
deployment orchestration.

On every restart, close the gate before recovery and claiming. Preserve queued
work identity, attempt counts, leases and age; if work is too old, report that
condition instead of racing a retry against recovery. Reopen only after the
independent check succeeds, then follow the normal recovery and claim rules.

## Acceptance

- A fresh installation records the original bootstrap transaction, audit and
  queued work, followed by separate evidence of operator preparation and the
  verified physical Namespace name and UID. An uncertain bootstrap is resolved
  by reading state, without a second transaction.
- Effective permission checks allow the exact Namespace `get` and `/version`,
  and deny another Namespace `get`, Namespace `list`, `watch`, create, update, patch
  and delete. Tenant grants are checked separately. A mismatched UID, missing
  Namespace or forbidden lookup blocks binding and work without adoption.
- With the dependency held unavailable, authenticated limited transport can be
  ready while the original work remains unclaimed and no attempts are consumed.
  No unwanted work or provider action runs. Releasing the dependency permits the
  original work to converge under normal claim rules, without a second bootstrap
  or an attempt-count reset.
- A crash and restart closes the gate before recovery; retained identity,
  attempts, leases and age remain visible, including an explicit too-old result.
  Recovery does not race a retry. Missing identity, forbidden access and
  not-ready are distinguishable.
- Report source and test, deployment and runtime, and GitHub sign-in and
  authorization evidence separately. This proposal establishes none of them.
