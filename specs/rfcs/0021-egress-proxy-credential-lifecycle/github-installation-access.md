# GitHub installation access through the online OpenShell sender

**Proposed addition to RFC-0021.** This mode is opt-in; it does not change the existing prepared Git grant or claim that stock OpenShell meets all of the online qualification requirements.

## Decision

Let an Installation operator grant an Agent the GitHub App installation's actual repository and API permissions. OCE owns admission, the App signing key, issuance, current authorization, withdrawal and retirement. OpenShell remains the only sender and owns credential injection. No separate public Git relay, personal access token or secret in the workspace.

The current prepared Git mode issues a token for one repository, checks one writable ref, and permits one controlled draft. It cannot support routine multi-repository engineering, issues or arbitrary review branches. Keep that mode unchanged. Add a distinct installation-wide policy; never infer it from a missing ref or a wildcard. A Namespace policy and an explicit Agent binding must select it. Changing mode changes the grant fingerprint and requires a new revision and installed material. Do not adopt an earlier narrow token or widen an existing execution on restart.

For installation access, issue a GitHub installation token without `repository_ids` or permission overrides, so GitHub's App installation remains the permission ceiling. Validate the returned token, expiry, repository selection and permission response according to the issuance mode; retain cleanup ownership for rejected or uncertain issuance. The existing single-repository validation remains strict. Separate installation-wide material from narrow material in durable identity, validation and retirement. Never expose installation-wide material through the native repository broker's token-returning operation.

An admitted Agent may use Git smart HTTP for reads and writes on github.com and the ordinary GitHub REST and GraphQL APIs on api.github.com (including the GraphQL operations used by `gh`). No OCE branch, PR-head or draft-only filter applies in this mode; GitHub's installation permissions, branch protection and repository rules still apply. Public Git reads and public REST reads may use the same token. GitHub's exact handling of an explicitly narrowed token on unrelated public repositories is not assumed. For the installation-wide mode the operator has deliberately authorized every private repository the App can access as well. This is **not** a public-only guarantee.

Use a GitHub-host-scoped credential helper and the existing nonsecret OpenShell marker, support ordinary Git and `gh`, and enforce verified HTTPS, the admitted sandbox/installed generation and a current OCE grant on each request. Never inject on another host or redirects to it. Reserve token issuance/retirement to the credential owner; do not expose the App JWT, token endpoint or a generic proxy. Do not interpret a failed or truncated middleware body as an approved operation; document transport size limits and qualify actual pack traffic. API operations may have external effects: an allow is not proof of delivery, and ambiguous writes must be reconciled rather than automatically retried. The existing one-draft receipt is not an installation-wide API deduplication mechanism.

A later independently selected **public-read-only** policy must not inherit installation-wide private reads. It needs an enforceable public-visibility boundary (or material demonstrably unable to read unapproved private repos), read-only methods including Git upload-pack, and the same OCE/OpenShell sender. Merely permitting GET or checking that GitHub returned 200 does not establish public visibility. Do not advertise this narrower policy until tested.

## Acceptance

- Default and existing bindings preserve current narrow issuance, ref and draft restrictions. Unbound or withdrawn executions fail closed, even with a still-valid provider token. Switching modes cannot reuse another Agent's or revision's material.
- From one installed Agent, read an unrelated public repo via REST and Git (including an object transfer); read/write an installed repo and open/update a normal PR and issue. Use controlled repositories for API mutation and branch-protection denial. No forced merge or bypass.
- Verify GitHub refuses a private repository outside the installation. Report actual authenticated REST rate-limit accounting separately from Git traffic. Verify credentials never reach a different host, including redirects.
- Retain stock middleware/transport qualification limits. Separately measure maximum viable Git/REST/GraphQL request sizes. No credential-free fallback or second egress route is introduced by this change.
