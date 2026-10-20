# OpenShell Git refusals

When the worker refuses a request on the [OpenShell Git route](openshell-git.md),
OpenShell answers `403` before GitHub sees the request. The response body carries
a short reason code (`reason_code`) that says what the Agent can do. The code never
names a token, an installation ID or an internal hostname.

## What the Agent sees

Git does not print the body of a JSON error response. When OpenShell refuses the
first request of a clone, fetch, `ls-remote` or push, Git shows only
`The requested URL returned error: 403` (exit 128). When it refuses only the
push's upload, usually `request_not_allowed` for another branch or tag, Git
shows `error: RPC failed; HTTP 403`, then
`fatal: the remote end hung up unexpectedly`, and may end with
`Everything up-to-date` (exit 1). That last line does not mean there was nothing
to push: the push never reached GitHub.

To see the reason, rerun with Git's HTTP trace, which redacts the authorization
header. The trace splits the body across lines, so join them first:

```bash
GIT_TRACE_CURL=1 git ls-remote origin 2>&1 | sed -n 's/.*<= Recv data: //p' \
  | tr -d '\n' | grep -o '"reason_code":"[a-z_]*"'
```

The draft helper prints the code and the matching advice itself, for example
`Draft not created: the repository route refused it (access_withdrawn); GitHub did not receive it.`

## Reason codes

| Code                          | Meaning                                                                                                                      | What to do                                                                             |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `request_not_allowed`         | The binding does not admit this request: another branch, tag or repository, a non-draft or other-base create, an API call    | Do not retry. Change the request or ask an operator                                    |
| `draft_already_opened`        | The grant's one draft was already created                                                                                    | Find it at GitHub; see the [draft limit](openshell-git.md#use-the-admitted-repository) |
| `access_withdrawn`            | This version's repository access ended: the binding was removed, the version was replaced or stopped, or its session expired | Do not retry. An operator binds and deploys                                            |
| `credential_unavailable`      | The route lost its credential, for example because GitHub rejected the App key or a renewal failed                           | An operator checks the worker log; a rejected key needs a new deploy                   |
| `route_blocked`               | The worker closed this version's route for good, for example after the Sandbox was replaced                                  | An operator deploys a new version                                                      |
| `route_not_ready`             | The route is starting, verifying or briefly unavailable                                                                      | Retry in a minute                                                                      |
| `online_authorization_denied` | The worker did not answer in time, or could not match the request to one of its routes                                       | Retry once, then ask an operator                                                       |

A version that is still deploying has no credential yet, so its requests answer
`route_not_ready` until it is active.

## Worker log

Each refused request logs one `worker.openshell-git-denied` line. Its `reasonCode`
is the code above, and its `reason` is the worker's detailed cause, such as
`ref_not_allowed`, `draft_rejected`, `session_closed`, `material_unavailable`,
`installation_changed` or `route_blocked`. The line also carries the Sandbox ID and
the request ID that the supervisor's own log shows. The
`worker.openshell-git-route-warning` line for a lost credential carries the same
`reasonCode`, so an alert can tell a removed binding (`access_withdrawn`) from a
rejected App key (`credential_unavailable`).
