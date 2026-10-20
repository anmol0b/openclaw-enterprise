# OpenShell Git refusals

When the worker refuses a request on the [OpenShell Git route](openshell-git.md),
OpenShell answers `403` before GitHub sees the request. The response body names a
short reason code that says what the Agent can do. It never contains a token, an
installation ID or an internal hostname.

## What the Agent sees

Git does not print the body of a JSON error response. A refused clone, fetch or
`ls-remote` shows only `The requested URL returned error: 403` (exit 128). A
refused push shows `error: RPC failed; HTTP 403`, then
`fatal: the remote end hung up unexpectedly`, and may end with
`Everything up-to-date` (exit 1). That last line does not mean there was nothing
to push: the push never reached GitHub.

To see the reason, rerun the command with Git's HTTP trace and look for
`reason_code`. Git redacts the authorization header in this trace:

```bash
GIT_TRACE_CURL=1 git ls-remote origin 2>&1 | grep -o '"reason_code":"[a-z_]*"'
```

The draft helper prints the code and the matching advice itself, for example
`Draft not created: the repository route refused it (access_withdrawn); GitHub did not receive it.`

## Reason codes

| Code                          | Meaning                                                                                                                   | What to do                                                                             |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| `request_not_allowed`         | The binding does not admit this request: another branch, tag or repository, a non-draft or other-base create, an API call | Do not retry. Change the request or ask an operator                                    |
| `draft_already_opened`        | The grant's one draft was already created                                                                                 | Find it at GitHub; see the [draft limit](openshell-git.md#use-the-admitted-repository) |
| `access_withdrawn`            | This version's repository access ended: the binding was removed, or the version was replaced or stopped                   | Do not retry. An operator binds and deploys                                            |
| `credential_unavailable`      | The route lost its credential, for example because GitHub rejected the App key                                            | An operator recovers the key and deploys                                               |
| `route_blocked`               | The worker closed this version's route for good, for example after the Sandbox was replaced                               | An operator deploys a new version                                                      |
| `route_not_ready`             | The route is starting, verifying or briefly unavailable                                                                   | Retry in a minute                                                                      |
| `online_authorization_denied` | The worker did not answer in time, or could not match the request to one of its routes                                    | Retry once, then ask an operator                                                       |

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
