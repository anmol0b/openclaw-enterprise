# Test Agent OAuth connections locally

Start a disposable k3d stack that can hold
[Agent OAuth connections](../../reference/connection-templates.md), then connect
a Google account to a personal Agent with the
[Gmail guide](google-gmail-connection.md). This profile is for development only.

## Start the profile

Meet the [Kubernetes-only profile prerequisites](local-kubernetes-development.md#start-the-profile).
Use a fresh state directory. Startup downloads `gog` from GitHub.

```bash
pnpm cli:build
export OCC_DEVELOPMENT_COMPUTE_DRIVER=kubernetes
export OCC_DEVELOPMENT_CONTROL_PLANE=kubernetes
export OCC_DEVELOPMENT_SANDBOX_DRIVER=openshell
export OCC_DEVELOPMENT_CONNECTIONS=openshell
./scripts/dev-up
```

Expected result: the ready message also prints:

```text
Agent OAuth connections: enabled
  Callback URI: http://127.0.0.1:3000/oauth/callback
  Client Workspace: oce-oauth-clients
  Connection tool: /usr/local/bin/gog (gog 0.36.0)
```

Startup refuses `OCC_DEVELOPMENT_CONNECTIONS` with any other profile.

## What the profile configures

| Component                 | Setting                                                                                                                                                                                                                                                 |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenShell gateway         | HTTPS from a private development CA. A client certificate with `OU=operator` grants gateway administration. Sandboxes still authenticate with gateway-issued tokens; other OCC calls send no token, so NetworkPolicy remains their boundary.            |
| OpenShell Backend         | `https` endpoint, `rootCertificatePath`, and `operatorTls` from the Secret `openclaw-openshell-tls`, mounted at `/etc/openclaw/openshell-tls`.                                                                                                          |
| Credential Refresh Driver | `clientWorkspace: oce-oauth-clients`. Startup creates that Workspace and its Kubernetes namespace.                                                                                                                                                      |
| API egress                | TCP 443 to any address except `169.254.0.0/16`, for the callback's code exchange.                                                                                                                                                                       |
| Runtime image             | `openclaw-enterprise-runtime:connections` trusts the CA, so Agent Gateways reach sandboxes over HTTPS. It adds `gog` 0.36.0 at `/usr/local/bin/gog`, checked against the release SHA-256. The Credential Gateway's `toolBinaries` lists only that path. |

The CA, certificates, and keys stay in the state directory for three months.
`dev-down` deletes them with the cluster.

## Create a Google client for the loopback callback

Follow [Create the Google OAuth client](google-gmail-connection.md#create-the-google-oauth-client)
with these local differences:

- Choose **Desktop app**. Google accepts its `http://127.0.0.1` loopback
  redirect without registering the URI.
- In **Testing** mode, add each Google account that will connect as a test user.
- Save the downloaded JSON with mode `0600` outside the repository. Do not paste it.

## Connect and check

Continue the [Gmail guide](google-gmail-connection.md#create-the-connection-template)
with `OCC_URL=http://127.0.0.1:3000`. Locally, you can create and share the
template with the CLI and the service key file that startup prints, instead of
an administrator session:

```bash
export OCC_URL=http://127.0.0.1:3000
export OCC_SERVICE_KEY_FILE=<service key file>
./bin/occ connection-template create --file "$PRIVATE_DIR/template.json"
./bin/occ connection-template bind <templateId> --namespace <namespaceId>
```

Sign in to `http://127.0.0.1:3000/console/` as the person who connects, and
start the connection from that tab. After the callback, that person must deploy
the Agent: a connected Agent refuses deployment by anyone else, including the
service key.

The OpenShell gateway logs `provider credential refresh completed` with
`credential_key=GOG_ACCESS_TOKEN` after the first token is issued.

## Limits

- This profile serves no browser chat for OpenShell Harnesses, so the console
  cannot ask the Agent to run `gog`.
- `scripts/first-agent.mjs` Agents deny all tools until you remove `tools.deny`
  from their Configuration.
