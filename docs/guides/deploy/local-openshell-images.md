# Select local OpenShell candidate images

Use a fresh [local OpenShell development profile](local-kubernetes-development.md#start-the-openshell-fail-closed-profile)
to validate a reviewed candidate. First build or obtain all three images in the
selected local Docker or Podman engine. Keep an independent build receipt that
maps the OpenShell source tree and full commit, build inputs, Linux platform, and
immutable image digests. The launcher does not build candidate OpenShell images.

Each image needs an engine-resolvable `name@sha256:...` manifest reference. For
Docker, inspect the local image's `RepoDigests`:

```bash
docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' <image>
```

Use a returned reference; do not construct one from the image's `Id`. Docker's
classic image store may leave `RepoDigests` empty after a local build. In that
case, prepare the image through an engine that retains named manifest digests,
or publish and pull it through a registry you control before launching. The
launcher does not perform that registry step.

From the repository root, rebuild the CLI and replace every placeholder below
with the reviewed source commit and local image references:

```bash
pnpm cli:build
export OCC_DEVELOPMENT_COMPUTE_DRIVER=kubernetes
export OCC_DEVELOPMENT_CONTROL_PLANE=kubernetes
export OCC_DEVELOPMENT_SANDBOX_DRIVER=openshell
export OCC_DEVELOPMENT_OPENSHELL_SOURCE_REVISION='<40 lowercase hex characters>'
export OCC_DEVELOPMENT_OPENSHELL_GATEWAY_IMAGE='<gateway-name>@sha256:<64 lowercase hex characters>'
export OCC_DEVELOPMENT_OPENSHELL_SANDBOX_IMAGE='<sandbox-name>@sha256:<64 lowercase hex characters>'
export OCC_DEVELOPMENT_OPENSHELL_SUPERVISOR_IMAGE='<supervisor-name>@sha256:<64 lowercase hex characters>'
./scripts/dev-up
```

These selectors also work with the Compose control plane. Supplying any one,
even an empty value, requires all four. Image names may include a tag, but must
end in an exact SHA-256 digest. Before creating state or cluster resources, the
launcher rejects incomplete or malformed selections, unavailable local images,
and images whose `org.opencontainers.image.revision` label differs from the
selected OpenShell commit. That commit identifies OpenShell, not the OCE checkout.
Labels establish consistency, **not build provenance**; verify the build receipt
independently. Candidate images are never pulled or replaced with released
images. If one disappears before import, startup fails and attempts to roll back owned resources. Follow the printed
recovery instructions if rollback is incomplete.

Chart selection remains separate. An image selection does not change the pinned
charts; use the [paired chart overrides](local-kubernetes-development.md#start-the-openshell-fail-closed-profile)
when the reviewed candidate needs matching charts. A chart override alone does
not select candidate images.

## Verify imported identities

Keep the launcher's three `OpenShell <component> image: source=… containerd=…`
lines with the build receipt. The source digest identifies the selected engine
image; containerd may record a different manifest representation after archive
import. The launcher resolves and registers that containerd digest, then supplies
it to exactly `gateway.image`, `sandboxRuntime.image`, and `supervisor.image`
in Helm, with pull policy `Never`. Do not assume source and containerd digests
are equal.

Before runtime qualification, inspect the actual supervisor container's
`imageID` in the Agent-owned Pod using the printed kubeconfig and context.
Check both `status.containerStatuses` and `status.initContainerStatuses`, and
resolve the recorded identity through the node's containerd inventory to the
imported supervisor and build receipt. Helm values alone do not prove which
image ran. Launcher success does not prove a model turn or end-to-end Agent
execution; follow the [OpenShell verification procedures](../../testing/openshell.md).

For invalid or missing candidates, correct the selectors or prepare the missing
local images and retry. Follow any printed cleanup instruction if startup
retains state. To return to released defaults on the next fresh start, **unset**
all four candidate selectors; assigning empty values is an error.
