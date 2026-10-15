package occdev

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestProtectedEgressSelectionFailsBeforeEffects(t *testing.T) {
	env := candidateOpenShellEnvironment()
	env["OCC_DEVELOPMENT_PROTECTED_EGRESS"] = "1"
	for _, key := range []string{"OCC_DEVELOPMENT_CONTROLLER_IMAGE", "OCC_KUBERNETES_RUNTIME_IMAGE"} {
		env[key] = "registry.example/runtime@" + profileTestDigest
	}
	for _, key := range []string{"OCC_DEVELOPMENT_OPENSHELL_HELM_CHART", "OCC_DEVELOPMENT_OPENSHELL_WORKSPACE_HELM_CHART"} {
		env[key] = "/explicit/chart"
	}
	r := &runner{env: env}
	if enabled, err := r.protectedEgressSelection("kubernetes", "openshell"); err != nil || !enabled {
		t.Fatalf("complete explicit selection refused: %v", err)
	}
	for _, pair := range [][2]string{{"compose", "openshell"}, {"kubernetes", "none"}} {
		if _, err := r.protectedEgressSelection(pair[0], pair[1]); err == nil {
			t.Fatal("protected mode accepted an unsupported profile")
		}
	}
	for key, value := range env {
		if key == "OCC_DEVELOPMENT_PROTECTED_EGRESS" {
			continue
		}
		delete(env, key)
		if _, err := r.protectedEgressSelection("kubernetes", "openshell"); err == nil {
			t.Fatalf("accepted missing %s", key)
		}
		env[key] = value
	}
	// Only an explicitly selected owned private host can receive the native alias.
	for _, address := range []string{"", "127.0.0.1", "0.0.0.0", "169.254.169.254", "8.8.8.8", "::1", "172.030.42.1", "host.example.test"} {
		env["OCC_DEVELOPMENT_OPENSHELL_HOST_GATEWAY_IP"] = address
		if _, err := r.protectedEgressSelection("kubernetes", "openshell"); err == nil {
			t.Fatalf("accepted unsupported host alias address %q", address)
		}
	}
	env["OCC_DEVELOPMENT_OPENSHELL_HOST_GATEWAY_IP"] = "172.30.42.1"
	if _, err := r.protectedEgressSelection("kubernetes", "openshell"); err != nil {
		t.Fatal(err)
	}
	env["OCC_DEVELOPMENT_PROTECTED_EGRESS"] = "0"
	if _, err := r.protectedEgressSelection("kubernetes", "openshell"); err == nil {
		t.Fatal("unprotected profile silently accepted host alias configuration")
	}
	delete(env, "OCC_DEVELOPMENT_OPENSHELL_HOST_GATEWAY_IP")
	for _, value := range []string{"true", "yes", "2"} {
		env["OCC_DEVELOPMENT_PROTECTED_EGRESS"] = value
		if _, err := r.protectedEgressSelection("kubernetes", "openshell"); err == nil {
			t.Fatal("accepted ambiguous opt-in")
		}
	}
	for _, value := range []string{"", "0"} {
		r.env = map[string]string{"OCC_DEVELOPMENT_PROTECTED_EGRESS": value}
		if enabled, err := r.protectedEgressSelection("compose", "none"); err != nil || enabled {
			t.Fatalf("default profile changed: %v", err)
		}
	}
}

func TestDevelopmentDatabaseSelectorIsDisposable(t *testing.T) {
	r := &runner{env: map[string]string{}}
	if name, err := r.selectedDevelopmentDatabase("compose"); err != nil || name != "openclaw_enterprise" {
		t.Fatalf("default changed: %s %v", name, err)
	}
	for _, name := range []string{"", "production", "openclaw_enterprise", "openclaw_k8s_", "openclaw_k8s_Foo", "openclaw_k8s_x;DROP DATABASE x", "openclaw_k8s_" + strings.Repeat("a", 51)} {
		r.env["OCC_DEVELOPMENT_DATABASE_NAME"] = name
		if _, err := r.selectedDevelopmentDatabase("kubernetes"); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	r.env["OCC_DEVELOPMENT_DATABASE_NAME"] = "openclaw_k8s_connected"
	if _, err := r.selectedDevelopmentDatabase("compose"); err == nil {
		t.Fatal("Compose accepted an unsupported database selector")
	}
	if name, err := r.selectedDevelopmentDatabase("kubernetes"); err != nil || name != "openclaw_k8s_connected" {
		t.Fatalf("valid database refused: %v", err)
	}
}

// Run the normal release coordinator with command-boundary fixtures. The resulting
// Installation is loaded by real controller composition, and both charts are
// rendered by real Helm. This proves packaging/order, not Kubernetes or PostgreSQL.
func TestProtectedPlatformInstallationOrdersAuthorityBeforeGatewayReadiness(t *testing.T) {
	supplierChart := os.Getenv("OCC_TEST_OPENSHELL_CHART")
	if supplierChart == "" {
		t.Skip("OCC_TEST_OPENSHELL_CHART selects the matching supplier chart for local packaging proof")
	}
	realNode, err := exec.LookPath("node")
	if err != nil {
		t.Fatal(err)
	}
	helm := os.Getenv("OCC_HELM_BIN")
	if helm == "" {
		helm, err = exec.LookPath("helm")
	}
	if err != nil || helm == "" {
		t.Fatal("set OCC_HELM_BIN to render the normal protected profile")
	}
	state := kubernetesOnlyOpenShellState(t)
	state.ProtectedEgress = true
	state.DatabaseName = "openclaw_k8s_connected"
	state.OpenShellHostGatewayIP = "172.30.42.1"
	assets := &openShellDevelopmentAssets{gatewayChart: supplierChart, gatewayImage: "registry.example/gateway@" + profileTestDigest,
		sandboxImage: "registry.example/sandbox@" + profileTestDigest, supervisorImage: "registry.example/supervisor@" + profileTestDigest,
		workspaceResources: []any{map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": map[string]string{"name": "openshell-sandbox"}}}}
	// No actual engine or cluster command is reachable from the command fixtures.
	t.Setenv("PATH", t.TempDir())
	commands := fakeProfileCommands(t, map[string]string{
		"kubectl": `"get namespace oce-system") ;;
"apply -f "*) ;;
"get secret openshell-gateway-jwt-keys --namespace oce-system -o jsonpath={.data.kid}") echo dGVzdC1raWQ= ;;
"get node k3d-occ-dev-owned-server-0 -o json") echo '{"spec":{"podCIDR":"10.42.0.0/24"}}' ;;
"get service openshell-gateway --namespace oce-system -o jsonpath={.spec.clusterIP}") echo 10.43.0.50 ;;
"-n oce-system get pod bootstrap-password-prepare -o jsonpath={.status.phase}") echo Succeeded ;;
"-n oce-system rollout status statefulset/postgres "*) ;;
"-n oce-system get pod postgres-0 -o jsonpath={.status.podIP}") echo 10.42.0.20 ;;
"-n default get endpoints kubernetes -o jsonpath={.subsets[0].addresses[0].ip}") echo 172.30.42.3 ;;
"-n default get endpoints kubernetes -o jsonpath={.subsets[0].ports[0].port}") echo 6443 ;;
"-n oce-system rollout status deployment/occ-development-api-proxy "*) ;;
"rollout status statefulset/openshell-gateway --namespace oce-system --timeout 1m0s") ;;`,
		"docker": `"exec k3d-occ-dev-owned-server-0 ip route get 10.42.0.2") echo '10.42.0.2 dev cni0 src 10.42.0.1' ;;
"network inspect k3d-occ-dev-owned") echo '[{"IPAM":{"Config":[{"Subnet":"172.30.42.0/24"}]}}]' ;;`,
		"helm": `"upgrade --install openshell-gateway "*) ;;
"upgrade --install openclaw-enterprise "*) ;;`,
	})
	r := newRunner(Options{Repository: state.Repository})
	r.engine = "docker"
	if err := r.installDevelopmentPlatform(context.Background(), state, developmentPlatformInputs{
		openShell: assets, runtimeImage: "registry.example/runtime@" + profileTestDigest,
		controllerImage: "registry.example/controller@" + profileTestDigest, postgresImage: "registry.example/postgres@" + profileTestDigest,
	}, time.Minute); err != nil {
		t.Fatalf("platform packaging failed: %v\n%s", err, strings.Join(commands(), "\n"))
	}
	find := func(prefix string) int {
		i := slices.IndexFunc(commands(), func(s string) bool { return strings.HasPrefix(s, prefix) })
		if i < 0 {
			t.Fatalf("missing operation %s", prefix)
		}
		return i
	}
	gateway := find("helm upgrade --install openshell-gateway ")
	control := find("helm upgrade --install openclaw-enterprise ")
	ready := find("kubectl rollout status statefulset/openshell-gateway ")
	if gateway >= control || control >= ready {
		t.Fatal("the Gateway readiness gate must follow OCE installation")
	}
	if strings.Contains(commands()[gateway], "--wait") || !strings.Contains(commands()[control], "--wait") {
		t.Fatal("incorrect release readiness gates")
	}
	if strings.Contains(strings.Join(commands(), "\n"), "create secret generic openshell-gateway-jwt-keys") {
		t.Fatal("protected mode must leave complete PKI generation to OpenShell")
	}

	// Use the actual startup parser/Driver composition, without provider or cluster I/O.
	program := `import assert from 'node:assert/strict';
import {loadInstallationConfiguration} from './apps/controller/src/composition/installation-config.ts';
const loaded = await loadInstallationConfiguration({mode:'production', environment:{OCC_CONFIG_PATH:process.argv[1]}});
assert.equal(loaded.installation.backend[0].configuration.auth.mode,'mtls');
assert.equal(loaded.egressAuthority.keyId,'test-kid');
assert.equal(loaded.egressAuthority.issuer,'openshell-gateway:openshell-gateway');
assert.equal(loaded.installation.backend[0].drivers.conduit,loaded.conduitDriver.id);
`
	parse := exec.Command(realNode, "--input-type=module", "-e", program, filepath.Join(state.directory, "installation.yaml"))
	parse.Dir = state.Repository
	if out, err := parse.CombinedOutput(); err != nil {
		t.Fatalf("real startup rejected generated profile: %v\n%s", err, out)
	}

	// The generated server leaf must authenticate the exact registry hostname.
	caPEM, _ := os.ReadFile(filepath.Join(state.directory, "egress-ca.crt"))
	leafPEM, _ := os.ReadFile(filepath.Join(state.directory, "egress-tls.crt"))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("authority CA is invalid")
	}
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		t.Fatal("authority leaf is missing")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "openclaw-enterprise-egress-authority.oce-system.svc.cluster.local"}); err != nil {
		t.Fatal(err)
	}

	// Creation, readiness, migration and application URLs select one disposable database.
	postgres := readJSONFile(t, filepath.Join(state.directory, "postgres.json"))
	container := postgres["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
	if container["env"].([]any)[0].(map[string]any)["value"] != state.DatabaseName {
		t.Fatal("database creation selector diverged")
	}
	probe := container["readinessProbe"].(map[string]any)["exec"].(map[string]any)["command"].([]any)
	if probe[len(probe)-1] != state.DatabaseName {
		t.Fatal("database readiness selector diverged")
	}
	secrets := readJSONFile(t, filepath.Join(state.directory, "oce-secrets.json"))["items"].([]any)
	urls := secrets[1].(map[string]any)["stringData"].(map[string]any)
	for key, role := range map[string]string{"application-url": "occ_app", "migration-url": "occ_migrator"} {
		u, err := url.Parse(urls[key].(string))
		if err != nil {
			t.Fatal(err)
		}
		if u.Path != "/openclaw_k8s_connected" || u.User.Username() != role {
			t.Fatalf("database role or selector diverged for %s", key)
		}
	}
	selectedGateway := readJSONFile(t, filepath.Join(state.directory, "openshell-protected-values.json"))
	if selectedGateway["server"].(map[string]any)["hostGatewayIP"] != state.OpenShellHostGatewayIP {
		t.Fatal("selected owned host did not reach the supplier chart input")
	}
	for _, selected := range []struct{ name, chart, values string }{
		{"openclaw-enterprise", filepath.Join(state.Repository, "deploy/helm/openclaw-enterprise"), "helm-values.json"},
		{"openshell-gateway", supplierChart, "openshell-protected-values.json"},
	} {
		args := []string{"template", selected.name, selected.chart, "--namespace", "oce-system", "-f", filepath.Join(state.directory, selected.values)}
		if selected.name == "openshell-gateway" {
			args = append(args, "--set", "agentSandbox.preflight.enabled=false", "--set", "fullnameOverride=openshell-gateway")
		}
		render := exec.Command(helm, args...)
		render.Dir = state.Repository
		out, err := render.CombinedOutput()
		if err != nil {
			t.Fatalf("%s chart refused launch values: %v\n%s", selected.name, err, out)
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(out)))
		count := 0
		for {
			var object map[string]any
			if err := decoder.Decode(&object); err != nil {
				if err == io.EOF {
					break
				}
				t.Fatal(err)
			}
			if object["kind"] != nil {
				count++
			}
		}
		if count == 0 {
			t.Fatalf("%s rendered no resources", selected.name)
		}
	}
}
