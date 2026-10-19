package occcli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// Use real kubectl against a local API, including its actual NotFound rendering.
// Assert the wire operation, not just the arguments given to a mock executable.
func TestInstallationDoctor(t *testing.T) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		t.Skip("requires kubectl")
	}
	const job = `{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"demo-initialization","namespace":"operations","uid":"id","labels":{"app.kubernetes.io/instance":"demo","app.kubernetes.io/name":"openclaw-enterprise","app.kubernetes.io/component":"initialization","app.kubernetes.io/managed-by":"Helm"},"annotations":{"helm.sh/hook":"pre-install,pre-upgrade"}},"spec":{"template":{"spec":{"initContainers":[{"name":"migration","args":["scripts/migrate-production.mjs"]}],"containers":[{"name":"bootstrap","args":["scripts/bootstrap-installation.mjs"]}]}}},"status":{"succeeded":1,"conditions":[{"type":"Complete","status":"True"}]}}`
	for _, tc := range []struct {
		name       string
		status     int
		body, want string
		success    bool
	}{
		{"install", 200, job, "Initialization Job (install hook): complete", true},
		{"upgrade", 200, strings.Replace(job, `"initContainers":[`, `"initContainers":[{"name":"installation-check"},`, 1), "upgrade hook): complete", true},
		{"wrong-release", 200, strings.Replace(job, `io/instance":"demo"`, `io/instance":"other"`, 1), "did not identify", false},
		{"deleting", 200, strings.Replace(job, `"uid":"id"`, `"uid":"id","deletionTimestamp":"now"`, 1), "did not identify", false},
		{"no-condition", 200, strings.Replace(job, "Complete", "SuccessCriteriaMet", 1), "completion not established", false},
		{"wrong-steps", 200, strings.Replace(job, "migrate-production.mjs", "sensitive-detail", 1), "do not match", false},
		{"missing", 404, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"jobs.batch \"demo-initialization\" not found"}`, "not found at the selected target", false},
		{"denied", 403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"sensitive-detail"}`, "unknown. Could not read", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != "GET" || r.URL.RequestURI() != "/apis/batch/v1/namespaces/operations/jobs/demo-initialization" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer s.Close()
			config := filepath.Join(t.TempDir(), "kubeconfig")
			contents := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: test, cluster: {server: %s}}]
contexts: [{name: read, context: {cluster: test}}]
`, s.URL)
			if err := os.WriteFile(config, []byte(contents), 0600); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{"doctor", "plan"} {
				requests.Store(0)
				out, stderr, err := runHelp(t, "installation", action, "--kubeconfig", config, "--context", "read", "--kube-namespace", "operations", "--release", "demo")
				if (err == nil) != tc.success || stderr != "" || requests.Load() != 1 || strings.Contains(out, "sensitive-detail") {
					t.Errorf("out=%s stderr=%s err=%v requests=%d", out, stderr, err, requests.Load())
				}
				expected := []string{tc.want, "Do not replay", "removal unknown", "not qualified"}
				if action == "plan" {
					first := map[string]string{"denied": "permission to get", "missing": "first-install intent", "install": "Resume after migration", "upgrade": "Resume after migration"}[tc.name]
					expected = []string{tc.want, first, "2. If an API operation was attempted", "3. Verify temporary access", "4. Qualify useful work"}
				}
				for _, want := range expected {
					if !strings.Contains(out, want) {
						t.Errorf("want %q in %s", want, out)
					}
				}
			}
		})
	}
}
