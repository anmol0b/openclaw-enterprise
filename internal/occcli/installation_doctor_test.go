package occcli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	const migration = `"scripts/migrate-production.mjs"`
	failed := strings.Replace(strings.Replace(job, `"type":"Complete"`, `"type":"Failed"`, 1), `"succeeded":1`, `"failed":1`, 1)
	guarded := strings.Replace(job, migration, migration+`, "--expect-empty"`, 1)
	checkScript, err := os.ReadFile("../../deploy/helm/openclaw-enterprise/files/check-installation.mjs")
	if err != nil {
		t.Fatal(err)
	}
	checkArg, err := json.Marshal(string(checkScript))
	if err != nil {
		t.Fatal(err)
	}
	asUpgrade := func(job string) string {
		return strings.Replace(job, `"initContainers":[`, `"initContainers":[{"name":"installation-check","command":["node"],"args":["--input-type=module","-e",`+string(checkArg)+`]},`, 1)
	}
	for _, tc := range []struct {
		name       string
		status     int
		body, want string
		success    bool
		uid        string
	}{
		{"install", 200, job, "Initialization Job (install hook): complete", true, ""},
		{"guarded-install", 200, guarded, "Initialization Job (install hook): complete", true, ""},
		{"upgrade", 200, asUpgrade(job), "upgrade hook): complete", true, ""},
		{"wrong-upgrade-check", 200, strings.Replace(asUpgrade(job), string(checkArg), `"process.exit(0)"`, 1), "steps do not match", false, ""},
		{"guarded-upgrade", 200, asUpgrade(guarded), "steps do not match", false, ""},
		{"extra-install-arg", 200, strings.Replace(guarded, `"--expect-empty"`, `"--expect-empty","unexpected"`, 1), "steps do not match", false, ""},
		{"wrong-release", 200, strings.Replace(job, `io/instance":"demo"`, `io/instance":"other"`, 1), "did not identify", false, ""},
		{"deleting", 200, strings.Replace(job, `"uid":"id"`, `"uid":"id","deletionTimestamp":"now"`, 1), "did not identify", false, ""},
		{"external-controller", 200, strings.Replace(job, `"spec":{"template"`, `"spec":{"managedBy":"example.invalid/handoff-readback","template"`, 1), "unsupported Job controller", false, "id"},
		{"no-condition", 200, strings.Replace(job, "Complete", "SuccessCriteriaMet", 1), "completion not established", false, ""},
		{"wrong-steps", 200, strings.Replace(job, "migrate-production.mjs", "sensitive-detail", 1), "do not match", false, ""},
		{"missing", 404, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"jobs.batch \"demo-initialization\" not found"}`, "not found at the selected target", false, ""},
		{"denied", 403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"sensitive-detail"}`, "unknown. Could not read", false, ""},
		{"pinned-denied", 403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"sensitive-detail"}`, "unknown. Could not read", false, "old"},
		{"pinned-missing", 404, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"jobs.batch \"demo-initialization\" not found"}`, "original outcome remains unknown", false, "old"},
		{"pinned", 200, job, "matches the recorded UID", true, "id"},
		{"replaced", 200, job, `expected UID "old", observed UID "id"`, false, "old"},
		{"pinned-failed", 200, failed, "Initialization Job: failed", false, "id"},
		{"pinned-failing", 200, strings.Replace(failed, "Failed", "FailureTarget", 1), "completion not established", false, "id"},
		{"pinned-active-failed", 200, strings.Replace(failed, `"failed":1`, `"failed":1,"active":1`, 1), "completion not established", false, "id"},
		{"pinned-terminating-failed", 200, strings.Replace(failed, `"failed":1`, `"failed":1,"terminating":1`, 1), "completion not established", false, "id"},
		{"conflicting-terminal-conditions", 200, strings.Replace(job, `"conditions":[`, `"conditions":[{"type":"Failed","status":"True"},`, 1), "completion not established", false, "id"},
		{"suspended-complete", 200, strings.Replace(job, `"conditions":[`, `"conditions":[{"type":"Suspended","status":"True"},`, 1), "completion not established", false, "id"},
		{"unpinned-failed", 200, failed, "Initialization Job: failed", false, ""},
		{"replaced-failed", 200, failed, "original outcome remains unknown", false, "old"},
		{"unsafe-uid-failed", 200, strings.Replace(failed, `"uid":"id"`, `"uid":"a,b"`, 1), "Initialization Job: failed", false, "a,b"},
		{"no-uid", 200, strings.Replace(job, `"uid":"id",`, "", 1), "did not identify", false, "old"},
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
				args := []string{"installation", action, "--kubeconfig", config, "--context", "read", "--kube-namespace", "operations", "--release", "demo"}
				if tc.uid != "" {
					args = append(args, "--expect-job-uid", tc.uid)
				}
				out, stderr, err := runHelp(t, args...)
				if (err == nil) != tc.success || stderr != "" || requests.Load() != 1 || strings.Contains(out, "sensitive-detail") {
					t.Errorf("out=%s stderr=%s err=%v requests=%d", out, stderr, err, requests.Load())
				}
				expected := []string{tc.want, "Do not replay", "removal unknown", "not qualified"}
				if action == "plan" {
					first := map[string]string{"denied": "permission to get", "missing": "first-install intent", "install": "1. Establish whether", "guarded-install": "1. Establish whether", "upgrade": "1. Establish whether", "pinned": "1. Resume after migration", "replaced": "1. Recover the original installation record", "pinned-missing": "1. Recover the original installation record", "pinned-denied": "permission to get"}[tc.name]
					expected = []string{tc.want, first, "2. If an API operation was attempted", "3. Verify temporary access", "4. Qualify useful work"}
				}
				wantLookup := action == "plan" && tc.name == "pinned-failed"
				if strings.Contains(out, "get pods") != wantLookup {
					t.Errorf("want operator Pod lookup %v in %s", wantLookup, out)
				}
				if tc.success {
					expected = append(expected, `operations/demo-initialization, UID "id"`)
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

func TestInstallationDoctorRejectsEmptyExpectedUID(t *testing.T) {
	_, _, err := runHelp(t, "installation", "doctor", "--kubeconfig", "unused", "--context", "unused", "--kube-namespace", "demo", "--release", "demo", "--expect-job-uid=")
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("error = %v", err)
	}
}

func TestFailedJobPodLookupShellArguments(t *testing.T) {
	config, kctx := "/path/with space/operator's config", "reader '$USER"
	guidance := failedJobPodLookup(config, kctx, "operations", "abc-123")
	lines := strings.Split(guidance, "\n")
	if len(lines) != 3 {
		t.Fatalf("missing command in %q", guidance)
	}
	// Ask the shell how it parsed the displayed command. Do not run kubectl.
	script := `kubectl() { printf '%s\n' "$@"; }; ` + lines[1]
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	want := []string{"--kubeconfig=" + config, "--context=" + kctx, "--namespace=operations",
		"get", "pods", "--selector=batch.kubernetes.io/controller-uid=abc-123", "-o",
		"custom-columns=POD:.metadata.name,CONTROLLER_UID:.metadata.ownerReferences[?(@.controller==true)].uid"}
	if !slices.Equal(got, want) {
		t.Fatalf("arguments: %q, want %q", got, want)
	}
}
