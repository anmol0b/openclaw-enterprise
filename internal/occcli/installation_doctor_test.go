package occcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	withSidecar := func(body string) string {
		return strings.Replace(body, `"initContainers":[{`, `"initContainers":[{"restartPolicy":"Always",`, 1)
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
		{"sidecar-migration", 200, withSidecar(job), "runs an initialization step as a sidecar", false, "id"},
		{"sidecar-upgrade-check", 200, withSidecar(asUpgrade(job)), "runs an initialization step as a sidecar", false, "id"},
		{"wrong-upgrade-check", 200, strings.Replace(asUpgrade(job), string(checkArg), `"process.exit(0)"`, 1), "steps do not match", false, ""},
		{"guarded-upgrade", 200, asUpgrade(guarded), "steps do not match", false, ""},
		{"extra-install-arg", 200, strings.Replace(guarded, `"--expect-empty"`, `"--expect-empty","unexpected"`, 1), "steps do not match", false, ""},
		{"wrong-release", 200, strings.Replace(job, `io/instance":"demo"`, `io/instance":"other"`, 1), "did not identify", false, ""},
		{"deleting", 200, strings.Replace(job, `"uid":"id"`, `"uid":"id","deletionTimestamp":"now"`, 1), "did not identify", false, ""},
		{"external-controller", 200, strings.Replace(job, `"spec":{"template"`, `"spec":{"managedBy":"example.invalid/handoff-readback","template"`, 1), "unsupported Job controller", false, "id"},
		{"no-condition", 200, strings.Replace(job, "Complete", "SuccessCriteriaMet", 1), "completion not established", false, ""},
		{"wrong-steps", 200, strings.Replace(job, "migrate-production.mjs", "sensitive-detail", 1), "do not match", false, ""},
		{"missing", 404, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404,"message":"jobs.batch \"demo-initialization\" not found"}`, "not found at the selected target", false, ""},
		{"login", 401, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Unauthorized","code":401,"message":"sensitive-detail"}`, "kubectl reported a login problem", false, ""},
		{"denied", 403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"sensitive-detail"}`, "kubectl reported a refusal", false, ""},
		{"pinned-denied", 403, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Forbidden","code":403,"message":"sensitive-detail"}`, "kubectl reported a refusal", false, "old"},
		{"server-marker", 500, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"InternalError","code":500,"message":"sensitive-detail; error: You must be logged in to the server; Error from server (Forbidden): refused"}`, "unknown. Could not read", false, ""},
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
			config := installationDoctorKubeconfig(t, s.URL)
			for _, action := range []string{"doctor", "plan"} {
				requests.Store(0)
				args := []string{"installation", action, "--kubeconfig", config, "--context", "read", "--kube-namespace", "operations", "--release", "demo"}
				if tc.uid != "" {
					args = append(args, "--expect-job-uid", tc.uid)
				}
				out, stderr, err := runHelp(t, args...)
				var exit *ExitStatusError
				if (err == nil) != tc.success || (!tc.success && (!errors.As(err, &exit) || exit.Code != 1)) ||
					stderr != "" || requests.Load() != 1 || strings.Contains(out, "sensitive-detail") {
					t.Errorf("out=%s stderr=%s err=%v requests=%d", out, stderr, err, requests.Load())
				}
				if tc.status == 401 || tc.status == 403 || tc.status == 500 {
					for _, unwanted := range []string{"obtain permission", "first-install intent", "not found at the selected target"} {
						if strings.Contains(out, unwanted) {
							t.Errorf("unexpected %q in %s", unwanted, out)
						}
					}
				}
				expected := []string{tc.want, "Do not replay", "removal unknown", "not qualified"}
				if action == "plan" {
					first := map[string]string{"login": "1. Confirm the cluster target", "denied": "1. Confirm the cluster target and intended reader", "missing": "first-install intent", "install": "1. Establish whether", "guarded-install": "1. Establish whether", "upgrade": "1. Establish whether", "pinned": "1. Continue from the completed migration and bootstrap for the recorded Job", "replaced": "1. Recover the original installation record", "pinned-missing": "1. Recover the original installation record", "pinned-denied": "1. Confirm the cluster target and intended reader", "server-marker": "1. Confirm the cluster target"}[tc.name]
					expected = []string{tc.want, first, "2. If an API operation was attempted", "3. Verify temporary access", "4. Qualify useful work"}
					switch tc.status {
					case 401:
						expected = append(expected, "separately authorized read-only session")
					case 403:
						expected = append(expected, "Do not restore temporary privilege or request broader access")
					}
				}
				wantLookup := action == "plan" && tc.name == "pinned-failed"
				if strings.Contains(out, "get pods") != wantLookup {
					t.Errorf("want operator Pod lookup %v in %s", wantLookup, out)
				}
				if tc.success {
					expected = append(expected, `operations/demo-initialization, UID "id"`)
					// A completed hook can precede a failed Helm release. Its named Job
					// cannot prove the release or its API and worker workloads are ready.
					expected = append(expected, "This Job does not establish Helm release status", "whether the API and worker Deployments rolled out and are ready")
					if action == "plan" && tc.uid == "id" {
						expected = append(expected, "Ask the release operator to check the Helm release status", "whether its API and worker Deployments rolled out and are ready", "Do not rerun initialization")
					}
				}
				for _, want := range expected {
					if !strings.Contains(out, want) {
						t.Errorf("want %q in %s", want, out)
					}
				}
			}
		})
	}

	t.Run("rate-limited read observes replacement", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/apis/batch/v1/namespaces/operations/jobs/demo-initialization" {
				t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", "application/json")
			if requests.Add(1) == 1 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"TooManyRequests","message":"too many requests","details":{"retryAfterSeconds":1},"code":429}`)
				return
			}
			fmt.Fprint(w, strings.Replace(job, `"uid":"id"`, `"uid":"replacement"`, 1))
		}))
		defer server.Close()

		out, stderr, err := runHelp(t, "installation", "plan", "--kubeconfig", installationDoctorKubeconfig(t, server.URL),
			"--context", "read", "--kube-namespace", "operations", "--release", "demo", "--expect-job-uid", "id", "--timeout-seconds", "5")
		if err == nil || stderr != "" || requests.Load() < 2 {
			t.Fatalf("out=%s stderr=%s err=%v requests=%d", out, stderr, err, requests.Load())
		}
		for _, want := range []string{`expected UID "id", observed UID "replacement"`, "original outcome remains unknown", "1. Recover the original installation record"} {
			if !strings.Contains(out, want) {
				t.Errorf("want %q in %s", want, out)
			}
		}
	})
}

func installationDoctorKubeconfig(t *testing.T, serverURL string) string {
	t.Helper()
	config := filepath.Join(t.TempDir(), "kubeconfig")
	contents := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: test, cluster: {server: %s}}]
contexts: [{name: read, context: {cluster: test}}]
`, serverURL)
	if err := os.WriteFile(config, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestInstallationDoctorRejectsEmptyExpectedUID(t *testing.T) {
	_, _, err := runHelp(t, "installation", "doctor", "--kubeconfig", "unused", "--context", "unused", "--kube-namespace", "demo", "--release", "demo", "--expect-job-uid=")
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("error = %v", err)
	}
}

func TestReportedKubectlReadProblemRequiresAnUnwrappedDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, diagnostic string
		want             initializationState
	}{
		{"login", "error: You must be logged in to the server (details)\n", initializationLoginReported},
		{"refusal", "Error from server (Forbidden): details\n", initializationRefusalReported},
		{"warning", "Warning: unrelated\nError from server (Forbidden): details\n", initializationUnreadable},
		{"wrapped", "error: exec plugin failed: error: You must be logged in to the server (details)\n", initializationUnreadable},
		{"localized", "Error del servidor (Forbidden): details\n", initializationUnreadable},
		{"embedded", "Error from server (InternalError): Error from server (Forbidden): details\n", initializationUnreadable},
		{"empty-refusal", "Error from server (Forbidden): \n", initializationUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reportedKubectlReadProblem(tc.diagnostic); got != tc.want {
				t.Errorf("classification = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInstallationDoctorIgnoresIncompleteKubectlDiagnostics(t *testing.T) {
	dir := t.TempDir()
	kubectl := filepath.Join(dir, "kubectl")
	if err := os.WriteFile(kubectl, []byte("#!/bin/sh\nprintf '%s\\n' 'Error from server (Forbidden): details' >&2\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	message, state := readInitialization(context.Background(), "unused", "read", "operations", "demo-initialization", "demo", "")
	if state != initializationUnreadable || !strings.Contains(message, "unknown. Could not read") || strings.Contains(message, "refusal") {
		t.Fatalf("message=%q state=%v", message, state)
	}

	// An exact-looking NotFound line cannot establish absence when the other
	// output stream exceeded the read bound.
	if err := os.WriteFile(kubectl+".data", bytes.Repeat([]byte("x"), (4<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' 'Error from server (NotFound): jobs.batch \"demo-initialization\" not found' >&2\ncat \"$0.data\"\ntouch \"$0.done\"\nexit 1\n"
	if err := os.WriteFile(kubectl, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	message, state = readInitialization(context.Background(), "unused", "read", "operations", "demo-initialization", "demo", "")
	if _, err := os.Stat(kubectl + ".done"); err != nil {
		t.Fatalf("kubectl fixture did not finish: %v", err)
	}
	if state != initializationUnreadable || !strings.Contains(message, "unknown. Could not read") || strings.Contains(message, "not found at the selected target") {
		t.Fatalf("message=%q state=%v", message, state)
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
