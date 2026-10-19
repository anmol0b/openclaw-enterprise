package occcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// The Helm hook is replaced before the next install or upgrade. Its result
// describes the retained Job, not current database contents or release health.
func (app *application) installationHandoffCommand(action string) *cobra.Command {
	var kubeconfig, kubeContext, namespace, release, expectedUID string
	cmd := &cobra.Command{
		Use:         action,
		Short:       "Read the chart initialization Job and show where to resume",
		Annotations: map[string]string{outputFormatsAnnotation: "text"},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(kubeconfig) == "" || strings.TrimSpace(kubeContext) == "" || !dns1123Label(namespace) ||
				!dns1123Label(release) || len(release) > 53 {
				return errors.New("provide an explicit kubeconfig, context, Kubernetes namespace and Helm release name")
			}
			if cmd.Flags().Changed("expect-job-uid") && expectedUID == "" {
				return errors.New("--expect-job-uid must not be empty; use the UID recorded at the original installation")
			}
			// Match templates/jobs.yaml, including Helm release names whose
			// hook name is truncated. Verify the full release label below.
			name := release + "-initialization"
			name = strings.TrimSuffix(name[:min(63, len(name))], "-")
			ctx, cancel := context.WithTimeout(cmd.Context(), app.parsedTimeout)
			defer cancel()
			message, state := readInitialization(ctx, kubeconfig, kubeContext, namespace, name, release, expectedUID)
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, message)
			if action == "plan" {
				fmt.Fprintf(out, "Resume in order:\n1. %s\n", state.next(expectedUID != ""))
				fmt.Fprintln(out, "2. If an API operation was attempted, inspect that original attempt before another write. Never replay an uncertain operation.")
				fmt.Fprintln(out, "3. Verify temporary access was removed, separately with the access owner.")
				fmt.Fprintln(out, "4. Qualify useful work from the installed Agent.")
			} else {
				fmt.Fprintln(out, "API attempt: if started, inspect the original attempt and its outcome. Do not replay an uncertain operation.")
				fmt.Fprintln(out, "Temporary access: removal unknown. Verify separately with the access owner.")
				fmt.Fprintln(out, "Runtime: not qualified by this check.")
			}
			if state != initializationComplete {
				return &ExitStatusError{Code: 1}
			}
			return nil
		},
		Args: cobra.NoArgs,
	}
	f := cmd.Flags()
	f.StringVar(&kubeconfig, "kubeconfig", "", "Trusted kubeconfig file to use")
	f.StringVar(&kubeContext, "context", "", "Kubernetes context in that file")
	f.StringVar(&namespace, "kube-namespace", "", "Kubernetes namespace of the release")
	f.StringVar(&release, "release", "", "Helm release name")
	f.StringVar(&expectedUID, "expect-job-uid", "", "Require the persisted Job UID recorded during the original installation")
	for _, name := range []string{"kubeconfig", "context", "kube-namespace", "release"} {
		_ = cmd.MarkFlagRequired(name)
	}
	if action == "plan" {
		cmd.Short = "Show the read-only handoff plan for this installation checkpoint"
	}
	return cmd
}

type initializationState int

const (
	initializationUnreadable initializationState = iota
	initializationAbsent
	initializationOriginalNotFound
	initializationUnresolved
	initializationComplete
)

func (s initializationState) next(expectUID bool) string {
	switch s {
	case initializationUnreadable:
		return "Confirm the cluster target and obtain permission to get this named Job, then check again."
	case initializationAbsent:
		return "Confirm first-install intent and preflight with the database, identity and volume owners. Establish what already exists before considering bootstrap."
	case initializationOriginalNotFound:
		return "Recover the original installation record and reconcile that attempt. Do not replay initialization or substitute the current Job UID."
	case initializationComplete:
		if expectUID {
			return "Resume after migration and bootstrap for the recorded Job."
		}
		return "Establish whether this retained Job is the original. Without that link, the original outcome remains unknown."
	default:
		return "Resolve the identity, progress and effects of this initialization Job before considering another attempt."
	}
}

func readInitialization(ctx context.Context, config, kctx, ns, name, release, expectedUID string) (string, initializationState) {
	// get --raw skips discovery and needs only get on this named Job.
	// Never relay the Job, stderr, credentials or exec-plugin diagnostics.
	path := "/apis/batch/v1/namespaces/" + ns + "/jobs/" + name
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig="+config, "--context="+kctx, "get", "--raw="+path)
	cmd.WaitDelay = time.Second
	var out, diagnostic doctorBuffer
	cmd.Stdout, cmd.Stderr = &out, &diagnostic
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 && strings.TrimSpace(diagnostic.buf.String()) ==
			fmt.Sprintf("Error from server (NotFound): jobs.batch %q not found", name) {
			if expectedUID != "" {
				return fmt.Sprintf("Initialization Job: not found at this target; expected UID %+q. The original outcome remains unknown.", expectedUID), initializationOriginalNotFound
			}
			return "Initialization Job: not found at the selected target. For a first install, confirm the intended database, identity and volume state with their owners. Absence does not establish a new database or authorize bootstrap or retry.", initializationAbsent
		}
		return "Initialization: unknown. Could not read the named Job; check target, kubectl, connectivity and permission to get that Job. Do not assume it is absent.", initializationUnreadable
	}
	return initializationEvidence(out.buf.Bytes(), ns, name, release, expectedUID)
}

// Bound both streams even when an auth plugin or endpoint misbehaves.
type doctorBuffer struct{ buf bytes.Buffer }

func (b *doctorBuffer) Write(p []byte) (int, error) {
	if len(p) > (4<<20)-b.buf.Len() {
		return 0, errors.New("kubectl output too large")
	}
	return b.buf.Write(p)
}

func initializationEvidence(data []byte, namespace, name, release, expectedUID string) (message string, state initializationState) {
	type container struct {
		Name          string
		Command, Args []string
	}
	var job struct {
		Kind, APIVersion string
		Metadata         struct {
			Name, Namespace, UID string
			DeletionTimestamp    *string
			Labels, Annotations  map[string]string
		}
		Spec struct {
			Template struct {
				Spec struct{ InitContainers, Containers []container }
			}
		}
		Status struct {
			Succeeded, Active int
			Conditions        []struct{ Type, Status string }
		}
	}
	err := json.Unmarshal(data, &job)
	m := job.Metadata
	l := m.Labels
	p := job.Spec.Template.Spec
	if err != nil || job.Kind != "Job" || job.APIVersion != "batch/v1" || m.UID == "" || m.Name != name ||
		m.Namespace != namespace || m.DeletionTimestamp != nil || l["app.kubernetes.io/instance"] != release ||
		l["app.kubernetes.io/name"] != "openclaw-enterprise" || l["app.kubernetes.io/component"] != "initialization" ||
		l["app.kubernetes.io/managed-by"] != "Helm" || m.Annotations["helm.sh/hook"] != "pre-install,pre-upgrade" {
		return "Initialization: unknown. The response did not identify a retained initialization Job for this release.", initializationUnresolved
	}
	if expectedUID != "" && m.UID != expectedUID {
		return fmt.Sprintf("Initialization Job %s/%s: expected UID %+q, observed UID %+q. This is a different Job; the original outcome remains unknown.", namespace, name, expectedUID, m.UID), initializationOriginalNotFound
	}
	init := p.InitContainers
	hook := "install"
	if len(init) == 2 && init[0].Name == "installation-check" {
		init, hook = init[1:], "upgrade"
	}
	is := func(cs []container, name, script string) bool {
		return len(cs) == 1 && cs[0].Name == name && len(cs[0].Command) == 0 && slices.Equal(cs[0].Args, []string{"scripts/" + script + ".mjs"})
	}
	if !is(init, "migration", "migrate-production") || !is(p.Containers, "bootstrap", "bootstrap-installation") {
		return "Initialization: unknown. Job steps do not match the supported chart.", initializationUnresolved
	}
	// Helm reuses the name; the UID identifies this Job, not an API attempt.
	defer func() {
		message += fmt.Sprintf("\nObserved Job %s/%s, UID %+q", namespace, name, m.UID)
		if expectedUID != "" {
			message += " matches the recorded UID. This identifies only this Job; it does not establish an API attempt, its effects or permission to retry."
		} else {
			message += " (compare with the installation record)."
		}
	}()
	complete := false
	for _, c := range job.Status.Conditions {
		if c.Status != "True" {
			continue
		}
		switch c.Type {
		case "Failed", "FailureTarget":
			return "Initialization Job: failed. Inspect this attempt; migration or bootstrap might already have taken effect.", initializationUnresolved
		case "Complete":
			complete = true
		}
	}
	if !complete || job.Status.Succeeded != 1 || job.Status.Active != 0 {
		return "Initialization Job: completion not established. Inspect this attempt before any retry.", initializationUnresolved
	}
	return "Initialization Job (" + hook + " hook): complete. The chart reports migration and bootstrap completed (created or verified existing installation). Current database state and external provisioning are not verified.", initializationComplete
}
