//go:build e2e

package velero

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// logTarget is one workload whose logs and restart count are checked after
// every scenario.
type logTarget struct {
	namespace string
	selector  string
}

func healthTargets(t *testing.T) []logTarget {
	e := loadVersionsEnv(t)
	return []logTarget{
		{e.get(t, "VELERO_NAMESPACE"), "deploy/velero"},
		{e.get(t, "VELERO_NAMESPACE"), "daemonset/node-agent"},
		{e.get(t, "PROXY_NAMESPACE"), "deploy/s3ep-proxy"},
	}
}

// forbiddenLogPatterns are the strings that fail a scenario when they appear in
// any component log during it.
//
// Both Velero and the proxy are configured with JSON logging, so the level match
// is exact rather than a substring of prose. `level=error` is kept as well
// because the velero-plugin-for-aws logs through a different formatter.
var forbiddenLogPatterns = []string{
	`"level":"error"`,
	`"level":"fatal"`,
	"level=error",
	"level=fatal",
	"panic:",
	"runtime error",
	"HMAC verification failed",
}

// scenarioGuard records the state a scenario starts from so the health check can
// scope its log scan and compare restart counts.
type scenarioGuard struct {
	start    time.Time
	restarts map[string]int
}

// beginScenario captures the baseline. Call it before the first backup.
func beginScenario(t *testing.T, ctx context.Context) *scenarioGuard {
	t.Helper()
	return &scenarioGuard{
		// One second of slack: kubectl --since-time has second granularity, and
		// a log line written in the same second would otherwise be missed.
		start:    time.Now().Add(-1 * time.Second),
		restarts: containerRestarts(t, ctx),
	}
}

// assertHealthy is the mandatory post-scenario check: no error-level logs, no
// panics, no container restarts.
func (g *scenarioGuard) assertHealthy(t *testing.T, ctx context.Context) {
	t.Helper()

	sinceArg := "--since-time=" + g.start.UTC().Format(time.RFC3339)
	for _, target := range healthTargets(t) {
		logs, err := tryKubectl(t, ctx, "-n", target.namespace, "logs", target.selector,
			"--all-containers", "--prefix", sinceArg, "--tail=-1")
		if err != nil {
			// A workload that has no pods yet is a failure in itself, but report
			// it as such rather than as a log-scan result.
			t.Fatalf("could not read logs for %s/%s: %v\n%s", target.namespace, target.selector, err, logs)
		}
		for _, pattern := range forbiddenLogPatterns {
			if idx := strings.Index(logs, pattern); idx >= 0 {
				t.Errorf("%s/%s logged %q:\n%s", target.namespace, target.selector, pattern,
					excerpt(logs, idx))
			}
		}
	}

	after := containerRestarts(t, ctx)
	for name, before := range g.restarts {
		if now, ok := after[name]; ok && now != before {
			t.Errorf("container %s restarted during the scenario (%d -> %d)", name, before, now)
		}
	}
	for name, now := range after {
		if _, ok := g.restarts[name]; !ok && now != 0 {
			t.Errorf("new container %s already has %d restarts", name, now)
		}
	}
}

// excerpt returns the offending log line plus a little context, so a failure
// message is actionable without dumping the whole log.
func excerpt(logs string, idx int) string {
	start := strings.LastIndexByte(logs[:idx], '\n') + 1
	end := strings.IndexByte(logs[idx:], '\n')
	if end < 0 {
		end = len(logs)
	} else {
		end += idx
	}
	line := logs[start:end]
	const max = 2000
	if len(line) > max {
		line = line[:max] + "…"
	}
	return line
}

// containerRestarts maps "<namespace>/<pod>/<container>" to its restart count
// for every Velero and proxy container.
func containerRestarts(t *testing.T, ctx context.Context) map[string]int {
	t.Helper()
	e := loadVersionsEnv(t)

	var list struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				ContainerStatuses []struct {
					Name         string `json:"name"`
					RestartCount int    `json:"restartCount"`
				} `json:"containerStatuses"`
			} `json:"status"`
		} `json:"items"`
	}

	counts := map[string]int{}
	for _, ns := range []string{e.get(t, "VELERO_NAMESPACE"), e.get(t, "PROXY_NAMESPACE")} {
		kubectlJSON(t, ctx, &list, "-n", ns, "get", "pods")
		for _, pod := range list.Items {
			for _, cs := range pod.Status.ContainerStatuses {
				counts[fmt.Sprintf("%s/%s/%s", pod.Metadata.Namespace, pod.Metadata.Name, cs.Name)] = cs.RestartCount
			}
		}
	}
	return counts
}

// backupStatus is the part of a Backup CR the suite asserts on.
//
// The CR is read directly rather than through `velero backup describe`, because
// describe fetches the backup results through a pre-signed URL and would drag an
// unrelated code path into every assertion.
type backupStatus struct {
	Phase                         string `json:"phase"`
	Errors                        int    `json:"errors"`
	Warnings                      int    `json:"warnings"`
	ValidationErrors              []string
	CompletionTimestamp           string `json:"completionTimestamp"`
	FormatVersion                 string `json:"formatVersion"`
	BackupItemOperationsAttempted int    `json:"backupItemOperationsAttempted"`
	BackupItemOperationsCompleted int    `json:"backupItemOperationsCompleted"`
	BackupItemOperationsFailed    int    `json:"backupItemOperationsFailed"`
}

func isTerminal(phase string) bool {
	switch phase {
	case "Completed", "PartiallyFailed", "Failed", "FailedValidation",
		"WaitingForPluginOperationsPartiallyFailed":
		return true
	}
	return false
}

// waitBackupCompleted waits for a backup to reach a terminal phase and requires
// it to be Completed with zero errors. Warnings are recorded, not fatal.
func waitBackupCompleted(t *testing.T, ctx context.Context, name string, timeout time.Duration) backupStatus {
	t.Helper()
	var st backupStatus
	eventually(t, timeout, 5*time.Second,
		fmt.Sprintf("backup %s did not reach a terminal phase", name),
		func() (bool, string) {
			var obj struct {
				Status backupStatus `json:"status"`
			}
			raw, err := tryKubectl(t, ctx, "-n", loadVersionsEnv(t).get(t, "VELERO_NAMESPACE"),
				"get", "backup", name, "-o", "json")
			if err != nil {
				return false, "not created yet"
			}
			if unmarshalErr := jsonUnmarshal(raw, &obj); unmarshalErr != nil {
				return false, "unparseable"
			}
			st = obj.Status
			return isTerminal(st.Phase), st.Phase
		})

	if st.Warnings > 0 {
		t.Logf("backup %s completed with %d warnings", name, st.Warnings)
	}
	require.Equalf(t, "Completed", st.Phase, "backup %s phase", name)
	require.Zerof(t, st.Errors, "backup %s reported errors", name)
	require.Zerof(t, st.BackupItemOperationsFailed, "backup %s had failed item operations", name)
	return st
}

// waitRestoreCompleted mirrors waitBackupCompleted for Restore CRs.
func waitRestoreCompleted(t *testing.T, ctx context.Context, name string, timeout time.Duration) backupStatus {
	t.Helper()
	var st backupStatus
	eventually(t, timeout, 5*time.Second,
		fmt.Sprintf("restore %s did not reach a terminal phase", name),
		func() (bool, string) {
			var obj struct {
				Status backupStatus `json:"status"`
			}
			raw, err := tryKubectl(t, ctx, "-n", loadVersionsEnv(t).get(t, "VELERO_NAMESPACE"),
				"get", "restore", name, "-o", "json")
			if err != nil {
				return false, "not created yet"
			}
			if unmarshalErr := jsonUnmarshal(raw, &obj); unmarshalErr != nil {
				return false, "unparseable"
			}
			st = obj.Status
			return isTerminal(st.Phase), st.Phase
		})

	if st.Warnings > 0 {
		t.Logf("restore %s completed with %d warnings", name, st.Warnings)
	}
	require.Equalf(t, "Completed", st.Phase, "restore %s phase", name)
	require.Zerof(t, st.Errors, "restore %s reported errors", name)
	return st
}
