package monitoring

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The bundled dashboard shipped four panels querying series that had been
// deleted, and nothing noticed for a release: a panel that draws nothing looks
// exactly like a panel with no data yet. This asserts the other direction of
// that break too - a series renamed here leaves the dashboard behind.
const monDashboardPath = "../../deploy/helm/s3-encryption-proxy/dashboards/s3ep-performance-dashboard.json"

var monSeriesPattern = regexp.MustCompile(`\bs3ep_[a-z0-9_]+`)

func TestMonDashboardQueriesOnlySeriesTheProxyExports(t *testing.T) {
	raw, err := os.ReadFile(monDashboardPath)
	require.NoError(t, err, "the chart's dashboard must be readable from here")

	var dashboard struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
		Templating struct {
			List []struct {
				Name       string `json:"name"`
				Definition string `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	require.NoError(t, json.Unmarshal(raw, &dashboard))
	require.NotEmpty(t, dashboard.Panels)

	// Every series the dashboard names, with the panel or variable that names it.
	referenced := map[string]string{}
	for _, panel := range dashboard.Panels {
		for _, target := range panel.Targets {
			for _, name := range monSeriesPattern.FindAllString(target.Expr, -1) {
				referenced[name] = "panel " + panel.Title
			}
		}
	}
	for _, variable := range dashboard.Templating.List {
		for _, name := range monSeriesPattern.FindAllString(variable.Definition, -1) {
			referenced[name] = "variable $" + variable.Name
		}
	}
	require.NotEmpty(t, referenced)

	for name, where := range referenced {
		assert.Contains(t, monExportedSeries(t), name,
			"%s queries %s, which no scrape exports", where, name)
	}
}

// A Grafana variable whose values come from a counter resolves to nothing until
// the pod has served its first request, and every panel filtered by it then
// draws nothing - on a fresh pod the whole dashboard looks broken. The series
// behind these two must exist from startup.
func TestMonDashboardVariablesResolveBeforeTheFirstRequest(t *testing.T) {
	raw, err := os.ReadFile(monDashboardPath)
	require.NoError(t, err)

	var dashboard struct {
		Templating struct {
			List []struct {
				Name       string `json:"name"`
				Definition string `json:"definition"`
			} `json:"list"`
		} `json:"templating"`
	}
	require.NoError(t, json.Unmarshal(raw, &dashboard))

	// Set at startup, unconditionally, and never label-dependent.
	alwaysPresent := map[string]bool{"s3ep_server_info": true, "s3ep_active_connections": true}

	var checked int
	for _, variable := range dashboard.Templating.List {
		if variable.Name != "job" && variable.Name != "instance" {
			continue
		}
		checked++
		for _, name := range monSeriesPattern.FindAllString(variable.Definition, -1) {
			assert.True(t, alwaysPresent[name],
				"variable $%s resolves off %s, which has no children until the proxy "+
					"has served a request", variable.Name, name)
		}
	}
	assert.Equal(t, 2, checked, "both variables must still be declared")
}

// Moving /metrics onto the proxy's own registry once took the Go runtime and
// process collectors with it, and a scrape carried no heap, goroutine, CPU or
// file-descriptor series at all. Nothing asserted them back.
func TestMonScrapeCarriesTheRuntimeCollectors(t *testing.T) {
	exported := monExportedSeries(t)
	for _, name := range []string{
		"go_goroutines",
		"go_memstats_heap_alloc_bytes",
		"process_resident_memory_bytes",
		"process_cpu_seconds_total",
	} {
		assert.Contains(t, exported, name, "the runtime collectors must reach a scrape")
	}
}

// monExportedSeries gathers what a scrape would carry, with every metric the
// dashboard can name observed at least once first: a CounterVec or HistogramVec
// exports no family until one of its children exists.
func monExportedSeries(t *testing.T) []string {
	t.Helper()

	SetServerInfo("test-version", "test-commit", "test-time")
	expiry := time.Now().Add(48 * time.Hour)
	SetLicenseInfo(expiry.Format(time.RFC3339), true, float64(expiry.Unix()))
	RequestsTotal.WithLabelValues("GET", "/{bucket}/{key}", "200").Inc()
	RequestDuration.WithLabelValues("GET", "/{bucket}/{key}").Observe(0.01)
	ActiveConnections.Set(0)

	families, err := Gatherer().Gather()
	require.NoError(t, err)

	names := make([]string, 0, len(families)*2)
	for _, family := range families {
		names = append(names, family.GetName())
		// A histogram is queried by its derived series, not by its own name.
		if family.GetType().String() == "HISTOGRAM" {
			base := family.GetName()
			names = append(names, base+"_bucket", base+"_sum", base+"_count")
		}
	}
	sort.Strings(names)
	if t.Failed() {
		t.Logf("exported: %s", strings.Join(names, " "))
	}
	return names
}
