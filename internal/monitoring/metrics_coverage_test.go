package monitoring

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MonmetricValue holds the plain values of a single gathered metric child so
// that assertions never have to touch the protobuf types.
type MonmetricValue struct {
	Found     bool
	Value     float64 // counter or gauge value
	HistCount uint64
	HistSum   float64
}

// MongatherMetric looks up exactly one metric child by family name and label
// set. An empty labels map matches a metric without labels. A missing child is
// reported as a zero value with Found=false, which lets callers compute deltas
// against a not-yet-created child.
func MongatherMetric(t *testing.T, g prometheus.Gatherer, name string, labels map[string]string) MonmetricValue {
	t.Helper()

	families, err := g.Gather()
	require.NoError(t, err)

	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			got := make(map[string]string, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			if len(got) != len(labels) {
				continue
			}
			match := true
			for k, v := range labels {
				if got[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}

			out := MonmetricValue{Found: true}
			if c := m.GetCounter(); c != nil {
				out.Value = c.GetValue()
			}
			if gauge := m.GetGauge(); gauge != nil {
				out.Value = gauge.GetValue()
			}
			if h := m.GetHistogram(); h != nil {
				out.HistCount = h.GetSampleCount()
				out.HistSum = h.GetSampleSum()
			}
			return out
		}
	}

	return MonmetricValue{}
}

// MondefaultMetric reads a metric child from the registry this process exposes.
// There used to be two: every collector but RequestsTotal and RequestDuration
// landed in the default one, which is what /metrics served, while those two went
// to the private one, which nothing gathered. The labelled series were not
// exported and the exported series were not labelled.
func MondefaultMetric(t *testing.T, name string, labels map[string]string) MonmetricValue {
	t.Helper()
	return MongatherMetric(t, Gatherer(), name, labels)
}

func TestMonGetKubernetesLabels(t *testing.T) {
	origNamespace, origPod := kubernetesNamespace, kubernetesPodName
	origRelease, origChart := helmReleaseName, helmChartVersion
	t.Cleanup(func() {
		kubernetesNamespace, kubernetesPodName = origNamespace, origPod
		helmReleaseName, helmChartVersion = origRelease, origChart
	})

	tests := []struct {
		name      string
		namespace string
		pod       string
		release   string
		chart     string
		expected  prometheus.Labels
	}{
		{
			name:     "all environment variables unset",
			expected: prometheus.Labels{},
		},
		{
			name:      "only namespace set",
			namespace: "s3ep-system",
			expected:  prometheus.Labels{"kubernetes_namespace": "s3ep-system"},
		},
		{
			name:     "only pod name set",
			pod:      "s3ep-proxy-0",
			expected: prometheus.Labels{"kubernetes_pod_name": "s3ep-proxy-0"},
		},
		{
			name:     "only helm release set",
			release:  "prod-proxy",
			expected: prometheus.Labels{"helm_release": "prod-proxy"},
		},
		{
			name:     "only chart version set",
			chart:    "3.8.57",
			expected: prometheus.Labels{"helm_chart_version": "3.8.57"},
		},
		{
			name:      "full kubernetes deployment metadata",
			namespace: "s3ep-system",
			pod:       "s3ep-proxy-0",
			release:   "prod-proxy",
			chart:     "3.8.57",
			expected: prometheus.Labels{
				"kubernetes_namespace": "s3ep-system",
				"kubernetes_pod_name":  "s3ep-proxy-0",
				"helm_release":         "prod-proxy",
				"helm_chart_version":   "3.8.57",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubernetesNamespace = tt.namespace
			kubernetesPodName = tt.pod
			helmReleaseName = tt.release
			helmChartVersion = tt.chart

			assert.Equal(t, tt.expected, getKubernetesLabels())
		})
	}
}

func TestMonSetServerInfo(t *testing.T) {
	labels := map[string]string{
		"version":    "mon-1.2.3",
		"commit":     "deadbeef",
		"build_time": "2026-09-06T00:00:00Z",
	}
	require.False(t, MondefaultMetric(t, "s3ep_server_info", labels).Found)

	SetServerInfo("mon-1.2.3", "deadbeef", "2026-09-06T00:00:00Z")

	got := MondefaultMetric(t, "s3ep_server_info", labels)
	require.True(t, got.Found, "server info gauge must be exported")
	assert.Equal(t, float64(1), got.Value)
}

func TestMonSetLicenseInfo(t *testing.T) {
	tests := []struct {
		name          string
		valid         bool
		expiryOffset  time.Duration
		expectedGauge float64
	}{
		{
			name:          "valid license expiring in ten days",
			valid:         true,
			expiryOffset:  10 * 24 * time.Hour,
			expectedGauge: 1,
		},
		{
			name:          "invalid license still records expiry",
			valid:         false,
			expiryOffset:  2 * 24 * time.Hour,
			expectedGauge: 0,
		},
		{
			name:          "an expired license records the expiry that has passed",
			valid:         false,
			expiryOffset:  -48 * time.Hour,
			expectedGauge: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry := time.Now().Add(tt.expiryOffset)
			expiresAt := expiry.Format(time.RFC3339)
			expiryTimestamp := float64(expiry.Unix())

			SetLicenseInfo(expiresAt, tt.valid, expiryTimestamp)

			info := MondefaultMetric(t, "s3ep_license_info", map[string]string{
				"expires_at": expiresAt,
			})
			require.True(t, info.Found)
			assert.Equal(t, tt.expectedGauge, info.Value)

			// The timestamp is the whole statement: it is right whenever it is
			// scraped, where a remaining-time gauge set once at startup could
			// never fall and so could never raise an alert.
			expiryGauge := MondefaultMetric(t, "s3ep_license_expiry_timestamp", map[string]string{})
			require.True(t, expiryGauge.Found)
			assert.Equal(t, expiryTimestamp, expiryGauge.Value)
		})
	}
}

// The licensee's name and company were labels of s3ep_license_info until
// 5.0.0. The listener is unauthenticated by design, so they left a customer
// name on an endpoint built to be scraped widely and retained for a long time.
func TestMonLicenseInfoCarriesNoLicenseeIdentity(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour)
	SetLicenseInfo(expiry.Format(time.RFC3339), true, float64(expiry.Unix()))

	families, err := Gatherer().Gather()
	require.NoError(t, err)

	var seen bool
	for _, family := range families {
		if family.GetName() != "s3ep_license_info" {
			continue
		}
		seen = true
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				assert.NotContains(t, []string{"licensed_to", "company"}, label.GetName(),
					"the licensee's identity must not be a metric label")
			}
		}
	}
	require.True(t, seen, "s3ep_license_info must still be exported")
}

// Removed in 5.0.0: it was written once at startup and never refreshed, so a
// dashboard threshold on it sat on a value that could not fall.
func TestMonLicenseDaysRemainingIsGone(t *testing.T) {
	families, err := Gatherer().Gather()
	require.NoError(t, err)
	for _, family := range families {
		assert.NotEqual(t, "s3ep_license_days_remaining", family.GetName())
	}
}
