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

// MondefaultMetric reads a metric child from the default registry, which is the
// registry every collector except RequestsTotal/RequestDuration lands in.
func MondefaultMetric(t *testing.T, name string, labels map[string]string) MonmetricValue {
	t.Helper()
	return MongatherMetric(t, prometheus.DefaultGatherer, name, labels)
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

func TestMonPrometheusFmtBool(t *testing.T) {
	assert.Equal(t, "true", prometheusFmtBool(true))
	assert.Equal(t, "false", prometheusFmtBool(false))
}

func TestMonGetObjectSizeCategory(t *testing.T) {
	const (
		kb = int64(1024)
		mb = 1024 * kb
	)

	tests := []struct {
		name     string
		size     int64
		expected string
	}{
		{name: "negative size", size: -1, expected: "tiny"},
		{name: "zero", size: 0, expected: "tiny"},
		{name: "just below 1KB", size: kb - 1, expected: "tiny"},
		{name: "exactly 1KB", size: kb, expected: "small"},
		{name: "just below 1MB", size: mb - 1, expected: "small"},
		{name: "exactly 1MB", size: mb, expected: "medium"},
		{name: "just below 10MB", size: 10*mb - 1, expected: "medium"},
		{name: "exactly 10MB", size: 10 * mb, expected: "large"},
		{name: "just below 100MB", size: 100*mb - 1, expected: "large"},
		{name: "exactly 100MB", size: 100 * mb, expected: "huge"},
		{name: "multi gigabyte", size: 5 * 1024 * mb, expected: "huge"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, getObjectSizeCategory(tt.size))
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
		name              string
		licensedTo        string
		company           string
		valid             bool
		expiryOffset      time.Duration
		expectedGauge     float64
		expectedDaysLeft  float64
		expectedDaysDelta float64
	}{
		{
			name:              "valid license expiring in ten days",
			licensedTo:        "mon-license-valid",
			company:           "Mon Corp",
			valid:             true,
			expiryOffset:      10 * 24 * time.Hour,
			expectedGauge:     1,
			expectedDaysLeft:  10,
			expectedDaysDelta: 0.01,
		},
		{
			name:              "invalid license still records expiry",
			licensedTo:        "mon-license-invalid",
			company:           "Mon Corp",
			valid:             false,
			expiryOffset:      2 * 24 * time.Hour,
			expectedGauge:     0,
			expectedDaysLeft:  2,
			expectedDaysDelta: 0.01,
		},
		{
			name:              "expired license clamps days remaining to zero",
			licensedTo:        "mon-license-expired",
			company:           "Mon Corp",
			valid:             false,
			expiryOffset:      -48 * time.Hour,
			expectedGauge:     0,
			expectedDaysLeft:  0,
			expectedDaysDelta: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiry := time.Now().Add(tt.expiryOffset)
			expiresAt := expiry.Format(time.RFC3339)
			expiryTimestamp := float64(expiry.Unix())

			SetLicenseInfo(tt.licensedTo, tt.company, expiresAt, tt.valid, expiryTimestamp)

			info := MondefaultMetric(t, "s3ep_license_info", map[string]string{
				"licensed_to": tt.licensedTo,
				"company":     tt.company,
				"expires_at":  expiresAt,
			})
			require.True(t, info.Found)
			assert.Equal(t, tt.expectedGauge, info.Value)

			expiryGauge := MondefaultMetric(t, "s3ep_license_expiry_timestamp", map[string]string{})
			require.True(t, expiryGauge.Found)
			assert.Equal(t, expiryTimestamp, expiryGauge.Value)

			daysGauge := MondefaultMetric(t, "s3ep_license_days_remaining", map[string]string{})
			require.True(t, daysGauge.Found)
			assert.InDelta(t, tt.expectedDaysLeft, daysGauge.Value, tt.expectedDaysDelta)
		})
	}
}

func TestMonSetProviderInfo(t *testing.T) {
	tests := []struct {
		name          string
		alias         string
		isActive      bool
		expectedValue float64
		expectedLabel string
	}{
		{
			name:          "active provider",
			alias:         "mon-active-provider",
			isActive:      true,
			expectedValue: 1,
			expectedLabel: "true",
		},
		{
			name:          "available but inactive provider",
			alias:         "mon-inactive-provider",
			isActive:      false,
			expectedValue: 0,
			expectedLabel: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetProviderInfo(tt.alias, "aes", "fp-1234", tt.isActive)

			got := MondefaultMetric(t, "s3ep_encryption_providers_info", map[string]string{
				"alias":       tt.alias,
				"type":        "aes",
				"fingerprint": "fp-1234",
				"is_active":   tt.expectedLabel,
			})
			require.True(t, got.Found, "provider info gauge must carry the is_active label")
			assert.Equal(t, tt.expectedValue, got.Value)
		})
	}
}

func TestMonRecordHMACOperation(t *testing.T) {
	const (
		operation   = "mon-hmac-verify"
		algorithm   = "hmac-sha256"
		decision    = "strict"
		contentType = "whole"
	)

	countLabels := map[string]string{
		"operation":       operation,
		"algorithm":       algorithm,
		"policy_decision": decision,
		"content_type":    contentType,
	}
	perfLabels := map[string]string{
		"operation":    operation,
		"algorithm":    algorithm,
		"hmac_enabled": "true",
	}
	throughputLabels := map[string]string{
		"algorithm":    algorithm,
		"content_type": contentType,
		"hmac_enabled": "true",
	}

	before := MondefaultMetric(t, "s3ep_hmac_operations_total", countLabels)
	beforePerf := MondefaultMetric(t, "s3ep_hmac_performance_seconds", perfLabels)
	beforeThroughput := MondefaultMetric(t, "s3ep_hmac_throughput_mbps", throughputLabels)

	// 8 MB in 2 seconds is 4 MB/s.
	RecordHMACOperation(operation, algorithm, decision, contentType, 2*time.Second, 8, true)

	after := MondefaultMetric(t, "s3ep_hmac_operations_total", countLabels)
	require.True(t, after.Found)
	assert.Equal(t, before.Value+1, after.Value)

	afterPerf := MondefaultMetric(t, "s3ep_hmac_performance_seconds", perfLabels)
	require.True(t, afterPerf.Found)
	assert.Equal(t, beforePerf.HistCount+1, afterPerf.HistCount)
	assert.InDelta(t, beforePerf.HistSum+2, afterPerf.HistSum, 0.0001)

	afterThroughput := MondefaultMetric(t, "s3ep_hmac_throughput_mbps", throughputLabels)
	require.True(t, afterThroughput.Found)
	assert.Equal(t, beforeThroughput.HistCount+1, afterThroughput.HistCount)
	assert.InDelta(t, beforeThroughput.HistSum+4, afterThroughput.HistSum, 0.0001)
}

func TestMonRecordHMACOperationSkipsThroughput(t *testing.T) {
	const (
		operation   = "mon-hmac-skip"
		algorithm   = "hmac-sha256"
		contentType = "multipart"
	)

	throughputLabels := map[string]string{
		"algorithm":    algorithm,
		"content_type": contentType,
		"hmac_enabled": "false",
	}
	perfLabels := map[string]string{
		"operation":    operation,
		"algorithm":    algorithm,
		"hmac_enabled": "false",
	}

	tests := []struct {
		name     string
		duration time.Duration
		sizeMB   float64
	}{
		{name: "zero duration yields no throughput sample", duration: 0, sizeMB: 16},
		{name: "zero size yields no throughput sample", duration: time.Second, sizeMB: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			beforePerf := MondefaultMetric(t, "s3ep_hmac_performance_seconds", perfLabels)
			beforeThroughput := MondefaultMetric(t, "s3ep_hmac_throughput_mbps", throughputLabels)

			RecordHMACOperation(operation, algorithm, "off", contentType, tt.duration, tt.sizeMB, false)

			afterPerf := MondefaultMetric(t, "s3ep_hmac_performance_seconds", perfLabels)
			require.True(t, afterPerf.Found, "performance is always observed")
			assert.Equal(t, beforePerf.HistCount+1, afterPerf.HistCount)

			afterThroughput := MondefaultMetric(t, "s3ep_hmac_throughput_mbps", throughputLabels)
			assert.Equal(t, beforeThroughput.HistCount, afterThroughput.HistCount,
				"throughput must not be observed for a zero duration or zero size")
		})
	}
}

func TestMonRecordProxyPerformance(t *testing.T) {
	labels := map[string]string{
		"phase":                "mon-encrypt",
		"operation":            "PUT",
		"object_size_category": "medium",
	}
	before := MondefaultMetric(t, "s3ep_proxy_performance_seconds", labels)

	// 5 MB is the "medium" bucket (>= 1 MB, < 10 MB).
	RecordProxyPerformance("mon-encrypt", "PUT", 250*time.Millisecond, 5*1024*1024)

	after := MondefaultMetric(t, "s3ep_proxy_performance_seconds", labels)
	require.True(t, after.Found)
	assert.Equal(t, before.HistCount+1, after.HistCount)
	assert.InDelta(t, before.HistSum+0.25, after.HistSum, 0.0001)
}

func TestMonRecordDownloadThroughput(t *testing.T) {
	const operation = "mon-download"
	labels := map[string]string{
		"operation":            operation,
		"object_size_category": "large",
	}

	before := MondefaultMetric(t, "s3ep_download_throughput_mbps", labels)

	// 20 MiB in 2 seconds is 10 MB/s, and 20 MiB is the "large" bucket.
	RecordDownloadThroughput(operation, 20*1024*1024, 2*time.Second)

	after := MondefaultMetric(t, "s3ep_download_throughput_mbps", labels)
	require.True(t, after.Found)
	assert.Equal(t, before.HistCount+1, after.HistCount)
	assert.InDelta(t, before.HistSum+10, after.HistSum, 0.0001)

	// A zero duration must not divide by zero or record a sample.
	RecordDownloadThroughput(operation, 20*1024*1024, 0)

	afterZero := MondefaultMetric(t, "s3ep_download_throughput_mbps", labels)
	assert.Equal(t, after.HistCount, afterZero.HistCount,
		"a zero duration must not produce a throughput sample")
	assert.InDelta(t, after.HistSum, afterZero.HistSum, 0.0001)
}
