package monitoring

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// KubernetesLabels holds Kubernetes metadata labels
var (
	kubernetesNamespace = os.Getenv("KUBERNETES_NAMESPACE")
	kubernetesPodName   = os.Getenv("KUBERNETES_POD_NAME")
	helmReleaseName     = os.Getenv("HELM_RELEASE_NAME")
	helmChartVersion    = os.Getenv("HELM_CHART_VERSION")
)

// getKubernetesLabels returns the Kubernetes labels for metrics
func getKubernetesLabels() prometheus.Labels {
	labels := prometheus.Labels{}

	if kubernetesNamespace != "" {
		labels["kubernetes_namespace"] = kubernetesNamespace
	}
	if kubernetesPodName != "" {
		labels["kubernetes_pod_name"] = kubernetesPodName
	}
	if helmReleaseName != "" {
		labels["helm_release"] = helmReleaseName
	}
	if helmChartVersion != "" {
		labels["helm_chart_version"] = helmChartVersion
	}

	return labels
}

// registry is the one registry this process exposes. Everything is registered on
// it, and /metrics gathers from it (server.go) — the two used to be different
// things, which is why the two headline metrics reached no scrape at all: they
// were created through factory against this private registry while /metrics
// served promhttp.Handler(), which gathers prometheus.DefaultGatherer. The
// mechanism cut both ways, and the second half is the reason everything goes
// through factory now: the collectors that were exported used plain promauto
// against the default registerer, so they carried none of the Kubernetes and
// Helm labels — those are attached only by the wrapper below. Labelled series
// were not exported; exported series were not labelled.
var (
	registry   = prometheus.NewRegistry()
	registerer = prometheus.WrapRegistererWithPrefix("",
		prometheus.WrapRegistererWith(getKubernetesLabels(), registry))
	factory = promauto.With(registerer)
)

// The Go runtime and process collectors come with prometheus.DefaultRegisterer
// and had to be re-registered by hand when /metrics moved off it: without them
// a scrape carries no heap, goroutine, resident-memory, CPU or file-descriptor
// series at all, and the memory instrument of ADR 0020 D14 has nothing to read.
func init() {
	registerer.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
}

// Gatherer is what the monitoring listener serves. Exported so the listener
// cannot drift back onto the default one.
func Gatherer() prometheus.Gatherer { return registry }

// Prometheus metrics for S3 Encryption Proxy
var (
	// HTTP Request metrics
	RequestsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	RequestDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3ep_request_duration_seconds",
			Help:    "Request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)

	// License metrics
	LicenseInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_license_info",
			Help: "License information (1 = valid, 0 = invalid/expired)",
		},
		[]string{"licensed_to", "company", "expires_at"},
	)

	LicenseExpiryTime = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_license_expiry_timestamp",
			Help: "License expiry time as Unix timestamp",
		},
	)

	LicenseDaysRemaining = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_license_days_remaining",
			Help: "Number of days remaining until license expires",
		},
	)

	// Server metrics
	ServerInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_server_info",
			Help: "Server build information",
		},
		[]string{"version", "commit", "build_time"},
	)

	ActiveConnections = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_active_connections",
			Help: "Number of active connections",
		},
	)
)

// SetServerInfo sets server build information
func SetServerInfo(version, commit, buildTime string) {
	ServerInfo.WithLabelValues(version, commit, buildTime).Set(1)
}

// SetLicenseInfo sets license information
func SetLicenseInfo(licensedTo, company, expiresAt string, valid bool, expiryTimestamp float64) {
	value := float64(0)
	if valid {
		value = 1
	}
	LicenseInfo.WithLabelValues(licensedTo, company, expiresAt).Set(value)
	LicenseExpiryTime.Set(expiryTimestamp)

	// Calculate days remaining
	daysRemaining := (expiryTimestamp - float64(time.Now().Unix())) / 86400
	if daysRemaining < 0 {
		daysRemaining = 0
	}
	LicenseDaysRemaining.Set(daysRemaining)
}
