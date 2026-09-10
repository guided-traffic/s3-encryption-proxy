package monitoring

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// Registry with Kubernetes labels
var (
	registry = prometheus.NewRegistry()
	factory  = promauto.With(prometheus.WrapRegistererWithPrefix("",
		prometheus.WrapRegistererWith(getKubernetesLabels(), registry)))
)

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
	LicenseInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_license_info",
			Help: "License information (1 = valid, 0 = invalid/expired)",
		},
		[]string{"licensed_to", "company", "expires_at"},
	)

	LicenseExpiryTime = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_license_expiry_timestamp",
			Help: "License expiry time as Unix timestamp",
		},
	)

	LicenseDaysRemaining = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_license_days_remaining",
			Help: "Number of days remaining until license expires",
		},
	)

	// Server metrics
	ServerInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_server_info",
			Help: "Server build information",
		},
		[]string{"version", "commit", "build_time"},
	)

	ActiveConnections = promauto.NewGauge(
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
