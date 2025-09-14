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
) // Prometheus metrics for S3 Encryption Proxy
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

	// S3 Operation metrics
	S3OperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_s3_operations_total",
			Help: "Total number of S3 operations",
		},
		[]string{"operation", "bucket", "status"},
	)

	S3OperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3ep_s3_operation_duration_seconds",
			Help:    "S3 operation duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation", "bucket"},
	)

	// Encryption metrics
	EncryptionOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_encryption_operations_total",
			Help: "Total number of encryption/decryption operations",
		},
		[]string{"operation", "provider_type", "status"},
	)

	EncryptionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3ep_encryption_duration_seconds",
			Help:    "Encryption/decryption operation duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"operation", "provider_type"},
	)

	// Data transfer metrics
	BytesTransferred = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_bytes_transferred_total",
			Help: "Total bytes transferred",
		},
		[]string{"direction", "operation"},
	)

	// Multipart upload metrics
	MultipartUploadsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_multipart_uploads_total",
			Help: "Total number of multipart uploads",
		},
		[]string{"status"},
	)

	MultipartUploadPartsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_multipart_upload_parts_total",
			Help: "Total number of multipart upload parts",
		},
		[]string{"status"},
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

	// Performance metrics for proxy vs direct access
	ProxyPerformance = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3ep_proxy_performance_seconds",
			Help:    "Time spent in different phases of request processing",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 25, 60},
		},
		[]string{"phase", "operation", "object_size_category"},
	)

	DownloadThroughput = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "s3ep_download_throughput_mbps",
			Help:    "Download throughput in MB/s",
			Buckets: []float64{0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000},
		},
		[]string{"operation", "object_size_category"},
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

	// Provider metrics
	EncryptionProvidersInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_encryption_providers_info",
			Help: "Information about loaded encryption providers (1 = active, 0 = available)",
		},
		[]string{"alias", "type", "fingerprint", "is_active"},
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

// SetProviderInfo sets encryption provider information
func SetProviderInfo(alias, providerType, fingerprint string, isActive bool) {
	value := float64(0)
	if isActive {
		value = 1
	}
	EncryptionProvidersInfo.WithLabelValues(alias, providerType, fingerprint, "true").Set(value)
}

// RecordProxyPerformance records performance metrics for different phases
func RecordProxyPerformance(phase, operation string, duration time.Duration, objectSize int64) {
	sizeCategory := getObjectSizeCategory(objectSize)
	ProxyPerformance.WithLabelValues(phase, operation, sizeCategory).Observe(duration.Seconds())
}

// RecordDownloadThroughput records download throughput
func RecordDownloadThroughput(operation string, bytesTransferred int64, duration time.Duration) {
	sizeCategory := getObjectSizeCategory(bytesTransferred)
	if duration.Seconds() > 0 {
		mbps := float64(bytesTransferred) / (1024 * 1024) / duration.Seconds()
		DownloadThroughput.WithLabelValues(operation, sizeCategory).Observe(mbps)
	}
}

// getObjectSizeCategory categorizes objects by size for better metrics analysis
func getObjectSizeCategory(size int64) string {
	if size < 1024 {
		return "tiny" // < 1KB
	} else if size < 1024*1024 {
		return "small" // < 1MB
	} else if size < 10*1024*1024 {
		return "medium" // < 10MB
	} else if size < 100*1024*1024 {
		return "large" // < 100MB
	}
	return "huge" // >= 100MB
}
