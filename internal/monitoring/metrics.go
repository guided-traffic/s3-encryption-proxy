package monitoring

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for S3 Encryption Proxy
var (
	// HTTP Request metrics
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code"},
	)

	RequestDuration = promauto.NewHistogramVec(
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
}

// SetProviderInfo sets encryption provider information
func SetProviderInfo(alias, providerType, fingerprint string, isActive bool) {
	value := float64(0)
	if isActive {
		value = 1
	}
	EncryptionProvidersInfo.WithLabelValues(alias, providerType, fingerprint, "true").Set(value)
}
