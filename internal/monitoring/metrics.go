package monitoring

import (
	"os"

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

	// License metrics. The licensee's name and company are deliberately not
	// labels: the listener is unauthenticated by design, and a metric is read
	// widely and kept for a long time.
	LicenseInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_license_info",
			Help: "License information (1 = valid, 0 = invalid/expired)",
		},
		[]string{"expires_at"},
	)

	LicenseExpiryTime = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_license_expiry_timestamp",
			Help: "License expiry time as Unix timestamp",
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

	// ObjectIntegrityFailures is the one metric that is supposed to stay at
	// zero. It counts reads where an object did not authenticate, by what
	// failed and by when it was found.
	//
	// The phase is why this metric has to exist at all. A failure found before
	// the response begins is a 403 and is already visible in
	// s3ep_requests_total; a failure found mid-stream is not, because the status
	// line said 200 long before the fault and cannot be taken back - the
	// response is cut instead. Without this counter such a read is recorded as a
	// success (ADR 0003).
	//
	// Neither bucket nor key is a label: they are unbounded, and the log line
	// beside every increment names them.
	ObjectIntegrityFailures = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_object_integrity_failures_total",
			Help: "Reads refused or cut because an object failed its integrity check",
		},
		[]string{"reason", "phase"},
	)

	// What the real traffic showed about the backend. Nothing here probes on
	// its own, and no automatic actor may act on it (ADR 0034). The gauges are
	// the same measurement the status document renders for a human; the two
	// counters below are what an alert is written against, because a document
	// and a last-seen timestamp cannot express a rate.
	BackendLastResponseTimestamp = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_backend_last_response_timestamp",
			Help: "Unix time of the last HTTP response from the backend, 0 when there has been none",
		},
	)

	BackendLastFailureTimestamp = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_backend_last_failure_timestamp",
			Help: "Unix time of the last backend transport failure, by class",
		},
		[]string{"class"},
	)

	BackendObserved = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: "s3ep_backend_observed",
			Help: "1 once any backend round trip has been observed since start",
		},
	)

	// The class label is bounded to the five classes the observer resolves. No
	// host label: exactly one backend is configured, so it would be a constant.
	BackendTransportFailures = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: "s3ep_backend_transport_failures_total",
			Help: "Backend round trips that never produced an HTTP response, by failure class",
		},
		[]string{"class"},
	)

	// The denominator. The SDK retries, so a handful of failures an hour is
	// normal and a bare failure count cannot be read; what an operator alerts on
	// is the share of round trips that failed. s3ep_requests_total is the client
	// leg and cannot serve as this.
	BackendResponses = factory.NewCounter(
		prometheus.CounterOpts{
			Name: "s3ep_backend_responses_total",
			Help: "Backend round trips that produced an HTTP response, any status code",
		},
	)

	// The fingerprint is a label because an operator has to be able to see
	// which key the objects being written name, and an exit provider means the
	// backend holds plaintext (ADR 0025).
	EncryptionProviderInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "s3ep_encryption_provider_info",
			Help: "The active KEK provider (always 1)",
		},
		[]string{"alias", "type", "kek_fingerprint"},
	)
)

// The phases an integrity failure can be found in.
const (
	// IntegrityPhaseBeforeResponse is a refusal: nothing of the object reached
	// the client and the answer is 403 InvalidObjectState.
	IntegrityPhaseBeforeResponse = "before_response"
	// IntegrityPhaseMidStream is a truncation: the status line was already out,
	// so all the proxy can do is stop writing. A client that ignores a short
	// read sees incomplete data.
	IntegrityPhaseMidStream = "mid_stream"
)

// RecordObjectIntegrityFailure counts one failed read.
func RecordObjectIntegrityFailure(reason, phase string) {
	ObjectIntegrityFailures.WithLabelValues(reason, phase).Inc()
}

// SetServerInfo sets server build information
func SetServerInfo(version, commit, buildTime string) {
	ServerInfo.WithLabelValues(version, commit, buildTime).Set(1)
	setStatusBuild(version, commit, buildTime)
}

// SetLicenseInfo sets license information. It is called once, at startup, which
// is why no gauge here is a remaining-time figure: that would be frozen at the
// value it had when the process began and could never fall, so an alert on it
// could never fire. The expiry timestamp is correct whenever it is scraped, and
// the remaining time belongs in the query:
// (s3ep_license_expiry_timestamp - time()) / 86400
func SetLicenseInfo(expiresAt string, valid bool, expiryTimestamp float64) {
	value := float64(0)
	if valid {
		value = 1
	}
	LicenseInfo.WithLabelValues(expiresAt).Set(value)
	LicenseExpiryTime.Set(expiryTimestamp)
	setStatusLicense(expiresAt, valid, expiryTimestamp)
}
