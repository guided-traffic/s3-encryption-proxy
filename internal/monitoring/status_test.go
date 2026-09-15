package monitoring

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MonresetStatusState clears what startup code records, so a test can assert
// what a process that has only just come up reports.
func MonresetStatusState(t *testing.T) {
	t.Helper()

	statusMu.Lock()
	statusBuild = BuildStatus{}
	statusEncryption = EncryptionStatus{}
	statusLicenseSet = false
	statusLicenseAt = ""
	statusLicenseValid = false
	statusLicenseExpiry = time.Time{}
	statusMu.Unlock()
}

// MonstatusBody renders the document the way a reader gets it, as the raw JSON
// object, so a test can assert that a field is ABSENT rather than empty.
func MonstatusBody(t *testing.T) map[string]any {
	t.Helper()

	s := NewServer(&Config{BindAddress: "127.0.0.1:0", MetricsPath: "/metrics"})
	rec := Monserve(t, s, http.MethodGet, "/status")
	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

// A process that has served nothing says so, and says nothing more: a timestamp
// that does not exist is absent from the document rather than zero.
func TestMonStatusBeforeAnythingHappened(t *testing.T) {
	MonresetStatusState(t)
	MonresetBackendObservation(t)

	body := MonstatusBody(t)

	assert.Equal(t, "s3-encryption-proxy", body["service"])

	backend, ok := body["backend"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "no request since start", backend["status"])
	assert.NotContains(t, backend, "last_response")
	assert.NotContains(t, backend, "last_failure")
	assert.NotContains(t, backend, "last_failure_class")

	assert.NotContains(t, body, "license",
		"a licence nobody reported is absent, not a document of empty strings")
}

func TestMonStatusCarriesBuildAndActiveProvider(t *testing.T) {
	MonresetStatusState(t)
	SetServerInfo("5.0.2", "abc1234", "2026-09-15T00:00:00Z")
	SetActiveProvider("current-provider", "aes", "fp-9f86d081")

	doc := StatusSnapshot()

	assert.Equal(t, BuildStatus{Version: "5.0.2", Commit: "abc1234", BuildTime: "2026-09-15T00:00:00Z"}, doc.Build)
	assert.Equal(t, EncryptionStatus{
		ProviderAlias:  "current-provider",
		ProviderType:   "aes",
		KEKFingerprint: "fp-9f86d081",
	}, doc.Encryption)

	// The document is the human reading of the same measurement the scrape
	// carries, never a second one.
	gauge := MondefaultMetric(t, "s3ep_encryption_provider_info", map[string]string{
		"alias":           "current-provider",
		"type":            "aes",
		"kek_fingerprint": "fp-9f86d081",
	})
	require.True(t, gauge.Found, "the active provider must reach a scrape")
	assert.Equal(t, float64(1), gauge.Value)
}

// The remaining time is computed whenever the document is read. A figure taken
// when the licence was reported would be frozen at the value it had then and
// could never fall, which is the mistake the expiry gauge already avoids.
func TestMonStatusLicenseRemainingIsComputedAtReadTime(t *testing.T) {
	MonresetStatusState(t)
	// The expiry reported to the metrics is Unix seconds, so a margin under a
	// second would only be measuring that truncation.
	expiry := time.Now().Add(2500 * time.Millisecond)
	SetLicenseInfo(expiry.Format(time.RFC3339), true, float64(expiry.Unix()))

	first := StatusSnapshot().License
	require.NotNil(t, first)
	assert.Equal(t, expiry.Format(time.RFC3339), first.ExpiresAt)
	assert.True(t, first.Valid)
	assert.GreaterOrEqual(t, first.RemainingSeconds, int64(1))
	assert.Equal(t, (time.Duration(first.RemainingSeconds) * time.Second).String(), first.Remaining)

	time.Sleep(1200 * time.Millisecond)

	second := StatusSnapshot().License
	require.NotNil(t, second)
	assert.Less(t, second.RemainingSeconds, first.RemainingSeconds,
		"the remaining time must fall as the licence runs down")
}

func TestMonStatusExpiredLicenseRemainsAtZero(t *testing.T) {
	MonresetStatusState(t)
	expiry := time.Now().Add(-48 * time.Hour)
	SetLicenseInfo(expiry.Format(time.RFC3339), false, float64(expiry.Unix()))

	license := StatusSnapshot().License

	require.NotNil(t, license)
	assert.False(t, license.Valid)
	assert.Equal(t, int64(0), license.RemainingSeconds, "remaining is clamped, never negative")
	assert.Equal(t, "0s", license.Remaining)
}

// What the endpoint serves is what StatusSnapshot builds, backend observation
// included.
func TestMonStatusEndpointRendersTheObservedBackend(t *testing.T) {
	MonresetStatusState(t)
	MonresetBackendObservation(t)
	SetActiveProvider("exit-provider", "exit", "")
	recordBackendResponse(time.Now())

	body := MonstatusBody(t)

	backend, ok := body["backend"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ok", backend["status"])
	assert.Contains(t, backend, "last_response")

	encryption, ok := body["encryption"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "exit", encryption["provider_type"],
		"an exit provider means the backend holds plaintext, and an operator has to see it")
}
