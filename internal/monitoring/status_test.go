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
		"the proxy reads no license, so the document names none (ADR 0016)")
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
