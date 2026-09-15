package monitoring

import (
	"sync"
	"time"
)

// statusService is the name the status document identifies this process by.
const statusService = "s3-encryption-proxy"

// StatusDocument is what /status serves: everything descriptive about this
// process in one place. It is read by a human, never by an automatic actor —
// no probe depends on any of it (ADR 0034).
type StatusDocument struct {
	Service    string           `json:"service"`
	Build      BuildStatus      `json:"build"`
	Encryption EncryptionStatus `json:"encryption"`
	Backend    BackendStatus    `json:"backend"`
	License    *LicenseStatus   `json:"license,omitempty"`
}

// BuildStatus is the build this process was made from.
type BuildStatus struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
}

// EncryptionStatus is the provider writes go through.
type EncryptionStatus struct {
	ProviderAlias  string `json:"provider_alias"`
	ProviderType   string `json:"provider_type"`
	KEKFingerprint string `json:"kek_fingerprint"`
}

// LicenseStatus carries the licence remaining, computed at read time.
type LicenseStatus struct {
	ExpiresAt        string `json:"expires_at"`
	Valid            bool   `json:"valid"`
	Remaining        string `json:"remaining"`
	RemainingSeconds int64  `json:"remaining_seconds"`
}

// The descriptive state beside the metrics: written by startup code, read by
// every /status request.
var (
	statusMu            sync.RWMutex
	statusBuild         BuildStatus
	statusEncryption    EncryptionStatus
	statusLicenseSet    bool
	statusLicenseExpiry time.Time
	statusLicenseAt     string
	statusLicenseValid  bool
)

// SetActiveProvider records the provider writes go through, for the status
// document and for the s3ep_encryption_provider_info gauge.
func SetActiveProvider(alias, providerType, fingerprint string) {
	statusMu.Lock()
	statusEncryption = EncryptionStatus{
		ProviderAlias:  alias,
		ProviderType:   providerType,
		KEKFingerprint: fingerprint,
	}
	statusMu.Unlock()

	EncryptionProviderInfo.WithLabelValues(alias, providerType, fingerprint).Set(1)
}

func setStatusBuild(version, commit, buildTime string) {
	statusMu.Lock()
	defer statusMu.Unlock()
	statusBuild = BuildStatus{Version: version, Commit: commit, BuildTime: buildTime}
}

// The expiry instant is kept, never a remaining-time figure: one taken at
// startup would be frozen at the value it had then, which is the mistake
// SetLicenseInfo already avoids for the gauge.
func setStatusLicense(expiresAt string, valid bool, expiryTimestamp float64) {
	statusMu.Lock()
	defer statusMu.Unlock()
	statusLicenseSet = true
	statusLicenseAt = expiresAt
	statusLicenseValid = valid
	statusLicenseExpiry = time.Unix(int64(expiryTimestamp), 0)
}

// StatusSnapshot renders the current state as the status document.
func StatusSnapshot() StatusDocument {
	doc := StatusDocument{Service: statusService, Backend: backendSnapshot()}

	statusMu.RLock()
	defer statusMu.RUnlock()

	doc.Build = statusBuild
	doc.Encryption = statusEncryption
	if statusLicenseSet {
		remaining := time.Until(statusLicenseExpiry).Truncate(time.Second)
		if remaining < 0 {
			remaining = 0
		}
		doc.License = &LicenseStatus{
			ExpiresAt:        statusLicenseAt,
			Valid:            statusLicenseValid,
			Remaining:        remaining.String(),
			RemainingSeconds: int64(remaining.Seconds()),
		}
	}
	return doc
}
