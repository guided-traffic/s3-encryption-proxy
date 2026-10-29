package monitoring

import "sync"

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

// The descriptive state beside the metrics: written by startup code, read by
// every /status request.
var (
	statusMu         sync.RWMutex
	statusBuild      BuildStatus
	statusEncryption EncryptionStatus
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

// StatusSnapshot renders the current state as the status document.
func StatusSnapshot() StatusDocument {
	doc := StatusDocument{Service: statusService, Backend: backendSnapshot()}

	statusMu.RLock()
	defer statusMu.RUnlock()

	doc.Build = statusBuild
	doc.Encryption = statusEncryption
	return doc
}
