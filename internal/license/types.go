package license

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// LicenseClaims represents the JWT claims for the S3 Encryption Proxy license
// LicenseClaims represents license JWT claims
//
//nolint:revive // Exported type name matches domain context
type LicenseClaims struct {
	LicenseeName        string `json:"licensee_name"`
	LicenseeCompany     string `json:"licensee_company"`
	LicenseNote         string `json:"license_note"`
	KubernetesClusterID string `json:"k8s_cluster_id"`
	jwt.RegisteredClaims
}

// LicenseInfo contains parsed and validated license information
// LicenseInfo represents license information from JWT token
//
//nolint:revive // Exported type name matches domain context
type LicenseInfo struct {
	Claims        *LicenseClaims
	Valid         bool
	ExpiresAt     time.Time
	TimeRemaining TimeRemaining
}

// TimeRemaining represents the remaining time until license expiration
type TimeRemaining struct {
	Years int
	Days  int
	Total time.Duration
}

// LicenseValidator handles JWT validation and runtime monitoring
// LicenseValidator handles license validation logic
//
//nolint:revive // Exported type name matches domain context
type LicenseValidator struct {
	info     *LicenseInfo
	stopChan chan struct{}
	doneChan chan struct{}
	// monitoring is true only while the goroutine that closes doneChan is
	// running. Stop must not wait on doneChan otherwise: without a valid
	// license StartRuntimeMonitoring returns before launching it, and the wait
	// would never end. It also guards against a second goroutine, whose own
	// deferred close would panic on an already closed channel.
	monitoring atomic.Bool
	// stopOnce makes Stop idempotent. close(stopChan) panics on a second call,
	// and a shutdown path is exactly where a double call is plausible.
	stopOnce sync.Once
}

// ValidationResult represents the result of license validation
type ValidationResult struct {
	Valid   bool
	Info    *LicenseInfo
	Error   error
	Message string
}
