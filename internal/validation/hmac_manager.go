package validation

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

const (
	// HKDF constants for integrity verification according to specification
	hmacSalt = "s3-proxy-integrity-v1"
	hmacInfo = "file-hmac-key"
)

// HMACManager provides simplified HMAC operations for data integrity verification.
// It creates calculators from DEKs, finalizes them, and verifies integrity.
type HMACManager struct {
	logger *logrus.Entry
	config *config.Config
}

// NewHMACManager creates a new HMAC manager with optional config
func NewHMACManager(cfg *config.Config) *HMACManager {
	return &HMACManager{
		logger: logrus.WithField("component", "hmac_manager"),
		config: cfg,
	}
}

// NewHMACManagerWithoutConfig creates a new HMAC manager without config (for backwards compatibility)
func NewHMACManagerWithoutConfig() *HMACManager {
	return &HMACManager{
		logger: logrus.WithField("component", "hmac_manager"),
		config: nil,
	}
}

// SetConfig sets the configuration for the HMAC manager
func (hm *HMACManager) SetConfig(cfg *config.Config) {
	hm.config = cfg
}

// CreateCalculator creates a new HMAC calculator from a Data Encryption Key (DEK).
// The DEK is used to derive an HMAC key using HKDF-SHA256.
func (hm *HMACManager) CreateCalculator(dek []byte) (*HMACCalculator, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("DEK is empty")
	}

	// Derive HMAC key from DEK using HKDF-SHA256 with fixed constants
	hkdfReader := hkdf.New(sha256.New, dek, []byte(hmacSalt), []byte(hmacInfo))

	// Generate 32-byte HMAC key (for HMAC-SHA256)
	hmacKey := make([]byte, 32)
	n, err := hkdfReader.Read(hmacKey)
	if err != nil {
		hm.logger.WithError(err).Error("HKDF key derivation failed")
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	if n != 32 {
		hm.logger.WithField("bytes_read", n).Error("HKDF key derivation returned unexpected length")
		return nil, fmt.Errorf("HKDF key derivation returned %d bytes instead of 32", n)
	}

	// Create HMAC calculator with derived key
	calculator, err := NewHMACCalculator(hmacKey)
	if err != nil {
		hm.logger.WithError(err).Error("Failed to create HMAC calculator")
		return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
	}

	hm.logger.Debug("Successfully created HMAC calculator from DEK")
	return calculator, nil
}

// FinalizeCalculator extracts the current HMAC state from the calculator,
// performs cleanup on the calculator, and returns the final HMAC value.
func (hm *HMACManager) FinalizeCalculator(calculator *HMACCalculator) []byte {
	if calculator == nil {
		hm.logger.Warn("Cannot finalize nil HMAC calculator")
		return nil
	}

	// Get current HMAC hash
	hmacValue := calculator.GetCurrentHash()

	// Clean up the calculator
	calculator.Cleanup()

	hm.logger.WithField("hmac_size", len(hmacValue)).Debug("Finalized HMAC calculator")
	return hmacValue
}

// VerifyIntegrity finalizes the calculator and verifies the integrity
// against the expected HMAC using constant-time comparison.
// The behavior depends on the configured integrity verification mode.
func (hm *HMACManager) VerifyIntegrity(calculator *HMACCalculator, expectedHMAC []byte) error {
	if calculator == nil {
		return fmt.Errorf("HMAC calculator is nil")
	}

	// Handle different integrity verification modes
	mode := hm.GetIntegrityMode()

	// If mode is off, skip verification entirely
	if mode == config.HMACVerificationOff {
		hm.logger.Debug("HMAC verification disabled (mode: off)")
		return nil
	}

	// For hybrid mode, allow missing HMAC (legacy files)
	if len(expectedHMAC) == 0 {
		if mode == config.HMACVerificationHybrid {
			hm.logger.Info("HMAC not found in metadata - delivering file normally (hybrid mode)")
			return nil
		}
		hm.logger.WithField("mode", mode).Warn("Expected HMAC is empty")
		return fmt.Errorf("expected HMAC is empty")
	}

	// Finalize calculator and get computed HMAC
	computedHMAC := hm.FinalizeCalculator(calculator)
	if computedHMAC == nil {
		return fmt.Errorf("failed to compute HMAC from calculator")
	}

	// Compare HMACs using constant-time comparison
	if !hmac.Equal(expectedHMAC, computedHMAC) {
		hm.logger.WithFields(logrus.Fields{
			"expected_hmac_size":  len(expectedHMAC),
			"computed_hmac_size":  len(computedHMAC),
			"mode":               mode,
		}).Error("HMAC verification failed - data integrity compromised")

		// Handle verification failure based on mode
		switch mode {
		case config.HMACVerificationLax:
			hm.logger.Error("HMAC verification failed but continuing delivery (lax mode)")
			return nil // Continue delivery despite failure
		case config.HMACVerificationStrict, config.HMACVerificationHybrid:
			return fmt.Errorf("HMAC verification failed: data integrity compromised")
		default:
			return fmt.Errorf("HMAC verification failed: data integrity compromised")
		}
	}

	hm.logger.WithFields(logrus.Fields{
		"hmac_size": len(expectedHMAC),
		"mode":      mode,
	}).Debug("HMAC verification successful")
	return nil
}

// IsEnabled checks if HMAC verification is enabled in the configuration
func (hm *HMACManager) IsEnabled() bool {
	if hm.config == nil {
		return false
	}
	return hm.config.Encryption.IntegrityVerification != config.HMACVerificationOff
}

// GetIntegrityMode returns the current integrity verification mode
func (hm *HMACManager) GetIntegrityMode() string {
	if hm.config == nil {
		return config.HMACVerificationOff
	}
	return hm.config.Encryption.IntegrityVerification
}

// ShouldCreateHMAC checks if HMAC should be created during upload
func (hm *HMACManager) ShouldCreateHMAC() bool {
	// HMAC should be created for all modes except "off"
	return hm.IsEnabled()
}

// ShouldVerifyHMAC checks if HMAC verification should be performed
func (hm *HMACManager) ShouldVerifyHMAC(hasHMAC bool) bool {
	mode := hm.GetIntegrityMode()

	switch mode {
	case config.HMACVerificationOff:
		return false
	case config.HMACVerificationLax, config.HMACVerificationStrict:
		return hasHMAC // Only verify if HMAC exists
	case config.HMACVerificationHybrid:
		return hasHMAC // Only verify if HMAC exists (for legacy compatibility)
	default:
		return false
	}
}

// ClearSensitiveData securely zeros out sensitive data from memory
func (hm *HMACManager) ClearSensitiveData(data []byte) {
	if data != nil {
		for i := range data {
			data[i] = 0
		}
	}
}
