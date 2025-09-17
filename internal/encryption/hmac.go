package encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

const (
	// HKDF constants for integrity verification according to specification
	hmacSalt = "s3-proxy-integrity-v1"
	hmacInfo = "file-hmac-key"
)

// HMACManager handles all HMAC operations for integrity verification
type HMACManager struct {
	enabled                bool
	verificationMode       string
	config                 *config.Config
	logger                 *logrus.Entry
	keyDeriver             func(dek []byte) []byte
}

// NewHMACManager creates a new HMAC manager with configuration
func NewHMACManager(cfg *config.Config) *HMACManager {
	logger := logrus.WithField("component", "hmac_manager")

	verificationMode := config.HMACVerificationOff
	enabled := false

	if cfg != nil {
		verificationMode = cfg.Encryption.IntegrityVerification
		enabled = verificationMode != config.HMACVerificationOff
	}

	hm := &HMACManager{
		enabled:          enabled,
		verificationMode: verificationMode,
		config:           cfg,
		logger:           logger,
	}

	logger.WithFields(logrus.Fields{
		"enabled":           enabled,
		"verification_mode": verificationMode,
	}).Info("Initialized HMAC manager")

	return hm
}

// IsEnabled returns true if HMAC verification is enabled (not off)
func (hm *HMACManager) IsEnabled() bool {
	return hm.enabled
}

// GetVerificationMode returns the current HMAC verification mode
func (hm *HMACManager) GetVerificationMode() string {
	return hm.verificationMode
}

// IsStrictMode returns true if HMAC verification is in strict mode
func (hm *HMACManager) IsStrictMode() bool {
	return hm.verificationMode == config.HMACVerificationStrict
}

// IsLaxMode returns true if HMAC verification is in lax mode
func (hm *HMACManager) IsLaxMode() bool {
	return hm.verificationMode == config.HMACVerificationLax
}

// IsHybridMode returns true if HMAC verification is in hybrid mode
func (hm *HMACManager) IsHybridMode() bool {
	return hm.verificationMode == config.HMACVerificationHybrid
}

// deriveHMACKey derives HMAC key from DEK using HKDF with fixed constants
func (hm *HMACManager) deriveHMACKey(dek []byte) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("DEK is empty")
	}

	// Use HKDF-SHA256 with fixed salt and info as per specification
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

	hm.logger.Debug("Successfully derived HMAC key from DEK")
	return hmacKey, nil
}

// CreateCalculator creates a new HMAC calculator initialized with a DEK-derived key
func (hm *HMACManager) CreateCalculator(dek []byte) (hash.Hash, error) {
	if !hm.enabled {
		return nil, fmt.Errorf("HMAC verification is disabled")
	}

	hmacKey, err := hm.deriveHMACKey(dek)
	if err != nil {
		hm.logger.WithError(err).Error("Failed to derive HMAC key for calculator")
		return nil, fmt.Errorf("failed to derive HMAC key: %w", err)
	}

	// Clear the HMAC key from memory when we're done with it
	defer func() {
		for i := range hmacKey {
			hmacKey[i] = 0
		}
	}()

	calculator := hmac.New(sha256.New, hmacKey)

	hm.logger.WithField("dek_size", len(dek)).Debug("Created HMAC calculator")
	return calculator, nil
}

// CalculateHMAC calculates HMAC for given data using the DEK
func (hm *HMACManager) CalculateHMAC(data []byte, dek []byte) ([]byte, error) {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - skipping calculation")
		return nil, nil
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	calculator, err := hm.CreateCalculator(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
	}

	calculator.Write(data)
	hmacValue := calculator.Sum(nil)

	hm.logger.WithFields(logrus.Fields{
		"data_size": len(data),
		"hmac_size": len(hmacValue),
	}).Debug("Calculated HMAC")

	return hmacValue, nil
}

// VerifyIntegrity verifies data integrity using HMAC with different verification modes
func (hm *HMACManager) VerifyIntegrity(data []byte, expectedHMAC []byte, dek []byte) error {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - skipping verification")
		return nil
	}

	// Handle missing HMAC based on verification mode
	if len(expectedHMAC) == 0 {
		switch hm.verificationMode {
		case config.HMACVerificationStrict:
			hm.logger.Error("HMAC verification failed: no HMAC found in strict mode")
			return fmt.Errorf("HMAC verification failed: no HMAC found in strict mode")
		case config.HMACVerificationHybrid:
			hm.logger.Warn("No HMAC found for file - ignoring in hybrid mode (backward compatibility)")
			return nil
		case config.HMACVerificationLax:
			hm.logger.Debug("No HMAC provided - skipping verification in lax mode for backward compatibility")
			return nil
		default:
			hm.logger.Debug("No HMAC provided - skipping verification for backward compatibility")
			return nil
		}
	}

	calculatedHMAC, err := hm.CalculateHMAC(data, dek)
	if err != nil {
		hm.logger.WithError(err).Error("Failed to calculate HMAC for verification")
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}

	// Compare HMACs using constant-time comparison
	if !hmac.Equal(expectedHMAC, calculatedHMAC) {
		logFields := logrus.Fields{
			"expected_hmac_size":    len(expectedHMAC),
			"calculated_hmac_size":  len(calculatedHMAC),
			"data_size":             len(data),
			"verification_mode":     hm.verificationMode,
		}

		switch hm.verificationMode {
		case config.HMACVerificationStrict, config.HMACVerificationHybrid:
			hm.logger.WithFields(logFields).Error("HMAC verification failed - data integrity compromised")
			return fmt.Errorf("HMAC verification failed: data integrity compromised")
		case config.HMACVerificationLax:
			hm.logger.WithFields(logFields).Error("HMAC verification failed - data integrity compromised (continuing in lax mode)")
			return nil // Continue processing despite HMAC failure in lax mode
		default:
			hm.logger.WithFields(logFields).Error("HMAC verification failed - data integrity compromised")
			return fmt.Errorf("HMAC verification failed: data integrity compromised")
		}
	}

	hm.logger.WithFields(logrus.Fields{
		"data_size":         len(data),
		"hmac_size":         len(expectedHMAC),
		"verification_mode": hm.verificationMode,
	}).Debug("HMAC verification successful")

	return nil
}

// AddHMACToMetadata calculates and adds HMAC to metadata map
func (hm *HMACManager) AddHMACToMetadata(metadata map[string]string, data []byte, dek []byte, metadataPrefix string) error {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - not adding HMAC to metadata")
		return nil
	}

	if metadata == nil {
		return fmt.Errorf("metadata map is nil")
	}

	hmacValue, err := hm.CalculateHMAC(data, dek)
	if err != nil {
		return fmt.Errorf("failed to calculate HMAC for metadata: %w", err)
	}

	// Store HMAC in metadata as base64
	hmacKey := metadataPrefix + "hmac"
	metadata[hmacKey] = base64.StdEncoding.EncodeToString(hmacValue)

	hm.logger.WithFields(logrus.Fields{
		"metadata_key": hmacKey,
		"hmac_size":    len(hmacValue),
		"data_size":    len(data),
	}).Debug("Added HMAC to metadata")

	return nil
}

// VerifyHMACFromMetadata verifies HMAC from object metadata
func (hm *HMACManager) VerifyHMACFromMetadata(metadata map[string]string, data []byte, dek []byte, metadataPrefix string) error {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - skipping metadata verification")
		return nil
	}

	hmacKey := metadataPrefix + "hmac"
	hmacBase64, exists := metadata[hmacKey]
	if !exists {
		// Handle missing HMAC based on verification mode
		switch hm.verificationMode {
		case config.HMACVerificationStrict:
			hm.logger.WithField("metadata_key", hmacKey).Error("No HMAC in metadata - failing in strict mode")
			return fmt.Errorf("HMAC verification failed: no HMAC found in metadata (strict mode)")
		case config.HMACVerificationHybrid:
			hm.logger.WithField("metadata_key", hmacKey).Warn("No HMAC in metadata - ignoring in hybrid mode (backward compatibility)")
			return nil
		case config.HMACVerificationLax:
			hm.logger.WithField("metadata_key", hmacKey).Debug("No HMAC in metadata - skipping verification in lax mode for backward compatibility")
			return nil
		default:
			hm.logger.WithField("metadata_key", hmacKey).Debug("No HMAC in metadata - skipping verification for backward compatibility")
			return nil
		}
	}

	// Decode stored HMAC
	storedHMAC, err := base64.StdEncoding.DecodeString(hmacBase64)
	if err != nil {
		hm.logger.WithFields(logrus.Fields{
			"metadata_key": hmacKey,
			"error":        err,
		}).Error("Failed to decode HMAC from metadata")
		return fmt.Errorf("failed to decode stored HMAC: %w", err)
	}

	// Verify integrity using the updated VerifyIntegrity method
	if err := hm.VerifyIntegrity(data, storedHMAC, dek); err != nil {
		hm.logger.WithField("metadata_key", hmacKey).Error("HMAC verification from metadata failed")
		return fmt.Errorf("HMAC verification from metadata failed: %w", err)
	}

	hm.logger.WithFields(logrus.Fields{
		"metadata_key": hmacKey,
		"data_size":    len(data),
		"hmac_size":    len(storedHMAC),
	}).Debug("Successfully verified HMAC from metadata")

	return nil
}

// ExtractHMACFromMetadata extracts HMAC value from metadata if present
func (hm *HMACManager) ExtractHMACFromMetadata(metadata map[string]string, metadataPrefix string) ([]byte, bool, error) {
	hmacKey := metadataPrefix + "hmac"
	hmacBase64, exists := metadata[hmacKey]
	if !exists {
		return nil, false, nil
	}

	hmacBytes, err := base64.StdEncoding.DecodeString(hmacBase64)
	if err != nil {
		hm.logger.WithFields(logrus.Fields{
			"metadata_key": hmacKey,
			"error":        err,
		}).Error("Failed to decode HMAC from metadata")
		return nil, true, fmt.Errorf("failed to decode HMAC from metadata: %w", err)
	}

	hm.logger.WithFields(logrus.Fields{
		"metadata_key": hmacKey,
		"hmac_size":    len(hmacBytes),
	}).Debug("Extracted HMAC from metadata")

	return hmacBytes, true, nil
}

// UpdateCalculatorSequential updates an HMAC calculator with data in sequence
// This is used for multipart uploads where parts must be processed in order
func (hm *HMACManager) UpdateCalculatorSequential(calculator hash.Hash, data []byte, partNumber int) error {
	if !hm.enabled || calculator == nil {
		return nil
	}

	calculator.Write(data)

	hm.logger.WithFields(logrus.Fields{
		"part_number": partNumber,
		"data_size":   len(data),
	}).Debug("Updated HMAC calculator with sequential data")

	return nil
}

// FinalizeCalculator finalizes the HMAC calculation and returns the result
func (hm *HMACManager) FinalizeCalculator(calculator hash.Hash) []byte {
	if !hm.enabled || calculator == nil {
		return nil
	}

	hmacValue := calculator.Sum(nil)

	hm.logger.WithField("hmac_size", len(hmacValue)).Debug("Finalized HMAC calculation")

	return hmacValue
}

// ClearSensitiveData clears sensitive data from memory (for security)
func (hm *HMACManager) ClearSensitiveData(data []byte) {
	if data != nil {
		for i := range data {
			data[i] = 0
		}
	}
}

// IsHMACMetadata checks if the given key is an HMAC metadata key
func (hm *HMACManager) IsHMACMetadata(key, metadataPrefix string) bool {
	return key == metadataPrefix+"hmac"
}
