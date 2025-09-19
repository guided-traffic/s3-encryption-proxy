package validation

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

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
		// Handle empty verification mode (should default to hybrid)
		if verificationMode == "" {
			verificationMode = config.HMACVerificationHybrid
		}
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

// CalculateHMACFromStream calculates HMAC for streaming data using bufio.Reader
// This is the ONLY HMAC calculation method - all operations are streaming-based
func (hm *HMACManager) CalculateHMACFromStream(reader *bufio.Reader, dek []byte) ([]byte, error) {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - skipping stream calculation")
		return nil, nil
	}

	if reader == nil {
		return nil, fmt.Errorf("reader is nil")
	}

	calculator, err := hm.CreateCalculator(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
	}

	// Stream data through the HMAC calculator
	totalBytes, err := hm.streamToCalculator(calculator, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to stream data to HMAC calculator: %w", err)
	}

	hmacValue := calculator.Sum(nil)

	hm.logger.WithFields(logrus.Fields{
		"total_bytes": totalBytes,
		"hmac_size":   len(hmacValue),
	}).Debug("Calculated HMAC from stream")

	return hmacValue, nil
}

// VerifyIntegrityFromStream verifies data integrity using HMAC with streaming data
// This is the ONLY integrity verification method - all operations are streaming-based
func (hm *HMACManager) VerifyIntegrityFromStream(dataReader *bufio.Reader, expectedHMAC []byte, dek []byte) error {
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

	calculatedHMAC, err := hm.CalculateHMACFromStream(dataReader, dek)
	if err != nil {
		hm.logger.WithError(err).Error("Failed to calculate HMAC for verification")
		return fmt.Errorf("failed to calculate HMAC: %w", err)
	}

	// Compare HMACs using constant-time comparison
	if !hmac.Equal(expectedHMAC, calculatedHMAC) {
		logFields := logrus.Fields{
			"expected_hmac_size":    len(expectedHMAC),
			"calculated_hmac_size":  len(calculatedHMAC),
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
		"hmac_size":         len(expectedHMAC),
		"verification_mode": hm.verificationMode,
	}).Debug("HMAC verification successful")

	return nil
}

// AddHMACToMetadataFromStream calculates and adds HMAC to metadata map from streaming data
// This is the ONLY method to add HMAC to metadata - all operations are streaming-based
func (hm *HMACManager) AddHMACToMetadataFromStream(metadata map[string]string, dataReader *bufio.Reader, dek []byte, metadataPrefix string) error {
	if !hm.enabled {
		hm.logger.Debug("HMAC verification disabled - not adding HMAC to metadata")
		return nil
	}

	if metadata == nil {
		return fmt.Errorf("metadata map is nil")
	}

	hmacValue, err := hm.CalculateHMACFromStream(dataReader, dek)
	if err != nil {
		return fmt.Errorf("failed to calculate HMAC for metadata: %w", err)
	}

	// Store HMAC in metadata as base64
	hmacKey := metadataPrefix + "hmac"
	metadata[hmacKey] = base64.StdEncoding.EncodeToString(hmacValue)

	hm.logger.WithFields(logrus.Fields{
		"metadata_key": hmacKey,
		"hmac_size":    len(hmacValue),
	}).Debug("Added HMAC to metadata from stream")

	return nil
}

// VerifyHMACFromMetadataStream verifies HMAC from object metadata using streaming data
// This is the ONLY method to verify HMAC from metadata - all operations are streaming-based
func (hm *HMACManager) VerifyHMACFromMetadataStream(metadata map[string]string, dataReader *bufio.Reader, dek []byte, metadataPrefix string) error {
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

	// Verify integrity using the streaming method
	if err := hm.VerifyIntegrityFromStream(dataReader, storedHMAC, dek); err != nil {
		hm.logger.WithField("metadata_key", hmacKey).Error("HMAC verification from metadata failed")
		return fmt.Errorf("HMAC verification from metadata failed: %w", err)
	}

	hm.logger.WithFields(logrus.Fields{
		"metadata_key": hmacKey,
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

// UpdateCalculatorFromStream updates an HMAC calculator with streaming data
// This provides streaming support for sequential updates (e.g., multipart uploads)
func (hm *HMACManager) UpdateCalculatorFromStream(calculator hash.Hash, dataReader *bufio.Reader, partNumber int) (int64, error) {
	if !hm.enabled || calculator == nil {
		return 0, nil
	}

	totalBytes, err := hm.streamToCalculator(calculator, dataReader)
	if err != nil {
		return 0, fmt.Errorf("failed to stream data to calculator: %w", err)
	}

	hm.logger.WithFields(logrus.Fields{
		"part_number": partNumber,
		"data_size":   totalBytes,
	}).Debug("Updated HMAC calculator with streaming data")

	return totalBytes, nil
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

// streamToCalculator efficiently streams data from bufio.Reader to hash calculator
// Returns the total number of bytes processed
func (hm *HMACManager) streamToCalculator(calculator hash.Hash, reader *bufio.Reader) (int64, error) {
	const bufferSize = 32 * 1024 // 32KB buffer for efficient streaming

	buffer := make([]byte, bufferSize)
	var totalBytes int64

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			calculator.Write(buffer[:n])
			totalBytes += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return totalBytes, fmt.Errorf("error reading from stream: %w", err)
		}
	}

	return totalBytes, nil
}

// CreateStreamingCalculator creates a streaming HMAC calculator that can be fed data incrementally
// This returns both the calculator and a function to stream data to it
func (hm *HMACManager) CreateStreamingCalculator(dek []byte) (hash.Hash, func(*bufio.Reader) (int64, error), error) {
	if !hm.enabled {
		return nil, nil, fmt.Errorf("HMAC verification is disabled")
	}

	calculator, err := hm.CreateCalculator(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HMAC calculator: %w", err)
	}

	streamFunc := func(reader *bufio.Reader) (int64, error) {
		return hm.streamToCalculator(calculator, reader)
	}

	return calculator, streamFunc, nil
}
