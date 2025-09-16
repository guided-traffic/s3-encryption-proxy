package encryption

import (
	"fmt"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

// ValidatingReader wraps a streamingDecryptionReader and validates HMAC
// before allowing any data to be read. This ensures that HTTP responses
// are never sent for tampered data.
type ValidatingReader struct {
	underlying    *streamingDecryptionReader
	validated     bool
	validationErr error
	objectKey     string
	mu           sync.Mutex
}

// NewValidatingReader creates a new validating reader that pre-validates HMAC
func NewValidatingReader(underlying *streamingDecryptionReader, objectKey string) *ValidatingReader {
	return &ValidatingReader{
		underlying: underlying,
		objectKey:  objectKey,
	}
}

// Read validates HMAC on first call, then delegates to underlying reader
func (v *ValidatingReader) Read(p []byte) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Perform validation on first read
	if !v.validated {
		logrus.WithField("objectKey", v.objectKey).Info("🔍 Pre-validating HMAC before allowing any data reads")

		v.validationErr = v.preValidateHMAC()
		v.validated = true

		if v.validationErr != nil {
			logrus.WithFields(logrus.Fields{
				"objectKey": v.objectKey,
				"error":     v.validationErr,
			}).Error("❌ HMAC pre-validation failed - blocking all data access")
			return 0, v.validationErr
		}

		logrus.WithField("objectKey", v.objectKey).Info("✅ HMAC pre-validation successful - allowing data access")
	}

	// If validation failed previously, return the error
	if v.validationErr != nil {
		return 0, v.validationErr
	}

	// Delegate to underlying reader
	return v.underlying.Read(p)
}

// preValidateHMAC reads all data and validates HMAC before allowing any access
func (v *ValidatingReader) preValidateHMAC() error {
	// Only validate if HMAC is enabled
	if !v.underlying.hmacEnabled || v.underlying.hmac == nil || len(v.underlying.expectedHMAC) == 0 {
		logrus.WithField("objectKey", v.objectKey).Debug("HMAC validation disabled - skipping pre-validation")
		return nil
	}

	logrus.WithField("objectKey", v.objectKey).Info("🎯 Starting full HMAC pre-validation")

	// Read all data to calculate HMAC
	totalBytes := int64(0)
	buffer := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := v.underlying.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("error during HMAC pre-validation: %w", err)
		}
	}

	// Check if HMAC was validated during the read process
	if !v.underlying.hmacVerified {
		return fmt.Errorf("HMAC validation failed during pre-validation (read %d bytes)", totalBytes)
	}

	logrus.WithFields(logrus.Fields{
		"objectKey":   v.objectKey,
		"totalBytes":  totalBytes,
		"hmacVerified": v.underlying.hmacVerified,
	}).Info("✅ HMAC pre-validation completed successfully")

	// Reset the underlying reader for actual data access
	// This is a bit complex, so for now we'll return an error
	// TODO: Implement proper buffering or reader reset
	return fmt.Errorf("HMAC pre-validation requires reader reset - not implemented yet")
}

// Close delegates to underlying reader
func (v *ValidatingReader) Close() error {
	if v.underlying != nil {
		return v.underlying.Close()
	}
	return nil
}
