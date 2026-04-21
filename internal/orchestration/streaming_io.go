package orchestration

import (
	"bufio"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// readCloserWrapper pairs an inner Reader with an underlying Closer. Close()
// closes both the inner Reader (if it implements io.Closer, e.g. to release
// pooled buffers or flush decryptor state) and the underlying Closer (typically
// the S3 response body), returning the first error encountered.
type readCloserWrapper struct {
	io.Reader
	closer io.Closer
}

func (r *readCloserWrapper) Close() error {
	var firstErr error
	if innerCloser, ok := r.Reader.(io.Closer); ok {
		if err := innerCloser.Close(); err != nil {
			firstErr = err
		}
	}
	if r.closer != nil {
		if err := r.closer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// encryptionReader wraps a *bufio.Reader to provide on-the-fly encryption.
// It implements the io.Reader interface and encrypts data as it's being read,
// enabling memory-efficient streaming encryption for large objects.
type encryptionReader struct {
	reader    *bufio.Reader                           // Source data reader
	encryptor *dataencryption.AESCTRStatefulEncryptor // Real streaming encryptor
	metadata  map[string]string                       // Encryption metadata to be returned
	finished  bool                                    // Flag indicating if reading is complete
	logger    *logrus.Entry                           // Logger for debugging
}

// decryptionReader wraps a *bufio.Reader to provide on-the-fly decryption.
// It implements the io.Reader interface and decrypts data as it's being read,
// enabling memory-efficient streaming decryption for large objects.
type decryptionReader struct {
	reader    *bufio.Reader                           // Source encrypted data reader
	decryptor *dataencryption.AESCTRStatefulEncryptor // Real streaming decryptor
	finished  bool                                    // Flag indicating if reading is complete
	metadata  map[string]string                       // Metadata containing HMAC for verification
	logger    *logrus.Entry                           // Logger for debugging
}

// hmacValidatingReader wraps a decryptionReader to provide HMAC validation BEFORE
// releasing the last chunk to the client. This ensures data integrity is verified
// before the HTTP response completes, preventing clients from receiving corrupted data.
type hmacValidatingReader struct {
	reader         io.Reader                   // Underlying decryption reader
	hmacCalculator *validation.HMACCalculator  // HMAC calculator for integrity verification
	hmacManager    *validation.HMACManager     // HMAC manager for verification
	expectedHMAC   []byte                      // Expected HMAC value from metadata
	objectKey      string                      // Object key for logging
	logger         *logrus.Entry               // Logger for debugging

	// Smart buffering for last chunk
	expectedSize   int64  // Total expected size from Content-Length
	totalRead      int64  // Total bytes read so far
	totalDecrypted int64  // Total bytes decrypted and passed to HMAC

	// Last chunk buffering
	lastChunkBuf   []byte // Buffer holding the last chunk for HMAC validation
	lastChunkSize  int    // Actual size of data in lastChunkBuf
	lastChunkPos   int    // Read position within lastChunkBuf
	validated      bool   // HMAC validation completed
	finished       bool   // Reading finished

	// Error state
	validationErr  error  // HMAC validation error (if any)
}

// Read implements io.Reader for encryptionReader
func (er *encryptionReader) Read(p []byte) (int, error) {
	if er.finished {
		return 0, io.EOF
	}

	n, err := er.reader.Read(p)
	if n > 0 {
		encryptedData, encErr := er.encryptor.EncryptPart(p[:n])
		if encErr != nil {
			er.logger.WithError(encErr).Error("Failed to encrypt streaming data")
			return n, fmt.Errorf("encryption failed: %w", encErr)
		}
		copy(p[:n], encryptedData)
		er.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_encrypted": len(encryptedData),
		}).Debug("Real-time encrypted streaming data")
	}

	if err != nil {
		if err == io.EOF {
			er.finished = true
			er.logger.Debug("Finished encryption reader stream")
		} else {
			er.logger.WithError(err).Error("Error reading from underlying stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for encryptionReader
func (er *encryptionReader) Close() error {
	er.logger.Debug("Closed encryption reader")
	return nil
}

// Read implements io.Reader for decryptionReader
func (dr *decryptionReader) Read(p []byte) (int, error) {
	if dr.finished {
		return 0, io.EOF
	}

	n, err := dr.reader.Read(p)
	if n > 0 {
		decryptedData, decErr := dr.decryptor.DecryptPart(p[:n])
		if decErr != nil {
			dr.logger.WithError(decErr).Error("Failed to decrypt streaming data")
			return n, fmt.Errorf("decryption failed: %w", decErr)
		}
		copy(p[:n], decryptedData)
		dr.logger.WithFields(logrus.Fields{
			"bytes_read":      n,
			"bytes_decrypted": len(decryptedData),
		}).Trace("Real-time decrypted streaming data")
	}

	if err != nil {
		if err == io.EOF {
			dr.finished = true
			dr.logger.Debug("Finished decryption reader stream")
		} else {
			dr.logger.WithError(err).Error("Error reading from underlying encrypted stream")
		}
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for decryptionReader
func (dr *decryptionReader) Close() error {
	dr.logger.Debug("Closed decryption reader")
	return nil
}

// Read implements io.Reader for hmacValidatingReader
func (hvr *hmacValidatingReader) Read(p []byte) (int, error) {
	if hvr.finished {
		return 0, io.EOF
	}

	if hvr.validationErr != nil {
		return 0, hvr.validationErr
	}

	// Serve buffered data from last chunk first
	if hvr.lastChunkSize > 0 && hvr.lastChunkPos < hvr.lastChunkSize {
		remaining := hvr.lastChunkSize - hvr.lastChunkPos
		n := remaining
		if n > len(p) {
			n = len(p)
		}
		copy(p, hvr.lastChunkBuf[hvr.lastChunkPos:hvr.lastChunkPos+n])
		hvr.lastChunkPos += n

		if hvr.lastChunkPos >= hvr.lastChunkSize {
			hvr.finished = true
			hvr.logger.WithFields(logrus.Fields{
				"object_key":      hvr.objectKey,
				"total_decrypted": hvr.totalDecrypted,
			}).Info("✅ Completed secure streaming with HMAC validation")
			return n, io.EOF
		}
		return n, nil
	}

	// Read from underlying reader
	n, err := hvr.reader.Read(p)

	if n > 0 {
		if hvr.hmacCalculator != nil {
			if _, hmacErr := hvr.hmacCalculator.Add(p[:n]); hmacErr != nil {
				hvr.logger.WithError(hmacErr).Error("Failed to update HMAC during streaming")
				hvr.validationErr = fmt.Errorf("HMAC calculation failed: %w", hmacErr)
				return 0, hvr.validationErr
			}
		}

		hvr.totalRead += int64(n)
		hvr.totalDecrypted += int64(n)

		// Check if near end for buffering
		bufferThreshold := hvr.expectedSize - (2 * int64(len(p)))
		if hvr.expectedSize > 0 && hvr.totalRead >= bufferThreshold && err == nil {
			hvr.logger.WithFields(logrus.Fields{
				"object_key":    hvr.objectKey,
				"total_read":    hvr.totalRead,
				"expected_size": hvr.expectedSize,
			}).Debug("🔒 Near end of stream - preparing to buffer last chunk")
			return n, nil
		}
	}

	// Handle EOF - this is the last chunk
	if err == io.EOF {
		hvr.logger.WithFields(logrus.Fields{
			"object_key":      hvr.objectKey,
			"last_chunk_size": n,
			"total_read":      hvr.totalRead,
		}).Info("🔍 Last chunk detected - buffering for HMAC validation")

		// Buffer this last chunk
		if hvr.lastChunkBuf == nil {
			hvr.lastChunkBuf = make([]byte, len(p))
		}
		copy(hvr.lastChunkBuf, p[:n])
		hvr.lastChunkSize = n
		hvr.lastChunkPos = 0

		// Validate HMAC before releasing
		if hvr.hmacManager != nil && hvr.hmacCalculator != nil && len(hvr.expectedHMAC) > 0 {
			hvr.logger.WithField("object_key", hvr.objectKey).Info("⏳ Validating HMAC before releasing last chunk...")

			if verifyErr := hvr.hmacManager.VerifyIntegrity(hvr.hmacCalculator, hvr.expectedHMAC); verifyErr != nil {
				hvr.logger.WithError(verifyErr).WithField("object_key", hvr.objectKey).Error("❌ HMAC validation FAILED")
				hvr.validationErr = fmt.Errorf("HMAC integrity verification failed: %w", verifyErr)
				hvr.finished = true
				return 0, hvr.validationErr
			}

			hvr.validated = true
			hvr.logger.WithField("object_key", hvr.objectKey).Info("✅ HMAC validation SUCCESSFUL - releasing last chunk")
		}

		// Serve buffered chunk
		return hvr.Read(p)
	}

	if err != nil {
		hvr.logger.WithError(err).Error("Error reading during HMAC validating stream")
		return n, err
	}

	return n, nil
}

// Close implements io.Closer for hmacValidatingReader
func (hvr *hmacValidatingReader) Close() error {
	if hvr.lastChunkBuf != nil {
		clear(hvr.lastChunkBuf)
		hvr.lastChunkBuf = nil
	}
	if hvr.hmacCalculator != nil {
		hvr.hmacCalculator.Cleanup()
		hvr.hmacCalculator = nil
	}
	if closer, ok := hvr.reader.(io.Closer); ok {
		return closer.Close()
	}
	hvr.logger.Debug("Closed HMAC validating reader and cleaned up resources")
	return nil
}
