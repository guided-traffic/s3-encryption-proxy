package orchestration

import (
	"context"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/sirupsen/logrus"
)

// RangeReadUnsupportedError reports that a partial read cannot be served for
// this object without downloading it in full.
type RangeReadUnsupportedError struct {
	Algorithm string
}

func (e *RangeReadUnsupportedError) Error() string {
	return fmt.Sprintf("ranged decryption is not possible for algorithm %q", e.Algorithm)
}

// SupportsRangeDecryption reports whether an object described by metadata can be
// decrypted from an arbitrary offset without reading the bytes before it.
//
// AES-CTR can: its keystream is a function of the key, the IV and the byte
// position. AES-GCM cannot: the authentication tag covers the whole ciphertext,
// so the object has to be read and verified in full and the range taken from the
// plaintext afterwards. That is bounded work because GCM is only used below
// optimizations.streaming_threshold.
func (m *Manager) SupportsRangeDecryption(metadata map[string]string) bool {
	return m.metadataManager.GetAlgorithmFromMetadata(metadata) == "aes-ctr"
}

// CreateRangeDecryptionReader decrypts a ciphertext range starting at
// plaintextOffset. For AES-CTR the ciphertext and plaintext offsets are the
// same, so the caller can fetch exactly the requested byte range from the
// backend.
//
// Integrity note: the object HMAC covers the whole object and cannot be checked
// against a partial read. A ranged read therefore returns data that is
// authenticated only by the backend and the transport, not by the proxy HMAC.
// Refusing partial reads instead is not a workable alternative -- it makes every
// kopia-based Velero restore impossible, since kopia reads its pack blobs with
// small ranged GETs -- so the tradeoff is made explicit here and logged.
func (m *Manager) CreateRangeDecryptionReader(
	_ context.Context,
	encrypted io.Reader,
	metadata map[string]string,
	objectKey string,
	plaintextOffset int64,
) (io.Reader, error) {
	algorithm := m.metadataManager.GetAlgorithmFromMetadata(metadata)
	if algorithm != "aes-ctr" {
		return nil, &RangeReadUnsupportedError{Algorithm: algorithm}
	}

	fingerprint, err := m.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint from metadata: %w", err)
	}
	if fingerprint == "none-provider-fingerprint" {
		// Pass-through data: no decryption, the range is already plaintext.
		return encrypted, nil
	}

	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted DEK from metadata: %w", err)
	}
	dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}
	iv, err := m.metadataManager.GetIV(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to get IV from metadata: %w", err)
	}

	reader, err := dataencryption.NewCTRRangeReader(encrypted, dek, iv, plaintextOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to create ranged CTR reader: %w", err)
	}

	if m.hmacManager.IsEnabled() {
		if expected, hmacErr := m.metadataManager.GetHMAC(metadata); hmacErr == nil && len(expected) > 0 {
			m.logger.WithFields(logrus.Fields{
				"object_key": objectKey,
				"offset":     plaintextOffset,
			}).Debug("Ranged read: object HMAC covers the whole object and is not verified for a partial read")
		}
	}

	return reader, nil
}

// GetMetadataAlgorithm returns the DEK algorithm recorded on an object, or the
// empty string when the metadata does not name one.
func (m *Manager) GetMetadataAlgorithm(metadata map[string]string) string {
	return m.metadataManager.GetAlgorithmFromMetadata(metadata)
}
