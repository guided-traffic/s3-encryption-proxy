package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// ===== Fixtures and helpers (every identifier carries the OrcPart token) =====

// OrcPartAESKeyB64 is a base64-encoded 256-bit AES KEK ("abcdefghijklmnopqrstuvwxyz123456").
const OrcPartAESKeyB64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

// OrcPartThreshold is the configured streaming threshold used by the boundary
// tests. Small on purpose: the boundary is what matters, not the byte count.
const OrcPartThreshold = 4096

// OrcPartSegmentSize keeps the per-part read buffer small. MultipartOperations
// pre-sizes one buffer of this size on every ProcessPart call.
const OrcPartSegmentSize int64 = 64 * 1024

// OrcPartSHA256 returns the hex-encoded SHA256 digest. Payloads are always
// compared by digest, never dumped.
func OrcPartSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OrcPartPayload builds a deterministic, non-repeating payload of n bytes.
func OrcPartPayload(n int) []byte {
	data := make([]byte, n)
	for i := range data {
		data[i] = byte((i*31 + 7) % 251)
	}
	return data
}

// OrcPartPrefixPtr returns a pointer to s, for EncryptionConfig.MetadataKeyPrefix.
func OrcPartPrefixPtr(s string) *string {
	return &s
}

// OrcPartReader wraps data in the *bufio.Reader the orchestration API takes.
func OrcPartReader(data []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(data))
}

// OrcPartAESConfig builds a config with one active AES provider and the given
// integrity-verification mode.
func OrcPartAESConfig(integrityMode string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcpart-aes",
			MetadataKeyPrefix:     OrcPartPrefixPtr("s3ep-"),
			IntegrityVerification: integrityMode,
			Providers: []config.EncryptionProvider{
				{
					Alias: "orcpart-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": OrcPartAESKeyB64,
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: OrcPartSegmentSize,
			StreamingThreshold:   OrcPartThreshold,
		},
	}
}

// OrcPartNoneConfig builds a config whose active provider is the pass-through
// "none" provider.
func OrcPartNoneConfig() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcpart-none",
			MetadataKeyPrefix:     OrcPartPrefixPtr("s3ep-"),
			IntegrityVerification: config.HMACVerificationOff,
			Providers: []config.EncryptionProvider{
				{Alias: "orcpart-none", Type: "none", Config: map[string]interface{}{}},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: OrcPartSegmentSize,
			StreamingThreshold:   OrcPartThreshold,
		},
	}
}

// OrcPartNewManager builds a Manager and shuts it down with the test so no
// background goroutine outlives it.
func OrcPartNewManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, m.Shutdown(ctx))
	})
	return m
}

// OrcPartFailingReader hands out its payload once and then fails.
type OrcPartFailingReader struct {
	payload []byte
	off     int
	err     error
}

func (r *OrcPartFailingReader) Read(p []byte) (int, error) {
	if r.off < len(r.payload) {
		n := copy(p, r.payload[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

// OrcPartCountingCloser counts Close calls on a backend body.
type OrcPartCountingCloser struct {
	io.Reader
	closes int
	err    error
}

func (c *OrcPartCountingCloser) Close() error {
	c.closes++
	return c.err
}

// OrcPartAttachHMAC computes the object HMAC the proxy writes for plaintext and
// stores it under the metadata key the decryptor reads.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func OrcPartAttachHMAC(t *testing.T, m *Manager, metadata map[string]string, plaintext []byte, objectKey string) {
	t.Helper()
	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	require.NoError(t, err)
	fingerprint, err := m.metadataManager.GetFingerprint(metadata)
	require.NoError(t, err)
	dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	require.NoError(t, err)

	calculator, err := m.hmacManager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calculator.Add(plaintext)
	require.NoError(t, err)
	m.metadataManager.SetHMAC(metadata, m.hmacManager.FinalizeCalculator(calculator))
}

// ===== Client contract: what goes in comes back out, and never in the clear =====

// TestOrcPartSinglePartRoundTripBoundarySizes drives both single-part write
// paths at the streaming threshold and one byte either side of it, plus the
// empty and one-byte objects. The contract asserted is the client's: the bytes
// handed to the backend are not the plaintext, and the bytes read back are
// byte-identical to what was written.
func TestOrcPartSinglePartRoundTripBoundarySizes(t *testing.T) {
	ctx := context.Background()

	for _, mode := range []string{config.HMACVerificationStrict, config.HMACVerificationOff} {
		for _, size := range []int{0, 1, OrcPartThreshold - 1, OrcPartThreshold, OrcPartThreshold + 1} {
			for _, enc := range []struct {
				name string
				call func(m *Manager, r *bufio.Reader, key string) (*StreamingEncryptionResult, error)
			}{
				{"gcm", func(m *Manager, r *bufio.Reader, key string) (*StreamingEncryptionResult, error) {
					return m.EncryptGCM(ctx, r, key)
				}},
				{"ctr", func(m *Manager, r *bufio.Reader, key string) (*StreamingEncryptionResult, error) {
					return m.EncryptCTR(ctx, r, key)
				}},
			} {
				t.Run(fmt.Sprintf("%s/%s/%d", mode, enc.name, size), func(t *testing.T) {
					m := OrcPartNewManager(t, OrcPartAESConfig(mode))
					plaintext := OrcPartPayload(size)
					key := fmt.Sprintf("bucket/%s-%d", enc.name, size)

					res, err := enc.call(m, OrcPartReader(plaintext), key)
					require.NoError(t, err)
					require.NotNil(t, res)

					ciphertext, err := io.ReadAll(res.EncryptedDataReader)
					require.NoError(t, err)
					if size > 0 {
						assert.NotEqual(t, OrcPartSHA256(plaintext), OrcPartSHA256(ciphertext),
							"plaintext must never be what the backend stores")
					}

					decrypted, err := m.DecryptData(ctx, OrcPartReader(ciphertext), res.Metadata, key)
					require.NoError(t, err)
					got, err := io.ReadAll(decrypted)
					require.NoError(t, err)
					assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))
					assert.Len(t, got, size)
				})
			}
		}
	}
}

// TestOrcPartEncryptedObjectMetadataIsOnlyTheAllowedKeys pins the metadata the
// two single-part write paths emit.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartEncryptedObjectMetadataIsOnlyTheAllowedKeys(t *testing.T) {
	allowed := map[string]bool{
		"s3ep-dek-algorithm":   true,
		"s3ep-encrypted-dek":   true,
		"s3ep-aes-iv":          true,
		"s3ep-kek-algorithm":   true,
		"s3ep-kek-fingerprint": true,
		"s3ep-hmac":            true,
	}

	t.Run("gcm", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		res, err := m.EncryptGCM(context.Background(), OrcPartReader(OrcPartPayload(64)), "k")
		require.NoError(t, err)
		for key := range res.Metadata {
			assert.True(t, allowed[key], "unexpected metadata key %q", key)
		}
		assert.Equal(t, "aes-gcm", res.Metadata["s3ep-dek-algorithm"])
		assert.Equal(t, "aes-gcm", res.Algorithm)
		assert.NotContains(t, res.Metadata, "s3ep-hmac",
			"the GCM write path stores no separable HMAC even in strict mode")
	})

	t.Run("ctr", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		res, err := m.EncryptCTR(context.Background(), OrcPartReader(OrcPartPayload(64)), "k")
		require.NoError(t, err)
		for key := range res.Metadata {
			assert.True(t, allowed[key], "unexpected metadata key %q", key)
		}
		assert.Equal(t, "aes-ctr", res.Metadata["s3ep-dek-algorithm"])
		assert.Equal(t, "aes-ctr", res.Algorithm)
		assert.Contains(t, res.Metadata, "s3ep-hmac")
		iv, err := base64.StdEncoding.DecodeString(res.Metadata["s3ep-aes-iv"])
		require.NoError(t, err)
		assert.Len(t, iv, 16)
	})

	t.Run("ctr without hmac mode", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		res, err := m.EncryptCTR(context.Background(), OrcPartReader(OrcPartPayload(64)), "k")
		require.NoError(t, err)
		assert.NotContains(t, res.Metadata, "s3ep-hmac")
		assert.Equal(t, "aes-ctr", res.Metadata["s3ep-dek-algorithm"])
	})
}

// TestOrcPartCTRCiphertextIsTheSameLengthAsThePlaintext is what makes ranged
// reads possible at all; a change here changes the whole GET story.
func TestOrcPartCTRCiphertextIsTheSameLengthAsThePlaintext(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
	for _, size := range []int{0, 1, 15, 16, 17, 8192} {
		res, err := m.EncryptCTR(context.Background(), OrcPartReader(OrcPartPayload(size)), "k")
		require.NoError(t, err)
		ciphertext, err := io.ReadAll(res.EncryptedDataReader)
		require.NoError(t, err)
		assert.Len(t, ciphertext, size)
	}
}

// ===== Encryption failure paths =====

// TestOrcPartEncryptFailsWhenTheActiveKeyIsUnavailable makes the active
// fingerprint unresolvable, which is what a mid-flight KEK removal looks like.
// Neither write path may fall back to storing plaintext.
func TestOrcPartEncryptFailsWhenTheActiveKeyIsUnavailable(t *testing.T) {
	ctx := context.Background()

	for _, mode := range []string{config.HMACVerificationStrict, config.HMACVerificationOff} {
		t.Run(mode, func(t *testing.T) {
			m := OrcPartNewManager(t, OrcPartAESConfig(mode))
			m.providerManager.activeFingerprint = "fingerprint-of-a-key-that-is-gone"

			_, err := m.EncryptGCM(ctx, OrcPartReader(OrcPartPayload(32)), "k")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to create envelope encryptor")

			_, err = m.EncryptCTR(ctx, OrcPartReader(OrcPartPayload(32)), "k")
			require.Error(t, err)
			if mode == config.HMACVerificationOff {
				assert.Contains(t, err.Error(), "failed to create envelope encryptor")
			} else {
				assert.Contains(t, err.Error(), "failed to encrypt DEK")
			}
		})
	}
}

// TestOrcPartEncryptPropagatesSourceReadErrors: a body that dies mid-upload must
// surface as an error, never as a short object.
func TestOrcPartEncryptPropagatesSourceReadErrors(t *testing.T) {
	boom := errors.New("connection reset by peer")
	ctx := context.Background()

	t.Run("gcm reads eagerly and fails at encryption time", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		src := bufio.NewReader(&OrcPartFailingReader{payload: OrcPartPayload(64), err: boom})
		_, err := m.EncryptGCM(ctx, src, "k")
		require.Error(t, err)
		assert.ErrorIs(t, err, boom)
		assert.Contains(t, err.Error(), "failed to encrypt stream with GCM")
	})

	t.Run("ctr with hmac buffers and fails at encryption time", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		src := bufio.NewReader(&OrcPartFailingReader{payload: OrcPartPayload(64), err: boom})
		_, err := m.EncryptCTR(ctx, src, "k")
		require.Error(t, err)
		assert.ErrorIs(t, err, boom)
		assert.Contains(t, err.Error(), "failed to read plaintext for CTR encryption")
	})

	t.Run("ctr without hmac streams and fails on read", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		src := bufio.NewReader(&OrcPartFailingReader{payload: OrcPartPayload(64), err: boom})
		res, err := m.EncryptCTR(ctx, src, "k")
		require.NoError(t, err, "the streaming path only fails when the caller reads")
		_, err = io.ReadAll(res.EncryptedDataReader)
		require.Error(t, err)
		assert.ErrorIs(t, err, boom)
	})
}

// ===== GCM decryption =====

// TestOrcPartDecryptGCMStreamRejectsEmptyCiphertext: a zero-byte body cannot be
// a GCM object (nonce plus tag is 28 bytes), and must not be served as an empty
// plaintext.
func TestOrcPartDecryptGCMStreamRejectsEmptyCiphertext(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	_, md := OrcPartEncryptGCMBytes(t, m, OrcPartPayload(16), "k")

	_, err := m.DecryptGCMStream(context.Background(), OrcPartReader(nil), md, "k")
	require.Error(t, err)
	assert.Equal(t, "encrypted data is empty", err.Error())
}

// OrcPartEncryptGCMBytes encrypts through the whole-object path and drains the
// ciphertext.
func OrcPartEncryptGCMBytes(t *testing.T, m *Manager, plaintext []byte, key string) ([]byte, map[string]string) {
	t.Helper()
	res, err := m.EncryptGCM(context.Background(), OrcPartReader(plaintext), key)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	return ciphertext, res.Metadata
}

// OrcPartEncryptCTRBytes encrypts through the streaming path and drains the
// ciphertext.
func OrcPartEncryptCTRBytes(t *testing.T, m *Manager, plaintext []byte, key string) ([]byte, map[string]string) {
	t.Helper()
	res, err := m.EncryptCTR(context.Background(), OrcPartReader(plaintext), key)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	return ciphertext, res.Metadata
}

// TestOrcPartDecryptGCMStreamRejectsBrokenMetadata walks every metadata field
// the GCM read path needs. A missing or unusable field must fail the read, not
// hand the stored bytes to the client.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartDecryptGCMStreamRejectsBrokenMetadata(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	plaintext := OrcPartPayload(256)
	ciphertext, base := OrcPartEncryptGCMBytes(t, m, plaintext, "k")

	tests := []struct {
		name    string
		mutate  func(md map[string]string)
		wantMsg string
	}{
		{
			name:    "no kek fingerprint",
			mutate:  func(md map[string]string) { delete(md, "s3ep-kek-fingerprint") },
			wantMsg: "failed to get fingerprint",
		},
		{
			name:    "no encrypted dek",
			mutate:  func(md map[string]string) { delete(md, "s3ep-encrypted-dek") },
			wantMsg: "failed to get encrypted DEK",
		},
		{
			name:    "encrypted dek is not base64",
			mutate:  func(md map[string]string) { md["s3ep-encrypted-dek"] = "!!! not base64 !!!" },
			wantMsg: "failed to get encrypted DEK",
		},
		{
			name:    "fingerprint of an unknown key",
			mutate:  func(md map[string]string) { md["s3ep-kek-fingerprint"] = "0000deadbeef" },
			wantMsg: "failed to decrypt DEK",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			md := make(map[string]string, len(base))
			for k, v := range base {
				md[k] = v
			}
			tc.mutate(md)

			_, err := m.DecryptGCMStream(context.Background(), OrcPartReader(ciphertext), md, "k")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestOrcPartDecryptGCMStreamVerifiesAttachedHMAC covers the HMAC-validating
// branch of the GCM read path: a matching HMAC delivers the plaintext, a wrong
// one must fail before the final bytes are released.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartDecryptGCMStreamVerifiesAttachedHMAC(t *testing.T) {
	ctx := context.Background()
	plaintext := OrcPartPayload(9000)

	t.Run("matching hmac delivers the plaintext", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		ciphertext, md := OrcPartEncryptGCMBytes(t, m, plaintext, "k")
		OrcPartAttachHMAC(t, m, md, plaintext, "k")

		reader, err := m.DecryptGCMStream(ctx, OrcPartReader(ciphertext), md, "k")
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))
	})

	t.Run("wrong hmac fails the read", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		ciphertext, md := OrcPartEncryptGCMBytes(t, m, plaintext, "k")
		OrcPartAttachHMAC(t, m, md, append(append([]byte(nil), plaintext...), 'x'), "k")

		reader, err := m.DecryptGCMStream(ctx, OrcPartReader(ciphertext), md, "k")
		require.NoError(t, err, "the failure is raised while streaming, not at construction")
		_, err = io.ReadAll(reader)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HMAC")
	})
}

// TestOrcPartDecryptGCMStreamWithoutHMACSkipsVerification records that "strict"
// integrity mode does not require an HMAC to be present: an object whose
// s3ep-hmac metadata is absent is delivered with no integrity check and no
// error, which is the behaviour documented for "hybrid", not for "strict".
// For GCM the auth tag still covers the ciphertext, so the practical exposure
// is on the AES-CTR path (see TestOrcPartStrictModeDeliversTamperedCTRObject...).
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartDecryptGCMStreamWithoutHMACSkipsVerification(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
	plaintext := OrcPartPayload(512)
	ciphertext, md := OrcPartEncryptGCMBytes(t, m, plaintext, "k")
	require.NotContains(t, md, "s3ep-hmac")

	reader, err := m.DecryptGCMStream(context.Background(), OrcPartReader(ciphertext), md, "k")
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))
}

// ===== CTR decryption =====

// TestOrcPartDecryptCTRStreamRejectsBrokenMetadata: the CTR read path needs the
// IV as well as the wrapped DEK.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartDecryptCTRStreamRejectsBrokenMetadata(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	ciphertext, base := OrcPartEncryptCTRBytes(t, m, OrcPartPayload(1024), "k")

	tests := []struct {
		name    string
		mutate  func(md map[string]string)
		wantMsg string
	}{
		{"no iv", func(md map[string]string) { delete(md, "s3ep-aes-iv") }, "failed to get IV from metadata"},
		{"truncated iv", func(md map[string]string) {
			md["s3ep-aes-iv"] = base64.StdEncoding.EncodeToString([]byte("short"))
		}, "invalid IV size"},
		{"no encrypted dek", func(md map[string]string) { delete(md, "s3ep-encrypted-dek") }, "failed to get encrypted DEK"},
		{"no fingerprint", func(md map[string]string) { delete(md, "s3ep-kek-fingerprint") }, "failed to get fingerprint"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			md := make(map[string]string, len(base))
			for k, v := range base {
				md[k] = v
			}
			tc.mutate(md)

			_, err := m.DecryptCTRStream(context.Background(), OrcPartReader(ciphertext), md, "k")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to create decryption reader")
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestOrcPartStrictModeDeliversTamperedCTRObjectWithoutHMACMetadata is the
// integrity bypass that matters: anyone able to rewrite the object's user
// metadata in the backend can delete the s3ep-hmac key, and the download path
// then serves flipped ciphertext bits as plaintext without an error, in strict
// mode. AES-CTR is malleable, so this is an undetected corruption channel.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartStrictModeDeliversTamperedCTRObjectWithoutHMACMetadata(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
	plaintext := OrcPartPayload(8192)
	key := "bucket/hmac-stripped"

	ciphertext, md := OrcPartEncryptCTRBytes(t, m, plaintext, key)
	require.Contains(t, md, "s3ep-hmac", "the upload wrote an integrity tag")

	// The tag is user metadata: whoever holds the backend credentials can drop it.
	delete(md, "s3ep-hmac")

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xFF

	body := &OrcPartCountingCloser{Reader: bytes.NewReader(tampered)}
	reader, err := m.CreateStreamingDecryptionReaderWithSize(
		context.Background(), body, nil, md, key, "", int64(len(plaintext)))
	require.NoError(t, err)

	got, err := io.ReadAll(reader)
	require.NoError(t, err, "no integrity error is raised once the HMAC metadata is gone")
	assert.NotEqual(t, OrcPartSHA256(plaintext), OrcPartSHA256(got),
		"the client is served corrupted plaintext, undetected")

	require.NoError(t, reader.Close())
	assert.Equal(t, 1, body.closes, "the backend body is released")
}

// TestOrcPartCreateStreamingDecryptionReaderWithSizeErrors surfaces broken
// metadata before any byte is handed out, and leaves the backend body to the
// caller's own defer.
func TestOrcPartCreateStreamingDecryptionReaderWithSizeErrors(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
	body := &OrcPartCountingCloser{Reader: bytes.NewReader(OrcPartPayload(64))}

	_, err := m.CreateStreamingDecryptionReaderWithSize(
		context.Background(), body, nil, map[string]string{"unrelated": "value"}, "k", "", 64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create decryption reader")
	assert.Contains(t, err.Error(), "failed to get fingerprint from metadata")
	assert.Equal(t, 0, body.closes,
		"the failed constructor does not close the body it was handed")
}

// TestOrcPartNoneProviderFingerprintBypassesDecryption pins the pass-through
// escape hatch: metadata naming the none-provider fingerprint returns the
// stored bytes unchanged, whatever the rest of the metadata says.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartNoneProviderFingerprintBypassesDecryption(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
	stored := OrcPartPayload(777)

	md := map[string]string{
		"s3ep-kek-fingerprint": "none-provider-fingerprint",
		"s3ep-dek-algorithm":   "aes-ctr",
	}
	reader, err := m.DecryptCTRStream(context.Background(), OrcPartReader(stored), md, "k")
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, OrcPartSHA256(stored), OrcPartSHA256(got))
}

// ===== DecryptDataWithMetadata: the entry point the GET handlers use =====

// TestOrcPartDecryptDataWithMetadataClosesTheBackendBody covers the ownership
// contract of the ReadCloser the handler gets back: closing it must release the
// backend response body exactly once.
func TestOrcPartDecryptDataWithMetadataClosesTheBackendBody(t *testing.T) {
	ctx := context.Background()
	plaintext := OrcPartPayload(4096)

	t.Run("closer source is closed through the wrapper", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationStrict))
		ciphertext, md := OrcPartEncryptGCMBytes(t, m, plaintext, "k")

		body := &OrcPartCountingCloser{Reader: bytes.NewReader(ciphertext)}
		reader, err := m.DecryptDataWithMetadata(ctx, body, md, "k")
		require.NoError(t, err)

		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))

		require.NoError(t, reader.Close())
		assert.Equal(t, 1, body.closes)
	})

	t.Run("non-closer source still yields a closable reader", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		ciphertext, md := OrcPartEncryptCTRBytes(t, m, plaintext, "k")

		reader, err := m.DecryptDataWithMetadata(ctx, bytes.NewReader(ciphertext), md, "k")
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))
		require.NoError(t, reader.Close())
	})

	t.Run("bufio source is used as-is", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		ciphertext, md := OrcPartEncryptCTRBytes(t, m, plaintext, "k")

		reader, err := m.DecryptDataWithMetadata(ctx, OrcPartReader(ciphertext), md, "k")
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, OrcPartSHA256(plaintext), OrcPartSHA256(got))
	})

	t.Run("broken metadata surfaces as an error and yields no reader", func(t *testing.T) {
		m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
		body := &OrcPartCountingCloser{Reader: bytes.NewReader(OrcPartPayload(32))}

		reader, err := m.DecryptDataWithMetadata(ctx, body,
			map[string]string{"s3ep-dek-algorithm": "chacha20"}, "k")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown algorithm: chacha20")
		assert.Nil(t, reader)
		assert.Equal(t, 0, body.closes)
	})
}

// ===== isNoneProviderData: which objects are treated as unencrypted =====

// TestOrcPartIsNoneProviderDataDecision documents exactly what the check
// decides: it answers "yes, pass this through unencrypted" for ANY metadata map
// that has no key starting with the prefix it computes from the config. It
// never looks at the KEK fingerprint or the DEK algorithm.
func TestOrcPartIsNoneProviderDataDecision(t *testing.T) {
	tests := []struct {
		name       string
		prefix     *string
		metadata   map[string]string
		wantIsNone bool
	}{
		{"nil metadata", OrcPartPrefixPtr("s3ep-"), nil, true},
		{"empty metadata", OrcPartPrefixPtr("s3ep-"), map[string]string{}, true},
		{"only user metadata", OrcPartPrefixPtr("s3ep-"), map[string]string{"content-owner": "hans"}, true},
		{"one s3ep key is enough", OrcPartPrefixPtr("s3ep-"), map[string]string{"s3ep-hmac": "x"}, false},
		{"prefix is case sensitive", OrcPartPrefixPtr("s3ep-"), map[string]string{"S3EP-encrypted-dek": "x"}, true},
		{"custom prefix matches", OrcPartPrefixPtr("enc-"), map[string]string{"enc-encrypted-dek": "x"}, false},
		{"custom prefix ignores the default one", OrcPartPrefixPtr("enc-"), map[string]string{"s3ep-encrypted-dek": "x"}, true},
		{"nil prefix falls back to s3ep-", nil, map[string]string{"s3ep-encrypted-dek": "x"}, false},
		{
			name:       "empty prefix falls back to s3ep- while the writer does not",
			prefix:     OrcPartPrefixPtr(""),
			metadata:   map[string]string{"encrypted-dek": "x", "dek-algorithm": "aes-ctr"},
			wantIsNone: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := OrcPartAESConfig(config.HMACVerificationStrict)
			cfg.Encryption.MetadataKeyPrefix = tc.prefix
			m := OrcPartNewManager(t, cfg)
			assert.Equal(t, tc.wantIsNone, m.isNoneProviderData(tc.metadata))
		})
	}
}

// TestOrcPartEmptyMetadataPrefixServesCiphertextAsPlaintext is the consequence
// of the last row above. With metadata_key_prefix configured as the empty
// string the writer stores its metadata unprefixed, while isNoneProviderData
// keeps looking for "s3ep-". Every GET then classifies the object as
// pass-through and hands the raw ciphertext to the client as if it were the
// plaintext - silently, with a 200.
func TestOrcPartEmptyMetadataPrefixServesCiphertextAsPlaintext(t *testing.T) {
	cfg := OrcPartAESConfig(config.HMACVerificationStrict)
	cfg.Encryption.MetadataKeyPrefix = OrcPartPrefixPtr("")
	m := OrcPartNewManager(t, cfg)

	plaintext := OrcPartPayload(2048)
	res, err := m.EncryptCTR(context.Background(), OrcPartReader(plaintext), "k")
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	require.Contains(t, res.Metadata, "encrypted-dek", "metadata is written unprefixed")

	got, err := m.DecryptData(context.Background(), OrcPartReader(ciphertext), res.Metadata, "k")
	require.NoError(t, err)
	served, err := io.ReadAll(got)
	require.NoError(t, err)

	assert.Equal(t, OrcPartSHA256(ciphertext), OrcPartSHA256(served),
		"the client receives the stored ciphertext")
	assert.NotEqual(t, OrcPartSHA256(plaintext), OrcPartSHA256(served))
}

// ===== Internal helpers reached only through failure injection =====

// TestOrcPartStreamingCryptorConstruction pins the input validation of the two
// stateful-cryptor helpers.
func TestOrcPartStreamingCryptorConstruction(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))

	t.Run("encryptor rejects a short DEK", func(t *testing.T) {
		_, err := m.createStreamingEncryptor([]byte("too short"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create AES-CTR streaming encryptor")
	})

	t.Run("encryptor accepts a 32 byte DEK", func(t *testing.T) {
		enc, err := m.createStreamingEncryptor(OrcPartPayload(32))
		require.NoError(t, err)
		require.NotNil(t, enc)
		assert.Len(t, enc.GetIV(), 16)
		enc.Cleanup()
	})

	t.Run("decryptor needs the IV from metadata", func(t *testing.T) {
		_, err := m.createStreamingDecryptor(OrcPartPayload(32), map[string]string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get IV from metadata")
	})
}

// TestOrcPartBuildEncryptionMetadataSimpleNeedsAKEK: the none-provider
// fingerprint has no key encryptor, so metadata cannot be built for it.
func TestOrcPartBuildEncryptionMetadataSimpleNeedsAKEK(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	encryptor, err := m.createStreamingEncryptor(OrcPartPayload(32))
	require.NoError(t, err)
	defer encryptor.Cleanup()

	m.providerManager.activeFingerprint = "none-provider-fingerprint"
	_, err = m.buildEncryptionMetadataSimple(context.Background(), OrcPartPayload(32), encryptor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get provider")
}

// TestOrcPartCreateDecryptionReaderRejectsMetadataWithoutIV covers the generic
// reader factory, which the range and streaming paths share.
func TestOrcPartCreateDecryptionReaderRejectsMetadataWithoutIV(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	_, md := OrcPartEncryptCTRBytes(t, m, OrcPartPayload(64), "k")
	delete(md, "s3ep-aes-iv")

	_, err := m.CreateDecryptionReader(context.Background(), bytes.NewReader(nil), md)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create streaming decryptor")
}

// TestOrcPartDecryptRejectsAnUnknownFingerprint: an object wrapped under a KEK
// this proxy does not hold must fail the read on both algorithm paths.
func TestOrcPartDecryptRejectsAnUnknownFingerprint(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	ciphertext, md := OrcPartEncryptCTRBytes(t, m, OrcPartPayload(512), "k")
	md["s3ep-kek-fingerprint"] = "fingerprint-of-a-key-we-do-not-hold"

	_, err := m.CreateDecryptionReader(context.Background(), bytes.NewReader(ciphertext), md)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt DEK")
	assert.Contains(t, err.Error(), "no provider found with fingerprint")
}

// TestOrcPartDecryptGCMStreamRejectsTheNoneProviderFingerprint records an
// asymmetry between the two read paths: metadata naming the none-provider
// fingerprint makes the CTR path pass the stored bytes through, while the GCM
// path fails because no pass-through key encryptor is registered.
//
// Pins current v1 storage-format behaviour. Ticket 013 replaces this; update together.
func TestOrcPartDecryptGCMStreamRejectsTheNoneProviderFingerprint(t *testing.T) {
	m := OrcPartNewManager(t, OrcPartAESConfig(config.HMACVerificationOff))
	ciphertext, md := OrcPartEncryptGCMBytes(t, m, OrcPartPayload(512), "k")
	md["s3ep-kek-fingerprint"] = "none-provider-fingerprint"

	_, err := m.DecryptGCMStream(context.Background(), OrcPartReader(ciphertext), md, "k")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create GCM envelope encryptor")
}
