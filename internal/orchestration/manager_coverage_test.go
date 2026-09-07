package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// ===== Fixtures and helpers (all prefixed with the OrcMgr token) =====

// OrcMgrAESKeyB64 is a base64-encoded 256-bit AES KEK used by the test configs.
const OrcMgrAESKeyB64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

// OrcMgrSegmentSize keeps the per-part read buffer small; MultipartOperations
// pre-sizes its part buffer to this value on every ProcessPart call.
const OrcMgrSegmentSize int64 = 5 * 1024 * 1024

// OrcMgrSHA256 returns the hex-encoded SHA256 digest of data. Large payloads are
// always compared by digest, never dumped.
func OrcMgrSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OrcMgrPrefixPtr returns a pointer to s, for config.EncryptionConfig.MetadataKeyPrefix.
func OrcMgrPrefixPtr(s string) *string {
	return &s
}

// OrcMgrAESConfig builds a config with a single active AES provider and the
// given integrity-verification mode.
func OrcMgrAESConfig(integrityMode string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcmgr-aes",
			MetadataKeyPrefix:     OrcMgrPrefixPtr("s3ep-"),
			IntegrityVerification: integrityMode,
			Providers: []config.EncryptionProvider{
				{
					Alias: "orcmgr-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": OrcMgrAESKeyB64,
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: OrcMgrSegmentSize,
		},
	}
}

// OrcMgrNoneConfig builds a config whose active provider is the pass-through
// "none" provider.
func OrcMgrNoneConfig() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcmgr-none",
			MetadataKeyPrefix:     OrcMgrPrefixPtr("s3ep-"),
			IntegrityVerification: config.HMACVerificationOff,
			Providers: []config.EncryptionProvider{
				{
					Alias:  "orcmgr-none",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: OrcMgrSegmentSize,
		},
	}
}

// OrcMgrNewManager builds a Manager and registers a shutdown so background
// goroutines never outlive the test.
func OrcMgrNewManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, m.Shutdown(shutdownCtx))
	})
	return m
}

// OrcMgrErrReader fails after handing out the wrapped payload once.
type OrcMgrErrReader struct {
	payload []byte
	off     int
	err     error
}

func (r *OrcMgrErrReader) Read(p []byte) (int, error) {
	if r.off < len(r.payload) {
		n := copy(p, r.payload[r.off:])
		r.off += n
		return n, nil
	}
	return 0, r.err
}

// OrcMgrEncryptWhole runs the whole-object encrypt path and drains the result.
func OrcMgrEncryptWhole(t *testing.T, m *Manager, plaintext []byte, key string) ([]byte, map[string]string) {
	t.Helper()
	res, err := m.EncryptDataWithContentType(context.Background(),
		bufio.NewReader(bytes.NewReader(plaintext)), key, factory.ContentTypeWhole)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	return ciphertext, res.Metadata
}

// ===== NewManager: construction and every invalid-config branch =====

func TestOrcMgrNewManagerInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		errorMsg string
	}{
		{
			name:     "nil configuration",
			cfg:      nil,
			errorMsg: "configuration cannot be nil",
		},
		{
			name:     "no providers and no alias",
			cfg:      &config.Config{},
			errorMsg: "no encryption providers configured",
		},
		{
			name: "providers configured but no active alias",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "none"},
					},
				},
			},
			errorMsg: "encryption_method_alias is required when providers are configured",
		},
		{
			name: "active alias does not match any provider",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "missing",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "none"},
					},
				},
			},
			errorMsg: "active encryption provider 'missing' not found",
		},
		{
			name: "active provider has empty type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: ""},
					},
				},
			},
			errorMsg: "provider 'a' has empty type",
		},
		{
			name: "active provider has unknown type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "rot13"},
					},
				},
			},
			errorMsg: "provider 'a' has invalid type 'rot13'",
		},
		{
			name: "aes provider with malformed key",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": "not-base64!!"}},
					},
				},
			},
			errorMsg: "failed to create key encryptor for provider 'a'",
		},
		{
			name: "aes provider without a key",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "aes", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "failed to create key encryptor for provider 'a'",
		},
		{
			name: "rsa provider missing public key",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "rsa", Config: map[string]interface{}{"private_key_pem": "x"}},
					},
				},
			},
			errorMsg: "failed to create key encryptor for provider 'a'",
		},
		{
			name: "tink provider is rejected as an invalid active type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "tink", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "provider 'a' has invalid type 'tink'",
		},
		{
			name: "secondary provider of unsupported type aborts construction",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "good",
					Providers: []config.EncryptionProvider{
						{Alias: "good", Type: "aes", Config: map[string]interface{}{"aes_key": OrcMgrAESKeyB64}},
						{Alias: "bad", Type: "rot13", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "unsupported provider type: rot13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewManager(tt.cfg)
			require.Error(t, err)
			assert.Nil(t, m)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

func TestOrcMgrNewManagerAppliesConfiguredSegmentSize(t *testing.T) {
	cfg := OrcMgrAESConfig(config.HMACVerificationOff)
	cfg.Optimizations.StreamingSegmentSize = 7 * 1024 * 1024
	m := OrcMgrNewManager(t, cfg)
	assert.Equal(t, int64(7*1024*1024), m.GetStreamingSegmentSize())

	defaultCfg := OrcMgrAESConfig(config.HMACVerificationOff)
	defaultCfg.Optimizations.StreamingSegmentSize = 0
	def := OrcMgrNewManager(t, defaultCfg)
	assert.Equal(t, int64(12*1024*1024), def.GetStreamingSegmentSize(), "falls back to the documented 12MB default")
}

// ===== Round-trip contract: what goes in comes back out, byte for byte =====

func TestOrcMgrRoundTripBoundarySizes(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, 4095, 4096, 4097, 65535, 65536, 65537, 1024*1024 + 7}

	for _, mode := range []string{config.HMACVerificationOff, config.HMACVerificationStrict} {
		for _, contentType := range []factory.ContentType{factory.ContentTypeWhole, factory.ContentTypeMultipart} {
			m := OrcMgrNewManager(t, OrcMgrAESConfig(mode))
			for _, size := range sizes {
				name := string(contentType) + "/" + mode + "/" + itoaOrcMgr(size)
				t.Run(name, func(t *testing.T) {
					plaintext := OrcMgrPayload(size)
					key := "objects/" + name

					res, err := m.EncryptDataWithContentType(context.Background(),
						bufio.NewReader(bytes.NewReader(plaintext)), key, contentType)
					require.NoError(t, err)
					require.NotNil(t, res)

					ciphertext, err := io.ReadAll(res.EncryptedDataReader)
					require.NoError(t, err)

					// The bytes handed to the backend must never be the plaintext.
					if size > 0 {
						assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(ciphertext),
							"ciphertext must differ from plaintext")
					}
					require.NotEmpty(t, res.Metadata, "an encrypting provider must emit metadata")

					dec, err := m.DecryptData(context.Background(),
						bufio.NewReader(bytes.NewReader(ciphertext)), res.Metadata, key)
					require.NoError(t, err)
					got, err := io.ReadAll(dec)
					require.NoError(t, err)
					assert.Equal(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))
				})
			}
		}
	}
}

// OrcMgrPayload builds a deterministic, non-repeating-ish payload of n bytes.
func OrcMgrPayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 7) % 251)
	}
	return b
}

func itoaOrcMgr(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestOrcMgrEncryptDataWithHTTPContentTypeRoundTrip(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	plaintext := OrcMgrPayload(9000)

	for _, isMultipart := range []bool{false, true} {
		key := "http-content-type"
		res, err := m.EncryptDataWithHTTPContentType(context.Background(),
			bufio.NewReader(bytes.NewReader(plaintext)), key, "application/octet-stream", isMultipart)
		require.NoError(t, err)

		ciphertext, err := io.ReadAll(res.EncryptedDataReader)
		require.NoError(t, err)
		assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(ciphertext))

		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(ciphertext)), res.Metadata, key)
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))
	}
}

// TestOrcMgrEncryptDataWithContentTypeUnknownFallsBackToSizeSelection covers the
// default arm of the content-type switch: an unrecognised ContentType must still
// produce a decryptable object rather than an error or plaintext.
func TestOrcMgrEncryptDataWithContentTypeUnknownFallsBack(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	plaintext := []byte("unknown content type must still be encrypted")
	key := "fallback-object"

	res, err := m.EncryptDataWithContentType(context.Background(),
		bufio.NewReader(bytes.NewReader(plaintext)), key, factory.ContentType("something-else"))
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(ciphertext))
	require.NotEmpty(t, res.Metadata)

	dec, err := m.DecryptData(context.Background(),
		bufio.NewReader(bytes.NewReader(ciphertext)), res.Metadata, key)
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	assert.Equal(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))
}

// ===== DecryptData routing =====

func TestOrcMgrDecryptDataRoutingErrors(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	body := []byte("some stored bytes")

	t.Run("metadata carries proxy keys but no algorithm", func(t *testing.T) {
		md := map[string]string{"s3ep-kek-fingerprint": "whatever"}
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(body)), md, "k")
		require.Error(t, err)
		assert.Nil(t, dec)
		assert.Contains(t, err.Error(), "failed to get algorithm from metadata")
	})

	t.Run("unknown algorithm is refused", func(t *testing.T) {
		md := map[string]string{"s3ep-dek-algorithm": "chacha20-poly1305"}
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(body)), md, "k")
		require.Error(t, err)
		assert.Nil(t, dec)
		assert.Equal(t, "unknown algorithm: chacha20-poly1305", err.Error())
	})

	t.Run("algorithm none passes the body through", func(t *testing.T) {
		md := map[string]string{"s3ep-dek-algorithm": "none"}
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(body)), md, "k")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(body), OrcMgrSHA256(got))
	})

	t.Run("gcm object with an unknown fingerprint is refused", func(t *testing.T) {
		md := map[string]string{
			"s3ep-dek-algorithm":   "aes-gcm",
			"s3ep-kek-fingerprint": "fingerprint-of-a-key-we-do-not-have",
			"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("junk")),
		}
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(body)), md, "k")
		require.Error(t, err)
		assert.Nil(t, dec)
	})

	t.Run("ctr object without an IV is refused", func(t *testing.T) {
		_, md := OrcMgrEncryptWhole(t, m, []byte("x"), "k")
		md["s3ep-dek-algorithm"] = "aes-ctr"
		delete(md, "s3ep-aes-iv")
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(body)), md, "k")
		require.Error(t, err)
		assert.Nil(t, dec)
		assert.Contains(t, err.Error(), "IV not found in metadata")
	})
}

// TestOrcMgrDecryptDataWithoutMetadataServesBackendBytesVerbatim pins the
// behaviour ADR 0003 calls out at manager.go:186. Under an *encrypting*
// provider, an object that arrives with no proxy metadata is handed to the
// client unchanged and with no error. A backend that can strip user metadata can
// therefore substitute an arbitrary body and the proxy will serve it as
// plaintext.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcMgrDecryptDataWithoutMetadataServesBackendBytesVerbatim(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationStrict))
	require.False(t, m.IsNoneProvider(), "the active provider encrypts")

	attackerBody := []byte("ATTACKER CONTROLLED BODY - never encrypted by this proxy")

	t.Run("nil metadata", func(t *testing.T) {
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(attackerBody)), nil, "victim/object")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(attackerBody), OrcMgrSHA256(got))
	})

	t.Run("empty metadata", func(t *testing.T) {
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(attackerBody)), map[string]string{}, "victim/object")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(attackerBody), OrcMgrSHA256(got))
	})

	t.Run("only foreign metadata keys", func(t *testing.T) {
		md := map[string]string{"content-type": "text/plain", "x-amz-meta-owner": "someone"}
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(attackerBody)), md, "victim/object")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(attackerBody), OrcMgrSHA256(got))
	})

	t.Run("stripping the metadata of a real encrypted object yields ciphertext", func(t *testing.T) {
		plaintext := []byte("real secret payload")
		ciphertext, _ := OrcMgrEncryptWhole(t, m, plaintext, "victim/object")

		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(ciphertext)), map[string]string{}, "victim/object")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(ciphertext), OrcMgrSHA256(got),
			"raw ciphertext is served to the client as if it were plaintext")
		assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))
	})
}

// TestOrcMgrDecryptDataSkipsHMACForCTRObjects records that Manager.DecryptData
// never verifies the object HMAC on the AES-CTR path: it calls the streaming
// reader with expectedSize = -1, and the HMAC-validating wrapper is only
// installed when a positive size is known. A single flipped ciphertext bit is
// therefore delivered to the client without error even in "strict" mode.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcMgrDecryptDataSkipsHMACForCTRObjects(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationStrict))
	plaintext := OrcMgrPayload(4096)
	key := "ctr/tampered"

	res, err := m.EncryptDataWithContentType(context.Background(),
		bufio.NewReader(bytes.NewReader(plaintext)), key, factory.ContentTypeMultipart)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	require.Contains(t, res.Metadata, "s3ep-hmac", "an HMAC was written at upload time")

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xFF

	dec, err := m.DecryptData(context.Background(),
		bufio.NewReader(bytes.NewReader(tampered)), res.Metadata, key)
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err, "no integrity error is raised on this path")
	assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got),
		"the client receives corrupted plaintext, undetected")
}

// TestOrcMgrDecryptDataDetectsTamperingForGCMObjects is the counterpart: the GCM
// auth tag does catch the same tampering.
func TestOrcMgrDecryptDataDetectsTamperingForGCMObjects(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationStrict))
	plaintext := OrcMgrPayload(4096)
	key := "gcm/tampered"

	ciphertext, md := OrcMgrEncryptWhole(t, m, plaintext, key)
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)-1] ^= 0xFF

	dec, err := m.DecryptData(context.Background(),
		bufio.NewReader(bytes.NewReader(tampered)), md, key)
	if err == nil {
		_, readErr := io.ReadAll(dec)
		require.Error(t, readErr, "tampered GCM ciphertext must not be delivered")
		return
	}
	require.Error(t, err)
}

// TestOrcMgrDecryptDataWrongObjectKeyFailsForGCM shows the object key is bound
// into the GCM associated data.
func TestOrcMgrDecryptDataWrongObjectKeyFailsForGCM(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	plaintext := []byte("bound to its key")
	ciphertext, md := OrcMgrEncryptWhole(t, m, plaintext, "bucket/right-key")

	dec, err := m.DecryptData(context.Background(),
		bufio.NewReader(bytes.NewReader(ciphertext)), md, "bucket/WRONG-key")
	if err == nil {
		_, readErr := io.ReadAll(dec)
		require.Error(t, readErr)
		return
	}
	require.Error(t, err)
}

// ===== none provider: pure pass-through across the whole facade =====

func TestOrcMgrNoneProviderPassThroughAcrossFacade(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrNoneConfig())
	ctx := context.Background()
	payload := OrcMgrPayload(3000)

	assert.True(t, m.IsNoneProvider())

	t.Run("EncryptData", func(t *testing.T) {
		res, err := m.EncryptData(ctx, bufio.NewReader(bytes.NewReader(payload)), "k")
		require.NoError(t, err)
		assert.Empty(t, res.Metadata)
		got, err := io.ReadAll(res.EncryptedDataReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))
	})

	t.Run("EncryptDataWithContentType", func(t *testing.T) {
		for _, ct := range []factory.ContentType{factory.ContentTypeWhole, factory.ContentTypeMultipart} {
			res, err := m.EncryptDataWithContentType(ctx, bufio.NewReader(bytes.NewReader(payload)), "k", ct)
			require.NoError(t, err)
			assert.Empty(t, res.Metadata)
			got, err := io.ReadAll(res.EncryptedDataReader)
			require.NoError(t, err)
			assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))
		}
	})

	t.Run("CreateEncryptionReader", func(t *testing.T) {
		r, md, err := m.CreateEncryptionReader(ctx, bytes.NewReader(payload), "k")
		require.NoError(t, err)
		assert.Empty(t, md)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))

		br, md2, err := m.CreateEncryptionReaderBuffered(ctx, bytes.NewReader(payload), "k")
		require.NoError(t, err)
		assert.Empty(t, md2)
		got2, err := io.ReadAll(br)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got2))
	})

	t.Run("multipart lifecycle needs no session", func(t *testing.T) {
		require.NoError(t, m.InitiateMultipartUpload(ctx, "up-none", "obj", "bucket"))
		assert.Equal(t, 0, m.GetSessionCount(), "none provider allocates no session state")

		res, err := m.UploadPart(ctx, "up-none", 1, bufio.NewReader(bytes.NewReader(payload)))
		require.NoError(t, err)
		assert.Empty(t, res.Metadata)
		got, err := io.ReadAll(res.EncryptedDataReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))

		md, err := m.CompleteMultipartUpload(ctx, "up-none", map[int]string{1: "etag-1"})
		require.NoError(t, err)
		assert.Empty(t, md)
	})

	t.Run("UploadPartStreamingBuffer passes segments through", func(t *testing.T) {
		var collected bytes.Buffer
		err := m.UploadPartStreamingBuffer(ctx, "up-none", 1, bytes.NewReader(payload), 512,
			func(seg []byte) error {
				_, writeErr := collected.Write(seg)
				return writeErr
			})
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(collected.Bytes()))
	})

	t.Run("UploadPartStreaming passes data through", func(t *testing.T) {
		res, err := m.UploadPartStreaming(ctx, "up-none", 2, bytes.NewReader(payload))
		require.NoError(t, err)
		got, err := io.ReadAll(res.EncryptedData)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))
	})
}

// ===== Multipart session map through the manager facade =====

func TestOrcMgrMultipartSessionLifecycle(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationStrict))
	ctx := context.Background()
	uploadID := "orcmgr-upload-1"
	objectKey := "bucket/multipart-object"

	require.Equal(t, 0, m.GetSessionCount())
	require.NoError(t, m.InitiateMultipartUpload(ctx, uploadID, objectKey, "bucket"))
	assert.Equal(t, 1, m.GetSessionCount())

	session, err := m.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.Equal(t, objectKey, session.ObjectKey)
	assert.Equal(t, "bucket", session.BucketName)

	part1 := OrcMgrPayload(2000)
	part2 := OrcMgrPayload(1500)

	var ciphertext bytes.Buffer
	for i, part := range [][]byte{part1, part2} {
		res, err := m.UploadPart(ctx, uploadID, i+1, bufio.NewReader(bytes.NewReader(part)))
		require.NoError(t, err)
		n, err := ciphertext.ReadFrom(res.EncryptedDataReader)
		require.NoError(t, err)
		require.Equal(t, int64(len(part)), n, "CTR keeps ciphertext the same length as plaintext")
		require.NoError(t, m.StorePartETag(uploadID, i+1, "etag-"+itoaOrcMgr(i+1)))
	}

	plaintext := append(append([]byte{}, part1...), part2...)
	assert.NotEqual(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(ciphertext.Bytes()),
		"the bytes going to the backend must not be the plaintext")

	metadata, err := m.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag-1", 2: "etag-2"})
	require.NoError(t, err)
	require.NotEmpty(t, metadata)

	// The whole object decrypts back to exactly what was uploaded.
	dec, err := m.DecryptData(ctx, bufio.NewReader(bytes.NewReader(ciphertext.Bytes())), metadata, objectKey)
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	assert.Equal(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))

	require.NoError(t, m.CleanupMultipartUpload(uploadID))
	assert.Equal(t, 0, m.GetSessionCount())

	_, err = m.GetMultipartUploadState(uploadID)
	require.Error(t, err)
}

func TestOrcMgrMultipartUploadPartStreamingRoundTrip(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	uploadID := "orcmgr-upload-streaming"
	objectKey := "bucket/streamed"

	require.NoError(t, m.InitiateMultipartUpload(ctx, uploadID, objectKey, "bucket"))

	part := OrcMgrPayload(8192)
	// Deliberately a plain io.Reader so the bufio wrapping branch is exercised.
	res, err := m.UploadPartStreaming(ctx, uploadID, 1, bytes.NewReader(part))
	require.NoError(t, err)
	ct1, err := io.ReadAll(res.EncryptedData)
	require.NoError(t, err)
	assert.NotEqual(t, OrcMgrSHA256(part), OrcMgrSHA256(ct1))

	// And once with an already-buffered reader.
	res2, err := m.UploadPartStreaming(ctx, uploadID, 2, bufio.NewReader(bytes.NewReader(part)))
	require.NoError(t, err)
	ct2, err := io.ReadAll(res2.EncryptedData)
	require.NoError(t, err)

	metadata, err := m.CompleteMultipartUpload(ctx, uploadID, map[int]string{})
	require.NoError(t, err)

	full := append(append([]byte{}, ct1...), ct2...)
	dec, err := m.DecryptData(ctx, bufio.NewReader(bytes.NewReader(full)), metadata, objectKey)
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	assert.Equal(t, OrcMgrSHA256(append(append([]byte{}, part...), part...)), OrcMgrSHA256(got))

	require.NoError(t, m.CleanupMultipartUpload(uploadID))
}

func TestOrcMgrMultipartErrorsOnUnknownSession(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	const missing = "no-such-upload"

	t.Run("UploadPart", func(t *testing.T) {
		res, err := m.UploadPart(ctx, missing, 1, bufio.NewReader(bytes.NewReader([]byte("x"))))
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "multipart upload no-such-upload not found")
	})

	t.Run("UploadPartStreaming", func(t *testing.T) {
		res, err := m.UploadPartStreaming(ctx, missing, 1, bytes.NewReader([]byte("x")))
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("StorePartETag", func(t *testing.T) {
		require.Error(t, m.StorePartETag(missing, 1, "etag"))
	})

	t.Run("CompleteMultipartUpload with parts", func(t *testing.T) {
		md, err := m.CompleteMultipartUpload(ctx, missing, map[int]string{1: "etag"})
		require.Error(t, err)
		assert.Nil(t, md)
		assert.Contains(t, err.Error(), "failed to store part ETag")
	})

	t.Run("CompleteMultipartUpload without parts", func(t *testing.T) {
		md, err := m.CompleteMultipartUpload(ctx, missing, map[int]string{})
		require.Error(t, err)
		assert.Nil(t, md)
	})

	t.Run("AbortMultipartUpload", func(t *testing.T) {
		require.Error(t, m.AbortMultipartUpload(ctx, missing))
	})

	t.Run("CleanupMultipartUpload", func(t *testing.T) {
		require.Error(t, m.CleanupMultipartUpload(missing))
	})

	t.Run("GetMultipartUploadState", func(t *testing.T) {
		s, err := m.GetMultipartUploadState(missing)
		require.Error(t, err)
		assert.Nil(t, s)
	})
}

func TestOrcMgrMultipartAbortReleasesSession(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationStrict))
	ctx := context.Background()

	require.NoError(t, m.InitiateMultipartUpload(ctx, "abort-me", "obj", "bucket"))
	assert.Equal(t, 1, m.GetSessionCount())

	// A second initiate for the same upload ID must be refused.
	err := m.InitiateMultipartUpload(ctx, "abort-me", "obj", "bucket")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	require.NoError(t, m.AbortMultipartUpload(ctx, "abort-me"))
	assert.Equal(t, 0, m.GetSessionCount())
	require.Error(t, m.AbortMultipartUpload(ctx, "abort-me"), "aborting twice must fail")
}

// TestOrcMgrUploadPartRejectsInvalidPartNumbers checks the S3 part-number range
// (1..10000) is enforced by the facade.
func TestOrcMgrUploadPartRejectsInvalidPartNumbers(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	require.NoError(t, m.InitiateMultipartUpload(ctx, "range-check", "obj", "bucket"))
	t.Cleanup(func() { _ = m.CleanupMultipartUpload("range-check") })

	for _, partNumber := range []int{0, -1, 10001} {
		res, err := m.UploadPart(ctx, "range-check", partNumber,
			bufio.NewReader(bytes.NewReader([]byte("x"))))
		require.Error(t, err, "part number %d", partNumber)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "must be between 1 and 10000")
	}
}

// ===== UploadPartStreamingBuffer =====

func TestOrcMgrUploadPartStreamingBufferEncrypted(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	uploadID := "buffered-upload"
	objectKey := "bucket/buffered"

	require.NoError(t, m.InitiateMultipartUpload(ctx, uploadID, objectKey, "bucket"))

	payload := OrcMgrPayload(20000)
	var collected bytes.Buffer
	segments := 0
	// Already buffered on the way in, which is how the proxy handler calls this.
	err := m.UploadPartStreamingBuffer(ctx, uploadID, 1, bufio.NewReader(bytes.NewReader(payload)), 4096,
		func(seg []byte) error {
			segments++
			_, writeErr := collected.Write(seg)
			return writeErr
		})
	require.NoError(t, err)
	assert.Greater(t, segments, 1, "a 20000-byte part must arrive in several 4096-byte segments")
	assert.Equal(t, len(payload), collected.Len())
	assert.NotEqual(t, OrcMgrSHA256(payload), OrcMgrSHA256(collected.Bytes()))

	metadata, err := m.CompleteMultipartUpload(ctx, uploadID, map[int]string{1: "etag-1"})
	require.NoError(t, err)

	dec, err := m.DecryptData(ctx, bufio.NewReader(bytes.NewReader(collected.Bytes())), metadata, objectKey)
	require.NoError(t, err)
	got, err := io.ReadAll(dec)
	require.NoError(t, err)
	assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))

	require.NoError(t, m.CleanupMultipartUpload(uploadID))
}

func TestOrcMgrUploadPartStreamingBufferErrors(t *testing.T) {
	ctx := context.Background()
	callbackErr := errors.New("segment sink is full")
	readErr := errors.New("network reset")

	t.Run("encrypted path without a session", func(t *testing.T) {
		m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
		err := m.UploadPartStreamingBuffer(ctx, "nope", 1, bytes.NewReader([]byte("data")), 16,
			func([]byte) error { return nil })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt part stream")
	})

	t.Run("encrypted path propagates a callback error", func(t *testing.T) {
		m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
		require.NoError(t, m.InitiateMultipartUpload(ctx, "cb-fail", "obj", "bucket"))
		t.Cleanup(func() { _ = m.CleanupMultipartUpload("cb-fail") })

		err := m.UploadPartStreamingBuffer(ctx, "cb-fail", 1, bytes.NewReader(OrcMgrPayload(1024)), 128,
			func([]byte) error { return callbackErr })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "segment callback failed")
		assert.ErrorIs(t, err, callbackErr)
	})

	t.Run("none provider propagates a callback error", func(t *testing.T) {
		m := OrcMgrNewManager(t, OrcMgrNoneConfig())
		err := m.UploadPartStreamingBuffer(ctx, "any", 1, bytes.NewReader(OrcMgrPayload(1024)), 128,
			func([]byte) error { return callbackErr })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "segment callback failed")
		assert.ErrorIs(t, err, callbackErr)
	})

	t.Run("none provider propagates a source read error", func(t *testing.T) {
		m := OrcMgrNewManager(t, OrcMgrNoneConfig())
		src := &OrcMgrErrReader{payload: OrcMgrPayload(64), err: readErr}
		err := m.UploadPartStreamingBuffer(ctx, "any", 1, src, 32,
			func([]byte) error { return nil })
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read segment")
		assert.ErrorIs(t, err, readErr)
	})

	t.Run("encrypted path propagates a source read error", func(t *testing.T) {
		m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
		require.NoError(t, m.InitiateMultipartUpload(ctx, "read-fail", "obj", "bucket"))
		t.Cleanup(func() { _ = m.CleanupMultipartUpload("read-fail") })

		src := &OrcMgrErrReader{payload: OrcMgrPayload(64), err: readErr}
		err := m.UploadPartStreamingBuffer(ctx, "read-fail", 1, src, 32,
			func([]byte) error { return nil })
		require.Error(t, err)
		assert.ErrorIs(t, err, readErr)
	})
}

// ===== Streaming reader factories =====

func TestOrcMgrCreateEncryptionAndDecryptionReaders(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	payload := OrcMgrPayload(30000)

	t.Run("plain reader in, encrypted reader out", func(t *testing.T) {
		encReader, metadata, err := m.CreateEncryptionReader(ctx, bytes.NewReader(payload), "obj")
		require.NoError(t, err)
		require.NotEmpty(t, metadata)

		ciphertext, err := io.ReadAll(encReader)
		require.NoError(t, err)
		assert.Equal(t, len(payload), len(ciphertext))
		assert.NotEqual(t, OrcMgrSHA256(payload), OrcMgrSHA256(ciphertext))

		decReader, err := m.CreateDecryptionReader(ctx, bytes.NewReader(ciphertext), metadata)
		require.NoError(t, err)
		got, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))
	})

	t.Run("buffered variants round-trip too", func(t *testing.T) {
		encReader, metadata, err := m.CreateEncryptionReaderBuffered(ctx,
			bufio.NewReader(bytes.NewReader(payload)), "obj")
		require.NoError(t, err)
		require.NotEmpty(t, metadata)

		ciphertext, err := io.ReadAll(encReader)
		require.NoError(t, err)

		decReader, err := m.CreateDecryptionReaderBuffered(ctx,
			bufio.NewReader(bytes.NewReader(ciphertext)), metadata)
		require.NoError(t, err)
		got, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))
	})

	t.Run("decryption readers refuse metadata without a fingerprint", func(t *testing.T) {
		r, err := m.CreateDecryptionReader(ctx, bytes.NewReader(payload), map[string]string{})
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to get fingerprint from metadata")

		br, err := m.CreateDecryptionReaderBuffered(ctx, bytes.NewReader(payload), map[string]string{})
		require.Error(t, err)
		assert.Nil(t, br)
	})

	t.Run("decryption readers refuse metadata without an encrypted DEK", func(t *testing.T) {
		md := map[string]string{"s3ep-kek-fingerprint": m.providerManager.GetActiveFingerprint()}
		r, err := m.CreateDecryptionReader(ctx, bytes.NewReader(payload), md)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to get encrypted DEK from metadata")
	})

	t.Run("none-provider fingerprint short-circuits decryption", func(t *testing.T) {
		md := map[string]string{"s3ep-kek-fingerprint": "none-provider-fingerprint"}
		r, err := m.CreateDecryptionReader(ctx, bytes.NewReader(payload), md)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(got))

		// The buffered variant must hand back the same bytes without
		// re-wrapping an already-buffered reader.
		br, err := m.CreateDecryptionReaderBuffered(ctx, bytes.NewReader(payload), md)
		require.NoError(t, err)
		gotBuffered, err := io.ReadAll(br)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(payload), OrcMgrSHA256(gotBuffered))
	})
}

// TestOrcMgrEncryptionFailsWhenActiveKeyIsUnavailable drives the KEK error path
// of the encryption facade by pointing the manager at a fingerprint no
// registered provider owns.
func TestOrcMgrEncryptionFailsWhenActiveKeyIsUnavailable(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	m.providerManager.activeFingerprint = "fingerprint-that-does-not-exist"
	ctx := context.Background()

	res, err := m.EncryptData(ctx, bufio.NewReader(bytes.NewReader([]byte("secret"))), "obj")
	require.Error(t, err)
	assert.Nil(t, res, "no reader may be handed back when the KEK is unavailable")
	assert.Contains(t, err.Error(), "failed to create encryption reader")

	r, md, err := m.CreateEncryptionReader(ctx, bytes.NewReader([]byte("secret")), "obj")
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Nil(t, md)

	br, md2, err := m.CreateEncryptionReaderBuffered(ctx, bytes.NewReader([]byte("secret")), "obj")
	require.Error(t, err)
	assert.Nil(t, br)
	assert.Nil(t, md2)
}

// ===== Accessors, metadata filtering and statistics =====

func TestOrcMgrAccessorsAndMetadataFiltering(t *testing.T) {
	cfg := OrcMgrAESConfig(config.HMACVerificationStrict)
	cfg.Encryption.MetadataKeyPrefix = OrcMgrPrefixPtr("orcmgr-")
	cfg.Optimizations.StreamingThreshold = 3 * 1024 * 1024
	m := OrcMgrNewManager(t, cfg)

	assert.Equal(t, "orcmgr-", m.GetMetadataKeyPrefix())
	assert.Equal(t, []string{"orcmgr-aes"}, m.GetProviderAliases())
	assert.Equal(t, "orcmgr-aes", m.GetActiveProviderAlias())
	assert.False(t, m.IsNoneProvider())

	provider, ok := m.GetProvider("orcmgr-aes")
	assert.Nil(t, provider, "individual providers are deliberately not exposed")
	assert.False(t, ok)

	loaded := m.GetLoadedProviders()
	require.Len(t, loaded, 1)
	assert.Equal(t, "aes", loaded[0].Type)

	t.Run("client metadata never carries proxy keys", func(t *testing.T) {
		_, metadata := OrcMgrEncryptWhole(t, m, []byte("payload"), "obj")
		metadata["content-type"] = "application/json"
		metadata["x-amz-meta-user"] = "hans"

		filtered := m.FilterMetadataForClient(metadata)
		assert.Equal(t, map[string]string{
			"content-type":    "application/json",
			"x-amz-meta-user": "hans",
		}, filtered)
		for key := range filtered {
			assert.NotContains(t, key, "orcmgr-")
		}
	})

	t.Run("GetStats reports the live facade state", func(t *testing.T) {
		require.NoError(t, m.InitiateMultipartUpload(context.Background(), "stats-session", "obj", "bucket"))
		t.Cleanup(func() { _ = m.CleanupMultipartUpload("stats-session") })

		stats := m.GetStats()
		assert.Equal(t, 1, stats["active_sessions"])
		assert.Equal(t, 1, stats["provider_count"])
		assert.Equal(t, "orcmgr-aes", stats["active_provider"])
		assert.Equal(t, true, stats["hmac_enabled"])
		assert.Equal(t, "orcmgr-", stats["metadata_prefix"])
		assert.Equal(t, int64(3*1024*1024), stats["streaming_threshold"])
		assert.Equal(t, OrcMgrSegmentSize, stats["streaming_segment_size"])
	})

	t.Run("RotateKEK is not implemented", func(t *testing.T) {
		err := m.RotateKEK(context.Background())
		require.Error(t, err)
		assert.Equal(t, "KEK rotation not implemented in Manager", err.Error())
	})
}

// TestOrcMgrClearCachesKeepsDecryptionWorking guards against a cache flush
// breaking subsequent reads.
func TestOrcMgrClearCachesKeepsDecryptionWorking(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	plaintext := OrcMgrPayload(2048)
	ciphertext, metadata := OrcMgrEncryptWhole(t, m, plaintext, "cached/object")

	for i := 0; i < 3; i++ {
		dec, err := m.DecryptData(context.Background(),
			bufio.NewReader(bytes.NewReader(ciphertext)), metadata, "cached/object")
		require.NoError(t, err)
		got, err := io.ReadAll(dec)
		require.NoError(t, err)
		assert.Equal(t, OrcMgrSHA256(plaintext), OrcMgrSHA256(got))
		m.ClearCaches()
	}
}

func TestOrcMgrCleanupExpiredSessions(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()

	require.NoError(t, m.InitiateMultipartUpload(ctx, "old-1", "obj1", "bucket"))
	require.NoError(t, m.InitiateMultipartUpload(ctx, "old-2", "obj2", "bucket"))
	assert.Equal(t, 2, m.GetSessionCount())

	assert.Equal(t, 0, m.CleanupExpiredSessions(time.Hour), "young sessions survive")
	assert.Equal(t, 2, m.GetSessionCount())

	assert.Equal(t, 2, m.CleanupExpiredSessions(0), "a zero max age expires everything")
	assert.Equal(t, 0, m.GetSessionCount())
}

// ===== GetMetadataAlgorithm =====

func TestOrcMgrGetMetadataAlgorithm(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))

	tests := []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{"nil metadata", nil, ""},
		{"empty metadata", map[string]string{}, ""},
		{"no algorithm key", map[string]string{"content-type": "text/plain"}, ""},
		{"empty algorithm value", map[string]string{"s3ep-dek-algorithm": ""}, ""},
		{"prefixed dek-algorithm", map[string]string{"s3ep-dek-algorithm": "aes-ctr"}, "aes-ctr"},
		{"prefixed algorithm", map[string]string{"s3ep-algorithm": "aes-gcm"}, "aes-gcm"},
		{"unprefixed fallback", map[string]string{"dek-algorithm": "aes-gcm"}, "aes-gcm"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, m.GetMetadataAlgorithm(tt.metadata))
		})
	}

	t.Run("agrees with what encryption actually recorded", func(t *testing.T) {
		// Pins the current storage-format behaviour. The segmented-GCM format
		// (ADR 0003) replaces this; update together.
		_, wholeMD := OrcMgrEncryptWhole(t, m, []byte("x"), "obj")
		assert.Equal(t, "aes-gcm", m.GetMetadataAlgorithm(wholeMD))

		res, err := m.EncryptDataWithContentType(context.Background(),
			bufio.NewReader(bytes.NewReader([]byte("x"))), "obj", factory.ContentTypeMultipart)
		require.NoError(t, err)
		assert.Equal(t, "aes-ctr", m.GetMetadataAlgorithm(res.Metadata))
	})
}

// ===== Background cleanup and shutdown =====

func TestOrcMgrBackgroundCleanupRemovesExpiredSessions(t *testing.T) {
	cfg := OrcMgrAESConfig(config.HMACVerificationOff)
	cfg.Optimizations.MultipartSessionCleanupInterval = 1
	cfg.Optimizations.MultipartSessionMaxAge = 0

	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NoError(t, m.InitiateMultipartUpload(context.Background(), "expiring", "obj", "bucket"))
	require.Equal(t, 1, m.GetSessionCount())

	deadline := time.Now().Add(5 * time.Second)
	for m.GetSessionCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, 0, m.GetSessionCount(), "the background sweeper must drop the expired session")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, m.Shutdown(shutdownCtx))

	// Shutting down twice must stay safe.
	require.NoError(t, m.Shutdown(shutdownCtx))
}

func TestOrcMgrShutdownWithoutBackgroundCleanup(t *testing.T) {
	m, err := NewManager(OrcMgrAESConfig(config.HMACVerificationOff))
	require.NoError(t, err)
	require.NoError(t, m.Shutdown(context.Background()))
}

// TestOrcMgrShutdownReturnsWhenContextExpires proves Shutdown does not block
// forever if the cleanup goroutine refuses to stop.
func TestOrcMgrShutdownReturnsWhenContextExpires(t *testing.T) {
	m, err := NewManager(OrcMgrAESConfig(config.HMACVerificationOff))
	require.NoError(t, err)

	// Stand in for a cleanup worker that never finishes.
	var release sync.WaitGroup
	release.Add(1)
	m.cleanupWg.Add(1)
	go func() {
		release.Wait()
		m.cleanupWg.Done()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- m.Shutdown(ctx) }()

	select {
	case shutdownErr := <-done:
		require.NoError(t, shutdownErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on a stuck cleanup goroutine")
	}
	release.Done()
}

// TestOrcMgrMultipartResultDropsAlgorithmAndFingerprint records that the
// multipart path loses the algorithm and key fingerprint that ProcessPart
// produced: Manager.UploadPart builds its StreamingEncryptionResult without
// copying result.Algorithm / result.KeyFingerprint (it only logs them), so
// UploadPartStreaming always reports empty values. Nothing in the proxy reads
// these fields today, which is why it goes unnoticed.
//
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcMgrMultipartResultDropsAlgorithmAndFingerprint(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig(config.HMACVerificationOff))
	ctx := context.Background()
	require.NoError(t, m.InitiateMultipartUpload(ctx, "fields", "obj", "bucket"))
	t.Cleanup(func() { _ = m.CleanupMultipartUpload("fields") })

	part, err := m.UploadPart(ctx, "fields", 1, bufio.NewReader(bytes.NewReader(OrcMgrPayload(64))))
	require.NoError(t, err)
	assert.Empty(t, part.Algorithm, "dropped on the way out of UploadPart")
	assert.Empty(t, part.KeyFingerprint, "dropped on the way out of UploadPart")

	streamed, err := m.UploadPartStreaming(ctx, "fields", 2, bytes.NewReader(OrcMgrPayload(64)))
	require.NoError(t, err)
	assert.Empty(t, streamed.Algorithm)
	assert.Empty(t, streamed.KeyFingerprint)

	// The single-part paths do report an algorithm, so the field is meaningful
	// elsewhere and the multipart path is the outlier.
	whole, err := m.EncryptDataWithContentType(ctx,
		bufio.NewReader(bytes.NewReader([]byte("x"))), "obj", factory.ContentTypeWhole)
	require.NoError(t, err)
	assert.NotEmpty(t, whole.Algorithm)
	assert.Empty(t, whole.KeyFingerprint, "KeyFingerprint is never populated on any path")
}
