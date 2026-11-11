package orchestration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/v5/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/dataencryption"
)

// ===== Fixtures and helpers (all prefixed with the OrcMeta token) =====

// OrcMetaAESKeyB64 is a base64-encoded 256-bit AES KEK used by the test configs.
const OrcMetaAESKeyB64 = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// OrcMetaAllowedSuffixes is the complete list of metadata suffixes the proxy is
// allowed to attach to a stored object. Anything else under the configured
// prefix is a leak of proxy internals into the object store.
var OrcMetaAllowedSuffixes = []string{
	"dek-algorithm",
	"encrypted-dek",
	"kek-algorithm",
	"kek-fingerprint",
}

// OrcMetaPrefixPtr returns a pointer to s, for config.EncryptionConfig.MetadataKeyPrefix.
func OrcMetaPrefixPtr(s string) *string {
	return &s
}

// OrcMetaSHA256 returns the hex-encoded SHA256 digest of data. Payloads are
// always compared by digest, never dumped.
func OrcMetaSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OrcMetaConfig builds a config with a single active AES provider and the given
// metadata prefix pointer (nil means "not configured").
func OrcMetaConfig(prefix *string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcmeta-aes",
			MetadataKeyPrefix:     prefix,
			Providers: []config.EncryptionProvider{
				{
					Alias: "orcmeta-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": OrcMetaAESKeyB64,
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			MultipartPartSize: 5 * 1024 * 1024,
		},
	}
}

// OrcMetaNewManager builds a Manager and registers its shutdown.
func OrcMetaNewManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, m.Shutdown(context.Background()))
	})
	return m
}

// OrcMetaPrefixedKeys returns the sorted keys of metadata that carry prefix.
func OrcMetaPrefixedKeys(metadata map[string]string, prefix string) []string {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// OrcMetaAssertOnlyAllowedKeys fails when metadata carries a prefixed key that
// is not one of the documented, allowed encryption metadata fields.
func OrcMetaAssertOnlyAllowedKeys(t *testing.T, metadata map[string]string, prefix string) {
	t.Helper()
	for _, key := range OrcMetaPrefixedKeys(metadata, prefix) {
		suffix := strings.TrimPrefix(key, prefix)
		assert.Contains(t, OrcMetaAllowedSuffixes, suffix,
			"metadata key %q is not an allowed encryption metadata field", key)
	}
}

// ===== Prefix configuration =====

// The metadata rules themselves live in pkg/encryption/storedobject and are
// tested there; what is left here is that the Manager hands them the configured
// prefix, and that an object whose format keys sit outside it is not one the
// Manager opens.

func TestOrcMetaPrefixComesFromTheConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"configured prefix", OrcMetaConfig(OrcMetaPrefixPtr("cfg-")), "cfg-"},
		{"default s3ep- when config prefix unset", OrcMetaConfig(nil), "s3ep-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := OrcMetaNewManager(t, tt.cfg)
			assert.Equal(t, tt.want, m.GetMetadataKeyPrefix())

			write, err := m.NewSegmentedWrite("objects/prefix", bytes.NewReader(nil), 0, nil)
			require.NoError(t, err)
			assert.Contains(t, write.Metadata, tt.want+"encrypted-dek")
			assert.True(t, m.IsSegmentedObject(write.Metadata))
		})
	}
}

// TestOrcMetaUnprefixedObjectIsRefused: a key outside the prefix is a client's,
// so an object that carries the format keys only there was not written by this
// proxy and is refused rather than half-read (ADR 0009 D1).
func TestOrcMetaUnprefixedObjectIsRefused(t *testing.T) {
	unprefixed := map[string]string{
		"encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("dek")),
		"dek-algorithm":   dataencryption.FormatID,
		"kek-fingerprint": "someone-elses-fp",
		"kek-algorithm":   "aes",
	}
	m := segManager(t)
	assert.False(t, m.ClaimsSegmentedFormat(unprefixed))
	assert.False(t, m.IsSegmentedObject(unprefixed))
}

// ===== End-to-end: what actually lands next to the ciphertext =====

// TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys drives a real Manager with
// a real AES provider and checks the client-visible contract: the object bytes
// handed to the backend are not the plaintext, the metadata stored alongside
// them carries only allowed keys under the configured prefix, and the round trip
// is byte-identical.
func TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys(t *testing.T) {
	const prefix = "orcmeta-"

	cfg := OrcMetaConfig(OrcMetaPrefixPtr(prefix))
	m := OrcMetaNewManager(t, cfg)
	require.Equal(t, prefix, m.GetMetadataKeyPrefix())

	sizes := []int{0, 1, 4096, 1024 * 1024}
	for _, size := range sizes {
		plaintext := bytes.Repeat([]byte("orcmeta-payload!"), 1+size/16)[:size]

		write, err := m.NewSegmentedWrite("objects/roundtrip", bytes.NewReader(plaintext), int64(size), nil)
		require.NoError(t, err)

		ciphertext, err := io.ReadAll(write.Body)
		require.NoError(t, err)
		assert.Equal(t, write.ContentLength, int64(len(ciphertext)))

		assert.NotEqual(t, OrcMetaSHA256(plaintext), OrcMetaSHA256(ciphertext),
			"plaintext must never be what the backend stores")

		OrcMetaAssertOnlyAllowedKeys(t, write.Metadata, prefix)
		for key := range write.Metadata {
			assert.True(t, strings.HasPrefix(key, prefix),
				"stored metadata key %q must carry the configured prefix", key)
		}
		assert.Contains(t, write.Metadata, prefix+"encrypted-dek")
		assert.Contains(t, write.Metadata, prefix+"kek-fingerprint")
		assert.Contains(t, write.Metadata, prefix+"dek-algorithm")
		assert.NotContains(t, write.Metadata, "s3ep-encrypted-dek",
			"the default prefix must not appear when another prefix is configured")

		decReader, err := m.OpenSegmented("objects/roundtrip", write.Metadata, bytes.NewReader(ciphertext))
		require.NoError(t, err)
		roundTrip, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMetaSHA256(plaintext), OrcMetaSHA256(roundTrip),
			"round trip must be byte-identical for size %d", size)
	}
}

// TestOrcMetaEndToEndDefaultPrefixIsS3EP verifies the documented default: with
// no metadata_key_prefix configured, stored keys start with "s3ep-".
func TestOrcMetaEndToEndDefaultPrefixIsS3EP(t *testing.T) {
	m := OrcMetaNewManager(t, OrcMetaConfig(nil))
	assert.Equal(t, "s3ep-", m.GetMetadataKeyPrefix())

	write, err := m.NewSegmentedWrite("objects/default-prefix", bytes.NewReader([]byte("hello")), 5, nil)
	require.NoError(t, err)

	require.NotEmpty(t, write.Metadata)
	OrcMetaAssertOnlyAllowedKeys(t, write.Metadata, "s3ep-")
	for key := range write.Metadata {
		assert.True(t, strings.HasPrefix(key, "s3ep-"), "unexpected metadata key %q", key)
	}
}
