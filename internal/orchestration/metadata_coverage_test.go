package orchestration

import (
	"bufio"
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

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// ===== Fixtures and helpers (all prefixed with the OrcMeta token) =====

// OrcMetaAESKeyB64 is a base64-encoded 256-bit AES KEK used by the test configs.
const OrcMetaAESKeyB64 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="

// OrcMetaAllowedSuffixes is the complete list of metadata suffixes the proxy is
// allowed to attach to a stored object (see CLAUDE.md). Anything else under the
// configured prefix is a leak of proxy internals into the object store.
var OrcMetaAllowedSuffixes = []string{
	"dek-algorithm",
	"encrypted-dek",
	"aes-iv",
	"kek-algorithm",
	"kek-fingerprint",
	"hmac",
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
			IntegrityVerification: config.HMACVerificationStrict,
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
			StreamingSegmentSize: 5 * 1024 * 1024,
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

// ===== BuildMetadataForEncryption: exact key set =====

func TestOrcMetaBuildMetadataWritesExactlyTheAllowedKeys(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	metadata := mm.BuildMetadataForEncryption(
		[]byte("plaintext-dek-32-bytes-aaaaaaaaa"),
		[]byte("encrypted-dek-blob"),
		[]byte("0123456789abcdef"),
		"aes-ctr",
		"fingerprint-abc",
		"aes",
		nil,
	)

	assert.Equal(t, []string{
		"s3ep-aes-iv",
		"s3ep-dek-algorithm",
		"s3ep-encrypted-dek",
		"s3ep-kek-algorithm",
		"s3ep-kek-fingerprint",
	}, OrcMetaPrefixedKeys(metadata, "s3ep-"))
	assert.Len(t, metadata, 5, "no non-encryption key may appear when none was supplied")
	OrcMetaAssertOnlyAllowedKeys(t, metadata, "s3ep-")

	// Values must be base64 for the binary fields and verbatim for the rest.
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("encrypted-dek-blob")), metadata["s3ep-encrypted-dek"])
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), metadata["s3ep-aes-iv"])
	assert.Equal(t, "aes-ctr", metadata["s3ep-dek-algorithm"])
	assert.Equal(t, "fingerprint-abc", metadata["s3ep-kek-fingerprint"])
	assert.Equal(t, "aes", metadata["s3ep-kek-algorithm"])

	// The plaintext DEK is the first parameter and must never be stored.
	for key, value := range metadata {
		assert.NotContains(t, value, "plaintext-dek", "plaintext DEK leaked into %q", key)
	}
	assert.Equal(t, 5, mm.countEncryptionKeys(metadata))
}

func TestOrcMetaBuildMetadataOmitsIVWhenEmptyAndKeepsUserMetadata(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	for _, iv := range [][]byte{nil, {}} {
		metadata := mm.BuildMetadataForEncryption(
			nil,
			[]byte("dek"),
			iv,
			"aes-gcm",
			"fp",
			"aes",
			map[string]string{"user-key": "user-value", "content-type": "text/plain"},
		)

		assert.NotContains(t, metadata, "s3ep-aes-iv", "GCM stores its IV inside the payload, not in metadata")
		assert.Equal(t, "user-value", metadata["user-key"])
		assert.Equal(t, "text/plain", metadata["content-type"])
		assert.Equal(t, 4, mm.countEncryptionKeys(metadata))
		OrcMetaAssertOnlyAllowedKeys(t, metadata, "s3ep-")
	}
}

func TestOrcMetaBuildMetadataUserKeyCollidingWithPrefixIsOverwritten(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	// A client that sends x-amz-meta-s3ep-encrypted-dek must not be able to
	// dictate the stored DEK: the proxy's own value wins.
	metadata := mm.BuildMetadataForEncryption(
		nil,
		[]byte("real-dek"),
		nil,
		"aes-gcm",
		"real-fp",
		"aes",
		map[string]string{
			"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("attacker-dek")),
			"s3ep-kek-fingerprint": "attacker-fp",
		},
	)

	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("real-dek")), metadata["s3ep-encrypted-dek"])
	assert.Equal(t, "real-fp", metadata["s3ep-kek-fingerprint"])
}

// ===== Prefix configuration =====

func TestOrcMetaPrefixResolutionOrder(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		explicit string
		want     string
	}{
		{"explicit prefix wins over config", OrcMetaConfig(OrcMetaPrefixPtr("cfg-")), "explicit-", "explicit-"},
		{"config prefix used when explicit empty", OrcMetaConfig(OrcMetaPrefixPtr("cfg-")), "", "cfg-"},
		{"default s3ep- when config prefix unset", OrcMetaConfig(nil), "", "s3ep-"},
		// Pins current behaviour: an explicitly configured empty prefix stays
		// empty rather than falling back to the default.
		{"configured empty prefix stays empty", OrcMetaConfig(OrcMetaPrefixPtr("")), "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mm := NewMetadataManager(tt.cfg, tt.explicit)
			require.NotNil(t, mm)
			assert.Equal(t, tt.want, mm.GetMetadataPrefix())
			assert.Equal(t, tt.want+"encrypted-dek", mm.BuildMetadataKey("encrypted-dek"))
			assert.Equal(t, "encrypted-dek", mm.ExtractMetadataKey(tt.want+"encrypted-dek"))
		})
	}
}

// TestOrcMetaEmptyPrefixSwallowsAllClientMetadata documents a real defect: when
// the operator configures metadata_key_prefix: "", every key gets prefix-matched
// by strings.HasPrefix(key, "") and the client receives no user metadata at all.
func TestOrcMetaEmptyPrefixSwallowsAllClientMetadata(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("")), "")
	require.Equal(t, "", mm.GetMetadataPrefix())

	filtered := mm.FilterMetadataForClient(map[string]string{
		"content-type":  "text/plain",
		"x-amz-meta-ab": "cd",
		"encrypted-dek": "blob",
	})

	assert.Empty(t, filtered,
		"DEFECT: with an empty prefix every user metadata key is stripped from the response")

	extracted, err := mm.ExtractEncryptionMetadata(map[string]string{"user": "value"})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"user": "value"}, extracted,
		"DEFECT: with an empty prefix all user metadata is treated as encryption metadata")
}

// ===== FilterMetadataForClient =====

func TestOrcMetaFilterMetadataForClientRemovesEveryPrefixedKey(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	input := map[string]string{
		"s3ep-encrypted-dek":   "dek",
		"s3ep-dek-algorithm":   "aes-ctr",
		"s3ep-kek-fingerprint": "fp",
		"s3ep-kek-algorithm":   "aes",
		"s3ep-aes-iv":          "iv",
		"s3ep-hmac":            "mac",
		"s3ep-future-field":    "whatever",
		"content-type":         "application/octet-stream",
		"x-amz-meta-user":      "hans",
	}

	filtered := mm.FilterMetadataForClient(input)

	assert.Equal(t, map[string]string{
		"content-type":    "application/octet-stream",
		"x-amz-meta-user": "hans",
	}, filtered)
	assert.Len(t, input, 9, "filtering must not mutate the caller's map")
}

// TestOrcMetaFilterMetadataForClientIsCaseSensitive pins a real defect: S3 user
// metadata keys are case-insensitive, so a backend that hands back
// "S3EP-encrypted-dek" (or a client that stored one) leaks the encrypted DEK,
// the KEK fingerprint and the HMAC straight through to the client.
func TestOrcMetaFilterMetadataForClientIsCaseSensitive(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	input := map[string]string{
		"S3EP-encrypted-dek":   "dek",
		"S3ep-kek-fingerprint": "fp",
		"s3EP-hmac":            "mac",
		"user":                 "value",
	}

	filtered := mm.FilterMetadataForClient(input)

	assert.Equal(t, "dek", filtered["S3EP-encrypted-dek"],
		"DEFECT: case-different proxy metadata reaches the client")
	assert.Equal(t, "fp", filtered["S3ep-kek-fingerprint"])
	assert.Equal(t, "mac", filtered["s3EP-hmac"])
	assert.Equal(t, "value", filtered["user"])

	// The same case-sensitivity blinds the readers, so a case-different object
	// is not decryptable either - it fails closed on the read path.
	_, err := mm.GetEncryptedDEK(map[string]string{"S3EP-encrypted-dek": "dek"})
	assert.EqualError(t, err, "encrypted DEK not found in metadata")
	_, err = mm.GetAlgorithm(map[string]string{"S3EP-dek-algorithm": "aes-ctr"})
	assert.EqualError(t, err, "algorithm not found in metadata")
}

func TestOrcMetaExtractEncryptionMetadataStripsPrefix(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("proxy_")), "")

	extracted, err := mm.ExtractEncryptionMetadata(map[string]string{
		"proxy_encrypted-dek": "dek",
		"proxy_aes-iv":        "iv",
		"user":                "value",
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"encrypted-dek": "dek", "aes-iv": "iv"}, extracted)

	empty, err := mm.ExtractEncryptionMetadata(nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// ===== Typed getters: happy path, fallback, error path =====

func TestOrcMetaGettersReportMissingFields(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")
	empty := map[string]string{}

	_, err := mm.GetEncryptedDEK(empty)
	assert.EqualError(t, err, "encrypted DEK not found in metadata")

	_, err = mm.GetAlgorithm(empty)
	assert.EqualError(t, err, "algorithm not found in metadata")

	_, err = mm.GetFingerprint(empty)
	assert.EqualError(t, err, "KEK fingerprint not found in metadata")

	_, err = mm.GetIV(empty)
	assert.EqualError(t, err, "IV not found in metadata")

	_, err = mm.GetKEKAlgorithm(empty)
	assert.EqualError(t, err, "KEK algorithm not found in metadata")

	_, err = mm.GetHMAC(empty)
	assert.EqualError(t, err, "HMAC not found in metadata")

	assert.False(t, mm.HasHMAC(empty))
}

func TestOrcMetaGettersRejectMalformedBase64(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	_, err := mm.GetEncryptedDEK(map[string]string{"s3ep-encrypted-dek": "not!base64"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode encrypted DEK")

	_, err = mm.GetIV(map[string]string{"s3ep-aes-iv": "not!base64"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode IV")

	_, err = mm.GetHMAC(map[string]string{"s3ep-hmac": "not!base64"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode HMAC")
}

// TestOrcMetaGettersAcceptUnprefixedLegacyKeys pins the current storage-format
// behaviour: objects written before the prefix existed are still readable.
// The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcMetaGettersAcceptUnprefixedLegacyKeys(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	legacy := map[string]string{
		"encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("dek")),
		"dek-algorithm":   "aes-ctr",
		"kek-fingerprint": "legacy-fp",
		"kek-algorithm":   "aes",
		"aes-iv":          base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")),
	}

	dek, err := mm.GetEncryptedDEK(legacy)
	require.NoError(t, err)
	assert.Equal(t, []byte("dek"), dek)

	algorithm, err := mm.GetAlgorithm(legacy)
	require.NoError(t, err)
	assert.Equal(t, "aes-ctr", algorithm)

	fingerprint, err := mm.GetFingerprint(legacy)
	require.NoError(t, err)
	assert.Equal(t, "legacy-fp", fingerprint)

	kekAlgorithm, err := mm.GetKEKAlgorithm(legacy)
	require.NoError(t, err)
	assert.Equal(t, "aes", kekAlgorithm)

	iv, err := mm.GetIV(legacy)
	require.NoError(t, err)
	assert.Equal(t, []byte("0123456789abcdef"), iv)

	// The HMAC getter has no unprefixed fallback, so a legacy object simply has
	// no integrity tag - strict mode has to reject it elsewhere.
	assert.False(t, mm.HasHMAC(legacy))
}

func TestOrcMetaPrefixedValueWinsOverUnprefixed(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	metadata := map[string]string{
		"s3ep-dek-algorithm":   "aes-gcm",
		"dek-algorithm":        "aes-ctr",
		"s3ep-kek-fingerprint": "current",
		"kek-fingerprint":      "legacy",
		"s3ep-kek-algorithm":   "aes",
		"kek-algorithm":        "rsa",
		"s3ep-encrypted-dek":   base64.StdEncoding.EncodeToString([]byte("current-dek")),
		"encrypted-dek":        base64.StdEncoding.EncodeToString([]byte("legacy-dek")),
		"s3ep-aes-iv":          base64.StdEncoding.EncodeToString([]byte("current-iv-16byt")),
		"aes-iv":               base64.StdEncoding.EncodeToString([]byte("legacy-iv-16bytes")),
	}

	algorithm, err := mm.GetAlgorithm(metadata)
	require.NoError(t, err)
	assert.Equal(t, "aes-gcm", algorithm)

	fingerprint, err := mm.GetFingerprint(metadata)
	require.NoError(t, err)
	assert.Equal(t, "current", fingerprint)

	kekAlgorithm, err := mm.GetKEKAlgorithm(metadata)
	require.NoError(t, err)
	assert.Equal(t, "aes", kekAlgorithm)

	dek, err := mm.GetEncryptedDEK(metadata)
	require.NoError(t, err)
	assert.Equal(t, []byte("current-dek"), dek)

	iv, err := mm.GetIV(metadata)
	require.NoError(t, err)
	assert.Equal(t, []byte("current-iv-16byt"), iv)
}

func TestOrcMetaHMACRoundTrip(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("mac-")), "")
	metadata := map[string]string{}

	assert.False(t, mm.HasHMAC(metadata))
	mm.SetHMAC(metadata, []byte{})
	assert.True(t, mm.HasHMAC(metadata), "an empty HMAC still occupies the metadata slot")
	assert.Equal(t, "", metadata["mac-hmac"])

	sum := sha256.Sum256([]byte("payload"))
	mm.SetHMAC(metadata, sum[:])
	assert.True(t, mm.HasHMAC(metadata))

	got, err := mm.GetHMAC(metadata)
	require.NoError(t, err)
	assert.Equal(t, sum[:], got)
	assert.Equal(t, []string{"mac-hmac"}, OrcMetaPrefixedKeys(metadata, "mac-"))
}

// ===== Validation helpers =====

func TestOrcMetaValidateEncryptionMetadataNamesTheMissingField(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	complete := map[string]string{
		"s3ep-encrypted-dek":   "dek",
		"s3ep-dek-algorithm":   "aes-ctr",
		"s3ep-kek-fingerprint": "fp",
		"s3ep-kek-algorithm":   "aes",
	}
	require.NoError(t, mm.ValidateEncryptionMetadata(complete))

	for _, required := range []string{"encrypted-dek", "dek-algorithm", "kek-fingerprint", "kek-algorithm"} {
		incomplete := make(map[string]string, len(complete))
		for key, value := range complete {
			incomplete[key] = value
		}
		delete(incomplete, "s3ep-"+required)

		err := mm.ValidateEncryptionMetadata(incomplete)
		require.Error(t, err)
		assert.EqualError(t, err, required+" is required")
	}

	assert.Error(t, mm.ValidateEncryptionMetadata(nil))
}

func TestOrcMetaValidateMetadataListsAllMissingKeys(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	err := mm.ValidateMetadata(nil)
	assert.EqualError(t, err, "metadata cannot be nil")

	err = mm.ValidateMetadata(map[string]string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s3ep-encrypted-dek")
	assert.Contains(t, err.Error(), "s3ep-kek-fingerprint")

	err = mm.ValidateMetadata(map[string]string{"s3ep-encrypted-dek": "dek"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s3ep-kek-fingerprint")
	assert.NotContains(t, err.Error(), "s3ep-encrypted-dek")

	require.NoError(t, mm.ValidateMetadata(map[string]string{
		"s3ep-encrypted-dek":   "dek",
		"s3ep-kek-fingerprint": "fp",
	}))

	// An empty value passes: only presence is checked.
	require.NoError(t, mm.ValidateMetadata(map[string]string{
		"s3ep-encrypted-dek":   "",
		"s3ep-kek-fingerprint": "",
	}))
}

func TestOrcMetaValidateConfiguration(t *testing.T) {
	assert.EqualError(t, NewMetadataManager(nil, "s3ep-").ValidateConfiguration(),
		"configuration cannot be nil")

	require.NoError(t, NewMetadataManager(OrcMetaConfig(nil), "").ValidateConfiguration())
	require.NoError(t, NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("")), "").ValidateConfiguration(),
		"an empty prefix is a valid configuration")

	for _, bad := range []string{"s3ep ", "s3\tep-", "s3ep-\n"} {
		err := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr(bad)), "").ValidateConfiguration()
		assert.EqualError(t, err, "metadata prefix cannot contain whitespace characters",
			"prefix %q must be rejected", bad)
	}
}

// ===== Key classification helpers =====

func TestOrcMetaIsEncryptionMetadataClassification(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	for _, key := range []string{
		"s3ep-dek-algorithm", "s3ep-encrypted-dek", "s3ep-aes-iv",
		"s3ep-kek-algorithm", "s3ep-kek-fingerprint", "s3ep-hmac",
		"dek-algorithm", "encrypted-dek", "hmac",
	} {
		assert.True(t, mm.IsEncryptionMetadata(key), "%q must be classified as encryption metadata", key)
	}

	for _, key := range []string{"x-amz-meta-user", "s3ep-unknown", "S3EP-hmac", ""} {
		assert.False(t, mm.IsEncryptionMetadata(key), "%q must not be classified as encryption metadata", key)
	}

	// DEFECT (dead code today): "content-type" and "algorithm" are plain user
	// metadata names, yet they are classified as encryption metadata and would
	// be stripped from a client response.
	assert.True(t, mm.IsEncryptionMetadata("content-type"))
	assert.True(t, mm.IsEncryptionMetadata("algorithm"))
}

func TestOrcMetaFilterEncryptionMetadata(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	assert.Nil(t, mm.FilterEncryptionMetadata(nil))

	filtered := mm.FilterEncryptionMetadata(map[string]string{
		"s3ep-encrypted-dek": "dek",
		"s3ep-hmac":          "mac",
		"encrypted-dek":      "legacy-dek",
		"content-type":       "text/plain",
		"x-amz-meta-user":    "hans",
	})

	assert.Equal(t, map[string]string{"x-amz-meta-user": "hans"}, filtered,
		"DEFECT: content-type is user metadata but gets stripped as encryption metadata")
}

func TestOrcMetaExtractRequiredFingerprintSearchOrder(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	assert.Equal(t, "", mm.ExtractRequiredFingerprint(nil))
	assert.Equal(t, "", mm.ExtractRequiredFingerprint(map[string]string{"other": "value"}))
	assert.Equal(t, "", mm.ExtractRequiredFingerprint(map[string]string{"s3ep-kek-fingerprint": ""}),
		"an empty fingerprint value must not be treated as found")

	assert.Equal(t, "primary", mm.ExtractRequiredFingerprint(map[string]string{
		"s3ep-kek-fingerprint":       "primary",
		"s3ep-key-id":                "secondary",
		"kek-fingerprint":            "legacy",
		"encryption-kek-fingerprint": "alternative",
	}))
	assert.Equal(t, "secondary", mm.ExtractRequiredFingerprint(map[string]string{
		"s3ep-key-id":     "secondary",
		"kek-fingerprint": "legacy",
	}))
	assert.Equal(t, "legacy", mm.ExtractRequiredFingerprint(map[string]string{"kek-fingerprint": "legacy"}))
	assert.Equal(t, "alternative", mm.ExtractRequiredFingerprint(map[string]string{"encryption-kek-fingerprint": "alternative"}))

	// A non-default prefix still finds the s3ep- legacy keys.
	custom := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("proxy-")), "")
	assert.Equal(t, "own", custom.ExtractRequiredFingerprint(map[string]string{
		"proxy-kek-fingerprint": "own",
		"s3ep-kek-fingerprint":  "foreign",
	}))
	assert.Equal(t, "foreign", custom.ExtractRequiredFingerprint(map[string]string{
		"s3ep-kek-fingerprint": "foreign",
	}))
}

func TestOrcMetaGetAlgorithmFromMetadata(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	assert.Equal(t, "", mm.GetAlgorithmFromMetadata(nil))
	assert.Equal(t, "", mm.GetAlgorithmFromMetadata(map[string]string{}))
	assert.Equal(t, "", mm.GetAlgorithmFromMetadata(map[string]string{"s3ep-dek-algorithm": ""}))
	assert.Equal(t, "aes-gcm", mm.GetAlgorithmFromMetadata(map[string]string{
		"s3ep-dek-algorithm": "aes-gcm",
		"s3ep-algorithm":     "aes-ctr",
		"dek-algorithm":      "legacy",
	}))
	assert.Equal(t, "aes-ctr", mm.GetAlgorithmFromMetadata(map[string]string{"s3ep-algorithm": "aes-ctr"}))
	assert.Equal(t, "legacy", mm.GetAlgorithmFromMetadata(map[string]string{"dek-algorithm": "legacy"}))
	assert.Equal(t, "bare", mm.GetAlgorithmFromMetadata(map[string]string{"algorithm": "bare"}))
}

// TestOrcMetaAddStandardMetadataWritesUndocumentedKey pins the current behaviour
// of a helper that writes prefix+"algorithm", which is not one of the documented
// allowed metadata fields (dek-algorithm is).
func TestOrcMetaAddStandardMetadataWritesUndocumentedKey(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	assert.NotPanics(t, func() { mm.AddStandardMetadata(nil, "fp", "aes-gcm") })

	metadata := map[string]string{}
	mm.AddStandardMetadata(metadata, "fp", "")
	assert.Equal(t, map[string]string{"s3ep-kek-fingerprint": "fp"}, metadata)

	mm.AddStandardMetadata(metadata, "fp2", "aes-gcm")
	assert.Equal(t, "fp2", metadata["s3ep-kek-fingerprint"])
	assert.Equal(t, "aes-gcm", metadata["s3ep-algorithm"])
	assert.NotContains(t, OrcMetaAllowedSuffixes, "algorithm",
		"DEFECT: AddStandardMetadata writes s3ep-algorithm, which is not an allowed metadata field")
}

func TestOrcMetaCreateMissingKEKError(t *testing.T) {
	mm := NewMetadataManager(OrcMetaConfig(OrcMetaPrefixPtr("s3ep-")), "")

	err := mm.CreateMissingKEKError("bucket/object.txt", "fp-123", map[string]string{
		"s3ep-kek-algorithm": "rsa",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEK_MISSING")
	assert.Contains(t, err.Error(), "bucket/object.txt")
	assert.Contains(t, err.Error(), "fp-123")
	assert.Contains(t, err.Error(), "type: rsa")

	err = mm.CreateMissingKEKError("obj", "fp", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type: unknown")

	err = mm.CreateMissingKEKError("obj", "fp", map[string]string{"other": "value"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type: unknown")
}

// ===== End-to-end: what actually lands next to the ciphertext =====

// TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys drives a real Manager with
// a real AES provider and checks the client-visible contract: the object bytes
// handed to the backend are not the plaintext, the metadata stored alongside
// them carries only allowed keys under the configured prefix, the round trip is
// byte-identical, and nothing prefixed survives the filter back to the client.
func TestOrcMetaEndToEndStoredMetadataIsOnlyAllowedKeys(t *testing.T) {
	const prefix = "orcmeta-"

	cfg := OrcMetaConfig(OrcMetaPrefixPtr(prefix))
	m := OrcMetaNewManager(t, cfg)
	require.Equal(t, prefix, m.GetMetadataKeyPrefix())

	sizes := []int{0, 1, 4096, 1024 * 1024}
	for _, size := range sizes {
		plaintext := bytes.Repeat([]byte("orcmeta-payload!"), 1+size/16)[:size]

		encReader, metadata, err := m.CreateEncryptionReader(context.Background(),
			bytes.NewReader(plaintext), "objects/roundtrip")
		require.NoError(t, err)

		ciphertext, err := io.ReadAll(encReader)
		require.NoError(t, err)

		if size > 0 {
			assert.NotEqual(t, OrcMetaSHA256(plaintext), OrcMetaSHA256(ciphertext),
				"plaintext must never be what the backend stores")
		}

		OrcMetaAssertOnlyAllowedKeys(t, metadata, prefix)
		for key := range metadata {
			assert.True(t, strings.HasPrefix(key, prefix),
				"stored metadata key %q must carry the configured prefix", key)
		}
		assert.Contains(t, metadata, prefix+"encrypted-dek")
		assert.Contains(t, metadata, prefix+"kek-fingerprint")
		assert.Contains(t, metadata, prefix+"dek-algorithm")
		assert.NotContains(t, metadata, "s3ep-encrypted-dek",
			"the default prefix must not appear when another prefix is configured")

		decReader, err := m.DecryptData(context.Background(), bufio.NewReader(bytes.NewReader(ciphertext)),
			metadata, "objects/roundtrip")
		require.NoError(t, err)
		roundTrip, err := io.ReadAll(decReader)
		require.NoError(t, err)
		assert.Equal(t, OrcMetaSHA256(plaintext), OrcMetaSHA256(roundTrip),
			"round trip must be byte-identical for size %d", size)

		// Simulate the response path: user metadata survives, proxy metadata does not.
		response := make(map[string]string, len(metadata)+2)
		for key, value := range metadata {
			response[key] = value
		}
		response["content-type"] = "application/octet-stream"
		response["x-amz-meta-owner"] = "hans"

		filtered := m.FilterMetadataForClient(response)
		assert.Equal(t, map[string]string{
			"content-type":     "application/octet-stream",
			"x-amz-meta-owner": "hans",
		}, filtered, "no proxy metadata may reach the client for size %d", size)
	}
}

// TestOrcMetaEndToEndDefaultPrefixIsS3EP verifies the documented default: with
// no metadata_key_prefix configured, stored keys start with "s3ep-".
func TestOrcMetaEndToEndDefaultPrefixIsS3EP(t *testing.T) {
	m := OrcMetaNewManager(t, OrcMetaConfig(nil))
	assert.Equal(t, "s3ep-", m.GetMetadataKeyPrefix())

	_, metadata, err := m.CreateEncryptionReader(context.Background(),
		bytes.NewReader([]byte("hello")), "objects/default-prefix")
	require.NoError(t, err)

	require.NotEmpty(t, metadata)
	OrcMetaAssertOnlyAllowedKeys(t, metadata, "s3ep-")
	for key := range metadata {
		assert.True(t, strings.HasPrefix(key, "s3ep-"), "unexpected metadata key %q", key)
	}
}
