package keyencryption

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const KekTinkURI = "gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k"

// KekNewTink builds a Tink provider backed by a locally generated keyset.
func KekNewTink(t *testing.T, uri string) *TinkProvider {
	t.Helper()
	provider, err := NewTinkProviderFromConfig(&TinkConfig{KEKUri: uri})
	require.NoError(t, err)
	require.NotNil(t, provider)
	return provider
}

func TestKekTinkConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  TinkConfig
		wantErr string
	}{
		{name: "uri only", config: TinkConfig{KEKUri: KekTinkURI}},
		{name: "AES128_GCM", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "AES128_GCM"}},
		{name: "AES256_GCM", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "AES256_GCM"}},
		{name: "AES128_CTR_HMAC_SHA256", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "AES128_CTR_HMAC_SHA256"}},
		{name: "AES256_CTR_HMAC_SHA256", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "AES256_CTR_HMAC_SHA256"}},
		{name: "with credentials path", config: TinkConfig{KEKUri: KekTinkURI, CredentialsPath: "/nonexistent/creds.json"}},
		{name: "missing uri", config: TinkConfig{}, wantErr: "kek_uri is required for Tink provider"},
		{name: "missing uri with template", config: TinkConfig{KeyTemplate: "AES256_GCM"}, wantErr: "kek_uri is required"},
		{name: "unsupported template", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "CHACHA20_POLY1305"}, wantErr: "unsupported key_template: CHACHA20_POLY1305"},
		{name: "template case sensitive", config: TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "aes256_gcm"}, wantErr: "unsupported key_template: aes256_gcm"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.config
			err := cfg.Validate()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestKekTinkProviderFromConfigRejectsInvalidConfig(t *testing.T) {
	provider, err := NewTinkProviderFromConfig(&TinkConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kek_uri is required")
	assert.Nil(t, provider)

	provider, err = NewTinkProviderFromConfig(&TinkConfig{KEKUri: KekTinkURI, KeyTemplate: "NOPE"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key_template")
	assert.Nil(t, provider)
}

func TestKekTinkProviderConstruction(t *testing.T) {
	t.Run("nil handle", func(t *testing.T) {
		provider, err := NewTinkProvider(nil, KekTinkURI)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KEK handle cannot be nil")
		assert.Nil(t, provider)
	})

	t.Run("handle without AEAD primitive", func(t *testing.T) {
		handle, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
		require.NoError(t, err)

		provider, err := NewTinkProvider(handle, KekTinkURI)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create KEK AEAD")
		assert.Nil(t, provider)
	})
}

func TestKekTinkDEKRoundTrip(t *testing.T) {
	provider := KekNewTink(t, KekTinkURI)
	ctx := context.Background()

	tests := []struct {
		name string
		dek  []byte
	}{
		{name: "empty dek", dek: []byte{}},
		{name: "32 byte dek", dek: KekBytePattern(32)},
		{name: "large dek", dek: KekBytePattern(4096)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, err := provider.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)
			assert.Greater(t, len(ciphertext), len(tc.dek), "AEAD adds a tag and key prefix")
			assert.NotEqual(t, sha256.Sum256(tc.dek), sha256.Sum256(ciphertext))

			plaintext, err := provider.DecryptDEK(ctx, ciphertext)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(plaintext))
		})
	}
}

func TestKekTinkDecryptDEKFailures(t *testing.T) {
	provider := KekNewTink(t, KekTinkURI)
	ctx := context.Background()
	dek := KekBytePattern(32)

	ciphertext, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	t.Run("tampered ciphertext is detected", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0x01

		_, err := provider.DecryptDEK(ctx, tampered)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with Tink KEK")
	})

	t.Run("empty ciphertext is rejected", func(t *testing.T) {
		_, err := provider.DecryptDEK(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with Tink KEK")
	})
}

func TestKekTinkFingerprintDerivesFromURIOnly(t *testing.T) {
	first := KekNewTink(t, KekTinkURI)
	second := KekNewTink(t, KekTinkURI)
	other := KekNewTink(t, KekTinkURI+"-other")

	expected := sha256.Sum256([]byte(KekTinkURI))
	assert.Equal(t, hex.EncodeToString(expected[:]), first.Fingerprint())
	assert.NotEqual(t, first.Fingerprint(), other.Fingerprint())

	// The fingerprint covers only the URI, while loadKEKHandle generates a fresh
	// random keyset per call. Two providers built from the same config therefore
	// advertise the same key ID but cannot read each other's wrapped DEKs.
	ctx := context.Background()
	ciphertext, err := first.EncryptDEK(ctx, KekBytePattern(32))
	require.NoError(t, err)
	assert.Equal(t, first.Fingerprint(), second.Fingerprint())

	_, err = second.DecryptDEK(ctx, ciphertext)
	require.Error(t, err, "identical fingerprint, different key material")
	assert.Contains(t, err.Error(), "failed to decrypt DEK with Tink KEK")
}

func TestKekTinkName(t *testing.T) {
	provider := KekNewTink(t, KekTinkURI)
	assert.Equal(t, "tink", provider.Name())
}
