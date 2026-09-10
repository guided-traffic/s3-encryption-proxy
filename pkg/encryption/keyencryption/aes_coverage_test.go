package keyencryption

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// KekAESKeyA and KekAESKeyB are two distinct 32-byte KEKs used across the AES tests.
var (
	KekAESKeyA = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	KekAESKeyB = []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
)

// KekBytePattern returns n bytes with a deterministic, non-constant pattern.
func KekBytePattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 3)
	}
	return out
}

// KekNewAES builds an AES key encryptor and fails the test if construction fails.
func KekNewAES(t *testing.T, kek []byte) *AESProvider {
	t.Helper()
	p, err := NewAESKeyEncryptor(kek)
	require.NoError(t, err)
	provider, ok := p.(*AESProvider)
	require.True(t, ok, "NewAESKeyEncryptor must return *AESProvider")
	return provider
}

func TestKekAESNewFromRawKEK(t *testing.T) {
	tests := []struct {
		name    string
		kek     []byte
		wantErr string
	}{
		{name: "valid 32 bytes", kek: KekAESKeyA},
		{name: "nil key", kek: nil, wantErr: "must be exactly 32 bytes, got 0"},
		{name: "empty key", kek: []byte{}, wantErr: "must be exactly 32 bytes, got 0"},
		{name: "16 bytes AES-128 rejected", kek: make([]byte, 16), wantErr: "must be exactly 32 bytes, got 16"},
		{name: "31 bytes off by one", kek: make([]byte, 31), wantErr: "must be exactly 32 bytes, got 31"},
		{name: "33 bytes off by one", kek: make([]byte, 33), wantErr: "must be exactly 32 bytes, got 33"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewAESKeyEncryptor(tc.kek)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, provider)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, provider)
			assert.Equal(t, "aes", provider.Name())
		})
	}
}

func TestKekAESNewProviderFromConfigMap(t *testing.T) {
	tests := []struct {
		name    string
		config  map[string]interface{}
		wantKEK []byte
		wantErr string
	}{
		{
			name:    "base64 encoded 32 byte key is decoded",
			config:  map[string]interface{}{"aes_key": base64.StdEncoding.EncodeToString(KekAESKeyB)},
			wantKEK: KekAESKeyB,
		},
		{
			name:    "raw 32 byte ascii key is refused",
			config:  map[string]interface{}{"aes_key": string(KekAESKeyA)},
			wantErr: "must be base64 of exactly 32 bytes",
		},
		{
			name:    "missing aes_key",
			config:  map[string]interface{}{},
			wantErr: "missing 'aes_key' in configuration",
		},
		{
			name:    "aes_key not a string",
			config:  map[string]interface{}{"aes_key": 12345},
			wantErr: "aes_key must be a string",
		},
		{
			name:    "empty aes_key",
			config:  map[string]interface{}{"aes_key": ""},
			wantErr: "must be base64 of exactly 32 bytes",
		},
		{
			name:    "base64 of wrong length is rejected",
			config:  map[string]interface{}{"aes_key": base64.StdEncoding.EncodeToString(make([]byte, 16))},
			wantErr: "must be base64 of exactly 32 bytes",
		},
		{
			name:    "short non base64 key rejected",
			config:  map[string]interface{}{"aes_key": "too-short"},
			wantErr: "must be base64 of exactly 32 bytes",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewAESProvider(tc.config)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, provider)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, KekNewAES(t, tc.wantKEK).Fingerprint(), provider.Fingerprint(),
				"fingerprint must be derived from the decoded KEK")
		})
	}
}

func TestKekAESDEKRoundTrip(t *testing.T) {
	provider := KekNewAES(t, KekAESKeyA)
	ctx := context.Background()

	tests := []struct {
		name string
		dek  []byte
	}{
		{name: "empty dek", dek: []byte{}},
		{name: "single byte dek", dek: []byte{0x42}},
		{name: "32 byte dek", dek: []byte("0123456789abcdef0123456789abcdef")},
		{name: "all zero dek", dek: make([]byte, 32)},
		{name: "large dek with byte pattern", dek: KekBytePattern(512)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapped, err := provider.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)

			// salt || nonce || ciphertext || tag.
			require.Len(t, wrapped, wrapSaltSize+12+len(tc.dek)+16)

			plaintext, err := provider.DecryptDEK(ctx, wrapped)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(plaintext))
		})
	}
}

func TestKekAESEncryptDEKUsesFreshSalt(t *testing.T) {
	provider := KekNewAES(t, KekAESKeyA)
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")

	first, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)
	second, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	assert.NotEqual(t, first[:wrapSaltSize], second[:wrapSaltSize], "salt must be freshly generated per call")
	assert.NotEqual(t, first, second, "same DEK must not produce identical wrapped output")
}

func TestKekAESFingerprintStabilityAndUniqueness(t *testing.T) {
	providerA := KekNewAES(t, KekAESKeyA)
	providerA2 := KekNewAES(t, KekAESKeyA)
	providerB := KekNewAES(t, KekAESKeyB)

	assert.Equal(t, providerA.Fingerprint(), providerA2.Fingerprint(), "same KEK must fingerprint identically")
	assert.NotEqual(t, providerA.Fingerprint(), providerB.Fingerprint(), "different KEKs must fingerprint differently")
	assert.Len(t, providerA.Fingerprint(), 64, "32 derived bytes, hex encoded")
}
