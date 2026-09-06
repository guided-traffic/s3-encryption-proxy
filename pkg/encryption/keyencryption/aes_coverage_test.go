package keyencryption

import (
	"context"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	rawKey := string(KekAESKeyA)
	b64Key := base64.StdEncoding.EncodeToString(KekAESKeyB)

	tests := []struct {
		name        string
		config      map[string]interface{}
		wantErr     string
		wantKEKHash []byte
	}{
		{
			name:        "base64 encoded 32 byte key is decoded",
			config:      map[string]interface{}{"aes_key": b64Key},
			wantKEKHash: KekAESKeyB,
		},
		{
			name:        "raw 32 byte ascii key is used verbatim",
			config:      map[string]interface{}{"aes_key": rawKey},
			wantKEKHash: KekAESKeyA,
		},
		{
			name:    "missing aes_key",
			config:  map[string]interface{}{},
			wantErr: "missing 'aes_key' in configuration",
		},
		{
			name:    "aes_key not a string",
			config:  map[string]interface{}{"aes_key": 12345},
			wantErr: "key must be a string",
		},
		{
			name:    "empty aes_key",
			config:  map[string]interface{}{"aes_key": ""},
			wantErr: "key cannot be empty",
		},
		{
			name:    "base64 of wrong length falls back to raw bytes and is rejected",
			config:  map[string]interface{}{"aes_key": base64.StdEncoding.EncodeToString(make([]byte, 16))},
			wantErr: "must be exactly 32 bytes",
		},
		{
			name:    "short non base64 key rejected",
			config:  map[string]interface{}{"aes_key": "too-short"},
			wantErr: "must be exactly 32 bytes, got 9",
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
			expected := sha256.Sum256(tc.wantKEKHash)
			assert.Equal(t, hex.EncodeToString(expected[:]), provider.Fingerprint(),
				"fingerprint must be derived from the decoded KEK")
		})
	}
}

func TestKekAESNewProviderFromBase64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{name: "valid base64 32 bytes", input: base64.StdEncoding.EncodeToString(KekAESKeyA)},
		{name: "invalid base64", input: "!!!not-base64!!!", wantErr: "failed to decode base64 KEK"},
		{name: "valid base64 but 16 bytes", input: base64.StdEncoding.EncodeToString(make([]byte, 16)), wantErr: "must be exactly 32 bytes, got 16"},
		{name: "empty string decodes to zero bytes", input: "", wantErr: "must be exactly 32 bytes, got 0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewAESProviderFromBase64(tc.input)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, provider)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, provider)

			// The provider built from base64 must be interchangeable with the raw one.
			raw := KekNewAES(t, KekAESKeyA)
			assert.Equal(t, raw.Fingerprint(), provider.Fingerprint())
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
			ciphertext, keyID, err := provider.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)
			assert.Equal(t, provider.Fingerprint(), keyID)

			// Layout is IV || CTR(dek), so the wrapped DEK grows by exactly one AES block.
			require.Len(t, ciphertext, aes.BlockSize+len(tc.dek))
			if len(tc.dek) > 0 {
				assert.NotEqual(t, tc.dek, ciphertext[aes.BlockSize:], "ciphertext must differ from plaintext DEK")
			}

			plaintext, err := provider.DecryptDEK(ctx, ciphertext, keyID)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(plaintext))
		})
	}
}

func TestKekAESEncryptDEKUsesFreshIV(t *testing.T) {
	provider := KekNewAES(t, KekAESKeyA)
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")

	first, _, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)
	second, _, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	assert.NotEqual(t, first[:aes.BlockSize], second[:aes.BlockSize], "IV must be freshly generated per call")
	assert.NotEqual(t, first, second, "same DEK must not produce identical wrapped output")
}

func TestKekAESDecryptDEKRejectsForeignKeyID(t *testing.T) {
	providerA := KekNewAES(t, KekAESKeyA)
	providerB := KekNewAES(t, KekAESKeyB)
	ctx := context.Background()

	ciphertext, keyID, err := providerA.EncryptDEK(ctx, []byte("0123456789abcdef0123456789abcdef"))
	require.NoError(t, err)

	_, err = providerB.DecryptDEK(ctx, ciphertext, keyID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key ID mismatch")
	assert.Contains(t, err.Error(), providerB.Fingerprint())

	_, err = providerA.DecryptDEK(ctx, ciphertext, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key ID mismatch")
}

func TestKekAESDecryptDEKTooShort(t *testing.T) {
	provider := KekNewAES(t, KekAESKeyA)
	ctx := context.Background()

	for _, size := range []int{0, 1, aes.BlockSize - 1} {
		_, err := provider.DecryptDEK(ctx, make([]byte, size), provider.Fingerprint())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "encrypted DEK too short")
	}

	// Exactly one block is the boundary: it is the IV with an empty payload.
	dek, err := provider.DecryptDEK(ctx, make([]byte, aes.BlockSize), provider.Fingerprint())
	require.NoError(t, err)
	assert.Empty(t, dek)
}

// TestKekAESWrapIsUnauthenticated documents that the AES KEK layer uses raw CTR:
// a wrong key or a flipped bit yields a silently wrong DEK instead of an error.
// Integrity therefore depends entirely on the DEK layer (GCM/HMAC).
func TestKekAESWrapIsUnauthenticated(t *testing.T) {
	providerA := KekNewAES(t, KekAESKeyA)
	providerB := KekNewAES(t, KekAESKeyB)
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")

	ciphertext, _, err := providerA.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	// Wrong KEK, but the caller supplies the matching fingerprint of that KEK.
	wrong, err := providerB.DecryptDEK(ctx, ciphertext, providerB.Fingerprint())
	require.NoError(t, err, "CTR unwrapping cannot detect a wrong KEK")
	assert.NotEqual(t, dek, wrong, "wrong KEK must not recover the DEK")

	// Bit flip inside the wrapped DEK.
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[aes.BlockSize] ^= 0x01
	corrupted, err := providerA.DecryptDEK(ctx, tampered, providerA.Fingerprint())
	require.NoError(t, err, "CTR unwrapping cannot detect tampering")
	require.Len(t, corrupted, len(dek))
	assert.Equal(t, dek[0]^0x01, corrupted[0])
	assert.Equal(t, dek[1:], corrupted[1:], "CTR keeps the flip strictly local")
}

func TestKekAESFingerprintStabilityAndUniqueness(t *testing.T) {
	providerA := KekNewAES(t, KekAESKeyA)
	providerA2 := KekNewAES(t, KekAESKeyA)
	providerB := KekNewAES(t, KekAESKeyB)

	assert.Equal(t, providerA.Fingerprint(), providerA2.Fingerprint(), "same KEK must fingerprint identically")
	assert.NotEqual(t, providerA.Fingerprint(), providerB.Fingerprint(), "different KEKs must fingerprint differently")
	assert.Len(t, providerA.Fingerprint(), 64, "SHA-256 hex digest")

	// The fingerprint is an unsalted SHA-256 over the raw KEK, which is also what
	// ends up in object metadata. Pinning it here makes any change to that
	// derivation an explicit, visible decision.
	expected := sha256.Sum256(KekAESKeyA)
	assert.Equal(t, hex.EncodeToString(expected[:]), providerA.Fingerprint())
}

func TestKekAESNameAndRotateKEK(t *testing.T) {
	provider := KekNewAES(t, KekAESKeyA)
	assert.Equal(t, "aes", provider.Name())

	err := provider.RotateKEK(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AES key rotation is not implemented")
}
