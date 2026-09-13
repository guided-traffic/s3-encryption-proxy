package keyencryption

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKEK is the same key the Velero V9 scenario uses: bytes 0..31.
func testKEK() []byte {
	kek := make([]byte, KEKSize)
	for i := range kek {
		kek[i] = byte(i)
	}
	return kek
}

// The vector was computed with an independent HKDF implementation (RFC 5869,
// SHA-256, empty salt, info "s3ep-kek-fingerprint"), not with this package. A
// change in the derivation makes every stored object unreadable, so it is
// pinned rather than recomputed.
const testKEKFingerprint = "9f659e62ecbacf206fb7affdb37a23f989d228a371333dde251950f001048df5"

func TestAESKeyEncryptorFingerprintVector(t *testing.T) {
	provider, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	assert.Equal(t, testKEKFingerprint, provider.Fingerprint())

	// H-8: the published fingerprint must not be a hash of the key itself, or
	// it is an offline oracle for a guessable key.
	rawHash := sha256.Sum256(testKEK())
	assert.NotEqual(t, hex.EncodeToString(rawHash[:]), provider.Fingerprint())
}

func TestAESKeyEncryptorFingerprintDiffersPerKey(t *testing.T) {
	first, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	other := testKEK()
	other[31] ^= 0x01
	second, err := NewAESKeyEncryptor(other)
	require.NoError(t, err)

	assert.NotEqual(t, first.Fingerprint(), second.Fingerprint())
}

func TestAESKeyEncryptorWrapRoundTrip(t *testing.T) {
	provider, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	ctx := context.Background()
	dek := bytes.Repeat([]byte{0xA5}, 32)

	wrapped, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)
	assert.Len(t, wrapped, wrapSaltSize+12+32+16, "salt + nonce + ciphertext + tag")
	assert.NotContains(t, string(wrapped), string(dek))

	unwrapped, err := provider.DecryptDEK(ctx, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)
}

func TestAESKeyEncryptorWrapIsNotDeterministic(t *testing.T) {
	provider, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	ctx := context.Background()
	dek := bytes.Repeat([]byte{0xA5}, 32)

	first, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)
	second, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "a fresh salt and nonce per wrap")
}

// Every byte of the wrap is authenticated: the salt selects the wrapping key,
// the rest is nonce, ciphertext and tag.
func TestAESKeyEncryptorRejectsTamperedWrap(t *testing.T) {
	provider, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	ctx := context.Background()
	dek := bytes.Repeat([]byte{0xA5}, 32)
	wrapped, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	for i := range wrapped {
		tampered := append([]byte(nil), wrapped...)
		tampered[i] ^= 0x01

		_, err := provider.DecryptDEK(ctx, tampered)
		require.Error(t, err, "byte %d", i)
		assert.True(t, errors.Is(err, ErrWrappedDEKAuth), "byte %d: %v", i, err)
	}
}

func TestAESKeyEncryptorRejectsShortWrap(t *testing.T) {
	provider, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	_, err = provider.DecryptDEK(context.Background(), make([]byte, wrapSaltSize))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWrappedDEKAuth))
}

func TestAESKeyEncryptorRejectsForeignWrap(t *testing.T) {
	ctx := context.Background()
	mine, err := NewAESKeyEncryptor(testKEK())
	require.NoError(t, err)

	other := testKEK()
	other[0] ^= 0xFF
	theirs, err := NewAESKeyEncryptor(other)
	require.NoError(t, err)

	wrapped, err := theirs.EncryptDEK(ctx, bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)

	_, err = mine.DecryptDEK(ctx, wrapped)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrWrappedDEKAuth))
}

func TestAESKeyEncryptorRejectsWrongKEKSize(t *testing.T) {
	_, err := NewAESKeyEncryptor([]byte("short"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be exactly 32 bytes")
}

func TestAESProviderFromConfig(t *testing.T) {
	provider, err := NewAESProvider(map[string]interface{}{
		"aes_key": base64.StdEncoding.EncodeToString(testKEK()),
	})
	require.NoError(t, err)
	assert.Equal(t, testKEKFingerprint, provider.Fingerprint())

	ctx := context.Background()
	dek := bytes.Repeat([]byte{0x5A}, 32)
	wrapped, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	unwrapped, err := provider.DecryptDEK(ctx, wrapped)
	require.NoError(t, err)
	assert.Equal(t, dek, unwrapped)
}

// The raw-string fallback is gone (H-8): a 32-character passphrase is not a
// key, and it used to become one silently.
func TestAESProviderRejectsAnythingButBase64Of32Bytes(t *testing.T) {
	// A base64-wrapped hex string decodes to 32 bytes and is refused one layer
	// up, by the startup admission rules in the configuration package.
	cases := map[string]interface{}{
		"raw 32 byte ascii key":   "12345678901234567890123456789012",
		"base64 of 16 bytes":      base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"base64 of 64 bytes":      base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"not base64 at all":       "this is not base64 $$$",
		"empty":                   "",
		"wrong type":              42,
		"missing key is reported": nil,
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			config := map[string]interface{}{}
			if value != nil {
				config["aes_key"] = value
			}

			_, err := NewAESProvider(config)
			require.Error(t, err)
		})
	}
}
