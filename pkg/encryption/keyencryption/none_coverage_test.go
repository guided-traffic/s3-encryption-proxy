package keyencryption

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKekNoneProviderPassThrough(t *testing.T) {
	p, err := NewNoneProvider(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
	ctx := context.Background()

	tests := []struct {
		name string
		dek  []byte
	}{
		{name: "nil dek", dek: nil},
		{name: "empty dek", dek: []byte{}},
		{name: "32 byte dek", dek: KekBytePattern(32)},
		{name: "large dek", dek: KekBytePattern(4096)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapped, keyID, err := p.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)

			// The none provider is a deliberate pass-through: the DEK is stored
			// verbatim and no key ID is emitted.
			assert.Empty(t, keyID, "none provider must not emit a key ID")
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(wrapped),
				"DEK must be stored unchanged (plaintext DEK at rest)")

			unwrapped, err := p.DecryptDEK(ctx, wrapped, keyID)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(unwrapped))
		})
	}
}

func TestKekNoneProviderIgnoresKeyID(t *testing.T) {
	p, err := NewNoneProvider(map[string]interface{}{"irrelevant": "value"})
	require.NoError(t, err)
	ctx := context.Background()
	dek := KekBytePattern(32)

	for _, keyID := range []string{"", "none-provider-fingerprint", "some-other-provider", p.Fingerprint()} {
		out, err := p.DecryptDEK(ctx, dek, keyID)
		require.NoError(t, err, "none provider accepts any key ID")
		assert.Equal(t, dek, out)
	}
}

func TestKekNoneProviderIdentity(t *testing.T) {
	first, err := NewNoneProvider(nil)
	require.NoError(t, err)
	second, err := NewNoneProvider(map[string]interface{}{})
	require.NoError(t, err)

	assert.Equal(t, "none", first.Name())
	assert.Equal(t, "none-provider-fingerprint", first.Fingerprint())
	assert.Equal(t, first.Fingerprint(), second.Fingerprint(), "fingerprint must be stable across instances")

	// It must not collide with a real KEK provider fingerprint.
	aesProvider := KekNewAES(t, KekAESKeyA)
	assert.NotEqual(t, aesProvider.Fingerprint(), first.Fingerprint())

	require.NoError(t, first.RotateKEK(context.Background()), "rotation is a no-op for the none provider")
}
