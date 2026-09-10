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
			wrapped, err := p.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)

			// The none provider is a deliberate pass-through: the DEK is stored
			// verbatim.
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(wrapped),
				"DEK must be stored unchanged (plaintext DEK at rest)")

			unwrapped, err := p.DecryptDEK(ctx, wrapped)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(unwrapped))
		})
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
}
