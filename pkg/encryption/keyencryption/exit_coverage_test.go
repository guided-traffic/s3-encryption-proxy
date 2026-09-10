package keyencryption

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exit provider holds no key material: it stores plaintext on write, and on
// read the object's own fingerprint names the provider that wrapped its data
// key. So both key operations are errors, not pass-throughs.
func TestKekExitProviderRefusesEveryKeyUse(t *testing.T) {
	p, err := NewExitProvider(nil)
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
			require.ErrorIs(t, err, ErrExitProviderKeyUse)
			assert.Nil(t, wrapped, "no key material may leave this provider")

			// A pass-through unwrap here would be the forgery: a backend that
			// labelled an object with this fingerprint would be handing the proxy
			// a data key of its own choosing.
			unwrapped, err := p.DecryptDEK(ctx, tc.dek)
			require.ErrorIs(t, err, ErrExitProviderKeyUse)
			assert.Nil(t, unwrapped)
		})
	}
}

func TestKekExitProviderIdentity(t *testing.T) {
	first, err := NewExitProvider(nil)
	require.NoError(t, err)
	second, err := NewExitProvider(map[string]interface{}{})
	require.NoError(t, err)

	assert.Equal(t, "exit", first.Name())
	assert.Equal(t, "exit-provider-fingerprint", first.Fingerprint())
	assert.Equal(t, first.Fingerprint(), second.Fingerprint(), "fingerprint must be stable across instances")

	// It must not collide with a real KEK provider fingerprint.
	aesProvider := KekNewAES(t, KekAESKeyA)
	assert.NotEqual(t, aesProvider.Fingerprint(), first.Fingerprint())
}
