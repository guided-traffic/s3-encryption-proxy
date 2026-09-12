package keyencryption

// Known-answer vectors for the AES key wrap.
//
// THESE CONSTANTS DESCRIBE KEY MATERIAL THAT IS ALREADY STORED. They were
// captured once and are never regenerated. The derivation labels below are what
// every stored object's wrapped data key was sealed under, so changing one makes
// every object written before the change unopenable - with no converter and no
// way back (ADR 0017 D3, D10).
//
// Nothing else pinned them: the round-trip tests wrap and unwrap in one process,
// which agrees with itself under any label, and neither string appeared in a
// single test file. These vectors only ever OPEN captured bytes, because the
// wrap draws a fresh salt and a fresh nonce and cannot be recomputed.
//
// The key and the data key are test-only literals that appear nowhere else in
// the tree, so neither can be copied out of here into a configuration
// (ADR 0021). They are readable ASCII on purpose: they announce what they are.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	aesVecKEK     = "d3JhcC12ZWN0b3ItS0VLLW5vdC1mb3ItdXNlISEhISE="
	aesVecDEK     = "d3JhcC12ZWN0b3ItREVLLW5vdC1mb3ItdXNlISEhISE="
	aesVecWrapped = "BO32yCUI0iPWmp6VoTdj8rC0tXQyQH7SlgQ9dgKXOyhprtVYhTSZu0NUuJKRHYV9OO2YbMqYVMrINm1i8zHc0LsMwv9tgjK3RFR/8Q=="

	// What "s3ep-kek-fingerprint" expands to for that key. It is the value a
	// stored object names, so a provider that derives it differently stops
	// finding its own objects.
	aesVecFingerprint = "d3df3fd93981e66cca3bc3a0da3b3976943b1b5d31f41c654d05e81d3cda9d09"
)

func aesVecProvider(t *testing.T) *AESProvider {
	t.Helper()
	kek, err := base64.StdEncoding.DecodeString(aesVecKEK)
	require.NoError(t, err)
	p, err := NewAESKeyEncryptor(kek)
	require.NoError(t, err)
	return p.(*AESProvider)
}

// The wrap derivation is fixed: "s3ep-kek-wrap-v1" expands the wrapping key and
// "s3ep-dek-wrap-v1" is the associated data (ADR 0004 D7). Change either and this
// captured wrap stops opening - which is exactly what would happen to every
// object already at a backend.
func TestAesVectorWrappedKeyStillOpens(t *testing.T) {
	wrapped, err := base64.StdEncoding.DecodeString(aesVecWrapped)
	require.NoError(t, err)

	dek, err := aesVecProvider(t).DecryptDEK(context.Background(), wrapped)
	require.NoError(t, err,
		"a wrap captured from the shipped build no longer opens: the derivation changed, "+
			"and every stored object's data key changed with it (ADR 0017 D3)")
	assert.Equal(t, aesVecDEK, base64.StdEncoding.EncodeToString(dek))
}

// The fingerprint is the other derivation from the same master key, under its
// own label, and it is what a stored object names its provider by.
func TestAesVectorFingerprintIsStable(t *testing.T) {
	assert.Equal(t, aesVecFingerprint, aesVecProvider(t).Fingerprint(),
		"the fingerprint derivation changed: stored objects name the old value and "+
			"no loaded provider answers to it")
}

// The associated data is what keeps a wrap from being replayed as something
// else. A wrap whose ciphertext is intact but whose salt was taken from another
// wrap must not open.
func TestAesVectorWrapIsBoundToItsSalt(t *testing.T) {
	wrapped, err := base64.StdEncoding.DecodeString(aesVecWrapped)
	require.NoError(t, err)

	tampered := append([]byte{}, wrapped...)
	tampered[0] ^= 0xff // one bit of the salt: a different wrapping key

	_, err = aesVecProvider(t).DecryptDEK(context.Background(), tampered)
	assert.ErrorIs(t, err, ErrWrappedDEKAuth)
}
