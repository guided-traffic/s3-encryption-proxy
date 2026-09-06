package dataencryption

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DekgcmNonceSize is the nonce length used by the standard AES-GCM mode.
const DekgcmNonceSize = 12

// DekgcmTagSize is the length of the GCM authentication tag.
const DekgcmTagSize = 16

// DekencryptGCM encrypts plaintext and returns the stored blob together with
// the nonce the encryptor recorded for the object metadata.
func DekencryptGCM(t *testing.T, plaintext, dek, aad []byte) (blob, nonce []byte) {
	t.Helper()
	enc := NewAESGCMDataEncryptor()
	r, err := enc.EncryptStream(context.Background(), DekbufReader(plaintext), dek, aad)
	require.NoError(t, err)
	blob, err = io.ReadAll(r)
	require.NoError(t, err)
	nonce = enc.(*AESGCMDataEncryptor).GetLastIV()
	return blob, nonce
}

func TestDekAESGCMRoundTripSizes(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)
	aad := []byte("bucket/object-key")

	for _, size := range []int{0, 1, 15, 16, 17, 4096, 1 << 20} {
		t.Run(Deksize(size), func(t *testing.T) {
			plaintext := DekrandomBytes(t, size)
			blob, nonce := DekencryptGCM(t, plaintext, dek, aad)

			// The stored blob is nonce || ciphertext || tag.
			assert.Len(t, blob, size+DekgcmNonceSize+DekgcmTagSize)
			assert.Len(t, nonce, DekgcmNonceSize)
			assert.Equal(t, hex.EncodeToString(nonce), hex.EncodeToString(blob[:DekgcmNonceSize]),
				"the recorded nonce must be the one prepended to the ciphertext")
			if size > 0 {
				assert.NotEqual(t, Deksum(plaintext), Deksum(blob[DekgcmNonceSize:len(blob)-DekgcmTagSize]),
					"ciphertext must differ from plaintext")
			}

			dec := NewAESGCMDataEncryptor()
			r, err := dec.DecryptStream(ctx, DekbufReader(blob), dek, nil, aad)
			require.NoError(t, err)
			got, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, Deksum(plaintext), Deksum(got))
		})
	}
}

// A fresh nonce per object is what keeps GCM safe; a repeat under the same DEK
// is catastrophic, so this must never produce identical output.
func TestDekAESGCMFreshNoncePerEncryption(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	plaintext := []byte("identical plaintext")

	blob1, nonce1 := DekencryptGCM(t, plaintext, dek, nil)
	blob2, nonce2 := DekencryptGCM(t, plaintext, dek, nil)

	assert.NotEqual(t, hex.EncodeToString(nonce1), hex.EncodeToString(nonce2))
	assert.NotEqual(t, Deksum(blob1), Deksum(blob2))
}

// Tampering with any part of the stored blob must abort the download rather
// than serve modified bytes.
func TestDekAESGCMDetectsTampering(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)
	aad := []byte("bucket/object-key")
	plaintext := DekrandomBytes(t, 2048)
	blob, _ := DekencryptGCM(t, plaintext, dek, aad)

	cases := map[string]func(b []byte) []byte{
		"flip_bit_in_nonce":      func(b []byte) []byte { b[0] ^= 0x01; return b },
		"flip_bit_in_ciphertext": func(b []byte) []byte { b[DekgcmNonceSize+10] ^= 0x01; return b },
		"flip_bit_in_last_byte":  func(b []byte) []byte { b[len(b)-DekgcmTagSize-1] ^= 0x80; return b },
		"flip_bit_in_tag":        func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b },
		"truncate_one_byte":      func(b []byte) []byte { return b[:len(b)-1] },
		"append_one_byte":        func(b []byte) []byte { return append(b, 0x00) },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			corrupted := mutate(append([]byte(nil), blob...))
			r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(corrupted), dek, nil, aad)
			require.Error(t, err, "tampered data must not decrypt")
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "failed to decrypt data")
		})
	}
}

func TestDekAESGCMWrongKeyAndWrongAssociatedData(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)
	aad := []byte("bucket/object-key")
	plaintext := DekrandomBytes(t, 512)
	blob, _ := DekencryptGCM(t, plaintext, dek, aad)

	t.Run("wrong_dek", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), DekrandomBytes(t, 32), nil, aad)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	// The object key is bound in as associated data, so a blob moved to another
	// key must not decrypt.
	t.Run("wrong_associated_data", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), dek, nil, []byte("bucket/other-key"))
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("missing_associated_data", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), dek, nil, nil)
		require.Error(t, err)
		assert.Nil(t, r)
	})
}

// The explicit-nonce branch expects the nonce to have been stripped from the
// blob already. This documents the exact contract of the iv parameter.
func TestDekAESGCMExplicitNonceBranch(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)
	aad := []byte("bucket/object-key")
	plaintext := DekrandomBytes(t, 1024)
	blob, nonce := DekencryptGCM(t, plaintext, dek, aad)

	t.Run("nonce_with_stripped_blob_succeeds", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob[DekgcmNonceSize:]), dek, nonce, aad)
		require.NoError(t, err)
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, Deksum(plaintext), Deksum(got))
	})

	// DEFECT (reported, not fixed here): the encryptor also publishes this nonce
	// as aes-iv metadata while prepending it to the blob. Feeding both back in -
	// the obvious reading of the API - fails authentication.
	t.Run("nonce_with_full_blob_fails", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), dek, nonce, aad)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})

	t.Run("wrong_nonce_length", func(t *testing.T) {
		for _, size := range []int{1, 11, 13, 16, 32} {
			r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), dek, make([]byte, size), aad)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "invalid nonce size")
		}
	})

	// A zero-length IV is not nil, so it takes the explicit branch and is
	// rejected on length rather than silently falling back to extraction.
	t.Run("empty_non_nil_nonce", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(blob), dek, []byte{}, aad)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "invalid nonce size")
	})
}

func TestDekAESGCMShortEncryptedData(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)

	t.Run("shorter_than_nonce", func(t *testing.T) {
		for _, size := range []int{0, 1, 11} {
			r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(make([]byte, size)), dek, nil, nil)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "encrypted data too short")
		}
	})

	// Nonce present but no tag: the length check passes and GCM rejects it.
	t.Run("nonce_only", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader(make([]byte, DekgcmNonceSize)), dek, nil, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to decrypt data")
	})
}

func TestDekAESGCMRejectsBadDEK(t *testing.T) {
	ctx := context.Background()

	for _, size := range []int{0, 1, 16, 24, 31, 33} {
		t.Run("encrypt_"+Dekitoa(size), func(t *testing.T) {
			r, err := NewAESGCMDataEncryptor().EncryptStream(ctx, DekbufReader([]byte("data")), make([]byte, size), nil)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "invalid DEK size")
		})
		t.Run("decrypt_"+Dekitoa(size), func(t *testing.T) {
			r, err := NewAESGCMDataEncryptor().DecryptStream(ctx, DekbufReader([]byte("data")), make([]byte, size), nil, nil)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "invalid DEK size")
		})
	}
}

func TestDekAESGCMGetLastIV(t *testing.T) {
	enc := NewAESGCMDataEncryptor().(*AESGCMDataEncryptor)
	assert.Nil(t, enc.GetLastIV(), "no nonce before the first encryption")

	_, err := enc.EncryptStream(context.Background(), DekbufReader([]byte("payload")), DekrandomBytes(t, 32), nil)
	require.NoError(t, err)
	first := enc.GetLastIV()
	require.Len(t, first, DekgcmNonceSize)

	// A second encryption replaces the recorded nonce.
	_, err = enc.EncryptStream(context.Background(), DekbufReader([]byte("payload")), DekrandomBytes(t, 32), nil)
	require.NoError(t, err)
	second := enc.GetLastIV()
	require.Len(t, second, DekgcmNonceSize)
	assert.NotEqual(t, hex.EncodeToString(first), hex.EncodeToString(second))
}

func TestDekAESGCMGenerateDEK(t *testing.T) {
	ctx := context.Background()
	enc := NewAESGCMDataEncryptor()

	dek, err := enc.GenerateDEK(ctx)
	require.NoError(t, err)
	require.Len(t, dek, 32)

	// The generated key must actually work end to end.
	plaintext := []byte("round trip with a generated DEK")
	blob, _ := DekencryptGCM(t, plaintext, dek, nil)
	r, err := enc.DecryptStream(ctx, DekbufReader(blob), dek, nil, nil)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, Deksum(plaintext), Deksum(got))
}

func TestDekAESGCMEntropyFailures(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	DekbreakRandReader(t)
	ctx := context.Background()

	t.Run("generate_dek", func(t *testing.T) {
		got, err := NewAESGCMDataEncryptor().GenerateDEK(ctx)
		require.Error(t, err)
		assert.Nil(t, got)
		assert.Contains(t, err.Error(), "failed to generate DEK")
	})

	t.Run("nonce", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().EncryptStream(ctx, DekbufReader([]byte("x")), dek, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "failed to generate nonce")
	})
}

// GCM buffers the whole object, so a source failure is detected before anything
// is handed back - the caller must never receive a truncated "successful" blob.
func TestDekAESGCMSourceReadErrors(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)

	t.Run("encrypt", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().EncryptStream(ctx,
			bufio.NewReader(&DekfailingReader{okBytes: 64}), dek, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.ErrorIs(t, err, DekBoomError{})
		assert.Contains(t, err.Error(), "failed to read data for GCM encryption")
	})

	t.Run("decrypt", func(t *testing.T) {
		r, err := NewAESGCMDataEncryptor().DecryptStream(ctx,
			bufio.NewReader(&DekfailingReader{okBytes: 64}), dek, nil, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.ErrorIs(t, err, DekBoomError{})
		assert.Contains(t, err.Error(), "failed to read encrypted data for GCM decryption")
	})
}

func TestDekAESGCMAlgorithmAndInterface(t *testing.T) {
	enc := NewAESGCMDataEncryptor()
	assert.Equal(t, "aes-gcm", enc.Algorithm())

	_, ok := enc.(interface{ GetLastIV() []byte })
	assert.True(t, ok, "AESGCMDataEncryptor must expose the nonce for metadata")
}

// Guard against the encryptor ever being used without a working entropy source
// producing a predictable nonce: two encryptors on the same DEK must not
// collide.
func TestDekAESGCMDistinctEncryptorsDoNotCollide(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	plaintext := DekrandomBytes(t, 256)

	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		blob, nonce := DekencryptGCM(t, plaintext, dek, nil)
		key := hex.EncodeToString(nonce)
		require.False(t, seen[key], "nonce reuse under the same DEK")
		seen[key] = true
		require.Len(t, blob, len(plaintext)+DekgcmNonceSize+DekgcmTagSize)
	}
	require.NotNil(t, rand.Reader)
}
