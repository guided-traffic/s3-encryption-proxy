package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DekBoomError is the sentinel error returned by DekfailingReader. It is a
// comparable struct type so errors.Is matches it through fmt.Errorf wrapping.
type DekBoomError struct{}

func (DekBoomError) Error() string { return "dek-test: read failed" }

// DekfailingReader fails after handing out okBytes bytes of data.
type DekfailingReader struct {
	okBytes int
}

func (r *DekfailingReader) Read(p []byte) (int, error) {
	if r.okBytes <= 0 {
		return 0, DekBoomError{}
	}
	n := len(p)
	if n > r.okBytes {
		n = r.okBytes
	}
	for i := 0; i < n; i++ {
		p[i] = 0x41
	}
	r.okBytes -= n
	return n, nil
}

// DekbufReader wraps a byte slice in a *bufio.Reader.
func DekbufReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

// Deksum returns the hex SHA256 digest, so large buffers are compared by digest
// instead of by dumping their contents.
func Deksum(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// DekrandomBytes returns n cryptographically random bytes.
func DekrandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// DekbreakRandReader replaces crypto/rand.Reader with a reader that always
// fails, so the "entropy source unavailable" branches become reachable. The
// original reader is restored when the test ends.
func DekbreakRandReader(t *testing.T) {
	t.Helper()
	original := rand.Reader
	rand.Reader = &DekfailingReader{}
	t.Cleanup(func() { rand.Reader = original })
}

// DekencryptCTR runs a full encrypt pass and returns the ciphertext plus the IV
// recorded for the object metadata.
func DekencryptCTR(t *testing.T, plaintext, dek []byte) (ciphertext, iv []byte) {
	t.Helper()
	enc := NewAESCTRDataEncryptor()
	r, err := enc.EncryptStream(context.Background(), DekbufReader(plaintext), dek, nil)
	require.NoError(t, err)
	ciphertext, err = io.ReadAll(r)
	require.NoError(t, err)
	iv = enc.(*AESCTRDataEncryptor).GetLastIV()
	return ciphertext, iv
}

func TestDekAESCTRRoundTripSizes(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)

	sizes := []int{0, 1, 15, 16, 17, 4095, 4096, 1 << 20}
	for _, size := range sizes {
		t.Run(Deksize(size), func(t *testing.T) {
			plaintext := DekrandomBytes(t, size)
			ciphertext, iv := DekencryptCTR(t, plaintext, dek)

			// AES-CTR is length preserving: no padding, no header.
			assert.Len(t, ciphertext, size, "AES-CTR must not change the length")
			assert.Len(t, iv, aes.BlockSize)

			if size > 0 {
				assert.NotEqual(t, Deksum(plaintext), Deksum(ciphertext),
					"ciphertext must differ from plaintext")
			}

			dec := NewAESCTRDataEncryptor()
			plainReader, err := dec.DecryptStream(ctx, DekbufReader(ciphertext), dek, iv, nil)
			require.NoError(t, err)
			got, err := io.ReadAll(plainReader)
			require.NoError(t, err)
			assert.Equal(t, Deksum(plaintext), Deksum(got))
		})
	}
}

// Deksize renders a size as a subtest name.
func Deksize(n int) string {
	return "size_" + Dekitoa(n)
}

func Dekitoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Two encryptions of the same plaintext must not produce the same ciphertext:
// the IV is fresh per object. A repeated IV under the same DEK would leak the
// XOR of both plaintexts.
func TestDekAESCTRFreshIVPerEncryption(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	plaintext := []byte("the same plaintext, encrypted twice")

	ct1, iv1 := DekencryptCTR(t, plaintext, dek)
	ct2, iv2 := DekencryptCTR(t, plaintext, dek)

	assert.NotEqual(t, hex.EncodeToString(iv1), hex.EncodeToString(iv2), "IV must be fresh per encryption")
	assert.NotEqual(t, Deksum(ct1), Deksum(ct2), "identical plaintext must not yield identical ciphertext")
}

// AES-CTR is unauthenticated: a wrong DEK or IV yields garbage rather than an
// error. This pins that property so nobody mistakes CTR for integrity
// protection - integrity comes from the separate HMAC layer.
func TestDekAESCTRWrongKeyOrIVYieldsGarbageWithoutError(t *testing.T) {
	ctx := context.Background()
	dek := DekrandomBytes(t, 32)
	plaintext := DekrandomBytes(t, 8192)
	ciphertext, iv := DekencryptCTR(t, plaintext, dek)

	t.Run("wrong_dek", func(t *testing.T) {
		wrongDEK := DekrandomBytes(t, 32)
		dec := NewAESCTRDataEncryptor()
		r, err := dec.DecryptStream(ctx, DekbufReader(ciphertext), wrongDEK, iv, nil)
		require.NoError(t, err, "AES-CTR cannot detect a wrong key")
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Len(t, got, len(plaintext))
		assert.NotEqual(t, Deksum(plaintext), Deksum(got))
	})

	t.Run("wrong_iv", func(t *testing.T) {
		wrongIV := DekrandomBytes(t, aes.BlockSize)
		dec := NewAESCTRDataEncryptor()
		r, err := dec.DecryptStream(ctx, DekbufReader(ciphertext), dek, wrongIV, nil)
		require.NoError(t, err, "AES-CTR cannot detect a wrong IV")
		got, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.NotEqual(t, Deksum(plaintext), Deksum(got))
	})
}

func TestDekAESCTREncryptStreamRejectsBadDEK(t *testing.T) {
	ctx := context.Background()
	enc := NewAESCTRDataEncryptor()

	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		t.Run(Deksize(size), func(t *testing.T) {
			r, err := enc.EncryptStream(ctx, DekbufReader([]byte("data")), make([]byte, size), nil)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "invalid DEK size")
		})
	}
}

func TestDekAESCTRDecryptStreamValidation(t *testing.T) {
	ctx := context.Background()
	dec := NewAESCTRDataEncryptor()
	goodDEK := DekrandomBytes(t, 32)
	goodIV := DekrandomBytes(t, aes.BlockSize)

	t.Run("bad_dek", func(t *testing.T) {
		r, err := dec.DecryptStream(ctx, DekbufReader(nil), make([]byte, 16), goodIV, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "invalid DEK size")
	})

	for _, size := range []int{0, 1, 8, 15, 17, 32} {
		t.Run("bad_iv_"+Dekitoa(size), func(t *testing.T) {
			r, err := dec.DecryptStream(ctx, DekbufReader(nil), goodDEK, make([]byte, size), nil)
			require.Error(t, err)
			assert.Nil(t, r)
			assert.Contains(t, err.Error(), "invalid IV size")
		})
	}

	t.Run("nil_iv_is_rejected", func(t *testing.T) {
		r, err := dec.DecryptStream(ctx, DekbufReader(nil), goodDEK, nil, nil)
		require.Error(t, err)
		assert.Nil(t, r)
		assert.Contains(t, err.Error(), "invalid IV size")
	})
}

func TestDekAESCTRGetLastIV(t *testing.T) {
	ctx := context.Background()
	enc := NewAESCTRDataEncryptor().(*AESCTRDataEncryptor)

	assert.Nil(t, enc.GetLastIV(), "no IV before the first encryption")

	_, err := enc.EncryptStream(ctx, DekbufReader([]byte("payload")), DekrandomBytes(t, 32), nil)
	require.NoError(t, err)

	iv := enc.GetLastIV()
	require.Len(t, iv, aes.BlockSize)

	// The caller must not be able to corrupt the stored IV: the metadata written
	// to S3 has to stay exactly what the keystream was built from.
	original := append([]byte(nil), iv...)
	for i := range iv {
		iv[i] ^= 0xff
	}
	assert.Equal(t, hex.EncodeToString(original), hex.EncodeToString(enc.GetLastIV()),
		"GetLastIV must return a defensive copy")
}

func TestDekAESCTRGenerateDEK(t *testing.T) {
	ctx := context.Background()
	enc := NewAESCTRDataEncryptor()

	dek, err := enc.GenerateDEK(ctx)
	require.NoError(t, err)
	assert.Len(t, dek, 32)

	other, err := enc.GenerateDEK(ctx)
	require.NoError(t, err)
	assert.NotEqual(t, hex.EncodeToString(dek), hex.EncodeToString(other))
}

// The generated DEK must never silently fall back to a zero key when the
// entropy source fails.
func TestDekAESCTRGenerateDEKEntropyFailure(t *testing.T) {
	DekbreakRandReader(t)

	dek, err := NewAESCTRDataEncryptor().GenerateDEK(context.Background())
	require.Error(t, err)
	assert.Nil(t, dek)
	assert.Contains(t, err.Error(), "failed to generate DEK")
}

// Likewise the IV: no entropy means no encryption, never a predictable IV.
func TestDekAESCTREncryptStreamEntropyFailure(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	DekbreakRandReader(t)

	r, err := NewAESCTRDataEncryptor().EncryptStream(context.Background(), DekbufReader([]byte("x")), dek, nil)
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "failed to generate IV")
}

// A failure of the source stream must surface to the reader of the encrypted
// stream instead of being reported as a short but successful object.
func TestDekAESCTRStreamPropagatesSourceError(t *testing.T) {
	dek := DekrandomBytes(t, 32)

	enc := NewAESCTRDataEncryptor()
	encReader, err := enc.EncryptStream(context.Background(),
		bufio.NewReader(&DekfailingReader{okBytes: 100}), dek, nil)
	require.NoError(t, err)

	got, err := io.ReadAll(encReader)
	require.Error(t, err)
	assert.ErrorIs(t, err, DekBoomError{})
	assert.Len(t, got, 100, "the bytes read before the failure are still encrypted and returned")
}

func TestDekAESCTRStatefulEncryptorRoundTrip(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	plaintext := DekrandomBytes(t, 300_000)
	plainDigest := Deksum(plaintext)

	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.NoError(t, err)
	assert.Equal(t, "aes-ctr", enc.Algorithm())

	iv := enc.GetIV()
	require.Len(t, iv, aes.BlockSize)

	// Encrypt in irregular chunks, mimicking multipart part sizes.
	chunkSizes := []int{1, 15, 16, 17, 4096, 100_000}
	var ciphertext []byte
	offset := 0
	for offset < len(plaintext) {
		size := chunkSizes[offset%len(chunkSizes)]
		if offset+size > len(plaintext) {
			size = len(plaintext) - offset
		}
		part := append([]byte(nil), plaintext[offset:offset+size]...)
		out, encErr := enc.EncryptPart(part)
		require.NoError(t, encErr)
		ciphertext = append(ciphertext, out...)
		offset += size
	}
	require.Len(t, ciphertext, len(plaintext))
	assert.NotEqual(t, plainDigest, Deksum(ciphertext))

	// The chunk boundaries must not be visible in the ciphertext: a single-shot
	// encryption with the same DEK and IV has to produce the identical bytes.
	single, err := NewAESCTRStatefulEncryptorWithIV(dek, iv)
	require.NoError(t, err)
	oneShot, err := single.EncryptPart(append([]byte(nil), plaintext...))
	require.NoError(t, err)
	assert.Equal(t, Deksum(ciphertext), Deksum(oneShot),
		"chunked encryption must equal single-shot encryption")

	// And the stateless streaming decryptor must understand it.
	streamDec := NewAESCTRDataEncryptor()
	r, err := streamDec.DecryptStream(context.Background(), DekbufReader(ciphertext), dek, iv, nil)
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plainDigest, Deksum(got))

	// As must the stateful decryptor, chunk by chunk.
	dec, err := NewAESCTRStatefulEncryptorWithIV(dek, iv)
	require.NoError(t, err)
	var recovered []byte
	offset = 0
	for offset < len(ciphertext) {
		size := 7777
		if offset+size > len(ciphertext) {
			size = len(ciphertext) - offset
		}
		part := append([]byte(nil), ciphertext[offset:offset+size]...)
		out, decErr := dec.DecryptPart(part)
		require.NoError(t, decErr)
		recovered = append(recovered, out...)
		offset += size
	}
	assert.Equal(t, plainDigest, Deksum(recovered))
	dec.Cleanup()
	single.Cleanup()
	enc.Cleanup()
}

// EncryptPart and DecryptPart work in place and hand back the same slice; a
// caller that keeps the original slice must expect it to be overwritten.
func TestDekAESCTRStatefulEncryptPartIsInPlace(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.NoError(t, err)
	defer enc.Cleanup()

	buf := []byte("plaintext that will be overwritten")
	before := Deksum(buf)

	out, err := enc.EncryptPart(buf)
	require.NoError(t, err)
	assert.Equal(t, Deksum(buf), Deksum(out), "the returned slice is the caller's buffer")
	assert.NotEqual(t, before, Deksum(buf), "the caller's buffer was encrypted in place")
	require.Len(t, out, len(buf))
	assert.True(t, &buf[0] == &out[0], "no copy is made")
}

func TestDekAESCTRStatefulEncryptorEmptyPart(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.NoError(t, err)
	defer enc.Cleanup()

	out, err := enc.EncryptPart([]byte{})
	require.NoError(t, err)
	assert.Empty(t, out)

	out, err = enc.DecryptPart(nil)
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestDekAESCTRStatefulGetIVReturnsCopy(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.NoError(t, err)
	defer enc.Cleanup()

	iv := enc.GetIV()
	original := hex.EncodeToString(iv)
	for i := range iv {
		iv[i] ^= 0xff
	}
	assert.Equal(t, original, hex.EncodeToString(enc.GetIV()), "GetIV must return a defensive copy")
}

func TestDekAESCTRStatefulConstructorValidation(t *testing.T) {
	goodDEK := DekrandomBytes(t, 32)
	goodIV := DekrandomBytes(t, aes.BlockSize)

	t.Run("stateful_bad_dek", func(t *testing.T) {
		for _, size := range []int{0, 16, 24, 31, 33} {
			enc, err := NewAESCTRStatefulEncryptor(make([]byte, size))
			require.Error(t, err)
			assert.Nil(t, enc)
			assert.Contains(t, err.Error(), "invalid DEK size")
		}
	})

	t.Run("with_iv_bad_dek", func(t *testing.T) {
		enc, err := NewAESCTRStatefulEncryptorWithIV(make([]byte, 16), goodIV)
		require.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "invalid DEK size")
	})

	t.Run("with_iv_bad_iv", func(t *testing.T) {
		for _, size := range []int{0, 8, 15, 17, 32} {
			enc, err := NewAESCTRStatefulEncryptorWithIV(goodDEK, make([]byte, size))
			require.Error(t, err)
			assert.Nil(t, enc)
			assert.Contains(t, err.Error(), "invalid IV size")
		}
	})

	t.Run("with_iv_nil_iv", func(t *testing.T) {
		enc, err := NewAESCTRStatefulEncryptorWithIV(goodDEK, nil)
		require.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "invalid IV size")
	})
}

func TestDekAESCTRStatefulEncryptorEntropyFailure(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	DekbreakRandReader(t)

	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.Error(t, err)
	assert.Nil(t, enc)
	assert.Contains(t, err.Error(), "failed to generate IV")
}

// Cleanup must wipe the key material it copied and must be safe to call twice
// (complete and abort can both reach it).
func TestDekAESCTRStatefulCleanupWipesKeyMaterial(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	dekCopy := append([]byte(nil), dek...)

	enc, err := NewAESCTRStatefulEncryptor(dek)
	require.NoError(t, err)
	require.NotEmpty(t, enc.GetIV())

	enc.Cleanup()

	assert.Empty(t, enc.GetIV(), "IV must be gone after Cleanup")
	assert.Nil(t, enc.dek, "DEK must be gone after Cleanup")
	assert.Nil(t, enc.stream)
	assert.Equal(t, "aes-ctr", enc.Algorithm(), "Algorithm stays available after Cleanup")

	// The caller's DEK is untouched: the encryptor wiped its own copy.
	assert.Equal(t, hex.EncodeToString(dekCopy), hex.EncodeToString(dek))

	assert.NotPanics(t, func() { enc.Cleanup() }, "Cleanup must be idempotent")
}

func TestDekNewCTRRangeReaderRejectsBadKeyMaterial(t *testing.T) {
	r, err := NewCTRRangeReader(bytes.NewReader([]byte("ciphertext")), make([]byte, 16), make([]byte, aes.BlockSize), 0)
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "invalid DEK size")

	r, err = NewCTRRangeReader(bytes.NewReader([]byte("ciphertext")), make([]byte, 32), make([]byte, 8), 0)
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "invalid IV size")

	r, err = NewCTRRangeReader(bytes.NewReader([]byte("ciphertext")), make([]byte, 32), make([]byte, aes.BlockSize), -1)
	require.Error(t, err)
	assert.Nil(t, r)
	assert.Contains(t, err.Error(), "negative offset")
}

// A range read beyond the end of the object yields nothing, not an error.
func TestDekNewCTRRangeReaderPastEndOfObject(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	plaintext := DekrandomBytes(t, 64)
	ciphertext, iv := DekencryptCTR(t, plaintext, dek)

	r, err := NewCTRRangeReader(bytes.NewReader(ciphertext[len(ciphertext):]), dek, iv, int64(len(plaintext)))
	require.NoError(t, err)
	got, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// The seekable keystream and the sequential stateful encryptor must agree:
// both are used against the same stored objects.
func TestDekCTRStreamAtMatchesStatefulEncryptor(t *testing.T) {
	dek := DekrandomBytes(t, 32)
	iv := DekrandomBytes(t, aes.BlockSize)
	plaintext := DekrandomBytes(t, 5000)

	enc, err := NewAESCTRStatefulEncryptorWithIV(dek, iv)
	require.NoError(t, err)
	defer enc.Cleanup()
	ciphertext, err := enc.EncryptPart(append([]byte(nil), plaintext...))
	require.NoError(t, err)

	const offset = 1234
	stream, err := NewCTRStreamAt(dek, iv, offset)
	require.NoError(t, err)
	got := append([]byte(nil), ciphertext[offset:]...)
	stream.XORKeyStream(got, got)
	assert.Equal(t, Deksum(plaintext[offset:]), Deksum(got))
}

func TestDekCalculateStreamingSHA256(t *testing.T) {
	t.Run("known_value", func(t *testing.T) {
		got, err := calculateStreamingSHA256(bytes.NewReader([]byte("abc")))
		require.NoError(t, err)
		assert.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", got)
	})

	t.Run("empty", func(t *testing.T) {
		got, err := calculateStreamingSHA256(bytes.NewReader(nil))
		require.NoError(t, err)
		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", got)
	})

	t.Run("read_error", func(t *testing.T) {
		got, err := calculateStreamingSHA256(&DekfailingReader{})
		require.Error(t, err)
		assert.ErrorIs(t, err, DekBoomError{})
		assert.Empty(t, got)
	})
}
