package encryption_test

// The PUT path never measures the ciphertext it uploads. putObjectDirect sets
// input.ContentLength from ComputeCiphertextSize(len(plaintext), algorithm) and then hands
// the AWS SDK a reader, so the header and the body come from two independent sources. If
// the arithmetic and the encryptor ever disagree by a single byte, every upload on that
// path ships a wrong Content-Length and the backend stores a truncated or rejected object.
//
// These tests are the bridge between the two: they run the real data encryptors and assert
// the produced byte count equals what the arithmetic promised.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sizes spans the interesting boundaries: empty, one byte, the AES block size and either
// side of it, and a payload larger than any internal buffer.
var invariantSizes = []int{0, 1, 15, 16, 17, 31, 32, 33, 255, 4096, 65537}

func encryptAll(t *testing.T, enc encryption.DataEncryptor, plaintext []byte) []byte {
	t.Helper()
	ctx := context.Background()

	dek, err := enc.GenerateDEK(ctx)
	require.NoError(t, err)

	encReader, err := enc.EncryptStream(ctx, bufio.NewReader(bytes.NewReader(plaintext)), dek, nil)
	require.NoError(t, err)

	ciphertext, err := io.ReadAll(encReader)
	require.NoError(t, err)
	return ciphertext
}

// TestComputeCiphertextSizeMatchesTheRealEncryptors is the invariant the PUT path depends
// on. A failure here means Content-Length and the uploaded body disagree.
func TestComputeCiphertextSizeMatchesTheRealEncryptors(t *testing.T) {
	encryptors := map[string]encryption.DataEncryptor{
		"aes-gcm": dataencryption.NewAESGCMDataEncryptor(),
		"aes-ctr": dataencryption.NewAESCTRDataEncryptor(),
	}

	for algorithm, enc := range encryptors {
		t.Run(algorithm, func(t *testing.T) {
			require.Equal(t, algorithm, enc.Algorithm(),
				"the encryptor must report the algorithm name the arithmetic is keyed on")

			for _, size := range invariantSizes {
				plaintext := bytes.Repeat([]byte{0xA5}, size)
				ciphertext := encryptAll(t, enc, plaintext)

				predicted := encryption.ComputeCiphertextSize(int64(size), algorithm)
				assert.Equal(t, int64(len(ciphertext)), predicted,
					"ComputeCiphertextSize(%d, %q) must equal the bytes the encryptor produced",
					size, algorithm)

				// And the inverse has to bring us back, or HEAD reports a length GET does
				// not deliver.
				assert.Equal(t, int64(size), encryption.ComputePlaintextSize(predicted, algorithm),
					"ComputePlaintextSize must invert ComputeCiphertextSize at size %d", size)
			}
		})
	}
}

// TestGCMOverheadIsNonceAndTag pins the constant to the two things it is documented to be,
// so a change to either shows up here rather than as a wrong Content-Length in production.
func TestGCMOverheadIsNonceAndTag(t *testing.T) {
	const nonce, tag = 12, 16
	assert.Equal(t, int64(nonce+tag), encryption.GCMOverhead)

	enc := dataencryption.NewAESGCMDataEncryptor()
	empty := encryptAll(t, enc, nil)
	assert.Len(t, empty, nonce+tag,
		"an empty plaintext must encrypt to exactly the nonce plus the tag")
}

// TestComputeSizesRejectUnknownAlgorithms documents the -1 sentinel, and records the one
// asymmetry between the two functions: ComputePlaintextSize accepts the empty algorithm
// (objects stored before an algorithm was recorded) and ComputeCiphertextSize does not.
func TestComputeSizesRejectUnknownAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"aes-xts", "rot13", "AES-GCM", " aes-gcm"} {
		assert.Equal(t, int64(-1), encryption.ComputeCiphertextSize(100, algorithm),
			"unknown algorithm %q must not produce a length", algorithm)
		assert.Equal(t, int64(-1), encryption.ComputePlaintextSize(100, algorithm),
			"unknown algorithm %q must not produce a length", algorithm)
	}

	assert.Equal(t, int64(-1), encryption.ComputeCiphertextSize(100, ""),
		"the empty algorithm has no ciphertext size")
	assert.Equal(t, int64(100), encryption.ComputePlaintextSize(100, ""),
		"the empty algorithm is treated as stored-as-is on the read side")
}

// TestComputePlaintextSizeRejectsShortGCMObjects covers the guard that keeps a truncated or
// substituted GCM object from producing a negative Content-Length on HEAD.
func TestComputePlaintextSizeRejectsShortGCMObjects(t *testing.T) {
	for _, ciphertextSize := range []int64{0, 1, encryption.GCMOverhead - 1} {
		assert.Equal(t, int64(-1), encryption.ComputePlaintextSize(ciphertextSize, "aes-gcm"),
			"a GCM object shorter than the overhead cannot have a plaintext size")
	}
	assert.Equal(t, int64(0), encryption.ComputePlaintextSize(encryption.GCMOverhead, "aes-gcm"))
}

// TestPassthroughAlgorithmsAddNothing states the property the none provider and the CTR
// path both rely on: stored size equals plaintext size, in both directions.
func TestPassthroughAlgorithmsAddNothing(t *testing.T) {
	for _, algorithm := range []string{"aes-ctr", "none"} {
		for _, size := range invariantSizes {
			n := int64(size)
			assert.Equal(t, n, encryption.ComputeCiphertextSize(n, algorithm))
			assert.Equal(t, n, encryption.ComputePlaintextSize(n, algorithm))
		}
	}
}
