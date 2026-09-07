package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// OrcStrNewManager builds a Manager and shuts it down with the test so no
// background goroutine outlives it.
func OrcStrNewManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, m.Shutdown(ctx))
	})
	return m
}

// OrcStrEncryptCTR runs the streaming (AES-CTR) encryption path and returns the
// stored ciphertext together with the metadata the object would carry in S3.
func OrcStrEncryptCTR(t *testing.T, m *Manager, plaintext []byte, objectKey string) ([]byte, map[string]string) {
	t.Helper()
	res, err := m.EncryptData(context.Background(),
		bufio.NewReader(bytes.NewReader(plaintext)), objectKey)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(res.EncryptedDataReader)
	require.NoError(t, err)
	require.Len(t, ciphertext, len(plaintext))
	if len(plaintext) > 0 {
		require.NotEqual(t, OrcStrSHA256(plaintext), OrcStrSHA256(ciphertext),
			"the backend must never see the plaintext")
	}
	require.Equal(t, "aes-ctr", res.Metadata["s3ep-dek-algorithm"])
	return ciphertext, res.Metadata
}

// TestOrcStrRangeReadUnsupportedErrorMessage pins the error text callers match on.
func TestOrcStrRangeReadUnsupportedErrorMessage(t *testing.T) {
	err := &RangeReadUnsupportedError{Algorithm: "aes-gcm"}
	assert.Equal(t, `ranged decryption is not possible for algorithm "aes-gcm"`, err.Error())

	empty := &RangeReadUnsupportedError{}
	assert.Equal(t, `ranged decryption is not possible for algorithm ""`, empty.Error())
}

// TestOrcStrSupportsRangeDecryption pins which stored objects can be served
// from an offset without downloading everything before it.
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcStrSupportsRangeDecryption(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationStrict))

	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     bool
	}{
		{"aes-ctr is seekable", map[string]string{"s3ep-dek-algorithm": "aes-ctr"}, true},
		{"aes-gcm is not", map[string]string{"s3ep-dek-algorithm": "aes-gcm"}, false},
		{"unprefixed aes-ctr is accepted too", map[string]string{"dek-algorithm": "aes-ctr"}, true},
		{"no algorithm at all", map[string]string{"content-type": "text/plain"}, false},
		{"empty metadata", map[string]string{}, false},
		{"nil metadata", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, m.SupportsRangeDecryption(tc.metadata))
		})
	}
}

// TestOrcStrCreateRangeDecryptionReaderMatchesPlaintextSlice is the client
// contract: whatever offset is requested, the bytes must equal the same slice
// of the original plaintext. Offsets cover 0, inside the first AES block, both
// sides of a block boundary, the last byte, and a zero-length range at EOF.
func TestOrcStrCreateRangeDecryptionReaderMatchesPlaintextSlice(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationStrict))
	plaintext := OrcStrPayload(70000)
	ciphertext, metadata := OrcStrEncryptCTR(t, m, plaintext, "bucket/ranged")

	for _, offset := range []int64{
		0, 1, 15, 16, 17, 31, 32, 4095, 4096,
		int64(len(plaintext)) - 1,
		int64(len(plaintext)),
	} {
		reader, err := m.CreateRangeDecryptionReader(context.Background(),
			bytes.NewReader(ciphertext[offset:]), metadata, "bucket/ranged", offset)
		require.NoError(t, err, "offset %d", offset)

		got, err := io.ReadAll(reader)
		require.NoError(t, err, "offset %d", offset)
		assert.Equal(t, OrcStrSHA256(plaintext[offset:]), OrcStrSHA256(got),
			"offset %d must decrypt to the matching plaintext slice", offset)
	}

	t.Run("bounded range inside the object", func(t *testing.T) {
		const start, end = 1000, 5000
		reader, err := m.CreateRangeDecryptionReader(context.Background(),
			bytes.NewReader(ciphertext[start:end]), metadata, "bucket/ranged", start)
		require.NoError(t, err)

		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, OrcStrSHA256(plaintext[start:end]), OrcStrSHA256(got))
	})

	t.Run("zero length range", func(t *testing.T) {
		reader, err := m.CreateRangeDecryptionReader(context.Background(),
			bytes.NewReader(nil), metadata, "bucket/ranged", 8192)
		require.NoError(t, err)

		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

// TestOrcStrCreateRangeDecryptionReaderIsChunkSizeIndependent checks the ranged
// reader gives the same plaintext no matter how the caller slices its reads.
func TestOrcStrCreateRangeDecryptionReaderIsChunkSizeIndependent(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationOff))
	plaintext := OrcStrPayload(9000)
	ciphertext, metadata := OrcStrEncryptCTR(t, m, plaintext, "bucket/chunked")

	const offset = 23
	for _, bufSize := range []int{1, 7, 512, 64 * 1024} {
		reader, err := m.CreateRangeDecryptionReader(context.Background(),
			bytes.NewReader(ciphertext[offset:]), metadata, "bucket/chunked", offset)
		require.NoError(t, err)

		got, err := OrcStrReadAll(reader, bufSize)
		require.NoError(t, err)
		assert.Equal(t, OrcStrSHA256(plaintext[offset:]), OrcStrSHA256(got), "bufSize %d", bufSize)
	}
}

// TestOrcStrRangedReadIsNotIntegrityChecked confirms the integrity note in
// rangeread.go: the object HMAC covers the whole object, so a partial read is
// authenticated by nothing the proxy controls. Corrupted range bytes are handed
// to the client without an error even in strict mode.
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcStrRangedReadIsNotIntegrityChecked(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationStrict))
	require.True(t, m.hmacManager.IsEnabled())

	plaintext := OrcStrPayload(4096)
	ciphertext, metadata := OrcStrEncryptCTR(t, m, plaintext, "bucket/unauth")
	m.metadataManager.SetHMAC(metadata, bytes.Repeat([]byte{0x11}, 32))
	require.True(t, m.metadataManager.HasHMAC(metadata))

	const offset = 1024
	tampered := append([]byte(nil), ciphertext[offset:]...)
	tampered[0] ^= 0xFF

	reader, err := m.CreateRangeDecryptionReader(context.Background(),
		bytes.NewReader(tampered), metadata, "bucket/unauth", offset)
	require.NoError(t, err)

	got, err := io.ReadAll(reader)
	require.NoError(t, err, "no integrity error is raised for a partial read")
	require.Len(t, got, len(plaintext)-offset)
	assert.NotEqual(t, OrcStrSHA256(plaintext[offset:]), OrcStrSHA256(got),
		"the client receives corrupted plaintext, undetected")
	assert.Equal(t, plaintext[offset+1:], got[1:],
		"only the tampered byte differs, so the corruption is silent")
}

// TestOrcStrCreateRangeDecryptionReaderNoneProviderPassThrough covers the
// pass-through fingerprint: the range is already plaintext and is handed back
// as the very same reader.
func TestOrcStrCreateRangeDecryptionReaderNoneProviderPassThrough(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationOff))
	payload := OrcStrPayload(256)
	src := bytes.NewReader(payload)

	reader, err := m.CreateRangeDecryptionReader(context.Background(), src, map[string]string{
		"s3ep-dek-algorithm":   "aes-ctr",
		"s3ep-kek-fingerprint": "none-provider-fingerprint",
	}, "bucket/passthrough", 64)
	require.NoError(t, err)
	assert.Same(t, src, reader, "pass-through data is not wrapped")

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, OrcStrSHA256(payload), OrcStrSHA256(got))
}

// TestOrcStrCreateRangeDecryptionReaderErrors walks every failure branch a
// broken or foreign object can drive.
func TestOrcStrCreateRangeDecryptionReaderErrors(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationStrict))
	_, good := OrcStrEncryptCTR(t, m, OrcStrPayload(512), "bucket/good")

	clone := func(mutate func(map[string]string)) map[string]string {
		out := make(map[string]string, len(good))
		for k, v := range good {
			out[k] = v
		}
		mutate(out)
		return out
	}

	for _, tc := range []struct {
		name     string
		metadata map[string]string
		offset   int64
		contains string
	}{
		{
			name:     "gcm objects cannot be ranged",
			metadata: clone(func(md map[string]string) { md["s3ep-dek-algorithm"] = "aes-gcm" }),
			contains: `ranged decryption is not possible for algorithm "aes-gcm"`,
		},
		{
			name:     "object without an algorithm",
			metadata: map[string]string{},
			contains: `ranged decryption is not possible for algorithm ""`,
		},
		{
			name:     "missing fingerprint",
			metadata: clone(func(md map[string]string) { delete(md, "s3ep-kek-fingerprint") }),
			contains: "failed to get fingerprint from metadata",
		},
		{
			name:     "missing encrypted DEK",
			metadata: clone(func(md map[string]string) { delete(md, "s3ep-encrypted-dek") }),
			contains: "failed to get encrypted DEK from metadata",
		},
		{
			name:     "encrypted DEK is not base64",
			metadata: clone(func(md map[string]string) { md["s3ep-encrypted-dek"] = "not-base64-!!" }),
			contains: "failed to get encrypted DEK from metadata",
		},
		{
			name:     "unknown KEK fingerprint",
			metadata: clone(func(md map[string]string) { md["s3ep-kek-fingerprint"] = "some-other-kek" }),
			contains: "failed to decrypt DEK",
		},
		{
			name:     "missing IV",
			metadata: clone(func(md map[string]string) { delete(md, "s3ep-aes-iv") }),
			contains: "failed to get IV from metadata",
		},
		{
			name:     "IV is not base64",
			metadata: clone(func(md map[string]string) { md["s3ep-aes-iv"] = "%%%" }),
			contains: "failed to get IV from metadata",
		},
		{
			name: "IV has the wrong length",
			metadata: clone(func(md map[string]string) {
				md["s3ep-aes-iv"] = base64.StdEncoding.EncodeToString([]byte("short"))
			}),
			contains: "failed to create ranged CTR reader",
		},
		{
			name:     "negative offset",
			metadata: good,
			offset:   -1,
			contains: "failed to create ranged CTR reader",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, err := m.CreateRangeDecryptionReader(context.Background(),
				bytes.NewReader(nil), tc.metadata, "bucket/broken", tc.offset)
			require.Error(t, err)
			assert.Nil(t, reader)
			assert.Contains(t, err.Error(), tc.contains)
		})
	}
}

// TestOrcStrCreateRangeDecryptionReaderUnsupportedIsTyped checks the handler
// can tell "cannot range this object" apart from a real failure, which is what
// lets it fall back to a full read instead of returning an error to the client.
func TestOrcStrCreateRangeDecryptionReaderUnsupportedIsTyped(t *testing.T) {
	m := OrcStrNewManager(t, OrcStrAESConfig(config.HMACVerificationStrict))

	_, err := m.CreateRangeDecryptionReader(context.Background(), bytes.NewReader(nil),
		map[string]string{"s3ep-dek-algorithm": "aes-gcm"}, "bucket/whole", 10)
	require.Error(t, err)

	var unsupported *RangeReadUnsupportedError
	require.True(t, errors.As(err, &unsupported))
	assert.Equal(t, "aes-gcm", unsupported.Algorithm)
}
