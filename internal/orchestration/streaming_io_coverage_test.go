package orchestration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// ===== Fixtures and helpers (all prefixed with the OrcStr token) =====

// OrcStrAESKeyB64 is a base64-encoded 256-bit AES KEK for the test configs.
const OrcStrAESKeyB64 = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// OrcStrSHA256 returns the hex-encoded SHA256 digest of data. Payloads are
// always compared by digest, never dumped.
func OrcStrSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// OrcStrPrefixPtr returns a pointer to s, for config.EncryptionConfig.MetadataKeyPrefix.
func OrcStrPrefixPtr(s string) *string {
	return &s
}

// OrcStrAESConfig builds a config with one active AES provider and the given
// integrity-verification mode.
func OrcStrAESConfig(integrityMode string) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcstr-aes",
			MetadataKeyPrefix:     OrcStrPrefixPtr("s3ep-"),
			IntegrityVerification: integrityMode,
			Providers: []config.EncryptionProvider{
				{
					Alias: "orcstr-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": OrcStrAESKeyB64,
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: 5 * 1024 * 1024,
		},
	}
}

// OrcStrLogger returns a quiet logger entry for the readers under test.
func OrcStrLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l.WithField("component", "orcstr_test")
}

// OrcStrDEK returns a deterministic 32-byte DEK.
func OrcStrDEK() []byte {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	return dek
}

// OrcStrIV returns a deterministic 16-byte IV.
func OrcStrIV() []byte {
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}
	return iv
}

// OrcStrPayload returns n deterministic, non-repeating-enough bytes.
func OrcStrPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 7) % 251)
	}
	return out
}

// OrcStrCTR builds a stateful AES-CTR encryptor pinned to a known DEK and IV so
// two independent instances produce the same keystream.
func OrcStrCTR(t *testing.T) *dataencryption.AESCTRStatefulEncryptor {
	t.Helper()
	enc, err := dataencryption.NewAESCTRStatefulEncryptorWithIV(OrcStrDEK(), OrcStrIV())
	require.NoError(t, err)
	return enc
}

// OrcStrHMACManager builds an HMACManager in the given integrity mode.
func OrcStrHMACManager(mode string) *validation.HMACManager {
	return validation.NewHMACManager(&config.Config{
		Encryption: config.EncryptionConfig{IntegrityVerification: mode},
	})
}

// OrcStrExpectedHMAC computes the HMAC an object of this plaintext would carry.
func OrcStrExpectedHMAC(t *testing.T, hm *validation.HMACManager, dek, plaintext []byte) []byte {
	t.Helper()
	calc, err := hm.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = calc.Add(plaintext)
	require.NoError(t, err)
	return hm.FinalizeCalculator(calc)
}

// OrcStrDeadCalculator returns an HMACCalculator that has already been cleaned
// up, so every Add on it fails. It is the only reachable way to drive the
// "HMAC calculation failed" branches.
func OrcStrDeadCalculator(t *testing.T, hm *validation.HMACManager, dek []byte) *validation.HMACCalculator {
	t.Helper()
	calc, err := hm.CreateCalculator(dek)
	require.NoError(t, err)
	calc.Cleanup()
	return calc
}

// OrcStrChunkReader hands out at most chunk bytes per Read and terminates with
// a separate (0, io.EOF) call, exactly like bufio.Reader does.
type OrcStrChunkReader struct {
	data  []byte
	chunk int
	off   int
}

// Read implements io.Reader.
func (r *OrcStrChunkReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := len(p)
	if r.chunk > 0 && n > r.chunk {
		n = r.chunk
	}
	if n > len(r.data)-r.off {
		n = len(r.data) - r.off
	}
	copy(p, r.data[r.off:r.off+n])
	r.off += n
	return n, nil
}

// OrcStrDataEOFReader returns its payload together with io.EOF in a single
// Read, the (n>0, err) shape io.Reader explicitly allows.
type OrcStrDataEOFReader struct {
	data []byte
	off  int
}

// Read implements io.Reader.
func (r *OrcStrDataEOFReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	if r.off >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

// OrcStrErrReader hands out its payload and then fails. With together=true the
// failure arrives on the same Read as the last bytes.
type OrcStrErrReader struct {
	data     []byte
	off      int
	err      error
	together bool
}

// Read implements io.Reader.
func (r *OrcStrErrReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	if r.together && r.off >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

// OrcStrCountingCloser records Close calls and can fail on demand.
type OrcStrCountingCloser struct {
	io.Reader
	closes int
	err    error
}

// Close implements io.Closer.
func (c *OrcStrCountingCloser) Close() error {
	c.closes++
	return c.err
}

// OrcStrReadAll drains r using a fixed-size buffer, so the caller controls the
// exact chunk size the reader under test sees.
func OrcStrReadAll(r io.Reader, bufSize int) ([]byte, error) {
	buf := make([]byte, bufSize)
	var out []byte
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// ===== encryptionReader =====

// TestOrcStrEncryptionReaderIsChunkSizeIndependent is the load-bearing property
// of every streaming wrapper: the ciphertext must not depend on how the caller
// slices its Read calls. A wrapper that fails this corrupts large uploads.
func TestOrcStrEncryptionReaderIsChunkSizeIndependent(t *testing.T) {
	plaintext := OrcStrPayload(70000)

	var reference string
	for _, tc := range []struct {
		name       string
		srcChunk   int
		bufioSize  int
		callerSize int
	}{
		{"one big read", 0, 64 * 1024, 128 * 1024},
		{"single byte source", 1, 16, 1},
		{"tiny caller buffer", 0, 16, 3},
		{"prime sized chunks", 7, 16, 13},
		{"aligned chunks", 16, 4096, 16},
		{"large chunks", 32 * 1024, 64 * 1024, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &OrcStrChunkReader{data: plaintext, chunk: tc.srcChunk}
			er := &encryptionReader{
				reader:    bufio.NewReaderSize(src, tc.bufioSize),
				encryptor: OrcStrCTR(t),
				metadata:  map[string]string{"s3ep-dek-algorithm": "aes-ctr"},
				logger:    OrcStrLogger(),
			}

			ciphertext, err := OrcStrReadAll(er, tc.callerSize)
			require.NoError(t, err)
			require.Len(t, ciphertext, len(plaintext))
			require.NotEqual(t, OrcStrSHA256(plaintext), OrcStrSHA256(ciphertext),
				"the wrapper must never hand the plaintext to the backend")

			digest := OrcStrSHA256(ciphertext)
			if reference == "" {
				reference = digest
			}
			assert.Equal(t, reference, digest,
				"ciphertext must be identical regardless of read chunking")

			// And the bytes must decrypt back to exactly the input.
			dr := &decryptionReader{
				reader:    bufio.NewReader(bytes.NewReader(ciphertext)),
				decryptor: OrcStrCTR(t),
				logger:    OrcStrLogger(),
			}
			roundTrip, err := OrcStrReadAll(dr, 4096)
			require.NoError(t, err)
			assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(roundTrip))
		})
	}
}

// TestOrcStrEncryptionReaderBoundarySizes covers empty, one byte and the AES
// block boundaries either side of 16 bytes.
func TestOrcStrEncryptionReaderBoundarySizes(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 4095, 4096, 4097} {
		plaintext := OrcStrPayload(size)

		er := &encryptionReader{
			reader:    bufio.NewReader(bytes.NewReader(plaintext)),
			encryptor: OrcStrCTR(t),
			logger:    OrcStrLogger(),
		}
		ciphertext, err := OrcStrReadAll(er, 64)
		require.NoError(t, err)
		require.Len(t, ciphertext, size)

		dr := &decryptionReader{
			reader:    bufio.NewReader(bytes.NewReader(ciphertext)),
			decryptor: OrcStrCTR(t),
			logger:    OrcStrLogger(),
		}
		roundTrip, err := OrcStrReadAll(dr, 64)
		require.NoError(t, err)
		assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(roundTrip), "size %d", size)
	}
}

// TestOrcStrEncryptionReaderEOFIsSticky pins that a drained reader keeps
// answering io.EOF instead of restarting the cipher stream.
func TestOrcStrEncryptionReaderEOFIsSticky(t *testing.T) {
	er := &encryptionReader{
		reader:    bufio.NewReader(bytes.NewReader(nil)),
		encryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}

	buf := make([]byte, 32)
	n, err := er.Read(buf)
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err)

	n, err = er.Read(buf)
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err, "the finished flag must short-circuit further reads")

	dr := &decryptionReader{
		reader:    bufio.NewReader(bytes.NewReader(nil)),
		decryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	n, err = dr.Read(buf)
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err)
	n, err = dr.Read(buf)
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err)
}

// TestOrcStrEncryptionReaderDataWithEOFInSameRead exercises the (n>0, io.EOF)
// shape: the bytes are still encrypted and handed out with the EOF.
func TestOrcStrEncryptionReaderDataWithEOFInSameRead(t *testing.T) {
	plaintext := OrcStrPayload(48)

	er := &encryptionReader{
		// A bufio buffer no larger than the caller's slice makes bufio read
		// straight into p, so the source's (n>0, io.EOF) survives the wrapper.
		reader:    bufio.NewReaderSize(&OrcStrDataEOFReader{data: plaintext}, 16),
		encryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}

	buf := make([]byte, 64)
	n, err := er.Read(buf)
	require.Equal(t, len(plaintext), n)
	require.Equal(t, io.EOF, err)
	assert.NotEqual(t, OrcStrSHA256(plaintext), OrcStrSHA256(buf[:n]))

	dr := &decryptionReader{
		reader:    bufio.NewReaderSize(&OrcStrDataEOFReader{data: buf[:n]}, 16),
		decryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	out := make([]byte, 64)
	n, err = dr.Read(out)
	require.Equal(t, len(plaintext), n)
	require.Equal(t, io.EOF, err)
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(out[:n]))
}

// TestOrcStrEncryptionReaderPropagatesSourceError checks that a mid-stream
// failure of the request body is surfaced and not swallowed as a short object.
func TestOrcStrEncryptionReaderPropagatesSourceError(t *testing.T) {
	boom := errors.New("upstream connection reset")

	er := &encryptionReader{
		reader: bufio.NewReaderSize(&OrcStrErrReader{
			data: OrcStrPayload(64),
			err:  boom,
		}, 16),
		encryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	_, err := OrcStrReadAll(er, 32)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)

	dr := &decryptionReader{
		reader: bufio.NewReaderSize(&OrcStrErrReader{
			data: OrcStrPayload(64),
			err:  boom,
		}, 16),
		decryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	_, err = OrcStrReadAll(dr, 32)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

// TestOrcStrStreamingReaderCloseIsNoop documents that Close on the plain
// encryption/decryption wrappers releases nothing: the AES-CTR key material
// inside the encryptor is not zeroed here.
func TestOrcStrStreamingReaderCloseIsNoop(t *testing.T) {
	er := &encryptionReader{
		reader:    bufio.NewReader(bytes.NewReader(nil)),
		encryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	assert.NoError(t, er.Close())

	dr := &decryptionReader{
		reader:    bufio.NewReader(bytes.NewReader(nil)),
		decryptor: OrcStrCTR(t),
		logger:    OrcStrLogger(),
	}
	assert.NoError(t, dr.Close())
}

// ===== hmacValidatingReader =====

// OrcStrNewHVR builds an hmacValidatingReader over plaintext with a correct
// HMAC, in the given integrity mode.
func OrcStrNewHVR(t *testing.T, plaintext []byte, mode string, expectedSize int64) *hmacValidatingReader {
	t.Helper()
	hm := OrcStrHMACManager(mode)
	dek := OrcStrDEK()
	calc, err := hm.CreateCalculator(dek)
	require.NoError(t, err)

	return &hmacValidatingReader{
		reader:         bufio.NewReader(bytes.NewReader(plaintext)),
		hmacCalculator: calc,
		hmacManager:    hm,
		expectedHMAC:   OrcStrExpectedHMAC(t, hm, dek, plaintext),
		objectKey:      "bucket/object",
		logger:         OrcStrLogger(),
		expectedSize:   expectedSize,
	}
}

// TestOrcStrHMACValidatingReaderDeliversVerifiedPlaintext is the regression
// test for the double-verification defect: the terminating (0, io.EOF) read of
// a bufio source used to re-run VerifyIntegrity against a calculator that the
// first, successful verification had already finalized and cleaned up, so every
// download ended in "failed to compute HMAC from calculator" after all bytes
// had been delivered.
func TestOrcStrHMACValidatingReaderDeliversVerifiedPlaintext(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 4096, 70000} {
		plaintext := OrcStrPayload(size)
		for _, bufSize := range []int{1, 64, 8192} {
			hvr := OrcStrNewHVR(t, plaintext, config.HMACVerificationStrict, int64(size))

			got, err := OrcStrReadAll(hvr, bufSize)
			require.NoError(t, err, "size=%d bufSize=%d", size, bufSize)
			require.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got),
				"size=%d bufSize=%d", size, bufSize)

			n, err := hvr.Read(make([]byte, 8))
			assert.Zero(t, n)
			assert.Equal(t, io.EOF, err)
		}
	}
}

// TestOrcStrHMACValidatingReaderRejectsWrongHMAC covers the failure branch.
func TestOrcStrHMACValidatingReaderRejectsWrongHMAC(t *testing.T) {
	plaintext := OrcStrPayload(2048)
	hvr := OrcStrNewHVR(t, plaintext, config.HMACVerificationStrict, int64(len(plaintext)))
	hvr.expectedHMAC[0] ^= 0xFF

	_, err := OrcStrReadAll(hvr, 512)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC integrity verification failed")
	assert.Contains(t, err.Error(), "data integrity compromised")
}

// TestOrcStrHMACValidatingReaderReleasesDataBeforeVerifying pins a real gap.
// The type comment promises HMAC validation "BEFORE releasing the last chunk",
// but with any source that signals EOF in a separate zero-byte read -- which is
// what bufio.Reader always does, and bufio is what both production call sites
// feed it -- nothing is ever held back: the client has already received every
// plaintext byte by the time the HMAC is checked.
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcStrHMACValidatingReaderReleasesDataBeforeVerifying(t *testing.T) {
	plaintext := OrcStrPayload(4096)
	hvr := OrcStrNewHVR(t, plaintext, config.HMACVerificationStrict, int64(len(plaintext)))
	hvr.expectedHMAC[0] ^= 0xFF

	delivered, err := OrcStrReadAll(hvr, 1024)
	require.Error(t, err, "the corruption is detected")
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(delivered),
		"but every byte was already handed to the caller before detection")
}

// TestOrcStrHMACValidatingReaderErrorIsMaskedOnRetry pins that a second Read
// after a failed verification answers io.EOF rather than repeating the error,
// because the finished flag is checked before the stored validation error.
func TestOrcStrHMACValidatingReaderErrorIsMaskedOnRetry(t *testing.T) {
	plaintext := OrcStrPayload(64)
	hvr := OrcStrNewHVR(t, plaintext, config.HMACVerificationStrict, int64(len(plaintext)))
	hvr.expectedHMAC[0] ^= 0xFF

	_, err := OrcStrReadAll(hvr, 32)
	require.Error(t, err)

	n, retryErr := hvr.Read(make([]byte, 32))
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, retryErr,
		"a caller that retries sees a clean EOF instead of the integrity failure")
}

// TestOrcStrHMACValidatingReaderWithoutExpectedHMAC covers the branch where no
// HMAC is configured: the data streams through unverified.
func TestOrcStrHMACValidatingReaderWithoutExpectedHMAC(t *testing.T) {
	plaintext := OrcStrPayload(1024)
	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	calc, err := hm.CreateCalculator(OrcStrDEK())
	require.NoError(t, err)

	hvr := &hmacValidatingReader{
		reader:         bufio.NewReader(bytes.NewReader(plaintext)),
		hmacCalculator: calc,
		hmacManager:    hm,
		expectedHMAC:   nil,
		objectKey:      "bucket/legacy",
		logger:         OrcStrLogger(),
	}

	got, err := OrcStrReadAll(hvr, 128)
	require.NoError(t, err)
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got))
}

// TestOrcStrHMACValidatingReaderCalculatorFailure drives the "HMAC calculation
// failed" branch and checks the error is sticky for the next Read.
func TestOrcStrHMACValidatingReaderCalculatorFailure(t *testing.T) {
	plaintext := OrcStrPayload(256)
	hm := OrcStrHMACManager(config.HMACVerificationStrict)

	hvr := &hmacValidatingReader{
		reader:         bufio.NewReader(bytes.NewReader(plaintext)),
		hmacCalculator: OrcStrDeadCalculator(t, hm, OrcStrDEK()),
		hmacManager:    hm,
		expectedHMAC:   bytes.Repeat([]byte{1}, 32),
		objectKey:      "bucket/object",
		logger:         OrcStrLogger(),
	}

	n, err := hvr.Read(make([]byte, 64))
	assert.Zero(t, n)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC calculation failed")

	n, again := hvr.Read(make([]byte, 64))
	assert.Zero(t, n)
	assert.Equal(t, err, again, "the stored validation error is returned again")
}

// TestOrcStrHMACValidatingReaderPropagatesSourceError covers a non-EOF failure
// of the underlying decryption stream.
func TestOrcStrHMACValidatingReaderPropagatesSourceError(t *testing.T) {
	boom := errors.New("backend stream aborted")
	plaintext := OrcStrPayload(128)
	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	calc, err := hm.CreateCalculator(OrcStrDEK())
	require.NoError(t, err)

	hvr := &hmacValidatingReader{
		reader:         bufio.NewReaderSize(&OrcStrErrReader{data: plaintext, err: boom}, 16),
		hmacCalculator: calc,
		hmacManager:    hm,
		expectedHMAC:   OrcStrExpectedHMAC(t, hm, OrcStrDEK(), plaintext),
		objectKey:      "bucket/object",
		logger:         OrcStrLogger(),
	}

	_, err = OrcStrReadAll(hvr, 64)
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
}

// TestOrcStrHMACValidatingReaderNearEndBufferingBranch exercises the
// expectedSize bookkeeping: once the read position is within two buffers of the
// announced size the reader takes its own "near end" return path.
func TestOrcStrHMACValidatingReaderNearEndBufferingBranch(t *testing.T) {
	plaintext := OrcStrPayload(512)
	hvr := OrcStrNewHVR(t, plaintext, config.HMACVerificationStrict, int64(len(plaintext)))

	got, err := OrcStrReadAll(hvr, 64)
	require.NoError(t, err)
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got))
	assert.True(t, hvr.validated)
	assert.Equal(t, int64(len(plaintext)), hvr.totalDecrypted)
}

// TestOrcStrHMACValidatingReaderHoldsBackDataEOFChunk covers the one source
// shape for which the "verify before release" design actually works: a reader
// that returns its last bytes together with io.EOF. Only then is a chunk held
// back until verification has run.
func TestOrcStrHMACValidatingReaderHoldsBackDataEOFChunk(t *testing.T) {
	plaintext := OrcStrPayload(48)
	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	calc, err := hm.CreateCalculator(OrcStrDEK())
	require.NoError(t, err)

	hvr := &hmacValidatingReader{
		reader:         bufio.NewReaderSize(&OrcStrDataEOFReader{data: plaintext}, 16),
		hmacCalculator: calc,
		hmacManager:    hm,
		expectedHMAC:   OrcStrExpectedHMAC(t, hm, OrcStrDEK(), plaintext),
		objectKey:      "bucket/object",
		logger:         OrcStrLogger(),
	}

	buf := make([]byte, 64)
	n, err := hvr.Read(buf)
	require.Equal(t, io.EOF, err)
	require.Equal(t, len(plaintext), n)
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(buf[:n]))
	assert.True(t, hvr.validated, "the chunk was released only after verification")
}

// TestOrcStrHMACValidatingReaderServesBufferedChunkInSlices covers the partial
// drain of the held-back chunk. Production never reaches it -- the recursive
// re-entry serves the buffer with the same slice it was filled from -- so the
// buffer state is set up directly here.
// Pins the current storage-format behaviour. The segmented-GCM format (ADR 0003) replaces this; update together.
func TestOrcStrHMACValidatingReaderServesBufferedChunkInSlices(t *testing.T) {
	held := OrcStrPayload(10)
	hvr := &hmacValidatingReader{
		reader:         bufio.NewReader(bytes.NewReader(nil)),
		objectKey:      "bucket/object",
		logger:         OrcStrLogger(),
		lastChunkBuf:   append([]byte(nil), held...),
		lastChunkSize:  len(held),
		totalDecrypted: int64(len(held)),
	}

	first := make([]byte, 4)
	n, err := hvr.Read(first)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	assert.Equal(t, held[:4], first[:n])

	rest := make([]byte, 16)
	n, err = hvr.Read(rest)
	require.Equal(t, io.EOF, err)
	require.Equal(t, 6, n)
	assert.Equal(t, held[4:], rest[:n])

	n, err = hvr.Read(rest)
	assert.Zero(t, n)
	assert.Equal(t, io.EOF, err)
}

// TestOrcStrHMACValidatingReaderCloseReleasesResources checks Close wipes the
// held chunk, drops the calculator and closes the wrapped reader once.
func TestOrcStrHMACValidatingReaderCloseReleasesResources(t *testing.T) {
	t.Run("closes the inner reader and reports its error", func(t *testing.T) {
		closeErr := errors.New("body close failed")
		inner := &OrcStrCountingCloser{Reader: bytes.NewReader(nil), err: closeErr}
		hm := OrcStrHMACManager(config.HMACVerificationStrict)
		calc, err := hm.CreateCalculator(OrcStrDEK())
		require.NoError(t, err)

		hvr := &hmacValidatingReader{
			reader:         inner,
			hmacCalculator: calc,
			hmacManager:    hm,
			logger:         OrcStrLogger(),
			lastChunkBuf:   OrcStrPayload(8),
			lastChunkSize:  8,
		}

		assert.Equal(t, closeErr, hvr.Close())
		assert.Equal(t, 1, inner.closes)
		assert.Nil(t, hvr.lastChunkBuf)
		assert.Nil(t, hvr.hmacCalculator)
	})

	t.Run("succeeds when the inner reader is not a closer", func(t *testing.T) {
		hvr := &hmacValidatingReader{
			reader: bytes.NewReader(nil),
			logger: OrcStrLogger(),
		}
		assert.NoError(t, hvr.Close())
	})
}

// ===== hmacGatedDecryptionReader =====

// OrcStrGatedFixture encrypts plaintext with AES-CTR and returns the ciphertext
// plus the HMAC that a matching object would carry.
func OrcStrGatedFixture(t *testing.T, plaintext []byte, mode string) (ciphertext, expectedHMAC []byte) {
	t.Helper()
	enc := OrcStrCTR(t)
	ciphertext = append([]byte(nil), plaintext...)
	_, err := enc.EncryptPart(ciphertext)
	require.NoError(t, err)
	if len(plaintext) > 0 {
		require.NotEqual(t, OrcStrSHA256(plaintext), OrcStrSHA256(ciphertext))
	}
	return ciphertext, OrcStrExpectedHMAC(t, OrcStrHMACManager(mode), OrcStrDEK(), plaintext)
}

// TestOrcStrHMACGatedReaderRoundTrip covers the multipart download reader over
// several payload sizes and caller buffer sizes, including payloads larger than
// the 64 KiB ping-pong buffers.
func TestOrcStrHMACGatedReaderRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 16, hmacGatedBufSize - 1, hmacGatedBufSize, hmacGatedBufSize + 1, 3 * hmacGatedBufSize} {
		ciphertext, expected := OrcStrGatedFixture(t, OrcStrPayload(size), config.HMACVerificationStrict)
		plaintext := OrcStrPayload(size)

		for _, bufSize := range []int{1, 777, 4096, 256 * 1024} {
			hm := OrcStrHMACManager(config.HMACVerificationStrict)
			calc, err := hm.CreateCalculator(OrcStrDEK())
			require.NoError(t, err)

			r := newHMACGatedDecryptionReader(
				bytes.NewReader(append([]byte(nil), ciphertext...)),
				OrcStrCTR(t), calc, hm, expected, "bucket/multipart")

			got, err := OrcStrReadAll(r, bufSize)
			require.NoError(t, err, "size=%d bufSize=%d", size, bufSize)
			require.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got),
				"size=%d bufSize=%d", size, bufSize)

			n, err := r.Read(make([]byte, 8))
			assert.Zero(t, n)
			assert.Equal(t, io.EOF, err, "EOF stays sticky")
			assert.NoError(t, r.Close())
		}
	}
}

// TestOrcStrHMACGatedReaderWithholdsFinalChunkOnTamper is the contract this
// reader exists for: corrupted multipart data must not be fully delivered.
func TestOrcStrHMACGatedReaderWithholdsFinalChunkOnTamper(t *testing.T) {
	plaintext := OrcStrPayload(3 * hmacGatedBufSize)
	ciphertext, expected := OrcStrGatedFixture(t, plaintext, config.HMACVerificationStrict)
	ciphertext[0] ^= 0xFF

	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	calc, err := hm.CreateCalculator(OrcStrDEK())
	require.NoError(t, err)

	r := newHMACGatedDecryptionReader(bytes.NewReader(ciphertext), OrcStrCTR(t), calc, hm, expected, "bucket/multipart")

	delivered, err := OrcStrReadAll(r, 4096)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC verification failed for bucket/multipart")
	assert.Less(t, len(delivered), len(plaintext),
		"the final chunk must stay withheld when verification fails")

	n, again := r.Read(make([]byte, 16))
	assert.Zero(t, n)
	assert.Equal(t, err, again, "the failure is sticky")
}

// TestOrcStrHMACGatedReaderWithoutHMAC covers the branch where verification is
// not configured at all: the bytes stream straight through.
func TestOrcStrHMACGatedReaderWithoutHMAC(t *testing.T) {
	plaintext := OrcStrPayload(5000)
	ciphertext, _ := OrcStrGatedFixture(t, plaintext, config.HMACVerificationOff)

	r := newHMACGatedDecryptionReader(bytes.NewReader(ciphertext), OrcStrCTR(t), nil, nil, nil, "bucket/plain")
	got, err := OrcStrReadAll(r, 512)
	require.NoError(t, err)
	assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got))
	assert.NoError(t, r.Close())
}

// TestOrcStrHMACGatedReaderPropagatesSourceError covers a backend stream that
// dies mid-object, in both the (0, err) and (n>0, err) shapes.
func TestOrcStrHMACGatedReaderPropagatesSourceError(t *testing.T) {
	boom := errors.New("backend read failed")
	for _, together := range []bool{false, true} {
		plaintext := OrcStrPayload(2048)
		ciphertext, expected := OrcStrGatedFixture(t, plaintext, config.HMACVerificationStrict)

		hm := OrcStrHMACManager(config.HMACVerificationStrict)
		calc, err := hm.CreateCalculator(OrcStrDEK())
		require.NoError(t, err)

		src := &OrcStrErrReader{data: ciphertext, err: boom, together: together}
		r := newHMACGatedDecryptionReader(src, OrcStrCTR(t), calc, hm, expected, "bucket/multipart")

		_, err = OrcStrReadAll(r, 4096)
		require.Error(t, err, "together=%v", together)
		assert.ErrorIs(t, err, boom)

		n, again := r.Read(make([]byte, 8))
		assert.Zero(t, n)
		assert.Equal(t, boom, again)
	}
}

// TestOrcStrHMACGatedReaderCalculatorFailure drives the "HMAC calculation
// failed" branch.
func TestOrcStrHMACGatedReaderCalculatorFailure(t *testing.T) {
	plaintext := OrcStrPayload(1024)
	ciphertext, expected := OrcStrGatedFixture(t, plaintext, config.HMACVerificationStrict)

	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	r := newHMACGatedDecryptionReader(
		bytes.NewReader(ciphertext), OrcStrCTR(t),
		OrcStrDeadCalculator(t, hm, OrcStrDEK()), hm, expected, "bucket/multipart")

	n, err := r.Read(make([]byte, 4096))
	assert.Zero(t, n)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HMAC calculation failed")
}

// TestOrcStrHMACGatedReaderCloseIsIdempotent checks Close can run twice and
// after a completed stream without panicking.
func TestOrcStrHMACGatedReaderCloseIsIdempotent(t *testing.T) {
	hm := OrcStrHMACManager(config.HMACVerificationStrict)
	calc, err := hm.CreateCalculator(OrcStrDEK())
	require.NoError(t, err)

	r := newHMACGatedDecryptionReader(bytes.NewReader(nil), OrcStrCTR(t), calc, hm, nil, "bucket/empty")
	assert.NoError(t, r.Close())
	assert.NoError(t, r.Close())
	assert.Nil(t, r.hmacCalc)
}

// TestOrcStrSizedStreamingDownloadReturnsPlaintextWithoutError drives the
// reader through the facade the GET handler uses, which is where the
// double-verification defect actually bit: every single-part AES-CTR object
// with an HMAC used to end its download with a bogus integrity error after all
// bytes had already gone out. Byte-for-byte equality is the client contract;
// the absence of an error is the regression guard.
func TestOrcStrSizedStreamingDownloadReturnsPlaintextWithoutError(t *testing.T) {
	for _, mode := range []string{
		config.HMACVerificationStrict,
		config.HMACVerificationLax,
		config.HMACVerificationHybrid,
		config.HMACVerificationOff,
	} {
		t.Run(mode, func(t *testing.T) {
			m := OrcStrNewManager(t, OrcStrAESConfig(mode))
			plaintext := OrcStrPayload(64 * 1024)

			res, err := m.EncryptDataWithContentType(context.Background(),
				bufio.NewReader(bytes.NewReader(plaintext)), "bucket/streamed",
				factory.ContentTypeMultipart)
			require.NoError(t, err)
			ciphertext, err := io.ReadAll(res.EncryptedDataReader)
			require.NoError(t, err)
			require.NotEqual(t, OrcStrSHA256(plaintext), OrcStrSHA256(ciphertext))

			body := &OrcStrCountingCloser{Reader: bytes.NewReader(ciphertext)}
			reader, err := m.CreateStreamingDecryptionReaderWithSize(context.Background(),
				body, nil, res.Metadata, "bucket/streamed", "", int64(len(plaintext)))
			require.NoError(t, err)

			got, err := io.ReadAll(reader)
			require.NoError(t, err, "a correct object must not fail integrity verification")
			assert.Equal(t, OrcStrSHA256(plaintext), OrcStrSHA256(got))

			require.NoError(t, reader.Close())
			assert.Equal(t, 1, body.closes, "the backend body is released")
		})
	}
}

// ===== readCloserWrapper =====

// TestOrcStrReadCloserWrapperClose pins which error wins when both the inner
// reader and the underlying body fail to close.
func TestOrcStrReadCloserWrapperClose(t *testing.T) {
	innerErr := errors.New("inner close failed")
	outerErr := errors.New("body close failed")

	t.Run("inner error wins over the body error", func(t *testing.T) {
		inner := &OrcStrCountingCloser{Reader: bytes.NewReader([]byte("data")), err: innerErr}
		outer := &OrcStrCountingCloser{Reader: bytes.NewReader(nil), err: outerErr}
		w := &readCloserWrapper{Reader: inner, closer: outer}

		got, err := io.ReadAll(w)
		require.NoError(t, err)
		assert.Equal(t, []byte("data"), got)

		assert.Equal(t, innerErr, w.Close())
		assert.Equal(t, 1, inner.closes)
		assert.Equal(t, 1, outer.closes, "the body is closed even when the inner close fails")
	})

	t.Run("body error surfaces when the inner reader is not a closer", func(t *testing.T) {
		outer := &OrcStrCountingCloser{Reader: bytes.NewReader(nil), err: outerErr}
		w := &readCloserWrapper{Reader: bytes.NewReader(nil), closer: outer}
		assert.Equal(t, outerErr, w.Close())
	})

	t.Run("nil closer and clean closes return nil", func(t *testing.T) {
		inner := &OrcStrCountingCloser{Reader: bytes.NewReader(nil)}
		assert.NoError(t, (&readCloserWrapper{Reader: inner, closer: nil}).Close())
		assert.Equal(t, 1, inner.closes)

		outer := &OrcStrCountingCloser{Reader: bytes.NewReader(nil)}
		assert.NoError(t, (&readCloserWrapper{Reader: bytes.NewReader(nil), closer: outer}).Close())
		assert.Equal(t, 1, outer.closes)
	})
}
