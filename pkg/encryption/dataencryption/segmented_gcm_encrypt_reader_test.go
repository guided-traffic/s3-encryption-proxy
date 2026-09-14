package dataencryption

import (
	"bytes"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errAfterReader hands out n bytes and then fails, so the pull path can be shown
// to surface a source error instead of sealing a truncated object.
type errAfterReader struct {
	data []byte
	pos  int
	err  error
}

func (r *errAfterReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestSegEncryptReaderRoundTrip(t *testing.T) {
	sizes := []int{0, 1, SegmentSize - 1, SegmentSize, SegmentSize + 1, 3*SegmentSize + 7}

	for _, size := range sizes {
		plaintext := make([]byte, size)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		c := testCodec(t, testKey)
		sealed, err := io.ReadAll(c.NewEncryptReader(bytes.NewReader(plaintext)))
		require.NoError(t, err, "size %d", size)

		want, err := CiphertextSize(int64(size))
		require.NoError(t, err)
		assert.Equal(t, want, int64(len(sealed)), "size %d: stored length must match CiphertextSize", size)

		got, err := open(t, c, sealed)
		require.NoError(t, err, "size %d", size)
		assert.Equal(t, plaintext, got, "size %d", size)
	}
}

// The reader must survive a caller that drains it one byte at a time: that is
// what an SDK with a small copy buffer does to it.
func TestSegEncryptReaderTinyReads(t *testing.T) {
	plaintext := make([]byte, 2*SegmentSize+1234)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	c := testCodec(t, testKey)
	er := c.NewEncryptReader(bytes.NewReader(plaintext))

	var sealed []byte
	one := make([]byte, 1)
	for {
		n, err := er.Read(one)
		sealed = append(sealed, one[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
	}

	got, err := open(t, c, sealed)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// A pull reader and the push writer are two entry points into the same chain;
// an object written through one must be indistinguishable from the other.
func TestSegEncryptReaderMatchesWriter(t *testing.T) {
	plaintext := make([]byte, SegmentSize+99)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	c := testCodec(t, testKey)
	viaWriter := seal(t, c, plaintext)
	viaReader, err := io.ReadAll(c.NewEncryptReader(bytes.NewReader(plaintext)))
	require.NoError(t, err)

	assert.Equal(t, len(viaWriter), len(viaReader), "same plaintext must produce the same stored length")

	fromWriter, err := open(t, c, viaWriter)
	require.NoError(t, err)
	fromReader, err := open(t, c, viaReader)
	require.NoError(t, err)
	assert.Equal(t, fromWriter, fromReader)
}

func TestSegEncryptReaderChecksum(t *testing.T) {
	plaintext := make([]byte, SegmentSize+7)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	c := testCodec(t, testKey)
	er := c.NewEncryptReader(bytes.NewReader(plaintext))
	sealed, err := io.ReadAll(er)
	require.NoError(t, err)

	sum, tracked := er.Checksum()
	require.True(t, tracked, "a whole-object reader writes the trailer, so it must keep a checksum")
	assert.Equal(t, int64(len(plaintext)), sum.Length)
	assert.Equal(t, crc32.Checksum(plaintext, crcTable), sum.Value)

	// The same values must be what the trailer authenticates.
	sealedTrailer, err := c.OpenTrailerForTest(sealed[len(sealed)-TrailerSize:])
	require.NoError(t, err)
	assert.Equal(t, sum, sealedTrailer)
}

// A source that fails mid-stream must fail the read, not close the object early:
// a sealed short object would be indistinguishable from a complete one.
func TestSegEncryptReaderPropagatesSourceError(t *testing.T) {
	sentinel := errors.New("client went away")
	src := &errAfterReader{data: make([]byte, SegmentSize+10), err: sentinel}

	c := testCodec(t, testKey)
	_, err := io.ReadAll(c.NewEncryptReader(src))
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel)
}

func TestSegEncryptReaderStaysFailedAfterAnError(t *testing.T) {
	sentinel := errors.New("client went away")
	src := &errAfterReader{data: make([]byte, 10), err: sentinel}

	c := testCodec(t, testKey)
	er := c.NewEncryptReader(src)

	buf := make([]byte, 4096)
	_, first := er.Read(buf)
	require.Error(t, first)

	_, second := er.Read(buf)
	require.Error(t, second)
	assert.ErrorIs(t, second, sentinel, "a failed reader must not resume")
}

// TestSegPartEncryptReaderHasNoChecksum pins the other half of the contract: a
// part writes no trailer, so it keeps no running checksum and says so. The
// sealed bytes must not depend on that.
func TestSegPartEncryptReaderHasNoChecksum(t *testing.T) {
	plaintext := make([]byte, 2*SegmentSize)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)

	c := testCodec(t, testKey)
	pr, err := c.NewPartEncryptReader(bytes.NewReader(plaintext), 0, false, false)
	require.NoError(t, err)
	sealed, err := io.ReadAll(pr)
	require.NoError(t, err)

	_, tracked := pr.Checksum()
	require.False(t, tracked, "a part reader keeps no checksum")

	// The part still has to open, segment for segment, at the offset it claims.
	var out []byte
	for i := 0; i < 2; i++ {
		from := i * (SegmentSize + SegmentOverhead)
		opened, oerr := c.OpenSegmentForTest(nil, sealed[from:from+SegmentSize+SegmentOverhead], uint64(i))
		require.NoError(t, oerr)
		out = append(out, opened...)
	}
	require.Equal(t, plaintext, out)
}
