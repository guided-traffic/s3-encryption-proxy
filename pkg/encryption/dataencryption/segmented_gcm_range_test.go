package dataencryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSegRangeExhaustive walks every offset and length over a multi-segment
// object at the boundaries that matter, and checks the plaintext byte for byte.
func TestSegRangeExhaustive(t *testing.T) {
	c := testCodec(t, testKey)
	const total = 3*SegmentSize + 777
	plaintext := make([]byte, total)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	offsets := []int64{0, 1, SegmentSize - 1, SegmentSize, SegmentSize + 1,
		2 * SegmentSize, 3 * SegmentSize, 3*SegmentSize + 776}
	lengths := []int64{1, 2, 100, SegmentSize - 1, SegmentSize, SegmentSize + 1, 2 * SegmentSize, total}

	for _, off := range offsets {
		for _, length := range lengths {
			if off >= total {
				continue
			}
			w, err := PlanRange(off, length, total)
			require.NoError(t, err, "plan %d+%d", off, length)

			want := plaintext[off:min64(off+length, total)]
			assert.Equal(t, int64(len(want)), w.PlaintextLength, "planned length %d+%d", off, length)

			src := bytes.NewReader(sealed[w.CiphertextOffset : w.CiphertextOffset+w.CiphertextLength])
			got, err := io.ReadAll(c.NewRangeReader(src, w))
			require.NoError(t, err, "read %d+%d", off, length)
			assert.Equal(t, want, got, "range %d+%d", off, length)
		}
	}
}

// TestSegRangeAmplificationBound pins ADR 0003 D9: at most two segments of
// over-read plus their framing and the trailer.
func TestSegRangeAmplificationBound(t *testing.T) {
	const total = 10 * SegmentSize
	const bound = 2*SegmentSize + 2*SegmentOverhead + TrailerSize
	for off := int64(0); off < total; off += 4097 {
		for _, length := range []int64{1, 64, 4096, SegmentSize} {
			w, err := PlanRange(off, length, total)
			require.NoError(t, err)
			over := w.CiphertextLength - w.PlaintextLength
			assert.LessOrEqual(t, over, int64(bound),
				"over-read for %d+%d must stay within the bound", off, length)
		}
	}
}

// TestSegRangeOverflowGuard covers the length a client may legally ask for. The
// segment arithmetic multiplies, so an unclamped length turns the window
// negative.
func TestSegRangeOverflowGuard(t *testing.T) {
	const total = 2 * SegmentSize
	for _, length := range []int64{math.MaxInt64, math.MaxInt64 - 1, total * 1000} {
		w, err := PlanRange(0, length, total)
		require.NoError(t, err, "length %d", length)
		assert.Equal(t, int64(total), w.PlaintextLength)
		assert.Positive(t, w.CiphertextLength)
		assert.GreaterOrEqual(t, w.CiphertextOffset, int64(0))
	}
	w, err := PlanRange(SegmentSize, math.MaxInt64, total)
	require.NoError(t, err)
	assert.Equal(t, int64(SegmentSize), w.PlaintextLength)
}

func TestSegRangeRefusals(t *testing.T) {
	const total = SegmentSize
	_, err := PlanRange(-1, 10, total)
	assert.ErrorIs(t, err, ErrRangeNotSatisfiable)
	_, err = PlanRange(0, 0, total)
	assert.ErrorIs(t, err, ErrRangeNotSatisfiable)
	_, err = PlanRange(total, 1, total)
	assert.ErrorIs(t, err, ErrRangeNotSatisfiable, "a start at the end is not satisfiable")
	_, err = PlanRange(0, 1, MaxPlaintextLen+1)
	assert.ErrorIs(t, err, ErrNotWellFormed)
}

// TestSegRangeTailVerifiesTheAuthenticatedLength: a window that reaches the end
// carries the trailer, so a backend that lied about the stored length is caught.
func TestSegRangeTailVerifiesTheAuthenticatedLength(t *testing.T) {
	c := testCodec(t, testKey)
	const total = SegmentSize + 500
	plaintext := make([]byte, total)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	w, err := PlanRange(total-100, 100, total)
	require.NoError(t, err)
	require.True(t, w.IncludesTrailer, "a tail range must carry the trailer")

	src := bytes.NewReader(sealed[w.CiphertextOffset : w.CiphertextOffset+w.CiphertextLength])
	got, err := io.ReadAll(c.NewRangeReader(src, w))
	require.NoError(t, err)
	assert.Equal(t, plaintext[total-100:], got)

	// A window planned for a different claimed length addresses different stored
	// bytes, so it is refused where it reads them: the segment arithmetic is the
	// first guard, well before the trailer.
	bad := w
	bad.TotalPlaintext = total + 1
	src = bytes.NewReader(sealed[w.CiphertextOffset : w.CiphertextOffset+w.CiphertextLength])
	_, err = io.ReadAll(c.NewRangeReader(src, bad))
	assert.ErrorIs(t, err, ErrCorrupt, "a window planned against the wrong length must fail")

	// The guard this test is named for is a different one, and nothing above
	// reaches it: every segment of the window opens, and the trailer behind them
	// is the object's own trailer swapped for another of the same key. The AAD
	// binds the format, the key and the index - not the length - so the swapped
	// trailer opens, and the only thing that catches it is the comparison of the
	// length it authenticates against the length the window was planned for.
	other := seal(t, c, make([]byte, 3*SegmentSize+7))
	spliced := append([]byte{}, sealed[w.CiphertextOffset:w.CiphertextOffset+w.CiphertextLength]...)
	copy(spliced[len(spliced)-TrailerSize:], other[len(other)-TrailerSize:])

	_, err = io.ReadAll(c.NewRangeReader(bytes.NewReader(spliced), w))
	assert.ErrorIs(t, err, ErrCorrupt,
		"a trailer authenticating another length must not be served as this object's")
}

// TestSegRangeMidObjectDoesNotCarryTheTrailer keeps the amplification promise
// honest: only a range that reaches the end pays the extra 40 bytes.
func TestSegRangeMidObjectDoesNotCarryTheTrailer(t *testing.T) {
	w, err := PlanRange(0, 10, 5*SegmentSize)
	require.NoError(t, err)
	assert.False(t, w.IncludesTrailer)
	assert.Equal(t, int64(SegmentSize+SegmentOverhead), w.CiphertextLength)
}

func TestSegRangeTamperedSegmentFails(t *testing.T) {
	c := testCodec(t, testKey)
	const total = 3 * SegmentSize
	plaintext := make([]byte, total)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	w, err := PlanRange(SegmentSize, 100, total)
	require.NoError(t, err)
	window := append([]byte(nil), sealed[w.CiphertextOffset:w.CiphertextOffset+w.CiphertextLength]...)
	window[50] ^= 0x80

	_, err = io.ReadAll(c.NewRangeReader(bytes.NewReader(window), w))
	assert.ErrorIs(t, err, ErrCorrupt)
}

// TestSegRangeSegmentFromAnotherOffsetFails: the index in the associated data
// binds a segment to its plaintext offset, so a backend cannot answer a range
// with a different segment of the same object.
func TestSegRangeSegmentFromAnotherOffsetFails(t *testing.T) {
	c := testCodec(t, testKey)
	const total = 3 * SegmentSize
	plaintext := bytes.Repeat([]byte{0x42}, total)
	sealed := seal(t, c, plaintext)

	w, err := PlanRange(SegmentSize, 100, total)
	require.NoError(t, err)

	const stride = SegmentSize + SegmentOverhead
	wrong := append([]byte(nil), sealed[0:stride]...) // segment 0 where segment 1 belongs
	_, err = io.ReadAll(c.NewRangeReader(bytes.NewReader(wrong), w))
	assert.ErrorIs(t, err, ErrCorrupt)
}

func TestSegRangeShortWindowFails(t *testing.T) {
	c := testCodec(t, testKey)
	const total = 2 * SegmentSize
	plaintext := make([]byte, total)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	w, err := PlanRange(0, SegmentSize, total)
	require.NoError(t, err)
	short := sealed[w.CiphertextOffset : w.CiphertextOffset+w.CiphertextLength-1]
	_, err = io.ReadAll(c.NewRangeReader(bytes.NewReader(short), w))
	assert.ErrorIs(t, err, ErrCorrupt)
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
