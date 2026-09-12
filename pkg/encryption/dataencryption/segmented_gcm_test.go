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

const testKey = "bucketless/object/key.bin"

func testCodec(t *testing.T, key string) *Codec {
	t.Helper()
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	c, err := NewCodec(dek, key)
	require.NoError(t, err)
	return c
}

func seal(t *testing.T, c *Codec, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := c.NewWriter(&buf)
	_, err := w.Write(plaintext)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

func open(t *testing.T, c *Codec, sealed []byte) ([]byte, error) {
	t.Helper()
	return io.ReadAll(c.NewReader(bytes.NewReader(sealed)))
}

// sizes span every boundary the segment grid has.
var sizes = []int{0, 1, 27, 28, 1024, SegmentSize - 1, SegmentSize, SegmentSize + 1,
	2*SegmentSize - 1, 2 * SegmentSize, 2*SegmentSize + 1, 3*SegmentSize + 12345}

func TestSegRoundTrip(t *testing.T) {
	c := testCodec(t, testKey)
	for _, n := range sizes {
		plaintext := make([]byte, n)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		sealed := seal(t, c, plaintext)

		want, err := CiphertextSize(int64(n))
		require.NoError(t, err)
		assert.Equal(t, want, int64(len(sealed)), "stored length at %d", n)

		got, err := open(t, c, sealed)
		require.NoError(t, err, "open at %d", n)
		assert.Equal(t, plaintext, got, "round trip at %d", n)
	}
}

func TestSegSizeFunctionsRoundTrip(t *testing.T) {
	for _, n := range append(sizes, 12*1024*1024, 1<<30) {
		c, err := CiphertextSize(int64(n))
		require.NoError(t, err, "ciphertext size at %d", n)
		p, err := PlaintextSize(c)
		require.NoError(t, err, "plaintext size at %d (stored %d)", n, c)
		assert.Equal(t, int64(n), p, "size round trip at %d", n)
	}
}

// TestSegSizeGuardRejectsUnreachableLengths pins ADR 0003 D12a: the backend
// reports the stored length freely, and lengths no writer can produce must be
// refused rather than answered with a fabricated size.
func TestSegSizeGuardRejectsUnreachableLengths(t *testing.T) {
	reachable := map[int64]bool{}
	for p := int64(0); p <= 5*SegmentSize+5; p++ {
		c, err := CiphertextSize(p)
		require.NoError(t, err)
		reachable[c] = true
	}
	for c := int64(0); c <= 5*SegmentSize+5+6*SegmentOverhead+TrailerSize; c++ {
		p, err := PlaintextSize(c)
		if reachable[c] {
			require.NoError(t, err, "stored length %d is reachable", c)
			back, err := CiphertextSize(p)
			require.NoError(t, err)
			assert.Equal(t, c, back, "round trip at stored length %d", c)
			continue
		}
		assert.ErrorIs(t, err, ErrNotWellFormed, "stored length %d is not reachable", c)
	}
	// The two lengths ADR 0003 D12a names explicitly.
	_, err := PlaintextSize(68)
	assert.ErrorIs(t, err, ErrNotWellFormed)
	_, err = PlaintextSize(65605)
	assert.ErrorIs(t, err, ErrNotWellFormed)
}

func TestSegFlippedBitFails(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := make([]byte, 3*SegmentSize)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	// Every region of the object: a nonce, a ciphertext byte, a tag, the trailer.
	for _, at := range []int{0, 5, 100, SegmentSize, len(sealed) - TrailerSize, len(sealed) - 1} {
		corrupt := append([]byte(nil), sealed...)
		corrupt[at] ^= 0x01
		_, err := open(t, c, corrupt)
		assert.ErrorIs(t, err, ErrCorrupt, "flipped bit at offset %d must fail", at)
	}
}

func TestSegSwappedSegmentsFail(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := make([]byte, 3*SegmentSize)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	const stride = SegmentSize + SegmentOverhead
	swapped := append([]byte(nil), sealed...)
	copy(swapped[0:stride], sealed[stride:2*stride])
	copy(swapped[stride:2*stride], sealed[0:stride])

	_, err = open(t, c, swapped)
	assert.ErrorIs(t, err, ErrCorrupt, "reordered segments must fail")
}

// TestSegSegmentFromAnotherObjectFails is why the client's object key is in the
// associated data: a hostile backend can copy metadata, so metadata alone binds
// nothing.
func TestSegSegmentFromAnotherObjectFails(t *testing.T) {
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	a, err := NewCodec(dek, "objects/a.bin")
	require.NoError(t, err)
	b, err := NewCodec(dek, "objects/b.bin")
	require.NoError(t, err)

	plaintext := make([]byte, 2*SegmentSize)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	sealedA := seal(t, a, plaintext)
	sealedB := seal(t, b, plaintext)

	const stride = SegmentSize + SegmentOverhead
	grafted := append([]byte(nil), sealedA...)
	copy(grafted[0:stride], sealedB[0:stride])

	_, err = open(t, a, grafted)
	assert.ErrorIs(t, err, ErrCorrupt, "a segment from another object key must fail")

	// The whole object under the wrong key fails too.
	_, err = open(t, b, sealedA)
	assert.ErrorIs(t, err, ErrCorrupt, "the wrong object key must fail")
}

func TestSegTruncatedFails(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := make([]byte, 2*SegmentSize+7)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	for _, cut := range []int{
		len(sealed) - 1,                             // one byte off the trailer
		len(sealed) - TrailerSize,                   // the trailer removed entirely
		SegmentSize + SegmentOverhead + TrailerSize, // a whole segment dropped
		TrailerSize,                                 // nothing but a trailer-sized prefix
		0,                                           // empty
	} {
		_, err := open(t, c, sealed[:cut])
		assert.Error(t, err, "truncation to %d bytes must fail", cut)
		if cut > 0 {
			assert.ErrorIs(t, err, ErrCorrupt, "truncation to %d bytes", cut)
		}
	}
}

// TestSegExtendedFails covers the backend appending to a finished object. The
// trailer's authenticated length is what catches it.
func TestSegExtendedFails(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := make([]byte, SegmentSize+11)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	// A second, well-formed object appended after the first one's trailer.
	extra := seal(t, c, []byte("appended"))
	_, err = open(t, c, append(append([]byte(nil), sealed...), extra...))
	assert.Error(t, err, "an extended object must fail")

	// Garbage appended.
	_, err = open(t, c, append(append([]byte(nil), sealed...), 0x00, 0x01, 0x02))
	assert.ErrorIs(t, err, ErrCorrupt, "trailing garbage must fail")
}

// TestSegTrailerIsNotABareChecksum pins that the stored trailer never exposes the
// plaintext checksum in the clear: a cleartext checksum of a small object is a
// guessing oracle for the backend (ADR 0003 D13).
func TestSegTrailerIsNotABareChecksum(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := []byte("a short, guessable object")
	sealed := seal(t, c, plaintext)

	trailer := sealed[len(sealed)-TrailerSize:]
	sum := crc32.Checksum(plaintext, crcTable)
	bare := []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
	assert.False(t, bytes.Contains(trailer, bare), "the trailer must not carry the checksum in the clear")

	length := []byte{0, 0, 0, 0, 0, 0, 0, byte(len(plaintext))}
	assert.False(t, bytes.Contains(trailer, length), "the trailer must not carry the length in the clear")
}

func TestSegChecksumMatchesTrailer(t *testing.T) {
	c := testCodec(t, testKey)
	for _, n := range []int{0, 1, SegmentSize, 2*SegmentSize + 3} {
		plaintext := make([]byte, n)
		_, err := rand.Read(plaintext)
		require.NoError(t, err)

		var buf bytes.Buffer
		w := c.NewWriter(&buf)
		_, err = w.Write(plaintext)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		assert.Equal(t, NewChecksum(plaintext), w.Checksum(), "writer checksum at %d", n)

		r := c.NewReader(bytes.NewReader(buf.Bytes()))
		_, err = io.ReadAll(r)
		require.NoError(t, err)
		got, ok := r.(interface{ Checksum() (Checksum, bool) }).Checksum()
		require.True(t, ok)
		assert.Equal(t, NewChecksum(plaintext), got, "trailer checksum at %d", n)
	}
}

// TestSegChecksumAppendMatchesWholeCRC pins the GF(2) combine against the
// standard implementation: the client-driven multipart path folds per-part
// checksums with it.
func TestSegChecksumAppendMatchesWholeCRC(t *testing.T) {
	whole := make([]byte, 300000)
	_, err := rand.Read(whole)
	require.NoError(t, err)

	for _, split := range []int{0, 1, 12345, 65536, 299999, len(whole)} {
		got := NewChecksum(whole[:split]).Append(NewChecksum(whole[split:]))
		assert.Equal(t, NewChecksum(whole), got, "combine at split %d", split)
	}

	// Three parts, and a middle part replaced by a re-upload of different content.
	a, b, cc := whole[:100000], whole[100000:200000], whole[200000:]
	assert.Equal(t, NewChecksum(whole), NewChecksum(a).Append(NewChecksum(b)).Append(NewChecksum(cc)))
}

func TestSegWriteAfterCloseFails(t *testing.T) {
	c := testCodec(t, testKey)
	w := c.NewWriter(&bytes.Buffer{})
	require.NoError(t, w.Close())
	_, err := w.Write([]byte("x"))
	assert.Error(t, err)
}

func TestSegShortMiddleSegmentIsUnreadable(t *testing.T) {
	c := testCodec(t, testKey)
	// Hand-build a chain whose first segment is short. The writer cannot produce
	// this; the raw atom can, which is why it is not exported.
	var buf bytes.Buffer
	first, err := c.SealSegmentForTest(nil, []byte("short"), 0)
	require.NoError(t, err)
	buf.Write(first)
	second, err := c.SealSegmentForTest(nil, bytes.Repeat([]byte{7}, SegmentSize), 1)
	require.NoError(t, err)
	buf.Write(second)
	trailer, err := c.SealSegmentForTest(nil, make([]byte, 12), TrailerIndexForTest)
	require.NoError(t, err)
	buf.Write(trailer)

	_, err = open(t, c, buf.Bytes())
	assert.Error(t, err, "a short middle segment must not read back")
}

func TestSegOversizeRefused(t *testing.T) {
	_, err := CiphertextSize(MaxPlaintextLen + 1)
	assert.ErrorIs(t, err, ErrTooLarge)
	_, err = CiphertextSize(-1)
	assert.ErrorIs(t, err, ErrNotWellFormed)
	_, err = PlaintextSize(TrailerSize - 1)
	assert.ErrorIs(t, err, ErrNotWellFormed)
}

func TestSegReaderPropagatesSourceError(t *testing.T) {
	c := testCodec(t, testKey)
	sentinel := errors.New("backend went away")
	_, err := io.ReadAll(c.NewReader(io.MultiReader(bytes.NewReader(make([]byte, 10)), errReader{sentinel})))
	assert.Error(t, err)
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// TestSegIdenticalSegmentsCannotBeReordered isolates the segment index in the
// associated data. Two identical segments carry the same plaintext, so reordering
// them leaves the length and the checksum untouched: nothing but the index in the
// AAD can catch it.
func TestSegIdenticalSegmentsCannotBeReordered(t *testing.T) {
	c := testCodec(t, testKey)
	half := bytes.Repeat([]byte{0xAB}, SegmentSize)
	plaintext := append(append([]byte(nil), half...), half...)
	sealed := seal(t, c, plaintext)

	const stride = SegmentSize + SegmentOverhead
	swapped := append([]byte(nil), sealed...)
	copy(swapped[0:stride], sealed[stride:2*stride])
	copy(swapped[stride:2*stride], sealed[0:stride])

	// Sanity: the two sealed blocks really do differ, so the swap is a real change.
	require.NotEqual(t, sealed[0:stride], sealed[stride:2*stride], "random nonces must differ")

	_, err := open(t, c, swapped)
	assert.ErrorIs(t, err, ErrCorrupt,
		"identical segments must still be bound to their index")
}

// TestSegForgedTrailerLengthFails covers the authenticated length. The segments
// all open; only the trailer disagrees about how much plaintext there is.
func TestSegForgedTrailerLengthFails(t *testing.T) {
	c := testCodec(t, testKey)
	plaintext := make([]byte, SegmentSize+100)
	_, err := rand.Read(plaintext)
	require.NoError(t, err)
	sealed := seal(t, c, plaintext)

	honest := NewChecksum(plaintext)
	forged, err := c.SealTrailerForTest(Checksum{Value: honest.Value, Length: honest.Length - 1})
	require.NoError(t, err)

	spliced := append(append([]byte(nil), sealed[:len(sealed)-TrailerSize]...), forged...)
	_, err = open(t, c, spliced)
	assert.ErrorIs(t, err, ErrCorrupt, "a trailer stating the wrong length must fail")
}

// TestSegForgedTrailerChecksumFails covers the checksum half of the trailer: the
// detector for a fault in the proxy's own reassembly of already-verified
// plaintext (ADR 0003 D13).
//
// It also pins HOW MUCH plaintext is out by the time the detector fires, which
// depends on the size and is worth stating rather than discovering:
//
//   - An object that does not end on a segment boundary has its last, short
//     segment in the same read as the trailer, so nothing of it is released:
//     the reader stops with the trailer's verdict and the tail never leaves.
//   - An object that ends exactly on a boundary has already released its last
//     full segment when the trailer arrives, because the reader learns the
//     object ended only on the read after it. Every released byte was still
//     authenticated under its own key, index and object key; what the trailer
//     adds - the whole-object length and checksum - lands as an error before
//     io.EOF, so a reader that honours the error never accepts the object.
//
// ADR 0003 D6 is written for the first case; the second is what the streaming
// reader can promise without holding a whole object in memory.
func TestSegForgedTrailerChecksumFails(t *testing.T) {
	sizes := map[string]struct {
		plaintext int
		released  int
	}{
		"on a segment boundary":     {plaintext: 2 * SegmentSize, released: 2 * SegmentSize},
		"not on a segment boundary": {plaintext: 2*SegmentSize + 17, released: 2 * SegmentSize},
	}

	for name, tc := range sizes {
		t.Run(name, func(t *testing.T) {
			c := testCodec(t, testKey)
			plaintext := make([]byte, tc.plaintext)
			_, err := rand.Read(plaintext)
			require.NoError(t, err)
			sealed := seal(t, c, plaintext)

			honest := NewChecksum(plaintext)
			forged, err := c.SealTrailerForTest(Checksum{Value: honest.Value ^ 1, Length: honest.Length})
			require.NoError(t, err)

			spliced := append(append([]byte(nil), sealed[:len(sealed)-TrailerSize]...), forged...)

			// Counted, not discarded: "an error arrived" says nothing about how
			// much of the object went out before it.
			reader := c.NewReader(bytes.NewReader(spliced))
			got, err := io.ReadAll(reader)
			assert.ErrorIs(t, err, ErrCorrupt, "a trailer stating the wrong checksum must fail")
			assert.Equal(t, tc.released, len(got),
				"the reader released %d of %d plaintext bytes before the trailer's verdict",
				len(got), tc.plaintext)
			assert.Equal(t, plaintext[:len(got)], got,
				"whatever was released was the authenticated plaintext, byte for byte")
		})
	}
}

// TestSegTrailerAndSegmentsAreSeparateDomains pins the reserved trailer index. If
// the trailer shared a domain with segment 0, a backend could present one as the
// other.
func TestSegTrailerAndSegmentsAreSeparateDomains(t *testing.T) {
	c := testCodec(t, testKey)

	// A trailer must not open as segment 0, and a segment must not open as a trailer.
	trailer, err := c.SealTrailerForTest(Checksum{Value: 0, Length: 0})
	require.NoError(t, err)
	_, err = c.OpenSegmentForTest(nil, trailer, 0)
	assert.ErrorIs(t, err, ErrCorrupt, "the trailer must not open as segment 0")

	body := make([]byte, 12)
	segment, err := c.SealSegmentForTest(nil, body, 0)
	require.NoError(t, err)
	_, err = c.OpenSegmentForTest(nil, segment, TrailerIndexForTest)
	assert.ErrorIs(t, err, ErrCorrupt, "a segment must not open as the trailer")

	// And the reserved index is beyond anything a real object can reach.
	maxSegments := uint64((MaxPlaintextLen + SegmentSize - 1) / SegmentSize)
	assert.Less(t, maxSegments, TrailerIndexForTest,
		"the reserved trailer index must be unreachable by a segment index")
}

// TestSegTrailerSubstitutedFromAnotherObjectFails: a trailer is bound to the
// object key like every other seal.
func TestSegTrailerSubstitutedFromAnotherObjectFails(t *testing.T) {
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)
	a, err := NewCodec(dek, "objects/a.bin")
	require.NoError(t, err)
	b, err := NewCodec(dek, "objects/b.bin")
	require.NoError(t, err)

	plaintext := make([]byte, 1000)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)

	sealedA := seal(t, a, plaintext)
	sealedB := seal(t, b, plaintext)

	spliced := append(append([]byte(nil), sealedA[:len(sealedA)-TrailerSize]...),
		sealedB[len(sealedB)-TrailerSize:]...)
	_, err = open(t, a, spliced)
	assert.ErrorIs(t, err, ErrCorrupt, "another object's trailer must fail")
}

// TestSegNoncesAreUnique is the test a round trip can never be: a constant nonce
// round-trips perfectly and destroys the confidentiality of every plaintext under
// the key, plus the authentication key itself. The format's whole reason for
// carrying an inline random nonce per segment is that a multipart part can be
// uploaded again with different content, so a derived counter nonce would repeat
// (ADR 0003).
func TestSegNoncesAreUnique(t *testing.T) {
	c := testCodec(t, testKey)

	// Identical plaintext in every segment: if the nonce were derived from the
	// content or fixed, the sealed segments would be byte-identical.
	segmentsWanted := 8
	plaintext := bytes.Repeat([]byte{0x5A}, segmentsWanted*SegmentSize)
	sealed := seal(t, c, plaintext)

	seen := map[string]int{}
	const stride = SegmentSize + SegmentOverhead
	for i := 0; i < segmentsWanted; i++ {
		nonce := string(sealed[i*stride : i*stride+nonceSize])
		if first, dup := seen[nonce]; dup {
			t.Fatalf("segment %d reuses the nonce of segment %d", i, first)
		}
		seen[nonce] = i
		assert.NotEqual(t, make([]byte, nonceSize), []byte(nonce), "segment %d has a zero nonce", i)
	}
	trailerNonce := string(sealed[len(sealed)-TrailerSize : len(sealed)-TrailerSize+nonceSize])
	_, dup := seen[trailerNonce]
	assert.False(t, dup, "the trailer reuses a segment nonce")
	assert.NotEqual(t, make([]byte, nonceSize), []byte(trailerNonce), "the trailer has a zero nonce")

	// Sealing the same object twice must produce different ciphertext throughout.
	again := seal(t, c, plaintext)
	assert.NotEqual(t, sealed, again, "sealing twice must not be deterministic")
	for i := 0; i < segmentsWanted; i++ {
		assert.NotEqual(t, sealed[i*stride:i*stride+nonceSize], again[i*stride:i*stride+nonceSize],
			"segment %d repeated its nonce across two seals", i)
	}
}
