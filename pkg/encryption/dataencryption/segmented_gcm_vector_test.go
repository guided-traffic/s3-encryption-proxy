package dataencryption

// Known-answer vectors for the stored byte layout.
//
// THESE CONSTANTS DESCRIBE THE STORED FORMAT. They were captured once from the
// build that shipped it and are never regenerated. A failure here does not mean
// the test is stale — it means the format changed, and ADR 0017 D10 says a change
// that breaks the stored format never lands in a minor.
//
// Every other test in this package seals with this tree's writer and opens with
// this tree's reader, so the two can agree on a different layout and stay green:
// reversing the fields of the associated data, or swapping the trailer's length
// and checksum, passes the whole suite. Nothing else in the repo carries captured
// ciphertext, and integration and e2e cannot substitute — one binary writes and
// reads there too. These vectors are the only thing that pins the layout.
//
// The nonces are random per object and per segment (ADR 0003 D3), so a writer
// cannot recompute these bytes. That is the point: the assertions below only ever
// OPEN captured bytes, never re-seal them.
//
// The key is a test-only literal that appears nowhere else in the tree, so it can
// never be copied out of here into a configuration (ADR 0021).

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	vecDEK       = "1sln5Be35fo0c7+dHlzNHbrmT3u+dbLbFq7eQEBgfcY="
	vecObjectKey = "vectors/kat.bin"

	// The associated data of segment 0 and of the trailer:
	// FormatID ‖ object key ‖ 8-byte big-endian index.
	vecAAD0    = "733365702d67636d2d7365672d7632766563746f72732f6b61742e62696e0000000000000000"
	vecAADTail = "733365702d67636d2d7365672d7632766563746f72732f6b61742e62696effffffffffffffff"

	// One segment's plaintext, sealed at index 0 and again at index 7.
	vecSegmentPlaintext = "c2VnbWVudCBwbGFpbnRleHQsIHRoaXJ0eS10d28gYnk="
	vecSegmentAt0       = "4LbtEi1WVAQkeNC7TROy2jHMfZXv1XYEdslZbHJa6TyI6oepokOqxx2ninDcriOHtCS6QW2bybkg3lhR"
	vecSegmentAt7       = "cP5JhRDud+0CdDvT7zLosQ+cW239lQIH39GoGFJSu9FGoaK/DvtAcHGA95+cYscLKhmTVwn7AzetoAuK"

	// A 100-byte object: its plaintext, its sealed trailer, and the whole sealed
	// chain the reader has to assemble.
	vecObjectPlaintext = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tng5+71/AMKERgfJi00O0JJUFdeZWxzeoGIj5ad" +
		"pKuyucDHztXc4+rx+P8GDRQbIikwNz5FTFNaYWhvdn2Ei5KZoKeutQ=="
	vecObjectLength  = 100
	vecObjectCRC32C  = 3635079923
	vecObjectTrailer = "wPFnr1yWR6sRi5IXClKyqQeN4v5YdHKACHFZQmDpX/MJdsuvY5dY7w=="
	vecObjectSealed  = "OVmVUb+PPSY3JJbi0+Ct3VWLCC9iVYREwJpqgfuWKWuTm2eB0/v42vJ4L+4MccoLojGHWoJDvrTy0y82" +
		"1eXJvF78MAkAkLvarYre5iUc5IEvmfXslgnTqku9k14LHqgrtkxzb8fzz6K2sij53FPG4NRTDpGPr/cq" +
		"6Af1JriilLrK3yPovcR0jVTyBkhf2FKplb6OCKaFrabuIgsSAcgi2s0qudk9eCDp"
)

func vecCodec(t *testing.T) *Codec {
	t.Helper()
	dek, err := base64.StdEncoding.DecodeString(vecDEK)
	require.NoError(t, err)
	c, err := NewCodec(dek, vecObjectKey)
	require.NoError(t, err)
	return c
}

func vecBytes(t *testing.T, encoded string) []byte {
	t.Helper()
	out, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return out
}

// The cheapest pin of the field order, and it needs no ciphertext: the associated
// data is built, not opened. Reversing the three appends fails here.
func TestSegVectorAssociatedData(t *testing.T) {
	c := vecCodec(t)

	assert.Equal(t, vecAAD0, hex.EncodeToString(c.AADForTest(0)),
		"the associated data of segment 0 is FormatID, object key, then the index")
	assert.Equal(t, vecAADTail, hex.EncodeToString(c.AADForTest(TrailerIndexForTest)),
		"the trailer's index is the all-ones one, in the same position")

	// The two above would also pass if the index were little-endian and the
	// captured bytes had been taken from such a build, so state the layout
	// independently: the index occupies the last eight bytes, big-endian.
	aad := c.AADForTest(1)
	require.Len(t, aad, len(FormatID)+len(vecObjectKey)+8)
	assert.Equal(t, FormatID, string(aad[:len(FormatID)]))
	assert.Equal(t, vecObjectKey, string(aad[len(FormatID):len(FormatID)+len(vecObjectKey)]))
	assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0, 1}, aad[len(aad)-8:],
		"the index is an 8-byte big-endian integer at the end")
}

// A captured segment opens at the index it was sealed under, and at no other.
// This pins the index into the seal rather than merely into the AAD builder.
func TestSegVectorSegmentIsBoundToItsIndex(t *testing.T) {
	c := vecCodec(t)
	want := vecBytes(t, vecSegmentPlaintext)

	for _, tc := range []struct {
		name   string
		sealed string
		index  uint64
	}{
		{"segment sealed at 0", vecSegmentAt0, 0},
		{"segment sealed at 7", vecSegmentAt7, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.OpenSegmentForTest(nil, vecBytes(t, tc.sealed), tc.index)
			require.NoError(t, err, "the stored segment layout changed")
			assert.Equal(t, want, got)

			_, err = c.OpenSegmentForTest(nil, vecBytes(t, tc.sealed), tc.index+1)
			assert.ErrorIs(t, err, ErrCorrupt, "a segment must not open at another index")
		})
	}

	// The two captures are the same plaintext under the same key, so the only
	// thing separating them is the index and the nonce. Neither may open as the
	// other.
	_, err := c.OpenSegmentForTest(nil, vecBytes(t, vecSegmentAt7), 0)
	assert.ErrorIs(t, err, ErrCorrupt)
}

// The trailer's two fields are asserted separately. A packer that swaps the
// length and the checksum round-trips within one build and fails here.
func TestSegVectorTrailerFieldsAreWhereTheyWere(t *testing.T) {
	c := vecCodec(t)

	sum, err := c.OpenTrailerForTest(vecBytes(t, vecObjectTrailer))
	require.NoError(t, err, "the stored trailer layout changed")

	assert.Equal(t, int64(vecObjectLength), sum.Length, "the trailer's plaintext length")
	assert.Equal(t, uint32(vecObjectCRC32C), sum.Value, "the trailer's CRC32C")

	// The captured length and checksum are different numbers of different types,
	// so this also states that the two cannot have been read from each other's
	// position — the assertion that a swap has to fail.
	require.NotEqual(t, uint32(vecObjectLength), sum.Value)
}

// The assembled read path over a captured object: every atom above, in the order
// the reader walks them, against a plaintext it did not produce.
func TestSegVectorWholeObjectReadsBack(t *testing.T) {
	c := vecCodec(t)
	sealed := vecBytes(t, vecObjectSealed)

	require.Equal(t, vecObjectLength+SegmentOverhead+TrailerSize, len(sealed),
		"the captured object is one segment and a trailer")
	stored, err := CiphertextSize(vecObjectLength)
	require.NoError(t, err)
	assert.Equal(t, int64(len(sealed)), stored,
		"CiphertextSize disagrees with the captured object")

	got, err := io.ReadAll(c.NewReader(bytes.NewReader(sealed)))
	require.NoError(t, err, "the stored object layout changed")
	assert.Equal(t, vecBytes(t, vecObjectPlaintext), got)
}

// The object key is the associated data's one variable field, so a captured
// object must not open under a different one. This is what keeps filename
// encryption a rename pass rather than a re-encryption (ADR 0023).
func TestSegVectorObjectIsBoundToItsKey(t *testing.T) {
	dek, err := base64.StdEncoding.DecodeString(vecDEK)
	require.NoError(t, err)

	for _, key := range []string{
		"vectors/kat.bin ",  // a trailing space
		"/vectors/kat.bin",  // a leading separator
		"vectors%2Fkat.bin", // the URL-encoded form
		"kat.bin",           // the leaf alone
	} {
		other, err := NewCodec(dek, key)
		require.NoError(t, err)

		_, err = io.ReadAll(other.NewReader(bytes.NewReader(vecBytes(t, vecObjectSealed))))
		assert.Error(t, err, "the object opened under the key %q, so the key is not bound", key)
	}
}
