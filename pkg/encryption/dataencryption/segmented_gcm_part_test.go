package dataencryption

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// partCodec builds a codec on a fixed key so a test can seal a part and read the
// object back through the sequential reader.
func partCodec(t *testing.T, objectKey string) *Codec {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	c, err := NewCodec(key, objectKey)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	return c
}

// sealInParts writes plaintext as a chain of parts of partSize bytes each,
// exactly as a multipart upload does, and closes the object with the trailer
// built from the parts' combined checksum.
func sealInParts(t *testing.T, c *Codec, plaintext []byte, partSize int) []byte {
	t.Helper()
	var stored bytes.Buffer
	var sum Checksum

	for offset := 0; ; offset += partSize {
		end := min(offset+partSize, len(plaintext))
		w, err := c.NewPartWriter(&stored, int64(offset))
		if err != nil {
			t.Fatalf("part writer at %d: %v", offset, err)
		}
		if _, err := w.Write(plaintext[offset:end]); err != nil {
			t.Fatalf("write part at %d: %v", offset, err)
		}
		if err := w.FinishPart(end == len(plaintext)); err != nil {
			t.Fatalf("finish part at %d: %v", offset, err)
		}
		sum = sum.Append(w.Checksum())
		if end == len(plaintext) {
			break
		}
	}

	trailer, err := c.SealTrailer(sum)
	if err != nil {
		t.Fatalf("trailer: %v", err)
	}
	stored.Write(trailer)
	return stored.Bytes()
}

func TestSegPartWriterRoundTrip(t *testing.T) {
	sizes := []int{0, 1, SegmentSize - 1, SegmentSize, SegmentSize + 1, 3*SegmentSize + 17}
	partSizes := []int{SegmentSize, 2 * SegmentSize}

	for _, partSize := range partSizes {
		for _, size := range sizes {
			plaintext := make([]byte, size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatal(err)
			}
			c := partCodec(t, "bucket-object")

			stored := sealInParts(t, c, plaintext, partSize)

			want, err := CiphertextSize(int64(size))
			if err != nil {
				t.Fatalf("size: %v", err)
			}
			if int64(len(stored)) != want {
				t.Fatalf("part=%d size=%d: stored %d bytes, want %d", partSize, size, len(stored), want)
			}

			got, err := io.ReadAll(c.NewReader(bytes.NewReader(stored)))
			if err != nil {
				t.Fatalf("part=%d size=%d: read: %v", partSize, size, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("part=%d size=%d: round trip mismatch", partSize, size)
			}
		}
	}
}

// A part sealed at the wrong offset carries the wrong segment index in its
// associated data, which is exactly what stops a hostile backend from
// reordering parts.
func TestSegPartWriterOffsetIsAuthenticated(t *testing.T) {
	c := partCodec(t, "bucket-object")
	plaintext := bytes.Repeat([]byte{0x41}, 2*SegmentSize)

	var stored bytes.Buffer
	first, err := c.NewPartWriter(&stored, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Write(plaintext[:SegmentSize]); err != nil {
		t.Fatal(err)
	}
	if err := first.FinishPart(false); err != nil {
		t.Fatal(err)
	}

	// The second part claims to start at offset 0 as well.
	second, err := c.NewPartWriter(&stored, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Write(plaintext[SegmentSize:]); err != nil {
		t.Fatal(err)
	}
	if err := second.FinishPart(true); err != nil {
		t.Fatal(err)
	}
	trailer, err := c.SealTrailer(first.Checksum().Append(second.Checksum()))
	if err != nil {
		t.Fatal(err)
	}
	stored.Write(trailer)

	if _, err := io.ReadAll(c.NewReader(bytes.NewReader(stored.Bytes()))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a misplaced part must not open: %v", err)
	}
}

func TestSegPartWriterRefusesUnalignedOffset(t *testing.T) {
	c := partCodec(t, "bucket-object")
	for _, offset := range []int64{-1, 1, SegmentSize - 1, SegmentSize + 1} {
		if _, err := c.NewPartWriter(io.Discard, offset); !errors.Is(err, ErrNotWellFormed) {
			t.Fatalf("offset %d: %v", offset, err)
		}
	}
	if _, err := c.NewPartWriter(io.Discard, MaxPlaintextLen+SegmentSize); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("offset past the maximum object size: %v", err)
	}
}

// A middle part that ends inside a segment is refused at the writer, not
// discovered on the first read.
func TestSegPartWriterRefusesShortMiddlePart(t *testing.T) {
	c := partCodec(t, "bucket-object")
	w, err := c.NewPartWriter(io.Discard, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, SegmentSize-1)); err != nil {
		t.Fatal(err)
	}
	if err := w.FinishPart(false); !errors.Is(err, ErrPartNotAligned) {
		t.Fatalf("short middle part: %v", err)
	}
	// The writer stays failed: a caller cannot retry it into a valid object.
	if err := w.FinishPart(true); !errors.Is(err, ErrPartNotAligned) {
		t.Fatalf("a failed part writer must stay failed: %v", err)
	}
}

// The trailer built from combined part checksums must authenticate the same
// length and value as the one a single sequential writer produces.
func TestSegSealTrailerMatchesSequentialWriter(t *testing.T) {
	plaintext := make([]byte, 2*SegmentSize+1234)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	c := partCodec(t, "bucket-object")

	var sequential bytes.Buffer
	w := c.NewWriter(&sequential)
	if _, err := w.Write(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	parted := sealInParts(t, c, plaintext, SegmentSize)

	sumSequential, err := c.OpenTrailer(sequential.Bytes()[sequential.Len()-TrailerSize:])
	if err != nil {
		t.Fatal(err)
	}
	sumParted, err := c.OpenTrailer(parted[len(parted)-TrailerSize:])
	if err != nil {
		t.Fatal(err)
	}
	if sumSequential != sumParted {
		t.Fatalf("trailer mismatch: sequential %+v, parts %+v", sumSequential, sumParted)
	}
}

func TestSegOpenTrailerRejectsTampering(t *testing.T) {
	c := partCodec(t, "bucket-object")
	trailer, err := c.SealTrailer(Checksum{Value: 0xdeadbeef, Length: 12345})
	if err != nil {
		t.Fatal(err)
	}

	for i := range trailer {
		tampered := append([]byte(nil), trailer...)
		tampered[i] ^= 0x01
		if _, err := c.OpenTrailer(tampered); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("byte %d: %v", i, err)
		}
	}

	// A trailer of another object does not open either: the object key is in the
	// associated data.
	other := partCodec(t, "another-object")
	if _, err := other.OpenTrailer(trailer); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign trailer: %v", err)
	}
}
