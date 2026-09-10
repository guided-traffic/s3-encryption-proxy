// Segmented AES-256-GCM storage format, ADR 0003.
//
// An object is a chain of fixed-size sealed segments followed by a sealed
// trailer. Every seal binds the format id, the client's object key and the
// segment index, so a hostile backend cannot reorder segments, move one between
// objects, or truncate the chain without the read failing.
//
//	segment i : nonce(12) ‖ AES-256-GCM(plaintext ≤ 65536) ‖ tag(16)
//	trailer   : nonce(12) ‖ AES-256-GCM(uint64 length ‖ uint32 CRC32C) ‖ tag(16)
package dataencryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	// SegmentSize is the plaintext carried by one segment. A constant of the
	// format, never a configuration value (ADR 0003 D2).
	SegmentSize = 65536

	// SegmentOverhead is the inline nonce plus the tag.
	SegmentOverhead = 12 + 16

	// TrailerSize is the sealed length-and-checksum record that closes an object.
	TrailerSize = 12 + 8 + 4 + 16

	// FormatID is the AAD prefix and the value stored as the DEK algorithm.
	FormatID = "s3ep-gcm-seg-v2"

	// MaxPlaintextLen is the largest object S3 accepts, 5 TiB. Lengths above it
	// are refused rather than allowed to overflow the window arithmetic.
	MaxPlaintextLen = 5 << 40

	// trailerIndex gives the trailer its own AAD domain. No segment index can
	// reach it: a 5 TiB object has fewer than 2^27 segments.
	trailerIndex = ^uint64(0)

	// maxSegmentIndex is the highest index a real object can carry. Anything
	// above it comes from a window this codec did not plan.
	maxSegmentIndex = (MaxPlaintextLen + SegmentSize - 1) / SegmentSize

	nonceSize = 12
)

var (
	// ErrCorrupt is returned whenever a seal does not open or the chain does not
	// match what the trailer authenticates. It never says which, because the
	// distinction is only useful to an attacker.
	ErrCorrupt = errors.New("segmented gcm: object failed authentication")

	// ErrNotWellFormed marks a stored length that no writer of this format could
	// have produced (ADR 0003 D12a).
	ErrNotWellFormed = errors.New("segmented gcm: stored length is not a valid chain")

	// ErrTooLarge marks a plaintext length above what S3 accepts.
	ErrTooLarge = errors.New("segmented gcm: plaintext exceeds the maximum object size")
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// Checksum is a CRC32C together with the plaintext length it covers. The length
// travels with the value because combining two checksums needs the length of the
// second, and a positional length is exactly what goes wrong on the
// client-driven path when a part is uploaded again.
type Checksum struct {
	Value  uint32
	Length int64
}

// NewChecksum computes the checksum of a complete plaintext.
func NewChecksum(plaintext []byte) Checksum {
	return Checksum{Value: crc32.Checksum(plaintext, crcTable), Length: int64(len(plaintext))}
}

// Append returns the checksum of this plaintext followed by next's.
func (c Checksum) Append(next Checksum) Checksum {
	return Checksum{
		Value:  crc32Combine(c.Value, next.Value, next.Length),
		Length: c.Length + next.Length,
	}
}

// Codec seals and opens the segments of one object. It is immutable and safe for
// concurrent use; all position state lives in the readers and writers it makes.
type Codec struct {
	aead      cipher.AEAD
	objectKey string
}

// NewCodec binds a data key to the object key the client used. The key is not
// copied: the caller keeps ownership and is responsible for wiping it.
func NewCodec(dek []byte, objectKey string) (*Codec, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("segmented gcm: data key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("segmented gcm: aead: %w", err)
	}
	return &Codec{aead: aead, objectKey: objectKey}, nil
}

// aad builds formatID ‖ objectKey ‖ index. The fixed-length prefix and suffix
// around one variable field make the encoding unambiguous without a length
// prefix.
func (c *Codec) aad(index uint64) []byte {
	out := make([]byte, 0, len(FormatID)+len(c.objectKey)+8)
	out = append(out, FormatID...)
	out = append(out, c.objectKey...)
	return binary.BigEndian.AppendUint64(out, index)
}

// sealSegment seals one segment's plaintext at the given index, appending to dst.
// Unexported on purpose: a caller able to seal a short middle segment would
// produce an object that writes cleanly and never reads.
func (c *Codec) sealSegment(dst, plaintext []byte, index uint64) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, nonceSize)...)
	if _, err := rand.Read(dst[start : start+nonceSize]); err != nil {
		return nil, fmt.Errorf("segmented gcm: nonce: %w", err)
	}
	return c.aead.Seal(dst, dst[start:start+nonceSize], plaintext, c.aad(index)), nil
}

// openSegment opens one sealed segment, appending the plaintext to dst.
func (c *Codec) openSegment(dst, sealed []byte, index uint64) ([]byte, error) {
	if len(sealed) < SegmentOverhead {
		return nil, ErrCorrupt
	}
	out, err := c.aead.Open(dst, sealed[:nonceSize], sealed[nonceSize:], c.aad(index))
	if err != nil {
		return nil, ErrCorrupt
	}
	return out, nil
}

// sealTrailer seals the authenticated length and checksum that close the object.
func (c *Codec) sealTrailer(dst []byte, sum Checksum) ([]byte, error) {
	if sum.Length < 0 || sum.Length > MaxPlaintextLen {
		return nil, ErrTooLarge
	}
	body := make([]byte, 12)
	binary.BigEndian.PutUint64(body[0:8], uint64(sum.Length))
	binary.BigEndian.PutUint32(body[8:12], sum.Value)
	return c.sealSegment(dst, body, trailerIndex)
}

// openTrailer opens the trailer and returns what it authenticates.
func (c *Codec) openTrailer(sealed []byte) (Checksum, error) {
	if len(sealed) != TrailerSize {
		return Checksum{}, ErrCorrupt
	}
	body, err := c.openSegment(nil, sealed, trailerIndex)
	if err != nil {
		return Checksum{}, ErrCorrupt
	}
	if len(body) != 12 {
		return Checksum{}, ErrCorrupt
	}
	stated := binary.BigEndian.Uint64(body[0:8])
	if stated > MaxPlaintextLen {
		return Checksum{}, ErrCorrupt
	}
	return Checksum{Value: binary.BigEndian.Uint32(body[8:12]), Length: int64(stated)}, nil
}

// CiphertextSize is the stored length of an object with the given plaintext
// length. Keyless (ADR 0003 D12).
func CiphertextSize(plaintext int64) (int64, error) {
	if plaintext < 0 {
		return 0, ErrNotWellFormed
	}
	if plaintext > MaxPlaintextLen {
		return 0, ErrTooLarge
	}
	segments := segmentCount(plaintext)
	return plaintext + segments*SegmentOverhead + TrailerSize, nil
}

// PlaintextSize inverts CiphertextSize and refuses a stored length that no chain
// of this format can have (ADR 0003 D12a). A rejected length is an error, never a
// fabricated size.
func PlaintextSize(ciphertext int64) (int64, error) {
	if ciphertext < TrailerSize {
		return 0, ErrNotWellFormed
	}
	body := ciphertext - TrailerSize
	if body == 0 {
		return 0, nil
	}
	const stride = SegmentSize + SegmentOverhead
	segments := (body + stride - 1) / stride
	plaintext := body - segments*SegmentOverhead
	if plaintext <= 0 {
		return 0, ErrNotWellFormed
	}
	// The guard: with n segments the plaintext must fall in ((n-1)·S, n·S].
	if plaintext <= (segments-1)*SegmentSize || plaintext > segments*SegmentSize {
		return 0, ErrNotWellFormed
	}
	if plaintext > MaxPlaintextLen {
		return 0, ErrTooLarge
	}
	return plaintext, nil
}

func segmentCount(plaintext int64) int64 {
	if plaintext == 0 {
		return 0
	}
	return (plaintext + SegmentSize - 1) / SegmentSize
}

// crc32Combine returns the CRC32C of a ‖ b given the CRC32C of each and the
// length of b. It is the zlib crc32_combine construction: CRC is linear over
// GF(2), so shifting `a` across `lenB` zero bytes is a matrix power.
func crc32Combine(a, b uint32, lenB int64) uint32 {
	if lenB <= 0 {
		return a
	}
	var even, odd [32]uint32

	// odd = the operator for one zero bit.
	odd[0] = crc32.Castagnoli
	row := uint32(1)
	for n := 1; n < 32; n++ {
		odd[n] = row
		row <<= 1
	}
	gf2MatrixSquare(&even, &odd) // two zero bits
	gf2MatrixSquare(&odd, &even) // four zero bits

	crc := a
	length := lenB
	for {
		gf2MatrixSquare(&even, &odd)
		if length&1 != 0 {
			crc = gf2MatrixTimes(&even, crc)
		}
		length >>= 1
		if length == 0 {
			break
		}
		gf2MatrixSquare(&odd, &even)
		if length&1 != 0 {
			crc = gf2MatrixTimes(&odd, crc)
		}
		length >>= 1
		if length == 0 {
			break
		}
	}
	return crc ^ b
}

func gf2MatrixTimes(mat *[32]uint32, vec uint32) uint32 {
	var sum uint32
	for i := 0; vec != 0; i++ {
		if vec&1 != 0 {
			sum ^= mat[i]
		}
		vec >>= 1
	}
	return sum
}

func gf2MatrixSquare(square, mat *[32]uint32) {
	for n := 0; n < 32; n++ {
		square[n] = gf2MatrixTimes(mat, mat[n])
	}
}
