//go:build perf

package perf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"io"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// segmentSize is the plaintext one segment carries. Taken from the codec so the
// model rows below cannot drift away from what the codec actually does.
const segmentSize = dataencryption.SegmentSize

// cryptoFloorSizes span the routing decisions of the write path: one segment,
// well inside a single request, the default streaming_segment_size (the
// single-request / multipart boundary), and an object of many parts.
var cryptoFloorSizes = []int64{
	64 * 1024,
	1024 * 1024,
	12 * 1024 * 1024,
	128 * 1024 * 1024,
}

// TestCryptoFloor measures the in-process cost of the segment chain: the raw
// per-segment GCM work as a floor, and the shipped codec against it, so the
// codec's own overhead (trailer, CRC32C, buffering) is visible as the
// difference. It depends on no stack and no stored object.
func TestCryptoFloor(t *testing.T) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("dek: %v", err)
	}
	crcTable := crc32.MakeTable(crc32.Castagnoli)

	codec, err := dataencryption.NewCodec(dek, "perf/cryptofloor.bin")
	if err != nil {
		t.Fatalf("codec: %v", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}

	for _, size := range cryptoFloorSizes {
		plain := make([]byte, size)
		if _, err := rand.Read(plain); err != nil {
			t.Fatalf("plaintext: %v", err)
		}

		// Ciphertext buffers reused across repetitions so allocation noise does
		// not land in the throughput number.
		segOut := make([]byte, 0, size+((size/segmentSize)+1)*int64(gcm.NonceSize()+gcm.Overhead()))
		// Every variant seals or opens into a buffer it reuses. Letting one
		// variant allocate while another reuses measures the allocator, not the
		// cipher: the rows scattered by 50-70 % until this was equalised.
		segPlain := make([]byte, 0, size)

		// The real codec, sealed once so the decrypt row has something to open.
		sink := bytes.NewBuffer(make([]byte, 0, size+size/segmentSize*28+64))
		cw := codec.NewWriter(sink)
		if _, err := cw.Write(plain); err != nil {
			t.Fatalf("codec prime: %v", err)
		}
		if err := cw.Close(); err != nil {
			t.Fatalf("codec prime: %v", err)
		}
		codecSealed := append([]byte(nil), sink.Bytes()...)

		type variant struct {
			op   string
			note string
			fn   func() error
		}
		variants := []variant{
			{"gcm_seg_encrypt", "per-segment AES-GCM only, no trailer and no checksum", func() error {
				segOut = sealSegments(segOut[:0], gcm, plain)
				return nil
			}},
			{"gcm_seg_decrypt", "per-segment AES-GCM only, no trailer and no checksum", func() error {
				var err error
				segPlain, err = openSegments(segPlain, gcm, segOut)
				return err
			}},
			{"crc32c", "plaintext checksum the trailer carries", func() error {
				_ = crc32.Checksum(plain, crcTable)
				return nil
			}},
			// The rows above are the floor. These two run the shipped codec, so
			// the difference is what the format costs beyond the cipher: the
			// trailer and the CRC32C pass.
			{"codec_encrypt", "the shipped segment codec, trailer and CRC included", func() error {
				sink.Reset()
				w := codec.NewWriter(sink)
				if _, err := w.Write(plain); err != nil {
					return err
				}
				return w.Close()
			}},
			{"codec_decrypt", "the shipped segment codec, trailer verified", func() error {
				r := codec.NewReader(bytes.NewReader(codecSealed))
				_, err := io.Copy(io.Discard, r)
				return err
			}},
		}

		// Prime the reusable buffers before timing anything.
		segOut = sealSegments(segOut[:0], gcm, plain)
		segPlain, _ = openSegments(segPlain, gcm, segOut)

		mib := float64(size) / (1024 * 1024)
		for _, v := range variants {
			var samples []float64
			for r := 0; r < Reps(); r++ {
				start := time.Now()
				if err := v.fn(); err != nil {
					t.Fatalf("%s at %d: %v", v.op, size, err)
				}
				elapsed := time.Since(start).Seconds()
				if elapsed <= 0 {
					continue
				}
				samples = append(samples, mib/elapsed)
			}
			Record(Measurement{
				Instrument: "cryptofloor", Transport: "n/a", Operation: v.op,
				Subject: "in-process", SizeBytes: size, Unit: "MiB/s",
				Samples: samples, Note: v.note,
			})
		}
		t.Logf("crypto floor at %s recorded", humanBytes(size))
	}

	SetStatus("cryptofloor", "ok", "")
}

// sealSegments models the segment chain: one GCM seal per segment, nonce and
// additional data derived from the segment index.
func sealSegments(dst []byte, gcm cipher.AEAD, plain []byte) []byte {
	nonce := make([]byte, gcm.NonceSize())
	aad := make([]byte, 12)
	for i, off := 0, 0; off < len(plain); i, off = i+1, off+segmentSize {
		end := off + segmentSize
		if end > len(plain) {
			end = len(plain)
		}
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(i))
		binary.BigEndian.PutUint64(aad[4:], uint64(i))
		dst = gcm.Seal(dst, nonce, plain[off:end], aad)
	}
	return dst
}

// openSegments opens the chain into dst, which it reuses across calls. Opening
// each segment into a fresh slice measures the allocator: at 64 KiB segments a
// 128 MiB object is two thousand allocations.
func openSegments(dst []byte, gcm cipher.AEAD, sealed []byte) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())
	aad := make([]byte, 12)
	stride := segmentSize + gcm.Overhead()
	dst = dst[:0]
	for i, off := 0, 0; off < len(sealed); i, off = i+1, off+stride {
		end := off + stride
		if end > len(sealed) {
			end = len(sealed)
		}
		binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(i))
		binary.BigEndian.PutUint64(aad[4:], uint64(i))
		var err error
		dst, err = gcm.Open(dst, nonce, sealed[off:end], aad)
		if err != nil {
			return dst, err
		}
	}
	return dst, nil
}
