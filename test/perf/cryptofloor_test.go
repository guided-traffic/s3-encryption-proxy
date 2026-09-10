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

	"github.com/guided-traffic/s3-encryption-proxy/internal/validation"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// segmentSize is the plaintext segment of the v2 candidate (ADR 0003).
const segmentSize = 64 * 1024

// cryptoFloorSizes span the routing decisions of the current path: below the
// 5 MiB streaming threshold (AES-GCM whole object), above it (AES-CTR plus
// HMAC), and a multi-part-sized buffer.
var cryptoFloorSizes = []int64{
	64 * 1024,
	1024 * 1024,
	12 * 1024 * 1024,
	128 * 1024 * 1024,
}

// TestCryptoFloor measures the in-process cost of the crypto paths the storage
// format change replaces, against the segmented-GCM candidate that replaces
// them. It is the only "before" that survives the rewrite untouched, because it
// depends on no stack and no stored object.
func TestCryptoFloor(t *testing.T) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("dek: %v", err)
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("hmac key: %v", err)
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
		ctrOut := make([]byte, size)
		gcmWhole := gcm.Seal(nil, make([]byte, gcm.NonceSize()), plain, nil)
		segOut := make([]byte, 0, size+((size/segmentSize)+1)*int64(gcm.NonceSize()+gcm.Overhead()))
		// Every variant seals or opens into a buffer it reuses. Letting one
		// variant allocate while another reuses measures the allocator, not the
		// cipher: the whole-object rows scattered by 50-70 % until this was
		// equalised.
		wholeOut := make([]byte, 0, len(gcmWhole))
		openOut := make([]byte, 0, size)
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
			{"ctr_encrypt", "AES-CTR only", func() error {
				enc, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
				if err != nil {
					return err
				}
				defer enc.Cleanup()
				_, err = enc.EncryptPart(plain)
				return err
			}},
			{"hmac_only", "HMAC-SHA256 over the plaintext", func() error {
				calc, err := validation.NewHMACCalculator(hmacKey)
				if err != nil {
					return err
				}
				defer calc.Cleanup()
				_, err = calc.Add(plain)
				_ = calc.Sum()
				return err
			}},
			{"v1_ctr_hmac_encrypt", "current write path above the threshold", func() error {
				calc, err := validation.NewHMACCalculator(hmacKey)
				if err != nil {
					return err
				}
				defer calc.Cleanup()
				if _, err := calc.Add(plain); err != nil {
					return err
				}
				enc, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
				if err != nil {
					return err
				}
				defer enc.Cleanup()
				if _, err := enc.EncryptPart(plain); err != nil {
					return err
				}
				_ = calc.Sum()
				return nil
			}},
			{"v1_ctr_hmac_decrypt", "current read path above the threshold", func() error {
				enc, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
				if err != nil {
					return err
				}
				defer enc.Cleanup()
				out, err := enc.DecryptPart(ctrOut)
				if err != nil {
					return err
				}
				calc, err := validation.NewHMACCalculator(hmacKey)
				if err != nil {
					return err
				}
				defer calc.Cleanup()
				_, err = calc.Add(out)
				_ = calc.Sum()
				return err
			}},
			{"v1_gcm_whole_encrypt", "current write path below the threshold", func() error {
				wholeOut = gcm.Seal(wholeOut[:0], make([]byte, gcm.NonceSize()), plain, nil)
				return nil
			}},
			{"v1_gcm_whole_decrypt", "current read path below the threshold", func() error {
				var err error
				openOut, err = gcm.Open(openOut[:0], make([]byte, gcm.NonceSize()), gcmWhole, nil)
				return err
			}},
			{"v2_gcm_seg_encrypt", "segmented AES-GCM candidate, 64 KiB segments", func() error {
				segOut = sealSegments(segOut[:0], gcm, plain)
				return nil
			}},
			{"v2_gcm_seg_decrypt", "segmented AES-GCM candidate, 64 KiB segments", func() error {
				var err error
				segPlain, err = openSegments(segPlain, gcm, segOut)
				return err
			}},
			{"crc32c", "plaintext checksum the v2 trailer adds", func() error {
				_ = crc32.Checksum(plain, crcTable)
				return nil
			}},
			// The rows above model the candidate. These two run the real codec,
			// so the comparison stops being a prediction. They include the
			// trailer and the CRC32C pass, which the model rows do not.
			{"v2_codec_encrypt", "the shipped segment codec, trailer and CRC included", func() error {
				sink.Reset()
				w := codec.NewWriter(sink)
				if _, err := w.Write(plain); err != nil {
					return err
				}
				return w.Close()
			}},
			{"v2_codec_decrypt", "the shipped segment codec, trailer verified", func() error {
				r := codec.NewReader(bytes.NewReader(codecSealed))
				_, err := io.Copy(io.Discard, r)
				return err
			}},
		}

		// Prime the reusable buffers before timing anything.
		enc, err := dataencryption.NewAESCTRStatefulEncryptor(dek)
		if err != nil {
			t.Fatalf("ctr prime: %v", err)
		}
		primed, err := enc.EncryptPart(plain)
		if err != nil {
			t.Fatalf("ctr prime: %v", err)
		}
		copy(ctrOut, primed)
		enc.Cleanup()
		segOut = sealSegments(segOut[:0], gcm, plain)
		wholeOut = gcm.Seal(wholeOut[:0], make([]byte, gcm.NonceSize()), plain, nil)
		openOut, _ = gcm.Open(openOut[:0], make([]byte, gcm.NonceSize()), gcmWhole, nil)
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

// sealSegments models the v2 segment chain: one GCM seal per 64 KiB of
// plaintext, nonce and additional data derived from the segment index.
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
