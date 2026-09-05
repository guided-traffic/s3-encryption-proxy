package dataencryption

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"
)

// TestNewCTRRangeReader_MatchesFullDecryption is the property that makes ranged
// reads of encrypted objects correct: decrypting bytes [off, off+n) directly
// must produce the same plaintext as decrypting everything and slicing.
func TestNewCTRRangeReader_MatchesFullDecryption(t *testing.T) {
	const size = 300_000

	plaintext := make([]byte, size)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	enc := NewAESCTRDataEncryptor()
	encReader, err := enc.EncryptStream(context.Background(), bufioReader(plaintext), dek, nil)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	ciphertext, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if len(ciphertext) != size {
		t.Fatalf("AES-CTR must not change the length: got %d, want %d", len(ciphertext), size)
	}

	iv := enc.(*AESCTRDataEncryptor).GetLastIV()

	cases := []struct {
		name   string
		offset int64
		length int
	}{
		{"start", 0, 64},
		{"block_aligned", 4096, 4096},
		{"mid_block", 1, 31},
		{"offset_15", 15, 1},
		{"offset_16", 16, 1},
		{"offset_17", 17, 100},
		{"kopia_style_small_read", 32, 32},
		{"crosses_many_blocks", 1234, 65536},
		{"to_end", size - 100, 100},
		{"whole_object", 0, size},
		{"single_byte_at_end", size - 1, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := bytes.NewReader(ciphertext[tc.offset : tc.offset+int64(tc.length)])
			r, err := NewCTRRangeReader(src, dek, iv, tc.offset)
			if err != nil {
				t.Fatalf("NewCTRRangeReader: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			want := plaintext[tc.offset : tc.offset+int64(tc.length)]
			if sha256.Sum256(got) != sha256.Sum256(want) {
				t.Fatalf("range [%d,%d) decrypted incorrectly (got %d bytes)",
					tc.offset, tc.offset+int64(tc.length), len(got))
			}
		})
	}
}

// A zero offset must behave exactly like the normal decrypt path.
func TestNewCTRStreamAt_ZeroOffsetEqualsPlainCTR(t *testing.T) {
	plaintext := []byte("the quick brown fox jumps over the lazy dog, twice over")
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand: %v", err)
	}

	enc := NewAESCTRDataEncryptor()
	encReader, err := enc.EncryptStream(context.Background(), bufioReader(plaintext), dek, nil)
	if err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	ciphertext, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	iv := enc.(*AESCTRDataEncryptor).GetLastIV()

	r, err := NewCTRRangeReader(bytes.NewReader(ciphertext), dek, iv, 0)
	if err != nil {
		t.Fatalf("NewCTRRangeReader: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("offset 0 did not round-trip: %q", got)
	}
}

func TestNewCTRStreamAt_Validation(t *testing.T) {
	goodDEK := make([]byte, 32)
	goodIV := make([]byte, aes.BlockSize)

	cases := map[string]struct {
		dek, iv []byte
		offset  int64
	}{
		"short_dek":       {make([]byte, 16), goodIV, 0},
		"short_iv":        {goodDEK, make([]byte, 8), 0},
		"negative_offset": {goodDEK, goodIV, -1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCTRStreamAt(tc.dek, tc.iv, tc.offset); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// addCounter has to behave like the 128-bit big-endian counter AES-CTR uses,
// including carry propagation across every byte boundary.
func TestAddCounter(t *testing.T) {
	cases := []struct {
		name   string
		iv     []byte
		blocks uint64
		want   []byte
	}{
		{
			"zero", bytes.Repeat([]byte{0}, 16), 0, bytes.Repeat([]byte{0}, 16),
		},
		{
			"one", bytes.Repeat([]byte{0}, 16), 1,
			append(bytes.Repeat([]byte{0}, 15), 1),
		},
		{
			"carry_over_one_byte", append(bytes.Repeat([]byte{0}, 15), 0xff), 1,
			append(bytes.Repeat([]byte{0}, 14), 1, 0),
		},
		{
			"carry_over_two_bytes", append(bytes.Repeat([]byte{0}, 14), 0xff, 0xff), 1,
			append(bytes.Repeat([]byte{0}, 13), 1, 0, 0),
		},
		{
			"large_addend", bytes.Repeat([]byte{0}, 16), 0x0102030405060708,
			append(bytes.Repeat([]byte{0}, 8), 1, 2, 3, 4, 5, 6, 7, 8),
		},
		{
			"wraps_at_the_top", bytes.Repeat([]byte{0xff}, 16), 1, bytes.Repeat([]byte{0}, 16),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := addCounter(tc.iv, tc.blocks)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("addCounter(%x, %d) = %x, want %x", tc.iv, tc.blocks, got, tc.want)
			}
		})
	}
}

// The IV must not be modified in place: it comes from a shared metadata map.
func TestAddCounter_DoesNotMutateInput(t *testing.T) {
	iv := bytes.Repeat([]byte{0xff}, 16)
	original := append([]byte(nil), iv...)
	_ = addCounter(iv, 12345)
	if !bytes.Equal(iv, original) {
		t.Fatal("addCounter modified the IV in place")
	}
}

func bufioReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }
