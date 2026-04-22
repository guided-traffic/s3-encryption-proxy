package request

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// buildAWSChunked builds a single-chunk aws-chunked framing around payload.
// Signatures are placeholders — the streaming decoder does not verify them.
func buildAWSChunked(t *testing.T, payload []byte, chunkSize int) []byte {
	t.Helper()
	var buf bytes.Buffer
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		fmt.Fprintf(&buf, "%x;chunk-signature=deadbeef\r\n", len(chunk))
		buf.Write(chunk)
		buf.WriteString("\r\n")
	}
	buf.WriteString("0;chunk-signature=deadbeef\r\n\r\n")
	return buf.Bytes()
}

func TestStreamingAWSChunkedReader_RoundTrip(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	tests := []struct {
		name      string
		size      int
		chunkSize int
	}{
		{"empty", 0, 1},
		{"single_small_chunk", 42, 128},
		{"exact_chunk_boundary", 4096, 4096},
		{"many_small_chunks", 100_000, 1024},
		{"single_large_chunk", 5 * 1024 * 1024, 5 * 1024 * 1024},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plaintext := make([]byte, tc.size)
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatalf("rand: %v", err)
			}
			framed := buildAWSChunked(t, plaintext, tc.chunkSize)

			reader := newStreamingAWSChunkedReader(bytes.NewReader(framed), logger)
			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if sha256.Sum256(got) != sha256.Sum256(plaintext) {
				t.Fatalf("decoded payload mismatch (got %d bytes, want %d)", len(got), len(plaintext))
			}
		})
	}
}

func TestStreamingAWSChunkedReader_InvalidSize(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	bad := strings.NewReader("zz;chunk-signature=abc\r\nhello\r\n0;chunk-signature=abc\r\n\r\n")
	reader := newStreamingAWSChunkedReader(bad, logger)
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected error on invalid chunk size")
	}
}

func TestStreamingAWSChunkedReader_TruncatedMidChunk(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	// Declare 10 bytes but only supply 3.
	reader := newStreamingAWSChunkedReader(strings.NewReader("a;chunk-signature=deadbeef\r\nabc"), logger)
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("expected error on truncated chunk")
	}
}

func TestIsAWSChunkedRequest_Headers(t *testing.T) {
	cases := map[string]map[string]string{
		"content_encoding":       {"Content-Encoding": "aws-chunked"},
		"content_encoding_mixed": {"Content-Encoding": "aws-chunked, identity"},
		"streaming_sha":          {"X-Amz-Content-Sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
		"streaming_sha_variant":  {"X-Amz-Content-Sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER"},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTestRequest(headers)
			if !isAWSChunkedRequest(r) {
				t.Fatalf("expected aws-chunked detection for headers %v", headers)
			}
		})
	}

	t.Run("identity", func(t *testing.T) {
		r := newTestRequest(nil)
		if isAWSChunkedRequest(r) {
			t.Fatal("identity request misdetected as aws-chunked")
		}
	})
}
