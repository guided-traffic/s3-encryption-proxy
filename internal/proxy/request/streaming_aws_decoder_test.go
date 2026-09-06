package request

import (
	"bytes"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return logrus.NewEntry(l)
}

// TestStreamingAWSChunkedReader_RoundTrip runs every wire format the proxy can
// receive through the streaming decoder at a range of chunk sizes.
func TestStreamingAWSChunkedReader_RoundTrip(t *testing.T) {
	logger := testLogger()

	sizes := []struct {
		name      string
		size      int
		chunkSize int
	}{
		{"empty", 0, 1},
		{"single_small_chunk", 42, 128},
		{"exact_chunk_boundary", 4096, 4096},
		{"many_small_chunks", 100_000, 1024},
		{"sdk_default_64k_chunks", 380_000, 64 * 1024},
		{"single_large_chunk", 5 * 1024 * 1024, 5 * 1024 * 1024},
	}

	for _, f := range allFramings {
		for _, s := range sizes {
			t.Run(f.name+"/"+s.name, func(t *testing.T) {
				plaintext := randomPayload(t, s.size)
				framed := f.build(plaintext, s.chunkSize)

				got, err := io.ReadAll(newStreamingAWSChunkedReader(bytes.NewReader(framed), logger))
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}
				if sha256.Sum256(got) != sha256.Sum256(plaintext) {
					t.Fatalf("decoded payload mismatch (got %d bytes, want %d)", len(got), len(plaintext))
				}
			})
		}
	}
}

// Reading with a tiny destination buffer must not lose or duplicate bytes at
// chunk boundaries.
func TestStreamingAWSChunkedReader_SmallReads(t *testing.T) {
	logger := testLogger()
	plaintext := randomPayload(t, 20_000)

	for _, f := range allFramings {
		t.Run(f.name, func(t *testing.T) {
			framed := f.build(plaintext, 4096)
			r := newStreamingAWSChunkedReader(bytes.NewReader(framed), logger)

			var out bytes.Buffer
			buf := make([]byte, 7)
			for {
				n, err := r.Read(buf)
				out.Write(buf[:n])
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
			}
			if sha256.Sum256(out.Bytes()) != sha256.Sum256(plaintext) {
				t.Fatalf("payload mismatch (got %d bytes, want %d)", out.Len(), len(plaintext))
			}
		})
	}
}

// Multiple trailer lines after the terminator chunk must all be drained.
func TestStreamingAWSChunkedReader_MultipleTrailers(t *testing.T) {
	body := "5\r\nhello\r\n0\r\n" +
		"x-amz-checksum-crc32:AAAAAA==\r\n" +
		"x-amz-checksum-crc32c:BBBBBB==\r\n" +
		"x-amz-trailer-signature:deadbeef\r\n\r\n"

	got, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want \"hello\"", got)
	}
}

func TestStreamingAWSChunkedReader_Errors(t *testing.T) {
	cases := map[string]string{
		"invalid_chunk_size":  "zz;chunk-signature=abc\r\nhello\r\n0;chunk-signature=abc\r\n\r\n",
		"truncated_mid_chunk": "a;chunk-signature=deadbeef\r\nabc",
		"missing_terminator":  "5\r\nhello\r\n",
		"empty_stream":        "",
		"garbage_size_line":   "not-a-chunk-header\r\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := newStreamingAWSChunkedReader(strings.NewReader(body), testLogger())
			if _, err := io.ReadAll(r); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

// A chunk whose declared size does not match the data must not silently succeed.
func TestStreamingAWSChunkedReader_SizeMismatch(t *testing.T) {
	// Declares 0x10 (16) bytes but the CRLF arrives after 5.
	body := "10\r\nhello\r\n0\r\n\r\n"
	r := newStreamingAWSChunkedReader(strings.NewReader(body), testLogger())
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("expected an error for a short chunk")
	}
}

func TestIsAWSChunkedRequest_Headers(t *testing.T) {
	positive := map[string]map[string]string{
		"content_encoding":       {"Content-Encoding": "aws-chunked"},
		"content_encoding_mixed": {"Content-Encoding": "aws-chunked, identity"},
		"content_encoding_cased": {"Content-Encoding": "AWS-Chunked"},
		"streaming_sha":          {"X-Amz-Content-Sha256": shaStreamingSigned},
		"streaming_sha_trailer":  {"X-Amz-Content-Sha256": shaStreamingSignedTrailer},
		"streaming_sha_unsigned": {"X-Amz-Content-Sha256": shaStreamingUnsignedTrailer},
	}
	for name, headers := range positive {
		t.Run(name, func(t *testing.T) {
			if !isAWSChunkedRequest(newTestRequest(headers)) {
				t.Fatalf("expected aws-chunked detection for headers %v", headers)
			}
		})
	}

	negative := map[string]map[string]string{
		"identity":         nil,
		"gzip":             {"Content-Encoding": "gzip"},
		"unsigned_payload": {"X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD"},
		"sha_hex":          {"X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for name, headers := range negative {
		t.Run(name, func(t *testing.T) {
			if isAWSChunkedRequest(newTestRequest(headers)) {
				t.Fatalf("request with headers %v misdetected as aws-chunked", headers)
			}
		})
	}
}
