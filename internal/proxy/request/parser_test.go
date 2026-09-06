package request

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
)

func testParser(t *testing.T, awsChunked, httpChunked bool) *Parser {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return NewParser(logrus.NewEntry(logger), &config.Config{
		Optimizations: config.OptimizationsConfig{
			CleanAWSSignatureV4Chunked: awsChunked,
			CleanHTTPTransferChunked:   httpChunked,
		},
	})
}

func randomPayload(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestReadBody_AWSChunkedFramings is the regression test for BUG-001: every
// framing a real client can send must come back out of ReadBody as the exact
// plaintext, byte for byte. Before the fix the unsigned variants were stored
// with their framing bytes included, which corrupted Velero backup metadata.
func TestReadBody_AWSChunkedFramings(t *testing.T) {
	p := testParser(t, true, false)

	sizes := []struct {
		name      string
		size      int
		chunkSize int
	}{
		{"single_chunk_380k", 380_000, 380_000},
		{"chunks_64k", 380_000, 64 * 1024},
		{"chunks_8k", 100_000, 8 * 1024},
		{"exact_chunk_boundary", 65536, 65536},
		{"tiny", 1, 1},
		{"empty", 0, 1},
	}

	for _, f := range allFramings {
		for _, s := range sizes {
			t.Run(f.name+"/"+s.name, func(t *testing.T) {
				payload := randomPayload(t, s.size)
				framed := f.build(payload, s.chunkSize)
				r := newChunkedRequest(t, f, payload, framed)

				got, err := p.ReadBody(r)
				if err != nil {
					t.Fatalf("ReadBody: %v", err)
				}
				if len(got) != len(payload) {
					t.Fatalf("length mismatch: got %d bytes, want %d (framing overhead leaked into payload)",
						len(got), len(payload))
				}
				if sha256.Sum256(got) != sha256.Sum256(payload) {
					t.Fatal("payload SHA-256 mismatch")
				}
			})
		}
	}
}

// Chunk data containing CRLF must not be mistaken for a framing boundary.
func TestReadBody_AWSChunked_PayloadContainsCRLF(t *testing.T) {
	p := testParser(t, true, false)
	payload := []byte("line one\r\n0\r\nline two\r\n\r\n8000;chunk-signature=nope\r\ntail")

	for _, f := range allFramings {
		t.Run(f.name, func(t *testing.T) {
			framed := f.build(payload, 7) // split mid-CRLF on purpose
			r := newChunkedRequest(t, f, payload, framed)

			got, err := p.ReadBody(r)
			if err != nil {
				t.Fatalf("ReadBody: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// A plain (identity) body must pass through untouched even with aws-chunked
// decoding enabled.
func TestReadBody_IdentityBody(t *testing.T) {
	p := testParser(t, true, true)
	payload := randomPayload(t, 4096)

	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
	r.ContentLength = int64(len(payload))

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("identity payload was modified")
	}
}

// With the aws-chunked optimisation disabled the framing must be handed through
// verbatim rather than silently half-decoded.
func TestReadBody_AWSChunkedDisabled(t *testing.T) {
	p := testParser(t, false, false)
	payload := randomPayload(t, 1024)
	f := allFramings[2] // unsigned_with_trailer
	framed := f.build(payload, 512)
	r := newChunkedRequest(t, f, payload, framed)

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if !bytes.Equal(got, framed) {
		t.Fatal("disabled decoder must return the raw framed body")
	}
}

func TestReadBody_NilBody(t *testing.T) {
	p := testParser(t, true, false)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
	r.Body = nil

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil body, got %d bytes", len(got))
	}
}

// A request that claims aws-chunked but carries garbage must fail loudly rather
// than storing the garbage as payload.
func TestReadBody_AWSChunked_MalformedFraming(t *testing.T) {
	p := testParser(t, true, false)

	cases := map[string]string{
		"invalid_hex_size":     "zzzz\r\npayload\r\n0\r\n\r\n",
		"truncated_chunk_data": "100\r\nshort",
		"no_terminator":        "5\r\nhello\r\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader(body))
			r.Header.Set("X-Amz-Content-Sha256", shaStreamingUnsignedTrailer)
			r.Header.Set("Content-Encoding", "aws-chunked")

			if _, err := p.ReadBody(r); err == nil {
				t.Fatal("expected a decode error, got nil (garbage would be stored as payload)")
			}
		})
	}
}

// The body must be consumed exactly once. A double read would silently truncate
// the payload; the old sniffing detector read it twice.
func TestReadBody_ReadsBodyOnce(t *testing.T) {
	p := testParser(t, true, false)
	payload := randomPayload(t, 200_000)
	f := allFramings[2] // unsigned_with_trailer
	framed := f.build(payload, 64*1024)

	counter := &countingReader{r: bytes.NewReader(framed)}
	r := newChunkedRequest(t, f, payload, framed)
	r.Body = io.NopCloser(counter)

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("payload mismatch")
	}
	if counter.bytes > len(framed) {
		t.Fatalf("body read %d bytes for a %d byte request: it was read more than once",
			counter.bytes, len(framed))
	}
}

type countingReader struct {
	r     io.Reader
	bytes int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.bytes += n
	return n, err
}

// StreamingReader must decode the same framings without buffering.
func TestStreamingReader_AWSChunkedFramings(t *testing.T) {
	p := testParser(t, true, false)
	payload := randomPayload(t, 300_000)

	for _, f := range allFramings {
		t.Run(f.name, func(t *testing.T) {
			framed := f.build(payload, 64*1024)
			r := newChunkedRequest(t, f, payload, framed)

			got, err := io.ReadAll(p.StreamingReader(r))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if sha256.Sum256(got) != sha256.Sum256(payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
		})
	}
}

// ReadBody and StreamingReader must agree on every framing — the proxy picks
// between them purely by object size, so a divergence is silent corruption for
// exactly one size class.
func TestReadBody_And_StreamingReader_Agree(t *testing.T) {
	p := testParser(t, true, false)
	payload := randomPayload(t, 150_000)

	for _, f := range allFramings {
		t.Run(f.name, func(t *testing.T) {
			framed := f.build(payload, 16*1024)

			buffered, err := p.ReadBody(newChunkedRequest(t, f, payload, framed))
			if err != nil {
				t.Fatalf("ReadBody: %v", err)
			}
			streamed, err := io.ReadAll(p.StreamingReader(newChunkedRequest(t, f, payload, framed)))
			if err != nil {
				t.Fatalf("StreamingReader: %v", err)
			}
			if sha256.Sum256(buffered) != sha256.Sum256(streamed) {
				t.Fatalf("buffered (%d bytes) and streamed (%d bytes) paths disagree",
					len(buffered), len(streamed))
			}
		})
	}
}

func TestStreamingReader_NilBody(t *testing.T) {
	p := testParser(t, true, false)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
	r.Body = nil

	got, err := io.ReadAll(p.StreamingReader(r))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty stream, got %d bytes", len(got))
	}
}

func TestDecodedContentLength(t *testing.T) {
	p := testParser(t, true, false)

	cases := []struct {
		name          string
		header        string
		contentLength int64
		want          int64
	}{
		{"decoded_header_wins", "380000", 380089, 380_000},
		{"zero_decoded_length", "0", 45, 0},
		{"no_header_falls_back", "", 1234, 1234},
		{"invalid_header_falls_back", "not-a-number", 1234, 1234},
		{"negative_header_falls_back", "-5", 1234, 1234},
		{"unknown_length", "", -1, -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
			if tc.header != "" {
				r.Header.Set("X-Amz-Decoded-Content-Length", tc.header)
			}
			r.ContentLength = tc.contentLength

			if got := p.DecodedContentLength(r); got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestResetBody(t *testing.T) {
	p := testParser(t, true, false)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("original"))

	p.ResetBody(r, []byte("replacement"))

	if r.ContentLength != int64(len("replacement")) {
		t.Fatalf("ContentLength = %d, want %d", r.ContentLength, len("replacement"))
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "replacement" {
		t.Fatalf("body = %q", got)
	}
}

func TestGetMetadataPrefix(t *testing.T) {
	custom := "mycompany-"
	empty := ""

	cases := []struct {
		name   string
		prefix *string
		want   string
	}{
		{"default", nil, "s3ep-"},
		{"custom", &custom, "mycompany-"},
		{"explicitly_empty", &empty, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			p := NewParser(logrus.NewEntry(logger), &config.Config{
				Encryption: config.EncryptionConfig{MetadataKeyPrefix: tc.prefix},
			})
			if got := p.GetMetadataPrefix(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// readAllSized must never over-allocate from an attacker-controlled length hint.
func TestReadAllSized_PreallocationIsCapped(t *testing.T) {
	payload := []byte("small")
	got, err := readAllSized(bytes.NewReader(payload), 1<<40) // 1 TiB claimed
	if err != nil {
		t.Fatalf("readAllSized: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if cap(got) > maxBodyPrealloc+len(payload) {
		t.Fatalf("allocated %d bytes for a %d byte body", cap(got), len(payload))
	}
}

func TestReadAllSized_PropagatesError(t *testing.T) {
	want := fmt.Errorf("boom")
	if _, err := readAllSized(&errReader{err: want}, 10); err == nil {
		t.Fatal("expected error")
	}
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }
