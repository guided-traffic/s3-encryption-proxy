package request

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ReqbuildHTTPChunked frames payload as RFC 7230 Transfer-Encoding: chunked
// using chunks of chunkSize bytes and the given line terminator.
func ReqbuildHTTPChunked(payload []byte, chunkSize int, eol string) []byte {
	if chunkSize <= 0 {
		chunkSize = len(payload)
	}
	var buf bytes.Buffer
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		fmt.Fprintf(&buf, "%x%s", len(chunk), eol)
		buf.Write(chunk)
		buf.WriteString(eol)
	}
	buf.WriteString("0" + eol + eol)
	return buf.Bytes()
}

// ReqnewTransferChunkedRequest builds a PUT that still carries the
// Transfer-Encoding header (net/http strips it on real server requests, so it
// has to be set by hand here).
func ReqnewTransferChunkedRequest(body []byte) *http.Request {
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(body))
	r.Header.Set("Transfer-Encoding", "chunked")
	r.ContentLength = int64(len(body))
	return r
}

func TestReqHTTPChunkedDecoder_GetName(t *testing.T) {
	if got := NewHTTPChunkedDecoder(testLogger()).GetName(); got != "HTTP-Chunked" {
		t.Fatalf("GetName() = %q, want %q", got, "HTTP-Chunked")
	}
}

// The decoder must satisfy the interface the parser selects it through.
func TestReqHTTPChunkedDecoder_ImplementsInterface(t *testing.T) {
	var d ChunkedDecoder = NewHTTPChunkedDecoder(testLogger())
	if d.GetName() == "" {
		t.Fatal("interface value lost its identity")
	}
	if base := NewChunkedDecoderBase(testLogger()); base.logger == nil {
		t.Fatal("NewChunkedDecoderBase dropped the logger")
	}
}

func TestReqHTTPChunkedDecoder_RequiresChunkedDecoding(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   bool
	}{
		{"chunked", "chunked", true},
		{"chunked_uppercase", "CHUNKED", true},
		{"chunked_mixed_case", "Chunked", true},
		{"absent", "", false},
		{"identity", "identity", false},
		{"gzip", "gzip", false},
		// EqualFold matches the whole value, so a list is not recognised.
		{"list_with_chunked", "gzip, chunked", false},
	}

	d := NewHTTPChunkedDecoder(testLogger())
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.header != "" {
				headers["Transfer-Encoding"] = tc.header
			}
			if got := d.RequiresChunkedDecoding(newTestRequest(headers)); got != tc.want {
				t.Fatalf("RequiresChunkedDecoding(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}

// Round trip: every framing variation must come back as the exact payload.
func TestReqHTTPChunkedDecoder_ProcessChunkedData_RoundTrip(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())

	cases := []struct {
		name      string
		size      int
		chunkSize int
		eol       string
	}{
		{"single_chunk_crlf", 512, 512, "\r\n"},
		{"many_chunks_crlf", 100_000, 4096, "\r\n"},
		{"chunk_size_one", 64, 1, "\r\n"},
		{"lf_only_terminators", 3000, 512, "\n"},
		{"exact_boundary", 8192, 8192, "\r\n"},
		{"empty_payload", 0, 1, "\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := randomPayload(t, tc.size)
			framed := ReqbuildHTTPChunked(payload, tc.chunkSize, tc.eol)

			got, err := d.ProcessChunkedData(framed)
			if err != nil {
				t.Fatalf("ProcessChunkedData: %v", err)
			}
			if len(got) != len(payload) {
				t.Fatalf("length mismatch: got %d, want %d (framing leaked into payload)", len(got), len(payload))
			}
			if sha256.Sum256(got) != sha256.Sum256(payload) {
				t.Fatal("payload SHA-256 mismatch")
			}
		})
	}
}

// Chunk data that itself looks like framing must not be re-interpreted.
func TestReqHTTPChunkedDecoder_ProcessChunkedData_PayloadLooksLikeFraming(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())
	payload := []byte("0\r\n\r\nff\r\nnot a chunk\r\n")
	framed := ReqbuildHTTPChunked(payload, 5, "\r\n")

	got, err := d.ProcessChunkedData(framed)
	if err != nil {
		t.Fatalf("ProcessChunkedData: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestReqHTTPChunkedDecoder_ProcessChunkedData_Terminators(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())

	cases := map[string]string{
		"zero_length_input":       "",
		"terminator_only":         "0\r\n\r\n",
		"terminator_without_crlf": "0\r\n",
		"terminator_with_lf_only": "0\n",
		"multi_digit_zero":        "00\r\n\r\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := d.ProcessChunkedData([]byte(body))
			if err != nil {
				t.Fatalf("ProcessChunkedData: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("expected empty payload, got %d bytes (%q)", len(got), got)
			}
		})
	}
}

// A chunk whose trailing CRLF is missing is tolerated (the decoder logs and
// keeps the data it already read).
func TestReqHTTPChunkedDecoder_ProcessChunkedData_MissingTrailingCRLF(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())

	got, err := d.ProcessChunkedData([]byte("5\r\nhello"))
	if err != nil {
		t.Fatalf("ProcessChunkedData: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// Deliberately malformed framing must produce an error, never a panic and never
// silently accepted garbage.
func TestReqHTTPChunkedDecoder_ProcessChunkedData_Malformed(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())

	cases := map[string]struct {
		body    string
		wantMsg string
	}{
		"non_hex_size":       {"zz\r\nhello\r\n0\r\n\r\n", "invalid HTTP chunk size"},
		"text_size_line":     {"not-a-size\r\npayload\r\n", "invalid HTTP chunk size"},
		"empty_size_line":    {"\r\n5\r\nhello\r\n", "invalid HTTP chunk size"},
		"negative_size":      {"-1\r\nhello\r\n0\r\n\r\n", "negative HTTP chunk size"},
		"truncated_chunk":    {"100\r\nshort", "failed to read chunk data"},
		"size_exceeds_body":  {"7fffffffffffffff\r\nshort\r\n", "failed to read chunk data"},
		"second_chunk_short": {"5\r\nhello\r\n20\r\ntoo short\r\n", "failed to read chunk data"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := d.ProcessChunkedData([]byte(tc.body))
			if err == nil {
				t.Fatalf("expected an error, got %d bytes of payload (%q)", len(got), got)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantMsg)
			}
			if got != nil {
				t.Fatalf("expected nil payload on error, got %q", got)
			}
		})
	}
}

// A forged multi-gigabyte chunk size must not be pre-allocated: the decoder has
// to fail on the short body instead of reserving the claimed length.
func TestReqHTTPChunkedDecoder_ProcessChunkedData_NoHugePreallocation(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())

	// 0x40000000 = 1 GiB claimed, 5 bytes delivered.
	if _, err := d.ProcessChunkedData([]byte("40000000\r\nhello\r\n")); err == nil {
		t.Fatal("expected an error for a chunk size larger than the body")
	}
}

func TestReqHTTPChunkedDecoder_CreateOptimalReader(t *testing.T) {
	d := NewHTTPChunkedDecoder(testLogger())
	payload := randomPayload(t, 20_000)

	t.Run("not_chunked_passes_through", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))
		got, err := io.ReadAll(d.CreateOptimalReader(r))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatal("identity body was modified")
		}
	})

	t.Run("chunked_is_decoded", func(t *testing.T) {
		framed := ReqbuildHTTPChunked(payload, 4096, "\r\n")
		got, err := io.ReadAll(d.CreateOptimalReader(ReqnewTransferChunkedRequest(framed)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatalf("decoded payload mismatch: got %d bytes, want %d", len(got), len(payload))
		}
	})

	t.Run("malformed_falls_back_to_raw_bytes", func(t *testing.T) {
		framed := []byte("zz\r\nhello\r\n")
		got, err := io.ReadAll(d.CreateOptimalReader(ReqnewTransferChunkedRequest(framed)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, framed) {
			t.Fatalf("fallback returned %q, want the raw framed body %q", got, framed)
		}
	})

	t.Run("body_read_error_returns_body", func(t *testing.T) {
		r := ReqnewTransferChunkedRequest(nil)
		r.Body = io.NopCloser(&errReader{err: fmt.Errorf("upstream reset")})

		if _, err := io.ReadAll(d.CreateOptimalReader(r)); err == nil {
			t.Fatal("expected the upstream read error to surface")
		}
	})
}
