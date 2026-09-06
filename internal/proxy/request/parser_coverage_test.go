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

// PlaintextContentLength must only claim to know the plaintext size when it
// really does: for an aws-chunked body without X-Amz-Decoded-Content-Length,
// r.ContentLength counts framing bytes the parser strips, so reporting it would
// make a complete upload look truncated.
func TestReqPlaintextContentLength(t *testing.T) {
	cases := []struct {
		name          string
		awsChunked    bool
		headers       map[string]string
		contentLength int64
		wantLen       int64
		wantKnown     bool
	}{
		{
			name:          "decoded_header_wins_over_framed_length",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Decoded-Content-Length": "380000", "Content-Encoding": "aws-chunked"},
			contentLength: 380089,
			wantLen:       380_000,
			wantKnown:     true,
		},
		{
			name:          "zero_decoded_length_is_known",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Decoded-Content-Length": "0", "Content-Encoding": "aws-chunked"},
			contentLength: 45,
			wantLen:       0,
			wantKnown:     true,
		},
		{
			name:          "aws_chunked_without_decoded_header_is_unknown",
			awsChunked:    true,
			headers:       map[string]string{"Content-Encoding": "aws-chunked"},
			contentLength: 4096,
			wantLen:       -1,
			wantKnown:     false,
		},
		{
			name:          "streaming_sha_without_decoded_header_is_unknown",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Content-Sha256": shaStreamingUnsignedTrailer},
			contentLength: 4096,
			wantLen:       -1,
			wantKnown:     false,
		},
		{
			name:          "malformed_decoded_header_on_chunked_is_unknown",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Decoded-Content-Length": "not-a-number", "Content-Encoding": "aws-chunked"},
			contentLength: 4096,
			wantLen:       -1,
			wantKnown:     false,
		},
		{
			name:          "negative_decoded_header_on_chunked_is_unknown",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Decoded-Content-Length": "-7", "Content-Encoding": "aws-chunked"},
			contentLength: 4096,
			wantLen:       -1,
			wantKnown:     false,
		},
		{
			// With decoding disabled the framing is passed through verbatim, so
			// the wire length is the payload length.
			name:          "aws_chunked_but_decoding_disabled_uses_content_length",
			awsChunked:    false,
			headers:       map[string]string{"Content-Encoding": "aws-chunked"},
			contentLength: 4096,
			wantLen:       4096,
			wantKnown:     true,
		},
		{
			name:          "identity_body_uses_content_length",
			awsChunked:    true,
			headers:       nil,
			contentLength: 1234,
			wantLen:       1234,
			wantKnown:     true,
		},
		{
			name:          "identity_empty_body_is_known_zero",
			awsChunked:    true,
			headers:       nil,
			contentLength: 0,
			wantLen:       0,
			wantKnown:     true,
		},
		{
			name:          "unknown_content_length_is_unknown",
			awsChunked:    true,
			headers:       nil,
			contentLength: -1,
			wantLen:       -1,
			wantKnown:     false,
		},
		{
			name:          "malformed_decoded_header_on_identity_falls_back",
			awsChunked:    true,
			headers:       map[string]string{"X-Amz-Decoded-Content-Length": "12abc"},
			contentLength: 99,
			wantLen:       99,
			wantKnown:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testParser(t, tc.awsChunked, false)
			r := newTestRequest(tc.headers)
			r.ContentLength = tc.contentLength

			gotLen, gotKnown := p.PlaintextContentLength(r)
			if gotLen != tc.wantLen || gotKnown != tc.wantKnown {
				t.Fatalf("PlaintextContentLength() = (%d, %v), want (%d, %v)",
					gotLen, gotKnown, tc.wantLen, tc.wantKnown)
			}
		})
	}
}

// DecodedContentLength is only a routing hint, PlaintextContentLength is the
// authority. They must differ exactly where that distinction matters: an
// aws-chunked body with no decoded-length header.
func TestReqDecodedVsPlaintextContentLength_DivergeOnlyWhereDocumented(t *testing.T) {
	p := testParser(t, true, false)
	r := newTestRequest(map[string]string{"Content-Encoding": "aws-chunked"})
	r.ContentLength = 5000

	if got := p.DecodedContentLength(r); got != 5000 {
		t.Fatalf("DecodedContentLength() = %d, want the framed length 5000", got)
	}
	if got, known := p.PlaintextContentLength(r); known || got != -1 {
		t.Fatalf("PlaintextContentLength() = (%d, %v), want (-1, false)", got, known)
	}
}

// The HTTP Transfer-Encoding branch of ReadBody.
func TestReqReadBody_HTTPTransferChunked(t *testing.T) {
	p := testParser(t, true, true)
	payload := randomPayload(t, 50_000)
	framed := ReqbuildHTTPChunked(payload, 4096, "\r\n")

	got, err := p.ReadBody(ReqnewTransferChunkedRequest(framed))
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(payload))
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatal("payload SHA-256 mismatch")
	}
}

// With the HTTP chunked optimisation disabled the framing must be handed
// through verbatim instead of being half-decoded.
func TestReqReadBody_HTTPTransferChunkedDisabled(t *testing.T) {
	p := testParser(t, true, false)
	payload := randomPayload(t, 1024)
	framed := ReqbuildHTTPChunked(payload, 256, "\r\n")

	got, err := p.ReadBody(ReqnewTransferChunkedRequest(framed))
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if !bytes.Equal(got, framed) {
		t.Fatal("disabled HTTP chunked decoder must return the raw framed body")
	}
}

// Malformed HTTP chunked framing must fail rather than be stored as payload.
func TestReqReadBody_HTTPTransferChunkedMalformed(t *testing.T) {
	p := testParser(t, true, true)

	if _, err := p.ReadBody(ReqnewTransferChunkedRequest([]byte("zz\r\nhello\r\n"))); err == nil {
		t.Fatal("expected a decode error, got nil (garbage would be stored as payload)")
	}
}

func TestReqReadBody_HTTPTransferChunkedBodyReadError(t *testing.T) {
	p := testParser(t, true, true)
	r := ReqnewTransferChunkedRequest(nil)
	r.Body = io.NopCloser(&errReader{err: fmt.Errorf("upstream reset")})

	got, err := p.ReadBody(r)
	if err == nil {
		t.Fatal("expected the upstream read error to surface")
	}
	if got != nil {
		t.Fatalf("expected nil payload on error, got %d bytes", len(got))
	}
}

// aws-chunked detection must win over the Transfer-Encoding branch when both
// are enabled and both markers are present.
func TestReqReadBody_AWSChunkedTakesPrecedenceOverTransferEncoding(t *testing.T) {
	p := testParser(t, true, true)
	payload := randomPayload(t, 8192)
	f := allFramings[2] // unsigned_with_trailer
	framed := f.build(payload, 2048)

	r := newChunkedRequest(t, f, payload, framed)
	r.Header.Set("Transfer-Encoding", "chunked")

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// An identity body whose reader fails must surface the error, not a partial
// payload.
func TestReqReadBody_IdentityBodyReadError(t *testing.T) {
	p := testParser(t, true, true)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
	r.Body = io.NopCloser(&errReader{err: fmt.Errorf("connection reset")})

	if _, err := p.ReadBody(r); err == nil {
		t.Fatal("expected the upstream read error to surface")
	}
}

func TestReqReadBody_ZeroLengthBody(t *testing.T) {
	p := testParser(t, true, true)

	t.Run("identity", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader(""))
		r.ContentLength = 0

		got, err := p.ReadBody(r)
		if err != nil {
			t.Fatalf("ReadBody: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected an empty body, got %d bytes", len(got))
		}
	})

	t.Run("aws_chunked_terminator_only", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("0\r\n\r\n"))
		r.Header.Set("X-Amz-Content-Sha256", shaStreamingUnsignedTrailer)
		r.Header.Set("X-Amz-Decoded-Content-Length", "0")

		got, err := p.ReadBody(r)
		if err != nil {
			t.Fatalf("ReadBody: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected an empty payload, got %d bytes", len(got))
		}
	})
}

// A forged X-Amz-Decoded-Content-Length must not drive a huge allocation, and
// must not truncate or pad the real payload either.
func TestReqReadBody_ForgedDecodedContentLength(t *testing.T) {
	p := testParser(t, true, false)
	payload := randomPayload(t, 4096)
	f := allFramings[0] // signed
	framed := f.build(payload, 1024)

	r := newChunkedRequest(t, f, payload, framed)
	r.Header.Set("X-Amz-Decoded-Content-Length", "1099511627776") // 1 TiB

	got, err := p.ReadBody(r)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if sha256.Sum256(got) != sha256.Sum256(payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if cap(got) > maxBodyPrealloc+len(payload) {
		t.Fatalf("allocated %d bytes for a %d byte payload", cap(got), len(payload))
	}
}

// StreamingReader must hand identity bodies through untouched, including when
// the request carries a Transfer-Encoding header (net/http already decoded it).
func TestReqStreamingReader_PassThrough(t *testing.T) {
	payload := randomPayload(t, 10_000)

	t.Run("identity", func(t *testing.T) {
		p := testParser(t, true, true)
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(payload))

		got, err := io.ReadAll(p.StreamingReader(r))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatal("identity body was modified")
		}
	})

	t.Run("transfer_encoding_chunked_is_transparent", func(t *testing.T) {
		p := testParser(t, true, true)
		r := ReqnewTransferChunkedRequest(payload)

		got, err := io.ReadAll(p.StreamingReader(r))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if sha256.Sum256(got) != sha256.Sum256(payload) {
			t.Fatal("StreamingReader must not re-decode a body net/http already decoded")
		}
	})

	t.Run("aws_chunked_disabled_returns_raw_framing", func(t *testing.T) {
		p := testParser(t, false, false)
		f := allFramings[2]
		framed := f.build(payload, 4096)

		got, err := io.ReadAll(p.StreamingReader(newChunkedRequest(t, f, payload, framed)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, framed) {
			t.Fatal("disabled decoder must stream the raw framed body")
		}
	})
}

// Malformed aws-chunked framing must surface as a read error on the stream, so
// the caller cannot store framing bytes as plaintext.
func TestReqStreamingReader_MalformedFramingErrors(t *testing.T) {
	p := testParser(t, true, false)
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("zzz\r\nhello\r\n"))
	r.Header.Set("Content-Encoding", "aws-chunked")

	if _, err := io.ReadAll(p.StreamingReader(r)); err == nil {
		t.Fatal("expected a decode error, got nil")
	}
}

func TestReqReadAllSized_HintBoundaries(t *testing.T) {
	payload := randomPayload(t, 1024)

	cases := []struct {
		name string
		hint int64
	}{
		{"no_hint", 0},
		{"negative_hint", -1},
		{"exact_hint", 1024},
		{"undersized_hint", 8},
		{"hint_at_cap", maxBodyPrealloc},
		{"hint_above_cap", maxBodyPrealloc + 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readAllSized(bytes.NewReader(payload), tc.hint)
			if err != nil {
				t.Fatalf("readAllSized: %v", err)
			}
			if sha256.Sum256(got) != sha256.Sum256(payload) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
			}
			if cap(got) > maxBodyPrealloc+len(payload) {
				t.Fatalf("allocated %d bytes for a %d byte body", cap(got), len(payload))
			}
		})
	}
}
