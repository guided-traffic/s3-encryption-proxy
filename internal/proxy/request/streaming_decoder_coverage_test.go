package request

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// ReqfailAfterReader yields data bytes and then fails with err instead of EOF,
// modelling a connection that breaks mid-body.
type ReqfailAfterReader struct {
	data []byte
	off  int
	err  error
}

func (r *ReqfailAfterReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, r.err
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

// A zero-length destination buffer must be a no-op, not consume framing.
func TestReqStreamingAWSChunkedReader_EmptyDestinationBuffer(t *testing.T) {
	r := newStreamingAWSChunkedReader(strings.NewReader("5\r\nhello\r\n0\r\n\r\n"), testLogger())

	n, err := r.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	n, err = r.Read([]byte{})
	if n != 0 || err != nil {
		t.Fatalf("Read(empty) = (%d, %v), want (0, nil)", n, err)
	}

	// The framing must still be intact afterwards.
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// Once the terminator chunk has been seen every further Read must report EOF
// without touching the upstream reader again.
func TestReqStreamingAWSChunkedReader_ReadAfterEOF(t *testing.T) {
	r := newStreamingAWSChunkedReader(strings.NewReader("5\r\nhello\r\n0\r\n\r\n"), testLogger())

	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}

	buf := make([]byte, 16)
	for i := 0; i < 3; i++ {
		n, err := r.Read(buf)
		if n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read after EOF #%d = (%d, %v), want (0, io.EOF)", i, n, err)
		}
	}
}

// An extra blank line between chunks is tolerated (some clients emit one).
func TestReqStreamingAWSChunkedReader_BlankLineBetweenChunks(t *testing.T) {
	body := "5\r\nhello\r\n" + "\r\n" + "5\r\nworld\r\n" + "0\r\n\r\n"

	got, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "helloworld" {
		t.Fatalf("got %q, want %q", got, "helloworld")
	}
}

// Chunk-size lines the parser must accept: upper and lower case hex, padding
// spaces, and a chunk signature or arbitrary extension after the semicolon.
func TestReqStreamingAWSChunkedReader_ChunkHeaderVariants(t *testing.T) {
	cases := map[string]string{
		"lowercase_hex":       "a\r\n0123456789\r\n0\r\n\r\n",
		"uppercase_hex":       "A\r\n0123456789\r\n0\r\n\r\n",
		"leading_zero":        "0a\r\n0123456789\r\n0\r\n\r\n",
		"padded_size":         " a \r\n0123456789\r\n0\r\n\r\n",
		"chunk_signature":     "a;chunk-signature=deadbeef\r\n0123456789\r\n0\r\n\r\n",
		"unknown_extension":   "a;foo=bar;baz\r\n0123456789\r\n0\r\n\r\n",
		"lf_only_terminators": "a\n0123456789\n0\n\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != "0123456789" {
				t.Fatalf("got %q, want %q", got, "0123456789")
			}
		})
	}
}

// Every way of corrupting the byte that must follow the chunk data has to be an
// error: otherwise a truncated upload is stored as a complete object.
func TestReqStreamingAWSChunkedReader_ChunkTerminatorErrors(t *testing.T) {
	cases := map[string]struct {
		body    string
		wantMsg string
	}{
		"cr_without_lf":       {"5\r\nhelloXY\r\n0\r\n\r\n", "expected"},
		"cr_then_wrong_byte":  {"5\r\nhello\rX0\r\n\r\n", "expected LF after CR"},
		"cr_then_eof":         {"5\r\nhello\r", ""},
		"no_terminator_bytes": {"5\r\nhello", ""},
		"garbage_terminator":  {"5\r\nhelloZZ0\r\n\r\n", "expected CRLF after chunk data"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(tc.body), testLogger()))
			if err == nil {
				t.Fatalf("expected an error for %q, got payload %q", tc.body, got)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.wantMsg)
			}
		})
	}
}

// A stream cut short exactly where the chunk terminator belongs must report an
// unexpected EOF, not a clean one.
func TestReqStreamingAWSChunkedReader_TruncationIsUnexpectedEOF(t *testing.T) {
	for _, body := range []string{"5\r\nhello\r", "5\r\nhello"} {
		t.Run(fmt.Sprintf("%q", body), func(t *testing.T) {
			_, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want io.ErrUnexpectedEOF (a truncated body must not look complete)", err)
			}
		})
	}
}

// A blank line followed by EOF is a truncated stream, not an empty chunk.
func TestReqStreamingAWSChunkedReader_BlankLineThenEOF(t *testing.T) {
	_, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader("5\r\nhello\r\n\r\n"), testLogger()))
	if err == nil {
		t.Fatal("expected an error for a stream ending after a blank line")
	}
	if !strings.Contains(err.Error(), "read chunk header after blank") {
		t.Fatalf("error = %q, want it to mention the blank-line header path", err)
	}
}

// An invalid size after a tolerated blank line must still be rejected.
func TestReqStreamingAWSChunkedReader_BlankLineThenInvalidSize(t *testing.T) {
	body := "5\r\nhello\r\n" + "\r\n" + "not-hex\r\n"
	_, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
	if err == nil {
		t.Fatal("expected an error for an invalid size line after a blank line")
	}
	if !strings.Contains(err.Error(), "invalid chunk size") {
		t.Fatalf("error = %q, want it to mention the invalid chunk size", err)
	}
}

// A negative chunk size parses as a number but must not be accepted as a length.
func TestReqStreamingAWSChunkedReader_NegativeChunkSize(t *testing.T) {
	_, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader("-5\r\nhello\r\n0\r\n\r\n"), testLogger()))
	if err == nil {
		t.Fatal("expected an error for a negative chunk size")
	}
}

// An upstream failure that is not EOF must be surfaced verbatim, both while
// reading chunk data and while reading a chunk header.
func TestReqStreamingAWSChunkedReader_UpstreamErrorPropagates(t *testing.T) {
	want := errors.New("connection reset by peer")

	// Each prefix stops the stream at a different position in the framing.
	cases := map[string][]byte{
		"at_start":            nil,
		"before_chunk_header": []byte("5\r\nhello\r\n"),
		"inside_chunk_data":   []byte("100\r\nhello"),
		"at_chunk_terminator": []byte("5\r\nhello"),
		"between_cr_and_lf":   []byte("5\r\nhello\r"),
	}

	for name, prefix := range cases {
		t.Run(name, func(t *testing.T) {
			src := &ReqfailAfterReader{data: prefix, err: want}
			_, err := io.ReadAll(newStreamingAWSChunkedReader(src, testLogger()))
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want the upstream error %v to surface", err, want)
			}
		})
	}
}

// Trailer lines after the terminator chunk are drained, whether or not the
// stream ends with the blank line that closes the trailer block.
func TestReqStreamingAWSChunkedReader_TrailerDrain(t *testing.T) {
	cases := map[string]string{
		"trailer_with_final_crlf":    "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n",
		"trailer_without_final_crlf": "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n",
		"trailer_truncated_mid_line": "5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAA",
		"no_trailer_block":           "5\r\nhello\r\n0\r\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := io.ReadAll(newStreamingAWSChunkedReader(strings.NewReader(body), testLogger()))
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != "hello" {
				t.Fatalf("got %q, want %q", got, "hello")
			}
		})
	}
}

// Reading with a buffer larger than the whole stream must still stop exactly at
// the payload boundary.
func TestReqStreamingAWSChunkedReader_OversizedDestinationBuffer(t *testing.T) {
	payload := randomPayload(t, 3000)
	framed := allFramings[0].build(payload, 512)

	r := newStreamingAWSChunkedReader(bytes.NewReader(framed), testLogger())
	buf := make([]byte, len(framed)*2)

	var out bytes.Buffer
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
	if sha256.Sum256(out.Bytes()) != sha256.Sum256(payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", out.Len(), len(payload))
	}
}
