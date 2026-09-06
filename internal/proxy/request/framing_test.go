package request

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Wire formats emitted by real S3 clients. aws-sdk-go-v2 picks the unsigned
// trailer variant for any non-empty stream over HTTPS (RequestChecksumCalculation
// defaults to WhenSupported), which is what Velero and every other current Go
// client sends. The signed variants come from older SDKs and from clients that
// explicitly opt into payload signing.
const (
	shaStreamingSigned          = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	shaStreamingSignedTrailer   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	shaStreamingUnsignedTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

// framing describes one aws-chunked wire format together with the headers a
// client sends alongside it.
type framing struct {
	name string
	// headers returns the request headers for a payload of the given length.
	headers func(payloadLen int) map[string]string
	// build wraps payload in this framing, splitting it into chunkSize pieces.
	build func(payload []byte, chunkSize int) []byte
}

func crc32Trailer(payload []byte) string {
	sum := crc32.ChecksumIEEE(payload)
	b := []byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}
	return base64.StdEncoding.EncodeToString(b)
}

// writeChunks writes the data chunks common to every variant. sigSuffix is
// appended to each size line (empty for the unsigned variants).
func writeChunks(buf *bytes.Buffer, payload []byte, chunkSize int, sigSuffix string) {
	if chunkSize <= 0 {
		chunkSize = len(payload)
	}
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		fmt.Fprintf(buf, "%x%s\r\n", len(chunk), sigSuffix)
		buf.Write(chunk)
		buf.WriteString("\r\n")
	}
}

func chunkedHeaders(sha string) func(int) map[string]string {
	return func(payloadLen int) map[string]string {
		return map[string]string{
			"Content-Encoding":             "aws-chunked",
			"X-Amz-Content-Sha256":         sha,
			"X-Amz-Decoded-Content-Length": strconv.Itoa(payloadLen),
			"Content-Type":                 "application/octet-stream",
		}
	}
}

// allFramings covers every aws-chunked variant the proxy can receive.
var allFramings = []framing{
	{
		name:    "signed",
		headers: chunkedHeaders(shaStreamingSigned),
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, ";chunk-signature=deadbeef")
			buf.WriteString("0;chunk-signature=deadbeef\r\n\r\n")
			return buf.Bytes()
		},
	},
	{
		name: "signed_with_trailer",
		headers: func(n int) map[string]string {
			h := chunkedHeaders(shaStreamingSignedTrailer)(n)
			h["X-Amz-Trailer"] = "x-amz-checksum-crc32"
			return h
		},
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, ";chunk-signature=deadbeef")
			buf.WriteString("0;chunk-signature=deadbeef\r\n")
			fmt.Fprintf(&buf, "x-amz-checksum-crc32:%s\r\n", crc32Trailer(payload))
			buf.WriteString("x-amz-trailer-signature:deadbeef\r\n")
			buf.WriteString("\r\n")
			return buf.Bytes()
		},
	},
	{
		// The BUG-001 case: no chunk signatures anywhere, so body sniffing cannot
		// detect it. This is the default for aws-sdk-go-v2 over HTTPS.
		name: "unsigned_with_trailer",
		headers: func(n int) map[string]string {
			h := chunkedHeaders(shaStreamingUnsignedTrailer)(n)
			h["X-Amz-Trailer"] = "x-amz-checksum-crc32"
			return h
		},
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, "")
			buf.WriteString("0\r\n")
			fmt.Fprintf(&buf, "x-amz-checksum-crc32:%s\r\n", crc32Trailer(payload))
			buf.WriteString("\r\n")
			return buf.Bytes()
		},
	},
	{
		// Some clients omit the blank line that terminates the trailer block.
		name: "unsigned_trailer_without_final_crlf",
		headers: func(n int) map[string]string {
			h := chunkedHeaders(shaStreamingUnsignedTrailer)(n)
			h["X-Amz-Trailer"] = "x-amz-checksum-crc32"
			return h
		},
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, "")
			buf.WriteString("0\r\n")
			fmt.Fprintf(&buf, "x-amz-checksum-crc32:%s\r\n", crc32Trailer(payload))
			return buf.Bytes()
		},
	},
	{
		name:    "unsigned_without_trailer",
		headers: chunkedHeaders(shaStreamingUnsignedTrailer),
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, "")
			buf.WriteString("0\r\n\r\n")
			return buf.Bytes()
		},
	},
	{
		// Detection must also work when only Content-Encoding says aws-chunked
		// and the payload hash header is absent.
		name: "content_encoding_only",
		headers: func(n int) map[string]string {
			return map[string]string{
				"Content-Encoding":             "aws-chunked",
				"X-Amz-Decoded-Content-Length": strconv.Itoa(n),
			}
		},
		build: func(payload []byte, chunkSize int) []byte {
			var buf bytes.Buffer
			writeChunks(&buf, payload, chunkSize, "")
			buf.WriteString("0\r\n\r\n")
			return buf.Bytes()
		},
	},
}

// newChunkedRequest builds a PUT carrying framed as its body with f's headers.
func newChunkedRequest(t *testing.T, f framing, payload []byte, framed []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(framed))
	for k, v := range f.headers(len(payload)) {
		r.Header.Set(k, v)
	}
	r.ContentLength = int64(len(framed))
	return r
}
