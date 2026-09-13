package request

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// streamingAWSChunkedReader decodes AWS Signature V4 chunked payloads on the fly
// without buffering the entire body. It implements io.Reader over an upstream
// source (typically http.Request.Body) and yields the raw chunk payload bytes.
//
// Format:
//
//	<hex-size>;chunk-signature=<sig>\r\n
//	<chunk-data>\r\n
//	...
//	0;chunk-signature=<sig>\r\n
//	\r\n
//
// Trailer lines after the zero-length chunk are parsed and kept, because a
// checksum trailer is the value the verifier compares against (ADR 0012 D3).
// Per-chunk signatures and x-amz-trailer-signature stay unverified (ADR 0014).
type streamingAWSChunkedReader struct {
	br        *bufio.Reader
	remaining int64
	finished  bool
	trailers  map[string]string
	logger    *logrus.Entry
}

func newStreamingAWSChunkedReader(src io.Reader, logger *logrus.Entry) *streamingAWSChunkedReader {
	return &streamingAWSChunkedReader{
		br:     bufio.NewReaderSize(src, 128*1024),
		logger: logger,
	}
}

// Read implements io.Reader.
func (r *streamingAWSChunkedReader) Read(p []byte) (int, error) {
	if r.finished {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		if err := r.readChunkHeader(); err != nil {
			return 0, err
		}
		if r.finished {
			return 0, io.EOF
		}
	}

	toRead := int64(len(p))
	if toRead > r.remaining {
		toRead = r.remaining
	}
	n, err := r.br.Read(p[:toRead])
	r.remaining -= int64(n)

	if r.remaining == 0 && err == nil {
		if cerr := r.consumeCRLF(); cerr != nil {
			return n, cerr
		}
	}
	if err == io.EOF && !r.finished {
		// Upstream closed mid-stream without a terminator chunk.
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (r *streamingAWSChunkedReader) readChunkHeader() error {
	line, err := r.br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("aws-chunked: read chunk header: %w", err)
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		// Tolerate an extra blank line between chunks.
		line, err = r.br.ReadString('\n')
		if err != nil {
			return fmt.Errorf("aws-chunked: read chunk header after blank: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
	}

	parts := strings.SplitN(line, ";", 2)
	sizeStr := strings.TrimSpace(parts[0])
	size, err := strconv.ParseInt(sizeStr, 16, 64)
	if err != nil {
		return fmt.Errorf("aws-chunked: invalid chunk size %q: %w", sizeStr, err)
	}
	if size < 0 {
		// ParseInt accepts a leading minus; without this guard the negative
		// length reaches p[:toRead] and panics the request goroutine.
		return fmt.Errorf("aws-chunked: negative chunk size %q", sizeStr)
	}

	if size == 0 {
		r.finished = true
		r.readTrailers()
		return nil
	}
	r.remaining = size
	return nil
}

// Bounds on the trailer block. A real one carries one checksum line and a
// signature; anything beyond this is a client spending the proxy's memory, and
// the lines are now kept rather than drained, so they need a ceiling.
const (
	maxTrailerBytes = 8 << 10
	maxTrailerLines = 16
)

// readTrailers collects the trailer block that follows the zero-length chunk.
// It runs before Read reports io.EOF, so a checksum trailer is available to the
// verifier at exactly the moment the verdict is due.
func (r *streamingAWSChunkedReader) readTrailers() {
	read := 0
	for lines := 0; lines < maxTrailerLines && read < maxTrailerBytes; lines++ {
		line, err := r.br.ReadString('\n')
		read += len(line)
		// ReadString returns the data it did read together with io.EOF when the
		// last line carries no terminator, and some clients end the trailer
		// block without one. Parsing before the error check is what keeps that
		// last trailer.
		r.recordTrailer(line)
		if err != nil {
			return
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return
		}
	}
	r.logger.Warn("aws-chunked: trailer block exceeds the bound, the rest is ignored")
}

// recordTrailer keeps a checksum trailer and nothing else. Storing every name a
// client sends would make the map as large as the client cares to make it, and
// the verifier looks up no other name.
func (r *streamingAWSChunkedReader) recordTrailer(line string) {
	line = strings.TrimRight(line, "\r\n")
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return
	}
	name = strings.ToLower(strings.TrimSpace(name))
	// x-amz-trailer-signature carries the prefix but is not a checksum, and is
	// deliberately never verified (ADR 0014).
	if !strings.HasPrefix(name, checksumHeaderPrefix) {
		return
	}
	if r.trailers == nil {
		r.trailers = make(map[string]string, 2)
	}
	r.trailers[name] = strings.TrimSpace(value)
}

// Trailers returns the trailer block, lowercase-keyed. It is only complete once
// Read has reported io.EOF.
func (r *streamingAWSChunkedReader) Trailers() map[string]string {
	return r.trailers
}

func (r *streamingAWSChunkedReader) consumeCRLF() error {
	b, err := r.br.ReadByte()
	if err != nil {
		// EOF where the chunk terminator must be means the upload was cut
		// short; reporting a plain io.EOF would hand the caller a truncated
		// payload as if it were complete.
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	if b == '\r' {
		next, err := r.br.ReadByte()
		if err != nil {
			if err == io.EOF {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if next != '\n' {
			return fmt.Errorf("aws-chunked: expected LF after CR, got %#x", next)
		}
		return nil
	}
	if b == '\n' {
		return nil
	}
	return fmt.Errorf("aws-chunked: expected CRLF after chunk data, got %#x", b)
}

// isAWSChunkedRequest detects aws-chunked uploads purely from headers, so the
// body can still be streamed. Matches Content-Encoding: aws-chunked or the
// STREAMING-* content SHA marker used by AWS SDKs.
func isAWSChunkedRequest(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") {
		return true
	}
	return strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-")
}
