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
// Trailing signatures and optional trailers after the zero-length chunk are
// drained best-effort and discarded — the proxy does not re-verify them.
type streamingAWSChunkedReader struct {
	br        *bufio.Reader
	remaining int64
	finished  bool
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

	if size == 0 {
		r.finished = true
		// Drain any remaining trailer lines until a blank CRLF or EOF.
		for {
			tline, terr := r.br.ReadString('\n')
			if terr != nil {
				return nil
			}
			if strings.TrimRight(tline, "\r\n") == "" {
				return nil
			}
		}
	}
	r.remaining = size
	return nil
}

func (r *streamingAWSChunkedReader) consumeCRLF() error {
	b, err := r.br.ReadByte()
	if err != nil {
		return err
	}
	if b == '\r' {
		next, err := r.br.ReadByte()
		if err != nil {
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
