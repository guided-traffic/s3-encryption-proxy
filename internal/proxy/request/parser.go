package request

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
)

// maxBodyPrealloc caps how much memory ReadBody reserves up front from a
// client-supplied length header. Beyond it the buffer grows on demand, so a
// forged X-Amz-Decoded-Content-Length cannot turn into a single huge allocation.
const maxBodyPrealloc = 32 << 20 // 32 MiB

// Parser handles request parsing and body reading
type Parser struct {
	logger *logrus.Entry
	config *config.Config
}

// NewParser creates a new request parser
func NewParser(logger *logrus.Entry, config *config.Config) *Parser {
	return &Parser{
		logger: logger,
		config: config,
	}
}

// ReadBody reads the request body into memory, decoding aws-chunked framing when
// the request carries it.
//
// aws-chunked is detected from headers alone (Content-Encoding / X-Amz-Content-Sha256),
// never by sniffing the body, so the body is read exactly once. Header detection is
// also the only thing that works for STREAMING-UNSIGNED-PAYLOAD-TRAILER: that framing
// carries no per-chunk signatures, so a content sniffer cannot recognise it and would
// store the raw framing bytes as if they were payload.
//
// Prefer StreamingReader for anything that can be large — ReadBody buffers the whole
// decoded payload.
//
// A checksum the request declares is verified against the decoded payload as it
// passes (ADR 0012): the returned error is then a *ChecksumError, which the
// error mapping answers as BadDigest or InvalidDigest rather than as a failed read.
func (p *Parser) ReadBody(r *http.Request) ([]byte, error) {
	return p.readBody(r, true, 0)
}

// ErrBodyTooLarge marks a body larger than the caller said it could hold. The
// read stops there, so the bytes beyond the limit are never in memory.
var ErrBodyTooLarge = errors.New("the request body is larger than the caller can hold")

// ReadBodyLimited reads at most limit bytes of decoded payload and refuses a
// body that carries more. A caller that has to keep what it reads — the one
// short part a multipart session buffers (ADR 0011 D5) — bounds the read with
// the same number that bounds the hold, instead of discovering after the fact
// that it has already buffered what it may not keep. A limit of zero or less
// reads the whole body.
func (p *Parser) ReadBodyLimited(r *http.Request, limit int64) ([]byte, error) {
	return p.readBody(r, true, limit)
}

// ReadBodyUnverified reads and decodes the body without checking any checksum
// the request declares.
//
// It exists for CompleteMultipartUpload alone. There S3 defines
// `x-amz-checksum-*` as the digest of the **completed object**, not of the
// request document (aws-sdk-go-v2 puts it on CompleteMultipartUploadInput for
// exactly that), so hashing the XML and comparing would answer BadDigest to a
// correct client. ADR 0012 D2 does not list the completion among the bodies it
// covers, for this reason.
func (p *Parser) ReadBodyUnverified(r *http.Request) ([]byte, error) {
	return p.readBody(r, false, 0)
}

func (p *Parser) readBody(r *http.Request, verify bool, limit int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	verifying := verifying
	if !verify {
		verifying = func(_ *http.Request, src io.Reader, _ func() map[string]string) (io.Reader, error) {
			return src, nil
		}
	}

	// AWS Signature V4 / aws-chunked framing (signed, unsigned, with or without trailers)
	if isAWSChunkedRequest(r) {
		p.logger.Debug("Decoding aws-chunked request body")
		decoder := newStreamingAWSChunkedReader(r.Body, p.logger)
		src, err := verifying(r, decoder, decoder.Trailers)
		if err != nil {
			return nil, err
		}
		return readAllSized(src, p.DecodedContentLength(r), limit)
	}

	src, err := verifying(r, r.Body, nil)
	if err != nil {
		return nil, err
	}
	return readAllSized(src, r.ContentLength, limit)
}

// readAllSized drains src into a buffer pre-sized from a length hint, falling back
// to plain growth when the hint is absent or implausible. A positive limit is the
// most it will hold: one byte more and it stops with ErrBodyTooLarge, so a
// declared length is never trusted in place of counting what arrives.
func readAllSized(src io.Reader, hint, limit int64) ([]byte, error) {
	if limit > 0 {
		if hint > limit {
			hint = limit
		}
		src = io.LimitReader(src, limit+1)
	}
	capacity := 0
	if hint > 0 {
		// bytes.Buffer.ReadFrom asks for bytes.MinRead of spare room before
		// every read, so a buffer sized to exactly the hint is reallocated to
		// twice its size -- and the whole payload copied -- by the final read
		// that only returns io.EOF. The spare room costs 512 bytes and saves
		// that copy on every upload whose length is declared.
		if hint > maxBodyPrealloc {
			capacity = maxBodyPrealloc
		} else {
			capacity = int(hint) + bytes.MinRead
		}
	}
	buf := bytes.NewBuffer(make([]byte, 0, capacity))
	if _, err := buf.ReadFrom(src); err != nil {
		return nil, err
	}
	if limit > 0 && int64(buf.Len()) > limit {
		return nil, ErrBodyTooLarge
	}
	return buf.Bytes(), nil
}

func (p *Parser) ResetBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}

// StreamingReader returns an io.Reader that yields the decoded request body
// incrementally. Unlike ReadBody, this NEVER buffers the full body — it is the
// only safe option for very large uploads.
//
// Behavior:
//   - aws-chunked (detected via Content-Encoding or X-Amz-Content-Sha256):
//     wraps r.Body in a streaming chunk-decoder. Per-chunk signatures are not
//     re-verified; that happens earlier in the auth pipeline.
//   - Transfer-Encoding: chunked: transparent — net/http already decodes it
//     before r.Body is read, so we return r.Body as-is.
//   - identity: returns r.Body unchanged.
//
// The returned reader does not need to be closed by the caller; closing
// r.Body is the HTTP handler's responsibility.
//
// A checksum the request declares is verified against the decoded payload as the
// consumer pulls it. The error returned here is the up-front one — a declared
// value that is not a digest at all — so a request that cannot be satisfied is
// refused before a backend request is opened. A mismatch can only be known at
// the end of the payload: it surfaces as the reader's error, and the handler
// asks Verdict(reader) rather than unwrapping whatever the SDK reports.
func (p *Parser) StreamingReader(r *http.Request) (io.Reader, error) {
	if r.Body == nil {
		return bytes.NewReader(nil), nil
	}
	if isAWSChunkedRequest(r) {
		p.logger.Debug("Streaming aws-chunked body without buffering")
		decoder := newStreamingAWSChunkedReader(r.Body, p.logger)
		return verifying(r, decoder, decoder.Trailers)
	}
	return verifying(r, r.Body, nil)
}

// DecodedContentLength returns the plaintext payload length the client will
// send, or -1 if it is not known from headers alone.
//
// For aws-chunked uploads the total size of the decoded body is carried in
// X-Amz-Decoded-Content-Length; for regular uploads it is r.ContentLength.
// The value is a routing hint: use PlaintextContentLength where a mismatch
// must be treated as an error.
func (p *Parser) DecodedContentLength(r *http.Request) int64 {
	if v := r.Header.Get("X-Amz-Decoded-Content-Length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return r.ContentLength
}

// PlaintextContentLength returns the plaintext payload length the client
// declared, and whether that number really describes the plaintext.
//
// It does not for an aws-chunked body without X-Amz-Decoded-Content-Length:
// r.ContentLength then counts the chunk framing this parser strips, so
// comparing it against the decoded byte count would reject a complete upload.
// Callers that turn a mismatch into an error must use this, not
// DecodedContentLength.
func (p *Parser) PlaintextContentLength(r *http.Request) (int64, bool) {
	if v := r.Header.Get("X-Amz-Decoded-Content-Length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n, true
		}
	}
	if isAWSChunkedRequest(r) {
		return -1, false
	}
	if r.ContentLength < 0 {
		return -1, false
	}
	return r.ContentLength, true
}
