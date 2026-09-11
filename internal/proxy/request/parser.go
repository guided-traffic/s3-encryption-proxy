package request

import (
	"bytes"
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
	if r.Body == nil {
		return nil, nil
	}

	// AWS Signature V4 / aws-chunked framing (signed, unsigned, with or without trailers)
	if p.config.Optimizations.CleanAWSSignatureV4Chunked && isAWSChunkedRequest(r) {
		p.logger.Debug("Decoding aws-chunked request body")
		decoder := newStreamingAWSChunkedReader(r.Body, p.logger)
		src, err := verifying(r, decoder, decoder.Trailers)
		if err != nil {
			return nil, err
		}
		return readAllSized(src, p.DecodedContentLength(r))
	}

	// HTTP Transfer-Encoding: chunked. net/http normally decodes this before the
	// handler sees r.Body; the decoder stays for backends that hand through raw framing.
	if p.config.Optimizations.CleanHTTPTransferChunked {
		httpDecoder := NewHTTPChunkedDecoder(p.logger)
		if httpDecoder.RequiresChunkedDecoding(r) {
			p.logger.Debug("Processing HTTP Transfer-Encoding chunked")
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			decoded, err := httpDecoder.ProcessChunkedData(data)
			if err != nil {
				return nil, err
			}
			// The framing is stripped first, so what a checksum covers is the
			// payload and never the chunk headers.
			src, verr := verifying(r, bytes.NewReader(decoded), nil)
			if verr != nil {
				return nil, verr
			}
			if _, wrapped := src.(*checksumReader); !wrapped {
				return decoded, nil
			}
			return readAllSized(src, int64(len(decoded)))
		}
	}

	if p.undecodedAWSChunked(r) {
		return readAllSized(r.Body, r.ContentLength)
	}

	src, err := verifying(r, r.Body, nil)
	if err != nil {
		return nil, err
	}
	return readAllSized(src, r.ContentLength)
}

// undecodedAWSChunked reports an aws-chunked request this parser is configured
// not to decode, and warns when that costs a check the client asked for.
//
// The verifier must not run on such a body. It would hash the chunk framing
// instead of the payload and answer BadDigest, which blames the client for a
// correct upload; what is actually wrong is that a body carrying framing is
// about to be stored as if it were content.
func (p *Parser) undecodedAWSChunked(r *http.Request) bool {
	if p.config.Optimizations.CleanAWSSignatureV4Chunked || !isAWSChunkedRequest(r) {
		return false
	}
	if DeclaresChecksum(r) {
		p.logger.Warn("Client checksum not verified: aws-chunked decoding is disabled, " +
			"so the payload this proxy sees is the chunk framing")
	}
	return true
}

// readAllSized drains src into a buffer pre-sized from a length hint, falling back
// to plain growth when the hint is absent or implausible.
func readAllSized(src io.Reader, hint int64) ([]byte, error) {
	capacity := 0
	if hint > 0 {
		if hint > maxBodyPrealloc {
			capacity = maxBodyPrealloc
		} else {
			capacity = int(hint)
		}
	}
	buf := bytes.NewBuffer(make([]byte, 0, capacity))
	if _, err := buf.ReadFrom(src); err != nil {
		return nil, err
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
	if p.config.Optimizations.CleanAWSSignatureV4Chunked && isAWSChunkedRequest(r) {
		p.logger.Debug("Streaming aws-chunked body without buffering")
		decoder := newStreamingAWSChunkedReader(r.Body, p.logger)
		return verifying(r, decoder, decoder.Trailers)
	}
	if p.undecodedAWSChunked(r) {
		return r.Body, nil
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
	if p.config.Optimizations.CleanAWSSignatureV4Chunked && isAWSChunkedRequest(r) {
		return -1, false
	}
	if r.ContentLength < 0 {
		return -1, false
	}
	return r.ContentLength, true
}
