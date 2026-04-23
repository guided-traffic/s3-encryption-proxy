package request

import (
	"bytes"
	"io"
	"net/http"
	"strconv"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
)

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

// ReadBody reads the request body, handling chunked encoding if necessary
func (p *Parser) ReadBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Create decoders
	awsDecoder := NewAWSChunkedDecoder(p.logger)
	httpDecoder := NewHTTPChunkedDecoder(p.logger)

	// Check AWS Signature V4 chunked processing
	if p.config.Optimizations.CleanAWSSignatureV4Chunked && awsDecoder.RequiresChunkedDecoding(r) {
		p.logger.Debug("Processing AWS Signature V4 chunked encoding")
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return awsDecoder.ProcessChunkedData(data)
	}

	// Check HTTP Transfer-Encoding chunked processing
	if p.config.Optimizations.CleanHTTPTransferChunked && httpDecoder.RequiresChunkedDecoding(r) {
		p.logger.Debug("Processing HTTP Transfer-Encoding chunked")
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return httpDecoder.ProcessChunkedData(data)
	}

	// Default: read body as-is
	if p.config.Optimizations.CleanAWSSignatureV4Chunked || p.config.Optimizations.CleanHTTPTransferChunked {
		p.logger.Debug("No chunked encoding detected, reading body directly")
	}
	return io.ReadAll(r.Body)
}

// GetMetadataPrefix returns the configured metadata prefix
func (p *Parser) GetMetadataPrefix() string {
	if p.config.Encryption.MetadataKeyPrefix != nil {
		return *p.config.Encryption.MetadataKeyPrefix
	}
	return "s3ep-" // default prefix
}

// ResetBody resets the request body with new content
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
func (p *Parser) StreamingReader(r *http.Request) io.Reader {
	if r.Body == nil {
		return bytes.NewReader(nil)
	}
	if p.config.Optimizations.CleanAWSSignatureV4Chunked && isAWSChunkedRequest(r) {
		p.logger.Debug("Streaming aws-chunked body without buffering")
		return newStreamingAWSChunkedReader(r.Body, p.logger)
	}
	return r.Body
}

// DecodedContentLength returns the plaintext payload length the client will
// send, or -1 if it is not known from headers alone.
//
// For aws-chunked uploads the total size of the decoded body is carried in
// X-Amz-Decoded-Content-Length; for regular uploads it is r.ContentLength.
func (p *Parser) DecodedContentLength(r *http.Request) int64 {
	if v := r.Header.Get("X-Amz-Decoded-Content-Length"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			return n
		}
	}
	return r.ContentLength
}
