package request

import (
	"bytes"
	"io"
	"net/http"

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
	p.logger.Debug("No chunked encoding processing required, reading body directly")
	return io.ReadAll(r.Body)
}

// ResetBody resets the request body with new content
func (p *Parser) ResetBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}
