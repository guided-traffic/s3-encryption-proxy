package request

import (
	"bytes"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Parser handles request parsing and body reading
type Parser struct {
	logger                  *logrus.Entry
	metadataPrefix         string
	chunkedEncodingDetector *ChunkedEncodingDetector
}

// NewParser creates a new request parser
func NewParser(logger *logrus.Entry, metadataPrefix string) *Parser {
	return &Parser{
		logger:                  logger,
		metadataPrefix:         metadataPrefix,
		chunkedEncodingDetector: NewChunkedEncodingDetector(logger),
	}
}

// ReadBody reads the request body, handling chunked encoding if necessary
func (p *Parser) ReadBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Use centralized chunked encoding processing
	return p.chunkedEncodingDetector.ProcessRequestBody(r)
}

// GetMetadataPrefix returns the configured metadata prefix
func (p *Parser) GetMetadataPrefix() string {
	return p.metadataPrefix
}

// GetChunkedEncodingDetector returns the chunked encoding detector for direct use
func (p *Parser) GetChunkedEncodingDetector() *ChunkedEncodingDetector {
	return p.chunkedEncodingDetector
}

// ResetBody resets the request body with new content
func (p *Parser) ResetBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}
