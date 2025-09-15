package request

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// Parser handles request parsing and body reading
type Parser struct {
	logger         *logrus.Entry
	metadataPrefix string
}

// NewParser creates a new request parser
func NewParser(logger *logrus.Entry, metadataPrefix string) *Parser {
	return &Parser{
		logger:         logger,
		metadataPrefix: metadataPrefix,
	}
}

// ReadBody reads the request body, handling chunked encoding if necessary
func (p *Parser) ReadBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	// Check if the request is chunked
	if len(r.TransferEncoding) > 0 && r.TransferEncoding[0] == "chunked" {
		// For chunked requests, we need to handle aws-chunked encoding
		return p.readChunkedBody(r)
	}

	// For regular requests, read the body directly
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	return body, nil
}

// readChunkedBody handles aws-chunked encoding
func (p *Parser) readChunkedBody(r *http.Request) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you'd need to handle AWS chunked encoding properly
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunked body: %w", err)
	}

	return body, nil
}

// GetMetadataPrefix returns the configured metadata prefix
func (p *Parser) GetMetadataPrefix() string {
	return p.metadataPrefix
}

// ResetBody resets the request body with new content
func (p *Parser) ResetBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
}
