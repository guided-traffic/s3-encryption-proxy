package request

import (
	"io"
	"net/http"

	"github.com/sirupsen/logrus"
)

// ChunkedDecoder defines the interface for different chunked encoding processors
type ChunkedDecoder interface {
	// RequiresChunkedDecoding checks if this decoder should handle the request
	RequiresChunkedDecoding(r *http.Request) bool

	// ProcessChunkedData processes chunked data and extracts raw content
	ProcessChunkedData(data []byte) ([]byte, error)

	// CreateOptimalReader creates an appropriate reader for the request
	CreateOptimalReader(r *http.Request) io.Reader

	// GetName returns the name of this decoder for logging
	GetName() string
}

// ChunkedDecoderBase provides common functionality for chunked decoders
type ChunkedDecoderBase struct {
	logger *logrus.Entry
}

// NewChunkedDecoderBase creates a new base decoder
func NewChunkedDecoderBase(logger *logrus.Entry) *ChunkedDecoderBase {
	return &ChunkedDecoderBase{
		logger: logger,
	}
}
