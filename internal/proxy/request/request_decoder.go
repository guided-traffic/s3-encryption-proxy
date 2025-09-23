package request

import (
	"io"
	"net/http"
)

// Decoder defines the interface for request body decoders
type Decoder interface {
	// RequiresDecoding checks if this decoder should handle the request
	RequiresDecoding(r *http.Request) bool

	// ProcessRequestData processes the request data and returns clean content
	ProcessRequestData(data []byte) ([]byte, error)

	// CreateOptimalReader creates an appropriate reader for the request
	CreateOptimalReader(r *http.Request) io.Reader
}
