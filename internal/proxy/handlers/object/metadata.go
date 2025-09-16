package object

import (
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// MetadataHandler handles object metadata operations
type MetadataHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewMetadataHandler creates a new object metadata handler
func NewMetadataHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *MetadataHandler {
	return &MetadataHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// FilterEncryptionMetadata filters out encryption metadata from response headers
func (h *MetadataHandler) FilterEncryptionMetadata(metadata map[string]string) map[string]string {
	filtered := make(map[string]string)
	prefix := h.requestParser.GetMetadataPrefix()
	if prefix == "" {
		prefix = "s3ep-"
	}

	for key, value := range metadata {
		if len(key) < len(prefix) || key[:len(prefix)] != prefix {
			filtered[key] = value
		}
	}

	return filtered
}
