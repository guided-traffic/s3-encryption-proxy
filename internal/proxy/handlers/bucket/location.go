package bucket

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// LocationHandler handles bucket location operations
type LocationHandler struct {
	s3Client    interfaces.S3ClientInterface
	logger      *logrus.Entry
	xmlWriter   *response.XMLWriter
	errorWriter *response.ErrorWriter
}

// NewLocationHandler creates a new location handler
func NewLocationHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
) *LocationHandler {
	return &LocationHandler{
		s3Client:    s3Client,
		logger:      logger,
		xmlWriter:   xmlWriter,
		errorWriter: errorWriter,
	}
}

// Handle handles bucket location operations (?location)
func (h *LocationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket location operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLocation(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketLocation_"+r.Method)
	}
}

// handleGetLocation handles GET bucket location requests
func (h *LocationHandler) handleGetLocation(w http.ResponseWriter, r *http.Request, bucket string) {
	// Check if S3 client is available (for testing)
	if h.s3Client == nil {
		// Return mock location
		mockLocation := `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>us-east-1</LocationConstraint>`
		h.xmlWriter.WriteRawXML(w, mockLocation)
		return
	}

	// For S3-compatible services, location might not be supported
	// Return a default response or proxy to backend
	h.errorWriter.WriteNotImplemented(w, "GetBucketLocation")
}
