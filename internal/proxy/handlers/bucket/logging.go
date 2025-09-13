package bucket

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// LoggingHandler handles bucket logging operations
type LoggingHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *LoggingHandler {
	return &LoggingHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket logging operations (?logging)
func (h *LoggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket logging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLogging(w, r, bucket)
	case http.MethodPut:
		h.handlePutLogging(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketLogging_"+r.Method)
	}
}

// handleGetLogging handles GET bucket logging requests
func (h *LoggingHandler) handleGetLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	// Bucket logging is typically not implemented in encryption proxies
	h.errorWriter.WriteNotImplemented(w, "GetBucketLogging")
}

// handlePutLogging handles PUT bucket logging requests
func (h *LoggingHandler) handlePutLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	// Bucket logging is typically not implemented in encryption proxies
	h.errorWriter.WriteNotImplemented(w, "PutBucketLogging")
}
