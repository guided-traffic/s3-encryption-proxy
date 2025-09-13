package bucket

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// PolicyHandler handles bucket policy operations
type PolicyHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewPolicyHandler creates a new policy handler
func NewPolicyHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *PolicyHandler {
	return &PolicyHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket policy operations (?policy)
func (h *PolicyHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket policy operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetPolicy(w, r, bucket)
	case http.MethodPut:
		h.handlePutPolicy(w, r, bucket)
	case http.MethodDelete:
		h.handleDeletePolicy(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketPolicy_"+r.Method)
	}
}

// handleGetPolicy handles GET bucket policy requests
func (h *PolicyHandler) handleGetPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	// Bucket policies are typically not implemented in encryption proxies
	// as they would interfere with the proxy's operation
	h.errorWriter.WriteNotImplemented(w, "GetBucketPolicy")
}

// handlePutPolicy handles PUT bucket policy requests
func (h *PolicyHandler) handlePutPolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	// Bucket policies are typically not implemented in encryption proxies
	h.errorWriter.WriteNotImplemented(w, "PutBucketPolicy")
}

// handleDeletePolicy handles DELETE bucket policy requests
func (h *PolicyHandler) handleDeletePolicy(w http.ResponseWriter, r *http.Request, bucket string) {
	// Bucket policies are typically not implemented in encryption proxies
	h.errorWriter.WriteNotImplemented(w, "DeleteBucketPolicy")
}
