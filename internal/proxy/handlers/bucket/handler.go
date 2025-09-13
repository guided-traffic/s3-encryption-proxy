package bucket

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// Handler handles bucket operations
type Handler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser

	// Sub-handlers
	aclHandler      *ACLHandler
	corsHandler     *CORSHandler
	policyHandler   *PolicyHandler
	locationHandler *LocationHandler
	loggingHandler  *LoggingHandler
}

// NewHandler creates a new bucket handler
func NewHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	metadataPrefix string,
) *Handler {
	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, metadataPrefix)

	h := &Handler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}

	// Initialize sub-handlers
	h.aclHandler = NewACLHandler(s3Client, logger, xmlWriter, errorWriter, requestParser)
	h.corsHandler = NewCORSHandler(s3Client, logger, xmlWriter, errorWriter, requestParser)
	h.policyHandler = NewPolicyHandler(s3Client, logger, xmlWriter, errorWriter, requestParser)
	h.locationHandler = NewLocationHandler(s3Client, logger, xmlWriter, errorWriter)
	h.loggingHandler = NewLoggingHandler(s3Client, logger, xmlWriter, errorWriter, requestParser)

	return h
}

// Handle routes bucket requests to appropriate sub-handlers based on query parameters
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Route to specific handlers based on query parameters
	if _, hasACL := query["acl"]; hasACL {
		h.aclHandler.Handle(w, r)
		return
	}

	if _, hasCORS := query["cors"]; hasCORS {
		h.corsHandler.Handle(w, r)
		return
	}

	if _, hasPolicy := query["policy"]; hasPolicy {
		h.policyHandler.Handle(w, r)
		return
	}

	if _, hasLocation := query["location"]; hasLocation {
		h.locationHandler.Handle(w, r)
		return
	}

	if _, hasLogging := query["logging"]; hasLogging {
		h.loggingHandler.Handle(w, r)
		return
	}

	// Handle base bucket operations (GET list objects, PUT create bucket, DELETE bucket, HEAD bucket)
	h.handleBaseBucketOperations(w, r)
}

// handleBaseBucketOperations handles basic bucket CRUD operations
func (h *Handler) handleBaseBucketOperations(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"path":   r.URL.Path,
	}).Debug("Handling base bucket operation")

	switch r.Method {
	case http.MethodGet:
		h.handleListObjects(w, r, bucket)
	case http.MethodPut:
		h.handleCreateBucket(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteBucket(w, r, bucket)
	case http.MethodHead:
		h.handleHeadBucket(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "Bucket_"+r.Method)
	}
}

// GetACLHandler returns the ACL handler for direct access
func (h *Handler) GetACLHandler() *ACLHandler {
	return h.aclHandler
}

// GetCORSHandler returns the CORS handler for direct access
func (h *Handler) GetCORSHandler() *CORSHandler {
	return h.corsHandler
}

// GetPolicyHandler returns the Policy handler for direct access
func (h *Handler) GetPolicyHandler() *PolicyHandler {
	return h.policyHandler
}

// GetLocationHandler returns the Location handler for direct access
func (h *Handler) GetLocationHandler() *LocationHandler {
	return h.locationHandler
}

// GetLoggingHandler returns the Logging handler for direct access
func (h *Handler) GetLoggingHandler() *LoggingHandler {
	return h.loggingHandler
}
