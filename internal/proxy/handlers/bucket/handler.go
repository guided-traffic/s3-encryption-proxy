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
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser

	// Sub-handlers
	aclHandler            *ACLHandler
	corsHandler           *CORSHandler
	policyHandler         *PolicyHandler
	locationHandler       *LocationHandler
	loggingHandler        *LoggingHandler
	versioningHandler     *VersioningHandler
	taggingHandler        *TaggingHandler
	notificationHandler   *NotificationHandler
	lifecycleHandler      *LifecycleHandler
	replicationHandler    *ReplicationHandler
	websiteHandler        *WebsiteHandler
	accelerateHandler     *AccelerateHandler
	requestPaymentHandler *RequestPaymentHandler
}

// NewHandler creates a new bucket handler
func NewHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	metadataPrefix string,
) *Handler {
	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, metadataPrefix)

	h := &Handler{
		s3Backend:      s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}

	// Initialize sub-handlers
	h.aclHandler = NewACLHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.corsHandler = NewCORSHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.policyHandler = NewPolicyHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.locationHandler = NewLocationHandler(s3Backend, logger, xmlWriter, errorWriter)
	h.loggingHandler = NewLoggingHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.versioningHandler = NewVersioningHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.taggingHandler = NewTaggingHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.notificationHandler = NewNotificationHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.lifecycleHandler = NewLifecycleHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.replicationHandler = NewReplicationHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.websiteHandler = NewWebsiteHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.accelerateHandler = NewAccelerateHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.requestPaymentHandler = NewRequestPaymentHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.locationHandler = NewLocationHandler(s3Backend, logger, xmlWriter, errorWriter)
	h.loggingHandler = NewLoggingHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)

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

	if _, hasVersioning := query["versioning"]; hasVersioning {
		h.versioningHandler.Handle(w, r)
		return
	}

	if _, hasTagging := query["tagging"]; hasTagging {
		h.taggingHandler.Handle(w, r)
		return
	}

	if _, hasNotification := query["notification"]; hasNotification {
		h.notificationHandler.Handle(w, r)
		return
	}

	if _, hasLifecycle := query["lifecycle"]; hasLifecycle {
		h.lifecycleHandler.Handle(w, r)
		return
	}

	if _, hasReplication := query["replication"]; hasReplication {
		h.replicationHandler.Handle(w, r)
		return
	}

	if _, hasWebsite := query["website"]; hasWebsite {
		h.websiteHandler.Handle(w, r)
		return
	}

	if _, hasAccelerate := query["accelerate"]; hasAccelerate {
		h.accelerateHandler.Handle(w, r)
		return
	}

	if _, hasRequestPayment := query["requestPayment"]; hasRequestPayment {
		h.requestPaymentHandler.Handle(w, r)
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

// GetVersioningHandler returns the Versioning handler for direct access
func (h *Handler) GetVersioningHandler() *VersioningHandler {
	return h.versioningHandler
}

// GetTaggingHandler returns the Tagging handler for direct access
func (h *Handler) GetTaggingHandler() *TaggingHandler {
	return h.taggingHandler
}

// GetNotificationHandler returns the Notification handler for direct access
func (h *Handler) GetNotificationHandler() *NotificationHandler {
	return h.notificationHandler
}

// GetLifecycleHandler returns the Lifecycle handler for direct access
func (h *Handler) GetLifecycleHandler() *LifecycleHandler {
	return h.lifecycleHandler
}

// GetReplicationHandler returns the Replication handler for direct access
func (h *Handler) GetReplicationHandler() *ReplicationHandler {
	return h.replicationHandler
}

// GetWebsiteHandler returns the Website handler for direct access
func (h *Handler) GetWebsiteHandler() *WebsiteHandler {
	return h.websiteHandler
}

// GetAccelerateHandler returns the Accelerate handler for direct access
func (h *Handler) GetAccelerateHandler() *AccelerateHandler {
	return h.accelerateHandler
}

// GetRequestPaymentHandler returns the RequestPayment handler for direct access
func (h *Handler) GetRequestPaymentHandler() *RequestPaymentHandler {
	return h.requestPaymentHandler
}
