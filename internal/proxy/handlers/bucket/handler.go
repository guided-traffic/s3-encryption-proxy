package bucket

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
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
	_ string,
	cfg *config.Config,
) *Handler {
	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, cfg)

	h := &Handler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}

	// Initialize sub-handlers with shared base
	base := NewBaseSubResourceHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.aclHandler = NewACLHandler(base)
	h.corsHandler = NewCORSHandler(base)
	h.policyHandler = NewPolicyHandler(base)
	h.locationHandler = NewLocationHandler(base)
	h.loggingHandler = NewLoggingHandler(base)
	h.versioningHandler = NewVersioningHandler(base)
	h.taggingHandler = NewTaggingHandler(base)
	h.notificationHandler = NewNotificationHandler(base)
	h.lifecycleHandler = NewLifecycleHandler(base)
	h.replicationHandler = NewReplicationHandler(base)
	h.websiteHandler = NewWebsiteHandler(base)
	h.accelerateHandler = NewAccelerateHandler(base)
	h.requestPaymentHandler = NewRequestPaymentHandler(base)

	return h
}

// Handle handles base bucket operations (GET list objects, PUT create bucket, DELETE bucket, HEAD bucket).
// Sub-resource routing (acl, cors, policy, etc.) is handled by the mux router in router.go.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
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
