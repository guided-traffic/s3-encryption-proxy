package object

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// Handler handles object operations
type Handler struct {
	s3Backend      interfaces.S3BackendInterface
	encryptionMgr  *encryption.Manager
	logger         *logrus.Entry
	xmlWriter      *response.XMLWriter
	errorWriter    *response.ErrorWriter
	requestParser  *request.Parser
	metadataPrefix string
	config         *config.Config

	// Sub-handlers
	aclHandler      *ACLHandler
	taggingHandler  *TaggingHandler
	metadataHandler *MetadataHandler
}

// NewHandler creates a new object handler
func NewHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	config *config.Config,
	logger *logrus.Entry,
) *Handler {
	metadataPrefix := "s3ep-" // default
	if config.Encryption.MetadataKeyPrefix != nil {
		metadataPrefix = *config.Encryption.MetadataKeyPrefix
	}

	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, metadataPrefix)

	h := &Handler{
		s3Backend:       s3Backend,
		encryptionMgr:  encryptionMgr,
		logger:         logger,
		xmlWriter:      xmlWriter,
		errorWriter:    errorWriter,
		requestParser:  requestParser,
		metadataPrefix: metadataPrefix,
		config:         config,
	}

	// Initialize sub-handlers
	h.aclHandler = NewACLHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.taggingHandler = NewTaggingHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)
	h.metadataHandler = NewMetadataHandler(s3Backend, logger, xmlWriter, errorWriter, requestParser)

	return h
}

// Handle routes object requests to appropriate sub-handlers based on query parameters
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()

	// Route to specific handlers based on query parameters
	if _, hasACL := query["acl"]; hasACL {
		h.aclHandler.Handle(w, r)
		return
	}

	if _, hasTagging := query["tagging"]; hasTagging {
		h.taggingHandler.Handle(w, r)
		return
	}

	// Handle base object operations (GET, PUT, DELETE, HEAD)
	h.handleBaseObjectOperations(w, r)
}

// handleBaseObjectOperations handles basic object CRUD operations
func (h *Handler) handleBaseObjectOperations(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
		"path":   r.URL.Path,
	}).Debug("Handling base object operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetObject(w, r, bucket, key)
	case http.MethodPut:
		h.handlePutObject(w, r, bucket, key)
	case http.MethodDelete:
		h.handleDeleteObject(w, r, bucket, key)
	case http.MethodHead:
		h.handleHeadObject(w, r, bucket, key)
	default:
		h.errorWriter.WriteNotImplemented(w, "Object_"+r.Method)
	}
}

// GetACLHandler returns the ACL handler for direct access
func (h *Handler) GetACLHandler() *ACLHandler {
	return h.aclHandler
}

// GetTaggingHandler returns the Tagging handler for direct access
func (h *Handler) GetTaggingHandler() *TaggingHandler {
	return h.taggingHandler
}

// GetMetadataHandler returns the Metadata handler for direct access
func (h *Handler) GetMetadataHandler() *MetadataHandler {
	return h.metadataHandler
}

// ===== PASSTHROUGH OPERATION HANDLERS =====

// HandleDeleteObjects handles bulk object deletion (passthrough)
func (h *Handler) HandleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.handleDeleteObjects(w, r, bucket)
}

// HandleObjectLegalHold handles object legal hold operations (passthrough)
func (h *Handler) HandleObjectLegalHold(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.handleObjectLegalHold(w, r, bucket, key)
}

// HandleObjectRetention handles object retention operations (passthrough)
func (h *Handler) HandleObjectRetention(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.handleObjectRetention(w, r, bucket, key)
}

// HandleObjectTorrent handles object torrent operations (passthrough)
func (h *Handler) HandleObjectTorrent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.handleObjectTorrent(w, r, bucket, key)
}

// HandleSelectObjectContent handles S3 Select operations (passthrough)
func (h *Handler) HandleSelectObjectContent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.handleSelectObjectContent(w, r, bucket, key)
}
