package object

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// Handler handles object operations
type Handler struct {
	s3Backend      interfaces.S3BackendInterface
	encryptionMgr  *orchestration.Manager
	logger         *logrus.Entry
	xmlWriter      *response.XMLWriter
	errorWriter    *response.ErrorWriter
	requestParser  *request.Parser
	metadataPrefix string
	config         *config.Config

	// Sub-handlers
	aclHandler     *ACLHandler
	taggingHandler *TaggingHandler
}

// NewHandler creates a new object handler
func NewHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	config *config.Config,
	logger *logrus.Entry,
) *Handler {
	metadataPrefix := "s3ep-" // default
	if config.Encryption.MetadataKeyPrefix != nil {
		metadataPrefix = *config.Encryption.MetadataKeyPrefix
	}

	xmlWriter := response.NewXMLWriter(logger)
	errorWriter := response.NewErrorWriter(logger)
	requestParser := request.NewParser(logger, config)

	h := &Handler{
		s3Backend:      s3Backend,
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

	return h
}

// knownObjectSubResources lists object sub-resource query parameters that have
// their own route in router.go, or their own branch below. Reaching the base
// operation with one of them means the route did not match - almost always
// because the HTTP method is not one the sub-resource is registered for.
var knownObjectSubResources = map[string]bool{
	"acl": true, "tagging": true, "attributes": true,
	"legal-hold": true, "retention": true, "torrent": true,
	"select": true, "select-type": true, "restore": true,
	"uploads": true,
	// partNumber and uploadId are deliberately NOT here. A PUT carrying both is
	// a part upload whose partNumber failed the router's [0-9]+ match; Handle
	// answers it InvalidArgument, which is what AWS answers. Every other verb
	// falls through to the unknown-parameter branch and is answered
	// NotImplemented: on a GET, partNumber is a legitimate S3 read of one part
	// that this proxy does not implement, and MethodNotAllowed would be the
	// wrong thing to say about a GET. Neither answer overwrites the object,
	// which the base PUT used to do.
}

// baseObjectParams lists the only query parameters the base object operations
// accept. Anything else names a sub-resource with no implementation, and running
// the base operation for the verb instead is how "DELETE /bucket?encryption"
// deleted the bucket - the same shape, one level down.
var baseObjectParams = map[string]bool{
	"versionId": true,
	// Operation marker appended by aws-sdk-go-v2.
	"x-id": true,
	// GET response header overrides. Forwarding them is a separate gap, but they
	// are legitimate on a base GET and must not be refused.
	"response-content-type": true, "response-content-language": true,
	"response-expires": true, "response-cache-control": true,
	"response-content-disposition": true, "response-content-encoding": true,
	// Every other "x-amz-*" parameter is admitted by
	// request.IsAWSProtocolQueryParam rather than listed here. Listing them
	// literally is what refused every pre-signed download: aws-sdk-go-v2 puts
	// X-Amz-Checksum-Mode into every pre-signed GetObject URL and it was not in
	// this map.
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

	// GetObjectAttributes has no route of its own. Without this branch the request
	// falls through to handleGetObject and the object's bytes are returned where an
	// XML document is expected.
	if _, hasAttributes := query["attributes"]; hasAttributes {
		h.errorWriter.WriteNotImplemented(w, "GetObjectAttributes")
		return
	}

	// A sub-resource that has a route but did not match it, so the method is
	// wrong for it. Answering the base operation here is destructive:
	// DELETE ?legal-hold deleted the object and PUT ?restore overwrote it with
	// the restore document. Both are answered rather than performed.
	for param := range query {
		if knownObjectSubResources[param] {
			h.logger.WithFields(logrus.Fields{
				"method": r.Method,
				"param":  param,
			}).Warn("Object sub-resource reached the base operation, refusing to run it")
			h.errorWriter.WriteGenericError(w, http.StatusMethodNotAllowed,
				"MethodNotAllowed",
				"The specified method is not allowed against this resource.")
			return
		}
	}

	// A part upload the router refused. router.go registers the two PUT part
	// routes before the catch-all object route and requires partNumber to match
	// [0-9]+, so a PUT that still carries both partNumber and uploadId here is a
	// part upload whose part number is not a number. Running the base PUT
	// replaced the whole object with the body of one part. AWS answers
	// InvalidArgument, which is more specific than the NotImplemented the
	// unknown-parameter branch below would give it, so it is answered first.
	if r.Method == http.MethodPut {
		_, hasPartNumber := query["partNumber"]
		_, hasUploadID := query["uploadId"]
		if hasPartNumber && hasUploadID {
			h.logger.WithFields(logrus.Fields{
				"method":     r.Method,
				"partNumber": query.Get("partNumber"),
			}).Warn("Malformed part upload reached the base object operation, refusing to run it")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
				"Part number must be an integer between 1 and 10000, inclusive")
			return
		}
	}

	// An unknown parameter names a sub-resource this proxy does not implement.
	// Refusing is the only safe answer: the alternative is performing a
	// different operation and reporting success.
	for param := range query {
		if !baseObjectParams[param] && !request.IsAWSProtocolQueryParam(param) {
			h.logger.WithFields(logrus.Fields{
				"method": r.Method,
				"param":  param,
			}).Warn("Unsupported object sub-resource, refusing to run the base object operation")
			h.errorWriter.WriteNotImplemented(w, "ObjectSubResource")
			return
		}
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
