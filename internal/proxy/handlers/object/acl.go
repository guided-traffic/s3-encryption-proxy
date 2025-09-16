package object

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// ACLHandler handles object ACL operations
type ACLHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewACLHandler creates a new object ACL handler
func NewACLHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ACLHandler {
	return &ACLHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles object ACL operations (?acl)
func (h *ACLHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling object ACL operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetACL(w, r, bucket, key)
	case http.MethodPut:
		h.handlePutACL(w, r, bucket, key)
	default:
		h.errorWriter.WriteNotImplemented(w, "ObjectACL_"+r.Method)
	}
}

// handleGetACL handles GET object ACL requests
func (h *ACLHandler) handleGetACL(w http.ResponseWriter, _ *http.Request, _, _ string) {
	h.errorWriter.WriteNotImplemented(w, "GetObjectACL")
}

// handlePutACL handles PUT object ACL requests
func (h *ACLHandler) handlePutACL(w http.ResponseWriter, _ *http.Request, _, _ string) {
	h.errorWriter.WriteNotImplemented(w, "PutObjectACL")
}
