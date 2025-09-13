package multipart

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// ListHandler handles list operations for multipart uploads
type ListHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewListHandler creates a new list handler
func NewListHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ListHandler {
	return &ListHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// HandleListParts handles list parts requests
func (h *ListHandler) HandleListParts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	query := r.URL.Query()
	uploadId := query.Get("uploadId")

	h.logger.WithFields(logrus.Fields{
		"method":   r.Method,
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadId,
	}).Debug("Handling list parts")

	h.errorWriter.WriteNotImplemented(w, "ListParts")
}

// HandleListMultipartUploads handles list multipart uploads requests
func (h *ListHandler) HandleListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling list multipart uploads")

	h.errorWriter.WriteNotImplemented(w, "ListMultipartUploads")
}
