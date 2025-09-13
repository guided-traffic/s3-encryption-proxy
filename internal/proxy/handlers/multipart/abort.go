package multipart

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// AbortHandler handles abort multipart upload operations
type AbortHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewAbortHandler creates a new abort handler
func NewAbortHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *AbortHandler {
	return &AbortHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles abort multipart upload requests
func (h *AbortHandler) Handle(w http.ResponseWriter, r *http.Request) {
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
	}).Debug("Handling abort multipart upload")

	h.errorWriter.WriteNotImplemented(w, "AbortMultipartUpload")
}
