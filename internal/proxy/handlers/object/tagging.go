package object

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// TaggingHandler handles object tagging operations
type TaggingHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewTaggingHandler creates a new object tagging handler
func NewTaggingHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *TaggingHandler {
	return &TaggingHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles object tagging operations (?tagging)
func (h *TaggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling object tagging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetTagging(w, r, bucket, key)
	case http.MethodPut:
		h.handlePutTagging(w, r, bucket, key)
	case http.MethodDelete:
		h.handleDeleteTagging(w, r, bucket, key)
	default:
		h.errorWriter.WriteNotImplemented(w, "ObjectTagging_"+r.Method)
	}
}

// handleGetTagging handles GET object tagging requests
func (h *TaggingHandler) handleGetTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.errorWriter.WriteNotImplemented(w, "GetObjectTagging")
}

// handlePutTagging handles PUT object tagging requests
func (h *TaggingHandler) handlePutTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.errorWriter.WriteNotImplemented(w, "PutObjectTagging")
}

// handleDeleteTagging handles DELETE object tagging requests
func (h *TaggingHandler) handleDeleteTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.errorWriter.WriteNotImplemented(w, "DeleteObjectTagging")
}
