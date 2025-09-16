package multipart

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// ListHandler handles list operations for multipart uploads
type ListHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewListHandler creates a new list handler
func NewListHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ListHandler {
	return &ListHandler{
		s3Backend:     s3Backend,
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
	uploadID := query.Get("uploadId")

	log := h.logger.WithFields(logrus.Fields{
		"method":   r.Method,
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	})

	log.Debug("Handling list parts")

	if uploadID == "" {
		log.Error("Missing uploadId")
		h.errorWriter.WriteS3Error(w, fmt.Errorf("missing uploadId"), bucket, key)
		return
	}

	// For now, return a basic empty response - this is less critical than the core upload operations
	// TODO: Implement full ListParts functionality when needed
	responseXML := `<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult>
    <Bucket>` + bucket + `</Bucket>
    <Key>` + key + `</Key>
    <UploadId>` + uploadID + `</UploadId>
    <StorageClass>STANDARD</StorageClass>
    <PartNumberMarker>0</PartNumberMarker>
    <NextPartNumberMarker>0</NextPartNumberMarker>
    <MaxParts>1000</MaxParts>
    <IsTruncated>false</IsTruncated>
</ListPartsResult>`

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(responseXML)); err != nil {
		h.logger.WithError(err).Error("Failed to write list parts response")
	}

	log.Debug("Returned basic ListParts response")
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
