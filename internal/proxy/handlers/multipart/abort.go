package multipart

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// AbortHandler handles abort multipart upload operations
type AbortHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewAbortHandler creates a new abort handler
func NewAbortHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *AbortHandler {
	return &AbortHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
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

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")

	log := h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
		"method":   r.Method,
	})

	log.Debug("AbortMultipartUpload - Request received")

	if uploadID == "" {
		log.Error("Missing uploadId")
		h.errorWriter.WriteS3Error(w, fmt.Errorf("missing uploadId"), bucket, key)
		return
	}

	// Create abort input
	abortInput := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	ctx := r.Context()
	_, err := h.s3Backend.AbortMultipartUpload(ctx, abortInput)
	if err != nil {
		log.WithError(err).Error("Failed to abort multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Clean up upload state in encryption manager
	if h.encryptionMgr != nil {
		if err := h.encryptionMgr.CleanupMultipartUpload(uploadID); err != nil {
			log.WithError(err).Warn("Failed to cleanup multipart upload state")
			// Continue - this is not a critical error for abort operation
		}
	}

	// Return 204 No Content for successful abort
	w.WriteHeader(http.StatusNoContent)

	log.Info("Successfully aborted multipart upload")
}
