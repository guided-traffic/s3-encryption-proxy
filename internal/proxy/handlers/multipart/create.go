package multipart

import (
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/utils"
	"github.com/sirupsen/logrus"
)

// CreateHandler handles create multipart upload operations
type CreateHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCreateHandler creates a new create handler
func NewCreateHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CreateHandler {
	return &CreateHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles create multipart upload requests
func (h *CreateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling create multipart upload")

	// Create the S3 input
	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Copy headers that should be preserved
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		input.ContentType = aws.String(contentType)
		h.logger.WithFields(logrus.Fields{
			"bucket":      bucket,
			"key":         key,
			"contentType": contentType,
		}).Debug("Setting Content-Type for S3")
	}
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
		h.logger.WithFields(logrus.Fields{
			"bucket":          bucket,
			"key":             key,
			"contentEncoding": contentEncoding,
		}).Debug("Setting Content-Encoding for S3")
	}

	// Create the multipart upload with S3
	result, err := h.s3Backend.CreateMultipartUpload(r.Context(), input)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload with S3")
		utils.HandleS3Error(w, h.logger, err, "Failed to create multipart upload", bucket, key)
		return
	}

	uploadID := aws.ToString(result.UploadId)

	// Initialize encryption session for multipart uploads
	err = h.encryptionMgr.InitiateMultipartUpload(r.Context(), uploadID, key, bucket)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("Failed to initialize encryption for multipart upload")

		// Abort the S3 multipart upload since encryption initialization failed
		abortInput := &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}
		if _, abortErr := h.s3Backend.AbortMultipartUpload(r.Context(), abortInput); abortErr != nil {
			h.logger.WithError(abortErr).Warn("Failed to abort multipart upload after encryption initialization failure")
		}

		utils.HandleS3Error(w, h.logger, err, "Failed to initialize encryption for multipart upload", bucket, key)
		return
	}

	// Handle metadata based on the encryption session
	metadata := input.Metadata

	// Set the metadata for the multipart upload
	input.Metadata = metadata

	// Return the CreateMultipartUploadResult
	h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("Sending CreateMultipartUploadResult response to client")

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <UploadId>%s</UploadId>
</InitiateMultipartUploadResult>`, bucket, key, uploadID)

	if _, err := w.Write([]byte(response)); err != nil {
		h.logger.WithError(err).Error("Failed to write multipart upload response")
		// At this point we can't send an error response since headers are already sent
	}
}

// prepareEncryptionMetadata merges client metadata with encryption metadata
func (h *CreateHandler) prepareEncryptionMetadata(clientMetadata, encryptionMetadata map[string]string) map[string]string {
	if clientMetadata == nil {
		clientMetadata = make(map[string]string)
	}

	// Copy client metadata
	metadata := make(map[string]string)
	for k, v := range clientMetadata {
		metadata[k] = v
	}

	// Add encryption metadata
	for k, v := range encryptionMetadata {
		metadata[k] = v
	}

	return metadata
}
