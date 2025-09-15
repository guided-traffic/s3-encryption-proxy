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
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/utils"
	"github.com/sirupsen/logrus"
)

// CreateHandler handles create multipart upload operations
type CreateHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCreateHandler creates a new create handler
func NewCreateHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CreateHandler {
	return &CreateHandler{
		s3Backend:      s3Backend,
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

	// Get encryption metadata for multipart uploads with HTTP Content-Type awareness
	httpContentType := aws.ToString(input.ContentType)
	encResult, err := h.encryptionMgr.EncryptDataWithHTTPContentType(r.Context(), []byte{}, key, httpContentType, true)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to initialize encryption for multipart upload")
		utils.HandleS3Error(w, h.logger, err, "Failed to initialize encryption for multipart upload", bucket, key)
		return
	}

	// Handle metadata based on encryption result
	var metadata map[string]string

	// For "none" provider: preserve original user metadata for pure pass-through
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		metadata = input.Metadata
	} else {
		// For encrypted providers, create metadata with client data + encryption info
		metadata = h.prepareEncryptionMetadata(input.Metadata, encResult.Metadata)
	}

	input.Metadata = metadata

	// Create multipart upload in S3
	result, err := h.s3Backend.CreateMultipartUpload(r.Context(), input)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload in S3")
		utils.HandleS3Error(w, h.logger, err, "Failed to create multipart upload", bucket, key)
		return
	}

	if result == nil || result.UploadId == nil {
		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"result": result,
		}).Error("S3 client returned nil result or nil UploadId")
		http.Error(w, "Failed to create multipart upload", http.StatusInternalServerError)
		return
	}

	uploadID := *result.UploadId

	// Initialize multipart upload in encryption manager
	err = h.encryptionMgr.InitiateMultipartUpload(r.Context(), uploadID, key, bucket)
	if err != nil {
		// Clean up the S3 multipart upload if encryption initialization fails
		abortInput := &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}
		_, _ = h.s3Backend.AbortMultipartUpload(r.Context(), abortInput)

		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("Failed to initialize multipart upload in encryption manager")
		utils.HandleS3Error(w, h.logger, err, "Failed to initialize multipart upload in encryption manager", bucket, key)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Info("Multipart upload created successfully")

	// Get the upload state for logging (optional - for debugging purposes)
	if h.encryptionMgr != nil {
		uploadState, err := h.encryptionMgr.GetMultipartUploadState(uploadID)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket":   bucket,
				"key":      key,
				"uploadId": uploadID,
			}).Warn("Failed to get upload state for logging, but upload was created successfully")
		} else {
			h.logger.WithFields(logrus.Fields{
				"bucket":         bucket,
				"key":            key,
				"uploadId":       uploadID,
				"keyFingerprint": uploadState.KeyFingerprint,
				"contentType":    uploadState.ContentType,
				"isCompleted":    uploadState.IsCompleted,
			}).Info("Successfully created encrypted multipart upload with details")
		}
	}

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

// prepareEncryptionMetadata prepares metadata for storage with encryption info
func (h *CreateHandler) prepareEncryptionMetadata(userMetadata, encryptionMetadata map[string]string) map[string]string {
	if encryptionMetadata == nil && userMetadata == nil {
		return nil
	}

	// Start with user metadata
	metadata := make(map[string]string)
	for k, v := range userMetadata {
		metadata[k] = v
	}

	// Add encryption metadata if provided
	for k, v := range encryptionMetadata {
		metadata[k] = v
	}

	return metadata
}
