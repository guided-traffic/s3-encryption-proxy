package multipart

import (
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
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
	// aws-chunked describes the request framing, not the stored object; the
	// proxy decodes it before encrypting, so it must not be recorded.
	if contentEncoding := object.StripAWSChunked(r.Header.Get("Content-Encoding")); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
		h.logger.WithFields(logrus.Fields{
			"bucket":          bucket,
			"key":             key,
			"contentEncoding": contentEncoding,
		}).Debug("Setting Content-Encoding for S3")
	}
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}
	if contentDisposition := r.Header.Get("Content-Disposition"); contentDisposition != "" {
		input.ContentDisposition = aws.String(contentDisposition)
	}
	if contentLanguage := r.Header.Get("Content-Language"); contentLanguage != "" {
		input.ContentLanguage = aws.String(contentLanguage)
	}

	// Preserve user metadata, as every single-part upload path does. Entries that
	// look like encryption metadata are dropped so a client cannot inject its own.
	if userMetadata := h.userMetadata(r); len(userMetadata) > 0 {
		input.Metadata = userMetadata
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
		// The upload exists at the backend, so the abort must reach it even when the
		// request context is already cancelled by a client that disconnected.
		abortCtx, cancelAbort := utils.CleanupContext(r)
		defer cancelAbort()
		if _, abortErr := h.s3Backend.AbortMultipartUpload(abortCtx, abortInput); abortErr != nil {
			h.logger.WithError(abortErr).Warn("Failed to abort multipart upload after encryption initialization failure")
		}

		utils.HandleS3Error(w, h.logger, err, "Failed to initialize encryption for multipart upload", bucket, key)
		return
	}

	// Return the CreateMultipartUploadResult
	h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("Sending CreateMultipartUploadResult response to client")

	writeXMLDocument(w, h.logger, initiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadID: uploadID,
	})
}

// userMetadata collects the x-amz-meta-* headers of a request, dropping entries
// that carry the encryption metadata prefix.
func (h *CreateHandler) userMetadata(r *http.Request) map[string]string {
	metadataPrefix := h.encryptionMgr.GetMetadataKeyPrefix()

	metadata := make(map[string]string)
	for name, values := range r.Header {
		if len(values) == 0 || !strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
			continue
		}
		metaKey := strings.ToLower(name[len("x-amz-meta-"):])
		if strings.HasPrefix(metaKey, metadataPrefix) {
			continue
		}
		metadata[metaKey] = values[0]
	}
	return metadata
}
