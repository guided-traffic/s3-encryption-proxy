package multipart

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// UploadHandler handles upload part operations
type UploadHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *encryption.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewUploadHandler creates a new upload handler
func NewUploadHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *UploadHandler {
	return &UploadHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles upload part requests
func (h *UploadHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	// Detailed request logging for debugging
	h.logger.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumberStr,
		"method":        r.Method,
		"contentLength": r.ContentLength,
		"contentType":   r.Header.Get("Content-Type"),
		"userAgent":     r.Header.Get("User-Agent"),
		"transferEnc":   r.Header.Get("Transfer-Encoding"),
		"contentEnc":    r.Header.Get("Content-Encoding"),
		"host":          r.Host,
		"remoteAddr":    r.RemoteAddr,
		"requestURI":    r.RequestURI,
	}).Debug("UploadPart - Request details")

	// Log chunked transfer detection
	isChunked := r.Header.Get("Transfer-Encoding") == "chunked"
	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumberStr,
		"isChunked":  isChunked,
	}).Trace("UploadPart - Chunked transfer detection")

	if uploadID == "" || partNumberStr == "" {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumberStr,
		}).Error("Missing uploadId or partNumber")
		http.Error(w, "Missing uploadId or partNumber", http.StatusBadRequest)
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		h.logger.WithFields(logrus.Fields{
			"bucket":       bucket,
			"key":          key,
			"uploadId":     uploadID,
			"partNumber":   partNumberStr,
			"parsedNumber": partNumber,
			"parseError":   err,
		}).Error("Invalid partNumber")
		http.Error(w, "Invalid partNumber", http.StatusBadRequest)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Trace("UploadPart - Parameters validated successfully")

	uploadState, err := h.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to get multipart upload state")
		http.Error(w, "Invalid upload ID", http.StatusBadRequest)
		return
	}

	// Check content type - multipart uploads always use streaming
	contentType := string(uploadState.ContentType)
	metadataPrefix := h.encryptionMgr.GetMetadataKeyPrefix()
	dataAlgorithm := uploadState.Metadata[metadataPrefix+"dek-algorithm"]
	h.logger.WithFields(logrus.Fields{
		"bucket":         bucket,
		"key":            key,
		"uploadId":       uploadID,
		"partNumber":     partNumber,
		"dataAlgorithm":  dataAlgorithm,
		"contentType":    contentType,
		"metadataPrefix": metadataPrefix,
	}).Debug("Upload state retrieved - determining handler")

	// For multipart uploads (ContentTypeMultipart), always use streaming handler
	if contentType == "multipart" || dataAlgorithm == "aes-256-ctr" {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Debug("Using streaming upload handler for multipart upload")
		h.handleStreamingUploadPart(w, r, bucket, key, uploadID, partNumber, uploadState)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("Using standard upload handler")

	// Standard (non-streaming) upload part handling
	h.handleStandardUploadPart(w, r, bucket, key, uploadID, partNumber)
}

// handleStandardUploadPart handles streaming upload part requests (no memory buffering)
func (h *UploadHandler) handleStandardUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int) {
	ctx := r.Context()

	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"handler":    "streaming-standard",
	})

	log.Debug("Using streaming encryption (NO memory buffering) to prevent OOM")

	// Check for AWS Signature V4 streaming
	var bodyReader io.Reader = r.Body
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		log.Debug("Detected AWS Signature V4 streaming via X-Amz-Content-Sha256 header")
		bodyReader = request.NewAWSChunkedReader(r.Body)
	}

	// Use streaming encryption instead of io.ReadAll to prevent OOM
	encResult, err := h.encryptionMgr.UploadPartStreaming(ctx, uploadID, partNumber, bodyReader)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithFields(logrus.Fields{
		"encryptedSize": len(encResult.EncryptedData),
	}).Debug("Part encrypted successfully with streaming")

	// Prepare S3 upload part input with encrypted data
	// Validate part number is within int32 range
	if partNumber < 1 || partNumber > 10000 {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("Part number out of valid range")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartNumber", "Part number must be between 1 and 10000")
		return
	}

	uploadInput := &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)),
		Body:          bytes.NewReader(encResult.EncryptedData),
		ContentLength: aws.Int64(int64(len(encResult.EncryptedData))),
	}

	// Copy required headers to S3 request
	if r.Header.Get("Content-MD5") != "" {
		uploadInput.ContentMD5 = aws.String(r.Header.Get("Content-MD5"))
	}

	// Upload the encrypted part to S3
	uploadOutput, err := h.s3Backend.UploadPart(ctx, uploadInput)
	if err != nil {
		log.WithError(err).Error("Failed to upload part to S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("etag", aws.ToString(uploadOutput.ETag)).Debug("Part uploaded successfully")

	// Store the part ETag for completion
	if uploadOutput.ETag != nil {
		cleanETag := strings.Trim(aws.ToString(uploadOutput.ETag), "\"")
		err = h.encryptionMgr.StorePartETag(uploadID, partNumber, cleanETag)
		if err != nil {
			log.WithFields(logrus.Fields{
				"uploadID":   uploadID,
				"partNumber": partNumber,
			}).Warn("Failed to store part ETag for completion")
		}
	}

	// Release encrypted data immediately after upload (memory management)
	encResult = nil

	// Return successful response with ETag
	w.Header().Set("ETag", aws.ToString(uploadOutput.ETag))
	if uploadOutput.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(uploadOutput.ServerSideEncryption))
	}
	w.WriteHeader(http.StatusOK)
}

// handleStreamingUploadPart handles streaming upload part requests with encryption
func (h *UploadHandler) handleStreamingUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int, _ *encryption.MultipartUploadState) {
	ctx := r.Context()

	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"handler":    "streaming",
	})

	// Check for AWS Signature V4 streaming
	var bodyReader io.Reader = r.Body
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		log.Debug("Detected AWS Signature V4 streaming via X-Amz-Content-Sha256 header in streaming handler")
		bodyReader = request.NewAWSChunkedReader(r.Body)
	}

	// Use streaming encryption instead of buffering entire part in memory
	log.Debug("Using streaming encryption for part upload")

	// Use the streaming encryption that processes data in chunks
	encResult, err := h.encryptionMgr.UploadPartStreaming(ctx, uploadID, partNumber, bodyReader)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt part with streaming")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("encryptedSize", len(encResult.EncryptedData)).Debug("Part encrypted successfully with streaming")

	// Validate part number is within int32 range (should already be validated but double check)
	if partNumber < 1 || partNumber > 10000 {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("Part number out of valid range for streaming")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartNumber", "Part number must be between 1 and 10000")
		return
	}

	// Prepare S3 upload part input with encrypted data
	uploadInput := &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)),
		Body:          bytes.NewReader(encResult.EncryptedData),
		ContentLength: aws.Int64(int64(len(encResult.EncryptedData))),
	}

	// Copy relevant headers
	if contentMD5 := r.Header.Get("Content-MD5"); contentMD5 != "" {
		uploadInput.ContentMD5 = aws.String(contentMD5)
	}

	// Perform the upload part operation
	result, err := h.s3Backend.UploadPart(ctx, uploadInput)
	if err != nil {
		log.WithError(err).Error("Failed to upload streaming part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Store part ETag in encryption manager
	if result.ETag != nil {
		cleanETag := strings.Trim(*result.ETag, "\"")
		err = h.encryptionMgr.StorePartETag(uploadID, partNumber, cleanETag)
		if err != nil {
			log.WithError(err).Warn("Failed to store part ETag")
			// Continue - this is not a critical error
		}
	}

	// Release encrypted data immediately after upload (memory management)
	encResult = nil

	// Set response headers
	if result.ETag != nil {
		w.Header().Set("ETag", *result.ETag)
	}
	if result.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(result.ServerSideEncryption))
	}
	if result.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *result.SSEKMSKeyId)
	}

	w.WriteHeader(http.StatusOK)

	log.WithFields(logrus.Fields{
		"etag":        result.ETag,
		"part_number": partNumber,
		"streaming":   true,
	}).Debug("Successfully uploaded streaming part")
}
