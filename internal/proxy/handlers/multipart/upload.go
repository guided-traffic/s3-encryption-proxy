package multipart

import (
	"bytes"
	"fmt"
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
	s3Client        interfaces.S3ClientInterface
	encryptionMgr   *encryption.Manager
	logger          *logrus.Entry
	xmlWriter       *response.XMLWriter
	errorWriter     *response.ErrorWriter
	requestParser   *request.Parser
}

// NewUploadHandler creates a new upload handler
func NewUploadHandler(
	s3Client interfaces.S3ClientInterface,
	encryptionMgr *encryption.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *UploadHandler {
	return &UploadHandler{
		s3Client:      s3Client,
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
	}).Debug("UploadPart - Chunked transfer detection")

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
	}).Debug("UploadPart - Parameters validated successfully")

	// Get upload state to check for streaming mode
	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("Getting multipart upload state")

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
	dataAlgorithm := uploadState.Metadata["s3ep-dek-algorithm"] // Default prefix
	h.logger.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"dataAlgorithm": dataAlgorithm,
		"contentType":   contentType,
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

// handleStandardUploadPart handles non-streaming upload part requests
func (h *UploadHandler) handleStandardUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int) {
	ctx := r.Context()

	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"handler":    "standard",
	})

	// Read the entire request body
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read request body")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("body_size", len(bodyData)).Debug("Read request body for standard upload part")

	// Encrypt the part using encryption manager
	encResult, err := h.encryptionMgr.UploadPart(ctx, uploadID, partNumber, bodyData)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithFields(logrus.Fields{
		"originalSize":  len(bodyData),
		"encryptedSize": len(encResult.EncryptedData),
	}).Debug("Part encrypted successfully")

	// Prepare S3 upload part input with encrypted data
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
	uploadOutput, err := h.s3Client.UploadPart(ctx, uploadInput)
	if err != nil {
		log.WithError(err).Error("Failed to upload part to S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("etag", aws.ToString(uploadOutput.ETag)).Debug("Part uploaded successfully")

	// Store the part ETag for completion (like s3client does)
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
func (h *UploadHandler) handleStreamingUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int, uploadState *encryption.MultipartUploadState) {
	ctx := r.Context()

	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"handler":    "streaming",
	})

	// Check if AWS chunked encoding is being used
	var bodyReader io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "aws-chunked" {
		log.Debug("Detected AWS chunked encoding")
		bodyReader = &awsChunkedReader{reader: r.Body}
	}

	// For encryption, we need to read the part data into memory first
	// The s3client approach also reads all data first, then encrypts
	partData, err := io.ReadAll(bodyReader)
	if err != nil {
		log.WithError(err).Error("Failed to read part data")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("partSize", len(partData)).Debug("Read part data for streaming upload")

	// Encrypt the part using encryption manager
	encResult, err := h.encryptionMgr.UploadPart(ctx, uploadID, partNumber, partData)
	if err != nil {
		log.WithError(err).Error("Failed to encrypt part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithFields(logrus.Fields{
		"originalSize":  len(partData),
		"encryptedSize": len(encResult.EncryptedData),
	}).Debug("Part encrypted successfully")

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
	result, err := h.s3Client.UploadPart(ctx, uploadInput)
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
	}).Info("Successfully uploaded streaming part")
}

// awsChunkedReader handles AWS chunked encoding
type awsChunkedReader struct {
	reader io.Reader
	buffer []byte
	pos    int
	eof    bool
}

func (r *awsChunkedReader) Read(p []byte) (n int, err error) {
	if r.eof {
		return 0, io.EOF
	}

	// If we have buffered data, use it first
	if r.pos < len(r.buffer) {
		n = copy(p, r.buffer[r.pos:])
		r.pos += n
		return n, nil
	}

	// Read chunk size line
	sizeLine, err := r.readLine()
	if err != nil {
		return 0, err
	}

	// Parse chunk size (hex)
	var chunkSize int64
	if _, err := fmt.Sscanf(sizeLine, "%x", &chunkSize); err != nil {
		return 0, fmt.Errorf("invalid chunk size: %s", sizeLine)
	}

	// Check for end of chunks
	if chunkSize == 0 {
		r.eof = true
		return 0, io.EOF
	}

	// Read chunk data
	chunkData := make([]byte, chunkSize)
	if _, err := io.ReadFull(r.reader, chunkData); err != nil {
		return 0, err
	}

	// Read trailing CRLF
	if _, err := r.readLine(); err != nil {
		return 0, err
	}

	// Copy to output buffer
	n = copy(p, chunkData)
	if n < len(chunkData) {
		// Buffer remaining data
		r.buffer = chunkData[n:]
		r.pos = 0
	}

	return n, nil
}

func (r *awsChunkedReader) readLine() (string, error) {
	var line []byte
	for {
		b := make([]byte, 1)
		if _, err := r.reader.Read(b); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			break
		}
		if b[0] != '\r' {
			line = append(line, b[0])
		}
	}
	return string(line), nil
}
