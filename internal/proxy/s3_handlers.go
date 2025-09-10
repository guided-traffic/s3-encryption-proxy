package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

// writeNotImplementedResponse writes a standard "not implemented" response
func (s *Server) writeNotImplementedResponse(w http.ResponseWriter, operation string) {
	// Log to stdout for console tracking
	fmt.Printf("[NOT IMPLEMENTED] Operation '%s' called but not yet implemented\n", operation)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotImplemented</Code>
    <Message>` + operation + ` operation is not yet implemented</Message>
    <Resource>` + operation + `</Resource>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write not implemented response")
	}
}

// writeDetailedNotImplementedResponse writes a detailed "not implemented" response with method and query parameters
func (s *Server) writeDetailedNotImplementedResponse(w http.ResponseWriter, r *http.Request, operation string) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Add query parameters information
	queryParams := r.URL.Query()
	queryParamsList := make([]string, 0, len(queryParams))
	for param := range queryParams {
		queryParamsList = append(queryParamsList, param)
	}

	// Create detailed message
	var message string
	if len(queryParamsList) > 0 {
		message = fmt.Sprintf("%s operation with method %s and query parameters [%s] is not yet implemented",
			operation, r.Method, fmt.Sprintf("%v", queryParamsList))
	} else {
		message = fmt.Sprintf("%s operation with method %s is not yet implemented", operation, r.Method)
	}

	// Add resource path information
	resourcePath := r.URL.Path
	if bucket != "" {
		resourcePath = fmt.Sprintf("bucket: %s", bucket)
		if key != "" {
			resourcePath = fmt.Sprintf("bucket: %s, key: %s", bucket, key)
		}
	}

	// Log detailed information to stdout for console tracking
	fmt.Printf("[NOT IMPLEMENTED] %s (Resource: %s, URL: %s)\n", message, resourcePath, r.URL.String())

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusNotImplemented)
	response := `<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NotImplemented</Code>
    <Message>` + message + `</Message>
    <Resource>` + resourcePath + `</Resource>
    <RequestURL>` + r.URL.String() + `</RequestURL>
</Error>`
	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write detailed not implemented response")
	}
}

// ===== MULTIPART UPLOAD HANDLERS =====
// These handlers implement encrypted multipart uploads for large files

// handleCreateMultipartUpload handles create multipart upload
func (s *Server) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Detailed request logging for debugging
	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"method":        r.Method,
		"contentLength": r.ContentLength,
		"contentType":   r.Header.Get("Content-Type"),
		"userAgent":     r.Header.Get("User-Agent"),
		"transferEnc":   r.Header.Get("Transfer-Encoding"),
		"host":          r.Host,
		"remoteAddr":    r.RemoteAddr,
		"requestURI":    r.RequestURI,
	}).Debug("MULTIPART-DEBUG: Creating multipart upload - Request details")

	// Log all headers for debugging
	headerMap := make(map[string]string)
	for name, values := range r.Header {
		headerMap[name] = strings.Join(values, ", ")
	}
	s.logger.WithFields(map[string]interface{}{
		"bucket":  bucket,
		"key":     key,
		"headers": headerMap,
	}).Debug("MULTIPART-DEBUG: All request headers")

	// Create the multipart upload with S3
	s.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("MULTIPART-DEBUG: Sending CreateMultipartUpload request to S3")

	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Copy headers that should be preserved
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		input.ContentType = aws.String(contentType)
		s.logger.WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"contentType": contentType,
		}).Debug("MULTIPART-DEBUG: Setting Content-Type for S3")
	}
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
		s.logger.WithFields(map[string]interface{}{
			"bucket":          bucket,
			"key":             key,
			"contentEncoding": contentEncoding,
		}).Debug("MULTIPART-DEBUG: Setting Content-Encoding for S3")
	}

	result, err := s.s3Client.CreateMultipartUpload(r.Context(), input)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Error("MULTIPART-DEBUG: Failed to create multipart upload in S3")
		s.handleS3Error(w, err, "Failed to create multipart upload", bucket, key)
		return
	}

	if result == nil || result.UploadId == nil {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
			"result": result,
		}).Error("MULTIPART-DEBUG: S3 client returned nil result or nil UploadId")
		http.Error(w, "Failed to create multipart upload", http.StatusInternalServerError)
		return
	}

	uploadID := *result.UploadId
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Successfully created S3 multipart upload")

	// Note: The S3 client already initializes the encryption state for multipart uploads,
	// so we don't need to do it again here. The uploadID is already registered with the encryption manager.

	// Get the upload state for logging (optional - for debugging purposes)
	if s.encryptionMgr != nil {
		uploadState, err := s.encryptionMgr.GetMultipartUploadState(uploadID)
		if err != nil {
			s.logger.WithError(err).WithFields(map[string]interface{}{
				"bucket":   bucket,
				"key":      key,
				"uploadId": uploadID,
			}).Warn("MULTIPART-DEBUG: Failed to get upload state for logging, but upload was created successfully")
		} else {
			s.logger.WithFields(map[string]interface{}{
				"bucket":            bucket,
				"key":               key,
				"uploadId":          uploadID,
				"keyFingerprint":    uploadState.KeyFingerprint,
				"contentType":       uploadState.ContentType,
				"isCompleted":       uploadState.IsCompleted,
			}).Info("MULTIPART-DEBUG: Successfully created encrypted multipart upload with details")
		}
	}

	// Return the CreateMultipartUploadResult
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Sending CreateMultipartUploadResult response to client")

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <UploadId>%s</UploadId>
</InitiateMultipartUploadResult>`, bucket, key, uploadID)

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write multipart upload response")
		// At this point we can't send an error response since headers are already sent
		return
	}
}

// handleUploadPart handles upload part
func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	// Detailed request logging for debugging
	s.logger.WithFields(map[string]interface{}{
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
	}).Debug("MULTIPART-DEBUG: UploadPart - Request details")

	// Log chunked transfer detection
	isChunked := r.Header.Get("Transfer-Encoding") == "chunked"
	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumberStr,
		"isChunked":  isChunked,
	}).Debug("MULTIPART-DEBUG: UploadPart - Chunked transfer detection")

	if uploadID == "" || partNumberStr == "" {
		s.logger.WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumberStr,
		}).Error("MULTIPART-DEBUG: Missing uploadId or partNumber")
		http.Error(w, "Missing uploadId or partNumber", http.StatusBadRequest)
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		s.logger.WithFields(map[string]interface{}{
			"bucket":       bucket,
			"key":          key,
			"uploadId":     uploadID,
			"partNumber":   partNumberStr,
			"parsedNumber": partNumber,
			"parseError":   err,
		}).Error("MULTIPART-DEBUG: Invalid partNumber")
		http.Error(w, "Invalid partNumber", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: UploadPart - Parameters validated successfully")

	// Get upload state to check for streaming mode
	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: Getting multipart upload state")

	uploadState, err := s.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to get multipart upload state")
		http.Error(w, "Invalid upload ID", http.StatusBadRequest)
		return
	}

	// Get metadata prefix for consistent access
	metadataPrefix := ""
	if s.config.Encryption.MetadataKeyPrefix != nil {
		metadataPrefix = *s.config.Encryption.MetadataKeyPrefix
	}

	// Check content type - multipart uploads always use streaming
	contentType := string(uploadState.ContentType)
	dataAlgorithm := uploadState.Metadata[metadataPrefix+"data-algorithm"]
	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"dataAlgorithm": dataAlgorithm,
		"contentType":   contentType,
	}).Debug("MULTIPART-DEBUG: Upload state retrieved - determining handler")

	// For multipart uploads (ContentTypeMultipart), always use streaming handler
	if contentType == "multipart" || dataAlgorithm == "aes-256-ctr" {
		s.logger.WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Debug("MULTIPART-DEBUG: Using streaming upload handler for multipart upload")
		s.handleStreamingUploadPartIntegrated(w, r, bucket, key, uploadID, partNumber, uploadState)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: Using standard upload handler")

	// Standard (non-streaming) upload part handling
	s.handleStandardUploadPart(w, r, bucket, key, uploadID, partNumber)
}

// handleStandardUploadPart handles non-streaming upload parts
func (s *Server) handleStandardUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int) {
	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: Starting standard upload part processing")

	// Read and decode the part data (handle chunked encoding)
	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"contentLength": r.ContentLength,
		"transferEnc":   r.Header.Get("Transfer-Encoding"),
		"contentSha256": r.Header.Get("X-Amz-Content-Sha256"),
	}).Debug("MULTIPART-DEBUG: Reading and decoding part data from request body")

	partData, err := s.decodeRequestBody(r, bucket, key)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to read and decode part data")
		http.Error(w, "Failed to read part data", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"dataSize":   len(partData),
	}).Debug("MULTIPART-DEBUG: Successfully read part data, starting encryption")

	// Encrypt the part data
	encryptionResult, err := s.encryptionMgr.UploadPart(r.Context(), uploadID, partNumber, partData)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
			"dataSize":   len(partData),
		}).Error("MULTIPART-DEBUG: Failed to encrypt part data")
		http.Error(w, "Failed to encrypt part data", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":           bucket,
		"key":              key,
		"uploadId":         uploadID,
		"partNumber":       partNumber,
		"originalSize":     len(partData),
		"encryptedSize":    len(encryptionResult.EncryptedData),
		"compressionRatio": float64(len(encryptionResult.EncryptedData)) / float64(len(partData)),
	}).Debug("MULTIPART-DEBUG: Successfully encrypted part data, uploading to S3")

	// Upload the encrypted part to S3
	// Double-check part number range before conversion (already validated above)
	if partNumber < 1 || partNumber > 10000 {
		http.Error(w, "Part number out of valid range", http.StatusBadRequest)
		return
	}

	uploadInput := &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(int32(partNumber)), // #nosec G109 - partNumber validated to be 1-10000
		Body:       bytes.NewReader(encryptionResult.EncryptedData),
	}

	uploadResult, err := s.s3Client.UploadPart(r.Context(), uploadInput)
	if err != nil {
		s.handleS3Error(w, err, "Failed to upload part", bucket, key)
		return
	}

	// Store the ETag in the encryption manager
	etag := aws.ToString(uploadResult.ETag)
	err = s.encryptionMgr.StorePartETag(uploadID, partNumber, etag)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
			"etag":       etag,
		}).Error("MULTIPART-DEBUG: Failed to store part ETag in encryption manager")
		http.Error(w, "Failed to store part metadata", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"etag":       etag,
	}).Debug("MULTIPART-DEBUG: Successfully uploaded encrypted part")

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"etag":       etag,
		"size":       len(encryptionResult.EncryptedData),
	}).Info("Successfully uploaded encrypted part")

	// Return the ETag
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

// handleUploadPartCopy handles upload part copy
func (s *Server) handleUploadPartCopy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	if uploadID == "" || partNumberStr == "" {
		http.Error(w, "Missing uploadId or partNumber", http.StatusBadRequest)
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		http.Error(w, "Invalid partNumber", http.StatusBadRequest)
		return
	}

	// Get the copy source from headers
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource == "" {
		http.Error(w, "Missing x-amz-copy-source header", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"copySource": copySource,
	}).Debug("Copying part from source")

	// For encrypted multipart uploads, we need to:
	// 1. Download the source object part
	// 2. Decrypt it (if it was encrypted)
	// 3. Re-encrypt it with the current upload's encryption context
	// 4. Upload it as a part

	// Parse the copy source to extract source bucket and key
	// Format: "source-bucket/source-object-key"
	sourceParts := strings.SplitN(copySource[1:], "/", 2) // Remove leading slash
	if len(sourceParts) != 2 {
		http.Error(w, "Invalid copy source format", http.StatusBadRequest)
		return
	}
	sourceBucket, sourceKey := sourceParts[0], sourceParts[1]

	// For encrypted multipart uploads, copy operations are complex
	// The new encryption manager doesn't support direct copy operations for multipart uploads
	// This would require decrypting the source and re-encrypting with the target upload's encryption state
	s.logger.WithFields(map[string]interface{}{
		"uploadId":     uploadID,
		"sourceBucket": sourceBucket,
		"sourceKey":    sourceKey,
		"partNumber":   partNumber,
	}).Warn("MULTIPART-DEBUG: UploadPartCopy not supported for encrypted multipart uploads")

	// Always return not implemented for copy operations with encrypted objects
	http.Error(w, "UploadPartCopy not supported for encrypted objects", http.StatusNotImplemented)
}

// handleCompleteMultipartUpload handles complete multipart upload
func (s *Server) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	uploadID := r.URL.Query().Get("uploadId")
	if uploadID == "" {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Error("MULTIPART-DEBUG: Missing uploadId in complete request")
		http.Error(w, "Missing uploadId", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"method":        r.Method,
		"contentLength": r.ContentLength,
		"contentType":   r.Header.Get("Content-Type"),
	}).Debug("MULTIPART-DEBUG: Completing multipart upload - Request details")

	// Log request body for debugging (if not too large)
	if r.ContentLength > 0 && r.ContentLength < 4096 {
		bodyBytes, err := io.ReadAll(r.Body)
		if err == nil {
			s.logger.WithFields(map[string]interface{}{
				"bucket":      bucket,
				"key":         key,
				"uploadId":    uploadID,
				"requestBody": string(bodyBytes),
			}).Debug("MULTIPART-DEBUG: Complete request body content")
			// Restore the body for further processing
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	// Get the multipart upload state first to check if it exists
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Getting upload state for completion")

	uploadState, err := s.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to get multipart upload state")
		http.Error(w, "Multipart upload not found", http.StatusNotFound)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":          bucket,
		"key":             key,
		"uploadId":        uploadID,
		"keyFingerprint":  uploadState.KeyFingerprint,
		"contentType":     uploadState.ContentType,
		"partCount":       len(uploadState.PartETags),
	}).Debug("MULTIPART-DEBUG: Upload state retrieved, proceeding with S3 completion")

	// Complete the S3 multipart upload with parts from the request
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	// Forward the complete request to S3 as-is (the client provides the parts and ETags)
	result, err := s.s3Client.CompleteMultipartUpload(r.Context(), completeInput)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to complete multipart upload in S3")
		s.handleS3Error(w, err, "Failed to complete multipart upload", bucket, key)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"s3Location":    aws.ToString(result.Location),
		"s3ETag":        aws.ToString(result.ETag),
	}).Info("MULTIPART-DEBUG: Multipart upload completed successfully")

	// Return the completion response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	location := aws.ToString(result.Location)
	etag := aws.ToString(result.ETag)

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
    <Location>%s</Location>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <ETag>%s</ETag>
</CompleteMultipartUploadResult>`, location, bucket, key, etag)

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write complete multipart upload response")
		// At this point we can't send an error response since headers are already sent
		return
	}

	// Clean up the upload state
	if err := s.encryptionMgr.AbortMultipartUpload(r.Context(), uploadID); err != nil {
		s.logger.WithError(err).Error("Failed to clean up multipart upload state")
	}
}

// handleAbortMultipartUpload handles abort multipart upload
func (s *Server) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	uploadID := r.URL.Query().Get("uploadId")
	if uploadID == "" {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Error("MULTIPART-DEBUG: Missing uploadId in abort request")
		http.Error(w, "Missing uploadId", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
		"method":   r.Method,
	}).Debug("MULTIPART-DEBUG: Aborting multipart upload - Request details")

	// Abort the S3 multipart upload
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Sending abort request to S3")

	_, err := s.s3Client.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to abort multipart upload in S3")
		s.handleS3Error(w, err, "Failed to abort multipart upload", bucket, key)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: S3 abort successful, cleaning up encryption state")

	// Clean up the encryption state
	err = s.encryptionMgr.AbortMultipartUpload(r.Context(), uploadID)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to clean up multipart upload state")
		// Don't fail the request for this
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Info("Aborted multipart upload")

	w.WriteHeader(http.StatusNoContent)
}

// handleListParts handles list parts
func (s *Server) handleListParts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	uploadID := r.URL.Query().Get("uploadId")
	if uploadID == "" {
		http.Error(w, "Missing uploadId", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("Listing parts")

	// List parts from S3
	input := &s3.ListPartsInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	// Parse optional query parameters
	if maxParts := r.URL.Query().Get("max-parts"); maxParts != "" {
		if mp, err := strconv.Atoi(maxParts); err == nil {
			// Validate range to prevent integer overflow
			if mp >= 0 && mp <= int(^uint32(0)>>1) { // Max value for int32
				input.MaxParts = aws.Int32(int32(mp)) // #nosec G109 - Range validated above
			} else {
				http.Error(w, "Invalid max-parts parameter", http.StatusBadRequest)
				return
			}
		}
	}
	if partNumberMarker := r.URL.Query().Get("part-number-marker"); partNumberMarker != "" {
		input.PartNumberMarker = aws.String(partNumberMarker)
	}

	result, err := s.s3Client.ListParts(r.Context(), input)
	if err != nil {
		s.handleS3Error(w, err, "Failed to list parts", bucket, key)
		return
	}

	// Return the list parts response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Build parts XML
	partsXML := ""
	for _, part := range result.Parts {
		partsXML += fmt.Sprintf(`
    <Part>
        <PartNumber>%d</PartNumber>
        <LastModified>%s</LastModified>
        <ETag>%s</ETag>
        <Size>%d</Size>
    </Part>`,
			aws.ToInt32(part.PartNumber),
			part.LastModified.Format("2006-01-02T15:04:05.000Z"),
			aws.ToString(part.ETag),
			aws.ToInt64(part.Size))
	}

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <UploadId>%s</UploadId>
    <StorageClass>%s</StorageClass>
    <PartNumberMarker>%s</PartNumberMarker>
    <NextPartNumberMarker>%s</NextPartNumberMarker>
    <MaxParts>%d</MaxParts>
    <IsTruncated>%t</IsTruncated>%s
</ListPartsResult>`,
		bucket, key, uploadID,
		string(result.StorageClass),
		aws.ToString(result.PartNumberMarker),
		aws.ToString(result.NextPartNumberMarker),
		aws.ToInt32(result.MaxParts),
		aws.ToBool(result.IsTruncated),
		partsXML)

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write list parts response")
		// At this point we can't send an error response since headers are already sent
		return
	}
}

// handleListMultipartUploads handles list multipart uploads
func (s *Server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Listing multipart uploads")

	// List multipart uploads from S3
	input := &s3.ListMultipartUploadsInput{
		Bucket: aws.String(bucket),
	}

	// Parse optional query parameters
	if maxUploads := r.URL.Query().Get("max-uploads"); maxUploads != "" {
		if mu, err := strconv.Atoi(maxUploads); err == nil {
			// Validate range to prevent integer overflow
			if mu >= 0 && mu <= int(^uint32(0)>>1) { // Max value for int32
				input.MaxUploads = aws.Int32(int32(mu)) // #nosec G109 - Range validated above
			} else {
				http.Error(w, "Invalid max-uploads parameter", http.StatusBadRequest)
				return
			}
		}
	}
	if prefix := r.URL.Query().Get("prefix"); prefix != "" {
		input.Prefix = aws.String(prefix)
	}
	if delimiter := r.URL.Query().Get("delimiter"); delimiter != "" {
		input.Delimiter = aws.String(delimiter)
	}
	if keyMarker := r.URL.Query().Get("key-marker"); keyMarker != "" {
		input.KeyMarker = aws.String(keyMarker)
	}
	if uploadIdMarker := r.URL.Query().Get("upload-id-marker"); uploadIdMarker != "" {
		input.UploadIdMarker = aws.String(uploadIdMarker)
	}

	result, err := s.s3Client.ListMultipartUploads(r.Context(), input)
	if err != nil {
		s.handleS3Error(w, err, "Failed to list multipart uploads", bucket, "")
		return
	}

	// Return the list multipart uploads response
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Build uploads XML
	uploadsXML := ""
	for _, upload := range result.Uploads {
		uploadsXML += fmt.Sprintf(`
    <Upload>
        <Key>%s</Key>
        <UploadId>%s</UploadId>
        <Initiator>
            <ID>%s</ID>
            <DisplayName>%s</DisplayName>
        </Initiator>
        <Owner>
            <ID>%s</ID>
            <DisplayName>%s</DisplayName>
        </Owner>
        <StorageClass>%s</StorageClass>
        <Initiated>%s</Initiated>
    </Upload>`,
			aws.ToString(upload.Key),
			aws.ToString(upload.UploadId),
			aws.ToString(upload.Initiator.ID),
			aws.ToString(upload.Initiator.DisplayName),
			aws.ToString(upload.Owner.ID),
			aws.ToString(upload.Owner.DisplayName),
			string(upload.StorageClass),
			upload.Initiated.Format("2006-01-02T15:04:05.000Z"))
	}

	// Build common prefixes XML
	commonPrefixesXML := ""
	for _, cp := range result.CommonPrefixes {
		commonPrefixesXML += fmt.Sprintf(`
    <CommonPrefixes>
        <Prefix>%s</Prefix>
    </CommonPrefixes>`, aws.ToString(cp.Prefix))
	}

	response := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult>
    <Bucket>%s</Bucket>
    <KeyMarker>%s</KeyMarker>
    <UploadIdMarker>%s</UploadIdMarker>
    <NextKeyMarker>%s</NextKeyMarker>
    <NextUploadIdMarker>%s</NextUploadIdMarker>
    <Delimiter>%s</Delimiter>
    <Prefix>%s</Prefix>
    <MaxUploads>%d</MaxUploads>
    <IsTruncated>%t</IsTruncated>%s%s
</ListMultipartUploadsResult>`,
		bucket,
		aws.ToString(result.KeyMarker),
		aws.ToString(result.UploadIdMarker),
		aws.ToString(result.NextKeyMarker),
		aws.ToString(result.NextUploadIdMarker),
		aws.ToString(result.Delimiter),
		aws.ToString(result.Prefix),
		aws.ToInt32(result.MaxUploads),
		aws.ToBool(result.IsTruncated),
		uploadsXML,
		commonPrefixesXML)

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.WithError(err).Error("Failed to write list multipart uploads response")
		// At this point we can't send an error response since headers are already sent
		return
	}
}

// ===== OBJECT SUB-RESOURCE HANDLERS =====

// handleObjectACL handles object ACL operations
func (s *Server) handleObjectACL(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "ObjectACL")
}

// handleObjectTagging handles object tagging operations
func (s *Server) handleObjectTagging(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "ObjectTagging")
}

// handleObjectLegalHold handles object legal hold operations
func (s *Server) handleObjectLegalHold(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "ObjectLegalHold")
}

// handleObjectRetention handles object retention operations
func (s *Server) handleObjectRetention(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "ObjectRetention")
}

// handleObjectTorrent handles object torrent operations
func (s *Server) handleObjectTorrent(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "ObjectTorrent")
}

// handleSelectObjectContent handles select object content operations
func (s *Server) handleSelectObjectContent(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "SelectObjectContent")
}

// handleCopyObject handles copy object operations
func (s *Server) handleCopyObject(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "CopyObject")
}

// handleDeleteObjects handles delete objects operations
func (s *Server) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	s.writeDetailedNotImplementedResponse(w, r, "DeleteObjects")
}

// ===== BASIC BUCKET HANDLERS =====

// handleBucket handles basic bucket operations
func (s *Server) handleBucket(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s.logger.WithField("bucket", bucket).Debug("Handling bucket operation")

	switch r.Method {
	case "GET":
		// Check for query parameters to determine operation
		queryParams := r.URL.Query()

		// Define known sub-resource parameters that should be routed to handleBucketSubResource
		subResourceParams := []string{
			"acl", "cors", "versioning", "policy", "location", "logging",
			"notification", "tagging", "lifecycle", "replication", "website",
			"accelerate", "requestPayment", "uploads",
		}

		// Check if any sub-resource parameters are present
		hasSubResource := false
		for _, param := range subResourceParams {
			if queryParams.Has(param) {
				hasSubResource = true
				break
			}
		}

		if hasSubResource {
			// Sub-resource operation - route to specific handler
			s.handleBucketSubResource(w, r)
		} else {
			// Regular bucket listing (may include listing parameters like prefix, max-keys, etc.)
			s.handleListObjects(w, r)
		}
	case "PUT":
		// Create bucket
		output, err := s.s3Client.CreateBucket(r.Context(), &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to create bucket", bucket, "")
			return
		}

		// Set location header if provided
		if output.Location != nil {
			w.Header().Set("Location", *output.Location)
		}
		w.WriteHeader(http.StatusOK)

	case "DELETE":
		// Delete bucket
		_, err := s.s3Client.DeleteBucket(r.Context(), &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to delete bucket", bucket, "")
			return
		}
		w.WriteHeader(http.StatusNoContent)

	case "HEAD":
		// Head bucket
		_, err := s.s3Client.HeadBucket(r.Context(), &s3.HeadBucketInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			s.handleS3Error(w, err, "Failed to head bucket", bucket, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleBucketSlash handles bucket operations with trailing slash
func (s *Server) handleBucketSlash(w http.ResponseWriter, r *http.Request) {
	// Remove trailing slash and delegate to handleBucket
	s.handleBucket(w, r)
}

// handleBucketSubResource handles bucket sub-resource operations
func (s *Server) handleBucketSubResource(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	queryParams := r.URL.Query()

	s.logger.WithField("bucket", bucket).WithField("queryParams", queryParams).Debug("Handling bucket sub-resource operation")

	// Determine which sub-resource operation is being requested
	if queryParams.Has("acl") {
		s.handleBucketACL(w, r)
	} else if queryParams.Has("cors") {
		s.handleBucketCORS(w, r)
	} else if queryParams.Has("versioning") {
		s.handleBucketVersioning(w, r)
	} else if queryParams.Has("policy") {
		s.handleBucketPolicy(w, r)
	} else if queryParams.Has("location") {
		s.handleBucketLocation(w, r)
	} else if queryParams.Has("logging") {
		s.handleBucketLogging(w, r)
	} else if queryParams.Has("notification") {
		s.handleBucketNotification(w, r)
	} else if queryParams.Has("tagging") {
		s.handleBucketTagging(w, r)
	} else if queryParams.Has("lifecycle") {
		s.handleBucketLifecycle(w, r)
	} else if queryParams.Has("replication") {
		s.handleBucketReplication(w, r)
	} else if queryParams.Has("website") {
		s.handleBucketWebsite(w, r)
	} else if queryParams.Has("accelerate") {
		s.handleBucketAccelerate(w, r)
	} else if queryParams.Has("requestPayment") {
		s.handleBucketRequestPayment(w, r)
	} else if queryParams.Has("uploads") {
		s.handleListMultipartUploads(w, r)
	} else {
		// Unknown sub-resource - provide detailed information about what was requested
		s.writeDetailedNotImplementedResponse(w, r, "UnknownBucketSubResource")
	}
}

// handleStreamingUploadPartIntegrated handles streaming upload parts with the new Manager API
func (s *Server) handleStreamingUploadPartIntegrated(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int, uploadState *encryption.MultipartUploadState) {
	s.logger.WithFields(map[string]interface{}{
		"bucket":           bucket,
		"key":              key,
		"uploadId":         uploadID,
		"partNumber":       partNumber,
		"contentLength":    r.ContentLength,
		"transferEncoding": r.Header.Get("Transfer-Encoding"),
		"contentType":      r.Header.Get("Content-Type"),
		"contentSha256":    r.Header.Get("X-Amz-Content-Sha256"),
		"isChunked":        r.Header.Get("Transfer-Encoding") == "chunked",
	}).Debug("MULTIPART-DEBUG: Starting streaming upload part with detailed request info")

	// Validate part number range
	if partNumber > 2147483647 { // Max int32 value
		http.Error(w, "Part number exceeds maximum allowed value", http.StatusBadRequest)
		return
	}

	// Read and decode the part data (handle chunked encoding)
	partData, err := s.decodeRequestBody(r, bucket, key)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to read and decode streaming part data")
		http.Error(w, "Failed to read part data", http.StatusBadRequest)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":      bucket,
		"key":         key,
		"uploadId":    uploadID,
		"partNumber":  partNumber,
		"decodedSize": len(partData),
	}).Debug("MULTIPART-DEBUG: Successfully decoded streaming part data")

	// Use the S3 client with decoded data - it will handle encryption internally
	// No need to call encryptionMgr.UploadPart explicitly as s3Client.UploadPart does this
	uploadResult, err := s.s3Client.UploadPart(r.Context(), &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		PartNumber:    aws.Int32(int32(partNumber)), // #nosec G115 - bounds checked above
		UploadId:      aws.String(uploadID),
		Body:          bytes.NewReader(partData), // Use the decoded data
		ContentLength: aws.Int64(int64(len(partData))),
	})
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to upload encrypted part to S3")
		http.Error(w, "Failed to upload part to S3", http.StatusInternalServerError)
		return
	}

	etag := aws.ToString(uploadResult.ETag)

	// Store the ETag in the encryption manager
	err = s.encryptionMgr.StorePartETag(uploadID, partNumber, etag)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
			"etag":       etag,
		}).Error("MULTIPART-DEBUG: Failed to store part ETag in encryption manager")
		http.Error(w, "Failed to store part metadata", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
		"etag":       etag,
	}).Info("MULTIPART-DEBUG: Streaming upload part completed successfully")

	// Return success response with ETag
	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

// decodeRequestBody reads and decodes request body, handling both AWS and HTTP chunked encoding
func (s *Server) decodeRequestBody(r *http.Request, bucket, key string) ([]byte, error) {
	transferEncoding := r.Header.Get("Transfer-Encoding")
	contentSha256 := r.Header.Get("X-Amz-Content-Sha256")

	s.logger.WithFields(map[string]interface{}{
		"bucket":           bucket,
		"key":              key,
		"transferEncoding": transferEncoding,
		"contentSha256":    contentSha256,
	}).Debug("s3_handlers.go > decodeRequestBody(): Checking encoding headers for request body")

	// Check for AWS chunked encoding (indicated by streaming SHA256 header)
	isAWSChunked := contentSha256 == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	isHTTPChunked := transferEncoding == "chunked" || strings.Contains(transferEncoding, "chunked")

	var bodyBytes []byte
	var err error

	if isAWSChunked {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Debug("s3_handlers.go > decodeRequestBody(): Detected AWS Signature V4 chunked encoding, decoding chunks")

		// Use our AWS chunked reader to decode
		bodyBytes, err = ReadAllAWSChunked(r.Body)
		if err != nil {
			s.logger.WithError(err).WithFields(map[string]interface{}{
				"bucket": bucket,
				"key":    key,
			}).Error("s3_handlers.go > decodeRequestBody(): Failed to decode AWS chunked request body")
			return nil, fmt.Errorf("failed to decode AWS chunked request body: %w", err)
		}
		s.logger.WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"decodedSize": len(bodyBytes),
		}).Debug("s3_handlers.go > decodeRequestBody(): Successfully decoded AWS chunked encoding")

	} else if isHTTPChunked {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Debug("s3_handlers.go > decodeRequestBody(): Detected HTTP chunked transfer encoding, decoding chunks")

		// Use Go's built-in chunked reader
		chunkedReader := httputil.NewChunkedReader(r.Body)
		bodyBytes, err = io.ReadAll(chunkedReader)
		if err != nil {
			s.logger.WithError(err).WithFields(map[string]interface{}{
				"bucket": bucket,
				"key":    key,
			}).Error("s3_handlers.go > decodeRequestBody(): Failed to decode HTTP chunked request body")
			return nil, fmt.Errorf("failed to decode HTTP chunked request body: %w", err)
		}
		s.logger.WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"decodedSize": len(bodyBytes),
		}).Debug("s3_handlers.go > decodeRequestBody(): Successfully decoded HTTP chunked transfer encoding")

	} else {
		s.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Debug("s3_handlers.go > decodeRequestBody(): No chunked encoding detected, reading body directly")

		// Standard read
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			s.logger.WithError(err).WithFields(map[string]interface{}{
				"bucket": bucket,
				"key":    key,
			}).Error("s3_handlers.go > decodeRequestBody(): Failed to read request body")
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		s.logger.WithFields(map[string]interface{}{
			"bucket":  bucket,
			"key":     key,
			"rawSize": len(bodyBytes),
		}).Debug("s3_handlers.go > decodeRequestBody(): Successfully read request body directly")
	}

	return bodyBytes, nil
}
