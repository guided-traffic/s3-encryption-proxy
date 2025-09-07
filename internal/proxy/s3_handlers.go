package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
	"github.com/sirupsen/logrus"
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

	// Check if encryption manager is available
	if s.encryptionMgr == nil {
		s.logger.WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Encryption manager is nil")
		http.Error(w, "Encryption not available", http.StatusInternalServerError)
		return
	}

	// Initialize encryption state for this multipart upload
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Initializing encryption state for multipart upload")

	uploadState, err := s.encryptionMgr.CreateMultipartUpload(r.Context(), uploadID, key, bucket)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to initialize encryption for multipart upload")
		// Abort the S3 multipart upload since we can't encrypt it
		if _, abortErr := s.s3Client.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}); abortErr != nil {
			s.logger.WithError(abortErr).WithFields(map[string]interface{}{
				"bucket":   bucket,
				"key":      key,
				"uploadId": uploadID,
			}).Error("MULTIPART-DEBUG: Failed to abort S3 multipart upload after encryption failure")
		}
		http.Error(w, "Failed to initialize encryption", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":         bucket,
		"key":            key,
		"uploadId":       uploadID,
		"providerAlias":  uploadState.ProviderAlias,
		"encryptionMode": uploadState.Metadata["encryption-mode"],
		"dekLength":      len(uploadState.DEK),
		"counterLength":  len(uploadState.Counter),
	}).Info("MULTIPART-DEBUG: Successfully created encrypted multipart upload with details")

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

	// Check if this is a streaming upload
	encryptionMode := uploadState.Metadata["encryption-mode"]
	s.logger.WithFields(map[string]interface{}{
		"bucket":         bucket,
		"key":            key,
		"uploadId":       uploadID,
		"partNumber":     partNumber,
		"encryptionMode": encryptionMode,
		"providerAlias":  uploadState.ProviderAlias,
		"totalBytes":     uploadState.TotalBytes,
	}).Debug("MULTIPART-DEBUG: Upload state retrieved - determining handler")

	if encryptionMode == "aes-ctr-streaming" {
		s.logger.WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Debug("MULTIPART-DEBUG: Using streaming upload handler")
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

	// Read the part data
	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"contentLength": r.ContentLength,
	}).Debug("MULTIPART-DEBUG: Reading part data from request body")

	partData, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to read part data")
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
	encryptionResult, err := s.encryptionMgr.EncryptMultipartData(r.Context(), uploadID, partNumber, partData)
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

	// Record the ETag for this part
	etag := aws.ToString(uploadResult.ETag)
	err = s.encryptionMgr.RecordPartETag(uploadID, partNumber, etag)
	if err != nil {
		s.logger.WithError(err).Error("Failed to record part ETag")
		// Don't fail the request for this
	}

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

	// For encrypted multipart uploads, this is a complex operation
	// We attempt to use the encryption manager to handle the copy
	_, err = s.encryptionMgr.CopyMultipartPart(uploadID, sourceBucket, sourceKey, "", partNumber)
	if err != nil {
		s.logger.WithError(err).Error("Failed to copy multipart part")
		// Always return not implemented for copy operations with encrypted objects
		http.Error(w, "UploadPartCopy not supported for encrypted objects", http.StatusNotImplemented)
		return
	}

	// If we reach here, the operation was successful (though currently it always fails)
	w.WriteHeader(http.StatusOK)
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

	// Get the multipart upload state for encryption metadata
	s.logger.WithFields(map[string]interface{}{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	}).Debug("MULTIPART-DEBUG: Getting upload state for completion")

	uploadState, err := s.encryptionMgr.CompleteMultipartUpload(uploadID)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
		}).Error("MULTIPART-DEBUG: Failed to get multipart upload state")
		http.Error(w, "Failed to complete multipart upload", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"providerAlias": uploadState.ProviderAlias,
		"totalBytes":    uploadState.TotalBytes,
		"partCount":     len(uploadState.PartETags),
	}).Debug("MULTIPART-DEBUG: Upload state retrieved, building parts list")

	// Complete the S3 multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	// Reconstruct the parts list from our stored ETags
	completeInput.MultipartUpload = &types.CompletedMultipartUpload{}
	var parts []types.CompletedPart
	for partNum, etag := range uploadState.PartETags {
		// AWS S3 part numbers must be between 1 and 10000
		if partNum < 1 || partNum > 10000 {
			s.logger.WithFields(map[string]interface{}{
				"bucket":   bucket,
				"key":      key,
				"uploadId": uploadID,
				"partNum":  partNum,
			}).Error("MULTIPART-DEBUG: Invalid part number in stored ETags")
			http.Error(w, "Invalid part number", http.StatusBadRequest)
			return
		}
		parts = append(parts, types.CompletedPart{
			PartNumber: aws.Int32(int32(partNum)), // #nosec G109 G115 - partNum validated to be 1-10000
			ETag:       aws.String(etag),
		})

		s.logger.WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadId": uploadID,
			"partNum":  partNum,
			"etag":     etag,
		}).Debug("MULTIPART-DEBUG: Added part to completion list")
	}

	// CRITICAL: Sort parts by PartNumber - S3 requires ascending order!
	sort.Slice(parts, func(i, j int) bool {
		return aws.ToInt32(parts[i].PartNumber) < aws.ToInt32(parts[j].PartNumber)
	})

	s.logger.WithFields(map[string]interface{}{
		"bucket":    bucket,
		"key":       key,
		"uploadId":  uploadID,
		"partCount": len(parts),
		"firstPart": aws.ToInt32(parts[0].PartNumber),
		"lastPart":  aws.ToInt32(parts[len(parts)-1].PartNumber),
	}).Debug("MULTIPART-DEBUG: Parts sorted by number, sending complete multipart upload request to S3")

	completeInput.MultipartUpload.Parts = parts

	s.logger.WithFields(map[string]interface{}{
		"bucket":    bucket,
		"key":       key,
		"uploadId":  uploadID,
		"partCount": len(parts),
	}).Debug("MULTIPART-DEBUG: Sending complete multipart upload request to S3")

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
		"providerAlias": uploadState.ProviderAlias,
		"etag":          aws.ToString(result.ETag),
	}).Debug("Multipart upload completed, now adding encryption metadata")

	// Add encryption metadata to the completed object using CopyObject
	// This is required because multipart uploads don't inherit metadata from the initial request
	encryptedDEKB64 := base64.StdEncoding.EncodeToString(uploadState.EncryptedDEK)
	ivB64 := base64.StdEncoding.EncodeToString(uploadState.Counter)

	copyInput := &s3.CopyObjectInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		CopySource: aws.String(fmt.Sprintf("%s/%s", bucket, key)),
		Metadata: map[string]string{
			"x-s3ep-provider":  uploadState.ProviderAlias,
			"x-s3ep-encrypted": "true",
			"x-s3ep-dek":       encryptedDEKB64,
			"x-s3ep-iv":        ivB64,
			"x-s3ep-mode":      "aes-ctr-streaming",
			"x-s3ep-multipart": "true",
		},
		MetadataDirective: types.MetadataDirectiveReplace,
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":          bucket,
		"key":             key,
		"provider":        uploadState.ProviderAlias,
		"encryptedDEKB64": encryptedDEKB64,
		"ivB64":           ivB64,
	}).Debug("Adding encryption metadata via CopyObject")

	copyResult, err := s.s3Client.CopyObject(r.Context(), copyInput)
	if err != nil {
		s.logger.WithError(err).Error("Failed to add encryption metadata to completed multipart upload")
		// Don't fail the request, the upload is already complete
		// But log this as an error because decryption won't work
	} else {
		s.logger.WithFields(map[string]interface{}{
			"bucket":       bucket,
			"key":          key,
			"copyETag":     aws.ToString(copyResult.CopyObjectResult.ETag),
			"originalETag": aws.ToString(result.ETag),
		}).Info("Successfully added encryption metadata to completed multipart upload")
	}

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
	if err := s.encryptionMgr.AbortMultipartUpload(uploadID); err != nil {
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
	err = s.encryptionMgr.AbortMultipartUpload(uploadID)
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

// handleStreamingUploadPartIntegrated handles streaming upload parts with AES-CTR
func (s *Server) handleStreamingUploadPartIntegrated(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int, uploadState *encryption.MultipartUploadState) {
	s.logger.WithFields(map[string]interface{}{
		"bucket":           bucket,
		"key":              key,
		"uploadId":         uploadID,
		"partNumber":       partNumber,
		"contentLength":    r.ContentLength,
		"transferEncoding": r.Header.Get("Transfer-Encoding"),
		"contentType":      r.Header.Get("Content-Type"),
		"isChunked":        r.Header.Get("Transfer-Encoding") == "chunked",
	}).Debug("MULTIPART-DEBUG: Starting streaming upload part with detailed request info")

	// Log upload state details
	s.logger.WithFields(map[string]interface{}{
		"bucket":         bucket,
		"key":            key,
		"uploadId":       uploadID,
		"partNumber":     partNumber,
		"providerAlias":  uploadState.ProviderAlias,
		"encryptionMode": uploadState.Metadata["encryption-mode"],
		"totalBytes":     uploadState.TotalBytes,
		"dekLength":      len(uploadState.DEK),
		"counterLength":  len(uploadState.Counter),
	}).Debug("MULTIPART-DEBUG: Upload state details for streaming")

	// Get the AES-CTR provider
	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"providerAlias": uploadState.ProviderAlias,
	}).Debug("MULTIPART-DEBUG: Getting AES-CTR provider for streaming")

	provider, exists := s.encryptionMgr.GetProvider(uploadState.ProviderAlias)
	if !exists {
		s.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"uploadId":      uploadID,
			"partNumber":    partNumber,
			"providerAlias": uploadState.ProviderAlias,
		}).Error("MULTIPART-DEBUG: Provider not found for streaming upload")
		http.Error(w, "Encryption provider not available", http.StatusInternalServerError)
		return
	}

	aesCTRProvider, ok := provider.(*providers.AESCTRProvider)
	if !ok {
		s.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"uploadId":      uploadID,
			"partNumber":    partNumber,
			"providerAlias": uploadState.ProviderAlias,
			"providerType":  fmt.Sprintf("%T", provider),
		}).Error("MULTIPART-DEBUG: Provider is not AES-CTR for streaming upload")
		http.Error(w, "Invalid encryption provider", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: Using streaming segmented approach for large files")

	// Get segment size from config (default 5MB)
	segmentSize := s.config.Streaming.SegmentSize
	if segmentSize == 0 {
		segmentSize = 5 * 1024 * 1024 // 5MB default
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumber,
		"segmentSize":   segmentSize,
		"segmentSizeMB": float64(segmentSize) / (1024 * 1024),
	}).Debug("MULTIPART-DEBUG: Starting streaming upload with segment size")

	// Process streaming transfer with segments
	err := s.processStreamingTransferWithSegments(r.Body, bucket, key, uploadID, &partNumber, aesCTRProvider, uploadState, segmentSize)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("MULTIPART-DEBUG: Failed to process streaming transfer")
		http.Error(w, "Failed to process streaming transfer", http.StatusInternalServerError)
		return
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":          bucket,
		"key":             key,
		"uploadId":        uploadID,
		"finalPartNumber": partNumber,
	}).Debug("MULTIPART-DEBUG: Streaming upload completed successfully")

	// Return success response
	w.WriteHeader(http.StatusOK)
}

// createChunkedReader creates a reader that handles AWS Signature V4 chunked encoding
func (s *Server) createChunkedReader(reader io.Reader) (io.Reader, error) {
	s.logger.Debug("MULTIPART-DEBUG: Creating chunked reader for AWS Signature V4")

	// Try to peek at the first few bytes to detect chunked encoding
	peekReader := bufio.NewReader(reader)
	firstLine, err := peekReader.Peek(100)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to peek at reader: %w", err)
	}

	firstLineStr := string(firstLine)
	s.logger.WithField("firstLine", firstLineStr).Debug("MULTIPART-DEBUG: Examining first line for chunk encoding")

	// Check if it looks like AWS Signature V4 chunked encoding
	// Format: "hex-size;chunk-signature=signature\r\n"
	if strings.Contains(firstLineStr, ";chunk-signature=") {
		s.logger.Debug("MULTIPART-DEBUG: Detected AWS Signature V4 chunked encoding")
		return &awsChunkedReader{
			reader: peekReader,
			logger: s.logger,
		}, nil
	}

	s.logger.Debug("MULTIPART-DEBUG: No chunked encoding detected, using original reader")
	return peekReader, nil
}

// awsChunkedReader implements io.Reader for AWS Signature V4 chunked encoding
type awsChunkedReader struct {
	reader *bufio.Reader
	logger logrus.FieldLogger
	buffer []byte
	offset int
	eof    bool
}

func (r *awsChunkedReader) Read(p []byte) (int, error) {
	if r.eof && len(r.buffer) == 0 {
		return 0, io.EOF
	}

	// If we have buffered data, return it first
	if len(r.buffer) > r.offset {
		n := copy(p, r.buffer[r.offset:])
		r.offset += n
		if r.offset >= len(r.buffer) {
			r.buffer = nil
			r.offset = 0
		}
		return n, nil
	}

	// Read next chunk - if we reach here, we need to read a new chunk
	if !r.eof {
		// Read chunk size line (e.g., "34;chunk-signature=...\r\n")
		chunkSizeLine, err := r.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				r.eof = true
				return 0, io.EOF
			}
			return 0, fmt.Errorf("failed to read chunk size line: %w", err)
		}

		chunkSizeLine = strings.TrimSpace(chunkSizeLine)
		r.logger.WithField("chunkSizeLine", chunkSizeLine).Debug("MULTIPART-DEBUG: Processing chunk size line")

		// Parse chunk size (before ';')
		parts := strings.Split(chunkSizeLine, ";")
		if len(parts) == 0 {
			return 0, fmt.Errorf("invalid chunk size line format: %s", chunkSizeLine)
		}

		chunkSizeStr := parts[0]
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse chunk size '%s': %w", chunkSizeStr, err)
		}

		r.logger.WithField("chunkSize", chunkSize).Debug("MULTIPART-DEBUG: Parsed chunk size")

		// If chunk size is 0, this is the last chunk
		if chunkSize == 0 {
			r.logger.Debug("MULTIPART-DEBUG: Reached final chunk (size 0)")
			// Read the trailing CRLF
			_, _ = r.reader.ReadString('\n')
			r.eof = true
			return 0, io.EOF
		}

		// Read the actual chunk data
		chunkData := make([]byte, chunkSize)
		_, err = io.ReadFull(r.reader, chunkData)
		if err != nil {
			return 0, fmt.Errorf("failed to read chunk data: %w", err)
		}

		// Read the trailing CRLF after chunk data
		_, _ = r.reader.ReadString('\n')

		r.logger.WithFields(map[string]interface{}{
			"chunkSize": chunkSize,
		}).Debug("MULTIPART-DEBUG: Successfully read chunk data")

		// Buffer the chunk data
		r.buffer = chunkData
		r.offset = 0

		// Return as much as fits in p
		n := copy(p, r.buffer[r.offset:])
		r.offset += n
		if r.offset >= len(r.buffer) {
			r.buffer = nil
			r.offset = 0
		}

		return n, nil
	}

	return 0, io.EOF
}

// processStreamingTransferWithSegments processes streaming data in segments and sends each segment as separate S3 upload parts
func (s *Server) processStreamingTransferWithSegments(reader io.Reader, bucket, key, uploadID string, partNumber *int, provider *providers.AESCTRProvider, uploadState *encryption.MultipartUploadState, segmentSize int64) error {
	// FIXED: Calculate counter based on part number instead of TotalBytes to avoid race conditions
	const standardPartSize = 5 * 1024 * 1024 // 5MB standard S3 part size
	baseCounter := uint64((*partNumber - 1) * standardPartSize)

	s.logger.WithFields(map[string]interface{}{
		"uploadId":          uploadID,
		"segmentSize":       segmentSize,
		"segmentSizeMB":     float64(segmentSize) / (1024 * 1024),
		"initialPartNumber": *partNumber,
		"initialCounter":    baseCounter,
	}).Debug("MULTIPART-DEBUG: Starting segmented streaming transfer")

	// Check if this is AWS Signature V4 chunked encoding
	var processedReader io.Reader
	var err error

	// Create a chunked reader to handle AWS Signature V4 chunked encoding
	processedReader, err = s.createChunkedReader(reader)
	if err != nil {
		s.logger.WithError(err).Debug("MULTIPART-DEBUG: Not chunked encoding or error processing chunks, using raw reader")
		processedReader = reader
	}

	// Initialize tracking variables
	// Check for negative TotalBytes before converting to uint64
	if uploadState.TotalBytes < 0 {
		return fmt.Errorf("invalid negative TotalBytes: %d", uploadState.TotalBytes)
	}

	// Use the previously calculated baseCounter from the beginning of the function
	counter := baseCounter

	totalBytesProcessed := int64(0)
	segmentBuffer := make([]byte, 0, segmentSize) // Pre-allocate segment buffer
	readBuffer := make([]byte, 64*1024)           // 64KB read buffer
	currentSegmentSize := int64(0)
	totalChunks := 0

	s.logger.WithFields(map[string]interface{}{
		"uploadId":         uploadID,
		"readBufferSize":   len(readBuffer),
		"segmentBufferCap": cap(segmentBuffer),
		"initialCounter":   counter,
	}).Debug("MULTIPART-DEBUG: Initialized buffers for streaming")

	// Process data chunk by chunk
	for {
		n, readErr := processedReader.Read(readBuffer)
		if n > 0 {
			totalChunks++
			chunk := readBuffer[:n]
			totalBytesProcessed += int64(n)

			s.logger.WithFields(map[string]interface{}{
				"uploadId":            uploadID,
				"chunkNumber":         totalChunks,
				"chunkSize":           n,
				"totalBytesProcessed": totalBytesProcessed,
				"currentCounter":      counter,
				"currentSegmentSize":  currentSegmentSize,
			}).Debug("MULTIPART-DEBUG: Processing chunk for streaming")

			// Encrypt chunk with current counter
			encryptedChunk, encErr := provider.EncryptStream(context.Background(), chunk, uploadState.DEK, uploadState.Counter, counter)
			if encErr != nil {
				return fmt.Errorf("failed to encrypt chunk %d: %w", totalChunks, encErr)
			}

			s.logger.WithFields(map[string]interface{}{
				"uploadId":      uploadID,
				"chunkNumber":   totalChunks,
				"originalSize":  n,
				"encryptedSize": len(encryptedChunk),
			}).Debug("MULTIPART-DEBUG: Chunk encrypted successfully")

			// Add encrypted chunk to segment buffer
			segmentBuffer = append(segmentBuffer, encryptedChunk...)
			currentSegmentSize += int64(len(encryptedChunk))
			// Check for potential overflow when converting int to uint64
			if n < 0 {
				return fmt.Errorf("invalid negative bytes read: %d", n)
			}
			counter += uint64(n) // Update counter by original bytes processed

			// Check if segment is ready to send
			if currentSegmentSize >= segmentSize {
				// Send this segment as an upload part
				err := s.uploadSegmentPart(context.Background(), bucket, key, uploadID, *partNumber, segmentBuffer)
				if err != nil {
					return fmt.Errorf("failed to upload segment part %d: %w", *partNumber, err)
				}

				s.logger.WithFields(map[string]interface{}{
					"uploadId":        uploadID,
					"partNumber":      *partNumber,
					"segmentSize":     currentSegmentSize,
					"chunksInSegment": "multiple",
				}).Debug("MULTIPART-DEBUG: Segment uploaded successfully")

				// Reset for next segment
				segmentBuffer = segmentBuffer[:0] // Reset slice but keep capacity
				currentSegmentSize = 0
				*partNumber++
			}
		}

		// Handle read completion
		if readErr == io.EOF {
			s.logger.WithFields(map[string]interface{}{
				"uploadId":             uploadID,
				"totalChunks":          totalChunks,
				"totalBytesProcessed":  totalBytesProcessed,
				"finalCounter":         counter,
				"remainingSegmentSize": currentSegmentSize,
			}).Debug("MULTIPART-DEBUG: Reached end of stream in segmented transfer")

			// Send any remaining data as final segment
			if currentSegmentSize > 0 {
				err := s.uploadSegmentPart(context.Background(), bucket, key, uploadID, *partNumber, segmentBuffer)
				if err != nil {
					return fmt.Errorf("failed to upload final segment part %d: %w", *partNumber, err)
				}

				s.logger.WithFields(map[string]interface{}{
					"uploadId":         uploadID,
					"partNumber":       *partNumber,
					"finalSegmentSize": currentSegmentSize,
				}).Debug("MULTIPART-DEBUG: Final segment uploaded successfully")

				*partNumber++
			}

			// Update total bytes in upload state
			bytesProcessed := counter - uint64(uploadState.TotalBytes)
			// Check for integer overflow when converting uint64 to int64
			if bytesProcessed > uint64(9223372036854775807) { // math.MaxInt64
				return fmt.Errorf("bytes processed overflow: %d exceeds maximum int64", bytesProcessed)
			}
			if err := s.encryptionMgr.UpdateMultipartTotalBytes(uploadID, int64(bytesProcessed)); err != nil {
				s.logger.WithError(err).WithFields(map[string]interface{}{
					"uploadId":       uploadID,
					"bytesProcessed": bytesProcessed,
				}).Error("MULTIPART-DEBUG: Failed to update total bytes")
			}

			s.logger.WithFields(map[string]interface{}{
				"uploadId":            uploadID,
				"totalBytesProcessed": totalBytesProcessed,
				"totalChunks":         totalChunks,
				"finalCounter":        counter,
				"totalPartsCreated":   *partNumber - 1,
			}).Debug("MULTIPART-DEBUG: Segmented streaming transfer completed successfully")

			break
		} else if readErr != nil {
			return fmt.Errorf("failed to read data during streaming: %w", readErr)
		}
	}

	return nil
}

// uploadSegmentPart uploads a single segment as an S3 upload part
func (s *Server) uploadSegmentPart(ctx context.Context, bucket, key, uploadID string, partNumber int, segmentData []byte) error {
	s.logger.WithFields(map[string]interface{}{
		"bucket":      bucket,
		"key":         key,
		"uploadId":    uploadID,
		"partNumber":  partNumber,
		"segmentSize": len(segmentData),
	}).Debug("MULTIPART-DEBUG: Uploading segment as S3 part")

	// Validate part number range to prevent overflow
	if partNumber < 1 || partNumber > 10000 {
		return fmt.Errorf("invalid part number: %d, must be between 1 and 10000", partNumber)
	}

	input := &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		PartNumber:    aws.Int32(int32(partNumber)), // #nosec G115 - partNumber validated to be 1-10000
		UploadId:      aws.String(uploadID),
		Body:          bytes.NewReader(segmentData),
		ContentLength: aws.Int64(int64(len(segmentData))),
	}

	result, err := s.s3Client.UploadPart(ctx, input)
	if err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"uploadId":    uploadID,
			"partNumber":  partNumber,
			"segmentSize": len(segmentData),
		}).Error("MULTIPART-DEBUG: Failed to upload segment part to S3")
		return err
	}

	// Record the ETag
	etag := aws.ToString(result.ETag)
	if err := s.encryptionMgr.RecordPartETag(uploadID, partNumber, etag); err != nil {
		s.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
			"etag":       etag,
		}).Error("MULTIPART-DEBUG: Failed to record part ETag")
		return err
	}

	s.logger.WithFields(map[string]interface{}{
		"bucket":      bucket,
		"key":         key,
		"uploadId":    uploadID,
		"partNumber":  partNumber,
		"etag":        etag,
		"segmentSize": len(segmentData),
	}).Debug("MULTIPART-DEBUG: Segment part uploaded and ETag recorded successfully")

	return nil
}
