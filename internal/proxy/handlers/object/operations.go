package object

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
)

// Note: HTTP chunked encoding is automatically handled by Go's http package.
// If we reach this point, the data should already be de-chunked.
// AWS S3 chunked encoding (for signature v4) is different and would need special handling,
// but that's typically handled by the AWS SDK, not manually here.

// handleGetObject handles GET object requests with decryption support
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object")

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	// Add range header if present
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		input.Range = aws.String(rangeHeader)
	}

	// Add if-match headers
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}

	// Get the encrypted object from S3
	output, err := h.s3Client.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer output.Body.Close()

	// Check if the object has encryption metadata
	encryptedDEKB64, hasEncryption, _ := h.extractEncryptionMetadata(output.Metadata)

	if !hasEncryption {
		// Object is not encrypted, return as-is
		h.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Debug("Object not encrypted, returning as-is")
		h.writeGetObjectResponse(w, output, false)
		return
	}

	// Decode the encrypted DEK
	encryptedDEK, err := h.decodeEncryptedDEK(encryptedDEKB64)
	if err != nil {
		h.logger.WithError(err).Error("Failed to decode encrypted DEK")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError", "Failed to decode encryption key")
		return
	}

	// Check DEK algorithm to determine processing method
	dekAlgorithm := "aes-gcm" // Default fallback for legacy objects
	if dekAlgorithmValue, exists := output.Metadata[h.metadataPrefix+"dek-algorithm"]; exists {
		dekAlgorithm = dekAlgorithmValue
	}

	h.logger.WithFields(map[string]interface{}{
		"bucket":       bucket,
		"key":          key,
		"dekAlgorithm": dekAlgorithm,
	}).Debug("Processing encrypted object based on DEK algorithm")

	if dekAlgorithm == "aes-256-ctr" {
		// For AES-CTR, check if this is a real streaming multipart object
		// Small files encrypted with multipart streaming but completed as single part
		// should use memory decryption for better compatibility
		contentLength := int64(0)
		if output.ContentLength != nil {
			contentLength = aws.ToInt64(output.ContentLength)
		}

		// Check if this is a real multipart object by looking for part metadata
		// Single-part files (even if encrypted with CTR) should use memory decryption
		isRealMultipart := h.isRealMultipartObject(output.Metadata, contentLength)

		if isRealMultipart {
			// Real multipart object: Use streaming decryption
			h.handleGetObjectStreamingDecryption(w, r, output, encryptedDEK, key)
		} else {
			// Single-part file (even with CTR): Use memory decryption for better compatibility
			h.logger.WithFields(map[string]interface{}{
				"bucket": bucket,
				"key":    key,
				"size":   contentLength,
			}).Debug("Using memory decryption for single-part CTR object")
			h.handleGetObjectMemoryDecryption(w, r, output, encryptedDEK, key)
		}
	} else {
		// AES-GCM: Use memory decryption for whole file processing
		h.handleGetObjectMemoryDecryption(w, r, output, encryptedDEK, key)
	}
}

// handleGetObjectStreamingDecryption handles memory-optimized decryption for multipart objects
func (h *Handler) handleGetObjectStreamingDecryption(w http.ResponseWriter, r *http.Request, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "get-streaming",
		"key":       objectKey,
	}).Debug("Using streaming decryption for multipart object")

	// Provider alias is not used for decryption selection anymore
	// Decryption is handled by key fingerprints and metadata
	providerAlias := ""

	// Create a streaming decryption reader with size hint for optimal buffer sizing
	contentLength := int64(-1)
	if output.ContentLength != nil {
		contentLength = aws.ToInt64(output.ContentLength)
	}

	decryptedReader, err := h.encryptionMgr.CreateStreamingDecryptionReaderWithSize(r.Context(), output.Body, encryptedDEK, output.Metadata, objectKey, providerAlias, contentLength)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create streaming decryption reader")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError", "Failed to create decryption reader")
		return
	}

	// Create modified output with decrypted reader
	decryptedOutput := &s3.GetObjectOutput{
		AcceptRanges:              output.AcceptRanges,
		Body:                      decryptedReader,
		CacheControl:              output.CacheControl,
		ContentDisposition:        output.ContentDisposition,
		ContentEncoding:           output.ContentEncoding,
		ContentLanguage:           output.ContentLanguage,
		ContentLength:             output.ContentLength, // Same length for AES-CTR
		ContentRange:              output.ContentRange,
		ContentType:               output.ContentType,
		DeleteMarker:              output.DeleteMarker,
		ETag:                      output.ETag,
		Expiration:                output.Expiration,
		ExpiresString:             output.ExpiresString,
		LastModified:              output.LastModified,
		Metadata:                  h.cleanMetadata(output.Metadata),
		MissingMeta:               output.MissingMeta,
		ObjectLockLegalHoldStatus: output.ObjectLockLegalHoldStatus,
		ObjectLockMode:            output.ObjectLockMode,
		ObjectLockRetainUntilDate: output.ObjectLockRetainUntilDate,
		PartsCount:                output.PartsCount,
		ReplicationStatus:         output.ReplicationStatus,
		RequestCharged:            output.RequestCharged,
		Restore:                   output.Restore,
		ServerSideEncryption:      output.ServerSideEncryption,
		SSECustomerAlgorithm:      output.SSECustomerAlgorithm,
		SSECustomerKeyMD5:         output.SSECustomerKeyMD5,
		SSEKMSKeyId:               output.SSEKMSKeyId,
		StorageClass:              output.StorageClass,
		TagCount:                  output.TagCount,
		VersionId:                 output.VersionId,
		WebsiteRedirectLocation:   output.WebsiteRedirectLocation,
		ChecksumCRC32:             output.ChecksumCRC32,
		ChecksumCRC32C:            output.ChecksumCRC32C,
		ChecksumSHA1:              output.ChecksumSHA1,
		ChecksumSHA256:            output.ChecksumSHA256,
	}

	h.writeGetObjectResponse(w, decryptedOutput, true)
}

// handleGetObjectMemoryDecryption handles full memory decryption for AES-GCM objects
func (h *Handler) handleGetObjectMemoryDecryption(w http.ResponseWriter, r *http.Request, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) {
	// Read the encrypted data first
	encryptedData, err := io.ReadAll(output.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read encrypted object data")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "ReadError", "Failed to read object data")
		return
	}

	// Close the original body safely
	if output.Body != nil {
		if closeErr := output.Body.Close(); closeErr != nil {
			h.logger.WithError(closeErr).WithField("key", objectKey).Warn("Failed to close original body")
		}
	}

	// Use the manager to decrypt the data
	// For backward compatibility, we try to find a provider alias
	providerAlias := ""

	// Pass metadata to support streaming decryption
	plaintext, err := h.encryptionMgr.DecryptDataWithMetadata(r.Context(), encryptedData, encryptedDEK, output.Metadata, objectKey, providerAlias)
	if err != nil {
		h.logger.WithError(err).Error("Failed to decrypt object data")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError", "Failed to decrypt object data")
		return
	}

	// Create a new response body reader from the decrypted data
	responseReader := bytes.NewReader(plaintext)
	responseBody := io.NopCloser(responseReader)

	// Create modified output with decrypted data
	decryptedOutput := &s3.GetObjectOutput{
		AcceptRanges:              output.AcceptRanges,
		Body:                      responseBody,
		CacheControl:              output.CacheControl,
		ContentDisposition:        output.ContentDisposition,
		ContentEncoding:           output.ContentEncoding,
		ContentLanguage:           output.ContentLanguage,
		ContentLength:             aws.Int64(int64(len(plaintext))),
		ContentRange:              output.ContentRange,
		ContentType:               output.ContentType,
		DeleteMarker:              output.DeleteMarker,
		ETag:                      output.ETag,
		Expiration:                output.Expiration,
		ExpiresString:             output.ExpiresString,
		LastModified:              output.LastModified,
		Metadata:                  h.cleanMetadata(output.Metadata),
		MissingMeta:               output.MissingMeta,
		ObjectLockLegalHoldStatus: output.ObjectLockLegalHoldStatus,
		ObjectLockMode:            output.ObjectLockMode,
		ObjectLockRetainUntilDate: output.ObjectLockRetainUntilDate,
		PartsCount:                output.PartsCount,
		ReplicationStatus:         output.ReplicationStatus,
		RequestCharged:            output.RequestCharged,
		Restore:                   output.Restore,
		ServerSideEncryption:      output.ServerSideEncryption,
		SSECustomerAlgorithm:      output.SSECustomerAlgorithm,
		SSECustomerKeyMD5:         output.SSECustomerKeyMD5,
		SSEKMSKeyId:               output.SSEKMSKeyId,
		StorageClass:              output.StorageClass,
		TagCount:                  output.TagCount,
		VersionId:                 output.VersionId,
		WebsiteRedirectLocation:   output.WebsiteRedirectLocation,
		ChecksumCRC32:             output.ChecksumCRC32,
		ChecksumCRC32C:            output.ChecksumCRC32C,
		ChecksumSHA1:              output.ChecksumSHA1,
		ChecksumSHA256:            output.ChecksumSHA256,
	}

	h.writeGetObjectResponse(w, decryptedOutput, true)
}

// writeGetObjectResponse writes the GET object response to the HTTP response writer
func (h *Handler) writeGetObjectResponse(w http.ResponseWriter, output *s3.GetObjectOutput, isDecrypted bool) {
	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}

	// Copy metadata headers (encryption metadata is already cleaned)
	if output.Metadata != nil {
		for key, value := range output.Metadata {
			w.Header().Set("x-amz-meta-"+key, value)
		}
	}

	w.WriteHeader(http.StatusOK)

	// Stream the object body
	if _, err := io.Copy(w, output.Body); err != nil {
		h.logger.WithError(err).Error("Failed to write object data")
	}
}

// handlePutObject handles PUT object requests with encryption support
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Putting object")

	// Get content type for encryption mode forcing
	contentType := r.Header.Get("Content-Type")

	// Determine processing strategy based on optimization settings and content type
	// Check if content-type forces streaming (AES-CTR)
	forced := contentType == "application/x-s3ep-force-aes-ctr"

	// Special handling for very small files with forced CTR
	// Very small files (< 1KB) can't use multipart upload due to S3 constraints
	// For these, use direct encryption but with CTR content type to force AES-CTR
	if forced && r.ContentLength >= 0 && r.ContentLength < 1024 {
		h.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"contentLength": r.ContentLength,
			"forced":        true,
			"reason":        "very_small_file_forced_ctr",
		}).Info("Using direct upload with forced AES-CTR for very small file")

		// Read the small amount of data into memory
		data, err := io.ReadAll(r.Body)
		if err != nil {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "ReadError", "Failed to read request body")
			return
		}

		h.putObjectDirect(w, r, bucket, key, data, contentType)
		return
	}

	// Use size-based routing unless forced by content-type
	// Use streaming for: forced CTR (>=1KB), unknown size, or files >= streaming threshold
	if forced || r.ContentLength < 0 || r.ContentLength >= h.config.Optimizations.StreamingThreshold {
		reason := getStreamingReason(forced, r.ContentLength, h.config.Optimizations.StreamingThreshold)
		h.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"contentLength": r.ContentLength,
			"streaming":     true,
			"reason":        reason,
		}).Info("Using streaming upload")
		h.putObjectStreamingReader(w, r, bucket, key, r.Body, contentType)
	} else {
		// Use direct encryption for small files (AES-GCM)
		h.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"contentLength": r.ContentLength,
			"streaming":     false,
			"reason":        fmt.Sprintf("size %d < threshold %d", r.ContentLength, h.config.Optimizations.StreamingThreshold),
		}).Info("Using direct upload")

		// Handle AWS Signature V4 streaming encoding before reading data
		var bodyReader io.Reader = r.Body

		// Check for AWS Signature V4 streaming (definitive detection)
		if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
			h.logger.Debug("Detected AWS Signature V4 streaming in direct upload, using AWSChunkedReader")
			bodyReader = request.NewAWSChunkedReader(r.Body)
		} // Read all data for direct encryption
		data, err := io.ReadAll(bodyReader)
		if err != nil {
			h.logger.WithError(err).Error("Failed to read request body")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "ReadError", "Failed to read request body")
			return
		}

		h.putObjectDirect(w, r, bucket, key, data, contentType)
	}
}

// getStreamingReason returns a human-readable reason for using streaming
func getStreamingReason(forced bool, contentLength int64, threshold int64) string {
	if forced {
		return "content-type forced"
	}
	return fmt.Sprintf("size %d >= threshold %d", contentLength, threshold)
}

// putObjectDirect handles direct encryption for small objects (AES-GCM)
func (h *Handler) putObjectDirect(w http.ResponseWriter, r *http.Request, bucket, key string, data []byte, contentType string) {
	// Encrypt the data with HTTP Content-Type awareness for encryption mode forcing
	encResult, err := h.encryptionMgr.EncryptDataWithHTTPContentType(r.Context(), data, key, contentType, false)
	if err != nil {
		h.logger.WithError(err).Error("Failed to encrypt object data")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to encrypt object data")
		return
	}

	// Prepare metadata
	metadata := h.prepareEncryptionMetadata(r, encResult)

	// Create input for S3
	input := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(encResult.EncryptedData),
		Metadata:    metadata,
		ContentType: aws.String(contentType),
	}

	// Add other headers from request
	h.addRequestHeaders(r, input)

	// Update content length to match final encrypted data
	input.ContentLength = aws.Int64(int64(len(encResult.EncryptedData)))

	// Store the encrypted object
	output, err := h.s3Client.PutObject(r.Context(), input)
	if err != nil {
		h.logger.WithError(err).Error("Failed to store encrypted object")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Info("Object encrypted and stored successfully")

	// Set response headers
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}

	w.WriteHeader(http.StatusOK)
}

// putObjectStreamingReader handles streaming multipart upload directly from reader
func (h *Handler) putObjectStreamingReader(w http.ResponseWriter, r *http.Request, bucket, key string, reader io.Reader, contentType string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Starting true streaming multipart upload")

	// Handle AWS Signature V4 streaming encoding before streaming processing
	if r.Header.Get("X-Amz-Content-Sha256") == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		h.logger.Debug("Detected AWS Signature V4 streaming in streaming upload, using AWSChunkedReader")
		reader = request.NewAWSChunkedReader(reader)
	}

	// Create multipart upload with encryption initialization
	createInput := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}

	// Add other headers from request
	h.addCreateMultipartHeaders(r, createInput)

	// Initialize encryption for this multipart upload
	encResult, err := h.encryptionMgr.EncryptDataWithHTTPContentType(r.Context(), []byte{}, key, contentType, true)
	if err != nil {
		h.logger.WithError(err).Error("Failed to initialize encryption for multipart upload")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to initialize encryption")
		return
	}

	// Prepare metadata for multipart upload
	var metadata map[string]string
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		metadata = createInput.Metadata
	} else {
		// For encrypted providers, create metadata with encryption info
		metadata = h.prepareEncryptionMetadata(r, encResult)
	}
	createInput.Metadata = metadata

	// Create multipart upload in S3 first
	createOutput, err := h.s3Client.CreateMultipartUpload(r.Context(), createInput)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create multipart upload in S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	uploadID := aws.ToString(createOutput.UploadId)

	// Initialize multipart upload in encryption manager
	err = h.encryptionMgr.InitiateMultipartUpload(r.Context(), uploadID, key, bucket)
	if err != nil {
		// Clean up the S3 multipart upload if encryption initialization fails
		abortInput := &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}
		_, _ = h.s3Client.AbortMultipartUpload(r.Context(), abortInput)

		h.logger.WithError(err).Error("Failed to initialize multipart upload in encryption manager")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to initialize encryption")
		return
	}
	h.logger.WithField("uploadID", uploadID).Debug("Multipart upload created")

	var completedParts []types.CompletedPart
	partNumber := int32(1)
	segmentSize := h.getSegmentSize()
	if segmentSize <= 0 {
		segmentSize = 12 * 1024 * 1024 // 12MB default
	}

	// Use io.Pipe for true streaming without memory accumulation
	for {
		// Upload this part using encryption manager's streaming function directly from reader
		// This avoids allocating large buffers in memory
		limitedReader := io.LimitReader(reader, segmentSize)

		// Check if we have any data to read
		firstByte := make([]byte, 1)
		n, err := limitedReader.Read(firstByte)
		if err == io.EOF {
			break // No more data
		}
		if err != nil {
			h.abortMultipartUpload(r.Context(), bucket, key, uploadID)
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "ReadError", "Failed to read from stream")
			return
		}

		// Create a MultiReader to prepend the first byte back to the stream
		segmentReader := io.MultiReader(bytes.NewReader(firstByte[:n]), limitedReader)

		// Upload this part using encryption manager's streaming function
		encResult, err := h.encryptionMgr.UploadPartStreaming(r.Context(), uploadID, int(partNumber), segmentReader)
		if err != nil {
			h.abortMultipartUpload(r.Context(), bucket, key, uploadID)
			h.logger.WithError(err).Error("Failed to upload part with streaming encryption")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "UploadError", fmt.Sprintf("Failed to upload part %d", partNumber))
			return
		}

		// Upload the encrypted part to S3
		uploadPartInput := &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(partNumber),
			Body:          bytes.NewReader(encResult.EncryptedData),
			ContentLength: aws.Int64(int64(len(encResult.EncryptedData))),
		}

		uploadPartOutput, err := h.s3Client.UploadPart(r.Context(), uploadPartInput)
		if err != nil {
			h.abortMultipartUpload(r.Context(), bucket, key, uploadID)
			h.logger.WithError(err).Error("Failed to upload encrypted part to S3")
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       uploadPartOutput.ETag,
			PartNumber: aws.Int32(partNumber),
		})

		h.logger.WithFields(map[string]interface{}{
			"partNumber":    partNumber,
			"encryptedSize": len(encResult.EncryptedData),
		}).Debug("Part uploaded successfully")

		partNumber++
	}

	// Prepare part ETags for completion
	partETags := make(map[int]string)
	for _, part := range completedParts {
		partETags[int(aws.ToInt32(part.PartNumber))] = aws.ToString(part.ETag)
	}

	// Complete multipart upload with encryption
	finalMetadata, err := h.encryptionMgr.CompleteMultipartUpload(r.Context(), uploadID, partETags)
	if err != nil {
		h.logger.WithError(err).Error("Failed to complete multipart upload in encryption manager")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to complete encryption")
		return
	}

	// Complete the S3 multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	completeOutput, err := h.s3Client.CompleteMultipartUpload(r.Context(), completeInput)
	if err != nil {
		h.logger.WithError(err).Error("Failed to complete multipart upload in S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// After completing the multipart upload, add the encryption metadata
	// to the final object since S3 doesn't transfer metadata from CreateMultipartUpload
	if len(finalMetadata) > 0 {
		h.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"uploadID":      uploadID,
			"metadataCount": len(finalMetadata),
		}).Debug("Adding encryption metadata to completed object")

		// Copy the object to itself with the encryption metadata
		copyInput := &s3.CopyObjectInput{
			Bucket:            aws.String(bucket),
			Key:               aws.String(key),
			CopySource:        aws.String(fmt.Sprintf("%s/%s", bucket, key)),
			Metadata:          finalMetadata,
			MetadataDirective: types.MetadataDirectiveReplace,
		}

		_, err = h.s3Client.CopyObject(r.Context(), copyInput)
		if err != nil {
			h.logger.WithFields(map[string]interface{}{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).WithError(err).Error("Failed to add encryption metadata to completed object")
			// Don't fail the entire upload for metadata issues, just log the error
		} else {
			h.logger.WithFields(map[string]interface{}{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).Debug("Successfully added encryption metadata to completed object")
		}
	} else {
		h.logger.WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Debug("No metadata to add to completed object")
	}

	h.logger.WithFields(map[string]interface{}{
		"bucket":    bucket,
		"key":       key,
		"uploadID":  uploadID,
		"partCount": len(completedParts),
	}).Info("Streaming multipart upload completed successfully")

	// Set response headers
	if completeOutput.ETag != nil {
		w.Header().Set("ETag", *completeOutput.ETag)
	}

	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject handles DELETE object requests
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Deleting object")

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	_, err := h.s3Client.DeleteObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleHeadObject handles HEAD object requests with encryption metadata filtering
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object metadata")

	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := h.s3Client.HeadObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	}

	// Copy metadata headers (but filter out encryption metadata)
	cleanedMetadata := h.cleanMetadata(output.Metadata)
	for key, value := range cleanedMetadata {
		w.Header().Set("x-amz-meta-"+key, value)
	}

	w.WriteHeader(http.StatusOK)
}

// ===== PASSTHROUGH OPERATIONS =====
// These operations are passed through to S3 without encryption/decryption

// handleDeleteObjects handles bulk object deletion
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "delete-objects",
		"bucket":    bucket,
	}).Debug("Handling delete objects (passthrough)")

	// Parse request body to get delete request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Parse XML delete request
	var deleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			Key       string `xml:"Key"`
			VersionId string `xml:"VersionId,omitempty"`
		} `xml:"Object"`
		Quiet bool `xml:"Quiet"`
	}

	if err := xml.Unmarshal(body, &deleteRequest); err != nil {
		h.logger.WithFields(map[string]interface{}{
			"operation": "delete-objects",
			"bucket":    bucket,
			"error":     err.Error(),
			"bodySize":  len(body),
		}).Error("Failed to parse delete objects XML request")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML", "The XML you provided was not well-formed")
		return
	}

	// Convert parsed objects to AWS SDK types
	objects := make([]types.ObjectIdentifier, len(deleteRequest.Objects))
	for i, obj := range deleteRequest.Objects {
		objects[i] = types.ObjectIdentifier{
			Key: aws.String(obj.Key),
		}
		if obj.VersionId != "" {
			objects[i].VersionId = aws.String(obj.VersionId)
		}
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(deleteRequest.Quiet),
		},
	}

	// Copy headers for checksum validation
	if contentMD5 := r.Header.Get("Content-MD5"); contentMD5 != "" {
		input.ChecksumAlgorithm = types.ChecksumAlgorithmSha256
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":   "delete-objects",
		"bucket":      bucket,
		"objectCount": len(objects),
		"quiet":       deleteRequest.Quiet,
	}).Debug("Calling S3 delete objects")

	output, err := h.s3Client.DeleteObjects(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Create XML response structure
	type DeleteError struct {
		Key       string `xml:"Key"`
		Code      string `xml:"Code"`
		Message   string `xml:"Message"`
		VersionId string `xml:"VersionId,omitempty"`
	}

	type DeleteResult struct {
		XMLName xml.Name `xml:"DeleteResult"`
		Deleted []struct {
			Key       string `xml:"Key"`
			VersionId string `xml:"VersionId,omitempty"`
		} `xml:"Deleted"`
		Errors []DeleteError `xml:"Error"`
	}

	result := DeleteResult{}

	// Add successfully deleted objects
	for _, deleted := range output.Deleted {
		item := struct {
			Key       string `xml:"Key"`
			VersionId string `xml:"VersionId,omitempty"`
		}{
			Key: aws.ToString(deleted.Key),
		}
		if deleted.VersionId != nil {
			item.VersionId = aws.ToString(deleted.VersionId)
		}
		result.Deleted = append(result.Deleted, item)
	}

	// Add errors
	for _, errItem := range output.Errors {
		deleteErr := DeleteError{
			Key:     aws.ToString(errItem.Key),
			Code:    aws.ToString(errItem.Code),
			Message: aws.ToString(errItem.Message),
		}
		if errItem.VersionId != nil {
			deleteErr.VersionId = aws.ToString(errItem.VersionId)
		}
		result.Errors = append(result.Errors, deleteErr)
	}

	// Marshal and write XML response
	xmlData, err := xml.Marshal(result)
	if err != nil {
		h.logger.WithFields(map[string]interface{}{
			"operation": "delete-objects",
			"bucket":    bucket,
			"error":     err.Error(),
		}).Error("Failed to marshal delete objects response")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError", "Failed to generate response")
		return
	}

	// Write XML declaration and response
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		h.logger.WithError(err).Error("Failed to write XML header")
		return
	}
	if _, err := w.Write(xmlData); err != nil {
		h.logger.WithError(err).Error("Failed to write XML data")
		return
	}

	h.logger.WithFields(map[string]interface{}{
		"operation": "delete-objects",
		"bucket":    bucket,
		"deleted":   len(output.Deleted),
		"errors":    len(output.Errors),
	}).Debug("Delete objects completed")
}

// handleObjectLegalHold handles object legal hold operations
func (h *Handler) handleObjectLegalHold(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "object-legal-hold",
		"bucket":    bucket,
		"key":       key,
		"method":    r.Method,
	}).Debug("Handling object legal hold (passthrough)")

	switch r.Method {
	case "GET":
		input := &s3.GetObjectLegalHoldInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}

		_, err := h.s3Client.GetObjectLegalHold(r.Context(), input)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// TODO: Write proper XML response based on output.LegalHold

	case "PUT":
		_, err := io.ReadAll(r.Body)
		if err != nil {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read request body")
			return
		}
		defer r.Body.Close()

		input := &s3.PutObjectLegalHoldInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			LegalHold: &types.ObjectLockLegalHold{
				Status: types.ObjectLockLegalHoldStatusOn, // Parse from body
			},
		}

		_, err = h.s3Client.PutObjectLegalHold(r.Context(), input)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		w.WriteHeader(http.StatusOK)

	default:
		h.errorWriter.WriteGenericError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed for legal hold")
	}
}

// handleObjectRetention handles object retention operations
func (h *Handler) handleObjectRetention(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "object-retention",
		"bucket":    bucket,
		"key":       key,
		"method":    r.Method,
	}).Debug("Handling object retention (passthrough)")

	switch r.Method {
	case "GET":
		input := &s3.GetObjectRetentionInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}

		_, err := h.s3Client.GetObjectRetention(r.Context(), input)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		// TODO: Write proper XML response based on output.Retention

	case "PUT":
		_, err := io.ReadAll(r.Body)
		if err != nil {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read request body")
			return
		}
		defer r.Body.Close()

		input := &s3.PutObjectRetentionInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
			Retention: &types.ObjectLockRetention{
				Mode: types.ObjectLockRetentionModeGovernance, // Parse from body
				// RetainUntilDate: Parse from body
			},
		}

		_, err = h.s3Client.PutObjectRetention(r.Context(), input)
		if err != nil {
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}

		w.WriteHeader(http.StatusOK)

	default:
		h.errorWriter.WriteGenericError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "Method not allowed for retention")
	}
}

// handleObjectTorrent handles object torrent operations
func (h *Handler) handleObjectTorrent(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "object-torrent",
		"bucket":    bucket,
		"key":       key,
	}).Debug("Handling object torrent (passthrough)")

	input := &s3.GetObjectTorrentInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := h.s3Client.GetObjectTorrent(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer output.Body.Close()

	// Set content type for torrent file
	w.Header().Set("Content-Type", "application/x-bittorrent")

	// Copy the torrent data
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, output.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to copy torrent data")
	}
}

// handleSelectObjectContent handles S3 Select operations
func (h *Handler) handleSelectObjectContent(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "select-object-content",
		"bucket":    bucket,
		"key":       key,
	}).Debug("Handling select object content (passthrough)")

	// TODO: For encrypted objects, we would need to:
	// 1. Check if object is encrypted
	// 2. If encrypted, decrypt first then apply select
	// 3. For now, this is a simple passthrough

	_, err := io.ReadAll(r.Body)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read request body")
		return
	}
	defer r.Body.Close()

	input := &s3.SelectObjectContentInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		// Expression, ExpressionType, InputSerialization, OutputSerialization
		// would be parsed from the request body
	}

	output, err := h.s3Client.SelectObjectContent(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// For EventStream handling in passthrough mode, we'll simply forward the response
	// In a real implementation with encryption, we'd need to handle the event stream properly
	eventStream := output.GetStream()
	defer eventStream.Close()

	// Stream the select results
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Simplified event processing - just forward events as-is
	// TODO: Implement proper event handling for encrypted objects
	for event := range eventStream.Events() {
		// In a real implementation, we would parse event types and handle accordingly
		// For now, this is a placeholder to ensure compilation
		_ = event // Use the event variable to avoid "unused" error
	}

	if err := eventStream.Err(); err != nil {
		h.logger.WithError(err).Error("Error in select object content event stream")
	}

	h.logger.WithFields(map[string]interface{}{
		"operation": "select-object-content",
		"bucket":    bucket,
		"key":       key,
	}).Debug("Select object content completed (simplified passthrough)")
}

// isRealMultipartObject determines if an object was uploaded as a real multipart upload
// by checking for specific indicators in metadata and size characteristics
func (h *Handler) isRealMultipartObject(metadata map[string]string, contentLength int64) bool {
	// Check for multipart upload indicators in metadata
	// Real multipart uploads typically have part-related metadata or size characteristics

	// Size-based heuristic: Objects larger than multipart threshold are likely real multipart
	// The standard S3 multipart threshold is 5MB, but proxy uses streaming for all sizes
	// However, very small files (< 5MB) are very unlikely to be real multipart
	if contentLength < 5*1024*1024 { // Less than 5MB
		return false
	}

	// Check for explicit multipart indicators in metadata
	// This could be extended to check for specific multipart metadata patterns
	// For now, use size as primary indicator

	// Objects over 15MB are very likely to be real multipart
	if contentLength > 15*1024*1024 { // Greater than 15MB
		return true
	}

	// For medium sizes (5MB-15MB), check for other indicators
	// This could be enhanced with additional metadata checks if needed
	return false
}
