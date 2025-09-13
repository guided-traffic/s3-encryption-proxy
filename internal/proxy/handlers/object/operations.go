package object

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

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
	encryptedDEKB64, hasEncryption, isStreamingEncryption := h.extractEncryptionMetadata(output.Metadata)

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

	if isStreamingEncryption {
		h.handleGetObjectStreamingDecryption(w, r, output, encryptedDEK, key)
		return
	}

	// Fallback to standard memory decryption for AES-GCM format
	h.handleGetObjectMemoryDecryption(w, r, output, encryptedDEK, key)
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

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Get content type
	contentType := r.Header.Get("Content-Type")

	// Check Content-Type for forcing single-part encryption (highest priority)
	forceEnvelopeEncryption := contentType == "application/x-s3ep-force-aes-gcm"
	forceStreamingEncryption := contentType == "application/x-s3ep-force-aes-ctr"

	// Get optimizations config
	segmentSize := h.getSegmentSize()

	// Content-Type forcing overrides automatic size-based decisions
	if forceEnvelopeEncryption {
		h.logger.WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"contentType": contentType,
		}).Info("Using AES-GCM encryption via Content-Type")
		h.putObjectDirect(w, r, bucket, key, body, contentType)
		return
	}

	if forceStreamingEncryption {
		h.logger.WithFields(map[string]interface{}{
			"bucket":      bucket,
			"key":         key,
			"contentType": contentType,
		}).Info("Using AES-CTR streaming encryption via Content-Type")
		h.putObjectStreaming(w, r, bucket, key, body, contentType)
		return
	}

	// No forcing - use automatic optimization based on file size
	// Check if we should use streaming multipart upload for large objects
	// Only use streaming if we know the content length and it's larger than segment size
	contentLength := int64(len(body))
	if segmentSize > 0 && contentLength > segmentSize {
		h.logger.WithFields(map[string]interface{}{
			"bucket":        bucket,
			"key":           key,
			"contentLength": contentLength,
		}).Info("Using streaming multipart upload for large object")
		h.putObjectStreaming(w, r, bucket, key, body, contentType)
		return
	}

	// For small objects, use direct encryption (AES-GCM)
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Info("Using direct encryption for small object")
	h.putObjectDirect(w, r, bucket, key, body, contentType)
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

// putObjectStreaming handles streaming multipart upload for large objects
func (h *Handler) putObjectStreaming(w http.ResponseWriter, r *http.Request, bucket, key string, data []byte, contentType string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Starting streaming multipart upload")

	// Create multipart upload
	createInput := &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String(contentType),
	}

	// Add other headers from request
	h.addCreateMultipartHeaders(r, createInput)

	// Use multipart handler for creating the upload - we'll implement this with encryption
	createOutput, err := h.createMultipartUploadWithEncryption(r.Context(), createInput, key, contentType)
	if err != nil {
		h.logger.WithError(err).Error("Failed to create multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	uploadID := aws.ToString(createOutput.UploadId)

	// Process stream in chunks
	var completedParts []types.CompletedPart
	partNumber := int32(1)
	segmentSize := h.getSegmentSize()
	buffer := make([]byte, segmentSize)

	reader := bytes.NewReader(data)

	for {
		// Read next chunk
		n, err := io.ReadFull(reader, buffer)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			// Abort upload on error
			h.abortMultipartUpload(r.Context(), bucket, key, uploadID)
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "ReadError", "Failed to read stream chunk")
			return
		}

		// Upload this chunk as a part using encryption
		partData := buffer[:n]
		partETag, err := h.uploadPartWithEncryption(r.Context(), bucket, key, uploadID, partNumber, partData)
		if err != nil {
			h.abortMultipartUpload(r.Context(), bucket, key, uploadID)
			h.logger.WithError(err).Error("Failed to upload part")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "UploadError", fmt.Sprintf("Failed to upload part %d", partNumber))
			return
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       aws.String(partETag),
			PartNumber: aws.Int32(partNumber),
		})

		partNumber++

		// If we read less than the buffer size, we're done
		if n < len(buffer) {
			break
		}
	}

	// Complete multipart upload with encryption
	completeOutput, err := h.completeMultipartUploadWithEncryption(r.Context(), bucket, key, uploadID, completedParts)
	if err != nil {
		h.logger.WithError(err).Error("Failed to complete multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
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
	if cleanedMetadata != nil {
		for key, value := range cleanedMetadata {
			w.Header().Set("x-amz-meta-"+key, value)
		}
	}

	w.WriteHeader(http.StatusOK)
}
