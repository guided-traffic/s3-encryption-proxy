package object

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
)

// extractEncryptionMetadata extracts encryption metadata from S3 object metadata
func (h *Handler) extractEncryptionMetadata(metadata map[string]string) (string, bool, bool) {
	if metadata == nil {
		return "", false, false
	}

	// Look for encrypted DEK metadata
	encryptedDEKB64, hasEncryption := metadata[h.metadataPrefix+"encrypted-dek"]
	if !hasEncryption {
		return "", false, false
	}

	// Check if this is streaming encryption by looking for streaming-specific metadata
	dekAlgorithm := metadata[h.metadataPrefix+"dek-algorithm"]
	isStreamingEncryption := dekAlgorithm == "aes-ctr" || dekAlgorithm == "AES-CTR"

	return encryptedDEKB64, true, isStreamingEncryption
}

// decodeEncryptedDEK decodes the base64-encoded encrypted DEK
func (h *Handler) decodeEncryptedDEK(encryptedDEKB64 string) ([]byte, error) {
	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}
	return encryptedDEK, nil
}

// cleanMetadata removes encryption-related metadata from the response
func (h *Handler) cleanMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	cleaned := make(map[string]string)
	for key, value := range metadata {
		if !h.isEncryptionMetadata(key) {
			cleaned[key] = value
		}
	}

	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

// isEncryptionMetadata checks if a metadata key is encryption-related
func (h *Handler) isEncryptionMetadata(key string) bool {
	return len(key) >= len(h.metadataPrefix) && key[:len(h.metadataPrefix)] == h.metadataPrefix
}

// prepareEncryptionMetadata prepares encryption metadata for S3 storage
func (h *Handler) prepareEncryptionMetadata(r *http.Request, encResult *encryption.EncryptionResult) map[string]string {
	metadata := make(map[string]string)

	// Add user metadata from request headers (case-insensitive check for x-amz-meta- headers)
	for headerName, headerValues := range r.Header {
		if len(headerValues) > 0 && len(headerName) > 11 && strings.ToLower(headerName[:11]) == "x-amz-meta-" {
			metaKey := headerName[11:] // Remove "X-Amz-Meta-" prefix
			if !h.isEncryptionMetadata(metaKey) {
				metadata[metaKey] = headerValues[0]
			}
		}
	}

	// Add encryption metadata
	for key, value := range encResult.Metadata {
		metadata[key] = value
	}

	return metadata
}

// addRequestHeaders adds relevant request headers to S3 input
func (h *Handler) addRequestHeaders(r *http.Request, input *s3.PutObjectInput) {
	// Add cache control
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}

	// Add content disposition
	if contentDisposition := r.Header.Get("Content-Disposition"); contentDisposition != "" {
		input.ContentDisposition = aws.String(contentDisposition)
	}

	// Add content encoding
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}

	// Add content language
	if contentLanguage := r.Header.Get("Content-Language"); contentLanguage != "" {
		input.ContentLanguage = aws.String(contentLanguage)
	}
}

// addCreateMultipartHeaders adds relevant request headers to CreateMultipartUpload input
func (h *Handler) addCreateMultipartHeaders(r *http.Request, input *s3.CreateMultipartUploadInput) {
	// Add cache control
	if cacheControl := r.Header.Get("Cache-Control"); cacheControl != "" {
		input.CacheControl = aws.String(cacheControl)
	}

	// Add content disposition
	if contentDisposition := r.Header.Get("Content-Disposition"); contentDisposition != "" {
		input.ContentDisposition = aws.String(contentDisposition)
	}

	// Add content encoding
	if contentEncoding := r.Header.Get("Content-Encoding"); contentEncoding != "" {
		input.ContentEncoding = aws.String(contentEncoding)
	}

	// Add content language
	if contentLanguage := r.Header.Get("Content-Language"); contentLanguage != "" {
		input.ContentLanguage = aws.String(contentLanguage)
	}

	// Add user metadata from request headers
	metadata := make(map[string]string)
	for headerName, headerValues := range r.Header {
		if len(headerValues) > 0 && len(headerName) > 11 && strings.ToLower(headerName[:11]) == "x-amz-meta-" {
			metaKey := headerName[11:] // Remove "X-Amz-Meta-" prefix
			if !h.isEncryptionMetadata(metaKey) {
				metadata[metaKey] = headerValues[0]
			}
		}
	}
	if len(metadata) > 0 {
		input.Metadata = metadata
	}
}

// getSegmentSize returns the configured streaming segment size
func (h *Handler) getSegmentSize() int64 {
	// Default segment size for streaming uploads (12MB)
	const defaultSegmentSize = 12 * 1024 * 1024

	if h.config != nil && h.config.Optimizations.StreamingSegmentSize > 0 {
		return h.config.Optimizations.StreamingSegmentSize
	}
	return defaultSegmentSize
}

// getStreamingThreshold returns the configured streaming threshold
func (h *Handler) getStreamingThreshold() int64 {
	// Default threshold for switching to streaming mode (1MB)
	const defaultStreamingThreshold = 1 * 1024 * 1024

	if h.config != nil && h.config.Optimizations.StreamingThreshold > 0 {
		return h.config.Optimizations.StreamingThreshold
	}
	return defaultStreamingThreshold
}

// createMultipartUploadWithEncryption creates a multipart upload with encryption metadata
func (h *Handler) createMultipartUploadWithEncryption(ctx context.Context, input *s3.CreateMultipartUploadInput, objectKey, contentType string) (*s3.CreateMultipartUploadOutput, error) {
	// Create the multipart upload first
	output, err := h.s3Client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return nil, err
	}

	uploadID := aws.ToString(output.UploadId)

	// Initialize the multipart upload in the encryption manager
	err = h.encryptionMgr.InitiateMultipartUpload(ctx, uploadID, objectKey, aws.ToString(input.Bucket))
	if err != nil {
		// Try to abort the upload since we can't track the encryption state
		abortInput := &s3.AbortMultipartUploadInput{
			Bucket:   input.Bucket,
			Key:      input.Key,
			UploadId: output.UploadId,
		}
		if _, err := h.s3Client.AbortMultipartUpload(ctx, abortInput); err != nil {
			h.logger.WithError(err).WithField("uploadId", *output.UploadId).Warn("Failed to abort multipart upload after encryption initialization failure")
		}
		return nil, fmt.Errorf("failed to initialize multipart encryption: %w", err)
	}

	return output, nil
}

// uploadPartWithEncryption uploads a single part with encryption
func (h *Handler) uploadPartWithEncryption(ctx context.Context, bucket, key, uploadID string, partNumber int32, data []byte) (string, error) {
	// Encrypt the part data using the encryption manager
	encResult, err := h.encryptionMgr.UploadPart(ctx, uploadID, int(partNumber), data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt part %d: %w", partNumber, err)
	}

	// Upload the encrypted part
	input := &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		PartNumber: aws.Int32(partNumber),
		UploadId:   aws.String(uploadID),
		Body:       bytes.NewReader(encResult.EncryptedData),
	}

	output, err := h.s3Client.UploadPart(ctx, input)
	if err != nil {
		return "", err
	}

	// Store the ETag in the encryption manager for completion
	etag := aws.ToString(output.ETag)
	err = h.encryptionMgr.StorePartETag(uploadID, int(partNumber), etag)
	if err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"etag":       etag,
		}).Warn("Failed to store part ETag")
	}

	return etag, nil
}

// completeMultipartUploadWithEncryption completes a multipart upload with encryption
func (h *Handler) completeMultipartUploadWithEncryption(ctx context.Context, bucket, key, uploadID string, parts []types.CompletedPart) (*s3.CompleteMultipartUploadOutput, error) {
	// Convert parts to the format expected by the encryption manager
	partsMap := make(map[int]string)
	for _, part := range parts {
		partsMap[int(aws.ToInt32(part.PartNumber))] = aws.ToString(part.ETag)
	}

	// Complete the multipart upload in the encryption manager
	encMetadata, err := h.encryptionMgr.CompleteMultipartUpload(ctx, uploadID, partsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart encryption: %w", err)
	}

	// Complete the multipart upload on S3
	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	output, err := h.s3Client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return nil, err
	}

	// If we have encryption metadata, we need to add it to the object
	// since S3 multipart uploads don't automatically preserve metadata from CreateMultipartUpload
	if len(encMetadata) > 0 {
		// Get the current object to retrieve existing metadata
		getInput := &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}

		getOutput, err := h.s3Client.GetObject(ctx, getInput)
		if err != nil {
			h.logger.WithError(err).WithFields(map[string]interface{}{
				"bucket": bucket,
				"key":    key,
			}).Warn("Failed to get object metadata after multipart upload completion")
		} else {
			// Merge existing metadata with encryption metadata
			mergedMetadata := make(map[string]string)

			// Copy existing metadata (should include client metadata from CreateMultipartUpload)
			if getOutput.Metadata != nil {
				for k, v := range getOutput.Metadata {
					mergedMetadata[k] = v
				}
			}

			// Add encryption metadata
			for k, v := range encMetadata {
				mergedMetadata[k] = v
			}

			// Copy the object to itself with updated metadata
			copyInput := &s3.CopyObjectInput{
				Bucket:            aws.String(bucket),
				Key:               aws.String(key),
				CopySource:        aws.String(fmt.Sprintf("%s/%s", bucket, key)),
				Metadata:          mergedMetadata,
				MetadataDirective: "REPLACE",
			}

			// Preserve content type and other attributes
			if getOutput.ContentType != nil {
				copyInput.ContentType = getOutput.ContentType
			}
			if getOutput.CacheControl != nil {
				copyInput.CacheControl = getOutput.CacheControl
			}
			if getOutput.ContentDisposition != nil {
				copyInput.ContentDisposition = getOutput.ContentDisposition
			}
			if getOutput.ContentEncoding != nil {
				copyInput.ContentEncoding = getOutput.ContentEncoding
			}
			if getOutput.ContentLanguage != nil {
				copyInput.ContentLanguage = getOutput.ContentLanguage
			}

			_, copyErr := h.s3Client.CopyObject(ctx, copyInput)
			if copyErr != nil {
				h.logger.WithError(copyErr).WithFields(map[string]interface{}{
					"bucket": bucket,
					"key":    key,
				}).Warn("Failed to update object metadata after multipart upload completion")
			} else {
				h.logger.WithFields(map[string]interface{}{
					"bucket":   bucket,
					"key":      key,
					"uploadID": uploadID,
				}).Debug("Successfully updated object metadata after multipart upload completion")
			}
		}
	}

	// Clean up encryption state
	if err := h.encryptionMgr.CleanupMultipartUpload(uploadID); err != nil {
		h.logger.WithError(err).WithField("uploadId", uploadID).Warn("Failed to cleanup multipart encryption state")
	}

	return output, nil
}

// abortMultipartUpload aborts a multipart upload and cleans up encryption state
func (h *Handler) abortMultipartUpload(ctx context.Context, bucket, key, uploadID string) {
	// Abort the upload
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	if _, err := h.s3Client.AbortMultipartUpload(ctx, input); err != nil {
		h.logger.WithError(err).WithFields(map[string]interface{}{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Warn("Failed to abort multipart upload")
	}

	// Clean up encryption state
	if err := h.encryptionMgr.AbortMultipartUpload(ctx, uploadID); err != nil {
		h.logger.WithError(err).WithField("uploadID", uploadID).Warn("Failed to abort multipart encryption")
	}
}
