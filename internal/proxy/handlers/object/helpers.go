package object

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
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
func (h *Handler) prepareEncryptionMetadata(r *http.Request, encResult *orchestration.EncryptionResult) map[string]string {
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

// abortMultipartUpload aborts a multipart upload and cleans up encryption state
func (h *Handler) abortMultipartUpload(ctx context.Context, bucket, key, uploadID string) {
	// Abort the upload
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	if _, err := h.s3Backend.AbortMultipartUpload(ctx, input); err != nil {
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
