package s3client

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
)

// ObjectHandler handles encrypted object operations
type ObjectHandler struct {
	client         *Client
	metadataHelper *MetadataHelper
}

// NewObjectHandler creates a new object handler
func NewObjectHandler(client *Client) *ObjectHandler {
	return &ObjectHandler{
		client:         client,
		metadataHelper: NewMetadataHelper(client.metadataPrefix),
	}
}

// PutObject encrypts and stores an object in S3
func (h *ObjectHandler) PutObject(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)
	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "put",
		"key":       objectKey,
		"bucket":    bucketName,
	}).Debug("Processing object upload")

	// Check Content-Type for forcing single-part encryption (highest priority)
	contentType := aws.ToString(input.ContentType)
	forceEnvelopeEncryption := contentType == "application/x-s3ep-force-aes-gcm"
	forceStreamingEncryption := contentType == "application/x-s3ep-force-aes-ctr"

	// Content-Type forcing overrides automatic size-based decisions
	if forceEnvelopeEncryption {
		h.client.logger.WithFields(logrus.Fields{
			"component":   "object-handler",
			"operation":   "put",
			"key":         objectKey,
			"bucket":      bucketName,
			"contentType": contentType,
		}).Info("Using AES-GCM encryption via Content-Type")
		return h.putObjectDirect(ctx, input)
	}

	if forceStreamingEncryption {
		h.client.logger.WithFields(logrus.Fields{
			"component":   "object-handler",
			"operation":   "put",
			"key":         objectKey,
			"bucket":      bucketName,
			"contentType": contentType,
		}).Info("Using AES-CTR streaming encryption via Content-Type")
		return h.putObjectStreaming(ctx, input)
	}

	// No forcing - use automatic optimization based on file size
	// Check if we should use streaming multipart upload for large objects
	// Only use streaming if we know the content length and it's larger than segment size
	if h.client.segmentSize > 0 && input.ContentLength != nil && aws.ToInt64(input.ContentLength) > h.client.segmentSize {
		h.client.logger.WithFields(logrus.Fields{
			"component":     "object-handler",
			"operation":     "put",
			"key":           objectKey,
			"bucket":        bucketName,
			"contentLength": aws.ToInt64(input.ContentLength),
		}).Info("Using streaming multipart upload for large object")
		return h.putObjectStreaming(ctx, input)
	}

	// For small objects, use direct encryption (AES-GCM)
	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "put",
		"key":       objectKey,
		"bucket":    bucketName,
	}).Info("Using direct encryption for small object")
	return h.putObjectDirect(ctx, input)
}

// putObjectDirect handles direct encryption for small objects (AES-GCM)
func (h *ObjectHandler) putObjectDirect(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	// Read the object data
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}

	// Encrypt the data with HTTP Content-Type awareness for encryption mode forcing
	httpContentType := aws.ToString(input.ContentType)

	encResult, err := h.client.encryptionMgr.EncryptDataWithHTTPContentType(ctx, data, objectKey, httpContentType, false)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt object data: %w", err)
	}

	// Handle metadata based on encryption result
	var metadata map[string]string

	// For "none" provider: preserve original user metadata for pure pass-through
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		metadata = input.Metadata
	} else {
		// For encrypted providers, create metadata with client data + encryption info
		metadata = h.metadataHelper.PrepareEncryptionMetadata(input.Metadata, encResult.Metadata)
	}

	// Create new input with encrypted data
	encryptedInput := &s3.PutObjectInput{
		Bucket:                  input.Bucket,
		Key:                     input.Key,
		Body:                    bytes.NewReader(encResult.EncryptedData),
		Metadata:                metadata,
		ContentType:             input.ContentType,
		ContentEncoding:         input.ContentEncoding,
		ContentDisposition:      input.ContentDisposition,
		ContentLanguage:         input.ContentLanguage,
		CacheControl:            input.CacheControl,
		Expires:                 input.Expires,
		ACL:                     input.ACL,
		StorageClass:            input.StorageClass,
		WebsiteRedirectLocation: input.WebsiteRedirectLocation,
		SSECustomerAlgorithm:    input.SSECustomerAlgorithm,
		SSECustomerKey:          input.SSECustomerKey,
		SSECustomerKeyMD5:       input.SSECustomerKeyMD5,
		SSEKMSKeyId:             input.SSEKMSKeyId,
		RequestPayer:            input.RequestPayer,
		Tagging:                 input.Tagging,
	}

	// Update content length to match final encrypted data (without IV)
	encryptedInput.ContentLength = aws.Int64(int64(len(encResult.EncryptedData)))

	// Store the encrypted object
	output, err := h.client.s3Client.PutObject(ctx, encryptedInput)
	if err != nil {
		return nil, fmt.Errorf("failed to store encrypted object: %w", err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "put-direct",
		"key":       objectKey,
		"bucket":    bucketName,
	}).Info("Object encrypted and stored successfully")

	return output, nil
}

// putObjectStreaming handles streaming multipart upload for large objects
func (h *ObjectHandler) putObjectStreaming(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "put-streaming",
		"key":       objectKey,
		"bucket":    bucketName,
	}).Debug("Starting streaming multipart upload")

	// Create multipart upload
	createInput := &s3.CreateMultipartUploadInput{
		Bucket:                  input.Bucket,
		Key:                     input.Key,
		ACL:                     input.ACL,
		CacheControl:            input.CacheControl,
		ContentDisposition:      input.ContentDisposition,
		ContentEncoding:         input.ContentEncoding,
		ContentLanguage:         input.ContentLanguage,
		ContentType:             input.ContentType,
		Expires:                 input.Expires,
		Metadata:                input.Metadata,
		StorageClass:            input.StorageClass,
		WebsiteRedirectLocation: input.WebsiteRedirectLocation,
		SSECustomerAlgorithm:    input.SSECustomerAlgorithm,
		SSECustomerKey:          input.SSECustomerKey,
		SSECustomerKeyMD5:       input.SSECustomerKeyMD5,
		SSEKMSKeyId:             input.SSEKMSKeyId,
		RequestPayer:            input.RequestPayer,
		Tagging:                 input.Tagging,
	}

	// Use multipart handler for creating the upload
	createOutput, err := h.client.multipartHandler.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create multipart upload: %w", err)
	}

	uploadID := aws.ToString(createOutput.UploadId)

	// Process stream in chunks
	var completedParts []types.CompletedPart
	partNumber := int32(1)
	buffer := make([]byte, h.client.segmentSize)

	for {
		// Read next chunk
		n, err := io.ReadFull(input.Body, buffer)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			// Abort upload on error
			abortInput := &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}
			_, _ = h.client.multipartHandler.AbortMultipartUpload(ctx, abortInput)
			return nil, fmt.Errorf("failed to read stream chunk: %w", err)
		}

		// Upload this chunk as a part
		partInput := &s3.UploadPartInput{
			Bucket:     input.Bucket,
			Key:        input.Key,
			UploadId:   createOutput.UploadId,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(buffer[:n]),
		}

		partOutput, err := h.client.multipartHandler.UploadPart(ctx, partInput)
		if err != nil {
			// Abort upload on error
			abortInput := &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}
			_, _ = h.client.multipartHandler.AbortMultipartUpload(ctx, abortInput)
			return nil, fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       partOutput.ETag,
			PartNumber: aws.Int32(partNumber),
		})

		partNumber++

		// If we read less than the buffer size, we're done
		if n < len(buffer) {
			break
		}
	}

	// Complete multipart upload
	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:   input.Bucket,
		Key:      input.Key,
		UploadId: createOutput.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	completeOutput, err := h.client.multipartHandler.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "put-streaming",
		"key":       objectKey,
		"bucket":    bucketName,
		"uploadID":  uploadID,
		"partCount": len(completedParts),
	}).Info("Streaming multipart upload completed successfully")

	// Convert to PutObjectOutput format
	return &s3.PutObjectOutput{
		ETag:                 completeOutput.ETag,
		Expiration:           completeOutput.Expiration,
		ServerSideEncryption: completeOutput.ServerSideEncryption,
		VersionId:            completeOutput.VersionId,
		SSEKMSKeyId:          completeOutput.SSEKMSKeyId,
		RequestCharged:       completeOutput.RequestCharged,
	}, nil
}

// GetObject retrieves and decrypts an object from S3
func (h *ObjectHandler) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
		"operation": "get",
		"key":       objectKey,
	}).Debug("Retrieving object from S3")

	// Get the encrypted object from S3
	output, err := h.client.s3Client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
	}

	// Check if the object has encryption metadata
	encryptedDEKB64, hasEncryption, isStreamingEncryption := h.metadataHelper.ExtractEncryptionMetadata(output.Metadata)

	if !hasEncryption {
		// Object is not encrypted, return as-is
		h.client.logger.WithFields(logrus.Fields{
			"component": "object-handler",
			"operation": "get",
			"key":       objectKey,
		}).Debug("Object not encrypted, returning as-is")
		return output, nil
	}

	// Decode the encrypted DEK
	encryptedDEK, err := h.metadataHelper.DecodeEncryptedDEK(encryptedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	if isStreamingEncryption {
		return h.getObjectMemoryDecryptionOptimized(ctx, output, encryptedDEK, objectKey)
	}

	// Fallback to standard memory decryption for AES-GCM format
	return h.getObjectMemoryDecryption(ctx, output, encryptedDEK, objectKey)
}

// getObjectMemoryDecryptionOptimized handles memory-optimized decryption for multipart objects
func (h *ObjectHandler) getObjectMemoryDecryptionOptimized(ctx context.Context, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) (*s3.GetObjectOutput, error) {
	h.client.logger.WithFields(logrus.Fields{
		"component": "object-handler",
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

	decryptedReader, err := h.client.encryptionMgr.CreateStreamingDecryptionReaderWithSize(ctx, output.Body, encryptedDEK, output.Metadata, objectKey, providerAlias, contentLength)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming decryption reader: %w", err)
	}

	// Remove encryption metadata from the response
	cleanMetadata := h.metadataHelper.CleanMetadata(output.Metadata)

	// Return the streaming decrypted data
	return &s3.GetObjectOutput{
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
		Metadata:                  cleanMetadata,
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
	}, nil
}

// getObjectMemoryDecryption handles full memory decryption for AES-GCM objects
func (h *ObjectHandler) getObjectMemoryDecryption(ctx context.Context, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) (*s3.GetObjectOutput, error) {
	// Read the encrypted data first
	encryptedData, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted object data: %w", err)
	}

	// Close the original body safely
	if output.Body != nil {
		if closeErr := output.Body.Close(); closeErr != nil {
			h.client.logger.WithError(closeErr).WithField("key", objectKey).Warn("Failed to close original body")
		}
	}

	// Use the manager to decrypt the data
	// For backward compatibility, we try to find a provider alias
	providerAlias := ""

	// Pass metadata to support streaming decryption
	plaintext, err := h.client.encryptionMgr.DecryptDataWithMetadata(ctx, encryptedData, encryptedDEK, output.Metadata, objectKey, providerAlias)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt object data: %w", err)
	}

	// Remove encryption metadata from the response
	cleanMetadata := h.metadataHelper.CleanMetadata(output.Metadata)

	// Create a new response body reader from the decrypted data
	// Use bytes.NewReader directly instead of io.NopCloser for simpler debugging
	responseReader := bytes.NewReader(plaintext)

	// Wrap in NopCloser to satisfy io.ReadCloser interface
	responseBody := io.NopCloser(responseReader)

	// Return the decrypted data with cleaned metadata
	return &s3.GetObjectOutput{
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
		Metadata:                  cleanMetadata,
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
	}, nil
}

// HeadObject retrieves object metadata, removing encryption-specific metadata
func (h *ObjectHandler) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	output, err := h.client.s3Client.HeadObject(ctx, input)
	if err != nil {
		return nil, err
	}

	// Remove encryption metadata from the response
	output.Metadata = h.metadataHelper.CleanMetadata(output.Metadata)

	return output, nil
}

// DeleteObject deletes an object from S3
func (h *ObjectHandler) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return h.client.s3Client.DeleteObject(ctx, input)
}

// CopyObject copies an object with encryption support
func (h *ObjectHandler) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	// TODO: Add encryption support for copy operations
	return h.client.s3Client.CopyObject(ctx, input)
}
