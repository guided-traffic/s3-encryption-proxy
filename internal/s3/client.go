package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
)

// PutObject encrypts and stores an object in S3
func (c *Client) PutObject(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)
	c.logger.WithFields(logrus.Fields{
		"key":    objectKey,
		"bucket": bucketName,
	}).Debug("Encrypting and putting object")

	// Check if we should use streaming multipart upload for large objects
	// Only use streaming if we know the content length and it's larger than segment size
	if c.segmentSize > 0 && input.ContentLength != nil && aws.ToInt64(input.ContentLength) > c.segmentSize {
		c.logger.WithFields(logrus.Fields{
			"key":           objectKey,
			"bucket":        bucketName,
			"segmentSize":   c.segmentSize,
			"contentLength": aws.ToInt64(input.ContentLength),
		}).Debug("Using streaming multipart upload for large object")
		return c.putObjectStreaming(ctx, input)
	}

	// For small objects, use direct encryption (legacy path)
	return c.putObjectDirect(ctx, input)
}

// putObjectDirect handles direct encryption for small objects (legacy behavior)
func (c *Client) putObjectDirect(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	// Read the object data
	data, err := io.ReadAll(input.Body)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to read object body for encryption")
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"dataSize": len(data),
	}).Debug("Successfully read object data for direct encryption")

	// Encrypt the data
	encResult, err := c.encryptionMgr.EncryptData(ctx, data, objectKey)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to encrypt object data")
		return nil, fmt.Errorf("failed to encrypt object data: %w", err)
	}

	// Get active provider alias for logging only
	activeProviderAlias := c.encryptionMgr.GetActiveProviderAlias()

	c.logger.WithFields(logrus.Fields{
		"key":              objectKey,
		"bucket":           bucketName,
		"originalSize":     len(data),
		"encryptedSize":    len(encResult.EncryptedData),
		"encryptedDEKSize": len(encResult.EncryptedDEK),
		"encryptedDEKHex":  fmt.Sprintf("%x", encResult.EncryptedDEK),
		"providerAlias":    activeProviderAlias,
	}).Debug("Successfully encrypted object data")

	// Handle metadata based on encryption result
	var metadata map[string]string

	// For "none" provider: preserve original user metadata for pure pass-through
	if encResult.EncryptedDEK == nil && encResult.Metadata == nil {
		// "none" provider - preserve user metadata, no encryption metadata
		if input.Metadata != nil {
			metadata = make(map[string]string)
			for k, v := range input.Metadata {
				metadata[k] = v
			}
		}
	} else {
		// For encrypted providers, create metadata with client data + encryption info
		metadata = make(map[string]string)
		if input.Metadata != nil {
			// Copy existing client metadata
			for k, v := range input.Metadata {
				metadata[k] = v
			}
		}

		// Add encryption metadata (already contains prefix from encryption manager)
		for k, v := range encResult.Metadata {
			metadata[k] = v
		}
	}

	c.logger.WithFields(logrus.Fields{
		"key":            objectKey,
		"bucket":         bucketName,
		"metadataLen":    len(metadata),
		"metadataPrefix": c.metadataPrefix,
		"metadata":       metadata,
	}).Info("📋 Prepared encryption metadata for S3 storage")

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
	output, err := c.s3Client.PutObject(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to put encrypted object to S3")
		return nil, fmt.Errorf("failed to put encrypted object: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":    objectKey,
		"bucket": bucketName,
		"etag":   aws.ToString(output.ETag),
	}).Info("Successfully encrypted and stored object")

	return output, nil
}

// GetObject retrieves and decrypts an object from S3
func (c *Client) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	c.logger.WithField("key", objectKey).Debug("Getting and decrypting object")

	// Get the encrypted object from S3
	output, err := c.s3Client.GetObject(ctx, input)
	if err != nil {
		c.logger.WithError(err).WithField("key", objectKey).Error("Failed to get object from S3")
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	// Check if the object has encryption metadata using the metadata handler
	encryptedDEKB64, hasEncryption := c.metadata.ExtractEncryptedDEK(output.Metadata)
	if !hasEncryption {
		// Object is not encrypted, return as-is
		c.logger.WithField("key", objectKey).Debug("Object is not encrypted, returning as-is")
		return output, nil
	}

	c.logger.WithField("key", objectKey).Debug("Object has encryption metadata, attempting to decrypt")

	// Decode the encrypted DEK
	encryptedDEK, err := base64.StdEncoding.DecodeString(encryptedDEKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	// Check if this is a multipart encrypted object (uses streaming decryption)
	if c.metadata.IsStreamingEncryption(output.Metadata) {
		c.logger.WithField("key", objectKey).Debug("Processing multipart encrypted object with streaming decryption")
		return c.getObjectMemoryDecryptionOptimized(ctx, output, encryptedDEK, objectKey)
	}

	// Fallback to standard memory decryption for legacy format
	c.logger.WithField("key", objectKey).Debug("Using standard memory decryption for legacy encrypted object")
	return c.getObjectMemoryDecryption(ctx, output, encryptedDEK, objectKey)
}

// getObjectMemoryDecryptionOptimized handles memory-optimized decryption for multipart objects
func (c *Client) getObjectMemoryDecryptionOptimized(ctx context.Context, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) (*s3.GetObjectOutput, error) {
	c.logger.WithFields(logrus.Fields{
		"key":              objectKey,
		"encryptedDEKSize": len(encryptedDEK),
	}).Debug("Starting streaming decryption for multipart object")

	// Provider alias is not used for decryption selection anymore
	// Decryption is handled by key fingerprints and metadata
	providerAlias := ""

	// Create a streaming decryption reader with size hint for optimal buffer sizing
	contentLength := int64(-1)
	if output.ContentLength != nil {
		contentLength = *output.ContentLength
	}

	decryptedReader, err := c.encryptionMgr.CreateStreamingDecryptionReaderWithSize(ctx, output.Body, encryptedDEK, output.Metadata, objectKey, providerAlias, contentLength)
	if err != nil {
		if closeErr := output.Body.Close(); closeErr != nil {
			c.logger.WithError(closeErr).Warn("Failed to close response body")
		}
		return nil, fmt.Errorf("failed to create streaming decryption reader: %w", err)
	}

	c.logger.WithField("key", objectKey).Debug("Successfully created streaming decryption reader for multipart object")

	// Clean metadata using the metadata handler
	cleanMetadata := c.metadata.CleanMetadata(output.Metadata)

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

// getObjectMemoryDecryption handles full memory decryption for legacy objects
func (c *Client) getObjectMemoryDecryption(ctx context.Context, output *s3.GetObjectOutput, encryptedDEK []byte, objectKey string) (*s3.GetObjectOutput, error) {
	// Read the encrypted data
	encryptedData, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}
	_ = output.Body.Close()

	c.logger.WithFields(logrus.Fields{
		"key":              objectKey,
		"encryptedSize":    len(encryptedData),
		"encryptedDEKSize": len(encryptedDEK),
	}).Debug("Read encrypted object data")

	// Use the manager to decrypt the data
	// For backward compatibility, we try to find a provider alias
	providerAlias := ""
	if alias, exists := output.Metadata[c.metadataPrefix+"provider"]; exists {
		providerAlias = alias
	}

	// Pass metadata to support streaming decryption
	plaintext, err := c.encryptionMgr.DecryptDataWithMetadata(ctx, encryptedData, encryptedDEK, output.Metadata, objectKey, providerAlias)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt object data: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":           objectKey,
		"plaintextSize": len(plaintext),
	}).Debug("Successfully decrypted object data")

	// Clean metadata using the metadata handler
	cleanMetadata := c.metadata.CleanMetadata(output.Metadata)

	// Return the decrypted data with cleaned metadata
	return &s3.GetObjectOutput{
		AcceptRanges:              output.AcceptRanges,
		Body:                      io.NopCloser(bytes.NewReader(plaintext)),
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
func (c *Client) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	output, err := c.s3Client.HeadObject(ctx, input)
	if err != nil {
		return nil, err
	}

	// Clean metadata using the metadata handler
	output.Metadata = c.metadata.CleanMetadata(output.Metadata)

	return output, nil
}

// DeleteObject deletes an object from S3
func (c *Client) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return c.s3Client.DeleteObject(ctx, input)
}

// ListObjects lists objects in a bucket
func (c *Client) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return c.s3Client.ListObjects(ctx, input)
}

// ListObjectsV2 lists objects in a bucket using the V2 API
func (c *Client) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return c.s3Client.ListObjectsV2(ctx, input)
}

// DeleteObjects deletes multiple objects from S3
func (c *Client) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	return c.s3Client.DeleteObjects(ctx, input)
}

// CopyObject copies an object within S3
func (c *Client) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	// TODO: Add encryption support for copy operations
	return c.s3Client.CopyObject(ctx, input)
}
