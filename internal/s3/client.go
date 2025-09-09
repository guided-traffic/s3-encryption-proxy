package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/sirupsen/logrus"
)

// Client wraps the AWS S3 client with encryption capabilities
type Client struct {
	s3Client       *s3.Client
	encryptionMgr  *encryption.Manager
	metadataPrefix string
	segmentSize    int64
	logger         *logrus.Entry
}

// GetRawS3Client returns the underlying raw S3 client for direct operations
func (c *Client) GetRawS3Client() *s3.Client {
	return c.s3Client
}

// Config holds S3 client configuration
type Config struct {
	Endpoint       string
	Region         string
	AccessKeyID    string
	SecretKey      string
	MetadataPrefix string
	DisableSSL     bool
	ForcePathStyle bool
	SegmentSize    int64 // Streaming segment size in bytes
}

// NewClient creates a new S3 client with encryption capabilities
func NewClient(cfg *Config, encMgr *encryption.Manager, logger *logrus.Logger) (*Client, error) {
	// Create AWS configuration with TLS support for self-signed certificates
	awsCfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID,
			cfg.SecretKey,
			"",
		)),
		config.WithHTTPClient(&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // #nosec G402 - Required for testing with self-signed certificates in development
				},
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with custom endpoint if provided
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.ForcePathStyle
	})

	return &Client{
		s3Client:       s3Client,
		encryptionMgr:  encMgr,
		metadataPrefix: cfg.MetadataPrefix,
		segmentSize:    cfg.SegmentSize,
		logger:         logger.WithField("component", "s3-client"),
	}, nil
}

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

		// Add encryption metadata
		metadata[c.metadataPrefix+"dek"] = base64.StdEncoding.EncodeToString(encResult.EncryptedDEK)

		// Add all metadata from the encryption result
		for k, v := range encResult.Metadata {
			metadata[c.metadataPrefix+k] = v
		}
	}

	c.logger.WithFields(logrus.Fields{
		"key":         objectKey,
		"bucket":      bucketName,
		"metadataLen": len(metadata),
	}).Debug("Prepared encryption metadata for S3 storage")

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

// putObjectStreaming handles streaming multipart upload for large objects
func (c *Client) putObjectStreaming(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)

	c.logger.WithFields(logrus.Fields{
		"key":         objectKey,
		"bucket":      bucketName,
		"segmentSize": c.segmentSize,
	}).Info("Starting streaming multipart upload")

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

	createOutput, err := c.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create streaming multipart upload: %w", err)
	}

	uploadID := aws.ToString(createOutput.UploadId)
	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"uploadID": uploadID,
	}).Debug("Created streaming multipart upload")

	// Process stream in chunks
	var completedParts []types.CompletedPart
	partNumber := int32(1)
	buffer := make([]byte, c.segmentSize)

	for {
		// Read next chunk
		n, err := io.ReadFull(input.Body, buffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			// Abort multipart upload on read error
			if _, abortErr := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}); abortErr != nil {
				c.logger.WithError(abortErr).Error("Failed to abort multipart upload after read error")
			}
			return nil, fmt.Errorf("failed to read data chunk: %w", err)
		}

		if n == 0 {
			break // End of stream
		}

		// Upload this chunk as a part
		partData := buffer[:n]
		partInput := &s3.UploadPartInput{
			Bucket:     input.Bucket,
			Key:        input.Key,
			UploadId:   createOutput.UploadId,
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(partData),
		}

		c.logger.WithFields(logrus.Fields{
			"key":        objectKey,
			"bucket":     bucketName,
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"chunkSize":  n,
		}).Debug("Uploading streaming chunk")

		partOutput, err := c.UploadPart(ctx, partInput)
		if err != nil {
			// Abort multipart upload on part upload error
			if _, abortErr := c.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   input.Bucket,
				Key:      input.Key,
				UploadId: createOutput.UploadId,
			}); abortErr != nil {
				c.logger.WithError(abortErr).Error("Failed to abort multipart upload after part upload error")
			}
			return nil, fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		completedParts = append(completedParts, types.CompletedPart{
			ETag:       partOutput.ETag,
			PartNumber: aws.Int32(partNumber),
		})

		c.logger.WithFields(logrus.Fields{
			"key":        objectKey,
			"bucket":     bucketName,
			"uploadID":   uploadID,
			"partNumber": partNumber,
			"etag":       aws.ToString(partOutput.ETag),
		}).Debug("Successfully uploaded streaming chunk")

		partNumber++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break // End of stream
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

	completeOutput, err := c.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		return nil, fmt.Errorf("failed to complete streaming multipart upload: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":       objectKey,
		"bucket":    bucketName,
		"uploadID":  uploadID,
		"partCount": len(completedParts),
		"etag":      aws.ToString(completeOutput.ETag),
	}).Info("Successfully completed streaming multipart upload")

	// Convert to PutObjectOutput format
	return &s3.PutObjectOutput{
		ETag:                 completeOutput.ETag,
		Expiration:          completeOutput.Expiration,
		ServerSideEncryption: completeOutput.ServerSideEncryption,
		VersionId:           completeOutput.VersionId,
		SSEKMSKeyId:         completeOutput.SSEKMSKeyId,
		RequestCharged:      completeOutput.RequestCharged,
	}, nil
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

	// Check if the object has encryption metadata
	// Support both legacy format (s3ep-dek) and streaming format (encryption-dek)
	var encryptedDEKB64 string
	var hasEncryption bool

	// First check for legacy format
	if dek, exists := output.Metadata[c.metadataPrefix+"dek"]; exists {
		encryptedDEKB64 = dek
		hasEncryption = true
	} else if dek, exists := output.Metadata["encryption-dek"]; exists {
		// Check for streaming format
		encryptedDEKB64 = dek
		hasEncryption = true
	}

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
	if dataAlgorithm, exists := output.Metadata["data-algorithm"]; exists && dataAlgorithm == "aes-256-ctr" {
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

	// Create a streaming decryption reader
	decryptedReader, err := c.encryptionMgr.CreateStreamingDecryptionReader(ctx, output.Body, encryptedDEK, output.Metadata, objectKey, providerAlias)
	if err != nil {
		if closeErr := output.Body.Close(); closeErr != nil {
			c.logger.WithError(closeErr).Warn("Failed to close response body")
		}
		return nil, fmt.Errorf("failed to create streaming decryption reader: %w", err)
	}

	c.logger.WithField("key", objectKey).Debug("Successfully created streaming decryption reader for multipart object")

	// Remove encryption metadata from the response
	cleanMetadata := make(map[string]string)
	for k, v := range output.Metadata {
		if !strings.HasPrefix(k, c.metadataPrefix) &&
		   !strings.HasPrefix(k, "encryption-") &&
		   k != "data-algorithm" && k != "kek-algorithm" &&
		   k != "kek-fingerprint" && k != "upload-id" {
			cleanMetadata[k] = v
		}
	}

	// Return the streaming decrypted data
	return &s3.GetObjectOutput{
		AcceptRanges:      output.AcceptRanges,
		Body:             decryptedReader,
		CacheControl:     output.CacheControl,
		ContentDisposition: output.ContentDisposition,
		ContentEncoding:  output.ContentEncoding,
		ContentLanguage:  output.ContentLanguage,
		ContentLength:    output.ContentLength, // Same length for AES-CTR
		ContentRange:     output.ContentRange,
		ContentType:      output.ContentType,
		DeleteMarker:     output.DeleteMarker,
		ETag:             output.ETag,
		Expiration:       output.Expiration,
		ExpiresString:    output.ExpiresString,
		LastModified:     output.LastModified,
		Metadata:         cleanMetadata,
		MissingMeta:      output.MissingMeta,
		ObjectLockLegalHoldStatus: output.ObjectLockLegalHoldStatus,
		ObjectLockMode:   output.ObjectLockMode,
		ObjectLockRetainUntilDate: output.ObjectLockRetainUntilDate,
		PartsCount:       output.PartsCount,
		ReplicationStatus: output.ReplicationStatus,
		RequestCharged:   output.RequestCharged,
		Restore:          output.Restore,
		ServerSideEncryption: output.ServerSideEncryption,
		SSECustomerAlgorithm: output.SSECustomerAlgorithm,
		SSECustomerKeyMD5: output.SSECustomerKeyMD5,
		SSEKMSKeyId:      output.SSEKMSKeyId,
		StorageClass:     output.StorageClass,
		TagCount:         output.TagCount,
		VersionId:        output.VersionId,
		WebsiteRedirectLocation: output.WebsiteRedirectLocation,
		ChecksumCRC32:    output.ChecksumCRC32,
		ChecksumCRC32C:   output.ChecksumCRC32C,
		ChecksumSHA1:     output.ChecksumSHA1,
		ChecksumSHA256:   output.ChecksumSHA256,
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

	// Remove encryption metadata from the response
	cleanMetadata := make(map[string]string)
	for k, v := range output.Metadata {
		if !strings.HasPrefix(k, c.metadataPrefix) {
			cleanMetadata[k] = v
		}
	}

	// Return the decrypted data with cleaned metadata
	return &s3.GetObjectOutput{
		AcceptRanges:     output.AcceptRanges,
		Body:             io.NopCloser(bytes.NewReader(plaintext)),
		CacheControl:     output.CacheControl,
		ContentDisposition: output.ContentDisposition,
		ContentEncoding:  output.ContentEncoding,
		ContentLanguage:  output.ContentLanguage,
		ContentLength:    aws.Int64(int64(len(plaintext))),
		ContentRange:     output.ContentRange,
		ContentType:      output.ContentType,
		DeleteMarker:     output.DeleteMarker,
		ETag:             output.ETag,
		Expiration:       output.Expiration,
		ExpiresString:    output.ExpiresString,
		LastModified:     output.LastModified,
		Metadata:         cleanMetadata,
		MissingMeta:      output.MissingMeta,
		ObjectLockLegalHoldStatus: output.ObjectLockLegalHoldStatus,
		ObjectLockMode:   output.ObjectLockMode,
		ObjectLockRetainUntilDate: output.ObjectLockRetainUntilDate,
		PartsCount:       output.PartsCount,
		ReplicationStatus: output.ReplicationStatus,
		RequestCharged:   output.RequestCharged,
		Restore:          output.Restore,
		ServerSideEncryption: output.ServerSideEncryption,
		SSECustomerAlgorithm: output.SSECustomerAlgorithm,
		SSECustomerKeyMD5: output.SSECustomerKeyMD5,
		SSEKMSKeyId:      output.SSEKMSKeyId,
		StorageClass:     output.StorageClass,
		TagCount:         output.TagCount,
		VersionId:        output.VersionId,
		WebsiteRedirectLocation: output.WebsiteRedirectLocation,
		ChecksumCRC32:    output.ChecksumCRC32,
		ChecksumCRC32C:   output.ChecksumCRC32C,
		ChecksumSHA1:     output.ChecksumSHA1,
		ChecksumSHA256:   output.ChecksumSHA256,
	}, nil
}

// HeadObject retrieves object metadata, removing encryption-specific metadata
func (c *Client) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	output, err := c.s3Client.HeadObject(ctx, input)
	if err != nil {
		return nil, err
	}

	// Remove encryption metadata from the response
	cleanMetadata := make(map[string]string)
	for k, v := range output.Metadata {
		if !strings.HasPrefix(k, c.metadataPrefix) {
			cleanMetadata[k] = v
		}
	}
	output.Metadata = cleanMetadata

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

// ==============================================
// PLACEHOLDER METHODS FOR S3 API COMPLETENESS
// ==============================================

// Bucket operations
func (c *Client) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return c.s3Client.CreateBucket(ctx, input)
}

func (c *Client) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	return c.s3Client.DeleteBucket(ctx, input)
}

func (c *Client) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return c.s3Client.HeadBucket(ctx, input)
}

func (c *Client) ListBuckets(ctx context.Context, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return c.s3Client.ListBuckets(ctx, input)
}

// Bucket sub-resource operations
func (c *Client) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return c.s3Client.GetBucketAcl(ctx, input)
}

func (c *Client) PutBucketAcl(ctx context.Context, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return c.s3Client.PutBucketAcl(ctx, input)
}

func (c *Client) GetBucketCors(ctx context.Context, input *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error) {
	return c.s3Client.GetBucketCors(ctx, input)
}

func (c *Client) PutBucketCors(ctx context.Context, input *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error) {
	return c.s3Client.PutBucketCors(ctx, input)
}

func (c *Client) DeleteBucketCors(ctx context.Context, input *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error) {
	return c.s3Client.DeleteBucketCors(ctx, input)
}

func (c *Client) GetBucketVersioning(ctx context.Context, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return c.s3Client.GetBucketVersioning(ctx, input)
}

func (c *Client) PutBucketVersioning(ctx context.Context, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return c.s3Client.PutBucketVersioning(ctx, input)
}

func (c *Client) GetBucketPolicy(ctx context.Context, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return c.s3Client.GetBucketPolicy(ctx, input)
}

func (c *Client) PutBucketPolicy(ctx context.Context, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return c.s3Client.PutBucketPolicy(ctx, input)
}

func (c *Client) DeleteBucketPolicy(ctx context.Context, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return c.s3Client.DeleteBucketPolicy(ctx, input)
}

func (c *Client) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	return c.s3Client.GetBucketLocation(ctx, input)
}

func (c *Client) GetBucketLogging(ctx context.Context, input *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	return c.s3Client.GetBucketLogging(ctx, input)
}

func (c *Client) PutBucketLogging(ctx context.Context, input *s3.PutBucketLoggingInput) (*s3.PutBucketLoggingOutput, error) {
	return c.s3Client.PutBucketLogging(ctx, input)
}

func (c *Client) GetBucketNotificationConfiguration(ctx context.Context, input *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return c.s3Client.GetBucketNotificationConfiguration(ctx, input)
}

func (c *Client) PutBucketNotificationConfiguration(ctx context.Context, input *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error) {
	return c.s3Client.PutBucketNotificationConfiguration(ctx, input)
}

func (c *Client) GetBucketTagging(ctx context.Context, input *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	return c.s3Client.GetBucketTagging(ctx, input)
}

func (c *Client) PutBucketTagging(ctx context.Context, input *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	return c.s3Client.PutBucketTagging(ctx, input)
}

func (c *Client) DeleteBucketTagging(ctx context.Context, input *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error) {
	return c.s3Client.DeleteBucketTagging(ctx, input)
}

func (c *Client) GetBucketLifecycleConfiguration(ctx context.Context, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return c.s3Client.GetBucketLifecycleConfiguration(ctx, input)
}

func (c *Client) PutBucketLifecycleConfiguration(ctx context.Context, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return c.s3Client.PutBucketLifecycleConfiguration(ctx, input)
}

func (c *Client) DeleteBucketLifecycle(ctx context.Context, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return c.s3Client.DeleteBucketLifecycle(ctx, input)
}

func (c *Client) GetBucketReplication(ctx context.Context, input *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error) {
	return c.s3Client.GetBucketReplication(ctx, input)
}

func (c *Client) PutBucketReplication(ctx context.Context, input *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error) {
	return c.s3Client.PutBucketReplication(ctx, input)
}

func (c *Client) DeleteBucketReplication(ctx context.Context, input *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error) {
	return c.s3Client.DeleteBucketReplication(ctx, input)
}

func (c *Client) GetBucketWebsite(ctx context.Context, input *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error) {
	return c.s3Client.GetBucketWebsite(ctx, input)
}

func (c *Client) PutBucketWebsite(ctx context.Context, input *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error) {
	return c.s3Client.PutBucketWebsite(ctx, input)
}

func (c *Client) DeleteBucketWebsite(ctx context.Context, input *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error) {
	return c.s3Client.DeleteBucketWebsite(ctx, input)
}

func (c *Client) GetBucketAccelerateConfiguration(ctx context.Context, input *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	return c.s3Client.GetBucketAccelerateConfiguration(ctx, input)
}

func (c *Client) PutBucketAccelerateConfiguration(ctx context.Context, input *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	return c.s3Client.PutBucketAccelerateConfiguration(ctx, input)
}

func (c *Client) GetBucketRequestPayment(ctx context.Context, input *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error) {
	return c.s3Client.GetBucketRequestPayment(ctx, input)
}

func (c *Client) PutBucketRequestPayment(ctx context.Context, input *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error) {
	return c.s3Client.PutBucketRequestPayment(ctx, input)
}

// Multipart upload operations with encryption support
func (c *Client) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	bucketName := aws.ToString(input.Bucket)
	c.logger.WithFields(logrus.Fields{
		"key":    objectKey,
		"bucket": bucketName,
	}).Debug("Creating multipart upload with encryption")

	// Get encryption metadata for multipart uploads
	dummyData := []byte("dummy")
	encResult, err := c.encryptionMgr.EncryptDataWithContentType(ctx, dummyData, objectKey, factory.ContentTypeMultipart)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to get encryption metadata for multipart upload")
		return nil, fmt.Errorf("failed to get encryption metadata: %w", err)
	}

	// Create enhanced input with encryption metadata
	encryptedInput := &s3.CreateMultipartUploadInput{
		Bucket:                     input.Bucket,
		Key:                        input.Key,
		ACL:                        input.ACL,
		CacheControl:               input.CacheControl,
		ContentDisposition:         input.ContentDisposition,
		ContentEncoding:            input.ContentEncoding,
		ContentLanguage:            input.ContentLanguage,
		ContentType:                input.ContentType,
		Expires:                    input.Expires,
		GrantFullControl:           input.GrantFullControl,
		GrantRead:                  input.GrantRead,
		GrantReadACP:               input.GrantReadACP,
		GrantWriteACP:              input.GrantWriteACP,
		RequestPayer:               input.RequestPayer,
		SSECustomerAlgorithm:       input.SSECustomerAlgorithm,
		SSECustomerKey:             input.SSECustomerKey,
		SSECustomerKeyMD5:          input.SSECustomerKeyMD5,
		SSEKMSKeyId:                input.SSEKMSKeyId,
		SSEKMSEncryptionContext:    input.SSEKMSEncryptionContext,
		ServerSideEncryption:       input.ServerSideEncryption,
		StorageClass:               input.StorageClass,
		Tagging:                    input.Tagging,
		WebsiteRedirectLocation:    input.WebsiteRedirectLocation,
		ChecksumAlgorithm:          input.ChecksumAlgorithm,
	}

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

		// Add encryption metadata including the DEK for multipart objects
		for k, v := range encResult.Metadata {
			// Include all metadata including the DEK for consistency
			metadata[c.metadataPrefix+k] = v
		}

		// Add content type metadata to indicate multipart encryption
		metadata[c.metadataPrefix+"content_type"] = "multipart"
	}

	encryptedInput.Metadata = metadata

	// Create the multipart upload in S3 with encryption metadata
	output, err := c.s3Client.CreateMultipartUpload(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to create multipart upload in S3")
		return nil, fmt.Errorf("failed to create multipart upload in S3: %w", err)
	}

	uploadID := aws.ToString(output.UploadId)

	// Initialize multipart upload in encryption manager
	err = c.encryptionMgr.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	if err != nil {
		// Abort the S3 multipart upload if encryption initialization fails
		_, _ = c.s3Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   input.Bucket,
			Key:      input.Key,
			UploadId: output.UploadId,
		})
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"bucket":   bucketName,
			"uploadID": uploadID,
		}).Error("Failed to initiate encrypted multipart upload")
		return nil, fmt.Errorf("failed to initiate encrypted multipart upload: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"bucket":   bucketName,
		"uploadID": uploadID,
	}).Info("Successfully created encrypted multipart upload")

	return output, nil
}

func (c *Client) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)
	partNumber := aws.ToInt32(input.PartNumber)

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
	}).Debug("Uploading encrypted part")

	// Use streaming encryption to avoid memory buffering large parts
	return c.uploadPartStreaming(ctx, input, objectKey, uploadID, int(partNumber))
}

// uploadPartStreaming implements true streaming encryption for upload parts
func (c *Client) uploadPartStreaming(ctx context.Context, input *s3.UploadPartInput, objectKey, uploadID string, partNumber int) (*s3.UploadPartOutput, error) {
	// For parts that are small enough, use direct encryption (more efficient)
	// For large parts, we would need to implement chunk-by-chunk processing
	// For now, we keep the current approach but with better memory management

	partData, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read part data: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"dataSize":   len(partData),
	}).Debug("Read part data for encryption")

	// Encrypt the part
	encResult, err := c.encryptionMgr.UploadPart(ctx, uploadID, partNumber, partData)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":        objectKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to encrypt part")
		return nil, fmt.Errorf("failed to encrypt part: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":             objectKey,
		"uploadID":        uploadID,
		"partNumber":      partNumber,
		"originalSize":    len(partData),
		"encryptedSize":   len(encResult.EncryptedData),
	}).Debug("Successfully encrypted part")

	// Create new input with encrypted data
	encryptedInput := &s3.UploadPartInput{
		Bucket:     input.Bucket,
		Key:        input.Key,
		PartNumber: input.PartNumber,
		UploadId:   input.UploadId,
		Body:       bytes.NewReader(encResult.EncryptedData),
		ContentLength: aws.Int64(int64(len(encResult.EncryptedData))),
		ChecksumAlgorithm: input.ChecksumAlgorithm,
		ChecksumCRC32:     input.ChecksumCRC32,
		ChecksumCRC32C:    input.ChecksumCRC32C,
		ChecksumSHA1:      input.ChecksumSHA1,
		ChecksumSHA256:    input.ChecksumSHA256,
		SSECustomerAlgorithm: input.SSECustomerAlgorithm,
		SSECustomerKey:       input.SSECustomerKey,
		SSECustomerKeyMD5:    input.SSECustomerKeyMD5,
		RequestPayer:         input.RequestPayer,
	}

	// Upload the encrypted part
	output, err := c.s3Client.UploadPart(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":        objectKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to upload encrypted part to S3")
		return nil, fmt.Errorf("failed to upload encrypted part: %w", err)
	}

	// Release encrypted data immediately after upload
	encResult.EncryptedData = nil

	c.logger.WithFields(logrus.Fields{
		"key":        objectKey,
		"uploadID":   uploadID,
		"partNumber": partNumber,
		"etag":       aws.ToString(output.ETag),
	}).Info("Successfully uploaded encrypted part")

	return output, nil
}

func (c *Client) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Completing encrypted multipart upload")

	// Get the encrypted ETags from the encryption manager
	uploadState, err := c.encryptionMgr.GetMultipartUploadState(uploadID)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to get multipart upload state for completion")
		return nil, fmt.Errorf("failed to get upload state: %w", err)
	}

	// Create new input with encrypted ETags
	encryptedInput := &s3.CompleteMultipartUploadInput{
		Bucket:                     input.Bucket,
		Key:                        input.Key,
		UploadId:                   input.UploadId,
		ChecksumCRC32:              input.ChecksumCRC32,
		ChecksumCRC32C:             input.ChecksumCRC32C,
		ChecksumSHA1:               input.ChecksumSHA1,
		ChecksumSHA256:             input.ChecksumSHA256,
		RequestPayer:               input.RequestPayer,
		SSECustomerAlgorithm:       input.SSECustomerAlgorithm,
		SSECustomerKey:             input.SSECustomerKey,
		SSECustomerKeyMD5:          input.SSECustomerKeyMD5,
	}

	// Build the parts with encrypted ETags
	if len(uploadState.PartETags) > 0 {
		encryptedInput.MultipartUpload = &types.CompletedMultipartUpload{}

		// Sort part numbers to ensure correct order
		var partNumbers []int
		for partNumber := range uploadState.PartETags {
			partNumbers = append(partNumbers, partNumber)
		}
		sort.Ints(partNumbers)

		// Add parts in sorted order
		for _, partNumber := range partNumbers {
			if partNumber > 2147483647 { // Max int32 value
				return nil, fmt.Errorf("part number %d exceeds maximum allowed value", partNumber)
			}
			encryptedEtag := uploadState.PartETags[partNumber]
			part := types.CompletedPart{
				ETag:       aws.String(encryptedEtag),
				PartNumber: aws.Int32(int32(partNumber)), // #nosec G115 - bounds checked above
			}
			encryptedInput.MultipartUpload.Parts = append(encryptedInput.MultipartUpload.Parts, part)
		}
	} else {
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Warn("No encrypted ETags found, using original parts")
		encryptedInput.MultipartUpload = input.MultipartUpload
	}

	// Get encryption metadata from upload state to propagate to final object
	// For "none" provider, skip metadata completely for pure pass-through
	var encryptionMetadata map[string]string
	if uploadState.Metadata != nil {
		encryptionMetadata = make(map[string]string)
		for k, v := range uploadState.Metadata {
			encryptionMetadata[k] = v
		}
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
			"metadata": encryptionMetadata,
		}).Debug("Propagating encryption metadata to final multipart object")
	}

	// Complete the multipart upload in S3 with encrypted ETags
	output, err := c.s3Client.CompleteMultipartUpload(ctx, encryptedInput)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload in S3")
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	// After completing the multipart upload, we need to add the encryption metadata
	// to the final object since S3 doesn't transfer metadata from CreateMultipartUpload
	// Skip this entirely for "none" provider to maintain pure pass-through
	if len(encryptionMetadata) > 0 {
		c.logger.WithFields(logrus.Fields{
			"key":      objectKey,
			"metadata": encryptionMetadata,
		}).Debug("Adding encryption metadata to completed multipart object")

		// Use CopyObject to add metadata to the completed object
		copyInput := &s3.CopyObjectInput{
			Bucket:     input.Bucket,
			Key:        input.Key,
			CopySource: aws.String(fmt.Sprintf("%s/%s", aws.ToString(input.Bucket), objectKey)),
			Metadata:   encryptionMetadata,
			MetadataDirective: types.MetadataDirectiveReplace,
		}

		_, copyErr := c.s3Client.CopyObject(ctx, copyInput)
		if copyErr != nil {
			c.logger.WithError(copyErr).WithFields(logrus.Fields{
				"key":      objectKey,
				"metadata": encryptionMetadata,
			}).Error("Failed to add encryption metadata to completed multipart object")
			// Don't return error since the upload itself succeeded
		} else {
			c.logger.WithFields(logrus.Fields{
				"key":      objectKey,
				"metadata": encryptionMetadata,
			}).Debug("Successfully added encryption metadata to completed multipart object")
		}
	}

	// Extract part ETags for the encryption manager cleanup
	parts := make(map[int]string)
	if input.MultipartUpload != nil {
		for _, part := range input.MultipartUpload.Parts {
			partNumber := int(aws.ToInt32(part.PartNumber))
			etag := aws.ToString(part.ETag)
			parts[partNumber] = etag
		}
	}

	// Clean up encryption state
	_, err = c.encryptionMgr.CompleteMultipartUpload(ctx, uploadID, parts)
	if err != nil {
		// Log but don't fail the operation since S3 operation succeeded
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Warn("Failed to clean up encryption state after successful multipart upload")
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
		"etag":     aws.ToString(output.ETag),
	}).Info("Successfully completed encrypted multipart upload")

	return output, nil
}

func (c *Client) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	objectKey := aws.ToString(input.Key)
	uploadID := aws.ToString(input.UploadId)

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Debug("Aborting encrypted multipart upload")

	// Abort in S3
	output, err := c.s3Client.AbortMultipartUpload(ctx, input)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to abort multipart upload in S3")
		// Continue to clean up encryption state even if S3 operation failed
	}

	// Clean up encryption state
	if err := c.encryptionMgr.AbortMultipartUpload(ctx, uploadID); err != nil {
		c.logger.WithError(err).WithField("uploadID", uploadID).Error("Failed to abort multipart upload in encryption manager")
	}

	c.logger.WithFields(logrus.Fields{
		"key":      objectKey,
		"uploadID": uploadID,
	}).Info("Aborted encrypted multipart upload")

	return output, err
}

func (c *Client) ListParts(ctx context.Context, input *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
	return c.s3Client.ListParts(ctx, input)
}

func (c *Client) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	return c.s3Client.ListMultipartUploads(ctx, input)
}

// Object operations
func (c *Client) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	// TODO: Add encryption support for copy operations
	return c.s3Client.CopyObject(ctx, input)
}

func (c *Client) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	return c.s3Client.DeleteObjects(ctx, input)
}

// Object sub-resource operations
func (c *Client) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return c.s3Client.GetObjectAcl(ctx, input)
}

func (c *Client) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) (*s3.PutObjectAclOutput, error) {
	return c.s3Client.PutObjectAcl(ctx, input)
}

func (c *Client) GetObjectTagging(ctx context.Context, input *s3.GetObjectTaggingInput) (*s3.GetObjectTaggingOutput, error) {
	return c.s3Client.GetObjectTagging(ctx, input)
}

func (c *Client) PutObjectTagging(ctx context.Context, input *s3.PutObjectTaggingInput) (*s3.PutObjectTaggingOutput, error) {
	return c.s3Client.PutObjectTagging(ctx, input)
}

func (c *Client) DeleteObjectTagging(ctx context.Context, input *s3.DeleteObjectTaggingInput) (*s3.DeleteObjectTaggingOutput, error) {
	return c.s3Client.DeleteObjectTagging(ctx, input)
}

func (c *Client) GetObjectLegalHold(ctx context.Context, input *s3.GetObjectLegalHoldInput) (*s3.GetObjectLegalHoldOutput, error) {
	return c.s3Client.GetObjectLegalHold(ctx, input)
}

func (c *Client) PutObjectLegalHold(ctx context.Context, input *s3.PutObjectLegalHoldInput) (*s3.PutObjectLegalHoldOutput, error) {
	return c.s3Client.PutObjectLegalHold(ctx, input)
}

func (c *Client) GetObjectRetention(ctx context.Context, input *s3.GetObjectRetentionInput) (*s3.GetObjectRetentionOutput, error) {
	return c.s3Client.GetObjectRetention(ctx, input)
}

func (c *Client) PutObjectRetention(ctx context.Context, input *s3.PutObjectRetentionInput) (*s3.PutObjectRetentionOutput, error) {
	return c.s3Client.PutObjectRetention(ctx, input)
}

func (c *Client) GetObjectTorrent(ctx context.Context, input *s3.GetObjectTorrentInput) (*s3.GetObjectTorrentOutput, error) {
	return c.s3Client.GetObjectTorrent(ctx, input)
}

func (c *Client) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	// TODO: Add encryption support for S3 Select
	return c.s3Client.SelectObjectContent(ctx, input)
}
