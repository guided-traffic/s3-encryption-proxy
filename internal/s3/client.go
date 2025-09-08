package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/sirupsen/logrus"
)

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Client wraps the AWS S3 client with encryption capabilities
type Client struct {
	s3Client       *s3.Client
	encryptionMgr  *encryption.Manager
	metadataPrefix string
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
	}).Debug("Successfully read object data for encryption")

	// Encrypt the data
	encResult, err := c.encryptionMgr.EncryptData(ctx, data, objectKey)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":    objectKey,
			"bucket": bucketName,
		}).Error("Failed to encrypt object data")
		return nil, fmt.Errorf("failed to encrypt object data: %w", err)
	}

	c.logger.WithFields(logrus.Fields{
		"key":              objectKey,
		"bucket":           bucketName,
		"originalSize":     len(data),
		"encryptedSize":    len(encResult.EncryptedData),
		"encryptedDEKSize": len(encResult.EncryptedDEK),
		"encryptedDEKHex":  fmt.Sprintf("%x", encResult.EncryptedDEK),
		"providerAlias":    encResult.Metadata["provider_alias"],
	}).Debug("Successfully encrypted object data")

	// Create metadata for the encrypted DEK and other encryption info
	metadata := make(map[string]string)
	if input.Metadata != nil {
		// Copy existing metadata
		for k, v := range input.Metadata {
			metadata[k] = v
		}
	}

	// Add encryption metadata using the new manager's metadata format
	metadata[c.metadataPrefix+"dek"] = base64.StdEncoding.EncodeToString(encResult.EncryptedDEK)

	// Add all metadata from the encryption result
	for k, v := range encResult.Metadata {
		// Map provider_alias to provider for consistency with existing format
		if k == "provider_alias" {
			metadata[c.metadataPrefix+"provider"] = v
		} else {
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
	encryptedDEKB64, hasEncryption := output.Metadata[c.metadataPrefix+"dek"]
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

	plaintext, err := c.encryptionMgr.DecryptData(ctx, encryptedData, encryptedDEK, objectKey, providerAlias)
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
		Expires:          output.Expires,
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
		SSECustomerAlgorithm: output.SSECustomerAlgorithm,
		SSECustomerKeyMD5:    output.SSECustomerKeyMD5,
		SSEKMSKeyId:      output.SSEKMSKeyId,
		StorageClass:     output.StorageClass,
		TagCount:         output.TagCount,
		VersionId:        output.VersionId,
		WebsiteRedirectLocation: output.WebsiteRedirectLocation,
		ResultMetadata:   output.ResultMetadata,
	}, nil
}

// Helper function to get metadata keys for debugging
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

	// Create the multipart upload in S3 first
	output, err := c.s3Client.CreateMultipartUpload(ctx, input)
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

	// Read the part data
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
	encResult, err := c.encryptionMgr.UploadPart(ctx, uploadID, int(partNumber), partData)
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

	// Complete the multipart upload in S3 first
	output, err := c.s3Client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		c.logger.WithError(err).WithFields(logrus.Fields{
			"key":      objectKey,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload in S3")
		return nil, fmt.Errorf("failed to complete multipart upload: %w", err)
	}

	// Extract part ETags for the encryption manager
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
	c.encryptionMgr.AbortMultipartUpload(ctx, uploadID)

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
