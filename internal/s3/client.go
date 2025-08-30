package s3

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/sirupsen/logrus"
)

// Client wraps the AWS S3 client with encryption capabilities
type Client struct {
	s3Client       *s3.S3
	encryptionMgr  *encryption.Manager
	metadataPrefix string
	logger         *logrus.Entry
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
func NewClient(cfg *Config, encMgr *encryption.Manager) (*Client, error) {
	// Create AWS session
	sess, err := session.NewSession(&aws.Config{
		Region:           aws.String(cfg.Region),
		Endpoint:         aws.String(cfg.Endpoint),
		DisableSSL:       aws.Bool(cfg.DisableSSL),
		S3ForcePathStyle: aws.Bool(cfg.ForcePathStyle),
		Credentials:      credentials.NewStaticCredentials(cfg.AccessKeyID, cfg.SecretKey, ""),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	s3Client := s3.New(sess)

	return &Client{
		s3Client:       s3Client,
		encryptionMgr:  encMgr,
		metadataPrefix: cfg.MetadataPrefix,
		logger:         logrus.WithField("component", "s3-client"),
	}, nil
}

// PutObject encrypts and stores an object in S3
func (c *Client) PutObject(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	objectKey := aws.StringValue(input.Key)
	c.logger.WithField("key", objectKey).Debug("Encrypting and putting object")

	// Read the object data
	data, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}

	// Encrypt the data
	encResult, err := c.encryptionMgr.EncryptData(ctx, data, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt object data: %w", err)
	}

	// Create metadata for the encrypted DEK and other encryption info
	metadata := make(map[string]*string)
	if input.Metadata != nil {
		// Copy existing metadata
		for k, v := range input.Metadata {
			metadata[k] = v
		}
	}

	// Add encryption metadata
	metadata[c.metadataPrefix+"encrypted-dek"] = aws.String(base64.StdEncoding.EncodeToString(encResult.EncryptedDEK))
	for k, v := range encResult.Metadata {
		metadata[c.metadataPrefix+k] = aws.String(v)
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

	// Update content length to match encrypted data
	encryptedInput.ContentLength = aws.Int64(int64(len(encResult.EncryptedData)))

	// Store the encrypted object
	output, err := c.s3Client.PutObjectWithContext(ctx, encryptedInput)
	if err != nil {
		return nil, fmt.Errorf("failed to put encrypted object: %w", err)
	}

	c.logger.WithField("key", objectKey).Debug("Successfully encrypted and stored object")
	return output, nil
}

// GetObject retrieves and decrypts an object from S3
func (c *Client) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	objectKey := aws.StringValue(input.Key)
	c.logger.WithField("key", objectKey).Debug("Getting and decrypting object")

	// Get the encrypted object from S3
	output, err := c.s3Client.GetObjectWithContext(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}

	// Check if the object is encrypted by looking for our metadata
	encryptedDEKB64, exists := output.Metadata[c.metadataPrefix+"encrypted-dek"]
	if !exists {
		// Object is not encrypted, return as-is
		c.logger.WithField("key", objectKey).Debug("Object is not encrypted, returning as-is")
		return output, nil
	}

	// Decode the encrypted DEK
	encryptedDEK, err := base64.StdEncoding.DecodeString(aws.StringValue(encryptedDEKB64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted DEK: %w", err)
	}

	// Read the encrypted data
	encryptedData, err := io.ReadAll(output.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted object body: %w", err)
	}
	output.Body.Close()

	// Decrypt the data
	plaintext, err := c.encryptionMgr.DecryptData(ctx, encryptedData, encryptedDEK, objectKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt object data: %w", err)
	}

	// Remove encryption metadata from the response
	cleanMetadata := make(map[string]*string)
	for k, v := range output.Metadata {
		if !strings.HasPrefix(k, c.metadataPrefix) {
			cleanMetadata[k] = v
		}
	}

	// Create new output with decrypted data
	decryptedOutput := &s3.GetObjectOutput{
		Body:                      io.NopCloser(bytes.NewReader(plaintext)),
		ContentLength:             aws.Int64(int64(len(plaintext))),
		ContentType:               output.ContentType,
		ContentEncoding:           output.ContentEncoding,
		ContentDisposition:        output.ContentDisposition,
		ContentLanguage:           output.ContentLanguage,
		CacheControl:              output.CacheControl,
		Expires:                   output.Expires,
		LastModified:              output.LastModified,
		ETag:                      output.ETag,
		Metadata:                  cleanMetadata,
		VersionId:                 output.VersionId,
		StorageClass:              output.StorageClass,
		WebsiteRedirectLocation:   output.WebsiteRedirectLocation,
		AcceptRanges:              output.AcceptRanges,
		SSECustomerAlgorithm:      output.SSECustomerAlgorithm,
		SSECustomerKeyMD5:         output.SSECustomerKeyMD5,
		SSEKMSKeyId:               output.SSEKMSKeyId,
		RequestCharged:            output.RequestCharged,
		ReplicationStatus:         output.ReplicationStatus,
		PartsCount:                output.PartsCount,
		TagCount:                  output.TagCount,
		ObjectLockMode:            output.ObjectLockMode,
		ObjectLockRetainUntilDate: output.ObjectLockRetainUntilDate,
		ObjectLockLegalHoldStatus: output.ObjectLockLegalHoldStatus,
	}

	c.logger.WithField("key", objectKey).Debug("Successfully retrieved and decrypted object")
	return decryptedOutput, nil
}

// HeadObject retrieves object metadata, removing encryption-specific metadata
func (c *Client) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	output, err := c.s3Client.HeadObjectWithContext(ctx, input)
	if err != nil {
		return nil, err
	}

	// Remove encryption metadata from the response
	cleanMetadata := make(map[string]*string)
	for k, v := range output.Metadata {
		if !strings.HasPrefix(k, c.metadataPrefix) {
			cleanMetadata[k] = v
		}
	}
	output.Metadata = cleanMetadata

	// If object is encrypted, adjust content length to show original size
	if encryptedDEKB64, exists := output.Metadata[c.metadataPrefix+"encrypted-dek"]; exists {
		// For simplicity, we're not calculating the original size here
		// In a real implementation, you might store the original size in metadata
		_ = encryptedDEKB64
	}

	return output, nil
}

// DeleteObject deletes an object from S3
func (c *Client) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return c.s3Client.DeleteObjectWithContext(ctx, input)
}

// ListObjects lists objects in a bucket
func (c *Client) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return c.s3Client.ListObjectsWithContext(ctx, input)
}

// ListObjectsV2 lists objects in a bucket using the V2 API
func (c *Client) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return c.s3Client.ListObjectsV2WithContext(ctx, input)
}
