package s3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/sirupsen/logrus"
)

// Client wraps the AWS S3 client with encryption capabilities
type Client struct {
	s3Client       *s3.Client
	encryptionMgr  *encryption.Manager
	metadataPrefix string
	segmentSize    int64
	logger         *logrus.Entry

	// Composed handlers for separation of concerns
	objectHandler      *ObjectHandler
	multipartHandler   *MultipartHandler
	bucketHandler      *BucketHandler
	passthroughHandler *PassthroughHandler
}

// GetRawS3Client returns the underlying raw S3 client for direct operations
func (c *Client) GetRawS3Client() *s3.Client {
	return c.s3Client
}

// GetMetadataPrefix returns the metadata prefix used for encryption metadata
func (c *Client) GetMetadataPrefix() string {
	return c.metadataPrefix
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

	client := &Client{
		s3Client:       s3Client,
		encryptionMgr:  encMgr,
		metadataPrefix: cfg.MetadataPrefix,
		segmentSize:    cfg.SegmentSize,
		logger:         logger.WithField("component", "s3-client"),
	}

	// Initialize handlers with shared dependencies
	client.objectHandler = NewObjectHandler(client)
	client.multipartHandler = NewMultipartHandler(client)
	client.bucketHandler = NewBucketHandler(s3Client)
	client.passthroughHandler = NewPassthroughHandler(s3Client)

	return client, nil
}

// ==============================================
// OBJECT OPERATIONS (delegated to ObjectHandler)
// ==============================================

// PutObject encrypts and stores an object in S3
func (c *Client) PutObject(ctx context.Context, input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return c.objectHandler.PutObject(ctx, input)
}

// GetObject retrieves and decrypts an object from S3
func (c *Client) GetObject(ctx context.Context, input *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	return c.objectHandler.GetObject(ctx, input)
}

// HeadObject retrieves object metadata, removing encryption-specific metadata
func (c *Client) HeadObject(ctx context.Context, input *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	return c.objectHandler.HeadObject(ctx, input)
}

// DeleteObject deletes an object from S3
func (c *Client) DeleteObject(ctx context.Context, input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	return c.objectHandler.DeleteObject(ctx, input)
}

// CopyObject copies an object with encryption support
func (c *Client) CopyObject(ctx context.Context, input *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	return c.objectHandler.CopyObject(ctx, input)
}

// ==============================================
// MULTIPART UPLOAD OPERATIONS (delegated to MultipartHandler)
// ==============================================

// CreateMultipartUpload creates a new multipart upload with encryption
func (c *Client) CreateMultipartUpload(ctx context.Context, input *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	return c.multipartHandler.CreateMultipartUpload(ctx, input)
}

// UploadPart uploads an encrypted part
func (c *Client) UploadPart(ctx context.Context, input *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	return c.multipartHandler.UploadPart(ctx, input)
}

// CompleteMultipartUpload completes an encrypted multipart upload
func (c *Client) CompleteMultipartUpload(ctx context.Context, input *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	return c.multipartHandler.CompleteMultipartUpload(ctx, input)
}

// AbortMultipartUpload aborts an encrypted multipart upload
func (c *Client) AbortMultipartUpload(ctx context.Context, input *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	return c.multipartHandler.AbortMultipartUpload(ctx, input)
}

// ListParts lists parts of a multipart upload
func (c *Client) ListParts(ctx context.Context, input *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
	return c.multipartHandler.ListParts(ctx, input)
}

// ListMultipartUploads lists multipart uploads
func (c *Client) ListMultipartUploads(ctx context.Context, input *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	return c.multipartHandler.ListMultipartUploads(ctx, input)
}

// ==============================================
// BUCKET OPERATIONS (delegated to BucketHandler)
// ==============================================

// CreateBucket creates a new bucket
func (c *Client) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return c.bucketHandler.CreateBucket(ctx, input)
}

// DeleteBucket deletes a bucket
func (c *Client) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	return c.bucketHandler.DeleteBucket(ctx, input)
}

// HeadBucket checks if a bucket exists
func (c *Client) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return c.bucketHandler.HeadBucket(ctx, input)
}

// ListBuckets lists all buckets
func (c *Client) ListBuckets(ctx context.Context, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return c.bucketHandler.ListBuckets(ctx, input)
}

// GetBucketAcl retrieves bucket ACL
func (c *Client) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return c.bucketHandler.GetBucketAcl(ctx, input)
}

// PutBucketAcl sets bucket ACL
func (c *Client) PutBucketAcl(ctx context.Context, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return c.bucketHandler.PutBucketAcl(ctx, input)
}

// GetBucketCors retrieves bucket CORS configuration
func (c *Client) GetBucketCors(ctx context.Context, input *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error) {
	return c.bucketHandler.GetBucketCors(ctx, input)
}

// PutBucketCors sets bucket CORS configuration
func (c *Client) PutBucketCors(ctx context.Context, input *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error) {
	return c.bucketHandler.PutBucketCors(ctx, input)
}

// DeleteBucketCors deletes bucket CORS configuration
func (c *Client) DeleteBucketCors(ctx context.Context, input *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error) {
	return c.bucketHandler.DeleteBucketCors(ctx, input)
}

// GetBucketVersioning retrieves bucket versioning configuration
func (c *Client) GetBucketVersioning(ctx context.Context, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return c.bucketHandler.GetBucketVersioning(ctx, input)
}

// PutBucketVersioning sets bucket versioning configuration
func (c *Client) PutBucketVersioning(ctx context.Context, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return c.bucketHandler.PutBucketVersioning(ctx, input)
}

// GetBucketPolicy retrieves bucket policy
func (c *Client) GetBucketPolicy(ctx context.Context, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return c.bucketHandler.GetBucketPolicy(ctx, input)
}

// PutBucketPolicy sets bucket policy
func (c *Client) PutBucketPolicy(ctx context.Context, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return c.bucketHandler.PutBucketPolicy(ctx, input)
}

// DeleteBucketPolicy deletes bucket policy
func (c *Client) DeleteBucketPolicy(ctx context.Context, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return c.bucketHandler.DeleteBucketPolicy(ctx, input)
}

// GetBucketLocation retrieves bucket location
func (c *Client) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	return c.bucketHandler.GetBucketLocation(ctx, input)
}

// GetBucketLogging retrieves bucket logging configuration
func (c *Client) GetBucketLogging(ctx context.Context, input *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	return c.bucketHandler.GetBucketLogging(ctx, input)
}

// PutBucketLogging sets bucket logging configuration
func (c *Client) PutBucketLogging(ctx context.Context, input *s3.PutBucketLoggingInput) (*s3.PutBucketLoggingOutput, error) {
	return c.bucketHandler.PutBucketLogging(ctx, input)
}

// GetBucketNotificationConfiguration retrieves bucket notification configuration
func (c *Client) GetBucketNotificationConfiguration(ctx context.Context, input *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return c.bucketHandler.GetBucketNotificationConfiguration(ctx, input)
}

// PutBucketNotificationConfiguration sets bucket notification configuration
func (c *Client) PutBucketNotificationConfiguration(ctx context.Context, input *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error) {
	return c.bucketHandler.PutBucketNotificationConfiguration(ctx, input)
}

// GetBucketTagging retrieves bucket tags
func (c *Client) GetBucketTagging(ctx context.Context, input *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	return c.bucketHandler.GetBucketTagging(ctx, input)
}

// PutBucketTagging sets bucket tags
func (c *Client) PutBucketTagging(ctx context.Context, input *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	return c.bucketHandler.PutBucketTagging(ctx, input)
}

// DeleteBucketTagging deletes bucket tags
func (c *Client) DeleteBucketTagging(ctx context.Context, input *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error) {
	return c.bucketHandler.DeleteBucketTagging(ctx, input)
}

// GetBucketLifecycleConfiguration retrieves bucket lifecycle configuration
func (c *Client) GetBucketLifecycleConfiguration(ctx context.Context, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return c.bucketHandler.GetBucketLifecycleConfiguration(ctx, input)
}

// PutBucketLifecycleConfiguration sets bucket lifecycle configuration
func (c *Client) PutBucketLifecycleConfiguration(ctx context.Context, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return c.bucketHandler.PutBucketLifecycleConfiguration(ctx, input)
}

// DeleteBucketLifecycle deletes bucket lifecycle configuration
func (c *Client) DeleteBucketLifecycle(ctx context.Context, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return c.bucketHandler.DeleteBucketLifecycle(ctx, input)
}

// GetBucketReplication retrieves bucket replication configuration
func (c *Client) GetBucketReplication(ctx context.Context, input *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error) {
	return c.bucketHandler.GetBucketReplication(ctx, input)
}

// PutBucketReplication sets bucket replication configuration
func (c *Client) PutBucketReplication(ctx context.Context, input *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error) {
	return c.bucketHandler.PutBucketReplication(ctx, input)
}

// DeleteBucketReplication deletes bucket replication configuration
func (c *Client) DeleteBucketReplication(ctx context.Context, input *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error) {
	return c.bucketHandler.DeleteBucketReplication(ctx, input)
}

// GetBucketWebsite retrieves bucket website configuration
func (c *Client) GetBucketWebsite(ctx context.Context, input *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error) {
	return c.bucketHandler.GetBucketWebsite(ctx, input)
}

// PutBucketWebsite sets bucket website configuration
func (c *Client) PutBucketWebsite(ctx context.Context, input *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error) {
	return c.bucketHandler.PutBucketWebsite(ctx, input)
}

// DeleteBucketWebsite deletes bucket website configuration
func (c *Client) DeleteBucketWebsite(ctx context.Context, input *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error) {
	return c.bucketHandler.DeleteBucketWebsite(ctx, input)
}

// GetBucketAccelerateConfiguration retrieves bucket acceleration configuration
func (c *Client) GetBucketAccelerateConfiguration(ctx context.Context, input *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	return c.bucketHandler.GetBucketAccelerateConfiguration(ctx, input)
}

// PutBucketAccelerateConfiguration sets bucket acceleration configuration
func (c *Client) PutBucketAccelerateConfiguration(ctx context.Context, input *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	return c.bucketHandler.PutBucketAccelerateConfiguration(ctx, input)
}

// GetBucketRequestPayment retrieves bucket request payment configuration
func (c *Client) GetBucketRequestPayment(ctx context.Context, input *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error) {
	return c.bucketHandler.GetBucketRequestPayment(ctx, input)
}

// PutBucketRequestPayment sets bucket request payment configuration
func (c *Client) PutBucketRequestPayment(ctx context.Context, input *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error) {
	return c.bucketHandler.PutBucketRequestPayment(ctx, input)
}

// ==============================================
// PASSTHROUGH OPERATIONS (delegated to PassthroughHandler)
// ==============================================

// ListObjects lists objects in a bucket
func (c *Client) ListObjects(ctx context.Context, input *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	return c.passthroughHandler.ListObjects(ctx, input)
}

// ListObjectsV2 lists objects in a bucket using the V2 API
func (c *Client) ListObjectsV2(ctx context.Context, input *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	return c.passthroughHandler.ListObjectsV2(ctx, input)
}

// DeleteObjects deletes multiple objects
func (c *Client) DeleteObjects(ctx context.Context, input *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	return c.passthroughHandler.DeleteObjects(ctx, input)
}

// GetObjectAcl retrieves object ACL
func (c *Client) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return c.passthroughHandler.GetObjectAcl(ctx, input)
}

// PutObjectAcl sets object ACL
func (c *Client) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) (*s3.PutObjectAclOutput, error) {
	return c.passthroughHandler.PutObjectAcl(ctx, input)
}

// GetObjectTagging retrieves object tags
func (c *Client) GetObjectTagging(ctx context.Context, input *s3.GetObjectTaggingInput) (*s3.GetObjectTaggingOutput, error) {
	return c.passthroughHandler.GetObjectTagging(ctx, input)
}

// PutObjectTagging sets object tags
func (c *Client) PutObjectTagging(ctx context.Context, input *s3.PutObjectTaggingInput) (*s3.PutObjectTaggingOutput, error) {
	return c.passthroughHandler.PutObjectTagging(ctx, input)
}

// DeleteObjectTagging deletes object tags
func (c *Client) DeleteObjectTagging(ctx context.Context, input *s3.DeleteObjectTaggingInput) (*s3.DeleteObjectTaggingOutput, error) {
	return c.passthroughHandler.DeleteObjectTagging(ctx, input)
}

// GetObjectLegalHold retrieves object legal hold
func (c *Client) GetObjectLegalHold(ctx context.Context, input *s3.GetObjectLegalHoldInput) (*s3.GetObjectLegalHoldOutput, error) {
	return c.passthroughHandler.GetObjectLegalHold(ctx, input)
}

// PutObjectLegalHold sets object legal hold
func (c *Client) PutObjectLegalHold(ctx context.Context, input *s3.PutObjectLegalHoldInput) (*s3.PutObjectLegalHoldOutput, error) {
	return c.passthroughHandler.PutObjectLegalHold(ctx, input)
}

// GetObjectRetention retrieves object retention
func (c *Client) GetObjectRetention(ctx context.Context, input *s3.GetObjectRetentionInput) (*s3.GetObjectRetentionOutput, error) {
	return c.passthroughHandler.GetObjectRetention(ctx, input)
}

// PutObjectRetention sets object retention
func (c *Client) PutObjectRetention(ctx context.Context, input *s3.PutObjectRetentionInput) (*s3.PutObjectRetentionOutput, error) {
	return c.passthroughHandler.PutObjectRetention(ctx, input)
}

// GetObjectTorrent retrieves object torrent
func (c *Client) GetObjectTorrent(ctx context.Context, input *s3.GetObjectTorrentInput) (*s3.GetObjectTorrentOutput, error) {
	return c.passthroughHandler.GetObjectTorrent(ctx, input)
}

// SelectObjectContent performs S3 Select
func (c *Client) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	return c.passthroughHandler.SelectObjectContent(ctx, input)
}
