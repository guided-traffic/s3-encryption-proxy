package s3client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ==============================================
// BUCKET OPERATIONS - Direct pass-through to S3
// ==============================================

// CreateBucket creates a new bucket
func (c *Client) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return c.s3Client.CreateBucket(ctx, input)
}

// DeleteBucket deletes a bucket
func (c *Client) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	return c.s3Client.DeleteBucket(ctx, input)
}

// HeadBucket checks if a bucket exists
func (c *Client) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return c.s3Client.HeadBucket(ctx, input)
}

// ListBuckets lists all buckets
func (c *Client) ListBuckets(ctx context.Context, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return c.s3Client.ListBuckets(ctx, input)
}

// ==============================================
// BUCKET SUB-RESOURCE OPERATIONS
// ==============================================

// GetBucketAcl retrieves bucket ACL
func (c *Client) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return c.s3Client.GetBucketAcl(ctx, input)
}

// PutBucketAcl sets bucket ACL
func (c *Client) PutBucketAcl(ctx context.Context, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return c.s3Client.PutBucketAcl(ctx, input)
}

// GetBucketCors retrieves bucket CORS configuration
func (c *Client) GetBucketCors(ctx context.Context, input *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error) {
	return c.s3Client.GetBucketCors(ctx, input)
}

// PutBucketCors sets bucket CORS configuration
func (c *Client) PutBucketCors(ctx context.Context, input *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error) {
	return c.s3Client.PutBucketCors(ctx, input)
}

// DeleteBucketCors deletes bucket CORS configuration
func (c *Client) DeleteBucketCors(ctx context.Context, input *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error) {
	return c.s3Client.DeleteBucketCors(ctx, input)
}

// GetBucketVersioning retrieves bucket versioning configuration
func (c *Client) GetBucketVersioning(ctx context.Context, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return c.s3Client.GetBucketVersioning(ctx, input)
}

// PutBucketVersioning sets bucket versioning configuration
func (c *Client) PutBucketVersioning(ctx context.Context, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return c.s3Client.PutBucketVersioning(ctx, input)
}

// GetBucketPolicy retrieves bucket policy
func (c *Client) GetBucketPolicy(ctx context.Context, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return c.s3Client.GetBucketPolicy(ctx, input)
}

// PutBucketPolicy sets bucket policy
func (c *Client) PutBucketPolicy(ctx context.Context, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return c.s3Client.PutBucketPolicy(ctx, input)
}

// DeleteBucketPolicy deletes bucket policy
func (c *Client) DeleteBucketPolicy(ctx context.Context, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return c.s3Client.DeleteBucketPolicy(ctx, input)
}

// GetBucketLocation retrieves bucket location
func (c *Client) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	return c.s3Client.GetBucketLocation(ctx, input)
}

// GetBucketLogging retrieves bucket logging configuration
func (c *Client) GetBucketLogging(ctx context.Context, input *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	return c.s3Client.GetBucketLogging(ctx, input)
}

// PutBucketLogging sets bucket logging configuration
func (c *Client) PutBucketLogging(ctx context.Context, input *s3.PutBucketLoggingInput) (*s3.PutBucketLoggingOutput, error) {
	return c.s3Client.PutBucketLogging(ctx, input)
}

// GetBucketNotificationConfiguration retrieves bucket notification configuration
func (c *Client) GetBucketNotificationConfiguration(ctx context.Context, input *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return c.s3Client.GetBucketNotificationConfiguration(ctx, input)
}

// PutBucketNotificationConfiguration sets bucket notification configuration
func (c *Client) PutBucketNotificationConfiguration(ctx context.Context, input *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error) {
	return c.s3Client.PutBucketNotificationConfiguration(ctx, input)
}

// GetBucketTagging retrieves bucket tags
func (c *Client) GetBucketTagging(ctx context.Context, input *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	return c.s3Client.GetBucketTagging(ctx, input)
}

// PutBucketTagging sets bucket tags
func (c *Client) PutBucketTagging(ctx context.Context, input *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	return c.s3Client.PutBucketTagging(ctx, input)
}

// DeleteBucketTagging deletes bucket tags
func (c *Client) DeleteBucketTagging(ctx context.Context, input *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error) {
	return c.s3Client.DeleteBucketTagging(ctx, input)
}

// GetBucketLifecycleConfiguration retrieves bucket lifecycle configuration
func (c *Client) GetBucketLifecycleConfiguration(ctx context.Context, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return c.s3Client.GetBucketLifecycleConfiguration(ctx, input)
}

// PutBucketLifecycleConfiguration sets bucket lifecycle configuration
func (c *Client) PutBucketLifecycleConfiguration(ctx context.Context, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return c.s3Client.PutBucketLifecycleConfiguration(ctx, input)
}

// DeleteBucketLifecycle deletes bucket lifecycle configuration
func (c *Client) DeleteBucketLifecycle(ctx context.Context, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return c.s3Client.DeleteBucketLifecycle(ctx, input)
}

// GetBucketReplication retrieves bucket replication configuration
func (c *Client) GetBucketReplication(ctx context.Context, input *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error) {
	return c.s3Client.GetBucketReplication(ctx, input)
}

// PutBucketReplication sets bucket replication configuration
func (c *Client) PutBucketReplication(ctx context.Context, input *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error) {
	return c.s3Client.PutBucketReplication(ctx, input)
}

// DeleteBucketReplication deletes bucket replication configuration
func (c *Client) DeleteBucketReplication(ctx context.Context, input *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error) {
	return c.s3Client.DeleteBucketReplication(ctx, input)
}

// GetBucketWebsite retrieves bucket website configuration
func (c *Client) GetBucketWebsite(ctx context.Context, input *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error) {
	return c.s3Client.GetBucketWebsite(ctx, input)
}

// PutBucketWebsite sets bucket website configuration
func (c *Client) PutBucketWebsite(ctx context.Context, input *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error) {
	return c.s3Client.PutBucketWebsite(ctx, input)
}

// DeleteBucketWebsite deletes bucket website configuration
func (c *Client) DeleteBucketWebsite(ctx context.Context, input *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error) {
	return c.s3Client.DeleteBucketWebsite(ctx, input)
}

// GetBucketAccelerateConfiguration retrieves bucket accelerate configuration
func (c *Client) GetBucketAccelerateConfiguration(ctx context.Context, input *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	return c.s3Client.GetBucketAccelerateConfiguration(ctx, input)
}

// PutBucketAccelerateConfiguration sets bucket accelerate configuration
func (c *Client) PutBucketAccelerateConfiguration(ctx context.Context, input *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	return c.s3Client.PutBucketAccelerateConfiguration(ctx, input)
}

// GetBucketRequestPayment retrieves bucket request payment configuration
func (c *Client) GetBucketRequestPayment(ctx context.Context, input *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error) {
	return c.s3Client.GetBucketRequestPayment(ctx, input)
}

// PutBucketRequestPayment sets bucket request payment configuration
func (c *Client) PutBucketRequestPayment(ctx context.Context, input *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error) {
	return c.s3Client.PutBucketRequestPayment(ctx, input)
}

// ==============================================
// OBJECT SUB-RESOURCE OPERATIONS
// ==============================================

// GetObjectAcl retrieves object ACL
func (c *Client) GetObjectAcl(ctx context.Context, input *s3.GetObjectAclInput) (*s3.GetObjectAclOutput, error) {
	return c.s3Client.GetObjectAcl(ctx, input)
}

// PutObjectAcl sets object ACL
func (c *Client) PutObjectAcl(ctx context.Context, input *s3.PutObjectAclInput) (*s3.PutObjectAclOutput, error) {
	return c.s3Client.PutObjectAcl(ctx, input)
}

// GetObjectTagging retrieves object tags
func (c *Client) GetObjectTagging(ctx context.Context, input *s3.GetObjectTaggingInput) (*s3.GetObjectTaggingOutput, error) {
	return c.s3Client.GetObjectTagging(ctx, input)
}

// PutObjectTagging sets object tags
func (c *Client) PutObjectTagging(ctx context.Context, input *s3.PutObjectTaggingInput) (*s3.PutObjectTaggingOutput, error) {
	return c.s3Client.PutObjectTagging(ctx, input)
}

// DeleteObjectTagging deletes object tags
func (c *Client) DeleteObjectTagging(ctx context.Context, input *s3.DeleteObjectTaggingInput) (*s3.DeleteObjectTaggingOutput, error) {
	return c.s3Client.DeleteObjectTagging(ctx, input)
}

// GetObjectLegalHold retrieves object legal hold status
func (c *Client) GetObjectLegalHold(ctx context.Context, input *s3.GetObjectLegalHoldInput) (*s3.GetObjectLegalHoldOutput, error) {
	return c.s3Client.GetObjectLegalHold(ctx, input)
}

// PutObjectLegalHold sets object legal hold status
func (c *Client) PutObjectLegalHold(ctx context.Context, input *s3.PutObjectLegalHoldInput) (*s3.PutObjectLegalHoldOutput, error) {
	return c.s3Client.PutObjectLegalHold(ctx, input)
}

// GetObjectRetention retrieves object retention configuration
func (c *Client) GetObjectRetention(ctx context.Context, input *s3.GetObjectRetentionInput) (*s3.GetObjectRetentionOutput, error) {
	return c.s3Client.GetObjectRetention(ctx, input)
}

// PutObjectRetention sets object retention configuration
func (c *Client) PutObjectRetention(ctx context.Context, input *s3.PutObjectRetentionInput) (*s3.PutObjectRetentionOutput, error) {
	return c.s3Client.PutObjectRetention(ctx, input)
}

// GetObjectTorrent retrieves object torrent
func (c *Client) GetObjectTorrent(ctx context.Context, input *s3.GetObjectTorrentInput) (*s3.GetObjectTorrentOutput, error) {
	return c.s3Client.GetObjectTorrent(ctx, input)
}

// SelectObjectContent performs S3 Select operations
func (c *Client) SelectObjectContent(ctx context.Context, input *s3.SelectObjectContentInput) (*s3.SelectObjectContentOutput, error) {
	// TODO: Add encryption support for S3 Select
	return c.s3Client.SelectObjectContent(ctx, input)
}
