package s3client

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// BucketHandler handles bucket-level operations
type BucketHandler struct {
	s3Client *s3.Client
}

// NewBucketHandler creates a new bucket handler
func NewBucketHandler(s3Client *s3.Client) *BucketHandler {
	return &BucketHandler{
		s3Client: s3Client,
	}
}

// CreateBucket creates a new bucket
func (h *BucketHandler) CreateBucket(ctx context.Context, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	return h.s3Client.CreateBucket(ctx, input)
}

// DeleteBucket deletes a bucket
func (h *BucketHandler) DeleteBucket(ctx context.Context, input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	return h.s3Client.DeleteBucket(ctx, input)
}

// HeadBucket checks if a bucket exists
func (h *BucketHandler) HeadBucket(ctx context.Context, input *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	return h.s3Client.HeadBucket(ctx, input)
}

// ListBuckets lists all buckets
func (h *BucketHandler) ListBuckets(ctx context.Context, input *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	return h.s3Client.ListBuckets(ctx, input)
}

// GetBucketAcl retrieves bucket ACL
func (h *BucketHandler) GetBucketAcl(ctx context.Context, input *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	return h.s3Client.GetBucketAcl(ctx, input)
}

// PutBucketAcl sets bucket ACL
func (h *BucketHandler) PutBucketAcl(ctx context.Context, input *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	return h.s3Client.PutBucketAcl(ctx, input)
}

// GetBucketCors retrieves bucket CORS configuration
func (h *BucketHandler) GetBucketCors(ctx context.Context, input *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error) {
	return h.s3Client.GetBucketCors(ctx, input)
}

// PutBucketCors sets bucket CORS configuration
func (h *BucketHandler) PutBucketCors(ctx context.Context, input *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error) {
	return h.s3Client.PutBucketCors(ctx, input)
}

// DeleteBucketCors deletes bucket CORS configuration
func (h *BucketHandler) DeleteBucketCors(ctx context.Context, input *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error) {
	return h.s3Client.DeleteBucketCors(ctx, input)
}

// GetBucketVersioning retrieves bucket versioning configuration
func (h *BucketHandler) GetBucketVersioning(ctx context.Context, input *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	return h.s3Client.GetBucketVersioning(ctx, input)
}

// PutBucketVersioning sets bucket versioning configuration
func (h *BucketHandler) PutBucketVersioning(ctx context.Context, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	return h.s3Client.PutBucketVersioning(ctx, input)
}

// GetBucketPolicy retrieves bucket policy
func (h *BucketHandler) GetBucketPolicy(ctx context.Context, input *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	return h.s3Client.GetBucketPolicy(ctx, input)
}

// PutBucketPolicy sets bucket policy
func (h *BucketHandler) PutBucketPolicy(ctx context.Context, input *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	return h.s3Client.PutBucketPolicy(ctx, input)
}

// DeleteBucketPolicy deletes bucket policy
func (h *BucketHandler) DeleteBucketPolicy(ctx context.Context, input *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	return h.s3Client.DeleteBucketPolicy(ctx, input)
}

// GetBucketLocation retrieves bucket location
func (h *BucketHandler) GetBucketLocation(ctx context.Context, input *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	return h.s3Client.GetBucketLocation(ctx, input)
}

// GetBucketLogging retrieves bucket logging configuration
func (h *BucketHandler) GetBucketLogging(ctx context.Context, input *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	return h.s3Client.GetBucketLogging(ctx, input)
}

// PutBucketLogging sets bucket logging configuration
func (h *BucketHandler) PutBucketLogging(ctx context.Context, input *s3.PutBucketLoggingInput) (*s3.PutBucketLoggingOutput, error) {
	return h.s3Client.PutBucketLogging(ctx, input)
}

// GetBucketNotificationConfiguration retrieves bucket notification configuration
func (h *BucketHandler) GetBucketNotificationConfiguration(ctx context.Context, input *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return h.s3Client.GetBucketNotificationConfiguration(ctx, input)
}

// PutBucketNotificationConfiguration sets bucket notification configuration
func (h *BucketHandler) PutBucketNotificationConfiguration(ctx context.Context, input *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error) {
	return h.s3Client.PutBucketNotificationConfiguration(ctx, input)
}

// GetBucketTagging retrieves bucket tags
func (h *BucketHandler) GetBucketTagging(ctx context.Context, input *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	return h.s3Client.GetBucketTagging(ctx, input)
}

// PutBucketTagging sets bucket tags
func (h *BucketHandler) PutBucketTagging(ctx context.Context, input *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	return h.s3Client.PutBucketTagging(ctx, input)
}

// DeleteBucketTagging deletes bucket tags
func (h *BucketHandler) DeleteBucketTagging(ctx context.Context, input *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error) {
	return h.s3Client.DeleteBucketTagging(ctx, input)
}

// GetBucketLifecycleConfiguration retrieves bucket lifecycle configuration
func (h *BucketHandler) GetBucketLifecycleConfiguration(ctx context.Context, input *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return h.s3Client.GetBucketLifecycleConfiguration(ctx, input)
}

// PutBucketLifecycleConfiguration sets bucket lifecycle configuration
func (h *BucketHandler) PutBucketLifecycleConfiguration(ctx context.Context, input *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return h.s3Client.PutBucketLifecycleConfiguration(ctx, input)
}

// DeleteBucketLifecycle deletes bucket lifecycle configuration
func (h *BucketHandler) DeleteBucketLifecycle(ctx context.Context, input *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	return h.s3Client.DeleteBucketLifecycle(ctx, input)
}

// GetBucketReplication retrieves bucket replication configuration
func (h *BucketHandler) GetBucketReplication(ctx context.Context, input *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error) {
	return h.s3Client.GetBucketReplication(ctx, input)
}

// PutBucketReplication sets bucket replication configuration
func (h *BucketHandler) PutBucketReplication(ctx context.Context, input *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error) {
	return h.s3Client.PutBucketReplication(ctx, input)
}

// DeleteBucketReplication deletes bucket replication configuration
func (h *BucketHandler) DeleteBucketReplication(ctx context.Context, input *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error) {
	return h.s3Client.DeleteBucketReplication(ctx, input)
}

// GetBucketWebsite retrieves bucket website configuration
func (h *BucketHandler) GetBucketWebsite(ctx context.Context, input *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error) {
	return h.s3Client.GetBucketWebsite(ctx, input)
}

// PutBucketWebsite sets bucket website configuration
func (h *BucketHandler) PutBucketWebsite(ctx context.Context, input *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error) {
	return h.s3Client.PutBucketWebsite(ctx, input)
}

// DeleteBucketWebsite deletes bucket website configuration
func (h *BucketHandler) DeleteBucketWebsite(ctx context.Context, input *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error) {
	return h.s3Client.DeleteBucketWebsite(ctx, input)
}

// GetBucketAccelerateConfiguration retrieves bucket acceleration configuration
func (h *BucketHandler) GetBucketAccelerateConfiguration(ctx context.Context, input *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	return h.s3Client.GetBucketAccelerateConfiguration(ctx, input)
}

// PutBucketAccelerateConfiguration sets bucket acceleration configuration
func (h *BucketHandler) PutBucketAccelerateConfiguration(ctx context.Context, input *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	return h.s3Client.PutBucketAccelerateConfiguration(ctx, input)
}

// GetBucketRequestPayment retrieves bucket request payment configuration
func (h *BucketHandler) GetBucketRequestPayment(ctx context.Context, input *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error) {
	return h.s3Client.GetBucketRequestPayment(ctx, input)
}

// PutBucketRequestPayment sets bucket request payment configuration
func (h *BucketHandler) PutBucketRequestPayment(ctx context.Context, input *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error) {
	return h.s3Client.PutBucketRequestPayment(ctx, input)
}
