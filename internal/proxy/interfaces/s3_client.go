package interfaces

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3ClientInterface defines the S3 operations we need
// This interface is compatible with our internal s3client.Client
type S3ClientInterface interface {
	// Bucket ACL operations
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error)
	PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error)

	// Bucket CORS operations
	GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error)
	PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error)
	DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error)

	// Bucket configuration operations
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error)
	PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error)
	GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error)
	PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error)
	GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error)
	PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error)

	// Bucket tagging operations
	GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error)
	PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error)
	DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error)

	// Bucket notification operations
	GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error)
	PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error)

	// Bucket lifecycle operations
	GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error)
	PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error)
	DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error)

	// Bucket replication operations
	GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error)
	PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error)
	DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error)

	// Bucket website operations
	GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error)
	PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error)
	DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error)

	// Standard S3 operations
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput) (*s3.ListBucketsOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	ListObjects(ctx context.Context, params *s3.ListObjectsInput) (*s3.ListObjectsOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error)

	// Multipart upload operations
	CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, params *s3.UploadPartInput) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error)
	ListParts(ctx context.Context, params *s3.ListPartsInput) (*s3.ListPartsOutput, error)
	ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error)
}
