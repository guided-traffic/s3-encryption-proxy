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
	GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error)
	GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error)

	// Standard S3 operations
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput) (*s3.ListBucketsOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error)
	ListObjects(ctx context.Context, params *s3.ListObjectsInput) (*s3.ListObjectsOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error)
}
