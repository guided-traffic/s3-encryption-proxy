package interfaces

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3ClientInterface defines the S3 operations we need
// This interface is compatible with AWS SDK v2 s3.Client
type S3ClientInterface interface {
	// Bucket ACL operations
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error)

	// Bucket CORS operations
	GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error)
	PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error)
	DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error)

	// Bucket configuration operations
	GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error)
	PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error)
	GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error)
	PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketAccelerateConfigurationOutput, error)
	GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error)
	PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.PutBucketRequestPaymentOutput, error)

	// Bucket tagging operations
	GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error)
	PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error)
	DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error)

	// Bucket notification operations
	GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error)
	PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error)

	// Bucket lifecycle operations
	GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error)
	PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error)
	DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error)

	// Bucket replication operations
	GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error)
	PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.PutBucketReplicationOutput, error)
	DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error)

	// Bucket website operations
	GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error)
	PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.PutBucketWebsiteOutput, error)
	DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error)

	// Standard S3 operations
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error)
	DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error)

	// Multipart upload operations
	CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error)
	ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error)

	// Object ACL and tagging operations
	GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error)
	PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error)
	GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error)
	PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error)
	DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error)

	// Passthrough operations (object governance and compliance)
	DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error)
	GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error)
	PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error)
	GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error)
	PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error)
	GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error)
	SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error)
}
