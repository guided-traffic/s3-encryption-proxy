package object

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"

	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

// MockS3Client for testing
type MockS3Client struct {
	mock.Mock
}

// Bucket operations
func (m *MockS3Client) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketPolicy(ctx context.Context, params *s3.PutBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketPolicy(ctx context.Context, params *s3.DeleteBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketLogging(ctx context.Context, params *s3.PutBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketLifecycleOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.PutBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.PutBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketRequestPaymentOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.PutBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketRequestPaymentOutput), args.Error(1)
}

// Basic bucket operations
func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

func (m *MockS3Client) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.HeadBucketOutput), args.Error(1)
}

func (m *MockS3Client) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
}

// Object operations
func (m *MockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListObjectsV2Output), args.Error(1)
}

func (m *MockS3Client) ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListObjectsOutput), args.Error(1)
}

func (m *MockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *MockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CopyObjectOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectAttributes(ctx context.Context, params *s3.GetObjectAttributesInput, optFns ...func(*s3.Options)) (*s3.GetObjectAttributesOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectAttributesOutput), args.Error(1)
}

// Multipart upload operations
func (m *MockS3Client) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CreateMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.UploadPartOutput), args.Error(1)
}

func (m *MockS3Client) UploadPartCopy(ctx context.Context, params *s3.UploadPartCopyInput, optFns ...func(*s3.Options)) (*s3.UploadPartCopyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.UploadPartCopyOutput), args.Error(1)
}

func (m *MockS3Client) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CompleteMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.AbortMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListPartsOutput), args.Error(1)
}

func (m *MockS3Client) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListMultipartUploadsOutput), args.Error(1)
}

// Object ACL and tagging operations
func (m *MockS3Client) GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectAclOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectAclOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectTaggingOutput), args.Error(1)
}

// Passthrough operations
func (m *MockS3Client) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectTorrentOutput), args.Error(1)
}

func (m *MockS3Client) SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

// Test helper functions

// testLogger creates a test logger
func testLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests
	return logrus.NewEntry(logger)
}

// testHandler creates a test handler with mock S3 client for unit tests
func testHandler() *Handler {
	mockS3Client := &MockS3Client{}

	// Setup some default mock behaviors to prevent nil pointer errors
	mockS3Client.On("GetBucketAcl", mock.Anything, mock.Anything).Return(&s3.GetBucketAclOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketAcl", mock.Anything, mock.Anything).Return(&s3.PutBucketAclOutput{}, nil).Maybe()

	// Mock CORS operations with realistic responses
	mockCorsOutput := &s3.GetBucketCorsOutput{
		CORSRules: []s3types.CORSRule{
			{
				AllowedOrigins: []string{"*"},
				AllowedMethods: []string{"GET", "PUT", "POST", "DELETE", "HEAD"},
				AllowedHeaders: []string{"*"},
				MaxAgeSeconds:  aws.Int32(3600),
			},
		},
	}
	mockS3Client.On("GetBucketCors", mock.Anything, mock.Anything).Return(mockCorsOutput, nil).Maybe()
	mockS3Client.On("PutBucketCors", mock.Anything, mock.Anything).Return(&s3.PutBucketCorsOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketCors", mock.Anything, mock.Anything).Return(&s3.DeleteBucketCorsOutput{}, nil).Maybe()

	// Mock versioning operations
	mockS3Client.On("GetBucketVersioning", mock.Anything, mock.Anything).Return(&s3.GetBucketVersioningOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketVersioning", mock.Anything, mock.Anything).Return(&s3.PutBucketVersioningOutput{}, nil).Maybe()

	// Mock notification operations
	mockS3Client.On("GetBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketNotificationConfigurationOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketNotificationConfiguration", mock.Anything, mock.Anything).Return(&s3.PutBucketNotificationConfigurationOutput{}, nil).Maybe()

	// Mock tagging operations
	mockS3Client.On("GetBucketTagging", mock.Anything, mock.Anything).Return(&s3.GetBucketTaggingOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketTagging", mock.Anything, mock.Anything).Return(&s3.PutBucketTaggingOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketTagging", mock.Anything, mock.Anything).Return(&s3.DeleteBucketTaggingOutput{}, nil).Maybe()

	// Mock lifecycle operations
	mockS3Client.On("GetBucketLifecycleConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketLifecycleConfigurationOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketLifecycleConfiguration", mock.Anything, mock.Anything).Return(&s3.PutBucketLifecycleConfigurationOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketLifecycle", mock.Anything, mock.Anything).Return(&s3.DeleteBucketLifecycleOutput{}, nil).Maybe()

	// Mock replication operations
	mockS3Client.On("GetBucketReplication", mock.Anything, mock.Anything).Return(&s3.GetBucketReplicationOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketReplication", mock.Anything, mock.Anything).Return(&s3.PutBucketReplicationOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketReplication", mock.Anything, mock.Anything).Return(&s3.DeleteBucketReplicationOutput{}, nil).Maybe()

	// Mock website operations
	mockS3Client.On("GetBucketWebsite", mock.Anything, mock.Anything).Return(&s3.GetBucketWebsiteOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketWebsite", mock.Anything, mock.Anything).Return(&s3.PutBucketWebsiteOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketWebsite", mock.Anything, mock.Anything).Return(&s3.DeleteBucketWebsiteOutput{}, nil).Maybe()

	// Mock accelerate operations
	mockS3Client.On("GetBucketAccelerateConfiguration", mock.Anything, mock.Anything).Return(&s3.GetBucketAccelerateConfigurationOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketAccelerateConfiguration", mock.Anything, mock.Anything).Return(&s3.PutBucketAccelerateConfigurationOutput{}, nil).Maybe()

	// Mock request payment operations
	mockS3Client.On("GetBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.GetBucketRequestPaymentOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketRequestPayment", mock.Anything, mock.Anything).Return(&s3.PutBucketRequestPaymentOutput{}, nil).Maybe()

	// Mock location operations
	mockS3Client.On("GetBucketLocation", mock.Anything, mock.Anything).Return(&s3.GetBucketLocationOutput{
		LocationConstraint: s3types.BucketLocationConstraint("us-east-1"),
	}, nil).Maybe()

	// Mock logging operations
	targetBucket := "access-logs"
	mockS3Client.On("GetBucketLogging", mock.Anything, mock.Anything).Return(&s3.GetBucketLoggingOutput{
		LoggingEnabled: &s3types.LoggingEnabled{
			TargetBucket: &targetBucket,
		},
	}, nil).Maybe()
	mockS3Client.On("PutBucketLogging", mock.Anything, mock.Anything).Return(&s3.PutBucketLoggingOutput{}, nil).Maybe()

	// Mock policy operations
	defaultPolicy := `{"Version": "2012-10-17", "Statement": []}`
	mockS3Client.On("GetBucketPolicy", mock.Anything, mock.Anything).Return(&s3.GetBucketPolicyOutput{
		Policy: &defaultPolicy,
	}, nil).Maybe()
	mockS3Client.On("PutBucketPolicy", mock.Anything, mock.Anything).Return(&s3.PutBucketPolicyOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketPolicy", mock.Anything, mock.Anything).Return(&s3.DeleteBucketPolicyOutput{}, nil).Maybe()

	// Mock tagging operations
	mockS3Client.On("GetBucketTagging", mock.Anything, mock.Anything).Return(&s3.GetBucketTaggingOutput{
		TagSet: []s3types.Tag{
			{
				Key:   aws.String("Environment"),
				Value: aws.String("test"),
			},
		},
	}, nil).Maybe()
	mockS3Client.On("PutBucketTagging", mock.Anything, mock.Anything).Return(&s3.PutBucketTaggingOutput{}, nil).Maybe()
	mockS3Client.On("DeleteBucketTagging", mock.Anything, mock.Anything).Return(&s3.DeleteBucketTaggingOutput{}, nil).Maybe()

	mockS3Client.On("ListObjectsV2", mock.Anything, mock.Anything).Return(&s3.ListObjectsV2Output{}, nil).Maybe()
	mockS3Client.On("ListObjects", mock.Anything, mock.Anything).Return(&s3.ListObjectsOutput{}, nil).Maybe()

	return NewHandler(mockS3Client, &encryption.Manager{}, testLogger(), "s3ep-")
}

// isValidJSON checks if a string is valid JSON
func isValidJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}
