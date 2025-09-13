package bucket

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/mock"
)

// MockS3Client for testing
type MockS3Client struct {
	mock.Mock
}

// Bucket operations
func (m *MockS3Client) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput) (*s3.GetBucketAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput) (*s3.PutBucketAclOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput) (*s3.GetBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput) (*s3.PutBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput) (*s3.DeleteBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput) (*s3.GetBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketPolicy(ctx context.Context, params *s3.PutBucketPolicyInput) (*s3.PutBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketPolicy(ctx context.Context, params *s3.DeleteBucketPolicyInput) (*s3.DeleteBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput) (*s3.GetBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketLogging(ctx context.Context, params *s3.PutBucketLoggingInput) (*s3.PutBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput) (*s3.PutBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput) (*s3.DeleteBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput) (*s3.GetBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput) (*s3.PutBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput) (*s3.DeleteBucketLifecycleOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketLifecycleOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput) (*s3.GetBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput) (*s3.PutBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput) (*s3.DeleteBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput) (*s3.GetBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput) (*s3.PutBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput) (*s3.DeleteBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput) (*s3.GetBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetBucketRequestPaymentOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput) (*s3.PutBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutBucketRequestPaymentOutput), args.Error(1)
}

// Basic bucket operations
func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

func (m *MockS3Client) HeadBucket(ctx context.Context, params *s3.HeadBucketInput) (*s3.HeadBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.HeadBucketOutput), args.Error(1)
}

func (m *MockS3Client) CreateBucket(ctx context.Context, params *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
}

// Object operations
func (m *MockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListObjectsV2Output), args.Error(1)
}

func (m *MockS3Client) ListObjects(ctx context.Context, params *s3.ListObjectsInput) (*s3.ListObjectsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListObjectsOutput), args.Error(1)
}

func (m *MockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *MockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput) (*s3.CopyObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CopyObjectOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectAttributes(ctx context.Context, params *s3.GetObjectAttributesInput) (*s3.GetObjectAttributesOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.GetObjectAttributesOutput), args.Error(1)
}

// Multipart upload operations
func (m *MockS3Client) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput) (*s3.CreateMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CreateMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) UploadPart(ctx context.Context, params *s3.UploadPartInput) (*s3.UploadPartOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.UploadPartOutput), args.Error(1)
}

func (m *MockS3Client) UploadPartCopy(ctx context.Context, params *s3.UploadPartCopyInput) (*s3.UploadPartCopyOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.UploadPartCopyOutput), args.Error(1)
}

func (m *MockS3Client) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput) (*s3.CompleteMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.CompleteMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput) (*s3.AbortMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.AbortMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) ListParts(ctx context.Context, params *s3.ListPartsInput) (*s3.ListPartsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListPartsOutput), args.Error(1)
}

func (m *MockS3Client) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput) (*s3.ListMultipartUploadsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListMultipartUploadsOutput), args.Error(1)
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
	mockS3Client.On("GetBucketCors", mock.Anything, mock.Anything).Return(&s3.GetBucketCorsOutput{}, nil).Maybe()
	mockS3Client.On("PutBucketCors", mock.Anything, mock.Anything).Return(&s3.PutBucketCorsOutput{}, nil).Maybe()
	mockS3Client.On("ListObjectsV2", mock.Anything, mock.Anything).Return(&s3.ListObjectsV2Output{}, nil).Maybe()
	mockS3Client.On("ListObjects", mock.Anything, mock.Anything).Return(&s3.ListObjectsOutput{}, nil).Maybe()

	return NewHandler(mockS3Client, testLogger(), "s3ep-")
}

// isValidJSON checks if a string is valid JSON
func isValidJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}
