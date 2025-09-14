package root

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockS3Client implements the S3ClientInterface for testing
type MockS3Client struct {
	mock.Mock
}

func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

// Minimal implementation of other required methods - we'll only implement what we need for testing
func (m *MockS3Client) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketAclOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketCorsOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketRequestPaymentOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.PutBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketRequestPaymentOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketLifecycleOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.PutBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Client) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.PutBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Client) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsV2Output), args.Error(1)
}

func (m *MockS3Client) ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsOutput), args.Error(1)
}

func (m *MockS3Client) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *MockS3Client) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

func (m *MockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CopyObjectOutput), args.Error(1)
}

func (m *MockS3Client) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.UploadPartOutput), args.Error(1)
}

func (m *MockS3Client) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CompleteMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.AbortMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Client) ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListPartsOutput), args.Error(1)
}

func (m *MockS3Client) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListMultipartUploadsOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectAclOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectAclOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Client) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Client) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Client) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectTorrentOutput), args.Error(1)
}

func (m *MockS3Client) SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

// Ensure MockS3Client implements the interface
var _ interfaces.S3ClientInterface = (*MockS3Client)(nil)

func TestHandleListBuckets(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockS3Client := &MockS3Client{}
	handler := NewHandler(mockS3Client, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create mock response
	mockResponse := &s3.ListBucketsOutput{
		Buckets: []types.Bucket{
			{
				Name: aws.String("test-bucket"),
			},
		},
	}

	// Setup mock expectations
	mockS3Client.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(mockResponse, nil)

	// Execute
	handler.HandleListBuckets(w, req)

	// Verify
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "test-bucket")
	mockS3Client.AssertExpectations(t)
}

func TestHandleListBucketsError(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockS3Client := &MockS3Client{}
	handler := NewHandler(mockS3Client, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Setup mock to return error
	mockS3Client.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(nil, assert.AnError)

	// Execute
	handler.HandleListBuckets(w, req)

	// Verify error response
	assert.Equal(t, 500, w.Code)
	assert.Contains(t, w.Body.String(), "Internal Server Error")
}

func TestHandleListBucketsMultipleBuckets(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockS3Client := &MockS3Client{}
	handler := NewHandler(mockS3Client, logger)

	// Create test request
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Create mock response with multiple buckets
	mockResponse := &s3.ListBucketsOutput{
		Buckets: []types.Bucket{
			{
				Name: aws.String("bucket-1"),
			},
			{
				Name: aws.String("bucket-2"),
			},
			{
				Name: aws.String("bucket-3"),
			},
		},
	}

	// Setup mock expectations
	mockS3Client.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(mockResponse, nil)

	// Execute
	handler.HandleListBuckets(w, req)

	// Verify
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, "bucket-1")
	assert.Contains(t, responseBody, "bucket-2")
	assert.Contains(t, responseBody, "bucket-3")
	mockS3Client.AssertExpectations(t)
}

func TestNewHandler(t *testing.T) {
	logger := logrus.New()
	mockS3Client := &MockS3Client{}

	handler := NewHandler(mockS3Client, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockS3Client, handler.s3Client)
	assert.Equal(t, logger, handler.logger)
}
