//nolint:revive // Mock S3 client methods follow AWS SDK naming conventions
package multipart

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

// MockS3Backend for testing
type MockS3Backend struct {
	mock.Mock
}

func (m *MockS3Backend) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.UploadPartOutput), args.Error(1)
}

func (m *MockS3Backend) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CompleteMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.AbortMultipartUploadOutput), args.Error(1)
}

func (m *MockS3Backend) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CopyObjectOutput), args.Error(1)
}

func (m *MockS3Backend) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectOutput), args.Error(1)
}

func (m *MockS3Backend) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

func (m *MockS3Backend) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Backend) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsV2Output), args.Error(1)
}

func (m *MockS3Backend) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
}

func (m *MockS3Backend) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

func (m *MockS3Backend) HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadBucketOutput), args.Error(1)
}

// Bucket ACL operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAclOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketAclOutput), args.Error(1)
}

// Bucket CORS operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketCorsOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketCorsOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketCorsOutput), args.Error(1)
}

// Bucket configuration operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketVersioningOutput), args.Error(1)
}

func (m *MockS3Backend) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketAccelerateConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketRequestPaymentOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.PutBucketRequestPaymentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketRequestPaymentOutput), args.Error(1)
}

// Bucket tagging operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketTaggingOutput), args.Error(1)
}

// Bucket notification operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketNotificationConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketNotificationConfigurationOutput), args.Error(1)
}

// Bucket lifecycle operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketLifecycleConfigurationOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketLifecycleOutput), args.Error(1)
}

// Bucket replication operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.PutBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketReplicationOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketReplicationOutput), args.Error(1)
}

// Bucket website operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.PutBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketWebsiteOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketWebsiteOutput), args.Error(1)
}

// Additional operations - stubs for interface compliance
func (m *MockS3Backend) ListObjects(ctx context.Context, params *s3.ListObjectsInput, optFns ...func(*s3.Options)) (*s3.ListObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListObjectsOutput), args.Error(1)
}

func (m *MockS3Backend) ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListPartsOutput), args.Error(1)
}

func (m *MockS3Backend) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListMultipartUploadsOutput), args.Error(1)
}

// Bucket location operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLocationOutput), args.Error(1)
}

// Bucket logging operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketLogging(ctx context.Context, params *s3.GetBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketLoggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketLogging(ctx context.Context, params *s3.PutBucketLoggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketLoggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketLoggingOutput), args.Error(1)
}

// Bucket policy operations - stubs for interface compliance
func (m *MockS3Backend) GetBucketPolicy(ctx context.Context, params *s3.GetBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.GetBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Backend) PutBucketPolicy(ctx context.Context, params *s3.PutBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.PutBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutBucketPolicyOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteBucketPolicy(ctx context.Context, params *s3.DeleteBucketPolicyInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketPolicyOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketPolicyOutput), args.Error(1)
}

// Object ACL and tagging operations - stubs for interface compliance
func (m *MockS3Backend) GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectAclOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectAclOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectTaggingOutput), args.Error(1)
}

func (m *MockS3Backend) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectTaggingOutput), args.Error(1)
}

// Passthrough operations - stubs for interface compliance
func (m *MockS3Backend) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteObjectsOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectLegalHoldOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Backend) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.PutObjectRetentionOutput), args.Error(1)
}

func (m *MockS3Backend) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.GetObjectTorrentOutput), args.Error(1)
}

func (m *MockS3Backend) SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.SelectObjectContentOutput), args.Error(1)
}

func setupMultipartTestEnv(t *testing.T) (*orchestration.Manager, *MockS3Backend, *logrus.Entry, *response.XMLWriter, *response.ErrorWriter, *request.Parser) {
	// Create test configuration with AES-CTR provider for testing
	metadataPrefix := "s3ep-"
	testConfig := &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes-ctr",
			MetadataKeyPrefix:     &metadataPrefix,
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes-ctr",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=", // Base64 of 32-byte key
					},
				},
			},
		},
	}

	// Create encryption manager
	encMgr, err := orchestration.NewManager(testConfig)
	require.NoError(t, err)

	// Create mock S3 client
	mockS3Backend := new(MockS3Backend)

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logEntry := logrus.NewEntry(logger)

	// Create response writers
	xmlWriter := response.NewXMLWriter(logEntry)
	errorWriter := response.NewErrorWriter(logEntry)

	// Create request parser
	requestParser := request.NewParser(logEntry, &config.Config{})

	return encMgr, mockS3Backend, logEntry, xmlWriter, errorWriter, requestParser
}

func TestCreateHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.CreateMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" && aws.ToString(input.Key) == "test-key"
	})).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create test request
	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req.Header.Set("Content-Type", "application/octet-stream")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test-upload-id")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_HandleStandard(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	testData := []byte("test part data for encryption")

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 response for upload part
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id" &&
			aws.ToInt32(input.PartNumber) == 1
	})).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"part-etag-1"`),
	}, nil)

	// Create test request
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id", bytes.NewReader(testData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"part-etag-1"`, w.Header().Get("ETag"))

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 responses
	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.CompleteMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id"
	})).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		ETag:     aws.String(`"complete-etag"`),
		Location: aws.String("http://test-bucket.s3.amazonaws.com/test-key"),
	}, nil)

	// Mock CopyObject for metadata (when finalMetadata is not empty)
	mockS3Backend.On("CopyObject", mock.Anything, mock.MatchedBy(func(input *s3.CopyObjectInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key"
	})).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag: aws.String(`"complete-etag"`),
		},
	}, nil)

	// Create test request body
	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"part-etag-1"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/xml")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "complete-etag")
	assert.Contains(t, w.Body.String(), "test-bucket")
	assert.Contains(t, w.Body.String(), "test-key")
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestAbortHandler_Handle(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewAbortHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response
	mockS3Backend.On("AbortMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.AbortMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id"
	})).Return(&s3.AbortMultipartUploadOutput{}, nil)

	// Create test request
	req := httptest.NewRequest("DELETE", "/test-bucket/test-key?uploadId=test-upload-id", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestUploadHandler_HandleStreaming(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	testData := []byte("test streaming part data for encryption")

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 response for upload part
	mockS3Backend.On("UploadPart", mock.Anything, mock.MatchedBy(func(input *s3.UploadPartInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id" &&
			aws.ToInt32(input.PartNumber) == 1
	})).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"streaming-part-etag-1"`),
	}, nil)

	// Create test request with streaming enabled (larger data triggers streaming)
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload-id", bytes.NewReader(testData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Transfer-Encoding", "chunked") // This triggers streaming path
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler - this should take the streaming path due to Transfer-Encoding
	handler.Handle(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `"streaming-part-etag-1"`, w.Header().Get("ETag"))

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestMultipartHandlers_Integration(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handlers
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	uploadHandler := NewUploadHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)
	completeHandler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	testData := []byte("integration test data for multipart upload")

	// Mock S3 responses for full flow
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("integration-upload-id"),
	}, nil)

	mockS3Backend.On("UploadPart", mock.Anything, mock.Anything).Return(&s3.UploadPartOutput{
		ETag: aws.String(`"integration-part-etag"`),
	}, nil)

	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		ETag:     aws.String(`"integration-complete-etag"`),
		Location: aws.String("http://test-bucket.s3.amazonaws.com/test-key"),
	}, nil)

	mockS3Backend.On("CopyObject", mock.Anything, mock.Anything).Return(&s3.CopyObjectOutput{
		CopyObjectResult: &types.CopyObjectResult{
			ETag: aws.String(`"integration-complete-etag"`),
		},
	}, nil)

	// Step 1: Create multipart upload
	req1 := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	req1.Header.Set("Content-Type", "application/octet-stream")
	req1 = mux.SetURLVars(req1, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w1 := httptest.NewRecorder()
	createHandler.Handle(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)
	assert.Contains(t, w1.Body.String(), "integration-upload-id")

	// Step 2: Upload part
	req2 := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=integration-upload-id", bytes.NewReader(testData))
	req2.Header.Set("Content-Length", fmt.Sprintf("%d", len(testData)))
	req2 = mux.SetURLVars(req2, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w2 := httptest.NewRecorder()
	uploadHandler.Handle(w2, req2)

	assert.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, `"integration-part-etag"`, w2.Header().Get("ETag"))

	// Step 3: Complete multipart upload
	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"integration-part-etag"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req3 := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=integration-upload-id", strings.NewReader(requestBody))
	req3.Header.Set("Content-Type", "application/xml")
	req3 = mux.SetURLVars(req3, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w3 := httptest.NewRecorder()
	completeHandler.Handle(w3, req3)

	assert.Equal(t, http.StatusOK, w3.Code)
	assert.Contains(t, w3.Body.String(), "integration-complete-etag")

	// Verify all mock expectations
	mockS3Backend.AssertExpectations(t)
}

func TestCompleteHandler_Handle_CopyObjectFailure(t *testing.T) {
	encMgr, mockS3Backend, logger, xmlWriter, errorWriter, requestParser := setupMultipartTestEnv(t)

	// Create handler
	handler := NewCompleteHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// First create a multipart upload state by calling the create handler
	createHandler := NewCreateHandler(mockS3Backend, encMgr, logger, xmlWriter, errorWriter, requestParser)

	// Mock S3 response for create multipart upload
	mockS3Backend.On("CreateMultipartUpload", mock.Anything, mock.Anything).Return(&s3.CreateMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		UploadId: aws.String("test-upload-id"),
	}, nil)

	// Create the multipart upload first to set up state
	createReq := httptest.NewRequest("POST", "/test-bucket/test-key?uploads", nil)
	createReq.Header.Set("Content-Type", "application/octet-stream")
	createReq = mux.SetURLVars(createReq, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	createW := httptest.NewRecorder()
	createHandler.Handle(createW, createReq)
	require.Equal(t, http.StatusOK, createW.Code)

	// Mock S3 responses - CompleteMultipartUpload succeeds
	mockS3Backend.On("CompleteMultipartUpload", mock.Anything, mock.MatchedBy(func(input *s3.CompleteMultipartUploadInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key" &&
			aws.ToString(input.UploadId) == "test-upload-id"
	})).Return(&s3.CompleteMultipartUploadOutput{
		Bucket:   aws.String("test-bucket"),
		Key:      aws.String("test-key"),
		ETag:     aws.String(`"complete-etag"`),
		Location: aws.String("http://test-bucket.s3.amazonaws.com/test-key"),
	}, nil)

	// Mock CopyObject for metadata - THIS FAILS (simulating context canceled or other error)
	mockS3Backend.On("CopyObject", mock.Anything, mock.MatchedBy(func(input *s3.CopyObjectInput) bool {
		return aws.ToString(input.Bucket) == "test-bucket" &&
			aws.ToString(input.Key) == "test-key"
	})).Return((*s3.CopyObjectOutput)(nil), fmt.Errorf("context canceled"))

	// Create test request body
	requestBody := `<CompleteMultipartUpload>
		<Part>
			<PartNumber>1</PartNumber>
			<ETag>"part-etag-1"</ETag>
		</Part>
	</CompleteMultipartUpload>`

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploadId=test-upload-id", strings.NewReader(requestBody))
	req.Header.Set("Content-Type", "application/xml")
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	w := httptest.NewRecorder()

	// Execute handler
	handler.Handle(w, req)

	// Verify response - should be an error (HTTP 500) since CopyObject failed
	// The upload should NOT be reported as successful when metadata cannot be added
	assert.Equal(t, http.StatusInternalServerError, w.Code)

	// Should not contain success messages
	assert.NotContains(t, w.Body.String(), "Successfully completed")

	// Should contain error information
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	// Verify mock expectations
	mockS3Backend.AssertExpectations(t)
}
