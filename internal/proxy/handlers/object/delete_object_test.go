package object

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

// MockS3Client for testing DeleteObject
type MockS3Client struct {
	mock.Mock
}

func (m *MockS3Client) DeleteObject(ctx context.Context, params *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*s3.DeleteObjectOutput), args.Error(1)
}

// Add other required interface methods as stubs for testing
func (m *MockS3Client) ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.ListBucketsOutput), args.Error(1)
}

func (m *MockS3Client) CreateBucket(ctx context.Context, params *s3.CreateBucketInput, optFns ...func(*s3.Options)) (*s3.CreateBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CreateBucketOutput), args.Error(1)
}

func (m *MockS3Client) DeleteBucket(ctx context.Context, params *s3.DeleteBucketInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.DeleteBucketOutput), args.Error(1)
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

func (m *MockS3Client) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.HeadObjectOutput), args.Error(1)
}

func (m *MockS3Client) CopyObject(ctx context.Context, params *s3.CopyObjectInput, optFns ...func(*s3.Options)) (*s3.CopyObjectOutput, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(*s3.CopyObjectOutput), args.Error(1)
}

// Add minimal stubs for other required interface methods
func (m *MockS3Client) GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketAcl(ctx context.Context, params *s3.PutBucketAclInput, optFns ...func(*s3.Options)) (*s3.PutBucketAclOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketCors(ctx context.Context, params *s3.GetBucketCorsInput, optFns ...func(*s3.Options)) (*s3.GetBucketCorsOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketCors(ctx context.Context, params *s3.PutBucketCorsInput, optFns ...func(*s3.Options)) (*s3.PutBucketCorsOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteBucketCors(ctx context.Context, params *s3.DeleteBucketCorsInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketCorsOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketVersioning(ctx context.Context, params *s3.GetBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.GetBucketVersioningOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketVersioning(ctx context.Context, params *s3.PutBucketVersioningInput, optFns ...func(*s3.Options)) (*s3.PutBucketVersioningOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketAccelerateConfiguration(ctx context.Context, params *s3.GetBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketAccelerateConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketAccelerateConfiguration(ctx context.Context, params *s3.PutBucketAccelerateConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketAccelerateConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketRequestPayment(ctx context.Context, params *s3.GetBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.GetBucketRequestPaymentOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketRequestPayment(ctx context.Context, params *s3.PutBucketRequestPaymentInput, optFns ...func(*s3.Options)) (*s3.PutBucketRequestPaymentOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketTagging(ctx context.Context, params *s3.GetBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.GetBucketTaggingOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketTagging(ctx context.Context, params *s3.PutBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.PutBucketTaggingOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteBucketTagging(ctx context.Context, params *s3.DeleteBucketTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketTaggingOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketNotificationConfiguration(ctx context.Context, params *s3.GetBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketNotificationConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketNotificationConfiguration(ctx context.Context, params *s3.PutBucketNotificationConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketNotificationConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketLifecycleConfiguration(ctx context.Context, params *s3.GetBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLifecycleConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketLifecycleConfiguration(ctx context.Context, params *s3.PutBucketLifecycleConfigurationInput, optFns ...func(*s3.Options)) (*s3.PutBucketLifecycleConfigurationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteBucketLifecycle(ctx context.Context, params *s3.DeleteBucketLifecycleInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketLifecycleOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketReplication(ctx context.Context, params *s3.GetBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.GetBucketReplicationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketReplication(ctx context.Context, params *s3.PutBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.PutBucketReplicationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteBucketReplication(ctx context.Context, params *s3.DeleteBucketReplicationInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketReplicationOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetBucketWebsite(ctx context.Context, params *s3.GetBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.GetBucketWebsiteOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutBucketWebsite(ctx context.Context, params *s3.PutBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.PutBucketWebsiteOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteBucketWebsite(ctx context.Context, params *s3.DeleteBucketWebsiteInput, optFns ...func(*s3.Options)) (*s3.DeleteBucketWebsiteOutput, error) {
	return nil, nil
}

// Multipart upload operations
func (m *MockS3Client) CreateMultipartUpload(ctx context.Context, params *s3.CreateMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	return nil, nil
}

func (m *MockS3Client) UploadPart(ctx context.Context, params *s3.UploadPartInput, optFns ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	return nil, nil
}

func (m *MockS3Client) CompleteMultipartUpload(ctx context.Context, params *s3.CompleteMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	return nil, nil
}

func (m *MockS3Client) AbortMultipartUpload(ctx context.Context, params *s3.AbortMultipartUploadInput, optFns ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	return nil, nil
}

func (m *MockS3Client) ListParts(ctx context.Context, params *s3.ListPartsInput, optFns ...func(*s3.Options)) (*s3.ListPartsOutput, error) {
	return nil, nil
}

func (m *MockS3Client) ListMultipartUploads(ctx context.Context, params *s3.ListMultipartUploadsInput, optFns ...func(*s3.Options)) (*s3.ListMultipartUploadsOutput, error) {
	return nil, nil
}

// Object ACL and tagging operations
func (m *MockS3Client) GetObjectAcl(ctx context.Context, params *s3.GetObjectAclInput, optFns ...func(*s3.Options)) (*s3.GetObjectAclOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutObjectAcl(ctx context.Context, params *s3.PutObjectAclInput, optFns ...func(*s3.Options)) (*s3.PutObjectAclOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetObjectTagging(ctx context.Context, params *s3.GetObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.GetObjectTaggingOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutObjectTagging(ctx context.Context, params *s3.PutObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.PutObjectTaggingOutput, error) {
	return nil, nil
}

func (m *MockS3Client) DeleteObjectTagging(ctx context.Context, params *s3.DeleteObjectTaggingInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectTaggingOutput, error) {
	return nil, nil
}

// Passthrough operations
func (m *MockS3Client) DeleteObjects(ctx context.Context, params *s3.DeleteObjectsInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectsOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetObjectLegalHold(ctx context.Context, params *s3.GetObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.GetObjectLegalHoldOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutObjectLegalHold(ctx context.Context, params *s3.PutObjectLegalHoldInput, optFns ...func(*s3.Options)) (*s3.PutObjectLegalHoldOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetObjectRetention(ctx context.Context, params *s3.GetObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.GetObjectRetentionOutput, error) {
	return nil, nil
}

func (m *MockS3Client) PutObjectRetention(ctx context.Context, params *s3.PutObjectRetentionInput, optFns ...func(*s3.Options)) (*s3.PutObjectRetentionOutput, error) {
	return nil, nil
}

func (m *MockS3Client) GetObjectTorrent(ctx context.Context, params *s3.GetObjectTorrentInput, optFns ...func(*s3.Options)) (*s3.GetObjectTorrentOutput, error) {
	return nil, nil
}

func (m *MockS3Client) SelectObjectContent(ctx context.Context, params *s3.SelectObjectContentInput, optFns ...func(*s3.Options)) (*s3.SelectObjectContentOutput, error) {
	return nil, nil
}

func TestHandleDeleteObject_Success(t *testing.T) {
	// Setup
	mockS3Client := new(MockS3Client)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Client:    mockS3Client,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations
	expectedDeleteOutput := &s3.DeleteObjectOutput{}
	mockS3Client.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
		return *input.Bucket == "test-bucket" && *input.Key == "test-key"
	})).Return(expectedDeleteOutput, nil)

	// Create request
	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute
	handler.handleDeleteObject(rr, req, "test-bucket", "test-key")

	// Verify
	assert.Equal(t, http.StatusNoContent, rr.Code)
	mockS3Client.AssertExpectations(t)
}

func TestHandleDeleteObject_S3Error(t *testing.T) {
	// Setup
	mockS3Client := new(MockS3Client)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Client:    mockS3Client,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations for S3 error
	mockS3Client.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
		return *input.Bucket == "test-bucket" && *input.Key == "test-key"
	})).Return(nil, assert.AnError)

	// Create request
	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute
	handler.handleDeleteObject(rr, req, "test-bucket", "test-key")

	// Verify error response
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockS3Client.AssertExpectations(t)
}

func TestHandleDeleteObject_InputValidation(t *testing.T) {
	// Setup
	mockS3Client := new(MockS3Client)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Client:    mockS3Client,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	testCases := []struct {
		name           string
		bucket         string
		key            string
		expectS3Call   bool
		expectedStatus int
	}{
		{
			name:           "Valid bucket and key",
			bucket:         "test-bucket",
			key:            "test-key",
			expectS3Call:   true,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "Empty bucket",
			bucket:         "",
			key:            "test-key",
			expectS3Call:   true, // Should still call S3 with empty bucket (S3 will handle validation)
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "Empty key",
			bucket:         "test-bucket",
			key:            "",
			expectS3Call:   true, // Should still call S3 with empty key (S3 will handle validation)
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset mock
			mockS3Client.ExpectedCalls = nil

			if tc.expectS3Call {
				expectedDeleteOutput := &s3.DeleteObjectOutput{}
				mockS3Client.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
					return *input.Bucket == tc.bucket && *input.Key == tc.key
				})).Return(expectedDeleteOutput, nil)
			}

			// Create request
			req := httptest.NewRequest("DELETE", "/"+tc.bucket+"/"+tc.key, nil)
			req = mux.SetURLVars(req, map[string]string{
				"bucket": tc.bucket,
				"key":    tc.key,
			})

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute
			handler.handleDeleteObject(rr, req, tc.bucket, tc.key)

			// Verify
			assert.Equal(t, tc.expectedStatus, rr.Code)
			if tc.expectS3Call {
				mockS3Client.AssertExpectations(t)
			}
		})
	}
}

func TestHandleDeleteObjectIntegration_BaseObjectOperations(t *testing.T) {
	// Setup
	mockS3Client := new(MockS3Client)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Client:    mockS3Client,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations
	expectedDeleteOutput := &s3.DeleteObjectOutput{}
	mockS3Client.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
		return *input.Bucket == "test-bucket" && *input.Key == "test-key"
	})).Return(expectedDeleteOutput, nil)

	// Create DELETE request that would go through handleBaseObjectOperations
	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	req = mux.SetURLVars(req, map[string]string{
		"bucket": "test-bucket",
		"key":    "test-key",
	})

	// Create response recorder
	rr := httptest.NewRecorder()

	// Execute through the base operations handler (simulates real routing)
	handler.handleBaseObjectOperations(rr, req)

	// Verify
	assert.Equal(t, http.StatusNoContent, rr.Code)
	mockS3Client.AssertExpectations(t)
}
