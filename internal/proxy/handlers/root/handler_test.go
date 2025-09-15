package root

import (
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

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
