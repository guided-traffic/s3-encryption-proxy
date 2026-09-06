package root

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHandleListBuckets(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockS3Backend := &MockS3Backend{}
	handler := NewHandler(mockS3Backend, logger)

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
	mockS3Backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(mockResponse, nil)

	// Execute
	handler.HandleListBuckets(w, req)

	// Verify
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "test-bucket")
	mockS3Backend.AssertExpectations(t)
}

// Every backend failure goes through the error mapper, so the client gets the
// status the backend answered with and an S3 <Error> document, not a text/plain 500.
func TestHandleListBucketsError(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	cases := []struct {
		name         string
		backendErr   error
		expectStatus int
		expectCode   string
	}{
		{
			name: "backend AccessDenied keeps its status and code",
			backendErr: &smithy.OperationError{
				ServiceID:     "S3",
				OperationName: "ListBuckets",
				Err: &awshttp.ResponseError{
					ResponseError: &smithyhttp.ResponseError{
						Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}},
						Err:      &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"},
					},
					RequestID: "TESTREQUESTID0001",
				},
			},
			expectStatus: http.StatusForbidden,
			expectCode:   "AccessDenied",
		},
		{
			name:         "internal failure stays an opaque 500",
			backendErr:   assert.AnError,
			expectStatus: http.StatusInternalServerError,
			expectCode:   "InternalError",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockS3Backend := &MockS3Backend{}
			handler := NewHandler(mockS3Backend, logger)

			req := httptest.NewRequest("GET", "/", nil)
			w := httptest.NewRecorder()

			mockS3Backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(nil, tc.backendErr)

			handler.HandleListBuckets(w, req)

			assert.Equal(t, tc.expectStatus, w.Code)
			assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
			assert.Contains(t, w.Body.String(), "<Code>"+tc.expectCode+"</Code>")
			assert.NotContains(t, w.Body.String(), "TESTREQUESTID0001")
			mockS3Backend.AssertExpectations(t)
		})
	}
}

func TestHandleListBucketsMultipleBuckets(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	mockS3Backend := &MockS3Backend{}
	handler := NewHandler(mockS3Backend, logger)

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
	mockS3Backend.On("ListBuckets", req.Context(), &s3.ListBucketsInput{}).Return(mockResponse, nil)

	// Execute
	handler.HandleListBuckets(w, req)

	// Verify
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, "bucket-1")
	assert.Contains(t, responseBody, "bucket-2")
	assert.Contains(t, responseBody, "bucket-3")
	mockS3Backend.AssertExpectations(t)
}

func TestNewHandler(t *testing.T) {
	logger := logrus.New()
	mockS3Backend := &MockS3Backend{}

	handler := NewHandler(mockS3Backend, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockS3Backend, handler.s3Backend)
	assert.Equal(t, logger, handler.logger)
}
