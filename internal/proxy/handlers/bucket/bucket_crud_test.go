package bucket

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleCreateBucket(t *testing.T) {
	tests := []struct {
		name           string
		bucketName     string
		requestBody    string
		contentType    string
		headers        map[string]string
		expectedStatus int
		mockSetup      func(*MockS3Client)
		expectedError  bool
	}{
		{
			name:           "Create bucket successfully",
			bucketName:     "test-bucket",
			requestBody:    "",
			expectedStatus: http.StatusOK,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("CreateBucket", mock.Anything, mock.AnythingOfType("*s3.CreateBucketInput"), mock.Anything).
					Return(&s3.CreateBucketOutput{
						Location: aws.String("/test-bucket"),
					}, nil)
			},
		},
		{
			name:        "Create bucket with location constraint",
			bucketName:  "test-bucket-eu",
			requestBody: `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`,
			contentType: "application/xml",
			expectedStatus: http.StatusOK,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("CreateBucket", mock.Anything, mock.MatchedBy(func(input *s3.CreateBucketInput) bool {
					return aws.ToString(input.Bucket) == "test-bucket-eu" &&
						input.CreateBucketConfiguration != nil &&
						string(input.CreateBucketConfiguration.LocationConstraint) == "eu-west-1"
				}), mock.Anything).
					Return(&s3.CreateBucketOutput{
						Location: aws.String("/test-bucket-eu"),
					}, nil)
			},
		},
		{
			name:       "Create bucket with ACL header",
			bucketName: "test-bucket-acl",
			headers: map[string]string{
				"x-amz-acl": "public-read",
			},
			expectedStatus: http.StatusOK,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("CreateBucket", mock.Anything, mock.MatchedBy(func(input *s3.CreateBucketInput) bool {
					return aws.ToString(input.Bucket) == "test-bucket-acl" &&
						string(input.ACL) == "public-read"
				}), mock.Anything).
					Return(&s3.CreateBucketOutput{
						Location: aws.String("/test-bucket-acl"),
					}, nil)
			},
		},
		{
			name:           "Create bucket - bucket already exists",
			bucketName:     "existing-bucket",
			expectedStatus: http.StatusConflict,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("CreateBucket", mock.Anything, mock.AnythingOfType("*s3.CreateBucketInput"), mock.Anything).
					Return(nil, &s3types.BucketAlreadyExists{})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockClient := &MockS3Client{}
			tt.mockSetup(mockClient)

			// Create handler
			logger := logrus.NewEntry(logrus.New())
			handler := NewHandler(mockClient, logger, "x-amz-meta-")

			// Create request
			var body *bytes.Buffer
			if tt.requestBody != "" {
				body = bytes.NewBufferString(tt.requestBody)
			} else {
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest(http.MethodPut, "/"+tt.bucketName, body)
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			// Set custom headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add bucket to mux vars
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucketName})

			// Create response recorder
			w := httptest.NewRecorder()

			// Call the handler
			handler.handleCreateBucket(w, req, tt.bucketName)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			if !tt.expectedError {
				// Check Content-Type header if success
				if w.Code == http.StatusOK {
					assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
				}
			}

			// Verify all expectations were met
			mockClient.AssertExpectations(t)
		})
	}
}

func TestHandleDeleteBucket(t *testing.T) {
	tests := []struct {
		name           string
		bucketName     string
		headers        map[string]string
		expectedStatus int
		mockSetup      func(*MockS3Client)
		expectedError  bool
	}{
		{
			name:           "Delete bucket successfully",
			bucketName:     "test-bucket",
			expectedStatus: http.StatusNoContent,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("DeleteBucket", mock.Anything, mock.AnythingOfType("*s3.DeleteBucketInput"), mock.Anything).
					Return(&s3.DeleteBucketOutput{}, nil)
			},
		},
		{
			name:       "Delete bucket with expected bucket owner",
			bucketName: "test-bucket-owner",
			headers: map[string]string{
				"x-amz-expected-bucket-owner": "123456789012",
			},
			expectedStatus: http.StatusNoContent,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("DeleteBucket", mock.Anything, mock.MatchedBy(func(input *s3.DeleteBucketInput) bool {
					return aws.ToString(input.Bucket) == "test-bucket-owner" &&
						aws.ToString(input.ExpectedBucketOwner) == "123456789012"
				}), mock.Anything).
					Return(&s3.DeleteBucketOutput{}, nil)
			},
		},
		{
			name:           "Delete bucket - bucket not found",
			bucketName:     "nonexistent-bucket",
			expectedStatus: http.StatusNotFound,
			mockSetup: func(mockClient *MockS3Client) {
				mockClient.On("DeleteBucket", mock.Anything, mock.AnythingOfType("*s3.DeleteBucketInput"), mock.Anything).
					Return(nil, &s3types.NoSuchBucket{})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockClient := &MockS3Client{}
			tt.mockSetup(mockClient)

			// Create handler
			logger := logrus.NewEntry(logrus.New())
			handler := NewHandler(mockClient, logger, "x-amz-meta-")

			// Create request
			req := httptest.NewRequest(http.MethodDelete, "/"+tt.bucketName, nil)

			// Set custom headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Add bucket to mux vars
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucketName})

			// Create response recorder
			w := httptest.NewRecorder()

			// Call the handler
			handler.handleDeleteBucket(w, req, tt.bucketName)

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Verify all expectations were met
			mockClient.AssertExpectations(t)
		})
	}
}
