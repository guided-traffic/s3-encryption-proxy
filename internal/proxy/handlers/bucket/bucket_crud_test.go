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

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func TestHandleCreateBucket(t *testing.T) {
	tests := []struct {
		name           string
		bucketName     string
		requestBody    string
		contentType    string
		headers        map[string]string
		expectedStatus int
		mockSetup      func(*MockS3Backend)
		expectedError  bool
	}{
		{
			name:           "Create bucket successfully",
			bucketName:     "test-bucket",
			requestBody:    "",
			expectedStatus: http.StatusOK,
			mockSetup: func(mockClient *MockS3Backend) {
				mockClient.On("CreateBucket", mock.Anything, mock.AnythingOfType("*s3.CreateBucketInput"), mock.Anything).
					Return(&s3.CreateBucketOutput{
						Location: aws.String("/test-bucket"),
					}, nil)
			},
		},
		{
			name:           "Create bucket with location constraint",
			bucketName:     "test-bucket-eu",
			requestBody:    `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`,
			contentType:    "application/xml",
			expectedStatus: http.StatusOK,
			mockSetup: func(mockClient *MockS3Backend) {
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
			mockSetup: func(mockClient *MockS3Backend) {
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
			mockSetup: func(mockClient *MockS3Backend) {
				mockClient.On("CreateBucket", mock.Anything, mock.AnythingOfType("*s3.CreateBucketInput"), mock.Anything).
					Return(nil, &s3types.BucketAlreadyExists{})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockClient := &MockS3Backend{}
			tt.mockSetup(mockClient)

			// Create handler
			logger := logrus.NewEntry(logrus.New())
			handler := NewHandler(mockClient, nil, logger, &config.Config{})

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
		mockSetup      func(*MockS3Backend)
		expectedError  bool
	}{
		{
			name:           "Delete bucket successfully",
			bucketName:     "test-bucket",
			expectedStatus: http.StatusNoContent,
			mockSetup: func(mockClient *MockS3Backend) {
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
			mockSetup: func(mockClient *MockS3Backend) {
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
			mockSetup: func(mockClient *MockS3Backend) {
				mockClient.On("DeleteBucket", mock.Anything, mock.AnythingOfType("*s3.DeleteBucketInput"), mock.Anything).
					Return(nil, &s3types.NoSuchBucket{})
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockClient := &MockS3Backend{}
			tt.mockSetup(mockClient)

			// Create handler
			logger := logrus.NewEntry(logrus.New())
			handler := NewHandler(mockClient, nil, logger, &config.Config{})

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

// TestBucketHandle_UnroutedSubResourceIsNotABaseOperation guards the routing
// defect where a bucket sub-resource without its own route in router.go fell
// through to the base operation of its HTTP method, so DELETE /bucket?encryption
// ran DeleteBucket and the bucket was gone.
func TestBucketHandle_UnroutedSubResourceIsNotABaseOperation(t *testing.T) {
	tests := []struct {
		name   string
		method string
		url    string
	}{
		{
			name:   "DELETE ?encryption must not delete the bucket",
			method: http.MethodDelete,
			url:    "/test-bucket?encryption",
		},
		{
			name:   "PUT ?encryption must not create the bucket",
			method: http.MethodPut,
			url:    "/test-bucket?encryption",
		},
		{
			name:   "GET ?versions must not answer with a current-object listing",
			method: http.MethodGet,
			url:    "/test-bucket?versions",
		},
		{
			name:   "GET ?encryption must not answer with a current-object listing",
			method: http.MethodGet,
			url:    "/test-bucket?encryption",
		},
		{
			name:   "DELETE ?publicAccessBlock must not delete the bucket",
			method: http.MethodDelete,
			url:    "/test-bucket?publicAccessBlock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockS3Backend{}
			// Registered so that a fall-through succeeds instead of panicking on a
			// missing expectation: the assertions below are what must report it.
			mockClient.On("DeleteBucket", mock.Anything, mock.Anything).
				Return(&s3.DeleteBucketOutput{}, nil).Maybe()
			mockClient.On("CreateBucket", mock.Anything, mock.Anything).
				Return(&s3.CreateBucketOutput{}, nil).Maybe()
			mockClient.On("ListObjectsV2", mock.Anything, mock.Anything).
				Return(&s3.ListObjectsV2Output{}, nil).Maybe()
			mockClient.On("ListObjects", mock.Anything, mock.Anything).
				Return(&s3.ListObjectsOutput{}, nil).Maybe()

			logger := logrus.NewEntry(logrus.New())
			handler := NewHandler(mockClient, nil, logger, &config.Config{})

			req := httptest.NewRequest(tt.method, tt.url, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()

			handler.Handle(w, req)

			assert.Equal(t, http.StatusNotImplemented, w.Code)
			mockClient.AssertNotCalled(t, "DeleteBucket", mock.Anything, mock.Anything)
			mockClient.AssertNotCalled(t, "CreateBucket", mock.Anything, mock.Anything)
			mockClient.AssertNotCalled(t, "ListObjectsV2", mock.Anything, mock.Anything)
			mockClient.AssertNotCalled(t, "ListObjects", mock.Anything, mock.Anything)
		})
	}
}

// TestBucketHandle_BaseOperationsStillReachTheBackend is the guard in the other
// direction: the allowlist must not turn a normal listing or a bucket delete
// into NotImplemented.
func TestBucketHandle_BaseOperationsStillReachTheBackend(t *testing.T) {
	t.Run("ListObjectsV2 with prefix and the SDK x-id marker", func(t *testing.T) {
		mockClient := &MockS3Backend{}
		mockClient.On("ListObjectsV2", mock.Anything, mock.MatchedBy(func(input *s3.ListObjectsV2Input) bool {
			return aws.ToString(input.Bucket) == "test-bucket" && aws.ToString(input.Prefix) == "p"
		})).Return(&s3.ListObjectsV2Output{}, nil)

		logger := logrus.NewEntry(logrus.New())
		handler := NewHandler(mockClient, nil, logger, &config.Config{})

		req := httptest.NewRequest(http.MethodGet, "/test-bucket?list-type=2&prefix=p&x-id=ListObjectsV2", nil)
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
		w := httptest.NewRecorder()

		handler.Handle(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockClient.AssertExpectations(t)
	})

	t.Run("plain DELETE still deletes the bucket", func(t *testing.T) {
		mockClient := &MockS3Backend{}
		mockClient.On("DeleteBucket", mock.Anything, mock.MatchedBy(func(input *s3.DeleteBucketInput) bool {
			return aws.ToString(input.Bucket) == "test-bucket"
		})).Return(&s3.DeleteBucketOutput{}, nil)

		logger := logrus.NewEntry(logrus.New())
		handler := NewHandler(mockClient, nil, logger, &config.Config{})

		req := httptest.NewRequest(http.MethodDelete, "/test-bucket", nil)
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
		w := httptest.NewRecorder()

		handler.Handle(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		mockClient.AssertExpectations(t)
	})
}

// TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed pins the two-stage
// order in Handle: a sub-resource that has its own route in router.go answers
// 405 for an unsupported method, and it keeps doing so when an unimplemented
// parameter rides along. Both checks run over a map, whose iteration order is
// random, so merging the two loops would make the status code flip between
// runs.
func TestBucketHandle_KnownSubResourceKeepsMethodNotAllowed(t *testing.T) {
	for _, url := range []string{"/test-bucket?acl", "/test-bucket?acl&encryption"} {
		t.Run(url, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				mockClient := &MockS3Backend{}
				logger := logrus.NewEntry(logrus.New())
				handler := NewHandler(mockClient, nil, logger, &config.Config{})

				req := httptest.NewRequest(http.MethodDelete, url, nil)
				req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
				w := httptest.NewRecorder()

				handler.Handle(w, req)

				assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
				mockClient.AssertNotCalled(t, "DeleteBucket", mock.Anything, mock.Anything)
			}
		})
	}
}
