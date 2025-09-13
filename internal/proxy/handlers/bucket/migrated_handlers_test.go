package bucket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestVersioningHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
	}{
		{
			name:           "GET bucket versioning - success",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketVersioning", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketVersioningInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketVersioningOutput{}, nil)
			},
		},
		{
			name:           "PUT bucket versioning - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
		},
		{
			name:           "POST bucket versioning - not supported",
			method:         "POST",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not supported method
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create versioning handler
			handler := NewVersioningHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?versioning", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestTaggingHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
	}{
		{
			name:           "GET bucket tagging - success",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketTaggingOutput{}, nil)
			},
		},
		{
			name:           "PUT bucket tagging - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
		},
		{
			name:           "DELETE bucket tagging - success",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("DeleteBucketTagging", mock.Anything, mock.MatchedBy(func(input *s3.DeleteBucketTaggingInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.DeleteBucketTaggingOutput{}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create tagging handler
			handler := NewTaggingHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?tagging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestNotificationHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
	}{
		{
			name:           "GET bucket notification - success",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketNotificationConfiguration", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketNotificationConfigurationInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketNotificationConfigurationOutput{}, nil)
			},
		},
		{
			name:           "PUT bucket notification - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create notification handler
			handler := NewNotificationHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?notification", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestLifecycleHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		bucket         string
		expectedStatus int
		setupMock      func(*MockS3Client)
	}{
		{
			name:           "GET bucket lifecycle - success",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketLifecycleConfiguration", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketLifecycleConfigurationInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketLifecycleConfigurationOutput{}, nil)
			},
		},
		{
			name:           "PUT bucket lifecycle - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
		},
		{
			name:           "DELETE bucket lifecycle - success",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("DeleteBucketLifecycle", mock.Anything, mock.MatchedBy(func(input *s3.DeleteBucketLifecycleInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.DeleteBucketLifecycleOutput{}, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}
			tt.setupMock(mockS3Client)

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create lifecycle handler
			handler := NewLifecycleHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest(tt.method, "/"+tt.bucket+"?lifecycle", strings.NewReader(""))
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestMainBucketHandler_NewHandlers(t *testing.T) {
	// Test that the main bucket handler correctly initializes all new sub-handlers
	mockS3Client := &MockS3Client{}
	logger := logrus.NewEntry(logrus.New())

	handler := NewHandler(mockS3Client, logger, "test-prefix")

	// Verify all handlers are initialized
	assert.NotNil(t, handler.GetVersioningHandler())
	assert.NotNil(t, handler.GetTaggingHandler())
	assert.NotNil(t, handler.GetNotificationHandler())
	assert.NotNil(t, handler.GetLifecycleHandler())
	assert.NotNil(t, handler.GetReplicationHandler())
	assert.NotNil(t, handler.GetWebsiteHandler())
	assert.NotNil(t, handler.GetAccelerateHandler())
	assert.NotNil(t, handler.GetRequestPaymentHandler())
}
