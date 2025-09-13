package bucket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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
		expectedBody   string
	}{
		{
			name:           "GET bucket versioning - success",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketVersioning", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketVersioningInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketVersioningOutput{
					Status: types.BucketVersioningStatusEnabled,
				}, nil)
			},
			expectedBody: "Enabled",
		},
		{
			name:           "GET bucket versioning - suspended",
			method:         "GET",
			bucket:         "test-bucket",
			expectedStatus: http.StatusOK,
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketVersioning", mock.Anything, mock.MatchedBy(func(input *s3.GetBucketVersioningInput) bool {
					return *input.Bucket == "test-bucket"
				})).Return(&s3.GetBucketVersioningOutput{
					Status: types.BucketVersioningStatusSuspended,
				}, nil)
			},
			expectedBody: "Suspended",
		},
		{
			name:           "PUT bucket versioning - not implemented",
			method:         "PUT",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not implemented
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "POST bucket versioning - not supported",
			method:         "POST",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not supported method
			},
			expectedBody: "not yet implemented",
		},
		{
			name:           "DELETE bucket versioning - not supported",
			method:         "DELETE",
			bucket:         "test-bucket",
			expectedStatus: http.StatusNotImplemented,
			setupMock: func(m *MockS3Client) {
				// No setup needed for not supported method
			},
			expectedBody: "not yet implemented",
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
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestVersioningHandler_HandleErrors(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*MockS3Client)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "GET versioning - S3 error",
			setupMock: func(m *MockS3Client) {
				m.On("GetBucketVersioning", mock.Anything, mock.Anything).Return(
					(*s3.GetBucketVersioningOutput)(nil),
					&types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")},
				)
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "NoSuchBucket",
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
			req := httptest.NewRequest("GET", "/test-bucket?versioning", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedError != "" {
				assert.Contains(t, w.Body.String(), tt.expectedError)
			}
			mockS3Client.AssertExpectations(t)
		})
	}
}

func TestVersioningHandler_MFAValidation(t *testing.T) {
	tests := []struct {
		name          string
		mfaHeader     string
		expectedValid bool
	}{
		{
			name:          "Valid MFA header",
			mfaHeader:     "123456789012 123456",
			expectedValid: true,
		},
		{
			name:          "Empty MFA header",
			mfaHeader:     "",
			expectedValid: true, // Empty is allowed
		},
		{
			name:          "Invalid MFA format - no space",
			mfaHeader:     "123456789012123456",
			expectedValid: false,
		},
		{
			name:          "Invalid MFA format - too short",
			mfaHeader:     "123 456",
			expectedValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create versioning handler
			handler := NewVersioningHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request with MFA header
			req := httptest.NewRequest("PUT", "/test-bucket?versioning", strings.NewReader(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			if tt.mfaHeader != "" {
				req.Header.Set("x-amz-mfa", tt.mfaHeader)
			}

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// For now, all PUT operations return not implemented
			// This test prepares for future MFA validation implementation
			assert.Equal(t, http.StatusNotImplemented, w.Code)
		})
	}
}

func TestVersioningHandler_XMLParsing(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name:           "Valid versioning configuration - Enabled",
			body:           `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard enable versioning request",
		},
		{
			name:           "Valid versioning configuration - Suspended",
			body:           `<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Standard suspend versioning request",
		},
		{
			name:           "Invalid XML format",
			body:           `<VersioningConfiguration><Status>Enabled</Status>`, // Missing closing tag
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Malformed XML should be rejected when implemented",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Empty body should be rejected when implemented",
		},
		{
			name:           "Invalid status value",
			body:           `<VersioningConfiguration><Status>Invalid</Status></VersioningConfiguration>`,
			expectedStatus: http.StatusNotImplemented, // PUT not implemented yet
			description:    "Invalid status should be rejected when implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock S3 client
			mockS3Client := &MockS3Client{}

			// Create logger
			logger := logrus.NewEntry(logrus.New())

			// Create response writers
			xmlWriter := response.NewXMLWriter(logger)
			errorWriter := response.NewErrorWriter(logger)

			// Create versioning handler
			handler := NewVersioningHandler(mockS3Client, logger, xmlWriter, errorWriter, nil)

			// Setup request
			req := httptest.NewRequest("PUT", "/test-bucket?versioning", strings.NewReader(tt.body))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			req.Header.Set("Content-Type", "application/xml")

			// Setup response recorder
			w := httptest.NewRecorder()

			// Execute
			handler.Handle(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code, tt.description)
		})
	}
}
