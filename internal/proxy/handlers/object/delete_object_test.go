package object

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
)

func TestHandleDeleteObject_Success(t *testing.T) {
	// Setup
	mockS3Backend := new(MockS3Backend)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Backend:   mockS3Backend,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations
	expectedDeleteOutput := &s3.DeleteObjectOutput{}
	mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
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
	mockS3Backend.AssertExpectations(t)
}

func TestHandleDeleteObject_S3Error(t *testing.T) {
	// Setup
	mockS3Backend := new(MockS3Backend)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Backend:   mockS3Backend,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations for S3 error
	mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
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
	mockS3Backend.AssertExpectations(t)
}

func TestHandleDeleteObject_InputValidation(t *testing.T) {
	// Setup
	mockS3Backend := new(MockS3Backend)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Backend:   mockS3Backend,
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
			mockS3Backend.ExpectedCalls = nil

			if tc.expectS3Call {
				expectedDeleteOutput := &s3.DeleteObjectOutput{}
				mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
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
				mockS3Backend.AssertExpectations(t)
			}
		})
	}
}

func TestHandleDeleteObjectIntegration_BaseObjectOperations(t *testing.T) {
	// Setup
	mockS3Backend := new(MockS3Backend)
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Suppress logs in tests

	handler := &Handler{
		s3Backend:   mockS3Backend,
		logger:      logger.WithField("component", "object-handler"),
		errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
	}

	// Setup expectations
	expectedDeleteOutput := &s3.DeleteObjectOutput{}
	mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
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
	mockS3Backend.AssertExpectations(t)
}

// TestHandleDeleteObject_VersionID pins the version story of DELETE: the request
// must address the version the client named, and the response must say what the
// delete actually did. Without the version id every DELETE on a versioned bucket
// only writes a delete marker and leaves every version behind.
func TestHandleDeleteObject_VersionID(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	t.Run("forwards the requested version", func(t *testing.T) {
		mockS3Backend := new(MockS3Backend)
		handler := &Handler{
			s3Backend:   mockS3Backend,
			logger:      logger.WithField("component", "object-handler"),
			errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
		}

		mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
			return aws.ToString(input.VersionId) == "version-42"
		})).Return(&s3.DeleteObjectOutput{
			VersionId:    aws.String("marker-7"),
			DeleteMarker: aws.Bool(true),
		}, nil)

		req := httptest.NewRequest("DELETE", "/test-bucket/test-key?versionId=version-42", nil)
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})

		rr := httptest.NewRecorder()
		handler.handleDeleteObject(rr, req, "test-bucket", "test-key")

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Equal(t, "marker-7", rr.Header().Get("x-amz-version-id"))
		assert.Equal(t, "true", rr.Header().Get("x-amz-delete-marker"))
		mockS3Backend.AssertExpectations(t)
	})

	t.Run("no version requested, none reported", func(t *testing.T) {
		mockS3Backend := new(MockS3Backend)
		handler := &Handler{
			s3Backend:   mockS3Backend,
			logger:      logger.WithField("component", "object-handler"),
			errorWriter: response.NewErrorWriter(logger.WithField("component", "error-writer")),
		}

		mockS3Backend.On("DeleteObject", mock.Anything, mock.MatchedBy(func(input *s3.DeleteObjectInput) bool {
			return input.VersionId == nil
		})).Return(&s3.DeleteObjectOutput{}, nil)

		req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
		req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-key"})

		rr := httptest.NewRecorder()
		handler.handleDeleteObject(rr, req, "test-bucket", "test-key")

		assert.Equal(t, http.StatusNoContent, rr.Code)
		assert.Empty(t, rr.Header().Get("x-amz-version-id"))
		assert.Empty(t, rr.Header().Get("x-amz-delete-marker"))
		mockS3Backend.AssertExpectations(t)
	})
}
