package object

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHandler_CopyObjectNotSupported(t *testing.T) {
	// Create test logger
	logger := logrus.NewEntry(logrus.New())

	// Create handler with minimal setup
	handler := &Handler{
		logger:      logger,
		errorWriter: response.NewErrorWriter(logger),
	}

	// Create test request with x-amz-copy-source header (CopyObject operation)
	req := httptest.NewRequest("PUT", "/test-bucket/test-key", nil)
	req.Header.Set("x-amz-copy-source", "/source-bucket/source-key")

	// Create response recorder
	w := httptest.NewRecorder()

	// Call the handler method directly
	handler.handlePutObject(w, req, "test-bucket", "test-key")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "Expected 422 status for unsupported CopyObject")

	// Check content type
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Check response body
	body := w.Body.String()
	assert.Contains(t, body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, body, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, body, "CopyObject operation is not supported when encryption is enabled")
	assert.Contains(t, body, "Encrypted objects cannot use S3 server-side copy functionality")
	assert.Contains(t, body, "<Resource>CopyObject</Resource>")
}

func TestHandler_CopyObjectHeaderDetection(t *testing.T) {
	tests := []struct {
		name       string
		copyHeader string
	}{
		{
			name:       "Copy source header triggers error",
			copyHeader: "/source-bucket/source-key",
		},
		{
			name:       "Copy source header with URL encoding triggers error",
			copyHeader: "/source-bucket/source%20key%20with%20spaces",
		},
		{
			name:       "Copy source header with complex path",
			copyHeader: "/my-bucket/path/to/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test logger
			logger := logrus.NewEntry(logrus.New())

			// Create handler with minimal setup
			handler := &Handler{
				logger:      logger,
				errorWriter: response.NewErrorWriter(logger),
			}

			// Create test request with copy source header
			req := httptest.NewRequest("PUT", "/test-bucket/test-key", nil)
			req.Header.Set("x-amz-copy-source", tt.copyHeader)

			// Create response recorder
			w := httptest.NewRecorder()

			// Call the handler method directly
			handler.handlePutObject(w, req, "test-bucket", "test-key")

			// Should always return copy error for any non-empty copy source header
			assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "Expected copy error for test: %s", tt.name)
			assert.Contains(t, w.Body.String(), "NotSupportedWithEncryption", "Expected copy error message for test: %s", tt.name)
			assert.Contains(t, w.Body.String(), "CopyObject operation is not supported", "Expected copy error message for test: %s", tt.name)
		})
	}
}
