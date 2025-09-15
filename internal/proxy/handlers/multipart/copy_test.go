package multipart

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCopyHandler_NotSupportedWithEncryption(t *testing.T) {
	// Create test logger
	logger := logrus.NewEntry(logrus.New())

	// Create copy handler with minimal setup
	handler := &CopyHandler{
		logger:      logger,
		errorWriter: response.NewErrorWriter(logger),
	}

	// Create test request
	req := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload", nil)
	req.Header.Set("x-amz-copy-source", "/source-bucket/source-key")

	// Create response recorder
	w := httptest.NewRecorder()

	// Call the handler
	handler.Handle(w, req)

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code, "Expected 422 status for unsupported UploadPartCopy")

	// Check content type
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Check response body
	body := w.Body.String()
	assert.Contains(t, body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, body, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, body, "UploadPartCopy operation is not supported when encryption is enabled")
	assert.Contains(t, body, "Encrypted objects cannot use S3 server-side copy functionality")
	assert.Contains(t, body, "<Resource>UploadPartCopy</Resource>")
}
