package response

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestErrorWriter_WriteNotSupportedWithEncryption(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method
	errorWriter.WriteNotSupportedWithEncryption(w, "TestOperation")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check content type
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Check response body
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, bodyStr, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, bodyStr, "<Message>TestOperation operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "Encrypted objects cannot use S3 server-side copy functionality")
	assert.Contains(t, bodyStr, "<Resource>TestOperation</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_CopyObject(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method for CopyObject operation
	errorWriter.WriteNotSupportedWithEncryption(w, "CopyObject")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check response body contains the right operation name
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "CopyObject operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "<Resource>CopyObject</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_UploadPartCopy(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method for UploadPartCopy operation
	errorWriter.WriteNotSupportedWithEncryption(w, "UploadPartCopy")

	// Check status code
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	// Check response body contains the right operation name
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)
	assert.Contains(t, bodyStr, "UploadPartCopy operation is not supported when encryption is enabled")
	assert.Contains(t, bodyStr, "<Resource>UploadPartCopy</Resource>")
}

func TestErrorWriter_WriteNotSupportedWithEncryption_XMLFormat(t *testing.T) {
	// Create a test logger
	logger := logrus.NewEntry(logrus.New())

	// Create error writer
	errorWriter := NewErrorWriter(logger)

	// Create test HTTP response writer
	w := httptest.NewRecorder()

	// Call the method
	errorWriter.WriteNotSupportedWithEncryption(w, "TestOp")

	// Check that XML is properly formatted
	body, err := io.ReadAll(w.Body)
	assert.NoError(t, err)

	bodyStr := string(body)

	// Verify XML structure
	assert.True(t, strings.HasPrefix(bodyStr, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"))
	assert.Contains(t, bodyStr, "<Error>")
	assert.Contains(t, bodyStr, "</Error>")
	assert.Contains(t, bodyStr, "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, bodyStr, "<Message>")
	assert.Contains(t, bodyStr, "</Message>")
	assert.Contains(t, bodyStr, "<Resource>TestOp</Resource>")
}
