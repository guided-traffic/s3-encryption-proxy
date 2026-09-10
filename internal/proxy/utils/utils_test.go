package utils

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHandleS3Error_Basic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	w := httptest.NewRecorder()
	err := &url.Error{Op: "Get", URL: "http://test", Err: http.ErrServerClosed}

	HandleS3Error(w, logger, err, "Test error", "test-bucket", "test-key")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "InternalError")
}

func TestHandleS3Error_EncryptionKeyMissing(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	w := httptest.NewRecorder()
	err := &url.Error{Op: "Get", URL: "http://test", Err: http.ErrServerClosed}
	err.Err = &url.Error{Op: "encryption", URL: "test", Err: &url.Error{Op: "KEY_MISSING", URL: "test", Err: http.ErrServerClosed}}

	HandleS3Error(w, logger, err, "Encryption key missing", "test-bucket", "test-key")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidRequest")
	assert.Contains(t, w.Body.String(), "Encryption key is missing or invalid")
}
