package utils

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetQueryParam(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string][]string
		key      string
		expected string
	}{
		{
			name: "Existing parameter",
			params: map[string][]string{
				"prefix":   {"test-prefix"},
				"max-keys": {"100"},
			},
			key:      "prefix",
			expected: "test-prefix",
		},
		{
			name: "Non-existing parameter",
			params: map[string][]string{
				"prefix": {"test-prefix"},
			},
			key:      "delimiter",
			expected: "",
		},
		{
			name: "Empty parameter value",
			params: map[string][]string{
				"prefix": {""},
			},
			key:      "prefix",
			expected: "",
		},
		{
			name: "Multiple values (returns first)",
			params: map[string][]string{
				"prefix": {"first", "second"},
			},
			key:      "prefix",
			expected: "first",
		},
		{
			name:     "Empty params map",
			params:   map[string][]string{},
			key:      "prefix",
			expected: "",
		},
		{
			name: "Parameter with empty slice",
			params: map[string][]string{
				"prefix": {},
			},
			key:      "prefix",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetQueryParam(tt.params, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseMaxKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected *int32
	}{
		{
			name:     "Valid positive number",
			input:    "100",
			expected: func() *int32 { v := int32(100); return &v }(),
		},
		{
			name:     "Valid zero",
			input:    "0",
			expected: func() *int32 { v := int32(0); return &v }(),
		},
		{
			name:     "Empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "Invalid number",
			input:    "abc",
			expected: nil,
		},
		{
			name:     "Negative number",
			input:    "-10",
			expected: nil,
		},
		{
			name:     "Float number",
			input:    "10.5",
			expected: nil,
		},
		{
			name:     "Very large number",
			input:    "999999999999999999",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseMaxKeys(tt.input)
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, *tt.expected, *result)
			}
		})
	}
}

func TestWriteNotImplementedResponse(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	w := httptest.NewRecorder()
	operation := "TestOperation"

	WriteNotImplementedResponse(w, logger, operation)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "NotImplemented")
	assert.Contains(t, w.Body.String(), operation)
}

func TestWriteDetailedNotImplementedResponse(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	w := httptest.NewRecorder()

	// Create request with query parameters
	req := httptest.NewRequest("GET", "/bucket/key?acl&versioning", nil)
	operation := "TestDetailedOperation"

	WriteDetailedNotImplementedResponse(w, logger, req, operation)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "NotImplemented")
	assert.Contains(t, w.Body.String(), operation)
	assert.Contains(t, w.Body.String(), "GET")
	assert.Contains(t, w.Body.String(), req.URL.String())
}

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

func TestReadRequestBody(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise during tests

	tests := []struct {
		name        string
		body        string
		expectError bool
		expected    string
	}{
		{
			name:        "Valid request body",
			body:        "test request body content",
			expectError: false,
			expected:    "test request body content",
		},
		{
			name:        "Empty request body",
			body:        "",
			expectError: false,
			expected:    "",
		},
		{
			name:        "JSON request body",
			body:        `{"key": "value", "number": 123}`,
			expectError: false,
			expected:    `{"key": "value", "number": 123}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/test", strings.NewReader(tt.body))
			require.NoError(t, err)

			result, err := ReadRequestBody(req, logger, "test-bucket", "test-key")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []byte(tt.expected), result)
			}
		})
	}
}

func TestReadRequestBody_ErrorReader(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise during tests

	req, err := http.NewRequest("POST", "/test", &errorReader{})
	require.NoError(t, err)

	_, err = ReadRequestBody(req, logger, "test-bucket", "test-key")
	assert.Error(t, err)
}

// errorReader is a helper type that always returns an error when read
type errorReader struct{}

func (e *errorReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("read error")
}
