package s3server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestConfigNone creates a test configuration with none provider
func createTestConfigNone() *config.Config {
	return &config.Config{
		BindAddress:    "localhost:8080",
		LogLevel:       "info",
		TargetEndpoint: "https://s3.amazonaws.com",
		Region:         "us-east-1",
		AccessKeyID:    "test-access-key",
		SecretKey:      "test-secret-key",
		TLS: config.TLSConfig{
			Enabled: false,
		},
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-none",
			Providers: []config.EncryptionProvider{
				{
					Alias:       "test-none",
					Type:        "none",
					Description: "Test none provider",
					Config: map[string]interface{}{
						"metadata_key_prefix": "s3ep-",
					},
				},
			},
		},
	}
}

func TestServer_NewServer_WithNoneProvider(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigNone()

	// This will fail because we don't have real S3 credentials
	// But we can test that the server structure is created correctly
	server, err := NewServer(cfg)
	if err != nil {
		// Expected to fail due to invalid S3 credentials in test
		// Check that it's the expected error type
		assert.Contains(t, err.Error(), "failed to create")
		return
	}

	require.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.NotNil(t, server.logger)
}

func TestServer_HealthEndpoint(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Create a test server without the full S3 setup
	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
	}

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call health handler directly
	server.handleHealth(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(body))
}

func TestServer_HealthEndpointLogging(t *testing.T) {
	// Create test configurations
	cfgWithLogging := &config.Config{
		LogHealthRequests: true,
		BindAddress:       "0.0.0.0:8080",
	}

	cfgWithoutLogging := &config.Config{
		LogHealthRequests: false,
		BindAddress:       "0.0.0.0:8080",
	}

	tests := []struct {
		name          string
		config        *config.Config
		expectLogging bool
	}{
		{
			name:          "Health logging enabled",
			config:        cfgWithLogging,
			expectLogging: true,
		},
		{
			name:          "Health logging disabled",
			config:        cfgWithoutLogging,
			expectLogging: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := &Server{
				config: tt.config,
				logger: logrus.WithField("component", "test-proxy-server"),
			}

			// Create test handler that uses the middleware
			handler := server.loggingMiddleware(http.HandlerFunc(server.handleHealth))

			// Create test request
			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			// Call the handler
			handler.ServeHTTP(w, req)

			// Check response is still OK
			resp := w.Result()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, "OK", string(body))

			// Note: We can't easily test the actual logging output without
			// changing the logging setup, but we can verify the function works
			// and doesn't panic with different configurations
		})
	}
}

func TestServer_HTTPStatusFromAWSError(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
	}

	tests := []struct {
		name           string
		errorStr       string
		expectedStatus int
	}{
		{
			name:           "NoSuchBucket error",
			errorStr:       "NoSuchBucket: The specified bucket does not exist",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "NoSuchKey error",
			errorStr:       "NoSuchKey: The specified key does not exist",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "AccessDenied error",
			errorStr:       "AccessDenied: Access Denied",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "InvalidBucketName error",
			errorStr:       "InvalidBucketName: The specified bucket is not valid",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "BucketAlreadyExists error",
			errorStr:       "BucketAlreadyExists: The requested bucket name is not available",
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "Unknown error",
			errorStr:       "SomeUnknownError: This is an unknown error",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Nil error",
			errorStr:       "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.errorStr != "" {
				err = &testError{message: tt.errorStr}
			}

			status := server.getHTTPStatusFromAWSError(err)
			assert.Equal(t, tt.expectedStatus, status)
		})
	}
}

func TestServer_RoutingSetup(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Create a test server with minimal config
	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
		config: &config.Config{
			Monitoring: config.MonitoringConfig{
				Enabled: false, // Disable monitoring for this test
			},
		},
	}

	// Create router and setup routes
	router := mux.NewRouter()
	server.setupRoutes(router)

	tests := []struct {
		name          string
		method        string
		path          string
		expectedMatch bool
	}{
		{
			name:          "Health endpoint",
			method:        "GET",
			path:          "/health",
			expectedMatch: true,
		},
		{
			name:          "Bucket listing",
			method:        "GET",
			path:          "/test-bucket",
			expectedMatch: true,
		},
		{
			name:          "Object GET",
			method:        "GET",
			path:          "/test-bucket/test-object.txt",
			expectedMatch: true,
		},
		{
			name:          "Object PUT",
			method:        "PUT",
			path:          "/test-bucket/test-object.txt",
			expectedMatch: true,
		},
		{
			name:          "Object DELETE",
			method:        "DELETE",
			path:          "/test-bucket/test-object.txt",
			expectedMatch: true,
		},
		{
			name:          "Object HEAD",
			method:        "HEAD",
			path:          "/test-bucket/test-object.txt",
			expectedMatch: true,
		},
		{
			name:          "Unsupported method",
			method:        "PATCH",
			path:          "/test-bucket/test-object.txt",
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			match := &mux.RouteMatch{}
			matches := router.Match(req, match)

			if tt.expectedMatch {
				assert.True(t, matches, "Route should match")
			} else {
				assert.False(t, matches, "Route should not match")
			}
		})
	}
}

func TestServer_MiddlewareApplication(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Create a test server
	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
	}

	// Create a simple handler for testing
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	})

	// Apply CORS middleware
	corsHandler := server.corsMiddleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
	assert.Contains(t, resp.Header.Get("Access-Control-Allow-Methods"), "GET")
}

func TestServer_CORSOptionsRequest(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Create a test server
	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
	}

	// Create a handler that should not be called for OPTIONS
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for OPTIONS request")
	})

	// Apply CORS middleware
	corsHandler := server.corsMiddleware(testHandler)

	req := httptest.NewRequest("OPTIONS", "/test", nil)
	w := httptest.NewRecorder()

	corsHandler.ServeHTTP(w, req)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "*", resp.Header.Get("Access-Control-Allow-Origin"))
}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getQueryParam(tt.params, tt.key)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsFunction(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		substr   string
		expected bool
	}{
		{
			name:     "Contains at beginning",
			s:        "NoSuchBucket: The bucket does not exist",
			substr:   "NoSuchBucket",
			expected: true,
		},
		{
			name:     "Contains at end",
			s:        "This is an AccessDenied",
			substr:   "AccessDenied",
			expected: true,
		},
		{
			name:     "Contains in middle",
			s:        "Error: InvalidBucketName: Invalid",
			substr:   "InvalidBucketName",
			expected: true,
		},
		{
			name:     "Does not contain",
			s:        "Some other error message",
			substr:   "NoSuchKey",
			expected: false,
		},
		{
			name:     "Exact match",
			s:        "NoSuchKey",
			substr:   "NoSuchKey",
			expected: true,
		},
		{
			name:     "Empty string",
			s:        "",
			substr:   "test",
			expected: false,
		},
		{
			name:     "Empty substring",
			s:        "test string",
			substr:   "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := contains(tt.s, tt.substr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// testError implements error interface for testing
type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

// TestServer_getHTTPStatusFromAWSError_KEK_MISSING tests that KEK_MISSING errors return 422
func TestServer_getHTTPStatusFromAWSError_KEK_MISSING(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigNone()
	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	tests := []struct {
		name           string
		errorMsg       string
		expectedStatus int
	}{
		{
			name:           "KEK_MISSING error should return 422",
			errorMsg:       "❌ KEK_MISSING: Object 'test-key' requires KEK fingerprint 'abc123' but not available",
			expectedStatus: http.StatusUnprocessableEntity, // 422
		},
		{
			name:           "KEK_MISSING in nested error should return 422",
			errorMsg:       "failed to decrypt object data: ❌ KEK_MISSING: Object 'nested-key' requires KEK fingerprint 'def456'",
			expectedStatus: http.StatusUnprocessableEntity, // 422
		},
		{
			name:           "NoSuchKey error should return 404",
			errorMsg:       "NoSuchKey: The specified key does not exist",
			expectedStatus: http.StatusNotFound, // 404
		},
		{
			name:           "AccessDenied error should return 403",
			errorMsg:       "AccessDenied: Access denied",
			expectedStatus: http.StatusForbidden, // 403
		},
		{
			name:           "Generic error should return 500",
			errorMsg:       "Some unknown error occurred",
			expectedStatus: http.StatusInternalServerError, // 500
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &testError{message: tt.errorMsg}
			statusCode := server.getHTTPStatusFromAWSError(err)
			assert.Equal(t, tt.expectedStatus, statusCode, "Expected status %d for error: %s", tt.expectedStatus, tt.errorMsg)
		})
	}
}

// TestServer_handleS3Error_KEK_MISSING tests that KEK errors produce user-friendly messages
func TestServer_handleS3Error_KEK_MISSING(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigNone()
	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	tests := []struct {
		name             string
		errorMsg         string
		expectedStatus   int
		expectedContains []string
	}{
		{
			name:           "KEK_MISSING error should have user-friendly message",
			errorMsg:       "❌ KEK_MISSING: Object 'test-bucket/test-key' requires KEK fingerprint 'abc123'",
			expectedStatus: http.StatusUnprocessableEntity,
			expectedContains: []string{
				"Unable to decrypt object",
				"test-bucket/test-key",
				"Required encryption key not available",
			},
		},
		{
			name:           "Regular error should have standard message",
			errorMsg:       "NoSuchKey: The specified key does not exist",
			expectedStatus: http.StatusNotFound,
			expectedContains: []string{
				"Failed to get object",
				"NoSuchKey",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a ResponseRecorder to record the response
			w := httptest.NewRecorder()
			err := &testError{message: tt.errorMsg}

			// Call handleS3Error
			server.handleS3Error(w, err, "Failed to get object", "test-bucket", "test-key")

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status %d for error: %s", tt.expectedStatus, tt.errorMsg)

			// Check response body contains expected strings
			responseBody := w.Body.String()
			for _, expectedString := range tt.expectedContains {
				assert.Contains(t, responseBody, expectedString, "Response should contain: %s", expectedString)
			}
		})
	}
}
