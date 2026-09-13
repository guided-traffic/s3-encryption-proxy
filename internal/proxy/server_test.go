package proxy

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestConfigExit creates a test configuration on the exit provider, which
// needs no license.
func createTestConfigExit() *config.Config {
	return &config.Config{
		BindAddress: "localhost:8080",
		LogLevel:    "info",
		S3Backend: config.S3BackendConfig{
			TargetEndpoint: "https://s3.amazonaws.com",
			Region:         "us-east-1",
			AccessKeyID:    "test-access-key",
			SecretKey:      "test-secret-key",
		},
		S3Clients: []config.S3ClientCredentials{
			{
				Type:        "static",
				AccessKeyID: "testkey123",
				SecretKey:   "testsecret123456",
				Description: "Test credentials",
			},
		},
		TLS: config.TLSConfig{
			Enabled: false,
		},
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-exit",
			Providers: []config.EncryptionProvider{
				{
					Alias:       "test-exit",
					Type:        "exit",
					Description: "Test exit provider",
					Config: map[string]interface{}{
						"metadata_key_prefix": "s3ep-",
					},
				},
			},
		},
	}
}

func TestServer_NewServer_WithExitProvider(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigExit()

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

	// Create a properly initialized test server
	config := createTestConfigExit()
	server, err := NewServer(config)
	require.NoError(t, err)

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call health handler through router
	router := mux.NewRouter()
	server.setupRoutes(router)
	router.ServeHTTP(w, req)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "healthy")
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

			// Create router with middleware and health handler
			router := mux.NewRouter()
			server.setupRoutes(router)
			handler := server.loggingMiddleware(router)

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
			assert.Contains(t, string(body), `"status":"healthy"`)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			// Note: We can't easily test the actual logging output without
			// changing the logging setup, but we can verify the function works
			// and doesn't panic with different configurations
		})
	}
}

// sdkError builds the error chain aws-sdk-go-v2 hands back for a failed
// operation: *smithy.OperationError -> *awshttp.ResponseError -> the typed error.
// A handler only ever sees the outermost value, so the mapper has to unwrap it.
func sdkError(operation string, status int, inner error) error {
	return &smithy.OperationError{
		ServiceID:     "S3",
		OperationName: operation,
		Err: &awshttp.ResponseError{
			ResponseError: &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
				Err:      inner,
			},
			RequestID: "TESTREQUESTID0001",
		},
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
		err            error
		expectedStatus int
		expectedCode   string
		forbidden      string
	}{
		{
			name:           "NoSuchBucket error",
			err:            sdkError("HeadBucket", http.StatusNotFound, &types.NoSuchBucket{Message: aws.String("The specified bucket does not exist")}),
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NoSuchBucket",
		},
		{
			name:           "NoSuchKey error",
			err:            sdkError("GetObject", http.StatusNotFound, &types.NoSuchKey{Message: aws.String("The specified key does not exist")}),
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NoSuchKey",
		},
		{
			name:           "AccessDenied error",
			err:            sdkError("GetObject", http.StatusForbidden, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"}),
			expectedStatus: http.StatusForbidden,
			expectedCode:   "AccessDenied",
		},
		{
			name:           "InvalidBucketName error",
			err:            sdkError("CreateBucket", http.StatusBadRequest, &smithy.GenericAPIError{Code: "InvalidBucketName", Message: "The specified bucket is not valid"}),
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "InvalidBucketName",
		},
		{
			name:           "BucketAlreadyExists error",
			err:            sdkError("CreateBucket", http.StatusConflict, &types.BucketAlreadyExists{}),
			expectedStatus: http.StatusConflict,
			expectedCode:   "BucketAlreadyExists",
		},
		{
			name:           "typed error without a response keeps its code",
			err:            &types.NoSuchUpload{Message: aws.String("The specified upload does not exist")},
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NoSuchUpload",
		},
		{
			name:           "internal error naming an S3 code is not mapped by its text",
			err:            errors.New("failed to load AccessDenied-key.pem for the NoSuchKey provider"),
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "InternalError",
			forbidden:      "AccessDenied",
		},
		{
			name:           "nil error",
			err:            nil,
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "InternalError",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			response.NewErrorWriter(server.logger).WriteS3Error(w, tt.err, "test-bucket", "test-key")

			body := w.Body.String()
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, body, "<Code>"+tt.expectedCode+"</Code>")
			assert.NotContains(t, body, "TESTREQUESTID0001", "backend RequestID must never reach the client")
			if tt.forbidden != "" {
				assert.NotContains(t, body, tt.forbidden, "internal error text must not leak into the response")
			}
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
				// A method no route declares reaches the refusal handler rather
				// than nothing at all, and mux reports that in MatchErr.
				assert.ErrorIs(t, match.MatchErr, mux.ErrMethodMismatch, "no route may carry this method")
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
		config: createTestConfigExit(), // Add configuration to avoid nil pointer
	}

	// Create a simple handler for testing
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		config: createTestConfigExit(), // Add configuration to avoid nil pointer
	}

	// Create a handler that should not be called for OPTIONS
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
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

// TestServer_WriteS3Error_KEK_MISSING tests that KEK_MISSING errors return 422
// and that backend errors keep the status the backend answered with.
func TestServer_WriteS3Error_KEK_MISSING(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigExit()
	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "KEK_MISSING error should return 422",
			err:            errors.New("❌ KEK_MISSING: Object 'test-key' requires KEK fingerprint 'abc123' but not available"),
			expectedStatus: http.StatusUnprocessableEntity, // 422
		},
		{
			name:           "KEK_MISSING in nested error should return 422",
			err:            fmt.Errorf("failed to decrypt object data: %w", errors.New("❌ KEK_MISSING: Object 'nested-key' requires KEK fingerprint 'def456'")),
			expectedStatus: http.StatusUnprocessableEntity, // 422
		},
		{
			name:           "backend NoSuchKey should return 404",
			err:            sdkError("GetObject", http.StatusNotFound, &types.NoSuchKey{Message: aws.String("The specified key does not exist")}),
			expectedStatus: http.StatusNotFound, // 404
		},
		{
			name:           "backend AccessDenied should return 403",
			err:            sdkError("GetObject", http.StatusForbidden, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"}),
			expectedStatus: http.StatusForbidden, // 403
		},
		{
			name:           "internal error should return 500",
			err:            errors.New("some unknown error occurred"),
			expectedStatus: http.StatusInternalServerError, // 500
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			response.NewErrorWriter(server.logger).WriteS3Error(w, tt.err, "test-bucket", "test-key")
			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status %d for error: %v", tt.expectedStatus, tt.err)
		})
	}
}

// TestServer_handleS3Error_KEK_MISSING tests that KEK errors produce user-friendly messages
func TestServer_handleS3Error_KEK_MISSING(t *testing.T) {
	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	cfg := createTestConfigExit()
	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	tests := []struct {
		name             string
		err              error
		expectedStatus   int
		expectedContains []string
		forbiddenStrings []string
	}{
		{
			name:           "KEK_MISSING error should have user-friendly message",
			err:            errors.New("❌ KEK_MISSING: Object 'test-bucket/test-key' requires KEK fingerprint 'abc123'"),
			expectedStatus: http.StatusUnprocessableEntity,
			expectedContains: []string{
				"Unable to decrypt object",
				"test-bucket/test-key",
				"Required encryption key not available",
			},
			forbiddenStrings: []string{"abc123", "fingerprint"},
		},
		{
			name:           "backend error keeps the backend code and message",
			err:            sdkError("GetObject", http.StatusNotFound, &types.NoSuchKey{Message: aws.String("The specified key does not exist")}),
			expectedStatus: http.StatusNotFound,
			expectedContains: []string{
				"NoSuchKey",
				"The specified key does not exist",
			},
			forbiddenStrings: []string{"TESTREQUESTID0001", "operation error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a ResponseRecorder to record the response
			w := httptest.NewRecorder()

			response.NewErrorWriter(server.logger).WriteS3Error(w, tt.err, "test-bucket", "test-key")

			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code, "Expected status %d for error: %v", tt.expectedStatus, tt.err)

			// Check response body contains expected strings
			responseBody := w.Body.String()
			for _, expectedString := range tt.expectedContains {
				assert.Contains(t, responseBody, expectedString, "Response should contain: %s", expectedString)
			}
			for _, forbidden := range tt.forbiddenStrings {
				assert.NotContains(t, responseBody, forbidden, "Response must not contain: %s", forbidden)
			}
		})
	}
}

// routeHandlerName returns the fully qualified function name behind a matched route.
func routeHandlerName(t *testing.T, h http.Handler) string {
	t.Helper()
	require.NotNil(t, h)
	return runtime.FuncForPC(reflect.ValueOf(h).Pointer()).Name()
}

// A part PUT carrying x-amz-copy-source is an UploadPartCopy. It used to be
// swallowed by the UploadPart route, which stored a 0-byte part and answered
// 200 - a silent truncation the running multipart HMAC could not catch, because
// the HMAC covers exactly the bytes that were written.
func TestServer_UploadPartCopyIsNotShadowedByUploadPart(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server := &Server{
		logger: logrus.WithField("component", "test-proxy-server"),
		config: &config.Config{Monitoring: config.MonitoringConfig{Enabled: false}},
	}
	router := mux.NewRouter()
	server.setupRoutes(router)

	copyReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload", nil)
	copyReq.Header.Set("x-amz-copy-source", "/source-bucket/source-key")
	var copyMatch mux.RouteMatch
	require.True(t, router.Match(copyReq, &copyMatch), "UploadPartCopy request must match a route")
	require.NotNil(t, copyMatch.Route)
	// require, not assert: the UploadPart handler would nil-deref the test's
	// nil encryption manager if it were executed below.
	require.Contains(t, routeHandlerName(t, copyMatch.Route.GetHandler()), "multipart.(*CopyHandler).Handle",
		"UploadPartCopy must not be routed to the UploadPart handler")

	// Route.GetHandler bypasses the auth middleware that match.Handler carries,
	// so the request needs no signature.
	w := httptest.NewRecorder()
	copyMatch.Route.GetHandler().ServeHTTP(w, copyReq)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "<Code>NotSupportedWithEncryption</Code>")
	assert.Contains(t, w.Body.String(), "<Resource>UploadPartCopy</Resource>")

	// The same request without the header still reaches the upload handler.
	uploadReq := httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId=test-upload", nil)
	var uploadMatch mux.RouteMatch
	require.True(t, router.Match(uploadReq, &uploadMatch), "UploadPart request must match a route")
	require.NotNil(t, uploadMatch.Route)
	assert.Contains(t, routeHandlerName(t, uploadMatch.Route.GetHandler()), "multipart.(*UploadHandler).Handle")
	assert.Equal(t, "1", uploadMatch.Vars["partNumber"])
	assert.Equal(t, "test-upload", uploadMatch.Vars["uploadId"])
}

// The auth error text carries the access key id the caller attempted. Reflecting
// it broke the XML document and echoed attacker-controlled text back.
func TestServer_AuthErrorDoesNotReflectAttackerText(t *testing.T) {
	logrus.SetLevel(logrus.ErrorLevel)

	server, err := NewServer(createTestConfigExit())
	require.NoError(t, err)

	// No "/" in the key: the credential scope is split on it.
	hostileKey := `AKIA&<Injected>"x"`
	now := time.Now().UTC()

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	req.Header.Set("X-Amz-Date", now.Format("20060102T150405Z"))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+hostileKey+"/"+now.Format("20060102")+
		"/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef")

	w := httptest.NewRecorder()
	server.s3AuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("authentication must not pass")
	})).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "no-cache, no-store, must-revalidate", w.Header().Get("Cache-Control"))

	body := w.Body.String()
	var doc struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
	}
	require.NoError(t, xml.Unmarshal([]byte(body), &doc), "the error document must stay well formed: %s", body)
	assert.Equal(t, "InvalidAccessKeyId", doc.Code)
	assert.NotContains(t, body, "Injected")
	assert.NotContains(t, body, "AKIA")
}

// Every code determineErrorCode can return needs its own wording in
// authErrorMessage. Without an entry the client would get the code of one
// failure and the message of another, since writeS3Error falls back to
// "Access Denied" for anything unmapped.
func TestServer_AuthErrorCodesAllHaveWording(t *testing.T) {
	server := &Server{}

	cases := map[string]string{
		"access key not found: AKIAEXAMPLE":                 "InvalidAccessKeyId",
		"signature verification failed: mismatch":           "SignatureDoesNotMatch",
		"timestamp validation failed: clock skew too large": "RequestTimeTooSkewed",
		"authorization header too large":                    "InvalidRequest",
		"malformed presigned credential: bad scope":         "AuthorizationHeaderMalformed",
		"presigned URL rejected: URL expired at 2026-01-01": "AccessDenied",
	}

	for errText, expectedCode := range cases {
		t.Run(expectedCode, func(t *testing.T) {
			code := server.determineErrorCode(errors.New(errText))
			require.Equal(t, expectedCode, code)
			message, ok := authErrorMessage[code]
			require.True(t, ok, "authErrorMessage has no entry for %q", code)
			assert.NotContains(t, message, "AKIA", "the wording must not echo the request")
		})
	}
}
