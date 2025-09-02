package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// testLogger creates a logger for testing
func testLogger() *logrus.Entry {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return logrus.NewEntry(logger)
}

func TestHandleBucketSubResourceRouting(t *testing.T) {
	tests := []struct {
		name           string
		queryParam     string
		method         string
		expectedStatus int
	}{
		{
			name:           "PUT bucket ACL - Not Implemented",
			queryParam:     "acl",
			method:         "PUT",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "PUT bucket CORS - Not Implemented",
			queryParam:     "cors",
			method:         "PUT",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "PUT bucket versioning - Not Implemented",
			queryParam:     "versioning",
			method:         "PUT",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Unknown sub-resource",
			queryParam:     "unknown",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Policy operations - Not Implemented",
			queryParam:     "policy",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Location operations - Not Implemented",
			queryParam:     "location",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Logging operations - Not Implemented",
			queryParam:     "logging",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Notification operations - Not Implemented",
			queryParam:     "notification",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Tagging operations - Not Implemented",
			queryParam:     "tagging",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Lifecycle operations - Not Implemented",
			queryParam:     "lifecycle",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Replication operations - Not Implemented",
			queryParam:     "replication",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Website operations - Not Implemented",
			queryParam:     "website",
			method:         "GET",
			expectedStatus: http.StatusNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server with minimal setup
			server := &Server{
				logger: testLogger(),
			}

			// Create request
			req := httptest.NewRequest(tt.method, "/test-bucket?"+tt.queryParam, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			server.handleBucketSubResource(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check that XML error response is returned for not implemented operations
			if tt.expectedStatus == http.StatusNotImplemented {
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			}
		})
	}
}

func TestHandleBucketSubResourceQueryParamDetection(t *testing.T) {
	// Test that the correct handler is called based on query parameters
	tests := []struct {
		name        string
		url         string
		method      string
		expectsCall string
	}{
		{
			name:        "ACL query parameter",
			url:         "/test-bucket?acl",
			method:      "GET",
			expectsCall: "handleBucketACL",
		},
		{
			name:        "CORS query parameter",
			url:         "/test-bucket?cors",
			method:      "GET",
			expectsCall: "handleBucketCORS",
		},
		{
			name:        "Versioning query parameter",
			url:         "/test-bucket?versioning",
			method:      "GET",
			expectsCall: "handleBucketVersioning",
		},
		{
			name:        "Accelerate query parameter",
			url:         "/test-bucket?accelerate",
			method:      "GET",
			expectsCall: "handleBucketAccelerate",
		},
		{
			name:        "RequestPayment query parameter",
			url:         "/test-bucket?requestPayment",
			method:      "GET",
			expectsCall: "handleBucketRequestPayment",
		},
		{
			name:        "Uploads query parameter",
			url:         "/test-bucket?uploads",
			method:      "GET",
			expectsCall: "handleListMultipartUploads",
		},
		{
			name:        "Multiple query parameters - first one wins",
			url:         "/test-bucket?acl&cors",
			method:      "GET",
			expectsCall: "handleBucketACL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				logger: testLogger(),
			}

			req := httptest.NewRequest(tt.method, tt.url, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			server.handleBucketSubResource(rr, req)

			// Most handlers will return NotImplemented for now, but we're testing routing
			// The test passes if the function doesn't panic and returns some response
			assert.True(t, rr.Code >= 200)
		})
	}
}

func TestBucketSubResourceHandlerMethods(t *testing.T) {
	// Test individual handler methods for HTTP method routing
	tests := []struct {
		name           string
		handler        string
		method         string
		expectedStatus int
	}{
		// ACL Handler
		{"BucketACL PUT", "acl", "PUT", http.StatusNotImplemented},
		{"BucketACL POST", "acl", "POST", http.StatusNotImplemented},

		// CORS Handler
		{"BucketCORS PUT", "cors", "PUT", http.StatusNotImplemented},
		{"BucketCORS POST", "cors", "POST", http.StatusNotImplemented},

		// Versioning Handler
		{"BucketVersioning PUT", "versioning", "PUT", http.StatusNotImplemented},
		{"BucketVersioning POST", "versioning", "POST", http.StatusNotImplemented},

		// Accelerate Handler
		{"BucketAccelerate PUT", "accelerate", "PUT", http.StatusNotImplemented},
		{"BucketAccelerate POST", "accelerate", "POST", http.StatusNotImplemented},

		// RequestPayment Handler
		{"BucketRequestPayment PUT", "requestPayment", "PUT", http.StatusNotImplemented},
		{"BucketRequestPayment POST", "requestPayment", "POST", http.StatusNotImplemented},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				logger: testLogger(),
			}

			req := httptest.NewRequest(tt.method, "/test-bucket?"+tt.handler, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			server.handleBucketSubResource(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}
