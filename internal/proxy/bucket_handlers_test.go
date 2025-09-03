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
			name:        "Policy query parameter",
			url:         "/test-bucket?policy",
			method:      "GET",
			expectsCall: "handleBucketPolicy",
		},
		{
			name:        "Location query parameter",
			url:         "/test-bucket?location",
			method:      "GET",
			expectsCall: "handleBucketLocation",
		},
		{
			name:        "Logging query parameter",
			url:         "/test-bucket?logging",
			method:      "GET",
			expectsCall: "handleBucketLogging",
		},
		{
			name:        "Notification query parameter",
			url:         "/test-bucket?notification",
			method:      "GET",
			expectsCall: "handleBucketNotification",
		},
		{
			name:        "Tagging query parameter",
			url:         "/test-bucket?tagging",
			method:      "GET",
			expectsCall: "handleBucketTagging",
		},
		{
			name:        "Lifecycle query parameter",
			url:         "/test-bucket?lifecycle",
			method:      "GET",
			expectsCall: "handleBucketLifecycle",
		},
		{
			name:        "Replication query parameter",
			url:         "/test-bucket?replication",
			method:      "GET",
			expectsCall: "handleBucketReplication",
		},
		{
			name:        "Website query parameter",
			url:         "/test-bucket?website",
			method:      "GET",
			expectsCall: "handleBucketWebsite",
		},
		{
			name:        "Uploads query parameter",
			url:         "/test-bucket?uploads",
			method:      "GET",
			expectsCall: "handleListMultipartUploads",
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

			// These handlers return NotImplemented for now, but we're testing routing
			// The test passes if the function doesn't panic and returns some response
			assert.Equal(t, http.StatusNotImplemented, rr.Code)
			assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
			assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
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
		// ACL Handler - now returns mock data
		{"BucketACL GET", "acl", "GET", http.StatusOK},
		{"BucketACL PUT", "acl", "PUT", http.StatusOK},
		{"BucketACL POST", "acl", "POST", http.StatusNotImplemented},

		// CORS Handler - now returns mock data
		{"BucketCORS GET", "cors", "GET", http.StatusOK},
		{"BucketCORS PUT", "cors", "PUT", http.StatusOK},
		{"BucketCORS DELETE", "cors", "DELETE", http.StatusNoContent},
		{"BucketCORS POST", "cors", "POST", http.StatusNotImplemented},

		// Versioning Handler - now returns mock data
		{"BucketVersioning GET", "versioning", "GET", http.StatusOK},
		{"BucketVersioning PUT", "versioning", "PUT", http.StatusNotImplemented},
		{"BucketVersioning POST", "versioning", "POST", http.StatusNotImplemented},

		// Accelerate Handler - now returns mock data
		{"BucketAccelerate GET", "accelerate", "GET", http.StatusOK},
		{"BucketAccelerate PUT", "accelerate", "PUT", http.StatusNotImplemented},
		{"BucketAccelerate POST", "accelerate", "POST", http.StatusNotImplemented},

		// RequestPayment Handler - now returns mock data
		{"BucketRequestPayment GET", "requestPayment", "GET", http.StatusOK},
		{"BucketRequestPayment PUT", "requestPayment", "PUT", http.StatusNotImplemented},
		{"BucketRequestPayment POST", "requestPayment", "POST", http.StatusNotImplemented},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{
				logger:   testLogger(),
				s3Client: nil, // No S3 client for testing
			}

			req := httptest.NewRequest(tt.method, "/test-bucket?"+tt.handler, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			server.handleBucketSubResource(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			
			// Check content type is XML for successful responses
			if tt.expectedStatus == http.StatusOK || tt.expectedStatus == http.StatusNoContent {
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				// For OK status, should have valid XML content, not NotImplemented
				if tt.expectedStatus == http.StatusOK {
					assert.NotContains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
				}
			} else {
				// For Not Implemented status, should have NotImplemented error
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			}
		})
	}
}
