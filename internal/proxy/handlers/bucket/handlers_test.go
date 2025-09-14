package bucket

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestHandleBucketSubResourceRouting(t *testing.T) {
	tests := []struct {
		name           string
		queryParam     string
		method         string
		body           string
		expectedStatus int
	}{
		{
			name:           "PUT bucket ACL - Mock Response",
			queryParam:     "acl",
			method:         "PUT",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT bucket CORS - Mock Response",
			queryParam:     "cors",
			method:         "PUT",
			body:           "",
			expectedStatus: http.StatusBadRequest, // Empty body will cause BadRequest
		},
		{
			name:           "PUT bucket versioning - Not Implemented",
			queryParam:     "versioning",
			method:         "PUT",
			body:           `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "Unknown sub-resource",
			queryParam:     "unknown",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK, // Falls back to ListObjects
		},
		{
			name:           "Policy operations - GET with Mock",
			queryParam:     "policy",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Policy operations - PUT with Mock",
			queryParam:     "policy",
			method:         "PUT",
			body:           `{"Version": "2012-10-17", "Statement": []}`,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "Policy operations - DELETE with Mock",
			queryParam:     "policy",
			method:         "DELETE",
			body:           "",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "Location operations - GET with Mock",
			queryParam:     "location",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Logging operations - GET with Mock",
			queryParam:     "logging",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Notification operations - Implemented",
			queryParam:     "notification",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Tagging operations - Implemented",
			queryParam:     "tagging",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Lifecycle operations - Implemented",
			queryParam:     "lifecycle",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Replication operations - Implemented",
			queryParam:     "replication",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Website operations - Implemented",
			queryParam:     "website",
			method:         "GET",
			body:           "",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler with minimal setup
			handler := testHandler()

			// Create request with body if provided
			var reqBody io.Reader
			if tt.body != "" {
				reqBody = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, "/test-bucket?"+tt.queryParam, reqBody)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			handler.Handle(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check content type based on operation type
			if tt.expectedStatus == http.StatusNoContent {
				// No content responses may not have content-type header
			} else if tt.expectedStatus == http.StatusOK && tt.queryParam == "cors" && tt.method == "GET" {
				// CORS GET operations should return XML when successful
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
			} else if tt.expectedStatus == http.StatusOK && tt.queryParam == "acl" && tt.method == "PUT" {
				// ACL PUT operations return empty response (no content-type)
				// This is correct behavior
			} else if tt.expectedStatus == http.StatusBadRequest {
				// Bad requests return plain text
				assert.Contains(t, rr.Header().Get("Content-Type"), "text/plain")
			} else if tt.expectedStatus != http.StatusBadRequest {
				// Other operations return XML (except bad requests which return plain text)
				// For not implemented operations, we don't check content type
			}

			// Check content based on status - either mock data or NotImplemented error
			switch tt.expectedStatus {
			case http.StatusNotImplemented:
				assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			case http.StatusOK:
				// For ACL and CORS, should contain mock data, not NotImplemented
				assert.NotContains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			case http.StatusBadRequest:
				// Bad requests don't need specific content checks
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
			handler := testHandler()

			// Skip the uploads test that requires S3 client (tested elsewhere)
			if tt.name == "Uploads query parameter" {
				t.Skip("Skipping uploads test - requires S3 client, tested in multipart handler tests")
				return
			}

			req := httptest.NewRequest(tt.method, tt.url, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.Handle(rr, req)

			// These handlers return NotImplemented for now, but we're testing routing
			// The test passes if the function doesn't panic and returns some response
			switch tt.name {
			case "Policy query parameter":
				// Policy handler is implemented and returns JSON
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
				assert.NotContains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			case "Notification query parameter", "Tagging query parameter", "Lifecycle query parameter", "Replication query parameter", "Website query parameter", "Location query parameter", "Logging query parameter":
				// These are implemented and should return success with XML
				assert.Equal(t, http.StatusOK, rr.Code)
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				assert.NotContains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			default:
				// Other handlers may return NotImplemented
				assert.Equal(t, http.StatusNotImplemented, rr.Code)
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			}
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
		{"BucketCORS PUT", "cors", "PUT", http.StatusBadRequest}, // Empty body causes BadRequest
		{"BucketCORS DELETE", "cors", "DELETE", http.StatusNoContent},
		{"BucketCORS POST", "cors", "POST", http.StatusNotImplemented},

		// Versioning Handler - now returns mock data
		{"BucketVersioning GET", "versioning", "GET", http.StatusOK},
		{"BucketVersioning PUT", "versioning", "PUT", http.StatusOK},
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
			handler := testHandler()

			req := httptest.NewRequest(tt.method, "/test-bucket?"+tt.handler, nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.Handle(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			// Check content type based on operation
			if tt.expectedStatus == http.StatusOK {
				// Some operations like ACL PUT return empty responses without content-type
				if tt.name == "BucketACL PUT" {
					// ACL PUT returns empty response, no content-type expected
					// Do not check content-type for ACL PUT operations
				} else {
					// Other GET operations should return XML
					assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
					assert.NotContains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
				}
			} else if tt.expectedStatus == http.StatusNoContent {
				// No content responses may not have content-type header
			} else if tt.expectedStatus == http.StatusBadRequest {
				// Bad requests return plain text
				assert.Contains(t, rr.Header().Get("Content-Type"), "text/plain")
			} else {
				// For Not Implemented status, should have NotImplemented error
				assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
				assert.Contains(t, rr.Body.String(), "<Code>NotImplemented</Code>")
			}
		})
	}
}

func TestMainBucketHandler_NewHandlers(t *testing.T) {
	// Test that the main bucket handler correctly initializes all new sub-handlers
	mockS3Client := &MockS3Client{}
	logger := logrus.NewEntry(logrus.New())

	handler := NewHandler(mockS3Client, logger, "test-prefix")

	// Verify all handlers are initialized
	assert.NotNil(t, handler.GetVersioningHandler())
	assert.NotNil(t, handler.GetTaggingHandler())
	assert.NotNil(t, handler.GetNotificationHandler())
	assert.NotNil(t, handler.GetLifecycleHandler())
	assert.NotNil(t, handler.GetReplicationHandler())
	assert.NotNil(t, handler.GetWebsiteHandler())
	assert.NotNil(t, handler.GetAccelerateHandler())
	assert.NotNil(t, handler.GetRequestPaymentHandler())
	assert.NotNil(t, handler.GetACLHandler())
	assert.NotNil(t, handler.GetCORSHandler())
	assert.NotNil(t, handler.GetPolicyHandler())
	assert.NotNil(t, handler.GetLocationHandler())
	assert.NotNil(t, handler.GetLoggingHandler())
}
