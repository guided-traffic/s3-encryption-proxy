package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewS3Handlers(t *testing.T) {
	_, router := setupHandlerTestServer(t)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Bucket ACL GET",
			method:         "GET",
			path:           "/test-bucket?acl",
			expectedStatus: http.StatusOK,
			expectedBody:   "AccessControlPolicy",
		},
		{
			name:           "Bucket CORS",
			method:         "GET",
			path:           "/test-bucket?cors",
			expectedStatus: http.StatusOK,
			expectedBody:   "CORSConfiguration",
		},
		{
			name:           "Bucket Versioning",
			method:         "GET",
			path:           "/test-bucket?versioning",
			expectedStatus: http.StatusOK,
			expectedBody:   "VersioningConfiguration",
		},
		{
			name:           "Bucket Policy",
			method:         "GET",
			path:           "/test-bucket?policy",
			expectedStatus: http.StatusOK,
			expectedBody:   "MockPolicyStatement",
		},
		{
			name:           "Object ACL",
			method:         "GET",
			path:           "/test-bucket/test-key?acl",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "ObjectACL",
		},
		{
			name:           "Object Tagging",
			method:         "GET",
			path:           "/test-bucket/test-key?tagging",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "ObjectTagging",
		},
		{
			name:           "Create Multipart Upload",
			method:         "POST",
			path:           "/test-bucket/test-key?uploads",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "CreateMultipartUpload",
		},
		{
			name:           "Copy Object",
			method:         "PUT",
			path:           "/test-bucket/test-key",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "CopyObject",
		},
		{
			name:           "Delete Objects",
			method:         "POST",
			path:           "/test-bucket?delete",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "DeleteObjects",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			require.NoError(t, err)

			// Add copy source header for copy object test
			if tt.name == "Copy Object" {
				req.Header.Set("x-amz-copy-source", "/source-bucket/source-key")
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tt.expectedBody)
			}
		})
	}
}
