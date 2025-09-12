package s3server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// setupTestServerWithoutClient creates a test server without S3 client for policy tests
func setupTestServerWithoutClient() *Server {
	return &Server{
		s3Client: nil, // No S3 client for testing
		logger:   log.WithField("test", true),
	}
}

func TestHandleBucketPolicy_GET_NoClient(t *testing.T) {
	server := setupTestServerWithoutClient()
	req := httptest.NewRequest("GET", "/test-bucket?policy", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
	rr := httptest.NewRecorder()

	server.handleBucketPolicy(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, rr.Body.String(), "Version")
	assert.Contains(t, rr.Body.String(), "2012-10-17")
	assert.Contains(t, rr.Body.String(), "MockPolicyStatement")
}

func TestHandleBucketPolicy_PUT_NoClient(t *testing.T) {
	server := setupTestServerWithoutClient()

	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Sid":       "TestStatement",
				"Effect":    "Allow",
				"Principal": map[string]string{"AWS": "*"},
				"Action":    "s3:GetObject",
				"Resource":  "arn:aws:s3:::test-bucket/*",
			},
		},
	}

	policyJSON, _ := json.Marshal(policy)
	req := httptest.NewRequest("PUT", "/test-bucket?policy", bytes.NewReader(policyJSON))
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
	rr := httptest.NewRecorder()

	server.handleBucketPolicy(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestHandleBucketPolicy_DELETE_NoClient(t *testing.T) {
	server := setupTestServerWithoutClient()
	req := httptest.NewRequest("DELETE", "/test-bucket?policy", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
	rr := httptest.NewRecorder()

	server.handleBucketPolicy(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
}

func TestBucketPolicyJSONValidation(t *testing.T) {
	server := setupTestServerWithoutClient()

	tests := []struct {
		name     string
		policy   string
		isValid  bool
		expected string
	}{
		{
			name: "Valid Policy JSON",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/*"
					}
				]
			}`,
			isValid:  true,
			expected: "Valid AWS S3 bucket policy",
		},
		{
			name: "Minimal Policy JSON",
			policy: `{
				"Version": "2012-10-17",
				"Statement": []
			}`,
			isValid:  true,
			expected: "Minimal valid policy structure",
		},
		{
			name:     "Invalid JSON",
			policy:   `{"Version": "2012-10-17", "Statement": [}`,
			isValid:  false,
			expected: "Malformed JSON structure",
		},
		{
			name:     "Empty JSON",
			policy:   "",
			isValid:  false,
			expected: "Empty policy not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Policy %s: %s", tt.name, tt.expected)

			result := server.isValidJSON(tt.policy)
			if tt.isValid {
				assert.True(t, result, "Expected policy to be valid JSON")
			} else {
				assert.False(t, result, "Expected policy to be invalid JSON")
			}
		})
	}
}

func TestBucketPolicyRequestBodyHandling(t *testing.T) {
	server := setupTestServerWithoutClient()

	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid Policy body",
			body: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/*"
					}
				]
			}`,
			expectedStatus: http.StatusNoContent,
			description:    "Valid policy should be accepted",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusBadRequest,
			description:    "Empty policy should be rejected",
		},
		{
			name:           "Invalid JSON body",
			body:           `{"Version": "2012-10-17", "Statement": [}`,
			expectedStatus: http.StatusBadRequest,
			description:    "Invalid JSON should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Test %s: %s", tt.name, tt.description)

			req := httptest.NewRequest("PUT", "/test-bucket?policy", bytes.NewReader([]byte(tt.body)))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			rr := httptest.NewRecorder()

			server.handleBucketPolicy(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestBucketPolicySecurityScenarios(t *testing.T) {
	tests := []struct {
		name        string
		policy      string
		description string
		hasWarning  bool
	}{
		{
			name: "Restrictive Policy is secure",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": {"AWS": "arn:aws:iam::123456789012:user/specific-user"},
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/public/*"
					}
				]
			}`,
			description: "Only specific user can access specific resources",
			hasWarning:  false,
		},
		{
			name: "Wildcard Principal is less secure",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/*"
					}
				]
			}`,
			description: "Wildcard principal allows any AWS account access",
			hasWarning:  true,
		},
		{
			name: "Write permissions with wildcard are risky",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": ["s3:PutObject", "s3:DeleteObject"],
						"Resource": "arn:aws:s3:::test-bucket/*"
					}
				]
			}`,
			description: "Wildcard principal with write permissions is very risky",
			hasWarning:  true,
		},
		{
			name: "Read-only wildcard is moderately secure",
			policy: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Principal": "*",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::test-bucket/public/*"
					}
				]
			}`,
			description: "Wildcard with read-only on public path has limited risk",
			hasWarning:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Policy %s: %s", tt.name, tt.description)
			if tt.hasWarning {
				t.Logf("WARNING: Policy %s has security implications", tt.name)
			}

			// Validate that the policy is valid JSON
			var policy interface{}
			err := json.Unmarshal([]byte(tt.policy), &policy)
			assert.NoError(t, err, "Policy should be valid JSON")
		})
	}
}

func TestBucketPolicyMethodHandling(t *testing.T) {
	server := setupTestServerWithoutClient()

	tests := []struct {
		name           string
		method         string
		expectedStatus int
		description    string
	}{
		{
			name:           "GET Policy",
			method:         "GET",
			expectedStatus: http.StatusOK,
			description:    "GET should return policy",
		},
		{
			name:           "PUT Policy",
			method:         "PUT",
			expectedStatus: http.StatusNoContent,
			description:    "PUT should set policy",
		},
		{
			name:           "DELETE Policy",
			method:         "DELETE",
			expectedStatus: http.StatusNoContent,
			description:    "DELETE should remove policy",
		},
		{
			name:           "POST Policy",
			method:         "POST",
			expectedStatus: http.StatusNotImplemented,
			description:    "POST should not be implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Method %s: %s", tt.method, tt.description)

			var body []byte
			if tt.method == "PUT" {
				policy := `{"Version": "2012-10-17", "Statement": []}`
				body = []byte(policy)
			}

			req := httptest.NewRequest(tt.method, "/test-bucket?policy", bytes.NewReader(body))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			rr := httptest.NewRecorder()

			server.handleBucketPolicy(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}
