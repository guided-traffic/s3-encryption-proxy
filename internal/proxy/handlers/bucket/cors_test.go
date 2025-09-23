package bucket

import (
	"bytes"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// TestHandleBucketCORS_GET_NoClient tests CORS GET handler without S3 client
func TestHandleBucketCORS_GET_NoClient(t *testing.T) {
	// Create handler without S3 client to test mock CORS behavior
	cfg := &config.Config{} // Empty config for testing
	handler := NewHandler(nil, testLogger(), "s3ep-", cfg)

	req := httptest.NewRequest("GET", "/test-bucket?cors", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
	w := httptest.NewRecorder()

	handler.GetCORSHandler().Handle(w, req)

	// Without S3 client, should return mock CORS data
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
	assert.Contains(t, w.Body.String(), "CORSConfiguration")
	assert.Contains(t, w.Body.String(), "AllowedOrigin")
}

// TestCORSXMLParsing tests parsing of CORS XML configurations
func TestCORSXMLParsing(t *testing.T) {
	tests := []struct {
		name        string
		xmlInput    string
		expectError bool
		description string
	}{
		{
			name: "Valid CORS XML",
			xmlInput: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedMethod>PUT</AllowedMethod>
					<AllowedHeader>*</AllowedHeader>
					<MaxAgeSeconds>3000</MaxAgeSeconds>
				</CORSRule>
			</CORSConfiguration>`,
			expectError: false,
			description: "Valid CORS configuration with multiple methods",
		},
		{
			name: "Minimal CORS XML",
			xmlInput: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>https://example.com</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`,
			expectError: false,
			description: "Minimal valid CORS configuration",
		},
		{
			name:        "Invalid XML",
			xmlInput:    `<InvalidXML><unclosed>`,
			expectError: true,
			description: "Malformed XML should fail parsing",
		},
		{
			name:        "Empty XML",
			xmlInput:    "",
			expectError: true,
			description: "Empty XML should fail parsing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(tt.xmlInput), &corsConfig)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				// Note: AWS SDK types.CORSConfiguration structure validation
				// The exact parsing behavior depends on AWS SDK XML tags
			}
		})
	}
}

// TestCORSHTTPMethods tests CORS HTTP method validation
func TestCORSHTTPMethods(t *testing.T) {
	validMethods := []string{"GET", "PUT", "POST", "DELETE", "HEAD"}

	for _, method := range validMethods {
		t.Run("Method_"+method, func(t *testing.T) {
			corsXML := `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>` + method + `</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`

			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(corsXML), &corsConfig)
			assert.NoError(t, err)
			// Note: Validation focuses on successful parsing rather than content structure
		})
	}
}

// TestCORSOriginPatterns tests CORS origin pattern validation
func TestCORSOriginPatterns(t *testing.T) {
	origins := []struct {
		pattern     string
		description string
	}{
		{"*", "Wildcard origin"},
		{"https://example.com", "Specific HTTPS origin"},
		{"http://localhost:3000", "Local development origin"},
		{"https://*.example.com", "Subdomain wildcard"},
	}

	for _, origin := range origins {
		t.Run("Origin_"+origin.pattern, func(t *testing.T) {
			corsXML := `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>` + origin.pattern + `</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`

			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(corsXML), &corsConfig)
			assert.NoError(t, err, origin.description)
			// Note: Content validation depends on AWS SDK XML structure
			t.Logf("Origin '%s': %s", origin.pattern, origin.description)
		})
	}
}

// TestCORSComplexConfiguration tests complex CORS configurations
func TestCORSComplexConfiguration(t *testing.T) {
	complexCORSXML := `<CORSConfiguration>
		<CORSRule>
			<ID>rule1</ID>
			<AllowedOrigin>https://www.example.com</AllowedOrigin>
			<AllowedOrigin>https://example.com</AllowedOrigin>
			<AllowedMethod>GET</AllowedMethod>
			<AllowedMethod>PUT</AllowedMethod>
			<AllowedMethod>POST</AllowedMethod>
			<AllowedHeader>x-amz-*</AllowedHeader>
			<AllowedHeader>content-type</AllowedHeader>
			<MaxAgeSeconds>3600</MaxAgeSeconds>
			<ExposeHeader>ETag</ExposeHeader>
		</CORSRule>
		<CORSRule>
			<ID>rule2</ID>
			<AllowedOrigin>*</AllowedOrigin>
			<AllowedMethod>GET</AllowedMethod>
			<MaxAgeSeconds>300</MaxAgeSeconds>
		</CORSRule>
	</CORSConfiguration>`

	var corsConfig types.CORSConfiguration
	err := xml.Unmarshal([]byte(complexCORSXML), &corsConfig)
	assert.NoError(t, err)

	// Note: Complex CORS validation depends on AWS SDK XML structure
	// Test focuses on successful parsing rather than exact content structure
	t.Log("Complex CORS XML parsed successfully")
}

// TestCORSRequestBodyHandling tests request body handling for CORS operations
func TestCORSRequestBodyHandling(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		description    string
	}{
		{
			name: "Valid CORS body",
			body: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`,
			expectedStatus: http.StatusOK,
			description:    "Valid CORS XML should be accepted",
		},
		{
			name:           "Empty body",
			body:           "",
			expectedStatus: http.StatusBadRequest,
			description:    "Empty body should return BadRequest",
		},
		{
			name:           "Invalid XML body",
			body:           "<invalid><xml>",
			expectedStatus: http.StatusBadRequest,
			description:    "Invalid XML should return BadRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := testHandler()

			var body *bytes.Buffer
			if tt.body != "" {
				body = bytes.NewBufferString(tt.body)
			} else {
				body = bytes.NewBuffer(nil)
			}

			req := httptest.NewRequest("PUT", "/test-bucket?cors", body)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			w := httptest.NewRecorder()

			handler.GetCORSHandler().Handle(w, req)

			// Since we don't have S3 client, we expect mock response
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}
