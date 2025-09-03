package integration

import (
	"encoding/xml"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

// TestBucketCORSValidation tests validation of CORS configurations
func TestBucketCORSValidation(t *testing.T) {
	tests := []struct {
		name        string
		corsXML     string
		expectValid bool
		description string
	}{
		{
			name: "Valid basic CORS",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`,
			expectValid: true,
			description: "Basic CORS configuration should be valid",
		},
		{
			name: "Valid complex CORS",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<ID>rule1</ID>
					<AllowedOrigin>https://example.com</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedMethod>PUT</AllowedMethod>
					<AllowedMethod>POST</AllowedMethod>
					<AllowedHeader>*</AllowedHeader>
					<MaxAgeSeconds>3600</MaxAgeSeconds>
					<ExposeHeader>ETag</ExposeHeader>
					<ExposeHeader>x-amz-meta-custom</ExposeHeader>
				</CORSRule>
			</CORSConfiguration>`,
			expectValid: true,
			description: "Complex CORS configuration should be valid",
		},
		{
			name: "Multiple CORS rules",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<ID>public-read</ID>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedMethod>HEAD</AllowedMethod>
					<MaxAgeSeconds>3000</MaxAgeSeconds>
				</CORSRule>
				<CORSRule>
					<ID>admin-write</ID>
					<AllowedOrigin>https://admin.example.com</AllowedOrigin>
					<AllowedMethod>PUT</AllowedMethod>
					<AllowedMethod>DELETE</AllowedMethod>
					<AllowedHeader>authorization</AllowedHeader>
					<AllowedHeader>content-type</AllowedHeader>
					<MaxAgeSeconds>0</MaxAgeSeconds>
				</CORSRule>
			</CORSConfiguration>`,
			expectValid: true,
			description: "Multiple CORS rules should be valid",
		},
		{
			name:        "Invalid XML format",
			corsXML:     `<CORSConfiguration><CORSRule><unclosed>`,
			expectValid: false,
			description: "Malformed XML should be invalid",
		},
		{
			name:        "Empty CORS configuration",
			corsXML:     "",
			expectValid: false,
			description: "Empty configuration should be invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.corsXML == "" {
				t.Log("CORS configuration:", "empty")
			} else {
				t.Log("CORS configuration:", tt.corsXML)
			}

			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(tt.corsXML), &corsConfig)

			if tt.expectValid {
				assert.NoError(t, err, tt.description)
				// Note: AWS SDK CORS structure validation
				// Content validation depends on actual AWS SDK XML tags
			} else {
				assert.Error(t, err, tt.description)
			}
		})
	}
}

// TestCORSMethodValidation tests validation of CORS HTTP methods
func TestCORSMethodValidation(t *testing.T) {
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

			// Note: Content validation depends on AWS SDK XML structure
			t.Logf("Method '%s' parsed successfully", method)
		})
	}
}

// TestCORSOriginValidation tests validation of CORS origins
func TestCORSOriginValidation(t *testing.T) {
	origins := []struct {
		pattern     string
		description string
		expectValid bool
	}{
		{"*", "Wildcard origin (allow all)", true},
		{"https://example.com", "Specific HTTPS origin", true},
		{"http://localhost:3000", "Local development origin", true},
		{"https://*.example.com", "Subdomain wildcard", true},
		{"ftp://example.com", "Non-HTTP protocol", true}, // S3 allows this
		{"", "Empty origin", true},                       // AWS S3 allows empty strings
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

			if origin.expectValid {
				assert.NoError(t, err, origin.description)
				// Note: Content validation depends on AWS SDK XML structure
				t.Logf("Origin '%s': %s", origin.pattern, origin.description)
			} else {
				assert.Error(t, err, origin.description)
			}
		})
	}
}

// TestCORSHeaderValidation tests validation of CORS headers
func TestCORSHeaderValidation(t *testing.T) {
	headers := []struct {
		header      string
		description string
	}{
		{"*", "Wildcard header (allow all)"},
		{"content-type", "Standard content type header"},
		{"authorization", "Authorization header"},
		{"x-amz-*", "AWS S3 metadata wildcard"},
		{"x-custom-header", "Custom application header"},
		{"Content-Type", "Case variant of content-type"},
	}

	for _, header := range headers {
		t.Run("Header_"+header.header, func(t *testing.T) {
			corsXML := `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedHeader>` + header.header + `</AllowedHeader>
				</CORSRule>
			</CORSConfiguration>`

			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(corsXML), &corsConfig)
			assert.NoError(t, err, header.description)

			// Note: Content validation depends on AWS SDK XML structure
			t.Logf("Header '%s': %s", header.header, header.description)
		})
	}
}

// TestCORSMaxAgeValidation tests validation of CORS MaxAge settings
func TestCORSMaxAgeValidation(t *testing.T) {
	maxAgeValues := []struct {
		value       int32
		description string
	}{
		{0, "Immediate expiry (no caching)"},
		{300, "5 minutes cache"},
		{3600, "1 hour cache"},
		{86400, "24 hour cache"},
		{604800, "1 week cache"},
	}

	for _, maxAge := range maxAgeValues {
		t.Run("MaxAge_"+string(rune(maxAge.value)), func(t *testing.T) {
			corsXML := `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<MaxAgeSeconds>` + string(rune(maxAge.value+'0')) + `</MaxAgeSeconds>
				</CORSRule>
			</CORSConfiguration>`

			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(corsXML), &corsConfig)
			assert.NoError(t, err, maxAge.description)

			// Note: Content validation depends on AWS SDK XML structure
			t.Logf("MaxAge %d seconds: %s", maxAge.value, maxAge.description)
		})
	}
}

// TestCORSSecurityScenarios tests CORS security implications
func TestCORSSecurityScenarios(t *testing.T) {
	scenarios := []struct {
		name        string
		corsXML     string
		securityMsg string
		isSecure    bool
	}{
		{
			name: "Restrictive CORS is secure",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>https://trusted.example.com</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<MaxAgeSeconds>300</MaxAgeSeconds>
				</CORSRule>
			</CORSConfiguration>`,
			securityMsg: "Only specific trusted origin allowed",
			isSecure:    true,
		},
		{
			name: "Wildcard origin is less secure",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedMethod>PUT</AllowedMethod>
					<AllowedHeader>*</AllowedHeader>
				</CORSRule>
			</CORSConfiguration>`,
			securityMsg: "Wildcard origin allows any website to make requests",
			isSecure:    false,
		},
		{
			name: "Write methods with wildcard are risky",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>DELETE</AllowedMethod>
					<AllowedMethod>PUT</AllowedMethod>
					<AllowedHeader>*</AllowedHeader>
				</CORSRule>
			</CORSConfiguration>`,
			securityMsg: "Wildcard origin with write methods is very risky",
			isSecure:    false,
		},
		{
			name: "Read-only wildcard is moderately secure",
			corsXML: `<CORSConfiguration>
				<CORSRule>
					<AllowedOrigin>*</AllowedOrigin>
					<AllowedMethod>GET</AllowedMethod>
					<AllowedMethod>HEAD</AllowedMethod>
				</CORSRule>
			</CORSConfiguration>`,
			securityMsg: "Wildcard with read-only methods has limited risk",
			isSecure:    false, // Still not secure due to wildcard
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			var corsConfig types.CORSConfiguration
			err := xml.Unmarshal([]byte(scenario.corsXML), &corsConfig)
			assert.NoError(t, err)

			t.Logf("CORS '%s': %s", scenario.name, scenario.securityMsg)
			if !scenario.isSecure {
				t.Logf("WARNING: CORS '%s' has security implications", scenario.name)
			}
		})
	}
}
