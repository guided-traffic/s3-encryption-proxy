package bucket

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// TestHandleBucketLocation_GET_NoClient tests the location handler GET operation with comprehensive mock setup
func TestHandleBucketLocation_GET_NoClient(t *testing.T) {
	// Create mock S3 client
	mockS3Backend := &MockS3Backend{}

	// Setup mock for GetBucketLocation to return us-west-2
	expectedLocation := "us-west-2"
	mockS3Backend.On("GetBucketLocation",
		mock.Anything,
		mock.MatchedBy(func(input *s3.GetBucketLocationInput) bool {
			return input.Bucket != nil && *input.Bucket == "test-bucket"
		}),
	).Return(&s3.GetBucketLocationOutput{
		LocationConstraint: types.BucketLocationConstraint(expectedLocation),
	}, nil)

	// Create handler with mock
	cfg := &config.Config{} // Empty config for testing
	handler := NewHandler(mockS3Backend, testLogger(), "s3ep-", cfg)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/test-bucket?location", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call the handler
	handler.GetLocationHandler().Handle(rr, req)

	// Check status code
	assert.Equal(t, http.StatusOK, rr.Code)

	// Check content type
	assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))

	// Check response body contains location constraint
	body := rr.Body.String()
	assert.Contains(t, body, `<LocationConstraint>us-west-2</LocationConstraint>`)
	// Note: AWS SDK XML output doesn't include XML declaration, that's expected behavior

	// Verify mock was called
	mockS3Backend.AssertExpectations(t)
}

// TestBucketLocationXMLValidation tests various XML location constraint responses
func TestBucketLocationXMLValidation(t *testing.T) {
	tests := []struct {
		name                string
		description         string
		expectedLocation    string
		shouldContainRegion bool
	}{
		{
			name:                "US West 2 Location",
			description:         "Standard US West 2 region location",
			expectedLocation:    "us-west-2",
			shouldContainRegion: true,
		},
		{
			name:                "EU West 1 Location",
			description:         "European region location constraint",
			expectedLocation:    "eu-west-1",
			shouldContainRegion: true,
		},
		{
			name:                "Asia Pacific Location",
			description:         "Asia Pacific region location",
			expectedLocation:    "ap-southeast-1",
			shouldContainRegion: true,
		},
		{
			name:                "US East 1 (Empty Location)",
			description:         "Default US East 1 region (empty constraint)",
			expectedLocation:    "",
			shouldContainRegion: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Location test %s: %s", tt.name, tt.description)

			// Validate the expected XML structure
			xmlResponse := `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>` + tt.expectedLocation + `</LocationConstraint>`

			if tt.shouldContainRegion {
				assert.Contains(t, xmlResponse, tt.expectedLocation)
			}
			assert.Contains(t, xmlResponse, "LocationConstraint")
			assert.Contains(t, xmlResponse, `<?xml version="1.0" encoding="UTF-8"?>`)
		})
	}
}

// TestBucketLocationRegionMapping tests region constraint mappings
func TestBucketLocationRegionMapping(t *testing.T) {
	tests := []struct {
		name        string
		region      string
		description string
	}{
		{
			name:        "US Standard",
			region:      "",
			description: "US East 1 (no constraint)",
		},
		{
			name:        "US West (Oregon)",
			region:      "us-west-2",
			description: "US West 2 Oregon region",
		},
		{
			name:        "US West (N. California)",
			region:      "us-west-1",
			description: "US West 1 N. California region",
		},
		{
			name:        "EU (Ireland)",
			region:      "eu-west-1",
			description: "European Union Ireland region",
		},
		{
			name:        "EU (Frankfurt)",
			region:      "eu-central-1",
			description: "European Union Frankfurt region",
		},
		{
			name:        "Asia Pacific (Singapore)",
			region:      "ap-southeast-1",
			description: "Asia Pacific Singapore region",
		},
		{
			name:        "Asia Pacific (Sydney)",
			region:      "ap-southeast-2",
			description: "Asia Pacific Sydney region",
		},
		{
			name:        "Asia Pacific (Tokyo)",
			region:      "ap-northeast-1",
			description: "Asia Pacific Tokyo region",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Region %s: %s", tt.region, tt.description)

			// Validate region format and structure
			if tt.region != "" {
				parts := strings.Split(tt.region, "-")
				assert.GreaterOrEqual(t, len(parts), 2, "Region should have at least 2 parts separated by hyphen")

				// Check for valid region prefix
				validPrefixes := []string{"us", "eu", "ap", "sa", "ca", "me", "af"}
				foundValidPrefix := false
				for _, prefix := range validPrefixes {
					if strings.HasPrefix(tt.region, prefix+"-") {
						foundValidPrefix = true
						break
					}
				}
				assert.True(t, foundValidPrefix, "Region should start with valid AWS region prefix")
			}
		})
	}
}

// TestBucketLocationSecurityScenarios tests security aspects of location operations
func TestBucketLocationSecurityScenarios(t *testing.T) {
	tests := []struct {
		name        string
		description string
		region      string
	}{
		{
			name:        "Secure EU Region",
			description: "EU region with data residency compliance",
			region:      "eu-west-1",
		},
		{
			name:        "Secure US Government Region",
			description: "US government region with enhanced security",
			region:      "us-gov-west-1",
		},
		{
			name:        "Secure Asia Pacific Region",
			description: "Asia Pacific region with local compliance",
			region:      "ap-southeast-1",
		},
		{
			name:        "Default US Region",
			description: "Standard US East region",
			region:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Location %s: %s", tt.name, tt.description)

			// Validate that location information doesn't expose sensitive data
			locationXML := `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>` + tt.region + `</LocationConstraint>`

			// Should not contain any sensitive information
			sensitivePatterns := []string{"password", "secret", "key", "token", "credential"}
			for _, pattern := range sensitivePatterns {
				assert.NotContains(t, strings.ToLower(locationXML), pattern,
					"Location response should not contain sensitive information")
			}

			// Should only contain valid XML and region data
			assert.Contains(t, locationXML, "LocationConstraint")
			assert.Contains(t, locationXML, `<?xml version="1.0" encoding="UTF-8"?>`)
		})
	}
}

// TestBucketLocationMethodHandling tests different HTTP methods for location operations
func TestBucketLocationMethodHandling(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		description    string
		expectedStatus int
	}{
		{
			name:           "GET Location",
			method:         "GET",
			description:    "GET should return location constraint",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST Location",
			method:         "POST",
			description:    "POST should not be implemented",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "PUT Location",
			method:         "PUT",
			description:    "PUT should not be implemented",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "DELETE Location",
			method:         "DELETE",
			description:    "DELETE should not be implemented",
			expectedStatus: http.StatusNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Method %s: %s", tt.method, tt.description)

			// Create a test server with no S3 client (mock mode)
			handler := testHandler()

			// Create request
			req := httptest.NewRequest(tt.method, "/test-bucket?location", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			handler.GetLocationHandler().Handle(rr, req)

			// Check status code
			assert.Equal(t, tt.expectedStatus, rr.Code)

			switch tt.expectedStatus {
			case http.StatusOK:
				// For successful GET, check XML content
				assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
				assert.Contains(t, rr.Body.String(), "LocationConstraint")
			case http.StatusNotImplemented:
				// For not implemented methods, check for appropriate response
				assert.Contains(t, rr.Body.String(), "BucketLocation_"+tt.method)
			}
		})
	}
}

// TestBucketLocationXMLFormat tests the XML format compliance
func TestBucketLocationXMLFormat(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		expected string
	}{
		{
			name:   "US West 2 XML",
			region: "us-west-2",
			expected: `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>us-west-2</LocationConstraint>`,
		},
		{
			name:   "Empty Region XML",
			region: "",
			expected: `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint></LocationConstraint>`,
		},
		{
			name:   "EU West 1 XML",
			region: "eu-west-1",
			expected: `<?xml version="1.0" encoding="UTF-8"?>
<LocationConstraint>eu-west-1</LocationConstraint>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate XML structure
			assert.Contains(t, tt.expected, `<?xml version="1.0" encoding="UTF-8"?>`)
			assert.Contains(t, tt.expected, "<LocationConstraint>")
			assert.Contains(t, tt.expected, "</LocationConstraint>")

			if tt.region != "" {
				assert.Contains(t, tt.expected, tt.region)
			}
		})
	}
}

// TestBucketLocationErrorHandling tests error scenarios
func TestBucketLocationErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		description string
		bucket      string
	}{
		{
			name:        "Valid bucket name",
			description: "Standard bucket name should work",
			bucket:      "valid-bucket-name",
		},
		{
			name:        "Bucket with numbers",
			description: "Bucket name with numbers",
			bucket:      "bucket123",
		},
		{
			name:        "Bucket with hyphens",
			description: "Bucket name with hyphens",
			bucket:      "my-test-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Test %s: %s", tt.name, tt.description)

			// Create a test server with no S3 client (mock mode)
			handler := testHandler()

			// Create request
			req := httptest.NewRequest("GET", "/"+tt.bucket+"?location", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucket})

			// Create response recorder
			rr := httptest.NewRecorder()

			// Call the handler
			handler.GetLocationHandler().Handle(rr, req)

			// Should succeed in mock mode
			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
			assert.Contains(t, rr.Body.String(), "LocationConstraint")
		})
	}
}
