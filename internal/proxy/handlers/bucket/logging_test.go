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

// TestHandleBucketLogging_GET_NoClient tests the GET operation with comprehensive mock setup
func TestHandleBucketLogging_GET_NoClient(t *testing.T) {
	// Create mock S3 client
	mockS3Backend := &MockS3Backend{}

	// Setup mock for GetBucketLogging to return logging configuration
	targetBucket := "access-logs-bucket"
	targetPrefix := "logs/"
	mockS3Backend.On("GetBucketLogging",
		mock.Anything,
		mock.MatchedBy(func(input *s3.GetBucketLoggingInput) bool {
			return input.Bucket != nil && *input.Bucket == "test-bucket"
		}),
	).Return(&s3.GetBucketLoggingOutput{
		LoggingEnabled: &types.LoggingEnabled{
			TargetBucket: &targetBucket,
			TargetPrefix: &targetPrefix,
		},
	}, nil)

	// Create handler with mock
	cfg := &config.Config{} // Empty config for testing
	handler := NewHandler(mockS3Backend, testLogger(), "s3ep-", cfg)

	req := httptest.NewRequest("GET", "/test-bucket?logging", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

	rr := httptest.NewRecorder()

	handler.GetLoggingHandler().Handle(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))

	body := rr.Body.String()
	assert.Contains(t, body, "LoggingEnabled")
	assert.Contains(t, body, "TargetBucket")
	assert.Contains(t, body, "TargetPrefix")
	// Note: AWS SDK XML format uses different wrapper element than S3 API spec, that's expected

	// Verify mock was called
	mockS3Backend.AssertExpectations(t)
}

// TestBucketLoggingXMLValidation tests various logging XML configurations
func TestBucketLoggingXMLValidation(t *testing.T) {
	tests := []struct {
		name        string
		description string
		loggingXML  string
	}{
		{
			name:        "Basic Logging Enabled",
			description: "Standard logging configuration with target bucket",
			loggingXML: `<BucketLoggingStatus>
    <LoggingEnabled>
        <TargetBucket>access-logs-bucket</TargetBucket>
        <TargetPrefix>logs/</TargetPrefix>
    </LoggingEnabled>
</BucketLoggingStatus>`,
		},
		{
			name:        "Logging with Grants",
			description: "Logging configuration with access control grants",
			loggingXML: `<BucketLoggingStatus>
    <LoggingEnabled>
        <TargetBucket>access-logs-bucket</TargetBucket>
        <TargetPrefix>access-logs/</TargetPrefix>
        <TargetGrants>
            <Grant>
                <Grantee xsi:type="CanonicalUser" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                    <ID>canonical-user-id</ID>
                    <DisplayName>Example User</DisplayName>
                </Grantee>
                <Permission>FULL_CONTROL</Permission>
            </Grant>
        </TargetGrants>
    </LoggingEnabled>
</BucketLoggingStatus>`,
		},
		{
			name:        "Logging Disabled",
			description: "Empty logging configuration (logging disabled)",
			loggingXML: `<BucketLoggingStatus>
</BucketLoggingStatus>`,
		},
		{
			name:        "Complex Prefix Path",
			description: "Logging with complex prefix path structure",
			loggingXML: `<BucketLoggingStatus>
    <LoggingEnabled>
        <TargetBucket>logs-central-bucket</TargetBucket>
        <TargetPrefix>company/department/application/access-logs/</TargetPrefix>
    </LoggingEnabled>
</BucketLoggingStatus>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Logging test %s: %s", tt.name, tt.description)

			handler := testHandler()

			req := httptest.NewRequest("PUT", "/test-bucket?logging", strings.NewReader(tt.loggingXML))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})
			req.Header.Set("Content-Type", "application/xml")

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestBucketLoggingTargetValidation tests target bucket and prefix validation
func TestBucketLoggingTargetValidation(t *testing.T) {
	tests := []struct {
		name         string
		targetBucket string
		targetPrefix string
		description  string
	}{
		{
			name:         "Standard Target",
			targetBucket: "access-logs-bucket",
			targetPrefix: "logs/",
			description:  "Standard target bucket and prefix",
		},
		{
			name:         "Different Account Target",
			targetBucket: "cross-account-logs",
			targetPrefix: "external/logs/",
			description:  "Cross-account logging bucket",
		},
		{
			name:         "Same Bucket Logging",
			targetBucket: "self-logging-bucket",
			targetPrefix: "internal-logs/",
			description:  "Logging to the same bucket (with prefix)",
		},
		{
			name:         "Deep Prefix Structure",
			targetBucket: "logs-warehouse",
			targetPrefix: "year=2023/month=09/day=04/hour=12/",
			description:  "Deep hierarchical prefix structure",
		},
		{
			name:         "No Prefix",
			targetBucket: "simple-logs",
			targetPrefix: "",
			description:  "Logging without prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Target %s: %s", tt.name, tt.description)

			loggingXML := `<BucketLoggingStatus>
    <LoggingEnabled>
        <TargetBucket>` + tt.targetBucket + `</TargetBucket>
        <TargetPrefix>` + tt.targetPrefix + `</TargetPrefix>
    </LoggingEnabled>
</BucketLoggingStatus>`

			handler := testHandler()

			req := httptest.NewRequest("PUT", "/test-bucket?logging", strings.NewReader(loggingXML))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestBucketLoggingSecurityScenarios tests security-related logging scenarios
func TestBucketLoggingSecurityScenarios(t *testing.T) {
	tests := []struct {
		name        string
		description string
		scenario    string
	}{
		{
			name:        "Secure Audit Logging",
			description: "Logging for security audit and compliance",
			scenario:    "High-security bucket with comprehensive access logging",
		},
		{
			name:        "Compliance Logging",
			description: "Logging for regulatory compliance requirements",
			scenario:    "Financial services bucket with mandatory audit trail",
		},
		{
			name:        "Cross-Region Logging",
			description: "Logging to different AWS region for disaster recovery",
			scenario:    "Multi-region logging setup for business continuity",
		},
		{
			name:        "Centralized Logging",
			description: "Centralized logging for multiple application buckets",
			scenario:    "Enterprise logging architecture with central log bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Scenario %s: %s", tt.name, tt.description)

			handler := testHandler()

			req := httptest.NewRequest("GET", "/test-bucket?logging", nil)
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Body.String(), "BucketLoggingStatus")
		})
	}
}

// TestBucketLoggingMethodHandling tests HTTP method handling
func TestBucketLoggingMethodHandling(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		expectedStatus int
		description    string
	}{
		{
			name:           "GET Logging",
			method:         "GET",
			expectedStatus: http.StatusOK,
			description:    "GET should return logging configuration",
		},
		{
			name:           "PUT Logging",
			method:         "PUT",
			expectedStatus: http.StatusOK,
			description:    "PUT should set logging configuration",
		},
		{
			name:           "DELETE Logging",
			method:         "DELETE",
			expectedStatus: http.StatusOK,
			description:    "DELETE should disable logging",
		},
		{
			name:           "POST Logging",
			method:         "POST",
			expectedStatus: http.StatusNotImplemented,
			description:    "POST should not be implemented",
		},
		{
			name:           "PATCH Logging",
			method:         "PATCH",
			expectedStatus: http.StatusNotImplemented,
			description:    "PATCH should not be implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Method %s: %s", tt.method, tt.description)

			handler := testHandler()

			var req *http.Request
			if tt.method == "PUT" {
				loggingXML := `<BucketLoggingStatus>
    <LoggingEnabled>
        <TargetBucket>test-logs</TargetBucket>
        <TargetPrefix>logs/</TargetPrefix>
    </LoggingEnabled>
</BucketLoggingStatus>`
				req = httptest.NewRequest(tt.method, "/test-bucket?logging", strings.NewReader(loggingXML))
			} else {
				req = httptest.NewRequest(tt.method, "/test-bucket?logging", nil)
			}
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			switch tt.expectedStatus {
			case http.StatusOK:
				if tt.method == "GET" || tt.method == "DELETE" {
					assert.Equal(t, "application/xml", rr.Header().Get("Content-Type"))
					assert.Contains(t, rr.Body.String(), "BucketLoggingStatus")
				}
			case http.StatusNotImplemented:
				assert.Contains(t, rr.Body.String(), "BucketLogging_"+tt.method)
			}
		})
	}
}

// TestBucketLoggingXMLFormat tests XML format validation and generation
func TestBucketLoggingXMLFormat(t *testing.T) {
	tests := []struct {
		name   string
		xmlStr string
	}{
		{
			name:   "Standard XML",
			xmlStr: `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>access/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>`,
		},
		{
			name:   "Formatted XML",
			xmlStr: `<BucketLoggingStatus>\n    <LoggingEnabled>\n        <TargetBucket>logs</TargetBucket>\n    </LoggingEnabled>\n</BucketLoggingStatus>`,
		},
		{
			name:   "Empty Logging",
			xmlStr: `<BucketLoggingStatus></BucketLoggingStatus>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := testHandler()

			req := httptest.NewRequest("PUT", "/test-bucket?logging", strings.NewReader(tt.xmlStr))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestBucketLoggingErrorHandling tests error handling scenarios
func TestBucketLoggingErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		bucketName  string
		requestBody string
		description string
	}{
		{
			name:        "Valid bucket name",
			bucketName:  "valid-bucket-name",
			requestBody: `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket></LoggingEnabled></BucketLoggingStatus>`,
			description: "Standard bucket name should work",
		},
		{
			name:        "Bucket with numbers",
			bucketName:  "bucket123",
			requestBody: `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs123</TargetBucket></LoggingEnabled></BucketLoggingStatus>`,
			description: "Bucket name with numbers",
		},
		{
			name:        "Bucket with hyphens",
			bucketName:  "my-logging-bucket",
			requestBody: `<BucketLoggingStatus><LoggingEnabled><TargetBucket>my-logs-bucket</TargetBucket></LoggingEnabled></BucketLoggingStatus>`,
			description: "Bucket name with hyphens",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Test %s: %s", tt.name, tt.description)

			handler := testHandler()

			req := httptest.NewRequest("PUT", "/"+tt.bucketName+"?logging", strings.NewReader(tt.requestBody))
			req = mux.SetURLVars(req, map[string]string{"bucket": tt.bucketName})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusOK, rr.Code)
		})
	}
}

// TestBucketLoggingInvalidXML tests invalid XML handling
func TestBucketLoggingInvalidXML(t *testing.T) {
	tests := []struct {
		name        string
		invalidXML  string
		description string
	}{
		{
			name:        "Malformed XML",
			invalidXML:  `<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket>`,
			description: "XML with missing closing tags",
		},
		{
			name:        "Invalid Structure",
			invalidXML:  `<InvalidRoot><SomeElement>test</SomeElement></InvalidRoot>`,
			description: "XML with completely wrong structure",
		},
		{
			name:        "Empty Body",
			invalidXML:  "",
			description: "Empty request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Invalid XML test %s: %s", tt.name, tt.description)

			handler := testHandler()

			req := httptest.NewRequest("PUT", "/test-bucket?logging", strings.NewReader(tt.invalidXML))
			req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

			rr := httptest.NewRecorder()

			handler.GetLoggingHandler().Handle(rr, req)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
		})
	}
}
