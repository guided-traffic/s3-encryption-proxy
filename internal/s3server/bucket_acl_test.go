package s3server

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestHandleBucketACL_GET_NoClient(t *testing.T) {
	// Test GET ACL without S3 client - should return mock data
	server := &Server{
		logger: testLogger(),
		// No S3 client
	}

	req := httptest.NewRequest(http.MethodGet, "/test-bucket?acl", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket"})

	rr := httptest.NewRecorder()
	server.handleBucketSubResource(rr, req)

	// Without S3 client, should return mock ACL data
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/xml")
	assert.Contains(t, rr.Body.String(), "AccessControlPolicy")
	assert.Contains(t, rr.Body.String(), "mock-owner-id")
}

func TestCannedACLMapping(t *testing.T) {
	tests := []struct {
		input    string
		expected types.BucketCannedACL
		valid    bool
	}{
		{"private", types.BucketCannedACLPrivate, true},
		{"public-read", types.BucketCannedACLPublicRead, true},
		{"public-read-write", types.BucketCannedACLPublicReadWrite, true},
		{"authenticated-read", types.BucketCannedACLAuthenticatedRead, true},
		{"invalid", "", false},
		{"", "", false},
		{"PRIVATE", "", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Input_%s", tt.input), func(t *testing.T) {
			result, valid := mapCannedACLForBucket(tt.input)
			assert.Equal(t, tt.valid, valid)
			if tt.valid {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// mapCannedACLForBucket maps canned ACL strings to AWS SDK types
func mapCannedACLForBucket(acl string) (types.BucketCannedACL, bool) {
	switch acl {
	case "private":
		return types.BucketCannedACLPrivate, true
	case "public-read":
		return types.BucketCannedACLPublicRead, true
	case "public-read-write":
		return types.BucketCannedACLPublicReadWrite, true
	case "authenticated-read":
		return types.BucketCannedACLAuthenticatedRead, true
	default:
		return "", false
	}
}

func TestACLXMLParsing(t *testing.T) {
	tests := []struct {
		name      string
		xml       string
		shouldErr bool
	}{
		{
			name: "Valid ACL XML",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
    <Owner>
        <ID>owner-id</ID>
        <DisplayName>owner-name</DisplayName>
    </Owner>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                <ID>owner-id</ID>
                <DisplayName>owner-name</DisplayName>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>`,
			shouldErr: false,
		},
		{
			name:      "Invalid XML",
			xml:       `<invalid xml>`,
			shouldErr: true,
		},
		{
			name:      "Empty XML",
			xml:       ``,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acp, err := parseACLXMLForTest(tt.xml)
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Nil(t, acp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, acp)
			}
		})
	}
}

// parseACLXMLForTest parses ACL XML for testing
func parseACLXMLForTest(xmlContent string) (*types.AccessControlPolicy, error) {
	if xmlContent == "" || !strings.Contains(xmlContent, "AccessControlPolicy") {
		return nil, fmt.Errorf("invalid XML")
	}

	var acp types.AccessControlPolicy
	err := xml.Unmarshal([]byte(xmlContent), &acp)
	if err != nil {
		return nil, err
	}

	return &acp, nil
}
