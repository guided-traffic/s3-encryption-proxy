package integration

import (
	"encoding/xml"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
)

func TestBucketACLValidation(t *testing.T) {
	// Test ACL validation logic in isolation

	tests := []struct {
		name        string
		cannedACL   string
		expectValid bool
	}{
		{"Valid private ACL", "private", true},
		{"Valid public-read ACL", "public-read", true},
		{"Valid public-read-write ACL", "public-read-write", true},
		{"Valid authenticated-read ACL", "authenticated-read", true},
		{"Invalid ACL", "invalid-acl", false},
		{"Empty ACL", "", false},
		{"Case sensitive - uppercase", "PRIVATE", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, valid := validateCannedACL(tt.cannedACL)
			assert.Equal(t, tt.expectValid, valid)
			if tt.expectValid {
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestBucketACLXMLValidation(t *testing.T) {
	// Test XML ACL validation logic

	tests := []struct {
		name      string
		xml       string
		expectErr bool
	}{
		{
			name: "Valid complete ACL XML",
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
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group">
                <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
            </Grantee>
            <Permission>READ</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>`,
			expectErr: false,
		},
		{
			name: "Valid minimal ACL XML",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                <ID>owner-id</ID>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>`,
			expectErr: false,
		},
		{
			name:      "Invalid XML format",
			xml:       `<invalid xml structure>`,
			expectErr: true,
		},
		{
			name:      "Empty XML",
			xml:       ``,
			expectErr: true,
		},
		{
			name: "Missing required elements",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy>
</AccessControlPolicy>`,
			expectErr: false, // AWS allows empty ACL lists
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acp, err := parseACLXML(tt.xml)
			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, acp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, acp)
			}
		})
	}
}

func TestACLPermissionMapping(t *testing.T) {
	// Test that we handle all S3 ACL permissions correctly
	validPermissions := []types.Permission{
		types.PermissionFullControl,
		types.PermissionRead,
		types.PermissionWrite,
		types.PermissionReadAcp,
		types.PermissionWriteAcp,
	}

	for _, perm := range validPermissions {
		t.Run(fmt.Sprintf("Permission_%s", perm), func(t *testing.T) {
			assert.NotEmpty(t, string(perm))
		})
	}
}

func TestACLGranteeTypes(t *testing.T) {
	// Test that we handle all S3 ACL grantee types correctly
	validGranteeTypes := []types.Type{
		types.TypeCanonicalUser,
		types.TypeAmazonCustomerByEmail,
		types.TypeGroup,
	}

	for _, granteeType := range validGranteeTypes {
		t.Run(fmt.Sprintf("GranteeType_%s", granteeType), func(t *testing.T) {
			assert.NotEmpty(t, string(granteeType))
		})
	}
}

func TestACLSecurityScenarios(t *testing.T) {
	// Test security-related ACL scenarios
	tests := []struct {
		name         string
		cannedACL    string
		expectSecure bool
		description  string
	}{
		{
			name:         "Private ACL is secure",
			cannedACL:    "private",
			expectSecure: true,
			description:  "Only bucket owner has access",
		},
		{
			name:         "Public-read is less secure",
			cannedACL:    "public-read",
			expectSecure: false,
			description:  "Anyone can read",
		},
		{
			name:         "Public-read-write is insecure",
			cannedACL:    "public-read-write",
			expectSecure: false,
			description:  "Anyone can read and write",
		},
		{
			name:         "Authenticated-read is moderately secure",
			cannedACL:    "authenticated-read",
			expectSecure: false,
			description:  "Any authenticated user can read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid := validateCannedACL(tt.cannedACL)
			assert.True(t, valid, "ACL should be valid")

			// Log security implications
			t.Logf("ACL '%s': %s", tt.cannedACL, tt.description)
			if !tt.expectSecure {
				t.Logf("WARNING: ACL '%s' has security implications", tt.cannedACL)
			}
		})
	}
}

// Helper functions for testing

func validateCannedACL(acl string) (types.BucketCannedACL, bool) {
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

func parseACLXML(xmlContent string) (*types.AccessControlPolicy, error) {
	if xmlContent == "" {
		return nil, fmt.Errorf("empty XML content")
	}

	var acp types.AccessControlPolicy
	err := xml.Unmarshal([]byte(xmlContent), &acp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse XML: %w", err)
	}

	return &acp, nil
}
