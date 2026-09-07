package request

import "testing"

// The literal allowlists these guards used to carry went stale the moment the
// SDK added a parameter: aws-sdk-go-v2 puts X-Amz-Checksum-Mode into every
// pre-signed GetObject URL, so the object guard answered NotImplemented to every
// pre-signed download and Velero could not fetch a backup log.
func TestReqIsAWSProtocolQueryParam(t *testing.T) {
	protocol := []string{
		"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
		"X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Security-Token",
		// The one that broke the pre-signed path.
		"X-Amz-Checksum-Mode",
		// Casing varies between clients; SigV4 signs the name as sent.
		"x-amz-checksum-mode", "X-AMZ-CHECKSUM-MODE",
		// Anything the SDK adds next must be admitted without a code change.
		"X-Amz-Some-Future-Parameter",
	}
	for _, name := range protocol {
		t.Run("admits "+name, func(t *testing.T) {
			if !IsAWSProtocolQueryParam(name) {
				t.Errorf("%q is an AWS protocol parameter and must not be refused as a sub-resource", name)
			}
		})
	}

	// No S3 sub-resource is named x-amz-*, and the guard must keep refusing the
	// ones that are: running the base operation instead is how DELETE
	// /bucket?encryption deleted the bucket.
	subResources := []string{
		"acl", "tagging", "legal-hold", "retention", "torrent", "select",
		"restore", "uploads", "versions", "encryption", "policy", "lifecycle",
		"publicAccessBlock", "ownershipControls", "partNumber", "uploadId",
		"versionId", "x-id", "list-type", "prefix",
		// Near misses that must not be admitted by a sloppy prefix test.
		"xamz-acl", "amz-acl", "x-amz", "x_amz-acl", "ax-amz-acl",
	}
	for _, name := range subResources {
		t.Run("refuses "+name, func(t *testing.T) {
			if IsAWSProtocolQueryParam(name) {
				t.Errorf("%q is not an AWS protocol parameter; admitting it widens the sub-resource guard", name)
			}
		})
	}
}
