package request

import "strings"

// awsProtocolQueryPrefix is the namespace AWS uses for protocol parameters in a
// query string: the SigV4 pre-signing set (X-Amz-Algorithm, X-Amz-Credential,
// X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature,
// X-Amz-Security-Token) and whatever the SDK adds beside them - aws-sdk-go-v2
// puts X-Amz-Checksum-Mode into every pre-signed GetObject URL, for instance.
const awsProtocolQueryPrefix = "x-amz-"

// IsAWSProtocolQueryParam reports whether a query parameter belongs to the AWS
// protocol namespace rather than naming an S3 sub-resource.
//
// The sub-resource guards in the bucket and object handlers refuse any parameter
// they do not recognise, because running the base operation instead is how
// "DELETE /bucket?encryption" deleted the bucket. That guard must not refuse the
// protocol parameters an ordinary client sends: an allowlist of literal names
// went stale the moment the SDK added one, which is what refused every
// pre-signed download over X-Amz-Checksum-Mode.
//
// Admitting the whole namespace is safe on both counts that matter. No S3
// sub-resource is named "x-amz-*" - they are plain names like acl, tagging or
// uploads - so nothing destructive can enter through it. And every query
// parameter except X-Amz-Signature itself goes into the canonical query string
// that the signature covers (buildPresignedCanonicalRequest in
// internal/proxy/middleware/s3auth_presigned.go), so a parameter cannot be added
// or altered by anyone who cannot already sign the request.
//
// The comparison is case-insensitive because SigV4 canonicalisation is
// case-sensitive on the name but clients differ on the casing they send.
func IsAWSProtocolQueryParam(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), awsProtocolQueryPrefix)
}
