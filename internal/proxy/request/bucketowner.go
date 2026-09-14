package request

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ExpectedBucketOwner returns the x-amz-expected-bucket-owner precondition of a
// request, or nil when the client sent none.
//
// It is a guard rather than a preference, and it is the one header whose drop
// fails open: S3 answers 403 AccessDenied when the bucket belongs to another
// account, which is what defends a client against writing to, reading from or
// deleting a bucket name someone else re-created. A proxy that drops it runs the
// operation and answers success, so the client believes it is guarded and is
// not. Every backend call made on a client's behalf carries it (ADR 0007 D14).
//
// One reader for every verb on purpose: the guard is only worth what its
// weakest verb honours, so a client that sees it work on HEAD must not find it
// ignored on PUT.
func ExpectedBucketOwner(r *http.Request) *string {
	if owner := r.Header.Get("x-amz-expected-bucket-owner"); owner != "" {
		return aws.String(owner)
	}
	return nil
}
