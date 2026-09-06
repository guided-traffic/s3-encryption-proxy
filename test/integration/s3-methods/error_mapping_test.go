//go:build integration

package s3methods

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Backend errors have to keep their status and code on the way through the
// proxy. They did not: a type switch on the error value never matched the
// wrapped SDK error, so every backend answer, a plain 404 included, reached the
// client as 500 InternalError carrying the raw SDK text.
//
// Velero depends on the distinction: probing for a backup object that does not
// exist yet is a normal branch for it, and a 500 turns that into a failure.
func TestBackendErrorsKeepTheirStatusAndCode(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	missingKey := "definitely-not-here-" + integration.RandomString(12)
	missingBucket := "no-such-bucket-" + integration.RandomString(12)

	cases := []struct {
		name       string
		call       func() error
		wantStatus int
		wantCode   string
	}{
		{
			name: "GetObject_on_a_missing_key",
			call: func() error {
				_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(missingKey),
				})
				return err
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchKey",
		},
		{
			name: "HeadObject_on_a_missing_key",
			call: func() error {
				_, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(missingKey),
				})
				return err
			},
			wantStatus: http.StatusNotFound,
			// HEAD carries no body, so the SDK reports the generic NotFound.
			wantCode: "NotFound",
		},
		{
			name: "GetObject_in_a_missing_bucket",
			call: func() error {
				_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(missingBucket), Key: aws.String("k"),
				})
				return err
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchBucket",
		},
		{
			name: "UploadPart_with_an_unknown_upload_id",
			call: func() error {
				_, err := tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:     aws.String(tc.TestBucket),
					Key:        aws.String("k"),
					UploadId:   aws.String("not-a-real-upload-id"),
					PartNumber: aws.Int32(1),
					Body:       strings.NewReader("data"),
				})
				return err
			},
			// The proxy rejects an unknown upload id before it reaches the
			// backend, so this asserts only that it is a client error.
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "ListObjectsV2_in_a_missing_bucket",
			call: func() error {
				_, err := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
					Bucket: aws.String(missingBucket),
				})
				return err
			},
			wantStatus: http.StatusNotFound,
			wantCode:   "NoSuchBucket",
		},
	}

	for _, tc2 := range cases {
		t.Run(tc2.name, func(t *testing.T) {
			err := tc2.call()
			require.Error(t, err, "the call was expected to fail")

			status := httpStatusOf(err)
			assert.Equalf(t, tc2.wantStatus, status,
				"wrong HTTP status for %s: %v", tc2.name, err)

			if tc2.wantCode != "" {
				assert.Equalf(t, tc2.wantCode, apiCodeOf(err),
					"wrong S3 error code for %s: %v", tc2.name, err)
			}

			// The proxy must not hand the backend's identifiers to the client.
			assert.NotContains(t, apiMessageOf(err), "operation error",
				"the response message leaks SDK plumbing text")
			assert.NotContains(t, apiMessageOf(err), "HostID",
				"the response message leaks the backend HostID")
		})
	}
}

// Conditional requests must map onto their own statuses rather than a blanket
// 500. Velero and other clients branch on 304 and 412.
func TestConditionalRequestErrors(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	key := fmt.Sprintf("conditional-%d", time.Now().UnixNano())
	put, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(tc.TestBucket),
		Key:           aws.String(key),
		Body:          strings.NewReader("hello conditional world"),
		ContentLength: aws.Int64(int64(len("hello conditional world"))),
	})
	require.NoError(t, err)
	require.NotNil(t, put.ETag)

	t.Run("if_match_with_a_wrong_etag", func(t *testing.T) {
		_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:  aws.String(tc.TestBucket),
			Key:     aws.String(key),
			IfMatch: aws.String(`"00000000000000000000000000000000"`),
		})
		require.Error(t, err)
		assert.Equal(t, http.StatusPreconditionFailed, httpStatusOf(err),
			"a failed If-Match must be 412, not 500")
	})

	t.Run("if_none_match_with_the_current_etag", func(t *testing.T) {
		_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:      aws.String(tc.TestBucket),
			Key:         aws.String(key),
			IfNoneMatch: put.ETag,
		})
		require.Error(t, err)
		assert.Equal(t, http.StatusNotModified, httpStatusOf(err),
			"a matching If-None-Match must be 304, not 500")
	})

	t.Cleanup(func() {
		_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})
}

func httpStatusOf(err error) int {
	var respErr *awshttp.ResponseError
	if errorsAs(err, &respErr) {
		return respErr.HTTPStatusCode()
	}
	return 0
}

func apiCodeOf(err error) string {
	var apiErr smithy.APIError
	if errorsAs(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

func apiMessageOf(err error) string {
	var apiErr smithy.APIError
	if errorsAs(err, &apiErr) {
		return apiErr.ErrorMessage()
	}
	return ""
}

// errorsAs is errors.As, named locally so the intent (unwrap the SDK chain) is
// visible at every call site.
func errorsAs(err error, target interface{}) bool { return errors.As(err, target) }
