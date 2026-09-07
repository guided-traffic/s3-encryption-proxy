//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An object sub-resource that has a route in router.go but not for the method
// used falls through gorilla/mux to the catch-all object route, where it used to
// execute the BASE operation for that verb. DELETE /bucket/key?legal-hold
// therefore deleted the object, and PUT /bucket/key?partNumber=abc replaced the
// whole object with a single part body.
//
// It is the same defect that made DELETE /bucket?encryption delete the bucket,
// which was fixed for buckets and left live for objects. These tests drive the
// real proxy over HTTP, because the point is the interaction between the router
// and the handler and a handler-level test cannot see it.
func subrefPutObject(t *testing.T, tc *integration.TestContext, key string, body []byte) {
	t.Helper()
	_, err := tc.ProxyClient.PutObject(tc.Ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(key),
		Body:   bytesReaderSubref(body),
	})
	require.NoError(t, err)
}

func bytesReaderSubref(b []byte) io.Reader { return bytes.NewReader(b) }

// subrefDigest reads the object back through the proxy and returns its sha256,
// which is how these tests assert the object is intact rather than dumping bytes.
func subrefDigest(t *testing.T, tc *integration.TestContext, key string) string {
	t.Helper()
	out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "the object must still be readable")
	defer out.Body.Close()

	sum := sha256.New()
	_, err = io.Copy(sum, out.Body)
	require.NoError(t, err)
	return fmt.Sprintf("%x", sum.Sum(nil))
}

// subrefRaw sends a request the AWS SDK will not construct, signed with the
// proxy credentials, and returns the status code.
func subrefRaw(t *testing.T, method, bucket, key, query string, body []byte) int {
	t.Helper()
	status, _ := subrefRawWithBody(t, method, bucket, key, query, body)
	return status
}

// subrefRawWithBody is subrefRaw plus the response body, for the cases that have
// to assert the S3 error code and not only the status.
func subrefRawWithBody(t *testing.T, method, bucket, key, query string, body []byte) (int, string) {
	t.Helper()
	target := fmt.Sprintf("%s/%s/%s?%s", integration.ProxyEndpoint, bucket, key, query)

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	require.NoError(t, err)
	req.ContentLength = int64(len(body))

	payloadHash := fmt.Sprintf("%x", sha256.Sum256(body))
	require.NoError(t, integration.SignHTTPRequestForS3WithCredentials(req, payloadHash))

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(responseBody)
}

// TestSubrefUnroutedSubResourcesDoNotDestroyTheObject is the regression test for
// the data-loss half. Every one of these requests used to delete the object.
func TestSubrefUnroutedSubResourcesDoNotDestroyTheObject(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := []byte("the object that must survive every one of these requests")
	want := fmt.Sprintf("%x", sha256.Sum256(payload))

	for _, sub := range []string{"legal-hold", "retention", "torrent", "restore", "select", "uploads"} {
		t.Run("DELETE_"+sub, func(t *testing.T) {
			key := "subref-delete-" + sub + "-" + integration.RandomString(8)
			subrefPutObject(t, tc, key, payload)

			status := subrefRaw(t, http.MethodDelete, tc.TestBucket, key, sub, nil)

			assert.NotEqual(t, http.StatusNoContent, status,
				"a sub-resource DELETE must not be answered as a successful object delete")
			assert.Contains(t, []int{http.StatusMethodNotAllowed, http.StatusNotImplemented}, status,
				"expected a refusal, got %d", status)

			assert.Equal(t, want, subrefDigest(t, tc, key),
				"the object must be byte-identical after the refused request")
		})
	}
}

// TestSubrefMalformedPartNumberDoesNotOverwriteTheObject covers the second half:
// the router requires partNumber to match [0-9]+, so a value that does not match
// arrived at the base handler as an ordinary PUT and the part body replaced the
// entire object.
func TestSubrefMalformedPartNumberDoesNotOverwriteTheObject(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := []byte("original object contents, must not be replaced by a part body")
	want := fmt.Sprintf("%x", sha256.Sum256(payload))

	key := "subref-partnumber-" + integration.RandomString(8)
	subrefPutObject(t, tc, key, payload)

	status, responseBody := subrefRawWithBody(t, http.MethodPut, tc.TestBucket, key,
		"partNumber=abc&uploadId=not-a-real-upload", []byte("PART BODY"))

	// D-27: AWS answers InvalidArgument for this shape. It used to be answered
	// 200 with the part body stored as the whole object, and between 568db10 and
	// D-27 it was 501.
	assert.Equal(t, http.StatusBadRequest, status,
		"a malformed part upload must be answered InvalidArgument")
	assert.Contains(t, responseBody, "InvalidArgument")
	assert.Equal(t, want, subrefDigest(t, tc, key),
		"the object must be byte-identical after the refused part upload")
}

// TestSubrefLegitimateParametersStillWork guards the other direction: the refusal
// must not turn ordinary reads into errors. A guard that is too broad is an
// outage, so the parameters a base object operation really carries are asserted
// to still reach it.
func TestSubrefLegitimateParametersStillWork(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := []byte("plain object read with legitimate query parameters")
	want := fmt.Sprintf("%x", sha256.Sum256(payload))

	key := "subref-legit-" + integration.RandomString(8)
	subrefPutObject(t, tc, key, payload)

	// The SDK appends x-id itself, so a plain GET already exercises that one.
	assert.Equal(t, want, subrefDigest(t, tc, key))

	for _, query := range []string{
		"x-id=GetObject",
		"response-content-type=text%2Fplain",
		// Deliberately without an encoded space. A value containing %20 is
		// answered 403 by the proxy signature check, which is a canonicalisation
		// question of its own and is recorded in ticket 024 rather than mixed
		// into this regression test.
		"response-content-disposition=inline",
		"versionId=null",
	} {
		t.Run(query, func(t *testing.T) {
			status := subrefRaw(t, http.MethodGet, tc.TestBucket, key, query, nil)
			assert.Equal(t, http.StatusOK, status,
				"a legitimate base-operation parameter must still be served")
		})
	}
}
