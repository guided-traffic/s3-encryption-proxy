//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
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

// Conditional GET and HEAD, checked differentially against the backend the
// proxy fronts.
//
// The oracle is MinIO itself: the same object is written twice, once through
// the proxy into the proxy bucket and once straight into a second bucket, and
// every precondition is then asked of both. Where the two answers disagree the
// table names the deviation, so today's behaviour is pinned and a change shows
// up as a failing test instead of as a silent regression.
//
// What the proxy actually forwards (internal/proxy/handlers/object/operations.go):
//   - handleGetObject  copies only If-Match and If-None-Match onto the backend
//     GetObjectInput. If-Modified-Since and If-Unmodified-Since are dropped.
//   - handleHeadObject builds a HeadObjectInput out of bucket, key and version
//     id only. No conditional header survives, so HEAD answers 200 where GET
//     answers 304 or 412 for the very same precondition.

// condWrongETag is a syntactically valid ETag that no object can carry.
const condWrongETag = `"00000000000000000000000000000000"`

// condPrecondition carries the four conditional headers GET and HEAD accept.
type condPrecondition struct {
	IfMatch           *string
	IfNoneMatch       *string
	IfModifiedSince   *time.Time
	IfUnmodifiedSince *time.Time
}

// condOutcome is the S3-observable result of one conditional request.
type condOutcome struct {
	Status  int
	Code    string
	BodyLen int64
	BodySHA string
}

// condGet issues a conditional GET and reduces the answer to status, error code
// and a digest of whatever body arrived.
func condGet(ctx context.Context, client *s3.Client, bucket, key string, p condPrecondition) condOutcome {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(key),
		IfMatch:           p.IfMatch,
		IfNoneMatch:       p.IfNoneMatch,
		IfModifiedSince:   p.IfModifiedSince,
		IfUnmodifiedSince: p.IfUnmodifiedSince,
	})
	if err != nil {
		return condOutcome{Status: condStatusOf(err), Code: condCodeOf(err)}
	}
	defer out.Body.Close()

	digest := sha256.New()
	n, copyErr := io.Copy(digest, out.Body)
	if copyErr != nil {
		return condOutcome{Status: http.StatusOK, Code: "body-read-error: " + copyErr.Error()}
	}
	return condOutcome{
		Status:  http.StatusOK,
		BodyLen: n,
		BodySHA: hex.EncodeToString(digest.Sum(nil)),
	}
}

// condHead issues the same precondition as a HEAD.
func condHead(ctx context.Context, client *s3.Client, bucket, key string, p condPrecondition) condOutcome {
	out, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(key),
		IfMatch:           p.IfMatch,
		IfNoneMatch:       p.IfNoneMatch,
		IfModifiedSince:   p.IfModifiedSince,
		IfUnmodifiedSince: p.IfUnmodifiedSince,
	})
	if err != nil {
		return condOutcome{Status: condStatusOf(err), Code: condCodeOf(err)}
	}
	return condOutcome{Status: http.StatusOK, BodyLen: aws.ToInt64(out.ContentLength)}
}

// condPutObject stores payload and returns the ETag the caller itself received,
// which is the only ETag a real client can use for a revalidation round trip.
func condPutObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, payload []byte) string {
	t.Helper()

	out, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("application/octet-stream"),
	})
	require.NoError(t, err, "PutObject into %s failed", bucket)
	require.NotNil(t, out.ETag, "PutObject into %s returned no ETag", bucket)
	return aws.ToString(out.ETag)
}

func condStatusOf(err error) int {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode()
	}
	return 0
}

func condCodeOf(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// condPayload builds a deterministic body small enough to be written in a
// single PutObject.
func condPayload() []byte {
	return bytes.Repeat([]byte("s3ep-conditional-request-oracle-payload!"), 1600) // 64000 bytes
}

// TestCondGetAndHeadPreconditions runs the six documented conditional cases
// through the proxy and, for the same object, straight through MinIO.
func TestCondGetAndHeadPreconditions(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// The oracle bucket is spoken to directly, never through the proxy.
	oracleBucket := "cond-oracle-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, oracleBucket)
	defer integration.CleanupTestBucket(t, tc.MinIOClient, oracleBucket)

	key := "cond-" + integration.RandomString(12)
	payload := condPayload()
	plainSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(payload); return s[:] }())

	proxyETag := condPutObject(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload)
	oracleETag := condPutObject(t, ctx, tc.MinIOClient, oracleBucket, key, payload)

	// Each side revalidates with the ETag it was handed, which is the round
	// trip a real client performs. The proxy stores ciphertext, so its ETag is
	// the ciphertext ETag and is expected to differ from the oracle's.
	assert.NotEqual(t, oracleETag, proxyETag,
		"the proxy ETag should describe the stored ciphertext, not the plaintext")

	past := time.Now().Add(-24 * time.Hour).UTC()
	future := time.Now().Add(24 * time.Hour).UTC()

	cases := []struct {
		name string
		// precond is built per target, because the ETag differs per target.
		precond func(etag string) condPrecondition
		// wantAWS is the status AWS S3 documents for this precondition, and the
		// status the MinIO oracle is held to.
		wantAWS int
		// wantProxyGet / wantProxyHead are the statuses the proxy actually
		// returns today. Where they differ from wantAWS, deviation says why.
		wantProxyGet  int
		wantProxyHead int
		getDeviation  string
		headDeviation string
	}{
		{
			name:          "IfNoneMatch_current_etag",
			precond:       func(etag string) condPrecondition { return condPrecondition{IfNoneMatch: aws.String(etag)} },
			wantAWS:       http.StatusNotModified,
			wantProxyGet:  http.StatusNotModified,
			wantProxyHead: http.StatusOK,
			headDeviation: "DEVIATION: handleHeadObject forwards no conditional header, " +
				"so HEAD answers 200 where AWS and MinIO answer 304",
		},
		{
			name:          "IfNoneMatch_wrong_etag",
			precond:       func(string) condPrecondition { return condPrecondition{IfNoneMatch: aws.String(condWrongETag)} },
			wantAWS:       http.StatusOK,
			wantProxyGet:  http.StatusOK,
			wantProxyHead: http.StatusOK,
		},
		{
			name:          "IfMatch_current_etag",
			precond:       func(etag string) condPrecondition { return condPrecondition{IfMatch: aws.String(etag)} },
			wantAWS:       http.StatusOK,
			wantProxyGet:  http.StatusOK,
			wantProxyHead: http.StatusOK,
		},
		{
			name:          "IfMatch_wrong_etag",
			precond:       func(string) condPrecondition { return condPrecondition{IfMatch: aws.String(condWrongETag)} },
			wantAWS:       http.StatusPreconditionFailed,
			wantProxyGet:  http.StatusPreconditionFailed,
			wantProxyHead: http.StatusOK,
			headDeviation: "DEVIATION: handleHeadObject forwards no conditional header, " +
				"so a guarded HEAD answers 200 where AWS and MinIO answer 412",
		},
		{
			name:          "IfModifiedSince_future",
			precond:       func(string) condPrecondition { return condPrecondition{IfModifiedSince: aws.Time(future)} },
			wantAWS:       http.StatusNotModified,
			wantProxyGet:  http.StatusOK,
			wantProxyHead: http.StatusOK,
			getDeviation: "DEVIATION: handleGetObject drops If-Modified-Since, so a " +
				"revalidating GET receives 200 and the whole body where AWS answers 304",
			headDeviation: "DEVIATION: handleHeadObject drops If-Modified-Since as well",
		},
		{
			name:          "IfModifiedSince_past",
			precond:       func(string) condPrecondition { return condPrecondition{IfModifiedSince: aws.Time(past)} },
			wantAWS:       http.StatusOK,
			wantProxyGet:  http.StatusOK,
			wantProxyHead: http.StatusOK,
		},
		{
			name:          "IfUnmodifiedSince_past",
			precond:       func(string) condPrecondition { return condPrecondition{IfUnmodifiedSince: aws.Time(past)} },
			wantAWS:       http.StatusPreconditionFailed,
			wantProxyGet:  http.StatusOK,
			wantProxyHead: http.StatusOK,
			getDeviation: "DEVIATION: handleGetObject drops If-Unmodified-Since, so the " +
				"412 that guards a read against concurrent overwrite never happens",
			headDeviation: "DEVIATION: handleHeadObject drops If-Unmodified-Since as well",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Run("GET", func(t *testing.T) {
				oracle := condGet(ctx, tc.MinIOClient, oracleBucket, key, c.precond(oracleETag))
				proxied := condGet(ctx, tc.ProxyClient, tc.TestBucket, key, c.precond(proxyETag))

				assert.Equalf(t, c.wantAWS, oracle.Status,
					"MinIO oracle answered %d for GET %s (code %q); AWS documents %d",
					oracle.Status, c.name, oracle.Code, c.wantAWS)
				assert.Equalf(t, c.wantProxyGet, proxied.Status,
					"proxy answered %d for GET %s (code %q)", proxied.Status, c.name, proxied.Code)

				if c.getDeviation == "" {
					assert.Equalf(t, oracle.Status, proxied.Status,
						"proxy and backend must agree on GET %s", c.name)
				} else {
					t.Log(c.getDeviation)
				}

				// A 412 must carry the S3 error code clients branch on.
				if oracle.Status == http.StatusPreconditionFailed {
					assert.Equal(t, "PreconditionFailed", oracle.Code, "MinIO 412 error code")
				}
				if proxied.Status == http.StatusPreconditionFailed {
					assert.Equal(t, "PreconditionFailed", proxied.Code, "proxy 412 error code")
				}

				// Whenever a 200 comes back it must carry the full plaintext.
				if oracle.Status == http.StatusOK {
					assert.Equal(t, int64(len(payload)), oracle.BodyLen, "oracle body length")
					assert.Equal(t, plainSHA, oracle.BodySHA, "oracle body digest")
				}
				if proxied.Status == http.StatusOK {
					assert.Equal(t, int64(len(payload)), proxied.BodyLen, "proxy body length")
					assert.Equal(t, plainSHA, proxied.BodySHA, "proxy body digest")
				}
			})

			t.Run("HEAD", func(t *testing.T) {
				oracle := condHead(ctx, tc.MinIOClient, oracleBucket, key, c.precond(oracleETag))
				proxied := condHead(ctx, tc.ProxyClient, tc.TestBucket, key, c.precond(proxyETag))

				assert.Equalf(t, c.wantAWS, oracle.Status,
					"MinIO oracle answered %d for HEAD %s (code %q); AWS documents %d",
					oracle.Status, c.name, oracle.Code, c.wantAWS)
				assert.Equalf(t, c.wantProxyHead, proxied.Status,
					"proxy answered %d for HEAD %s (code %q)", proxied.Status, c.name, proxied.Code)

				if c.headDeviation == "" {
					assert.Equalf(t, oracle.Status, proxied.Status,
						"proxy and backend must agree on HEAD %s", c.name)
				} else {
					t.Log(c.headDeviation)
				}
			})
		})
	}
}

// TestCondETagRoundTripIsSelfConsistent pins the revalidation round trip a real
// client performs: take the ETag the response carried and send it back.
//
// The proxy stores ciphertext, so its ETag is the ciphertext ETag. That is an
// allowed difference from the backend, but only as long as PUT, GET and HEAD
// all report the same value, and only as long as sending it back works.
func TestCondETagRoundTripIsSelfConsistent(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	oracleBucket := "cond-etag-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, oracleBucket)
	defer integration.CleanupTestBucket(t, tc.MinIOClient, oracleBucket)

	key := "cond-etag-" + integration.RandomString(12)
	payload := condPayload()
	plainSHA := hex.EncodeToString(func() []byte { s := sha256.Sum256(payload); return s[:] }())

	proxyPutETag := condPutObject(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload)
	oraclePutETag := condPutObject(t, ctx, tc.MinIOClient, oracleBucket, key, payload)

	// The object really is stored encrypted, which is what makes the ETag
	// difference legitimate rather than a bug.
	atRest, err := tc.MinIOClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "reading the proxy object straight from the backend")
	storedDigest := sha256.New()
	_, err = io.Copy(storedDigest, atRest.Body)
	require.NoError(t, err)
	require.NoError(t, atRest.Body.Close())
	assert.NotEqual(t, plainSHA, hex.EncodeToString(storedDigest.Sum(nil)),
		"the proxy must store ciphertext, otherwise this differential says nothing")

	for _, target := range []struct {
		name    string
		client  *s3.Client
		bucket  string
		putETag string
	}{
		{"proxy", tc.ProxyClient, tc.TestBucket, proxyPutETag},
		{"minio", tc.MinIOClient, oracleBucket, oraclePutETag},
	} {
		t.Run(target.name, func(t *testing.T) {
			get, err := target.client.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(target.bucket), Key: aws.String(key),
			})
			require.NoError(t, err)
			getDigest := sha256.New()
			_, err = io.Copy(getDigest, get.Body)
			require.NoError(t, err)
			require.NoError(t, get.Body.Close())
			assert.Equal(t, plainSHA, hex.EncodeToString(getDigest.Sum(nil)),
				"GET must deliver the plaintext that was written")

			head, err := target.client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(target.bucket), Key: aws.String(key),
			})
			require.NoError(t, err)

			assert.Equal(t, target.putETag, aws.ToString(get.ETag),
				"PUT and GET must report the same ETag")
			assert.Equal(t, target.putETag, aws.ToString(head.ETag),
				"PUT and HEAD must report the same ETag")

			// Sending the received ETag back must revalidate to 304 on GET.
			round := condGet(ctx, target.client, target.bucket, key,
				condPrecondition{IfNoneMatch: aws.String(aws.ToString(get.ETag))})
			assert.Equal(t, http.StatusNotModified, round.Status,
				"If-None-Match with the ETag this client just received must be 304")
		})
	}
}
