//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three object sub-resources ADR 0007 D4 makes passthrough: ?tagging,
// ?retention and ?legal-hold. All three used to answer 501, and before that
// something worse - ?legal-hold always set the hold ON whatever the body said.
//
// Every assertion reads the result back **directly from MinIO**, so what is
// proven is that the request reached the backend, not that the proxy echoed the
// document it was handed.

func TestSubpassObjectTaggingRoundTrip(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	key := "subpass-tagging-" + integration.RandomString(10)
	payload := []byte("tags travel to the backend in the clear, on a ciphertext object")
	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)

	_, err = tc.ProxyClient.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Tagging: &types.Tagging{TagSet: []types.Tag{
			{Key: aws.String("project"), Value: aws.String("conformance")},
			{Key: aws.String("stage"), Value: aws.String("test")},
		}},
	})
	require.NoError(t, err, "PUT ?tagging is passthrough, not 501")

	backend, err := tc.MinIOClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.Len(t, backend.TagSet, 2, "the tags reached the backend")

	// And the proxy reads back what the backend holds, as an S3 document the SDK
	// can parse - not the SDK output struct marshalled by Go field name.
	through, err := tc.ProxyClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.Len(t, through.TagSet, 2)
	assert.ElementsMatch(t, subpassTagPairs(backend.TagSet), subpassTagPairs(through.TagSet))

	_, err = tc.ProxyClient.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)

	cleared, err := tc.MinIOClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.Empty(t, cleared.TagSet, "DELETE ?tagging reached the backend")
}

func TestSubpassRetentionAndLegalHoldRoundTrip(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// Object lock needs a bucket that was created with it enabled, which is a
	// property of the bucket and not of the object.
	lockBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, true)

	key := "subpass-lock-" + integration.RandomString(10)
	payload := []byte("WORM on the ciphertext defends the credential, not the backend")
	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)

	retainUntil := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	_, err = tc.ProxyClient.PutObjectRetention(ctx, &s3.PutObjectRetentionInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
		Retention: &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionModeGovernance,
			RetainUntilDate: aws.Time(retainUntil),
		},
	})
	require.NoError(t, err, "PUT ?retention is passthrough, not 501")

	stored, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.Equal(t, types.ObjectLockModeGovernance, stored.ObjectLockMode)
	require.NotNil(t, stored.ObjectLockRetainUntilDate)
	assert.Equal(t, retainUntil, stored.ObjectLockRetainUntilDate.UTC().Truncate(time.Second))

	readBack, err := tc.ProxyClient.GetObjectRetention(ctx, &s3.GetObjectRetentionInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.NotNil(t, readBack.Retention)
	assert.Equal(t, types.ObjectLockRetentionModeGovernance, readBack.Retention.Mode)
	require.NotNil(t, readBack.Retention.RetainUntilDate)
	assert.Equal(t, retainUntil, readBack.Retention.RetainUntilDate.UTC().Truncate(time.Second))

	// The legal hold is the case the old handler got wrong: it read the body,
	// discarded it and always sent Status=On, so a release applied a hold.
	_, err = tc.ProxyClient.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
		LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOn},
	})
	require.NoError(t, err)

	held, err := tc.MinIOClient.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.NotNil(t, held.LegalHold)
	assert.Equal(t, types.ObjectLockLegalHoldStatusOn, held.LegalHold.Status)

	_, err = tc.ProxyClient.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
		LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff},
	})
	require.NoError(t, err)

	released, err := tc.MinIOClient.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.NotNil(t, released.LegalHold)
	assert.Equal(t, types.ObjectLockLegalHoldStatusOff, released.LegalHold.Status,
		"a request to release a hold must release it, not apply one")

	// And through the proxy's own read.
	throughProxy, err := tc.ProxyClient.GetObjectLegalHold(ctx, &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(lockBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	require.NotNil(t, throughProxy.LegalHold)
	assert.Equal(t, types.ObjectLockLegalHoldStatusOff, throughProxy.LegalHold.Status)
}

// A document the proxy cannot parse is MalformedXML through the proxy's own
// error document, not a bare transport error (ADR 0007 D5, D8).
func TestSubpassMalformedSubResourceDocumentIsMalformedXML(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	key := "subpass-malformed-" + integration.RandomString(10)
	payload := []byte("the object the malformed requests are aimed at")
	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)

	for _, sub := range []string{"tagging", "retention", "legal-hold"} {
		t.Run(sub, func(t *testing.T) {
			status, body := hdrSignedPutQuery(t, "/"+tc.TestBucket+"/"+key, sub,
				[]byte("<not-a-document"), nil)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Contains(t, string(body), "MalformedXML")
		})
	}
}

func subpassTagPairs(tags []types.Tag) []string {
	pairs := make([]string, 0, len(tags))
	for _, tag := range tags {
		pairs = append(pairs, aws.ToString(tag.Key)+"="+aws.ToString(tag.Value))
	}
	return pairs
}
