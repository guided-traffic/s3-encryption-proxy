//go:build integration
// +build integration

package variants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// TestDEKCacheReuploadRegression covers ticket 011: the DEK cache used to be
// keyed only on (fingerprint, objectKey), so a re-upload — which produces a
// fresh DEK and a fresh encryptedDEK blob — would still hit the previous
// entry on GET. The download was then decrypted with the wrong DEK, producing
// garbage plaintext and tripping HMAC verification.
//
// The fix (ticket 011, Option A) hashes the encryptedDEK into the cache key
// so a fresh upload cannot collide with a stale entry. This test asserts that
// the second download returns the second upload's content.
func TestDEKCacheReuploadRegression(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "create proxy client")

	const bucket = "dek-cache-reupload-regression"
	integration.SetupTestBucket(t, ctx, proxyClient, bucket)
	defer integration.CleanupTestBucket(t, proxyClient, bucket)

	// Two scenarios cover both encryption paths the cache feeds into:
	// - "single-part": small object → AES-GCM single-part
	// - "multipart":   >5 MB object via real multipart upload → AES-CTR
	t.Run("single-part_GCM", func(t *testing.T) {
		const key = "reupload-singlepart"
		first := makePattern(8*1024, 0xA1)
		second := makePattern(8*1024, 0xB2)
		runReuploadCycle(t, ctx, proxyClient, bucket, key, first, second, putSinglePart)
	})

	t.Run("multipart_CTR", func(t *testing.T) {
		const key = "reupload-multipart"
		// Two parts of 6 MB each; both must clear the 5 MB minimum part size.
		first := makePattern(12*1024*1024, 0xC3)
		second := makePattern(12*1024*1024, 0xD4)
		runReuploadCycle(t, ctx, proxyClient, bucket, key, first, second, putMultipartTwoParts)
	})
}

// runReuploadCycle encodes the bug repro: PUT first → GET (warms the DEK
// cache) → PUT second → GET → assert second GET matches second PUT.
func runReuploadCycle(
	t *testing.T,
	ctx context.Context,
	client *s3.Client,
	bucket, key string,
	first, second []byte,
	put func(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte),
) {
	t.Helper()

	put(t, ctx, client, bucket, key, first)
	requireDownloadHashEquals(t, ctx, client, bucket, key, sha256.Sum256(first),
		"first download must match first upload (warms the DEK cache)")

	put(t, ctx, client, bucket, key, second)
	requireDownloadHashEquals(t, ctx, client, bucket, key, sha256.Sum256(second),
		"second download must match second upload (regression: stale DEK)")
}

func putSinglePart(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte) {
	t.Helper()
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(body),
	})
	require.NoError(t, err, "PutObject %s/%s", bucket, key)
}

func putMultipartTwoParts(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte) {
	t.Helper()

	create, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "CreateMultipartUpload")
	uploadID := create.UploadId

	half := len(body) / 2
	parts := [][]byte{body[:half], body[half:]}
	completed := make([]types.CompletedPart, 0, len(parts))

	for i, part := range parts {
		partNum := int32(i + 1)
		resp, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(key),
			UploadId:   uploadID,
			PartNumber: aws.Int32(partNum),
			Body:       bytes.NewReader(part),
		})
		require.NoError(t, err, "UploadPart %d", partNum)
		completed = append(completed, types.CompletedPart{
			ETag:       resp.ETag,
			PartNumber: aws.Int32(partNum),
		})
	}

	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
	})
	require.NoError(t, err, "CompleteMultipartUpload")
}

func requireDownloadHashEquals(
	t *testing.T,
	ctx context.Context,
	client *s3.Client,
	bucket, key string,
	expected [32]byte,
	msg string,
) {
	t.Helper()
	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "GetObject %s/%s", bucket, key)
	defer resp.Body.Close()

	h := sha256.New()
	_, err = io.Copy(h, resp.Body)
	require.NoError(t, err, "drain GetObject body")

	var got [32]byte
	copy(got[:], h.Sum(nil))
	require.Equal(t, fmt.Sprintf("%x", expected), fmt.Sprintf("%x", got), msg)
}

// makePattern builds a deterministic byte slice whose contents differ between
// uploads so a stale-DEK hit is guaranteed to produce a hash mismatch.
func makePattern(size int, seed byte) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}
