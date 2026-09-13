//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
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

// Versioned buckets. Nothing in this repository created one before, so the whole
// versionId path was asserted at handler level against mocks and never once
// against a backend that keeps versions — and a mock returns the version id the
// test told it to return, which proves the plumbing and nothing about the
// backend.
//
// Versioning is enabled with the MinIO client, not through the proxy:
// PUT /{bucket}?versioning answers 501 for any non-empty body, and every real
// client sends <VersioningConfiguration><Status>Enabled</Status>.
//
// Teardown is HdrCleanupBucket, which walks ListObjectVersions. The shared
// CleanupTestBucket deletes without a versionId, which on a versioned bucket
// writes delete markers instead of removing versions; the DeleteBucket that
// follows then fails with BucketNotEmpty and its error is only logged, so the
// bucket would pile up in MinIO from run to run with nothing failing.

// vbNewVersionedBucket creates a bucket, turns versioning on at the backend and
// registers a teardown that can actually remove it.
func vbNewVersionedBucket(t *testing.T, ctx context.Context, tc *integration.TestContext) string {
	t.Helper()

	name := "vb-" + integration.RandomString(12)
	_, err := tc.MinIOClient.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
	require.NoError(t, err, "create versioned bucket %s", name)
	t.Cleanup(func() { HdrCleanupBucket(t, tc.MinIOClient, name) })

	_, err = tc.MinIOClient.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(name),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	require.NoError(t, err, "this backend has to keep versions; without that there is no oracle here")

	status, err := tc.MinIOClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(name),
	})
	require.NoError(t, err)
	require.Equal(t, types.BucketVersioningStatusEnabled, status.Status)
	return name
}

func vbSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// vbPut uploads through the proxy and returns the version id the write reported.
func vbPut(t *testing.T, ctx context.Context, tc *integration.TestContext, bucket, key string, body []byte) string {
	t.Helper()
	out, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	require.NoError(t, err)
	versionID := aws.ToString(out.VersionId)
	require.NotEmpty(t, versionID, "a versioned bucket has to report a version id on PUT")
	return versionID
}

// A dropped versionId serves the current version, which only a second version
// can expose. The ranged read is asserted separately because handleGetObjectRange
// passes the parameter on two separate backend requests.
func TestVbVersionIdAddressesTheVersionItNames(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	bucket := vbNewVersionedBucket(t, ctx, tc)

	key := "vb-two-versions-" + integration.RandomString(8)
	first := bytes.Repeat([]byte("first-version-payload!"), 3000)  // 66000 bytes, over one segment
	second := bytes.Repeat([]byte("second-version-payload"), 3000) // same length, different bytes
	require.Equal(t, len(first), len(second), "equal lengths, so only the bytes distinguish them")

	firstVersion := vbPut(t, ctx, tc, bucket, key, first)
	secondVersion := vbPut(t, ctx, tc, bucket, key, second)
	require.NotEqual(t, firstVersion, secondVersion)

	for name, tc2 := range map[string]struct {
		version string
		want    []byte
	}{
		"the older version":             {firstVersion, first},
		"the newer version":             {secondVersion, second},
		"no version is the current one": {"", second},
	} {
		t.Run(name, func(t *testing.T) {
			input := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
			if tc2.version != "" {
				input.VersionId = aws.String(tc2.version)
			}
			out, err := tc.ProxyClient.GetObject(ctx, input)
			require.NoError(t, err)
			defer func() { _ = out.Body.Close() }()
			body, err := io.ReadAll(out.Body)
			require.NoError(t, err)

			assert.Equal(t, vbSHA(tc2.want), vbSHA(body), "the wrong version was served")
			if tc2.version != "" {
				assert.Equal(t, tc2.version, aws.ToString(out.VersionId),
					"the response must name the version it served")
			}

			head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: input.Bucket, Key: input.Key, VersionId: input.VersionId,
			})
			require.NoError(t, err)
			assert.Equal(t, int64(len(tc2.want)), aws.ToInt64(head.ContentLength),
				"HEAD reports the plaintext length of the version it was asked for")
		})
	}

	// A ranged read of the older version. The plaintext window straddles the
	// 64 KiB segment boundary, which is where the chain arithmetic can go wrong,
	// and the request costs two backend calls on this path.
	t.Run("ranged read of the older version", func(t *testing.T) {
		const from, to = 65500, 65700
		out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: aws.String(firstVersion),
			Range:     aws.String(fmt.Sprintf("bytes=%d-%d", from, to)),
		})
		require.NoError(t, err)
		defer func() { _ = out.Body.Close() }()
		body, err := io.ReadAll(out.Body)
		require.NoError(t, err)

		assert.Equal(t, vbSHA(first[from:to+1]), vbSHA(body),
			"a ranged read of an older version served the wrong bytes")
	})

	t.Run("suffix range of the older version", func(t *testing.T) {
		out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:    aws.String(bucket),
			Key:       aws.String(key),
			VersionId: aws.String(firstVersion),
			Range:     aws.String("bytes=-64"),
		})
		require.NoError(t, err)
		defer func() { _ = out.Body.Close() }()
		body, err := io.ReadAll(out.Body)
		require.NoError(t, err)

		assert.Equal(t, vbSHA(first[len(first)-64:]), vbSHA(body),
			"the suffix path resolves the length with its own HEAD, which needs the versionId too")
	})
}

// DELETE without a versionId writes a delete marker; the previous version has to
// stay readable by id, and deleting that id has to remove it.
func TestVbDeleteMarkerAndVersionDelete(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	bucket := vbNewVersionedBucket(t, ctx, tc)

	key := "vb-delete-marker-" + integration.RandomString(8)
	payload := []byte("the version a delete marker must not destroy")
	version := vbPut(t, ctx, tc, bucket, key, payload)

	deleted, err := tc.ProxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.True(t, aws.ToBool(deleted.DeleteMarker),
		"x-amz-delete-marker must reach the client, or it cannot tell a delete from a marker")
	assert.NotEmpty(t, aws.ToString(deleted.VersionId), "the marker has a version id of its own")

	// The current version is now the marker.
	_, err = tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.Error(t, err, "reading the current version of a deleted key must fail")

	// The version itself is untouched.
	out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
	})
	require.NoError(t, err, "the previous version must still read by id")
	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	_ = out.Body.Close()
	assert.Equal(t, vbSHA(payload), vbSHA(body))

	// And deleting that id removes it.
	_, err = tc.ProxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
	})
	require.NoError(t, err)

	_, err = tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(version),
	})
	assert.Error(t, err, "the version the client deleted by id must be gone")
}

// An encrypted multipart upload writes exactly ONE version. Every metadata value
// exists before the first backend byte, so nothing rewrites the finished object
// to attach it — this is the test that fails if anyone reintroduces a
// post-completion rewrite (ADR 0011 D8, ADR 0024).
func TestVbMultipartUploadLeavesExactlyOneVersion(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	bucket := vbNewVersionedBucket(t, ctx, tc)

	key := "vb-multipart-" + integration.RandomString(8)
	// Above the demo stack's 12 MiB streaming_segment_size, so the request takes
	// the internal multipart producer rather than the single-request path.
	payload := vbPayload(16 << 20)

	out, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
		Body:               bytes.NewReader(payload),
		ContentLength:      aws.Int64(int64(len(payload))),
		ContentType:        aws.String("application/pdf"),
		CacheControl:       aws.String("max-age=4242"),
		ContentDisposition: aws.String(`attachment; filename="producer.pdf"`),
	})
	require.NoError(t, err)
	putETag := aws.ToString(out.ETag)
	putVersion := aws.ToString(out.VersionId)
	require.NotEmpty(t, putVersion)

	versions, err := tc.MinIOClient.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket), Prefix: aws.String(key),
	})
	require.NoError(t, err)
	assert.Len(t, versions.Versions, 1,
		"a multipart upload must leave exactly one version; a second one means something rewrote the object")
	assert.Empty(t, versions.DeleteMarkers)
	require.Len(t, versions.Versions, 1)
	assert.Equal(t, putVersion, aws.ToString(versions.Versions[0].VersionId),
		"the version CompleteMultipartUpload reported is the one that exists")

	// The encryption metadata sits on that one version.
	stored, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(putVersion),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, stored.Metadata["s3ep-encrypted-dek"], "metadata: %v", stored.Metadata)
	assert.NotEmpty(t, stored.Metadata["s3ep-kek-fingerprint"])
	assert.Equal(t, "s3ep-gcm-seg-v2", stored.Metadata["s3ep-dek-algorithm"])

	// And the object reads back, whole.
	got, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer func() { _ = got.Body.Close() }()
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, vbSHA(payload), vbSHA(body))

	// Item 24: the entity headers and the ETag on the producer path, over the
	// wire. Nothing in this suite used to upload past streaming_segment_size, so
	// the four headers putObjectAutoMultipart sets ran under no test but a mock.
	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.Equal(t, "application/pdf", aws.ToString(head.ContentType))
	assert.Equal(t, "max-age=4242", aws.ToString(head.CacheControl))
	assert.Equal(t, `attachment; filename="producer.pdf"`, aws.ToString(head.ContentDisposition))
	assert.Equal(t, putETag, aws.ToString(head.ETag),
		"the ETag the PUT returned has to be the one the stored object carries")
	assert.Equal(t, int64(len(payload)), aws.ToInt64(head.ContentLength),
		"HEAD reports the plaintext length")
}

// The client-driven multipart path, which is a third copy of the same header
// block, gets the same treatment on a versioned bucket.
func TestVbClientDrivenMultipartEntityHeaders(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	bucket := vbNewVersionedBucket(t, ctx, tc)

	key := "vb-client-mpu-" + integration.RandomString(8)
	part := vbPayload(6 << 20) // over the 5 MiB S3 minimum for a non-final part

	create, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
		ContentType:        aws.String("text/csv"),
		CacheControl:       aws.String("no-store"),
		ContentDisposition: aws.String(`attachment; filename="client.csv"`),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	up, err := tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(part),
		ContentLength: aws.Int64(int64(len(part))),
	})
	require.NoError(t, err)

	done, err := tc.ProxyClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{PartNumber: aws.Int32(1), ETag: up.ETag},
		}},
	})
	require.NoError(t, err)
	assert.Contains(t, aws.ToString(done.Location), key,
		"<Location> names the object, at the proxy's own address")

	versions, err := tc.MinIOClient.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket), Prefix: aws.String(key),
	})
	require.NoError(t, err)
	assert.Len(t, versions.Versions, 1, "one upload, one version")

	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.Equal(t, "text/csv", aws.ToString(head.ContentType))
	assert.Equal(t, "no-store", aws.ToString(head.CacheControl))
	assert.Equal(t, `attachment; filename="client.csv"`, aws.ToString(head.ContentDisposition))
	assert.Equal(t, int64(len(part)), aws.ToInt64(head.ContentLength))

	got, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer func() { _ = got.Body.Close() }()
	body, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	assert.Equal(t, vbSHA(part), vbSHA(body))
}

// The copy refusals, finished. Both verbs already answer 422 over the wire; what
// was missing is the assertion that the refusal left nothing behind.
func TestVbRefusedCopiesLeaveNothingBehind(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	source := "vb-copy-source-" + integration.RandomString(8)
	payload := []byte("the object a refused copy must not duplicate")
	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(source),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)

	t.Run("CopyObject across buckets", func(t *testing.T) {
		// A future implementation that handles only the same-bucket case must not
		// pass this.
		destBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)
		destKey := "vb-copy-dest-" + integration.RandomString(8)

		_, err := tc.ProxyClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket: aws.String(destBucket), Key: aws.String(destKey),
			CopySource: aws.String(tc.TestBucket + "/" + source),
		})
		require.Error(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, httpStatusOf(err))
		assert.Equal(t, "NotSupportedWithEncryption", apiCodeOf(err))

		_, err = tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(destBucket), Key: aws.String(destKey),
		})
		assert.Error(t, err, "the refused copy must not have created the destination")
	})

	t.Run("UploadPartCopy leaves no part on the upload", func(t *testing.T) {
		destKey := "vb-partcopy-dest-" + integration.RandomString(8)
		create, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(destKey),
		})
		require.NoError(t, err)
		uploadID := aws.ToString(create.UploadId)
		defer func() {
			_, _ = tc.ProxyClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(destKey),
				UploadId: aws.String(uploadID),
			})
		}()

		_, err = tc.ProxyClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(destKey),
			UploadId: aws.String(uploadID), PartNumber: aws.Int32(1),
			CopySource: aws.String(tc.TestBucket + "/" + source),
		})
		require.Error(t, err)
		assert.Equal(t, http.StatusUnprocessableEntity, httpStatusOf(err))
		assert.Equal(t, "NotSupportedWithEncryption", apiCodeOf(err))

		// The original bug stored an EMPTY part rather than none, so "no part" is
		// the assertion, not "a part of size 0". Read from the backend, because
		// the proxy's own ListParts answers a constant empty document.
		parts, err := tc.MinIOClient.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(destKey),
			UploadId: aws.String(uploadID),
		})
		require.NoError(t, err)
		assert.Empty(t, parts.Parts, "the refused part copy left a part on the upload")
	})
}

// vbPayload is compressible-but-not-uniform filler, sized exactly.
func vbPayload(size int) []byte {
	const unit = "s3ep-versioned-bucket-payload-"
	out := make([]byte, 0, size+len(unit))
	for len(out) < size {
		out = append(out, unit...)
	}
	return out[:size]
}
