//go:build integration

// The sealed plaintext checksum, over the wire (ADR 0003 D13/D14, ADR 0012 D10).
//
// Every write path seals a CRC32C over the whole plaintext into the object's
// trailer. A whole-object GET and a HEAD serve that value back as
// x-amz-checksum-crc32c, and both state the plaintext length the trailer
// authenticates rather than the one the backend reports about itself. The value
// is never in the clear at rest: a checksum lying beside the ciphertext is a
// confirmation oracle for a small or low-entropy object (ADR 0012 D9).
package s3methods

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CksExpected is the value S3 puts in x-amz-checksum-crc32c: base64 of the four
// checksum bytes, big-endian.
func CksExpected(plaintext []byte) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], crc32.Checksum(plaintext, crc32.MakeTable(crc32.Castagnoli)))
	return base64.StdEncoding.EncodeToString(raw[:])
}

// CksPayload is a deterministic pattern of the requested size.
func CksPayload(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*7 + 11)
	}
	return out
}

// TestCksEveryWritePathSealsTheSameChecksum walks the three write paths and
// checks the value the reads serve against a CRC32C the test computes itself.
// The paths produce the same byte layout, so they have to produce the same
// checksum, and a client cannot tell from the answer which one stored the
// object.
func TestCksEveryWritePathSealsTheSameChecksum(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// 13 MiB is above the default streaming_segment_size of 12 MiB, so that one
	// goes through the proxy's own multipart producer rather than a single PUT.
	sizes := map[string]int{
		"single request":    64 * 1024,
		"internal producer": 13 * 1024 * 1024,
	}

	for name, size := range sizes {
		t.Run(name, func(t *testing.T) {
			payload := CksPayload(size)
			key := "cks-" + integration.RandomString(10)
			t.Cleanup(func() { CksDelete(tc, key) })

			_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(tc.TestBucket),
				Key:    aws.String(key),
				Body:   bytes.NewReader(payload),
			})
			require.NoError(t, err, "PUT through the proxy")

			CksAssertServedChecksum(t, ctx, tc, key, payload)
		})
	}

	t.Run("client-driven multipart", func(t *testing.T) {
		// 5 MiB is the backend's minimum part size and a whole number of 64 KiB
		// segments, so it is a layout the proxy can store; the last part is short
		// and is held until Complete, where the trailer rides on it.
		const partSize = 5 * 1024 * 1024
		payload := CksPayload(2*partSize + 4096)
		key := "cks-mpu-" + integration.RandomString(10)
		t.Cleanup(func() { CksDelete(tc, key) })

		created, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err, "CreateMultipartUpload")
		uploadID := aws.ToString(created.UploadId)

		var completed []types.CompletedPart
		for i := 0; i*partSize < len(payload); i++ {
			end := min((i+1)*partSize, len(payload))
			part, uerr := tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     aws.String(tc.TestBucket),
				Key:        aws.String(key),
				UploadId:   aws.String(uploadID),
				PartNumber: aws.Int32(int32(i + 1)),
				Body:       bytes.NewReader(payload[i*partSize : end]),
			})
			require.NoErrorf(t, uerr, "UploadPart %d", i+1)
			completed = append(completed, types.CompletedPart{
				PartNumber: aws.Int32(int32(i + 1)), ETag: part.ETag,
			})
		}

		_, err = tc.ProxyClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:          aws.String(tc.TestBucket),
			Key:             aws.String(key),
			UploadId:        aws.String(uploadID),
			MultipartUpload: &types.CompletedMultipartUpload{Parts: completed},
		})
		require.NoError(t, err, "CompleteMultipartUpload")

		CksAssertServedChecksum(t, ctx, tc, key, payload)
	})
}

// CksAssertServedChecksum is the shared check: GET and HEAD agree with each
// other and with the CRC32C of the plaintext, a ranged read carries none, and
// the value is nowhere in the stored bytes.
func CksAssertServedChecksum(
	t *testing.T, ctx context.Context, tc *integration.TestContext, key string, payload []byte,
) {
	t.Helper()
	want := CksExpected(payload)

	get, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "GET through the proxy")
	body, err := io.ReadAll(get.Body)
	require.NoError(t, err, "reading the object")
	require.NoError(t, get.Body.Close())

	assert.Equal(t, EncSHA256(payload), EncSHA256(body), "the object did not read back intact")
	assert.Equal(t, want, aws.ToString(get.ChecksumCRC32C), "GET must serve the sealed checksum")
	assert.Equal(t, int64(len(payload)), aws.ToInt64(get.ContentLength),
		"the length served is the one the trailer authenticates")

	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "HEAD through the proxy")
	assert.Equal(t, want, aws.ToString(head.ChecksumCRC32C), "HEAD and GET must state the same checksum")
	assert.Equal(t, int64(len(payload)), aws.ToInt64(head.ContentLength))

	// A checksum over part of an object says nothing about the object, so a
	// ranged read carries none (ADR 0012).
	ranged, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Range: aws.String("bytes=0-63"),
	})
	require.NoError(t, err, "ranged GET through the proxy")
	_, _ = io.Copy(io.Discard, ranged.Body)
	require.NoError(t, ranged.Body.Close())
	assert.Empty(t, aws.ToString(ranged.ChecksumCRC32C), "a ranged read must carry no checksum")

	// At rest the value is sealed inside the trailer, never beside it: a
	// cleartext checksum of a small object is a guessing oracle for the backend.
	stored, err := tc.MinIOClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "reading the stored object directly from the backend")
	raw, err := io.ReadAll(stored.Body)
	require.NoError(t, err)
	require.NoError(t, stored.Body.Close())

	var plain [4]byte
	binary.BigEndian.PutUint32(plain[:], crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli)))
	assert.NotContains(t, string(raw), string(plain[:]),
		"the plaintext checksum is readable in the stored bytes")
	for name, value := range stored.Metadata {
		assert.NotContains(t, value, want, "the checksum leaked into metadata key %q", name)
	}
}

// TestCksSuffixRangeLargerThanTheObject pins what a backend answers when a
// suffix range covers the whole object, because that is the shape every
// whole-object read now asks for first.
func TestCksSuffixRangeLargerThanTheObject(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := CksPayload(1024)
	key := "cks-suffix-" + integration.RandomString(10)
	t.Cleanup(func() { CksDelete(tc, key) })

	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key), Body: bytes.NewReader(payload),
	})
	require.NoError(t, err, "PUT through the proxy")

	// Through the proxy: a suffix larger than the plaintext is the whole object.
	out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Range: aws.String(fmt.Sprintf("bytes=-%d", 10*len(payload))),
	})
	require.NoError(t, err, "suffix range larger than the object")
	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	require.NoError(t, out.Body.Close())
	assert.Equal(t, EncSHA256(payload), EncSHA256(body))

	// Directly at the backend, against the stored object: this is the answer the
	// proxy's own tail read depends on. MinIO answers 206 with a Content-Range
	// naming the whole object.
	storedLen := CksStoredLength(t, ctx, tc, key)
	raw, err := tc.MinIOClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Range: aws.String(fmt.Sprintf("bytes=-%d", 10*storedLen)),
	})
	require.NoError(t, err, "the backend refused a suffix range larger than the object")
	rawBody, err := io.ReadAll(raw.Body)
	require.NoError(t, err)
	require.NoError(t, raw.Body.Close())
	assert.Equal(t, storedLen, int64(len(rawBody)), "the backend returned the whole stored object")
	assert.NotEmpty(t, aws.ToString(raw.ContentRange),
		"the backend states a Content-Range, which is where the stored length comes from")
}

// CksStoredLength reports what the backend holds for this key.
func CksStoredLength(t *testing.T, ctx context.Context, tc *integration.TestContext, key string) int64 {
	t.Helper()
	head, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "HEAD directly against the backend")
	return aws.ToInt64(head.ContentLength)
}

// CksDelete removes a test object through the backend.
func CksDelete(tc *integration.TestContext, key string) {
	delCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = tc.MinIOClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
}

// TestCksPartNumberTenThousandIsRefused: the proxy keeps the last part number
// for the object's trailer, so a client-driven upload has 9999 (ADR 0011 D4).
// Refusing it when the part is sent is the point — the alternative is a failure
// at Complete, after every byte has been transferred.
func TestCksPartNumberTenThousandIsRefused(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	key := "cks-partnumber-" + integration.RandomString(10)
	created, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "CreateMultipartUpload")
	uploadID := aws.ToString(created.UploadId)
	t.Cleanup(func() {
		abortCtx, cancelAbort := context.WithTimeout(context.Background(), time.Minute)
		defer cancelAbort()
		_, _ = tc.ProxyClient.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
	})

	_, err = tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(10000),
		Body:       bytes.NewReader(CksPayload(1024)),
	})
	require.Error(t, err, "part 10000 must be refused: the trailer needs that number")
	assert.Equal(t, 400, EncHTTPStatus(err))
	assert.Equal(t, "InvalidArgument", EncAPICode(err))

	// 9999 is the client's upper bound and is accepted.
	_, err = tc.ProxyClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(9999),
		Body:       bytes.NewReader(CksPayload(1024)),
	})
	require.NoError(t, err, "9999 is a part number a client may use")
}
