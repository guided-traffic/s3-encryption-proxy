//go:build integration

package variants

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/require"
)

// TestRangeReadsOnEncryptedObjects covers partial reads of encrypted objects.
//
// This is not an academic case: kopia, the uploader Velero uses for volume data,
// reads its pack blobs with small ranged GETs (GetBlob(id, offset, length)).
// While the proxy rejected ranges, every kopia-based Velero restore failed with
// "Range requests are not currently supported for encrypted objects".
//
// The two encryption paths behave differently and both are covered here: AES-CTR
// is seekable and is served from a ranged backend read, AES-GCM is not and is
// served by decrypting the object and slicing the plaintext.
func TestRangeReadsOnEncryptedObjects(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// Sizes chosen around the default optimizations.streaming_threshold (5 MiB):
	// below it PutObject takes the buffered AES-GCM path, above it the streaming
	// AES-CTR path.
	objects := []struct {
		name string
		size int
	}{
		{"gcm_small_1kb", 1024},
		{"gcm_medium_1mb", 1 << 20},
		{"ctr_above_threshold_6mb", 6 << 20},
		{"ctr_large_20mb", 20 << 20},
	}

	for _, obj := range objects {
		t.Run(obj.name, func(t *testing.T) {
			payload := make([]byte, obj.size)
			_, err := rand.Read(payload)
			require.NoError(t, err)

			key := fmt.Sprintf("range-read-%s-%d", obj.name, time.Now().UnixNano())
			_, err = tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket:        aws.String(tc.TestBucket),
				Key:           aws.String(key),
				Body:          bytes.NewReader(payload),
				ContentLength: aws.Int64(int64(len(payload))),
			})
			require.NoError(t, err, "upload")

			t.Cleanup(func() {
				_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket),
					Key:    aws.String(key),
				})
			})

			// Tail window sized to the object so it stays valid for the small ones.
			tailStart := obj.size - 4096
			if tailStart < 0 {
				tailStart = obj.size / 2
			}

			ranges := []struct {
				name   string
				header string
				start  int
				length int
			}{
				{"first_byte", "bytes=0-0", 0, 1},
				{"first_kb", "bytes=0-1023", 0, 1024},
				{"kopia_style_32_bytes_at_32", "bytes=32-63", 32, 32},
				{"mid_object_unaligned", "bytes=4097-8192", 4097, 4096},
				{"small_object_unaligned", "bytes=17-517", 17, 501},
				{"crosses_block_boundary", "bytes=15-17", 15, 3},
				{"last_100_bytes_suffix", "bytes=-100", obj.size - 100, 100},
				{"open_ended_tail", fmt.Sprintf("bytes=%d-", tailStart), tailStart, obj.size - tailStart},
				{"whole_object", fmt.Sprintf("bytes=0-%d", obj.size-1), 0, obj.size},
				{"last_byte", fmt.Sprintf("bytes=%d-%d", obj.size-1, obj.size-1), obj.size - 1, 1},
			}

			for _, rg := range ranges {
				if rg.start < 0 || rg.start+rg.length > obj.size {
					continue // range does not apply to an object this small
				}
				t.Run(rg.name, func(t *testing.T) {
					out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
						Bucket: aws.String(tc.TestBucket),
						Key:    aws.String(key),
						Range:  aws.String(rg.header),
					})
					require.NoErrorf(t, err, "ranged GET %s", rg.header)
					defer out.Body.Close()

					got, err := io.ReadAll(out.Body)
					require.NoError(t, err)

					want := payload[rg.start : rg.start+rg.length]
					require.Equalf(t, len(want), len(got),
						"range %s returned the wrong number of bytes", rg.header)
					require.Equalf(t, sha256.Sum256(want), sha256.Sum256(got),
						"range %s decrypted to the wrong bytes", rg.header)

					require.NotNil(t, out.ContentRange, "a 206 response must carry Content-Range")
					require.Equalf(t,
						fmt.Sprintf("bytes %d-%d/%d", rg.start, rg.start+rg.length-1, obj.size),
						aws.ToString(out.ContentRange),
						"Content-Range must describe plaintext offsets and the plaintext total")
				})
			}

			// Many small sequential reads, the way kopia walks a pack blob.
			t.Run("many_small_reads_reassemble_the_object", func(t *testing.T) {
				const chunk = 64 * 1024
				limit := 512 * 1024
				if obj.size < limit {
					limit = obj.size
				}
				var assembled bytes.Buffer
				for off := 0; off < limit; off += chunk {
					end := off + chunk - 1
					if end > limit-1 {
						end = limit - 1
					}
					out, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
						Bucket: aws.String(tc.TestBucket),
						Key:    aws.String(key),
						Range:  aws.String(fmt.Sprintf("bytes=%d-%d", off, end)),
					})
					require.NoError(t, err)
					_, err = assembled.ReadFrom(out.Body)
					out.Body.Close()
					require.NoError(t, err)
				}
				require.Equal(t, sha256.Sum256(payload[:limit]), sha256.Sum256(assembled.Bytes()),
					"sequential ranged reads did not reassemble the original bytes")
			})
		})
	}
}

// Ranges outside the object must produce the S3 answer, not a decryption error.
func TestRangeReadErrors(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := make([]byte, 4096)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	key := fmt.Sprintf("range-error-%d", time.Now().UnixNano())
	_, err = tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(tc.TestBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)
	defer func() {
		_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	}()

	t.Run("range_past_end_of_object", func(t *testing.T) {
		_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(tc.TestBucket),
			Key:    aws.String(key),
			Range:  aws.String("bytes=99999-199999"),
		})
		require.Error(t, err, "a range past the end of the object must be rejected")
		require.Contains(t, err.Error(), "416", "expected 416 Range Not Satisfiable")
	})

	t.Run("range_on_a_missing_key", func(t *testing.T) {
		_, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(tc.TestBucket),
			Key:    aws.String("does-not-exist-" + integration.RandomString(8)),
			Range:  aws.String("bytes=0-99"),
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "404",
			"a ranged read of a missing key must be a 404, not an internal error")
	})
}
