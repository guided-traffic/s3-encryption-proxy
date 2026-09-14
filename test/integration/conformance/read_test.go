//go:build conformance

package conformance

import (
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestObjectsRoundTripByHash reads every corpus object back and compares it to
// the content its key defines. It writes nothing.
func TestObjectsRoundTripByHash(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	for _, obj := range Corpus {
		t.Run(obj.Key, func(t *testing.T) {
			out, err := proxy.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(Bucket),
				Key:    aws.String(Key(obj.Key)),
			})
			require.NoError(t, err)
			defer out.Body.Close()

			got, err := io.ReadAll(out.Body)
			require.NoError(t, err)

			assert.Equal(t, SHA256(Content(obj.Key, obj.Size)), SHA256(got),
				"%s round trips unchanged (%s)", obj.Key, obj.Why)
			assert.Equal(t, obj.Size, int64(len(got)))
			assert.Equal(t, obj.Size, aws.ToInt64(out.ContentLength),
				"Content-Length is the plaintext length, not the stored length")
		})
	}
}

// TestStoredBytesAreCiphertext reads the objects straight from the backend and
// asserts the proxy never handed it plaintext. This is the product's central
// claim, so it is checked against whatever backend the run uses rather than
// trusted from one.
//
// The corpus content is readable ASCII precisely so this assertion means
// something: a plaintext that was already random would pass an entropy check no
// matter what the proxy did.
func TestStoredBytesAreCiphertext(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	backend := BackendClient(t)

	for _, obj := range Corpus {
		if obj.Size == 0 {
			continue // a chain of no segments carries no ciphertext to inspect
		}
		t.Run(obj.Key, func(t *testing.T) {
			out, err := backend.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(Bucket),
				Key:    aws.String(Key(obj.Key)),
			})
			require.NoError(t, err, "reading the stored object directly from %s", BackendName)
			defer out.Body.Close()

			stored, err := io.ReadAll(out.Body)
			require.NoError(t, err)

			plaintext := Content(obj.Key, obj.Size)
			assert.NotEqual(t, SHA256(plaintext), SHA256(stored),
				"the backend holds the plaintext of %s", obj.Key)
			assert.Greater(t, int64(len(stored)), obj.Size,
				"the stored object carries the segment overhead and the trailer")
			assert.NotContains(t, string(stored), "s3ep conformance corpus",
				"the corpus marker is readable in what %s stored", BackendName)
		})
	}
}

// TestWholeObjectReadStatesTheSealedChecksum covers the tail-first read: both
// verbs answer the CRC32C the object's own trailer carries, and the plaintext
// length that trailer authenticates.
func TestWholeObjectReadStatesTheSealedChecksum(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	// seg-plus-one is the first size whose read costs two backend requests, and
	// tiny is the last that costs one. Both must answer the same way.
	for _, name := range []string{"tiny", "seg-plus-one", "mpu-client"} {
		t.Run(name, func(t *testing.T) {
			size := corpusSize(t, name)

			get, err := proxy.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(Bucket),
				Key:    aws.String(Key(name)),
			})
			require.NoError(t, err)
			defer get.Body.Close()
			body, err := io.ReadAll(get.Body)
			require.NoError(t, err)
			require.Equal(t, SHA256(Content(name, size)), SHA256(body))
			assert.NotEmpty(t, aws.ToString(get.ChecksumCRC32C),
				"a whole-object GET answers the sealed CRC32C")

			head, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(Bucket),
				Key:    aws.String(Key(name)),
			})
			require.NoError(t, err)
			assert.Equal(t, size, aws.ToInt64(head.ContentLength))
			assert.Equal(t, aws.ToString(get.ChecksumCRC32C), aws.ToString(head.ChecksumCRC32C),
				"GET and HEAD state the same sealed checksum")
		})
	}
}

// TestRangedReadsAddressPlaintextCoordinates walks the interesting offsets of
// the segment chain: inside one segment, across a boundary, a suffix range and
// an open-ended one. The proxy computes the stored window itself, so a range
// that lands wrong is an arithmetic bug rather than a backend difference.
func TestRangedReadsAddressPlaintextCoordinates(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	const seg = 65536
	size := corpusSize(t, "seg-three")
	full := Content("seg-three", size)

	cases := []struct {
		name        string
		header      string
		from, until int64
	}{
		{"inside the first segment", "bytes=0-99", 0, 100},
		{"across the first boundary", fmt.Sprintf("bytes=%d-%d", seg-10, seg+9), seg - 10, seg + 10},
		{"a whole middle segment", fmt.Sprintf("bytes=%d-%d", seg, 2*seg-1), seg, 2 * seg},
		{"the last byte", fmt.Sprintf("bytes=%d-%d", size-1, size-1), size - 1, size},
		{"a suffix range", "bytes=-100", size - 100, size},
		{"open ended", fmt.Sprintf("bytes=%d-", size-50), size - 50, size},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := proxy.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(Bucket),
				Key:    aws.String(Key("seg-three")),
				Range:  aws.String(tc.header),
			})
			require.NoError(t, err)
			defer out.Body.Close()
			got, err := io.ReadAll(out.Body)
			require.NoError(t, err)

			assert.Equal(t, SHA256(full[tc.from:tc.until]), SHA256(got), "%s", tc.header)
			assert.Equal(t, tc.until-tc.from, aws.ToInt64(out.ContentLength))
			assert.NotEmpty(t, aws.ToString(out.ContentRange),
				"a 206 carries a Content-Range")
			assert.Empty(t, aws.ToString(out.ChecksumCRC32C),
				"a range carries no checksum: the sealed one describes the whole object")
		})
	}
}

// TestListingReportsPlaintextSizes covers the listing document. The sizes are
// the point: a listing that reported stored lengths would have every client
// computing the wrong thing.
func TestListingReportsPlaintextSizes(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	out, err := proxy.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(Bucket),
		Prefix: aws.String(KeyPrefix + "list/"),
	})
	require.NoError(t, err)
	require.Len(t, out.Contents, ListCorpusSize)

	for _, entry := range out.Contents {
		assert.Equal(t, int64(1), aws.ToInt64(entry.Size),
			"%s is one plaintext byte, whatever the chain stored for it",
			aws.ToString(entry.Key))
	}

	t.Run("pagination", func(t *testing.T) {
		page, perr := proxy.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:  aws.String(Bucket),
			Prefix:  aws.String(KeyPrefix + "list/"),
			MaxKeys: aws.Int32(4),
		})
		require.NoError(t, perr)
		assert.Len(t, page.Contents, 4)
		assert.True(t, aws.ToBool(page.IsTruncated))
		require.NotEmpty(t, aws.ToString(page.NextContinuationToken))

		rest, rerr := proxy.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(Bucket),
			Prefix:            aws.String(KeyPrefix + "list/"),
			ContinuationToken: page.NextContinuationToken,
		})
		require.NoError(t, rerr)
		assert.Len(t, rest.Contents, ListCorpusSize-4)
	})
}

func corpusSize(t *testing.T, name string) int64 {
	t.Helper()
	for _, obj := range Corpus {
		if obj.Key == name {
			return obj.Size
		}
	}
	t.Fatalf("no corpus object named %q", name)
	return 0
}
