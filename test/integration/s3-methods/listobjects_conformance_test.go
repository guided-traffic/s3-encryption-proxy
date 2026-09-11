//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Listing conformance (ADR 0010).
//
// This file used to pin the proxy's deviations: a root element named after the
// Go SDK output type with no namespace, start-after / max-keys / fetch-owner /
// encoding-type silently dropped, <Owner> carrying the backend account, and a
// <Size> that reported the stored ciphertext length. Those tests asserted the
// wrong behaviour on purpose, as a baseline. The rewrite landed, so each of them
// is gone and what stands here is the corrected behaviour - with the reason the
// old answer was wrong kept next to the assertion that replaced it.
//
// Two rules run through the file:
//
//   - Where the DOCUMENT is the subject - root element, namespace, element order
//     - the assertion is on the raw response body. aws-sdk-go-v2 matches elements
//     by local name and ignores both the root and the order, which is precisely
//     why the old document passed every SDK-level test in the suite.
//   - Content is compared by SHA-256, never by dumping bytes.
//
// Every expected value here comes from the code or from a measurement against
// the demo MinIO (2026-09-10), never from the AWS documentation.
// ---------------------------------------------------------------------------

const (
	// lstEmptyPayloadSHA256 is the SigV4 payload hash of an empty body.
	lstEmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	// lstFramingOverhead is what the storage format costs an object that fits in
	// one segment: one segment's nonce and tag plus the sealed trailer.
	lstFramingOverhead = int64(dataencryption.SegmentOverhead + dataencryption.TrailerSize)

	// lstBulkObjects is the size of the shared pagination fixture: enough to need
	// three pages at the 1000-key limit.
	lstBulkObjects = 2500
)

// lstV2ElementOrder is the order MinIO emits a V2 listing in, measured against
// the demo backend. EncodingType is LAST, after CommonPrefixes, and
// NextContinuationToken comes BEFORE KeyCount - both are easy to get wrong and
// neither is visible through the SDK.
var lstV2ElementOrder = []string{
	"Name", "Prefix", "StartAfter", "ContinuationToken", "NextContinuationToken",
	"KeyCount", "MaxKeys", "Delimiter", "IsTruncated", "Contents", "CommonPrefixes", "EncodingType",
}

// lstV1ElementOrder is the same for a V1 listing: a marker instead of the
// continuation tokens, and no KeyCount at all. The root element is
// ListBucketResult in both versions.
var lstV1ElementOrder = []string{
	"Name", "Prefix", "Marker", "NextMarker", "MaxKeys", "Delimiter",
	"IsTruncated", "Contents", "CommonPrefixes", "EncodingType",
}

// lstContentsElementOrder is the order inside one <Contents>. Owner sits between
// Size and StorageClass.
var lstContentsElementOrder = []string{"Key", "LastModified", "ETag", "Size", "Owner", "StorageClass"}

// lstLastModifiedPattern is the timestamp shape S3 emits: RFC 3339 with exactly
// three fractional digits.
var lstLastModifiedPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// lstBody builds deterministic pseudo-random content of the requested length.
// Content is compared by SHA-256, so the bytes only have to be reproducible.
func lstBody(seed string, n int64) []byte {
	b := make([]byte, n)
	x := uint32(2166136261)
	for _, c := range []byte(seed) {
		x = (x ^ uint32(c)) * 16777619
	}
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

// lstCiphertextSize is the stored length of an object with this plaintext
// length. It is the production arithmetic the listing inverts.
func lstCiphertextSize(t *testing.T, plaintext int64) int64 {
	t.Helper()
	stored, err := dataencryption.CiphertextSize(plaintext)
	require.NoErrorf(t, err, "CiphertextSize(%d)", plaintext)
	return stored
}

// lstKeysOf extracts the keys of a listing page, in the order returned.
func lstKeysOf(contents []s3types.Object) []string {
	keys := make([]string, 0, len(contents))
	for _, o := range contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys
}

// lstPrefixesOf extracts the common prefixes of a listing page.
func lstPrefixesOf(prefixes []s3types.CommonPrefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, aws.ToString(p.Prefix))
	}
	sort.Strings(out)
	return out
}

// lstSizeOf returns the Size a listing reported for key.
func lstSizeOf(t *testing.T, contents []s3types.Object, key string) int64 {
	t.Helper()
	for _, o := range contents {
		if aws.ToString(o.Key) == key {
			return aws.ToInt64(o.Size)
		}
	}
	t.Fatalf("key %q is not in the listing", key)
	return 0
}

// lstListSizes lists a whole bucket through client and maps key to reported size.
func lstListSizes(t *testing.T, ctx context.Context, client *s3.Client, bucket string) map[string]int64 {
	t.Helper()
	sizes := make(map[string]int64)
	var token *string
	for {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket), ContinuationToken: token,
		})
		require.NoErrorf(t, err, "listing %s", bucket)
		for _, o := range out.Contents {
			sizes[aws.ToString(o.Key)] = aws.ToInt64(o.Size)
		}
		if !aws.ToBool(out.IsTruncated) {
			return sizes
		}
		token = out.NextContinuationToken
	}
}

// lstPut writes one object through client.
func lstPut(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte) {
	t.Helper()
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	require.NoErrorf(t, err, "PUT %q", key)
}

// lstGet reads one object back through client and returns its bytes.
func lstGet(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "GET %q", key)
	body, err := io.ReadAll(out.Body)
	require.NoErrorf(t, err, "reading %q", key)
	require.NoError(t, out.Body.Close())
	return body
}

// lstMultipartPut uploads body as a client-driven multipart upload.
func lstMultipartPut(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, body []byte, partSize int) {
	t.Helper()

	create, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "CreateMultipartUpload %q", key)
	uploadID := aws.ToString(create.UploadId)
	require.NotEmpty(t, uploadID)

	var parts []s3types.CompletedPart
	for i := 0; i*partSize < len(body); i++ {
		start := i * partSize
		end := start + partSize
		if end > len(body) {
			end = len(body)
		}
		number := int32(i + 1)
		out, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(number),
			Body:          bytes.NewReader(body[start:end]),
			ContentLength: aws.Int64(int64(end - start)),
		})
		require.NoErrorf(t, err, "UploadPart %d of %q", number, key)
		parts = append(parts, s3types.CompletedPart{ETag: out.ETag, PartNumber: aws.Int32(number)})
	}

	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts},
	})
	require.NoErrorf(t, err, "CompleteMultipartUpload %q", key)
}

// lstPurgeBucket empties and removes a bucket. The shared helper in
// test/integration only deletes the first page, which is not enough for the
// 2500-object fixture below.
func lstPurgeBucket(t *testing.T, client *s3.Client, bucket string) {
	t.Helper()
	integration.PurgeBucket(t, client, bucket)
}

// lstRawRequest issues a signed request without the SDK and returns the raw
// answer. Everything that asserts on the document itself goes through here:
// aws-sdk-go-v2 hides the root element, the namespace and the element order.
// There is no PresignListObjectsV2 in this SDK version, so the header signer is
// the way in.
func lstRawRequest(t *testing.T, method, endpoint, path, rawQuery, accessKey, secretKey string) (int, http.Header, []byte) {
	t.Helper()

	target := endpoint + path
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req, err := http.NewRequest(method, target, nil)
	require.NoErrorf(t, err, "building %s %s", method, target)
	require.NoError(t,
		integration.SignHTTPRequestForS3(req, accessKey, secretKey, integration.TestRegion, lstEmptyPayloadSHA256),
		"signing %s %s", method, target)

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoErrorf(t, err, "%s %s", method, target)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoErrorf(t, err, "reading the answer to %s %s", method, target)
	return resp.StatusCode, resp.Header, body
}

// lstProxyGet is lstRawRequest against the proxy with the proxy's credentials.
func lstProxyGet(t *testing.T, path, rawQuery string) (int, http.Header, []byte) {
	t.Helper()
	return lstRawRequest(t, http.MethodGet, integration.ProxyEndpoint, path, rawQuery,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey)
}

// lstElementSequence returns the child elements of the document root in document
// order, collapsing a run of repeats (a listing carries many <Contents>).
func lstElementSequence(t *testing.T, doc []byte) []string {
	t.Helper()

	decoder := xml.NewDecoder(bytes.NewReader(doc))
	var seq []string
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "the response must be well-formed XML")

		switch element := token.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && (len(seq) == 0 || seq[len(seq)-1] != element.Name.Local) {
				seq = append(seq, element.Name.Local)
			}
		case xml.EndElement:
			depth--
		}
	}
	return seq
}

// lstChildElements returns the child elements of the first element named parent.
func lstChildElements(t *testing.T, doc []byte, parent string) []string {
	t.Helper()

	decoder := xml.NewDecoder(bytes.NewReader(doc))
	var out []string
	depth, inside := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		require.NoError(t, err, "the response must be well-formed XML")

		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch {
			case inside == 0 && element.Name.Local == parent:
				inside = depth
			case inside > 0 && depth == inside+1:
				out = append(out, element.Name.Local)
			}
		case xml.EndElement:
			if inside > 0 && depth == inside {
				return out
			}
			depth--
		}
	}
	return out
}

// lstAssertElementOrder fails unless actual is a subsequence of canonical: every
// element the document carries has to be one S3 defines, and they have to appear
// in S3's order. Optional elements may be absent; nothing may be extra, and
// nothing may be out of place.
func lstAssertElementOrder(t *testing.T, what string, actual, canonical []string) {
	t.Helper()

	next := 0
	for _, name := range actual {
		found := false
		for ; next < len(canonical); next++ {
			if canonical[next] == name {
				next++
				found = true
				break
			}
		}
		require.Truef(t, found,
			"%s: <%s> is unknown or out of order.\n  document: %v\n  S3 order: %v",
			what, name, actual, canonical)
	}
}

// ---------------------------------------------------------------------------
// The shared pagination fixture: 2500 one-byte objects in an a/, b/, c/x/ layout
// with a handful of keys at the root. It is the largest fixture in the file, so
// every paging and filtering subtest works on this one bucket.
// ---------------------------------------------------------------------------

type lstBulkFixture struct {
	ctx    context.Context
	tc     *integration.TestContext
	bucket string
	keys   []string // every key written, in S3 listing order
}

// lstBulkKeys is the layout: three directories and a flat tail, chosen so that
// bytewise key order is also the order the groups are declared in.
func lstBulkKeys() []string {
	keys := make([]string, 0, lstBulkObjects)
	for i := 0; i < 800; i++ {
		keys = append(keys, fmt.Sprintf("a/k%04d", i))
	}
	for i := 0; i < 800; i++ {
		keys = append(keys, fmt.Sprintf("b/k%04d", i))
	}
	for i := 0; i < 800; i++ {
		keys = append(keys, fmt.Sprintf("c/x/k%04d", i))
	}
	for i := 0; i < 100; i++ {
		keys = append(keys, fmt.Sprintf("root-k%04d", i))
	}
	sort.Strings(keys)
	return keys
}

func lstNewBulkFixture(t *testing.T) *lstBulkFixture {
	t.Helper()
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	t.Cleanup(cancel)

	tc := integration.NewTestContextWithTimeout(t, ctx)
	t.Cleanup(func() { lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket) })

	keys := lstBulkKeys()
	require.Len(t, keys, lstBulkObjects)

	// In parallel: 2500 sequential PUTs would dominate the runtime of the whole
	// file, and every subtest below shares this one fixture.
	const workers = 24
	work := make(chan string)
	failures := make(chan error, len(keys))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for key := range work {
				_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
					Bucket:        aws.String(tc.TestBucket),
					Key:           aws.String(key),
					Body:          bytes.NewReader([]byte{'x'}),
					ContentLength: aws.Int64(1),
				})
				if err != nil {
					failures <- fmt.Errorf("PUT %q through the proxy: %w", key, err)
				}
			}
		}()
	}
	for _, key := range keys {
		work <- key
	}
	close(work)
	wg.Wait()
	close(failures)
	for err := range failures {
		require.NoError(t, err)
	}

	return &lstBulkFixture{ctx: ctx, tc: tc, bucket: tc.TestBucket, keys: keys}
}

// TestLstListingPagesAndFilters covers everything that decides WHICH keys a
// listing returns: the continuation token, the delimiter, max-keys in all its
// forms and start-after. The old file pinned start-after and max-keys as
// silently dropped - a client paging by key got the same first page forever, and
// asking for zero keys returned up to a thousand.
func TestLstListingPagesAndFilters(t *testing.T) {
	f := lstNewBulkFixture(t)

	t.Run("pagination_follows_the_continuation_token_to_exhaustion", func(t *testing.T) {
		var (
			got       []string
			seen      = make(map[string]int, len(f.keys))
			truncated []bool
			token     *string
			pages     int
		)
		for pages < 10 {
			out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
				Bucket:            aws.String(f.bucket),
				MaxKeys:           aws.Int32(1000),
				ContinuationToken: token,
			})
			require.NoError(t, err, "paged listing must succeed")
			pages++

			assert.Equal(t, int32(1000), aws.ToInt32(out.MaxKeys),
				"<MaxKeys> echoes the requested page size")
			assert.LessOrEqual(t, len(out.Contents), 1000,
				"a page must not exceed max-keys")
			assert.Equal(t, int32(len(out.Contents)), aws.ToInt32(out.KeyCount),
				"<KeyCount> counts the entries on the page")
			if token == nil {
				assert.Empty(t, aws.ToString(out.ContinuationToken),
					"the first page carries no <ContinuationToken>")
			} else {
				assert.Equal(t, aws.ToString(token), aws.ToString(out.ContinuationToken),
					"<ContinuationToken> echoes the token the client sent")
			}

			for _, key := range lstKeysOf(out.Contents) {
				got = append(got, key)
				seen[key]++
			}
			truncated = append(truncated, aws.ToBool(out.IsTruncated))

			if !aws.ToBool(out.IsTruncated) {
				assert.Empty(t, aws.ToString(out.NextContinuationToken),
					"the last page must not carry a continuation token")
				break
			}
			require.NotEmpty(t, aws.ToString(out.NextContinuationToken),
				"a truncated page must carry <NextContinuationToken>")
			token = out.NextContinuationToken
		}

		require.Equal(t, 3, pages, "2500 keys at 1000 per page are three pages")
		assert.Equal(t, []bool{true, true, false}, truncated,
			"IsTruncated is true until the last page")
		assert.Equal(t, f.keys, got,
			"the pages together are the whole bucket, in key order")
		assert.Len(t, seen, len(f.keys), "the pages dropped or duplicated keys")
		for key, times := range seen {
			assert.Equalf(t, 1, times, "key %q appeared on more than one page", key)
		}
	})

	t.Run("delimiter_rolls_directories_into_common_prefixes", func(t *testing.T) {
		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)

		assert.Equal(t, []string{"a/", "b/", "c/"}, lstPrefixesOf(out.CommonPrefixes),
			"every directory must collapse into a common prefix")

		keys := lstKeysOf(out.Contents)
		assert.Len(t, keys, 100, "only the keys without a delimiter stay in Contents")
		for _, key := range keys {
			assert.NotContainsf(t, key, "/",
				"key %q carries the delimiter and belongs in CommonPrefixes, not in Contents", key)
		}

		assert.Equal(t, int32(len(keys)+len(out.CommonPrefixes)), aws.ToInt32(out.KeyCount),
			"KeyCount counts Contents plus CommonPrefixes")
		assert.False(t, aws.ToBool(out.IsTruncated), "103 entries fit in one page")
		assert.Equal(t, "/", aws.ToString(out.Delimiter), "<Delimiter> is echoed")

		// The backend read directly is the oracle for the rollup itself.
		reference, err := f.tc.MinIOClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)
		assert.Equal(t, lstKeysOf(reference.Contents), keys,
			"proxy and backend disagree on which keys survive the delimiter")
		assert.Equal(t, lstPrefixesOf(reference.CommonPrefixes), lstPrefixesOf(out.CommonPrefixes),
			"proxy and backend disagree on the common prefixes")
	})

	t.Run("max_keys_1_pages_one_key_at_a_time", func(t *testing.T) {
		var (
			got   []string
			token *string
		)
		// One page more than there are keys: measured against the demo backend,
		// the page carrying the LAST key still reports IsTruncated and hands out a
		// token, and the page after it is empty. That is the backend's boundary
		// behaviour - a direct listing does exactly the same - and the proxy
		// forwards it, so the loop has to tolerate one empty terminal page.
		for page := 0; page <= len(f.keys); page++ {
			out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
				Bucket:            aws.String(f.bucket),
				MaxKeys:           aws.Int32(1),
				ContinuationToken: token,
			})
			require.NoError(t, err)

			assert.Equal(t, int32(1), aws.ToInt32(out.MaxKeys), "<MaxKeys> echoes 1")
			assert.Equal(t, int32(len(out.Contents)), aws.ToInt32(out.KeyCount))

			if len(out.Contents) == 0 {
				require.False(t, aws.ToBool(out.IsTruncated),
					"an empty page may only appear once the listing is exhausted")
				break
			}
			require.Len(t, out.Contents, 1, "max-keys=1 returns at most one key per page")

			got = append(got, aws.ToString(out.Contents[0].Key))
			if !aws.ToBool(out.IsTruncated) {
				break
			}
			require.NotEmpty(t, aws.ToString(out.NextContinuationToken))
			token = out.NextContinuationToken
		}

		assert.Equal(t, f.keys, got,
			"paging one key at a time must yield the whole bucket in key order")
	})

	t.Run("start_after_returns_only_greater_keys", func(t *testing.T) {
		startAfter := f.keys[len(f.keys)/2]

		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), StartAfter: aws.String(startAfter),
		})
		require.NoError(t, err)

		assert.Equal(t, startAfter, aws.ToString(out.StartAfter),
			"<StartAfter> must be echoed")

		keys := lstKeysOf(out.Contents)
		require.NotEmpty(t, keys)
		for _, key := range keys {
			assert.Greaterf(t, key, startAfter,
				"key %q is not strictly greater than start-after %q", key, startAfter)
		}
		// The default page is 1000 keys and 1249 keys follow the midpoint, so the
		// first page is exactly the next 1000.
		want := f.keys[len(f.keys)/2+1 : len(f.keys)/2+1001]
		assert.Equal(t, want, keys, "start-after must resume exactly after the given key")
		assert.True(t, aws.ToBool(out.IsTruncated))
	})

	t.Run("max_keys_above_the_limit_is_clamped_to_1000", func(t *testing.T) {
		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), MaxKeys: aws.Int32(5000),
		})
		require.NoError(t, err)

		assert.Equal(t, int32(1000), aws.ToInt32(out.MaxKeys),
			"the proxy clamps max-keys to the S3 limit and echoes what it applied")
		assert.Len(t, out.Contents, 1000, "and returns no more than that")
		assert.True(t, aws.ToBool(out.IsTruncated))

		// The clamp is the proxy's own behaviour and a deliberate deviation from
		// the backend. Measured: the backend caps the page at 1000 entries just
		// the same, but echoes the 5000 it was asked for, so its <MaxKeys> does
		// not describe the page it just sent. The proxy echoes what it applied.
		reference, err := f.tc.MinIOClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), MaxKeys: aws.Int32(5000),
		})
		require.NoError(t, err)
		assert.Equal(t, int32(5000), aws.ToInt32(reference.MaxKeys),
			"the backend echoes max-keys unclamped")
		assert.Len(t, reference.Contents, 1000,
			"the backend still sends at most 1000 entries per page")
	})

	t.Run("max_keys_zero_returns_no_keys", func(t *testing.T) {
		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), MaxKeys: aws.Int32(0),
		})
		require.NoError(t, err)

		assert.Empty(t, out.Contents, "max-keys=0 asks for no keys and gets none")
		assert.Equal(t, int32(0), aws.ToInt32(out.KeyCount))
		assert.Equal(t, int32(0), aws.ToInt32(out.MaxKeys), "<MaxKeys> echoes 0")
		assert.False(t, aws.ToBool(out.IsTruncated),
			"a zero-key page is not truncated, whatever the bucket holds")

		reference, err := f.tc.MinIOClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.bucket), MaxKeys: aws.Int32(0),
		})
		require.NoError(t, err)
		assert.Equal(t, aws.ToBool(reference.IsTruncated), aws.ToBool(out.IsTruncated),
			"proxy and backend disagree about truncation for max-keys=0")
		assert.Equal(t, aws.ToInt32(reference.KeyCount), aws.ToInt32(out.KeyCount))
	})

	t.Run("max_keys_that_is_not_a_non_negative_integer_is_refused", func(t *testing.T) {
		// The SDK cannot send these, so the raw client does.
		cases := []struct{ name, query string }{
			{"v2_negative", "list-type=2&max-keys=-1"},
			{"v2_not_a_number", "list-type=2&max-keys=abc"},
			{"v1_negative", "max-keys=-1"},
			{"v1_not_a_number", "max-keys=abc"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				status, _, body := lstProxyGet(t, "/"+f.bucket, c.query)
				assert.Equal(t, http.StatusBadRequest, status,
					"a max-keys the proxy cannot honour must be refused, not dropped")
				assert.Contains(t, string(body), "<Code>InvalidArgument</Code>",
					"the refusal must be an S3 <Error> document")
			})
		}
	})
}

// ---------------------------------------------------------------------------
// What <Size> means.
// ---------------------------------------------------------------------------

// TestLstListingSizeMatchesHeadAndGet is the crux of ADR 0010. The old file
// pinned the opposite: the listing reported the stored ciphertext length, so
// LIST, HEAD and GET on the same key disagreed and `aws s3 sync` re-transferred
// every object forever. The sizes here bracket the segment boundary, because
// that is where the plaintext-from-stored arithmetic can go wrong.
func TestLstListingSizeMatchesHeadAndGet(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket)

	const segment = int64(dataencryption.SegmentSize)
	cases := []struct {
		key       string
		plaintext int64
		multipart bool
	}{
		{key: "size/00-empty", plaintext: 0},
		{key: "size/01-one-byte", plaintext: 1},
		{key: "size/02-segment-minus-one", plaintext: segment - 1},
		{key: "size/03-segment", plaintext: segment},
		{key: "size/04-segment-plus-one", plaintext: segment + 1},
		{key: "size/05-twelve-mib", plaintext: 12 << 20},
		{key: "size/06-multipart", plaintext: 11 << 20, multipart: true},
	}

	content := make(map[string][]byte, len(cases))
	for _, c := range cases {
		body := lstBody(c.key, c.plaintext)
		content[c.key] = body
		if c.multipart {
			lstMultipartPut(t, ctx, tc.ProxyClient, tc.TestBucket, c.key, body, 5<<20)
			continue
		}
		lstPut(t, ctx, tc.ProxyClient, tc.TestBucket, c.key, body)
	}

	reported := lstListSizes(t, ctx, tc.ProxyClient, tc.TestBucket)
	stored := lstListSizes(t, ctx, tc.MinIOClient, tc.TestBucket)

	for _, c := range cases {
		c := c
		t.Run(strings.ReplaceAll(c.key, "/", "_"), func(t *testing.T) {
			atRest, ok := stored[c.key]
			require.Truef(t, ok, "%q is missing from the backend listing", c.key)
			listed, ok := reported[c.key]
			require.Truef(t, ok, "%q is missing from the proxy listing", c.key)

			// The object really is encrypted: at rest it carries its framing.
			assert.Equal(t, lstCiphertextSize(t, c.plaintext), atRest,
				"the stored object must be the plaintext plus its segment framing")

			head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(c.key),
			})
			require.NoError(t, err)
			body := lstGet(t, ctx, tc.ProxyClient, tc.TestBucket, c.key)

			assert.Equal(t, c.plaintext, listed,
				"the listing must report the plaintext length, not the stored length")
			assert.Equal(t, c.plaintext, aws.ToInt64(head.ContentLength),
				"HEAD must report the plaintext length")
			assert.Equal(t, c.plaintext, int64(len(body)),
				"GET must deliver the plaintext length")
			assert.Equal(t, listed, aws.ToInt64(head.ContentLength),
				"LIST and HEAD must agree about the size of the same object")
			assert.Equal(t, listed, int64(len(body)),
				"LIST must describe the body GET delivers")
			assert.Equal(t, sha256.Sum256(content[c.key]), sha256.Sum256(body),
				"round-tripped content differs from what was written")
		})
	}
}

// TestLstListingUnderReportsForeignObjects is the documented cost of computing
// the size instead of asking for it.
//
// The proxy derives the plaintext length from the stored length by arithmetic it
// controls: no metadata read, no round trip, one listing call however many keys
// the page holds. An object this proxy did not write has no framing, so when its
// stored length happens to be a length a chain could have had, the arithmetic
// subtracts framing that is not there and the entry is short by exactly that.
//
// This is deliberate and must NOT be "fixed" with a HeadObject per key: that
// turns one listing into a thousand backend requests, and it would slow down
// every correct listing to flatter the sizes of objects that do not belong to
// this proxy. A bucket the proxy owns has no foreign objects in it.
func TestLstListingUnderReportsForeignObjects(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket)

	const mine = int64(1000)
	lstPut(t, ctx, tc.ProxyClient, tc.TestBucket, "mixed/mine.bin", lstBody("mine", mine))

	// A foreign object whose raw length is one a chain of this format could have
	// had. Nothing distinguishes it from an encrypted object by size alone.
	foreignChainLength := lstCiphertextSize(t, mine)
	lstPut(t, ctx, tc.MinIOClient, tc.TestBucket, "mixed/foreign-chain.bin",
		lstBody("foreign", foreignChainLength))

	// A foreign object shorter than a trailer: no chain can be this short, so the
	// arithmetic refuses it and the stored length is reported verbatim.
	const foreignTiny = int64(10)
	lstPut(t, ctx, tc.MinIOClient, tc.TestBucket, "mixed/foreign-tiny.bin",
		lstBody("tiny", foreignTiny))

	sizes := lstListSizes(t, ctx, tc.ProxyClient, tc.TestBucket)

	assert.Equal(t, mine, sizes["mixed/mine.bin"],
		"a proxy-written object is reported exactly")
	assert.Equal(t, foreignChainLength-lstFramingOverhead, sizes["mixed/foreign-chain.bin"],
		"a foreign object of chain length is under-reported by exactly the framing")
	assert.Equal(t, foreignTiny, sizes["mixed/foreign-tiny.bin"],
		"a length no chain can have is reported verbatim rather than invented")

	// The proxy-written entry in the same mixed listing is still exact: the
	// under-report is confined to the objects the proxy did not write.
	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String("mixed/mine.bin"),
	})
	require.NoError(t, err)
	assert.Equal(t, sizes["mixed/mine.bin"], aws.ToInt64(head.ContentLength))
}

// ---------------------------------------------------------------------------
// The wire document.
// ---------------------------------------------------------------------------

// TestLstListingDocumentOnTheWire asserts on the raw bytes. The old file pinned
// a root element named <ListObjectsV2Output> with <ResultMetadata> and empty
// enum fields in it, no namespace and no XML declaration - a document no S3
// client validates and no S3 tool other than a permissive SDK accepts.
func TestLstListingDocumentOnTheWire(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket)

	// Two keys and two sub-directories under dir/, so that one page of two
	// entries carries a <Contents> and a <CommonPrefixes> at the same time.
	for _, key := range []string{"dir/a.txt", "dir/sub1/x.txt", "dir/sub2/y.txt", "dir/z.txt", "top.txt"} {
		lstPut(t, ctx, tc.ProxyClient, tc.TestBucket, key, lstBody(key, 21))
	}

	t.Run("v2_is_a_ListBucketResult_in_the_s3_namespace", func(t *testing.T) {
		status, header, body := lstProxyGet(t, "/"+tc.TestBucket,
			"list-type=2&prefix=dir%2F&delimiter=%2F&max-keys=2&encoding-type=url&fetch-owner=true&start-after=dir%2F")
		require.Equal(t, http.StatusOK, status)
		doc := string(body)

		assert.True(t, strings.HasPrefix(doc, `<?xml version="1.0" encoding="UTF-8"?>`),
			"S3 documents open with the XML declaration")
		assert.Contains(t, doc, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
			"the root element is ListBucketResult in the 2006-03-01 namespace")
		assert.NotContains(t, doc, "ListObjectsV2Output",
			"the SDK output type must not be the root element")
		assert.NotContains(t, doc, "ResultMetadata",
			"SDK plumbing must not reach the wire")
		assert.Equal(t, "application/xml", header.Get("Content-Type"))

		sequence := lstElementSequence(t, body)
		lstAssertElementOrder(t, "V2 listing", sequence, lstV2ElementOrder)
		assert.Equal(t, []string{
			"Name", "Prefix", "StartAfter", "NextContinuationToken",
			"KeyCount", "MaxKeys", "Delimiter", "IsTruncated",
			"Contents", "CommonPrefixes", "EncodingType",
		}, sequence, "the V2 element order changed")

		contents := lstChildElements(t, body, "Contents")
		lstAssertElementOrder(t, "V2 <Contents>", contents, lstContentsElementOrder)
		assert.Equal(t, []string{"Key", "LastModified", "ETag", "Size", "Owner", "StorageClass"}, contents,
			"with fetch-owner the Owner sits between Size and StorageClass")

		owner := lstChildElements(t, body, "Owner")
		assert.Equal(t, []string{"ID", "DisplayName"}, owner)
		assert.Contains(t, doc, "<ID>"+integration.ProxyTestAccessKey+"</ID>",
			"the owner is the caller, never the backend account")

		assert.Regexp(t, lstLastModifiedPattern, lstElementText(t, body, "LastModified"),
			"LastModified is RFC 3339 with exactly three fractional digits")

		assert.NotContains(t, strings.ToLower(doc), "s3ep-",
			"encryption metadata must never appear in a listing")
		for name := range header {
			assert.NotContains(t, strings.ToLower(name), "s3ep-",
				"encryption metadata must not appear in listing response headers")
		}
	})

	t.Run("v2_second_page_echoes_the_continuation_token_in_place", func(t *testing.T) {
		_, _, first := lstProxyGet(t, "/"+tc.TestBucket,
			"list-type=2&prefix=dir%2F&delimiter=%2F&max-keys=2&encoding-type=url")
		token := lstElementText(t, first, "NextContinuationToken")
		require.NotEmpty(t, token, "the first page must be truncated for this fixture")

		_, _, body := lstProxyGet(t, "/"+tc.TestBucket,
			"list-type=2&prefix=dir%2F&delimiter=%2F&max-keys=2&encoding-type=url"+
				"&continuation-token="+url.QueryEscape(token))

		sequence := lstElementSequence(t, body)
		lstAssertElementOrder(t, "V2 second page", sequence, lstV2ElementOrder)
		assert.Contains(t, sequence, "ContinuationToken",
			"the page must echo the token the client sent")
		assert.Equal(t, token, lstElementText(t, body, "ContinuationToken"))
	})

	t.Run("v1_is_the_same_root_without_a_KeyCount", func(t *testing.T) {
		status, _, body := lstProxyGet(t, "/"+tc.TestBucket, "prefix=dir%2F&delimiter=%2F&max-keys=2")
		require.Equal(t, http.StatusOK, status)
		doc := string(body)

		assert.True(t, strings.HasPrefix(doc, `<?xml version="1.0" encoding="UTF-8"?>`))
		assert.Contains(t, doc, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
			"V1 answers with ListBucketResult too")
		assert.NotContains(t, doc, "ListObjectsOutput")
		assert.NotContains(t, doc, "ResultMetadata")

		sequence := lstElementSequence(t, body)
		lstAssertElementOrder(t, "V1 listing", sequence, lstV1ElementOrder)
		assert.NotContains(t, sequence, "KeyCount", "V1 has no KeyCount")
		assert.NotContains(t, sequence, "EncodingType",
			"EncodingType is echoed only when the client asked for it")
		for _, required := range []string{"Name", "Prefix", "Marker", "MaxKeys", "IsTruncated", "Contents"} {
			assert.Containsf(t, sequence, required, "V1 must carry <%s>", required)
		}

		contents := lstChildElements(t, body, "Contents")
		lstAssertElementOrder(t, "V1 <Contents>", contents, lstContentsElementOrder)
		assert.Contains(t, contents, "Owner", "V1 carries the owner without being asked")
	})

	t.Run("list_buckets_carries_the_namespace_and_the_caller_as_owner", func(t *testing.T) {
		status, _, body := lstProxyGet(t, "/", "")
		require.Equal(t, http.StatusOK, status)
		doc := string(body)

		assert.True(t, strings.HasPrefix(doc, `<?xml version="1.0" encoding="UTF-8"?>`))
		assert.Contains(t, doc, `<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
			"the namespace belongs on the root element")

		sequence := lstElementSequence(t, body)
		lstAssertElementOrder(t, "ListBuckets", sequence,
			[]string{"Owner", "Buckets", "Prefix", "ContinuationToken"})

		assert.Equal(t, integration.ProxyTestAccessKey, lstElementText(t, body, "ID"),
			"the owner is the authenticated caller (ADR 0008)")
		assert.Equal(t, integration.ProxyTestAccessKey, lstElementText(t, body, "DisplayName"))
		assert.NotContains(t, doc, "<DisplayName>minio</DisplayName>",
			"the backend account must not be handed to a proxy client")
	})
}

// lstElementText returns the character data of the first element with this name.
func lstElementText(t *testing.T, doc []byte, name string) string {
	t.Helper()

	decoder := xml.NewDecoder(bytes.NewReader(doc))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return ""
		}
		require.NoError(t, err, "the response must be well-formed XML")

		if start, ok := token.(xml.StartElement); ok && start.Name.Local == name {
			var text string
			require.NoError(t, decoder.DecodeElement(&text, &start))
			return text
		}
	}
}

// ---------------------------------------------------------------------------
// encoding-type.
// ---------------------------------------------------------------------------

// TestLstListingEncodingTypeRoundTrip covers keys whose bytes are hostile to
// either the XML document or the URL that carries them: +, a space, &, <, a bare
// %, a literal %2B, and a non-ASCII character. The old file pinned encoding-type
// as dropped, so a client that asked for safe keys got raw ones.
//
// The proxy always asks the backend for URL encoding - that is what keeps the
// backend's own XML well formed - decodes with QueryUnescape (the demo backend
// encodes a space as "+", which PathUnescape would leave alone) and re-encodes
// only when the client asked.
func TestLstListingEncodingTypeRoundTrip(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket)

	keys := []string{
		"enc/amp&key.txt",
		"enc/angle<key>.txt",
		"enc/literal%2Bkey.txt",
		"enc/percent%key.txt",
		"enc/plus+key.txt",
		"enc/space key.txt",
		"enc/uni-äöü.txt",
	}
	sort.Strings(keys)

	content := make(map[string][]byte, len(keys))
	for _, key := range keys {
		body := lstBody(key, 37)
		content[key] = body
		lstPut(t, ctx, tc.ProxyClient, tc.TestBucket, key, body)
	}

	t.Run("without_encoding_type_the_keys_come_back_raw", func(t *testing.T) {
		out, err := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(tc.TestBucket), Prefix: aws.String("enc/"),
		})
		require.NoError(t, err)
		assert.Equal(t, keys, lstKeysOf(out.Contents),
			"the proxy must undo the encoding it asked the backend for")
		assert.Equal(t, s3types.EncodingType(""), out.EncodingType,
			"<EncodingType> is echoed only when the client asked for it")

		// The XML metacharacters survive because encoding/xml escapes them.
		_, _, body := lstProxyGet(t, "/"+tc.TestBucket, "list-type=2&prefix=enc%2F")
		doc := string(body)
		assert.Contains(t, doc, "amp&amp;key.txt", "& must be escaped, not concatenated")
		assert.Contains(t, doc, "angle&lt;key&gt;.txt", "< must be escaped")
	})

	t.Run("with_encoding_type_url_the_keys_are_encoded_and_echoed", func(t *testing.T) {
		out, err := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:       aws.String(tc.TestBucket),
			Prefix:       aws.String("enc/"),
			EncodingType: s3types.EncodingTypeUrl,
		})
		require.NoError(t, err)
		assert.Equal(t, s3types.EncodingTypeUrl, out.EncodingType,
			"<EncodingType>url</EncodingType> must be echoed")

		listed := lstKeysOf(out.Contents)
		require.Len(t, listed, len(keys))

		decoded := make([]string, 0, len(listed))
		encodedSeen := 0
		for _, key := range listed {
			plain, err := url.QueryUnescape(key)
			require.NoErrorf(t, err, "listed key %q is not valid URL encoding", key)
			decoded = append(decoded, plain)
			if plain != key {
				encodedSeen++
			}
		}
		assert.Equal(t, keys, decoded, "decoding must give back exactly what was written")
		assert.Equal(t, len(keys), encodedSeen, "every key here contains a byte that must be encoded")

		// The point of the parameter: what comes back must still address the
		// object. A failure here is a real defect, not a reason to relax the test.
		for i, key := range decoded {
			body := lstGet(t, ctx, tc.ProxyClient, tc.TestBucket, key)
			assert.Equalf(t, sha256.Sum256(content[key]), sha256.Sum256(body),
				"GET of the listed key %q returned different content", listed[i])
		}

		_, _, raw := lstProxyGet(t, "/"+tc.TestBucket, "list-type=2&prefix=enc%2F&encoding-type=url")
		assert.Contains(t, string(raw), "<EncodingType>url</EncodingType>")
		assert.Contains(t, string(raw), "<Prefix>enc%2F</Prefix>",
			"the echoed prefix is encoded too when the client asked for encoding")
	})
}

// ---------------------------------------------------------------------------
// HeadBucket.
// ---------------------------------------------------------------------------

// TestLstHeadBucket covers the operation that used to be a ListObjectsV2 with
// MaxKeys 0 - which answers 200 for a bucket that does not exist, because the
// backend short-circuits the listing before it checks the bucket.
func TestLstHeadBucket(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket)

	t.Run("existing_bucket_is_200_with_a_region", func(t *testing.T) {
		status, header, _ := lstRawRequest(t, http.MethodHead, integration.ProxyEndpoint,
			"/"+tc.TestBucket, "", integration.ProxyTestAccessKey, integration.ProxyTestSecretKey)
		assert.Equal(t, http.StatusOK, status)
		assert.Equal(t, integration.TestRegion, header.Get("x-amz-bucket-region"),
			"the region is the proxy's own answer, from s3_backend.region")
	})

	t.Run("missing_bucket_is_404", func(t *testing.T) {
		missing := "lst-no-such-bucket-" + integration.RandomString(12)
		status, _, _ := lstRawRequest(t, http.MethodHead, integration.ProxyEndpoint,
			"/"+missing, "", integration.ProxyTestAccessKey, integration.ProxyTestSecretKey)
		assert.Equal(t, http.StatusNotFound, status,
			"a HEAD on a bucket that does not exist must not answer 200")

		_, err := tc.ProxyClient.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(missing)})
		require.Error(t, err, "the SDK must see the 404 too")
		assert.Equal(t, http.StatusNotFound, httpStatusOf(err))
	})

	t.Run("the_backend_itself_sends_no_region", func(t *testing.T) {
		// Measured against the demo MinIO: it answers HeadBucket without an
		// x-amz-bucket-region header at all, which is why the proxy fills in the
		// configured region rather than forwarding one.
		status, header, _ := lstRawRequest(t, http.MethodHead, integration.MinIOEndpoint,
			"/"+tc.TestBucket, "", integration.MinIOAccessKey, integration.MinIOSecretKey)
		require.Equal(t, http.StatusOK, status)
		assert.Empty(t, header.Get("x-amz-bucket-region"),
			"the backend sends no region, so the proxy's header is its own")
	})
}

// ---------------------------------------------------------------------------
// The small mixed-key fixture, compared against the backend as an oracle.
// ---------------------------------------------------------------------------

// lstRefLayout is a small layout with awkward keys, written twice: once through
// the proxy (ciphertext at rest) and once directly into a reference bucket
// (plaintext). Anywhere the two listings disagree and the disagreement is not
// "the proxy encrypted the bytes", it is a finding.
var lstRefLayout = []struct {
	Key       string
	Plaintext int64
}{
	{"a.txt", 11},
	{"b.txt", 23},
	{"dir1/x.txt", 37},
	{"dir1/y.txt", 64},
	{"dir2/z.txt", 128},
	{"space key.txt", 41},
	{"uni-äöü.txt", 57},
}

type lstRefFixture struct {
	ctx         context.Context
	tc          *integration.TestContext
	proxyBucket string
	minioBucket string
	keys        []string
	plaintext   map[string]int64
}

func lstNewRefFixture(t *testing.T) *lstRefFixture {
	t.Helper()
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	tc := integration.NewTestContextWithTimeout(t, ctx)
	t.Cleanup(func() { lstPurgeBucket(t, tc.MinIOClient, tc.TestBucket) })

	minioBucket := "lst-ref-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, minioBucket)
	t.Cleanup(func() { lstPurgeBucket(t, tc.MinIOClient, minioBucket) })

	f := &lstRefFixture{
		ctx:         ctx,
		tc:          tc,
		proxyBucket: tc.TestBucket,
		minioBucket: minioBucket,
		plaintext:   make(map[string]int64, len(lstRefLayout)),
	}
	for _, o := range lstRefLayout {
		body := lstBody(o.Key, o.Plaintext)
		lstPut(t, ctx, tc.ProxyClient, f.proxyBucket, o.Key, body)
		lstPut(t, ctx, tc.MinIOClient, f.minioBucket, o.Key, body)
		f.keys = append(f.keys, o.Key)
		f.plaintext[o.Key] = o.Plaintext
	}
	require.True(t, sort.StringsAreSorted(f.keys),
		"lstRefLayout must be declared in S3 listing order")
	return f
}

// TestLstListObjectsV2MatchesMinIO covers the listing shapes where the proxy and
// the backend must agree exactly: no parameters, prefix, delimiter, a prefix that
// matches nothing - and, since ADR 0010, the reported sizes as well, because both
// now describe the same plaintext.
func TestLstListObjectsV2MatchesMinIO(t *testing.T) {
	f := lstNewRefFixture(t)

	cases := []struct {
		name         string
		prefix       string
		delimiter    string
		wantKeys     []string
		wantPrefixes []string
	}{
		{
			name:         "no_parameters_returns_the_whole_layout",
			wantKeys:     f.keys,
			wantPrefixes: []string{},
		},
		{
			name:         "prefix_dir1",
			prefix:       "dir1/",
			wantKeys:     []string{"dir1/x.txt", "dir1/y.txt"},
			wantPrefixes: []string{},
		},
		{
			name:      "delimiter_slash_rolls_directories_into_common_prefixes",
			delimiter: "/",
			// Only the keys that carry no delimiter after the prefix stay in
			// Contents; dir1/ and dir2/ collapse into CommonPrefixes.
			wantKeys:     []string{"a.txt", "b.txt", "space key.txt", "uni-äöü.txt"},
			wantPrefixes: []string{"dir1/", "dir2/"},
		},
		{
			name:         "prefix_and_delimiter_together",
			prefix:       "dir1/",
			delimiter:    "/",
			wantKeys:     []string{"dir1/x.txt", "dir1/y.txt"},
			wantPrefixes: []string{},
		},
		{
			name:         "prefix_matching_nothing_is_an_empty_listing_not_an_error",
			prefix:       "no-such-prefix-" + integration.RandomString(8) + "/",
			wantKeys:     []string{},
			wantPrefixes: []string{},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			build := func(bucket string) *s3.ListObjectsV2Input {
				in := &s3.ListObjectsV2Input{Bucket: aws.String(bucket)}
				if c.prefix != "" {
					in.Prefix = aws.String(c.prefix)
				}
				if c.delimiter != "" {
					in.Delimiter = aws.String(c.delimiter)
				}
				return in
			}

			proxyOut, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, build(f.proxyBucket))
			require.NoError(t, err, "proxy listing must succeed")

			minioOut, err := f.tc.MinIOClient.ListObjectsV2(f.ctx, build(f.minioBucket))
			require.NoError(t, err, "reference listing must succeed")

			assert.Equal(t, c.wantKeys, lstKeysOf(proxyOut.Contents), "proxy returned the wrong keys")
			assert.Equal(t, lstKeysOf(minioOut.Contents), lstKeysOf(proxyOut.Contents),
				"proxy and backend disagree on the key set")

			assert.Equal(t, c.wantPrefixes, lstPrefixesOf(proxyOut.CommonPrefixes),
				"proxy returned the wrong CommonPrefixes")
			assert.Equal(t, lstPrefixesOf(minioOut.CommonPrefixes), lstPrefixesOf(proxyOut.CommonPrefixes),
				"proxy and backend disagree on CommonPrefixes")

			assert.Equal(t, f.proxyBucket, aws.ToString(proxyOut.Name),
				"<Name> must echo the bucket that was listed")
			assert.Equal(t, c.prefix, aws.ToString(proxyOut.Prefix),
				"<Prefix> must echo the request prefix")
			assert.Equal(t, aws.ToString(minioOut.Delimiter), aws.ToString(proxyOut.Delimiter),
				"<Delimiter> echo differs from the backend")

			assert.False(t, aws.ToBool(proxyOut.IsTruncated),
				"a listing well under max-keys must not be truncated")
			assert.Equal(t, int32(len(c.wantKeys)+len(c.wantPrefixes)), aws.ToInt32(proxyOut.KeyCount),
				"KeyCount counts Contents plus CommonPrefixes")
			assert.Equal(t, aws.ToInt32(minioOut.KeyCount), aws.ToInt32(proxyOut.KeyCount),
				"proxy and backend disagree on KeyCount")
			assert.Empty(t, aws.ToString(proxyOut.NextContinuationToken),
				"an untruncated listing must not carry a continuation token")

			// Both sides now describe the same plaintext, so the sizes match key
			// for key even though one bucket holds ciphertext.
			for _, key := range c.wantKeys {
				assert.Equalf(t, f.plaintext[key], lstSizeOf(t, proxyOut.Contents, key),
					"the proxy must report the plaintext size of %q", key)
				assert.Equalf(t,
					lstSizeOf(t, minioOut.Contents, key), lstSizeOf(t, proxyOut.Contents, key),
					"proxy and plaintext reference disagree on the size of %q", key)
			}
		})
	}

	t.Run("fetch_owner_answers_with_the_caller", func(t *testing.T) {
		// The old behaviour dropped fetch-owner entirely; before that, a V1
		// listing handed the client the backend account's canonical id.
		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.proxyBucket), FetchOwner: aws.Bool(true),
		})
		require.NoError(t, err)
		require.NotEmpty(t, out.Contents)
		for _, o := range out.Contents {
			require.NotNilf(t, o.Owner, "fetch-owner=true must produce an <Owner> for %q", aws.ToString(o.Key))
			assert.Equal(t, integration.ProxyTestAccessKey, aws.ToString(o.Owner.ID))
			assert.Equal(t, integration.ProxyTestAccessKey, aws.ToString(o.Owner.DisplayName))
		}

		reference, err := f.tc.MinIOClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.minioBucket), FetchOwner: aws.Bool(true),
		})
		require.NoError(t, err)
		require.NotEmpty(t, reference.Contents)
		require.NotNil(t, reference.Contents[0].Owner)
		assert.NotEqual(t,
			aws.ToString(reference.Contents[0].Owner.ID),
			aws.ToString(out.Contents[0].Owner.ID),
			"the backend account must never be handed to a proxy client")
	})

	t.Run("without_fetch_owner_there_is_no_owner", func(t *testing.T) {
		out, err := f.tc.ProxyClient.ListObjectsV2(f.ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(f.proxyBucket),
		})
		require.NoError(t, err)
		require.NotEmpty(t, out.Contents)
		for _, o := range out.Contents {
			assert.Nilf(t, o.Owner, "V2 carries <Owner> only when fetch-owner was asked for (%q)", aws.ToString(o.Key))
		}
	})
}

// TestLstListObjectsV1MatchesMinIO covers the V1 parameters: prefix, delimiter,
// marker and max-keys. max-keys used to be parsed nowhere in the V1 branch, so a
// V1 client could not page at all.
func TestLstListObjectsV1MatchesMinIO(t *testing.T) {
	f := lstNewRefFixture(t)

	t.Run("no_parameters", func(t *testing.T) {
		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket),
		})
		require.NoError(t, err)
		minioOut, err := f.tc.MinIOClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.minioBucket),
		})
		require.NoError(t, err)

		assert.Equal(t, f.keys, lstKeysOf(proxyOut.Contents))
		assert.Equal(t, lstKeysOf(minioOut.Contents), lstKeysOf(proxyOut.Contents))
		assert.False(t, aws.ToBool(proxyOut.IsTruncated))
	})

	t.Run("delimiter_slash", func(t *testing.T) {
		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)
		minioOut, err := f.tc.MinIOClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.minioBucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)

		assert.Equal(t, []string{"a.txt", "b.txt", "space key.txt", "uni-äöü.txt"},
			lstKeysOf(proxyOut.Contents))
		assert.Equal(t, []string{"dir1/", "dir2/"}, lstPrefixesOf(proxyOut.CommonPrefixes))
		assert.Equal(t, lstPrefixesOf(minioOut.CommonPrefixes), lstPrefixesOf(proxyOut.CommonPrefixes))
	})

	t.Run("marker_resumes_after_the_given_key", func(t *testing.T) {
		const marker = "b.txt"
		want := []string{"dir1/x.txt", "dir1/y.txt", "dir2/z.txt", "space key.txt", "uni-äöü.txt"}

		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket), Marker: aws.String(marker),
		})
		require.NoError(t, err)
		minioOut, err := f.tc.MinIOClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.minioBucket), Marker: aws.String(marker),
		})
		require.NoError(t, err)

		assert.Equal(t, want, lstKeysOf(proxyOut.Contents))
		assert.Equal(t, lstKeysOf(minioOut.Contents), lstKeysOf(proxyOut.Contents))
		assert.Equal(t, marker, aws.ToString(proxyOut.Marker), "<Marker> is echoed")
	})

	t.Run("max_keys_pages_and_truncates", func(t *testing.T) {
		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket), MaxKeys: aws.Int32(3),
		})
		require.NoError(t, err)
		require.Len(t, proxyOut.Contents, 3, "V1 max-keys must be honoured")
		assert.True(t, aws.ToBool(proxyOut.IsTruncated))
		assert.Equal(t, int32(3), aws.ToInt32(proxyOut.MaxKeys))
		assert.Equal(t, f.keys[:3], lstKeysOf(proxyOut.Contents))

		minioOut, err := f.tc.MinIOClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.minioBucket), MaxKeys: aws.Int32(3),
		})
		require.NoError(t, err)
		assert.Equal(t, lstKeysOf(minioOut.Contents), lstKeysOf(proxyOut.Contents))
		assert.Equal(t, aws.ToBool(minioOut.IsTruncated), aws.ToBool(proxyOut.IsTruncated))

		// And the marker from the truncated page finishes the bucket.
		second, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket:  aws.String(f.proxyBucket),
			MaxKeys: aws.Int32(1000),
			Marker:  aws.String(f.keys[2]),
		})
		require.NoError(t, err)
		assert.Equal(t, f.keys[3:], lstKeysOf(second.Contents))
	})

	t.Run("owner_is_the_caller_not_the_backend_account", func(t *testing.T) {
		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket),
		})
		require.NoError(t, err)
		require.NotEmpty(t, proxyOut.Contents)

		minioOut, err := f.tc.MinIOClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.minioBucket),
		})
		require.NoError(t, err)
		require.NotEmpty(t, minioOut.Contents)
		require.NotNil(t, minioOut.Contents[0].Owner)

		for _, o := range proxyOut.Contents {
			require.NotNilf(t, o.Owner, "V1 always carries <Owner> (%q)", aws.ToString(o.Key))
			assert.Equal(t, integration.ProxyTestAccessKey, aws.ToString(o.Owner.ID))
			assert.NotEqual(t, aws.ToString(minioOut.Contents[0].Owner.ID), aws.ToString(o.Owner.ID),
				"a proxy client must not learn the backend account's canonical id")
		}
	})

	t.Run("size_is_the_plaintext_here_too", func(t *testing.T) {
		proxyOut, err := f.tc.ProxyClient.ListObjects(f.ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.proxyBucket),
		})
		require.NoError(t, err)
		for _, o := range proxyOut.Contents {
			key := aws.ToString(o.Key)
			assert.Equalf(t, f.plaintext[key], aws.ToInt64(o.Size),
				"V1 <Size> for %q must be the plaintext size", key)
		}
	})
}

// ---------------------------------------------------------------------------
// Error path.
// ---------------------------------------------------------------------------

// TestLstListObjectsMissingBucket asserts both listing versions answer a
// non-existent bucket with 404 NoSuchBucket, exactly as the backend does.
func TestLstListObjectsMissingBucket(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err)
	minioClient, err := integration.CreateMinIOClient()
	require.NoError(t, err)

	missing := "lst-no-such-bucket-" + integration.RandomString(12)

	cases := []struct {
		name string
		call func(client *s3.Client) error
	}{
		{
			name: "ListObjectsV2",
			call: func(client *s3.Client) error {
				_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(missing)})
				return err
			},
		},
		{
			name: "ListObjects",
			call: func(client *s3.Client) error {
				_, err := client.ListObjects(ctx, &s3.ListObjectsInput{Bucket: aws.String(missing)})
				return err
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			proxyErr := c.call(proxyClient)
			require.Error(t, proxyErr, "listing a missing bucket must fail")

			minioErr := c.call(minioClient)
			require.Error(t, minioErr)

			assert.Equal(t, http.StatusNotFound, httpStatusOf(proxyErr),
				"proxy must answer a missing bucket with 404: %v", proxyErr)
			assert.Equal(t, "NoSuchBucket", apiCodeOf(proxyErr),
				"proxy must answer with NoSuchBucket: %v", proxyErr)
			assert.Equal(t, httpStatusOf(minioErr), httpStatusOf(proxyErr),
				"proxy and backend disagree on the status for a missing bucket")
			assert.Equal(t, apiCodeOf(minioErr), apiCodeOf(proxyErr),
				"proxy and backend disagree on the error code for a missing bucket")
		})
	}
}
