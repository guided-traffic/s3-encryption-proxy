//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Baseline for the listing rewrite of ADR 0010.
//
// Every test in this file runs the SAME listing twice: once through the proxy
// against a bucket the proxy wrote (ciphertext at rest), once through the MinIO
// client against a reference bucket holding the identical plaintext objects.
// MinIO is the oracle for S3 listing semantics; anywhere the two disagree and
// the disagreement is not "the proxy encrypted the bytes", it is a finding.
//
// Tests whose name ends in "Deviation" assert the behaviour the proxy has
// TODAY, not the behaviour S3 documents. They exist so the ADR 0010 rewrite
// has a baseline to change from; each one names the defect it pins.
// ---------------------------------------------------------------------------

// LstStoredSize is what an object of this plaintext length occupies at rest:
// one nonce and one tag per segment, plus the trailer that closes the chain.
func LstStoredSize(plaintext int64) int64 {
	segments := plaintext / dataencryption.SegmentSize
	if plaintext%dataencryption.SegmentSize != 0 {
		segments++
	}
	return plaintext + segments*dataencryption.SegmentOverhead + dataencryption.TrailerSize
}

// LstKeyLayout is the bucket layout every listing test here works on. It is
// declared in S3 listing order (bytewise ascending) and the plaintext lengths
// are all distinct, so a Size in a listing identifies its key unambiguously.
var LstKeyLayout = []struct {
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

// LstFixture holds a proxy bucket and a plaintext reference bucket carrying the
// identical key layout.
type LstFixture struct {
	Ctx         context.Context
	TC          *integration.TestContext
	ProxyBucket string
	MinIOBucket string
	Keys        []string
	Plaintext   map[string]int64
}

// LstSetup creates the reference bucket, uploads the layout through both the
// proxy and MinIO, and registers cleanup for everything it made.
func LstSetup(t *testing.T, ctx context.Context, tc *integration.TestContext) *LstFixture {
	t.Helper()

	minioBucket := "lst-ref-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, minioBucket)
	t.Cleanup(func() { integration.CleanupTestBucket(t, tc.MinIOClient, minioBucket) })

	f := &LstFixture{
		Ctx:         ctx,
		TC:          tc,
		ProxyBucket: tc.TestBucket,
		MinIOBucket: minioBucket,
		Plaintext:   make(map[string]int64, len(LstKeyLayout)),
	}

	for _, o := range LstKeyLayout {
		body := LstBody(o.Key, o.Plaintext)

		_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(f.ProxyBucket),
			Key:           aws.String(o.Key),
			Body:          bytes.NewReader(body),
			ContentLength: aws.Int64(o.Plaintext),
		})
		require.NoErrorf(t, err, "PUT %q through the proxy", o.Key)

		_, err = tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(minioBucket),
			Key:           aws.String(o.Key),
			Body:          bytes.NewReader(body),
			ContentLength: aws.Int64(o.Plaintext),
		})
		require.NoErrorf(t, err, "PUT %q directly into MinIO", o.Key)

		f.Keys = append(f.Keys, o.Key)
		f.Plaintext[o.Key] = o.Plaintext
	}

	require.True(t, sort.StringsAreSorted(f.Keys),
		"LstKeyLayout must be declared in S3 listing order")

	return f
}

// LstBody builds deterministic content of the requested length.
func LstBody(key string, n int64) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('A' + (int(key[0])+i)%26)
	}
	return b
}

// LstKeysOf extracts the keys from a listing page, in the order returned.
func LstKeysOf(contents []s3types.Object) []string {
	keys := make([]string, 0, len(contents))
	for _, o := range contents {
		keys = append(keys, aws.ToString(o.Key))
	}
	return keys
}

// LstPrefixesOf extracts the common prefixes from a listing page.
func LstPrefixesOf(prefixes []s3types.CommonPrefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, aws.ToString(p.Prefix))
	}
	sort.Strings(out)
	return out
}

// LstSizeOf returns the Size a listing reported for key.
func LstSizeOf(t *testing.T, contents []s3types.Object, key string) int64 {
	t.Helper()
	for _, o := range contents {
		if aws.ToString(o.Key) == key {
			return aws.ToInt64(o.Size)
		}
	}
	t.Fatalf("key %q not present in the listing", key)
	return 0
}

// LstRecorder captures the raw HTTP response of the last request a recording
// client made, so the tests can assert on the wire document rather than on what
// the SDK deserializer was willing to accept.
type LstRecorder struct {
	Status  int
	Header  http.Header
	Body    []byte
	Request string
}

// LstRecordingTransport wraps a RoundTripper and copies each response into rec.
type LstRecordingTransport struct {
	base http.RoundTripper
	rec  *LstRecorder
}

func (rt *LstRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.base.RoundTrip(req)
	if err != nil || resp == nil || resp.Body == nil {
		return resp, err
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	rt.rec.Status = resp.StatusCode
	rt.rec.Header = resp.Header.Clone()
	rt.rec.Body = body
	rt.rec.Request = req.URL.String()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// LstNewRecordingClient builds an S3 client for endpoint that keeps the raw
// bytes of every response it receives. It mirrors integration.NewS3Client,
// which cannot be reused because it owns its HTTP client.
func LstNewRecordingClient(t *testing.T, endpoint, accessKey, secretKey string) (*s3.Client, *LstRecorder) {
	t.Helper()

	base := integration.TLSHTTPClient()
	rec := &LstRecorder{}
	httpClient := &http.Client{
		Transport: &LstRecordingTransport{base: base.Transport, rec: rec},
		Timeout:   base.Timeout,
	}

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion(integration.TestRegion),
		config.WithHTTPClient(httpClient),
	)
	require.NoError(t, err, "failed to build a recording S3 client")

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
	})
	return client, rec
}

// LstNewFixtureContext is the common preamble of every test below.
func LstNewFixtureContext(t *testing.T) (*LstFixture, func()) {
	t.Helper()
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	tc := integration.NewTestContextWithTimeout(t, ctx)

	cleanup := func() {
		tc.CleanupTestBucket()
		cancel()
	}
	return LstSetup(t, ctx, tc), cleanup
}

// ---------------------------------------------------------------------------
// The parts of ListObjectsV2 the proxy gets right.
// ---------------------------------------------------------------------------

// TestLstListObjectsV2MatchesMinIO covers the listing shapes the proxy does
// forward: no parameters, prefix, delimiter, and a prefix that matches nothing.
// The proxy and MinIO must agree on the key set, the order, the common
// prefixes, the echoed request parameters and the truncation flags.
func TestLstListObjectsV2MatchesMinIO(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	cases := []struct {
		name         string
		prefix       string
		delimiter    string
		wantKeys     []string
		wantPrefixes []string
	}{
		{
			name:         "no_parameters_returns_the_whole_layout",
			wantKeys:     f.Keys,
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

			proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, build(f.ProxyBucket))
			require.NoError(t, err, "proxy listing must succeed")

			minioOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, build(f.MinIOBucket))
			require.NoError(t, err, "reference listing must succeed")

			assert.Equal(t, c.wantKeys, LstKeysOf(proxyOut.Contents),
				"proxy returned the wrong keys")
			assert.Equal(t, LstKeysOf(minioOut.Contents), LstKeysOf(proxyOut.Contents),
				"proxy and MinIO disagree on the key set")

			assert.Equal(t, c.wantPrefixes, LstPrefixesOf(proxyOut.CommonPrefixes),
				"proxy returned the wrong CommonPrefixes")
			assert.Equal(t, LstPrefixesOf(minioOut.CommonPrefixes), LstPrefixesOf(proxyOut.CommonPrefixes),
				"proxy and MinIO disagree on CommonPrefixes")

			assert.Equal(t, f.ProxyBucket, aws.ToString(proxyOut.Name),
				"<Name> must echo the bucket that was listed")
			assert.Equal(t, c.prefix, aws.ToString(proxyOut.Prefix),
				"<Prefix> must echo the request prefix")
			assert.Equal(t, aws.ToString(minioOut.Delimiter), aws.ToString(proxyOut.Delimiter),
				"<Delimiter> echo differs from the backend")

			assert.False(t, aws.ToBool(proxyOut.IsTruncated),
				"a listing well under max-keys must not be truncated")
			assert.Equal(t, aws.ToBool(minioOut.IsTruncated), aws.ToBool(proxyOut.IsTruncated),
				"proxy and MinIO disagree on IsTruncated")

			// AWS counts Contents plus CommonPrefixes in KeyCount; MinIO does
			// the same, and the proxy forwards the backend value untouched.
			assert.Equal(t, aws.ToInt32(minioOut.KeyCount), aws.ToInt32(proxyOut.KeyCount),
				"proxy and MinIO disagree on KeyCount")
			assert.Equal(t, int32(len(c.wantKeys)+len(c.wantPrefixes)), aws.ToInt32(proxyOut.KeyCount),
				"KeyCount must count Contents plus CommonPrefixes")

			assert.Empty(t, aws.ToString(proxyOut.NextContinuationToken),
				"an untruncated listing must not carry a continuation token")
		})
	}
}

// TestLstListObjectsV2Pagination pages the whole layout with max-keys smaller
// than the key set and asserts the union of the pages is the full set, in
// order, with no duplicates and no gaps. max-keys inside 1..1000 and the
// continuation token are the two parameters the proxy does forward, so this is
// the one paging path that works today.
func TestLstListObjectsV2Pagination(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	const pageSize = int32(3)

	collect := func(client *s3.Client, bucket string) ([][]string, []bool) {
		var pages [][]string
		var truncated []bool
		var token *string

		for i := 0; i < 10; i++ {
			out, err := client.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
				Bucket:            aws.String(bucket),
				MaxKeys:           aws.Int32(pageSize),
				ContinuationToken: token,
			})
			require.NoError(t, err, "paged listing of %s must succeed", bucket)

			pages = append(pages, LstKeysOf(out.Contents))
			truncated = append(truncated, aws.ToBool(out.IsTruncated))

			assert.LessOrEqual(t, int32(len(out.Contents)), pageSize,
				"a page must not exceed max-keys")
			assert.Equal(t, pageSize, aws.ToInt32(out.MaxKeys),
				"<MaxKeys> must echo the requested page size")
			assert.Equal(t, int32(len(out.Contents)), aws.ToInt32(out.KeyCount),
				"<KeyCount> must match the number of entries on the page")

			if !aws.ToBool(out.IsTruncated) {
				assert.Empty(t, aws.ToString(out.NextContinuationToken),
					"the final page must not carry a continuation token")
				return pages, truncated
			}
			require.NotEmpty(t, aws.ToString(out.NextContinuationToken),
				"a truncated listing must carry NextContinuationToken")
			token = out.NextContinuationToken
		}
		t.Fatalf("listing of %s did not terminate within 10 pages", bucket)
		return pages, truncated
	}

	proxyPages, proxyTruncated := collect(f.TC.ProxyClient, f.ProxyBucket)
	minioPages, minioTruncated := collect(f.TC.MinIOClient, f.MinIOBucket)

	assert.Equal(t, minioPages, proxyPages,
		"proxy and MinIO must page identically")
	assert.Equal(t, minioTruncated, proxyTruncated,
		"proxy and MinIO must agree on IsTruncated per page")

	// 7 keys at 3 per page: 3 + 3 + 1.
	require.Len(t, proxyPages, 3, "expected three pages for 7 keys at max-keys=3")
	assert.Equal(t, []bool{true, true, false}, proxyTruncated)

	var union []string
	seen := map[string]int{}
	for _, page := range proxyPages {
		union = append(union, page...)
		for _, k := range page {
			seen[k]++
		}
	}
	assert.Equal(t, f.Keys, union,
		"the union of the pages must be the full key set, in listing order")
	for k, n := range seen {
		assert.Equalf(t, 1, n, "key %q appeared on more than one page", k)
	}
	assert.Len(t, seen, len(f.Keys), "pages dropped or duplicated keys")
}

// ---------------------------------------------------------------------------
// THE CRUX OF TICKET 018: what <Size> means.
// ---------------------------------------------------------------------------

// TestLstListObjectsV2SizeIsCiphertextDeviation records, for objects of known
// plaintext length, which size the proxy reports in a listing.
//
// ANSWER, pinned here: the proxy reports the CIPHERTEXT size - the byte count
// the backend stores - which is plaintext + 28 for every AES-GCM whole object.
// It is not the plaintext length, and it is not what the proxy itself reports
// from HEAD or delivers from GET for the same key.
//
// AWS behaviour: <Size> is the size of the object body a GET returns. This is
// therefore a deviation from ADR 0010, which requires every listing size to
// describe the plaintext. `aws s3 sync` and rclone compare the listing size
// against the local file and re-transfer every object.
func TestLstListObjectsV2SizeIsCiphertextDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket),
	})
	require.NoError(t, err)

	// The same bucket read directly from the backend: these are the bytes at
	// rest, i.e. ciphertext.
	backendOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket),
	})
	require.NoError(t, err)

	// The plaintext reference bucket: what a listing of unencrypted objects says.
	refOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.MinIOBucket),
	})
	require.NoError(t, err)

	require.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents))
	require.Equal(t, f.Keys, LstKeysOf(backendOut.Contents))

	for _, key := range f.Keys {
		key := key
		t.Run(strings.ReplaceAll(key, "/", "_"), func(t *testing.T) {
			plaintext := f.Plaintext[key]
			proxySize := LstSizeOf(t, proxyOut.Contents, key)
			backendSize := LstSizeOf(t, backendOut.Contents, key)
			refSize := LstSizeOf(t, refOut.Contents, key)

			// Sanity: MinIO on plaintext reports the plaintext length, so the
			// oracle is sound.
			assert.Equal(t, plaintext, refSize,
				"the plaintext reference listing must report the plaintext length")

			// The stored object really is longer - encryption is happening.
			assert.Equal(t, LstStoredSize(plaintext), backendSize,
				"at rest the object must carry its segment framing and trailer")

			// DEVIATION (ADR 0010): the proxy forwards the backend size
			// verbatim instead of reporting the plaintext size.
			assert.Equal(t, backendSize, proxySize,
				"the proxy listing size is the raw backend size")
			assert.NotEqual(t, plaintext, proxySize,
				"if this ever passes, the ADR 0010 listing sizes have landed - update this test")
			assert.Equal(t, LstStoredSize(plaintext), proxySize,
				"the proxy over-reports by exactly the stored framing")

			// ...and the proxy contradicts itself: HEAD and GET on the same key
			// through the same proxy report and deliver the plaintext length.
			head, err := f.TC.ProxyClient.HeadObject(f.Ctx, &s3.HeadObjectInput{
				Bucket: aws.String(f.ProxyBucket), Key: aws.String(key),
			})
			require.NoError(t, err)
			assert.Equal(t, plaintext, aws.ToInt64(head.ContentLength),
				"HEAD reports the plaintext length")
			assert.NotEqual(t, aws.ToInt64(head.ContentLength), proxySize,
				"LIST and HEAD disagree about the size of the same object")

			get, err := f.TC.ProxyClient.GetObject(f.Ctx, &s3.GetObjectInput{
				Bucket: aws.String(f.ProxyBucket), Key: aws.String(key),
			})
			require.NoError(t, err)
			body, err := io.ReadAll(get.Body)
			require.NoError(t, err)
			require.NoError(t, get.Body.Close())

			assert.Equal(t, plaintext, int64(len(body)),
				"GET delivers the plaintext length, so the listing size is wrong about the body")
			assert.Equal(t,
				sha256.Sum256(LstBody(key, plaintext)),
				sha256.Sum256(body),
				"round-tripped content differs from the plaintext")
		})
	}
}

// ---------------------------------------------------------------------------
// Dropped request parameters (ADR 0010: honoured or refused, never dropped).
// ---------------------------------------------------------------------------

// TestLstListObjectsV2StartAfterIgnoredDeviation pins that the proxy drops
// start-after: a client paging by key gets the same first page forever.
// AWS and MinIO return only the keys strictly greater than start-after.
// ADR 0010 requires start-after to be honoured and echoed.
func TestLstListObjectsV2StartAfterIgnoredDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	const startAfter = "b.txt"
	wantAfter := []string{"dir1/x.txt", "dir1/y.txt", "dir2/z.txt", "space key.txt", "uni-äöü.txt"}

	minioOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.MinIOBucket), StartAfter: aws.String(startAfter),
	})
	require.NoError(t, err)
	require.Equal(t, wantAfter, LstKeysOf(minioOut.Contents),
		"the oracle must honour start-after")
	assert.Equal(t, startAfter, aws.ToString(minioOut.StartAfter),
		"S3 echoes <StartAfter>")

	proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket), StartAfter: aws.String(startAfter),
	})
	require.NoError(t, err)

	// DEVIATION: the parameter never reaches the backend.
	assert.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents),
		"the proxy ignores start-after and returns the whole bucket")
	assert.NotEqual(t, wantAfter, LstKeysOf(proxyOut.Contents),
		"if this ever fails, start-after is now forwarded - update this test")
	assert.Empty(t, aws.ToString(proxyOut.StartAfter),
		"the proxy does not echo <StartAfter> either")
}

// TestLstListObjectsV2MaxKeysZeroIgnoredDeviation pins the sharpest case of the
// max-keys handling ADR 0010 replaces: a value outside 1..1000 is dropped rather
// than honoured or rejected, so asking for zero keys returns up to a thousand.
func TestLstListObjectsV2MaxKeysZeroIgnoredDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	minioOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.MinIOBucket), MaxKeys: aws.Int32(0),
	})
	require.NoError(t, err)
	assert.Empty(t, LstKeysOf(minioOut.Contents),
		"the oracle returns no keys for max-keys=0")

	proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket), MaxKeys: aws.Int32(0),
	})
	require.NoError(t, err)

	// DEVIATION: max-keys=0 is silently dropped, the backend default applies.
	assert.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents),
		"the proxy ignores max-keys=0 and returns the whole bucket")
	assert.Equal(t, int32(1000), aws.ToInt32(proxyOut.MaxKeys),
		"the echoed <MaxKeys> is the backend default, not what the client asked for")
}

// TestLstListObjectsV2FetchOwnerIgnoredDeviation pins that fetch-owner is
// dropped, so <Owner> never appears in a V2 listing from the proxy.
// ADR 0010 honours fetch-owner, and answers with the requesting client's own
// access key id rather than the backend account.
func TestLstListObjectsV2FetchOwnerIgnoredDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	minioOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.MinIOBucket), FetchOwner: aws.Bool(true),
	})
	require.NoError(t, err)
	require.NotEmpty(t, minioOut.Contents)
	assert.NotNil(t, minioOut.Contents[0].Owner,
		"the oracle returns <Owner> when fetch-owner=true")

	proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket), FetchOwner: aws.Bool(true),
	})
	require.NoError(t, err)
	require.NotEmpty(t, proxyOut.Contents)

	// DEVIATION: fetch-owner never reaches the backend.
	for _, o := range proxyOut.Contents {
		assert.Nilf(t, o.Owner, "the proxy never returns <Owner> for %q", aws.ToString(o.Key))
	}
}

// TestLstListObjectsV2EncodingTypeIgnoredDeviation covers the space and unicode
// keys with encoding-type=url.
//
// AWS: the keys come back percent-encoded and <EncodingType>url</EncodingType>
// is echoed, so a key containing bytes that are hostile to the client's XML
// reader survives the trip.
//
// Proxy: the parameter is dropped, keys come back raw and <EncodingType> is
// echoed empty. ADR 0010 honours encoding-type and echoes it.
//
// Note on the oracle: MinIO encodes a space as "+", where AWS S3 uses "%20".
// That is a MinIO deviation from AWS, which is why this test decodes with
// url.QueryUnescape (which accepts both) rather than comparing literals.
func TestLstListObjectsV2EncodingTypeIgnoredDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	minioOut, err := f.TC.MinIOClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.MinIOBucket), EncodingType: s3types.EncodingTypeUrl,
	})
	require.NoError(t, err)
	assert.Equal(t, s3types.EncodingTypeUrl, minioOut.EncodingType,
		"the oracle echoes <EncodingType>url</EncodingType>")

	minioKeys := LstKeysOf(minioOut.Contents)
	require.Len(t, minioKeys, len(f.Keys))

	// The awkward keys really are encoded on the wire, and decode back exactly.
	encodedSeen := 0
	decoded := make([]string, 0, len(minioKeys))
	for _, k := range minioKeys {
		plain, decErr := url.QueryUnescape(k)
		require.NoErrorf(t, decErr, "listed key %q is not valid URL encoding", k)
		decoded = append(decoded, plain)
		if plain != k {
			encodedSeen++
		}
	}
	assert.Equal(t, f.Keys, decoded,
		"URL-decoding the oracle keys must give back the originals")
	assert.GreaterOrEqual(t, encodedSeen, 2,
		"the space key and the unicode key must both be encoded by the oracle")

	proxyOut, err := f.TC.ProxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(f.ProxyBucket), EncodingType: s3types.EncodingTypeUrl,
	})
	require.NoError(t, err)

	// DEVIATION: encoding-type is dropped, so nothing is encoded and nothing is
	// echoed. The keys are still correct, they are just not what was asked for.
	assert.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents),
		"the proxy returns raw, unencoded keys despite encoding-type=url")
	assert.Equal(t, s3types.EncodingType(""), proxyOut.EncodingType,
		"the proxy echoes an empty <EncodingType>")
	assert.NotEqual(t, minioKeys, LstKeysOf(proxyOut.Contents),
		"if this ever fails, encoding-type is now forwarded - update this test")
}

// ---------------------------------------------------------------------------
// ListObjects V1.
// ---------------------------------------------------------------------------

// TestLstListObjectsV1MatchesMinIO covers the V1 parameters the proxy forwards
// (prefix, delimiter, marker) and pins the one it drops (max-keys).
func TestLstListObjectsV1MatchesMinIO(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	t.Run("no_parameters", func(t *testing.T) {
		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket),
		})
		require.NoError(t, err)
		minioOut, err := f.TC.MinIOClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.MinIOBucket),
		})
		require.NoError(t, err)

		assert.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents))
		assert.Equal(t, LstKeysOf(minioOut.Contents), LstKeysOf(proxyOut.Contents))
		assert.False(t, aws.ToBool(proxyOut.IsTruncated))
	})

	t.Run("delimiter_slash", func(t *testing.T) {
		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)
		minioOut, err := f.TC.MinIOClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.MinIOBucket), Delimiter: aws.String("/"),
		})
		require.NoError(t, err)

		assert.Equal(t, []string{"a.txt", "b.txt", "space key.txt", "uni-äöü.txt"},
			LstKeysOf(proxyOut.Contents))
		assert.Equal(t, []string{"dir1/", "dir2/"}, LstPrefixesOf(proxyOut.CommonPrefixes))
		assert.Equal(t, LstPrefixesOf(minioOut.CommonPrefixes), LstPrefixesOf(proxyOut.CommonPrefixes))
	})

	t.Run("marker_is_forwarded", func(t *testing.T) {
		const marker = "b.txt"
		want := []string{"dir1/x.txt", "dir1/y.txt", "dir2/z.txt", "space key.txt", "uni-äöü.txt"}

		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket), Marker: aws.String(marker),
		})
		require.NoError(t, err)
		minioOut, err := f.TC.MinIOClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.MinIOBucket), Marker: aws.String(marker),
		})
		require.NoError(t, err)

		assert.Equal(t, want, LstKeysOf(proxyOut.Contents),
			"V1 marker is one of the three parameters the proxy does forward")
		assert.Equal(t, LstKeysOf(minioOut.Contents), LstKeysOf(proxyOut.Contents))
	})

	t.Run("max_keys_ignored_deviation", func(t *testing.T) {
		// The V1 branch of handleListObjects reads prefix, delimiter and marker
		// only - max-keys is not parsed at all, so a V1 client cannot page.
		// ADR 0010 requires V1 max-keys to be honoured too.
		minioOut, err := f.TC.MinIOClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.MinIOBucket), MaxKeys: aws.Int32(3),
		})
		require.NoError(t, err)
		require.Len(t, minioOut.Contents, 3, "the oracle honours V1 max-keys")
		assert.True(t, aws.ToBool(minioOut.IsTruncated))

		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket), MaxKeys: aws.Int32(3),
		})
		require.NoError(t, err)

		// DEVIATION.
		assert.Equal(t, f.Keys, LstKeysOf(proxyOut.Contents),
			"the proxy ignores V1 max-keys and returns the whole bucket")
		assert.False(t, aws.ToBool(proxyOut.IsTruncated),
			"and therefore never reports truncation")
	})

	t.Run("owner_of_the_backend_account_is_passed_through", func(t *testing.T) {
		// V1 listings always carry <Owner> from the backend, and the proxy
		// forwards it verbatim. A proxy client authenticated as a proxy
		// identity therefore learns the backend account's display name and
		// canonical ID. Recorded here as the current behaviour; ADR 0010
		// replaces it.
		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket),
		})
		require.NoError(t, err)
		require.NotEmpty(t, proxyOut.Contents)

		minioOut, err := f.TC.MinIOClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.MinIOBucket),
		})
		require.NoError(t, err)
		require.NotEmpty(t, minioOut.Contents)

		require.NotNil(t, proxyOut.Contents[0].Owner)
		require.NotNil(t, minioOut.Contents[0].Owner)
		assert.Equal(t,
			aws.ToString(minioOut.Contents[0].Owner.ID),
			aws.ToString(proxyOut.Contents[0].Owner.ID),
			"the proxy hands the client the backend account's canonical ID")
	})

	t.Run("size_is_ciphertext_here_too", func(t *testing.T) {
		proxyOut, err := f.TC.ProxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{
			Bucket: aws.String(f.ProxyBucket),
		})
		require.NoError(t, err)
		for _, o := range proxyOut.Contents {
			key := aws.ToString(o.Key)
			assert.Equalf(t, LstStoredSize(f.Plaintext[key]), aws.ToInt64(o.Size),
				"V1 <Size> for %q is the ciphertext size, not the plaintext size of ADR 0010", key)
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
				"proxy and MinIO disagree on the status for a missing bucket")
			assert.Equal(t, apiCodeOf(minioErr), apiCodeOf(proxyErr),
				"proxy and MinIO disagree on the error code for a missing bucket")
		})
	}
}

// ---------------------------------------------------------------------------
// The wire document (ADR 0010: a real S3 ListBucketResult).
// ---------------------------------------------------------------------------

// TestLstListObjectsResponseDocumentDeviation asserts on the raw XML the proxy
// puts on the wire, which is what a strict client or an XSD validator sees.
// aws-sdk-go-v2 and minio-go match elements by local name and ignore the root,
// which is the only reason this has not broken anything yet.
//
// Everything asserted about the proxy here is a deviation from S3's
// ListBucketResult; the MinIO half of each assertion is the reference.
func TestLstListObjectsResponseDocumentDeviation(t *testing.T) {
	f, cleanup := LstNewFixtureContext(t)
	defer cleanup()

	proxyClient, proxyRec := LstNewRecordingClient(t,
		integration.ProxyEndpoint, integration.ProxyTestAccessKey, integration.ProxyTestSecretKey)
	minioClient, minioRec := LstNewRecordingClient(t,
		integration.MinIOEndpoint, integration.MinIOAccessKey, integration.MinIOSecretKey)

	_, err := proxyClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{Bucket: aws.String(f.ProxyBucket)})
	require.NoError(t, err)
	proxyDoc := string(proxyRec.Body)

	_, err = minioClient.ListObjectsV2(f.Ctx, &s3.ListObjectsV2Input{Bucket: aws.String(f.MinIOBucket)})
	require.NoError(t, err)
	minioDoc := string(minioRec.Body)

	t.Run("reference_document_is_a_ListBucketResult", func(t *testing.T) {
		assert.True(t, strings.HasPrefix(minioDoc, `<?xml version="1.0" encoding="UTF-8"?>`),
			"S3 emits an XML declaration")
		assert.Contains(t, minioDoc, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`,
			"S3 emits ListBucketResult in the 2006-03-01 namespace")
	})

	t.Run("proxy_document_is_the_marshalled_sdk_struct", func(t *testing.T) {
		// DEVIATION: root element named after the Go SDK output type.
		assert.True(t, strings.HasPrefix(proxyDoc, "<ListObjectsV2Output>"),
			"the proxy root element is the SDK type name, not <ListBucketResult>")
		assert.NotContains(t, proxyDoc, "ListBucketResult",
			"if this ever fails, the ADR 0010 listing document has landed - update this test")
		assert.NotContains(t, proxyDoc, "xmlns",
			"the proxy emits no XML namespace")
		assert.NotContains(t, proxyDoc, "<?xml",
			"the proxy emits no XML declaration")

		// DEVIATION: SDK plumbing and empty enum fields leak onto the wire.
		assert.Contains(t, proxyDoc, "<ResultMetadata></ResultMetadata>",
			"middleware.Metadata is marshalled into the response")
		assert.Contains(t, proxyDoc, "<ChecksumType></ChecksumType>",
			"the zero value of the non-pointer ChecksumType enum is emitted")
		assert.Contains(t, proxyDoc, "<RequestCharged></RequestCharged>",
			"the zero value of the non-pointer RequestCharged enum is emitted")
		assert.Contains(t, proxyDoc, "<EncodingType></EncodingType>",
			"an empty EncodingType is emitted even when the client asked for none")

		// What the encoder gets right and a rewrite must not lose: keys and
		// ETags are escaped by encoding/xml rather than concatenated.
		assert.Contains(t, proxyDoc, "<Key>space key.txt</Key>")
		assert.Contains(t, proxyDoc, "<Key>uni-äöü.txt</Key>")
		assert.Contains(t, proxyDoc, "&#34;", "the ETag quotes are XML-escaped")

		assert.Equal(t, "application/xml", proxyRec.Header.Get("Content-Type"))
	})

	t.Run("no_s3ep_metadata_leaks_into_the_listing", func(t *testing.T) {
		// The proxy filters its own metadata out of client responses; a listing
		// carries no user metadata at all, so neither document may mention it.
		assert.NotContains(t, strings.ToLower(proxyDoc), "s3ep-",
			"encryption metadata must never appear in a client listing")
		for name := range proxyRec.Header {
			assert.NotContains(t, strings.ToLower(name), "s3ep-",
				"encryption metadata must not appear in listing response headers")
		}
	})

	t.Run("v1_document_is_the_marshalled_sdk_struct_too", func(t *testing.T) {
		_, err := proxyClient.ListObjects(f.Ctx, &s3.ListObjectsInput{Bucket: aws.String(f.ProxyBucket)})
		require.NoError(t, err)
		v1Doc := string(proxyRec.Body)

		// DEVIATION: same defect family in the V1 branch.
		assert.True(t, strings.HasPrefix(v1Doc, "<ListObjectsOutput>"),
			"the V1 root element is the SDK type name, not <ListBucketResult>")
		assert.Contains(t, v1Doc, "<ResultMetadata></ResultMetadata>")
	})
}

// TestLstListObjectsV2XMLEscaping checks that keys carrying XML metacharacters
// survive a listing. This is the one property of the current handler that the
// ADR 0010 listing rewrite must not lose, so it is asserted as correct behaviour
// rather than as a deviation.
func TestLstListObjectsV2XMLEscaping(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	refBucket := "lst-esc-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, refBucket)
	defer integration.CleanupTestBucket(t, tc.MinIOClient, refBucket)

	keys := []string{`amp&ersand.txt`, `angle<bracket>.txt`, `quote"and'apos.txt`}
	sort.Strings(keys)

	for _, k := range keys {
		body := LstBody(k, 19)
		_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(k),
			Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))),
		})
		require.NoErrorf(t, err, "PUT %q through the proxy", k)

		_, err = tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(refBucket), Key: aws.String(k),
			Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))),
		})
		require.NoErrorf(t, err, "PUT %q directly into MinIO", k)
	}

	proxyOut, err := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(tc.TestBucket),
	})
	require.NoError(t, err)

	minioOut, err := tc.MinIOClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(refBucket),
	})
	require.NoError(t, err)

	assert.Equal(t, keys, LstKeysOf(proxyOut.Contents),
		"XML metacharacters in keys must round-trip through the listing")
	assert.Equal(t, LstKeysOf(minioOut.Contents), LstKeysOf(proxyOut.Contents),
		"proxy and MinIO disagree on keys containing XML metacharacters")
}
