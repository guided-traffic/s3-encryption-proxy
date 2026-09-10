//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/xml"
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

// Ranged GET conformance, checked differentially: every request is sent twice,
// once through the proxy against an encrypted object and once straight to MinIO
// against a plaintext copy of the same bytes in a second bucket. MinIO is the
// oracle for status, error code, Content-Range, Content-Length and body.
//
// The edge cases here are the ones test/integration/360-degree-variants/
// range_read_test.go does not cover: the error shapes (416, malformed, multiple
// ranges), the exact headers on the wire, and the tail window that overruns the
// plaintext end - the case where segment nonce and tag bytes would leak into a
// client's read if the proxy served the backend's ciphertext window verbatim.
//
// Requests are built and signed by hand rather than through the SDK: the SDK
// normalises away exactly what is under test (the status line of a 416, whether
// Content-Range is present at all, the literal Content-Length header) and it
// will not put a malformed Range header on the wire.

// rngEmptyPayloadSHA256 is the SigV4 payload hash of a body-less request.
const rngEmptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// rngSizes are the object sizes every case runs against. 1 byte and 1 KiB fit
// into a single segment, 6 MiB spans several, so the window planner has to skip
// whole segments before it reaches the first requested byte. Several of the
// findings below only appear on one of the two.
var rngSizes = []struct {
	name string
	size int
}{
	{"1B_gcm", 1},
	{"1KiB_gcm", 1024},
	{"6MiB_ctr", 6 << 20},
}

// rngObserved is everything a client can act on in the answer to a ranged GET.
type rngObserved struct {
	status        int
	code          string
	contentRange  string
	contentLength string
	acceptRanges  string
	bodySHA       [32]byte
	bodyLen       int
}

func (o rngObserved) String() string {
	return fmt.Sprintf("status=%d code=%q Content-Range=%q Content-Length=%q Accept-Ranges=%q body=%d bytes",
		o.status, o.code, o.contentRange, o.contentLength, o.acceptRanges, o.bodyLen)
}

// rngRawGet issues a signed GET with an arbitrary, possibly malformed Range
// header and reports the raw HTTP answer.
func rngRawGet(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket, key, rangeHeader string) rngObserved {
	t.Helper()

	url := fmt.Sprintf("%s/%s/%s", endpoint, bucket, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	require.NoError(t, integration.SignHTTPRequestForS3(
		req, accessKey, secretKey, integration.TestRegion, rngEmptyPayloadSHA256))

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoErrorf(t, err, "GET %s with Range %q", url, rangeHeader)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	observed := rngObserved{
		status:        resp.StatusCode,
		contentRange:  resp.Header.Get("Content-Range"),
		contentLength: resp.Header.Get("Content-Length"),
		acceptRanges:  resp.Header.Get("Accept-Ranges"),
		bodySHA:       sha256.Sum256(body),
		bodyLen:       len(body),
	}
	if resp.StatusCode >= 300 {
		var doc struct {
			XMLName xml.Name `xml:"Error"`
			Code    string   `xml:"Code"`
		}
		if xml.Unmarshal(body, &doc) == nil {
			observed.code = doc.Code
		}
	}
	return observed
}

func rngViaProxy(t *testing.T, ctx context.Context, bucket, key, rangeHeader string) rngObserved {
	t.Helper()
	return rngRawGet(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey, bucket, key, rangeHeader)
}

func rngViaMinIO(t *testing.T, ctx context.Context, bucket, key, rangeHeader string) rngObserved {
	t.Helper()
	return rngRawGet(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey, bucket, key, rangeHeader)
}

// rngFixture is the paired setup every test here uses: the harness bucket
// written through the proxy, plus a second bucket written directly into MinIO
// that holds the same plaintext and serves as the oracle.
type rngFixture struct {
	tc           *integration.TestContext
	directBucket string
}

func rngNewFixture(t *testing.T, ctx context.Context) *rngFixture {
	t.Helper()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	t.Cleanup(tc.CleanupTestBucket)

	directBucket := "rng-oracle-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, directBucket)
	t.Cleanup(func() { integration.CleanupTestBucket(t, tc.MinIOClient, directBucket) })

	return &rngFixture{tc: tc, directBucket: directBucket}
}

// putPair stores the same plaintext twice: through the proxy, where it is
// encrypted at rest, and straight into the oracle bucket, where it is not.
func (f *rngFixture) putPair(t *testing.T, ctx context.Context, key string, payload []byte) {
	t.Helper()

	_, err := f.tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(f.tc.TestBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err, "upload through the proxy")

	_, err = f.tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(f.directBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err, "upload straight into MinIO")

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = f.tc.ProxyClient.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(f.tc.TestBucket), Key: aws.String(key),
		})
		_, _ = f.tc.MinIOClient.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(f.directBucket), Key: aws.String(key),
		})
	})
}

// rngPayload returns size random bytes.
func rngPayload(t *testing.T, size int) []byte {
	t.Helper()
	payload := make([]byte, size)
	if size > 0 {
		_, err := rand.Read(payload)
		require.NoError(t, err)
	}
	return payload
}

// rngCase is one Range header and the window a conforming S3 must answer with.
type rngCase struct {
	name   string
	header string
	// satisfiable false means the answer must be 416 InvalidRange.
	satisfiable bool
	start       int
	length      int
}

// rngCasesFor builds the edge cases for an object of size n, with the window
// AWS S3 is documented to return for each.
func rngCasesFor(n int) []rngCase {
	suffixStart, suffixLen := 0, n
	if n > 100 {
		suffixStart, suffixLen = n-100, 100
	}
	return []rngCase{
		{"first_byte", "bytes=0-0", true, 0, 1},
		{"whole_object", fmt.Sprintf("bytes=0-%d", n-1), true, 0, n},
		{"last_byte", fmt.Sprintf("bytes=%d-%d", n-1, n-1), true, n - 1, 1},
		// A suffix longer than the object is clamped to the whole object.
		{"suffix_100", "bytes=-100", true, suffixStart, suffixLen},
		// Open ended: satisfiable only while the start is inside the object.
		{"open_ended_from_100", "bytes=100-", n > 100, 100, n - 100},
		// Entirely past the end.
		{"past_end", fmt.Sprintf("bytes=%d-%d", n, n+10), false, 0, 0},
		// Start after end.
		{"start_after_end", "bytes=5-2", false, 0, 0},
		// A zero-length suffix can never be satisfied.
		{"zero_suffix", "bytes=-0", false, 0, 0},
	}
}

// TestRngRangedGetMatchesMinIO is the core conformance check: for every edge
// case the proxy must answer exactly as the backend it fronts does, and a
// satisfiable range must return the matching slice of the original plaintext.
//
// Returning the right number of wrong bytes is the failure that matters here,
// so the body is compared by SHA-256 against the expected plaintext window and
// against MinIO's answer, not only by length.
func TestRngRangedGetMatchesMinIO(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := rngNewFixture(t, ctx)

	for _, sz := range rngSizes {
		t.Run(sz.name, func(t *testing.T) {
			payload := rngPayload(t, sz.size)
			key := fmt.Sprintf("rng-range-%s-%s", sz.name, integration.RandomString(8))
			f.putPair(t, ctx, key, payload)

			for _, c := range rngCasesFor(sz.size) {
				t.Run(c.name, func(t *testing.T) {
					proxy := rngViaProxy(t, ctx, f.tc.TestBucket, key, c.header)
					oracle := rngViaMinIO(t, ctx, f.directBucket, key, c.header)

					require.Equalf(t, oracle.status, proxy.status,
						"Range %q: status differs\n  proxy: %s\n  minio: %s", c.header, proxy, oracle)
					require.Equalf(t, oracle.code, proxy.code,
						"Range %q: S3 error code differs\n  proxy: %s\n  minio: %s", c.header, proxy, oracle)

					if !c.satisfiable {
						// AWS answers an unsatisfiable range with 416
						// InvalidRange. The Content-Range header that belongs
						// on that response is asserted separately in
						// TestRngUnsatisfiableRangeContentRange, because the
						// proxy only sometimes sends it.
						require.Equal(t, http.StatusRequestedRangeNotSatisfiable, proxy.status,
							"an unsatisfiable range must be 416")
						require.Equal(t, "InvalidRange", proxy.code)
						return
					}

					want := payload[c.start : c.start+c.length]
					wantRange := fmt.Sprintf("bytes %d-%d/%d", c.start, c.start+c.length-1, sz.size)

					require.Equal(t, http.StatusPartialContent, proxy.status,
						"a satisfiable range must be answered with 206")
					require.Equalf(t, wantRange, proxy.contentRange,
						"Range %q: Content-Range must describe plaintext offsets and the plaintext size", c.header)
					require.Equalf(t, fmt.Sprint(c.length), proxy.contentLength,
						"Range %q: Content-Length must be the length of the returned window", c.header)
					require.Equalf(t, c.length, proxy.bodyLen,
						"Range %q: wrong number of bytes returned", c.header)
					require.Equalf(t, sha256.Sum256(want), proxy.bodySHA,
						"Range %q: the returned window is the wrong slice of the object", c.header)

					// The proxy and the backend must agree byte for byte and
					// header for header on a satisfiable range.
					require.Equalf(t, oracle.bodySHA, proxy.bodySHA,
						"Range %q: proxy and MinIO returned different bytes", c.header)
					require.Equalf(t, oracle.contentRange, proxy.contentRange,
						"Range %q: Content-Range differs from the backend", c.header)
					require.Equalf(t, oracle.contentLength, proxy.contentLength,
						"Range %q: Content-Length differs from the backend", c.header)
					assert.Equalf(t, "bytes", proxy.acceptRanges,
						"Range %q: a 206 must advertise Accept-Ranges: bytes", c.header)
				})
			}
		})
	}
}

// TestRngGCMOverheadNeverLeaksIntoRangedReads pins the case where the stored
// object is longer than the plaintext.
//
// The sealed chain is longer than the plaintext it holds - a header, and a
// nonce and a tag per segment - so a window that runs past the end of the
// plaintext is still satisfiable against the stored bytes. If the proxy passed
// that window through, the client would receive nonce and tag bytes as if they
// were object content, with a Content-Range that claims they belong to the
// object.
func TestRngGCMOverheadNeverLeaksIntoRangedReads(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := rngNewFixture(t, ctx)

	for _, sz := range rngSizes {
		t.Run(sz.name, func(t *testing.T) {
			payload := rngPayload(t, sz.size)
			key := fmt.Sprintf("rng-overrun-%s-%s", sz.name, integration.RandomString(8))
			f.putPair(t, ctx, key, payload)

			// Tail window that starts inside the object and ends well past its
			// last plaintext byte.
			start := sz.size - 5
			if start < 0 {
				start = 0
			}
			header := fmt.Sprintf("bytes=%d-%d", start, sz.size+20)
			wantLen := sz.size - start

			proxy := rngViaProxy(t, ctx, f.tc.TestBucket, key, header)
			oracle := rngViaMinIO(t, ctx, f.directBucket, key, header)

			require.Equal(t, http.StatusPartialContent, proxy.status,
				"a window that starts inside the object is satisfiable")
			require.Equalf(t, fmt.Sprintf("bytes %d-%d/%d", start, sz.size-1, sz.size), proxy.contentRange,
				"Range %q: the end must be clamped to the last plaintext byte", header)
			require.Equalf(t, fmt.Sprint(wantLen), proxy.contentLength,
				"Range %q: Content-Length must not include encryption overhead", header)
			require.Equalf(t, wantLen, proxy.bodyLen,
				"Range %q: the response body must not include encryption overhead", header)
			require.Equalf(t, sha256.Sum256(payload[start:]), proxy.bodySHA,
				"Range %q: the tail window returned the wrong bytes", header)

			require.Equal(t, oracle.status, proxy.status)
			require.Equal(t, oracle.contentRange, proxy.contentRange)
			require.Equal(t, oracle.contentLength, proxy.contentLength)
			require.Equalf(t, oracle.bodySHA, proxy.bodySHA,
				"Range %q: proxy and MinIO returned different bytes", header)
		})
	}
}

// TestRngMalformedRangeHeader encodes a DEVIATION.
//
// AWS S3 ignores a Range header it cannot parse and answers 200 with the whole
// object; MinIO does the same. The proxy has one read path and follows the
// backend, so the answer no longer depends on the object size. The assertions
// below hold that agreement in place.
func TestRngMalformedRangeHeader(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := rngNewFixture(t, ctx)

	for _, sz := range rngSizes {
		t.Run(sz.name, func(t *testing.T) {
			payload := rngPayload(t, sz.size)
			key := fmt.Sprintf("rng-malformed-%s-%s", sz.name, integration.RandomString(8))
			f.putPair(t, ctx, key, payload)

			const header = "bytes=abc"
			proxy := rngViaProxy(t, ctx, f.tc.TestBucket, key, header)
			oracle := rngViaMinIO(t, ctx, f.directBucket, key, header)

			// AWS and MinIO both ignore a Range header they cannot parse and
			// serve the whole object. The proxy used to answer 400 for it on one
			// of its two read paths; there is one read path now, and it does what
			// the backend does.
			require.Equal(t, http.StatusOK, oracle.status,
				"MinIO is expected to ignore a malformed Range header, as AWS does")
			require.Equal(t, sha256.Sum256(payload), oracle.bodySHA)

			require.Equal(t, oracle.status, proxy.status,
				"a malformed Range header must be ignored, not refused")
			require.Equal(t, sha256.Sum256(payload), proxy.bodySHA,
				"an ignored Range header must yield the whole object")
			require.Equal(t, fmt.Sprint(sz.size), proxy.contentLength)
		})
	}
}

// TestRngMultipleRanges encodes a DEVIATION.
//
// AWS S3 does not support more than one range per GET: it ignores the header
// and returns the whole object with 200 (it never answers
// multipart/byteranges). MinIO behaves the same way, and so does the proxy -
// one read path, one answer, whatever the object size.
func TestRngMultipleRanges(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := rngNewFixture(t, ctx)

	for _, sz := range rngSizes {
		t.Run(sz.name, func(t *testing.T) {
			payload := rngPayload(t, sz.size)
			key := fmt.Sprintf("rng-multirange-%s-%s", sz.name, integration.RandomString(8))
			f.putPair(t, ctx, key, payload)

			const header = "bytes=0-1,5-6"
			proxy := rngViaProxy(t, ctx, f.tc.TestBucket, key, header)
			oracle := rngViaMinIO(t, ctx, f.directBucket, key, header)

			require.Equal(t, http.StatusOK, oracle.status,
				"MinIO is expected to ignore a multi-range header and return the whole object, as AWS does")
			require.NotContains(t, oracle.contentRange, ",",
				"neither AWS nor MinIO answer multipart/byteranges")

			// A multi-range header is ignored and the whole object is served, as
			// AWS and MinIO do. One read path, one answer.
			require.Equal(t, oracle.status, proxy.status,
				"a multi-range header must be ignored, not refused")
			require.Equal(t, sha256.Sum256(payload), proxy.bodySHA,
				"an ignored Range header must yield the whole object")
		})
	}
}

// TestRngUnsatisfiableRangeContentRange encodes a DEVIATION.
//
// RFC 7233 and AWS S3 put Content-Range: bytes */<size> on a 416 so the client
// learns the object size from the rejection instead of having to issue a HEAD.
// The proxy sends it only in one narrow case: a window that is unsatisfiable
// against the plaintext but still satisfiable against the longer sealed chain,
// so that the request survives the backend and reaches the proxy's own range
// parser. Every other 416 is a backend error passed through, and the header is
// dropped on that path.
//
// MinIO omits the header everywhere, so a plain proxy-versus-MinIO comparison
// would call the one correct case a difference. Both sides are recorded here.
func TestRngUnsatisfiableRangeContentRange(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	f := rngNewFixture(t, ctx)

	for _, sz := range rngSizes {
		t.Run(sz.name, func(t *testing.T) {
			payload := rngPayload(t, sz.size)
			key := fmt.Sprintf("rng-416-%s-%s", sz.name, integration.RandomString(8))
			f.putPair(t, ctx, key, payload)

			// A window that starts exactly at the end of the plaintext. The
			// sealed chain is longer than that, so this is still inside the
			// stored object and the backend answers 206.
			pastEnd := fmt.Sprintf("bytes=%d-%d", sz.size, sz.size+10)
			// Far past the end of both plaintext and ciphertext, so the
			// backend itself rejects it and the proxy relays that answer.
			farPastEnd := fmt.Sprintf("bytes=%d-%d", sz.size+1024, sz.size+2048)

			for _, c := range []struct {
				name   string
				header string
			}{{"just_past_the_plaintext_end", pastEnd}, {"far_past_the_end", farPastEnd}} {
				t.Run(c.name, func(t *testing.T) {
					proxy := rngViaProxy(t, ctx, f.tc.TestBucket, key, c.header)
					oracle := rngViaMinIO(t, ctx, f.directBucket, key, c.header)

					require.Equal(t, http.StatusRequestedRangeNotSatisfiable, proxy.status)
					require.Equal(t, "InvalidRange", proxy.code)
					require.Equal(t, oracle.status, proxy.status)
					require.Equal(t, oracle.code, proxy.code)

					// Recorded backend behaviour: MinIO omits Content-Range on a
					// 416 where AWS sends bytes */size.
					assert.Empty(t, oracle.contentRange,
						"recorded backend behaviour: MinIO omits Content-Range on 416, AWS sends bytes */size")

					// The proxy composes its own answer rather than relaying the
					// backend's (ADR 0008), and it knows the plaintext size, so
					// every 416 it sends tells the client what the object's size
					// is - which is what AWS does and what a client needs to
					// correct its next request.
					assert.Equalf(t, fmt.Sprintf("bytes */%d", sz.size), proxy.contentRange,
						"a 416 must report the plaintext size")
				})
			}
		})
	}
}
