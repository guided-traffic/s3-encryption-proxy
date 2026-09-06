//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Client-driven multipart upload conformance.
//
// Every behaviour is run twice where the comparison is meaningful: once through
// the proxy against the proxy bucket, once straight into MinIO against a bucket
// this file creates itself. MinIO is the oracle for "what an S3 implementation
// answers here"; the AWS documentation is the oracle for "what it should be".
// Where the proxy and MinIO disagree, or where both disagree with AWS, the test
// asserts the ACTUAL behaviour and the comment above it names the deviation, so
// the suite stays green and the gap stays visible.
//
// Deviations encoded below (search for DEVIATION):
//   D1 CompleteMultipartUpload with parts out of order is accepted (AWS/MinIO: InvalidPartOrder)
//   D2 CompleteMultipartUpload with an empty part list answers 500 InternalError (AWS: MalformedXML)
//   D3 UploadPart with partNumber 0 / 10001 answers 400 text/plain, no S3 error document
//   D4 UploadPart against an unknown uploadId answers 400 text/plain (AWS: 404 NoSuchUpload)
//   D5 ListParts is a stub: it answers 200 with an empty part list for ANY uploadId,
//      including an aborted or never-created one (AWS: real parts, and NoSuchUpload)
//   D6 ListMultipartUploads answers 501 NotImplemented
//   D7 the completed object carries a single-part ETag, not the "<md5>-<partcount>" form
//   D8 Complete against an aborted/unknown uploadId answers 500 InternalError (AWS: 404 NoSuchUpload)
//   D9 an UploadPart that arrives before its predecessors never returns; it blocks
//      until they do, with no context in the wait (AWS: any upload order, answered at once)

const (
	// MpuMinPartSize is the AWS minimum size of a non-final part.
	MpuMinPartSize = 5 * 1024 * 1024
	// MpuMetaPrefix is the metadata_key_prefix the demo stack runs with.
	MpuMetaPrefix = "s3ep-"
)

// MpuTarget is one side of the differential comparison: a client and the bucket
// that client owns.
type MpuTarget struct {
	Name   string
	Client *s3.Client
	Bucket string
}

// MpuTargets returns the proxy side (tc.TestBucket through tc.ProxyClient) and a
// direct-to-MinIO side backed by a bucket created and torn down here. The direct
// bucket is uniquely named and only ever touched by this test.
func MpuTargets(t *testing.T, tc *integration.TestContext) (MpuTarget, MpuTarget) {
	t.Helper()

	direct := "mpu-direct-" + integration.RandomString(12)
	integration.CreateTestBucket(t, tc.MinIOClient, direct)
	t.Cleanup(func() { integration.CleanupTestBucket(t, tc.MinIOClient, direct) })

	return MpuTarget{Name: "proxy", Client: tc.ProxyClient, Bucket: tc.TestBucket},
		MpuTarget{Name: "minio", Client: tc.MinIOClient, Bucket: direct}
}

// MpuKey builds a unique object key for a case.
func MpuKey(prefix string) string {
	return fmt.Sprintf("mpu-%s-%s", prefix, integration.RandomString(10))
}

// MpuPayload returns n random bytes.
func MpuPayload(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}

// MpuDigest is the sha256 of b as hex. Payloads are only ever compared by this,
// never dumped.
func MpuDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// MpuCreate starts an upload and registers an abort so a failing test never
// leaves a pending upload behind in the shared MinIO.
func MpuCreate(t *testing.T, ctx context.Context, tg MpuTarget, key string) string {
	t.Helper()

	out, err := tg.Client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tg.Bucket),
		Key:    aws.String(key),
	})
	require.NoErrorf(t, err, "%s: CreateMultipartUpload", tg.Name)
	require.NotNilf(t, out.UploadId, "%s: CreateMultipartUpload returned no UploadId", tg.Name)
	require.Equalf(t, tg.Bucket, aws.ToString(out.Bucket), "%s: CreateMultipartUpload echoed the wrong bucket", tg.Name)
	require.Equalf(t, key, aws.ToString(out.Key), "%s: CreateMultipartUpload echoed the wrong key", tg.Name)

	uploadID := *out.UploadId
	t.Cleanup(func() { MpuAbortQuiet(tg, key, uploadID) })
	return uploadID
}

// MpuAbortQuiet aborts an upload and ignores the outcome; it is cleanup only.
func MpuAbortQuiet(tg MpuTarget, key, uploadID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = tg.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(tg.Bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	})
}

// MpuPart uploads one part and returns the ETag the server reported.
func MpuPart(t *testing.T, ctx context.Context, tg MpuTarget, key, uploadID string, partNumber int, data []byte) string {
	t.Helper()

	out, err := tg.Client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(tg.Bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)),
		Body:          bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))),
	})
	require.NoErrorf(t, err, "%s: UploadPart %d", tg.Name, partNumber)
	require.NotNilf(t, out.ETag, "%s: UploadPart %d returned no ETag", tg.Name, partNumber)
	return aws.ToString(out.ETag)
}

// MpuComplete finishes an upload with exactly the part list it is given, in the
// order it is given, and returns the raw error for inspection.
func MpuComplete(ctx context.Context, tg MpuTarget, key, uploadID string, parts []types.CompletedPart) (*s3.CompleteMultipartUploadOutput, error) {
	return tg.Client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(tg.Bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
}

// MpuPartRef builds a CompletedPart entry.
func MpuPartRef(partNumber int, etag string) types.CompletedPart {
	return types.CompletedPart{PartNumber: aws.Int32(int32(partNumber)), ETag: aws.String(etag)}
}

// MpuShape is the client-observable rendering of a failure.
type MpuShape struct {
	Status  int
	Code    string
	Message string
}

func (s MpuShape) String() string {
	return fmt.Sprintf("status=%d code=%q message=%q", s.Status, s.Code, s.Message)
}

// MpuInspect extracts the status and the S3 error code from an SDK error. The
// SDK wraps everything as OperationError -> ResponseError -> APIError, so this
// unwraps rather than type-switching on the value.
func MpuInspect(err error) MpuShape {
	var out MpuShape
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		out.Status = respErr.HTTPStatusCode()
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		out.Code = apiErr.ErrorCode()
		out.Message = apiErr.ErrorMessage()
	}
	return out
}

// MpuGetBody reads an object whole through the given client.
func MpuGetBody(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	require.NoError(t, err, "GetObject %s/%s", bucket, key)
	defer out.Body.Close()

	body, err := io.ReadAll(out.Body)
	require.NoError(t, err, "reading %s/%s", bucket, key)
	return body
}

// MpuEncryptionMeta returns the s3ep-* entries of a metadata map. The SDK hands
// back user metadata with the x-amz-meta- prefix stripped and the names
// lowercased, so a plain prefix match is enough.
func MpuEncryptionMeta(meta map[string]string) map[string]string {
	found := make(map[string]string)
	for name, value := range meta {
		if strings.HasPrefix(strings.ToLower(name), MpuMetaPrefix) {
			found[strings.ToLower(name)] = value
		}
	}
	return found
}

// MpuSortedKeys returns the sorted keys of m, for stable failure messages.
func MpuSortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A plain three-part upload has to behave identically through the proxy and
// straight into MinIO, and the object the client reads back has to be the exact
// bytes it sent. On the proxy side the stored object must additionally be
// ciphertext carrying the s3ep-* metadata, and none of that metadata may reach
// the client.
func TestMpuThreePartRoundTrip(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	// Two full-size parts plus a short final part, which is the only place AWS
	// allows a part below 5 MiB.
	payloads := [][]byte{
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, 1024*1024),
	}
	var whole []byte
	for _, p := range payloads {
		whole = append(whole, p...)
	}
	wantDigest := MpuDigest(whole)

	type result struct {
		completeETag string
		headETag     string
		location     string
		headLength   int64
		listLength   int64
		partETags    []string
	}
	results := make(map[string]result, 2)

	key := MpuKey("roundtrip")

	// Deletion is registered on the parent test, not on the per-target subtest:
	// the at-rest assertions below still need the object.
	outer := t

	for _, tg := range []MpuTarget{proxy, direct} {
		tg := tg
		t.Run(tg.Name, func(t *testing.T) {
			uploadID := MpuCreate(t, ctx, tg, key)

			var parts []types.CompletedPart
			var etags []string
			for i, payload := range payloads {
				etag := MpuPart(t, ctx, tg, key, uploadID, i+1, payload)
				etags = append(etags, etag)
				parts = append(parts, MpuPartRef(i+1, etag))
			}

			out, err := MpuComplete(ctx, tg, key, uploadID, parts)
			require.NoErrorf(t, err, "%s: CompleteMultipartUpload", tg.Name)
			require.NotNil(t, out)

			assert.Equalf(t, tg.Bucket, aws.ToString(out.Bucket), "%s: Complete echoed the wrong bucket", tg.Name)
			assert.Equalf(t, key, aws.ToString(out.Key), "%s: Complete echoed the wrong key", tg.Name)
			assert.NotEmptyf(t, aws.ToString(out.ETag), "%s: Complete returned no ETag", tg.Name)
			assert.NotEmptyf(t, aws.ToString(out.Location), "%s: Complete returned no Location", tg.Name)

			// The object the client reads back is the object the client sent.
			body := MpuGetBody(t, ctx, tg.Client, tg.Bucket, key)
			assert.Equalf(t, len(whole), len(body), "%s: round-tripped length", tg.Name)
			assert.Equalf(t, wantDigest, MpuDigest(body), "%s: round-tripped sha256", tg.Name)

			head, err := tg.Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(tg.Bucket), Key: aws.String(key),
			})
			require.NoErrorf(t, err, "%s: HeadObject", tg.Name)

			list, err := tg.Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: aws.String(tg.Bucket), Prefix: aws.String(key),
			})
			require.NoErrorf(t, err, "%s: ListObjectsV2", tg.Name)
			require.Lenf(t, list.Contents, 1, "%s: the completed object must appear exactly once", tg.Name)

			results[tg.Name] = result{
				completeETag: aws.ToString(out.ETag),
				headETag:     aws.ToString(head.ETag),
				location:     aws.ToString(out.Location),
				headLength:   aws.ToInt64(head.ContentLength),
				listLength:   aws.ToInt64(list.Contents[0].Size),
				partETags:    etags,
			}

			outer.Cleanup(func() {
				_, _ = tg.Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
					Bucket: aws.String(tg.Bucket), Key: aws.String(key),
				})
			})
		})
	}

	require.Len(t, results, 2, "both sides must have produced a result")
	p, m := results["proxy"], results["minio"]

	// The size a client is told must be the plaintext size on both sides, and
	// HEAD and LIST must agree with each other.
	assert.Equal(t, int64(len(whole)), p.headLength, "proxy HEAD reports the plaintext length")
	assert.Equal(t, int64(len(whole)), m.headLength, "minio HEAD reports the plaintext length")
	assert.Equal(t, p.headLength, p.listLength, "proxy HEAD and LIST disagree on the size")
	assert.Equal(t, m.headLength, m.listLength, "minio HEAD and LIST disagree on the size")

	// A client that caches the ETag Complete returned and later revalidates with
	// HEAD must not be told the object changed underneath it.
	assert.Equal(t, p.completeETag, p.headETag, "proxy: Complete and HEAD disagree on the ETag")
	assert.Equal(t, m.completeETag, m.headETag, "minio: Complete and HEAD disagree on the ETag")

	// Location must point at the endpoint the client talked to, never at the
	// backend. The proxy rewrites it; MinIO names itself.
	assert.NotContains(t, p.location, "minio:9000", "the proxy leaked the backend endpoint in Location")
	assert.Contains(t, p.location, key, "Location does not name the object")
	assert.Contains(t, m.location, key, "Location does not name the object")

	// DEVIATION D7: AWS and MinIO give a multipart object an ETag of the form
	// "<md5-of-part-md5s>-<partcount>". The proxy rewrites the completed object
	// with a self-copy to attach the encryption metadata, and that copy replaces
	// the multipart ETag with a single-part one, the MD5 of the CIPHERTEXT.
	// The "-N" suffix is the documented signal that an ETag is not a content MD5,
	// so dropping it is not cosmetic: a client that sees a bare 32-hex ETag is
	// entitled to compare it against the MD5 of the plaintext it uploaded, and
	// that comparison can never match an encrypted object.
	assert.Regexpf(t, `-\d+"?$`, m.completeETag, "minio returned a non-multipart ETag: %s", m.completeETag)
	assert.NotRegexpf(t, `-\d+"?$`, p.completeETag,
		"the proxy now returns a multipart-form ETag (%s); deviation D7 is fixed, update this test", p.completeETag)

	t.Run("stored_object_is_ciphertext_with_encryption_metadata", func(t *testing.T) {
		// Same bucket, same key, but read straight from the backend.
		stored := MpuGetBody(t, ctx, tc.MinIOClient, tc.TestBucket, key)
		assert.NotEqual(t, wantDigest, MpuDigest(stored),
			"the object is stored as plaintext: encryption at rest is not happening")

		backendHead, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err, "backend HeadObject")

		backendMeta := MpuEncryptionMeta(backendHead.Metadata)
		require.NotEmpty(t, backendMeta, "the stored object carries no s3ep-* metadata; it could never be decrypted")
		for _, want := range []string{"dek-algorithm", "encrypted-dek", "aes-iv", "kek-fingerprint"} {
			assert.Containsf(t, backendMeta, MpuMetaPrefix+want,
				"the stored object is missing %s%s (present: %v)", MpuMetaPrefix, want, MpuSortedKeys(backendMeta))
		}
		assert.Equal(t, "aes-ctr", backendMeta[MpuMetaPrefix+"dek-algorithm"],
			"a client-driven multipart upload must be stored with AES-CTR")

		// The client must never see any of it.
		clientHead, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err, "client HeadObject")
		assert.Emptyf(t, MpuEncryptionMeta(clientHead.Metadata),
			"the proxy leaked encryption metadata to the client: %v", MpuSortedKeys(clientHead.Metadata))

		clientGet, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err, "client GetObject")
		defer clientGet.Body.Close()
		assert.Emptyf(t, MpuEncryptionMeta(clientGet.Metadata),
			"GetObject leaked encryption metadata to the client: %v", MpuSortedKeys(clientGet.Metadata))
	})
}

// AWS rejects a Complete whose parts are not in ascending part-number order with
// InvalidPartOrder. The proxy sorts the list before forwarding it, so the client
// never learns its list was wrong.
func TestMpuCompleteWithPartsOutOfOrder(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	first := MpuPayload(t, MpuMinPartSize)
	second := MpuPayload(t, MpuMinPartSize)
	third := MpuPayload(t, 512*1024)
	ordered := append(append(append([]byte{}, first...), second...), third...)

	key := MpuKey("outoforder")

	buildShuffled := func(t *testing.T, tg MpuTarget) (string, []types.CompletedPart) {
		uploadID := MpuCreate(t, ctx, tg, key)
		e1 := MpuPart(t, ctx, tg, key, uploadID, 1, first)
		e2 := MpuPart(t, ctx, tg, key, uploadID, 2, second)
		e3 := MpuPart(t, ctx, tg, key, uploadID, 3, third)
		// 3, 1, 2 - a descending first step is enough for AWS to refuse.
		return uploadID, []types.CompletedPart{MpuPartRef(3, e3), MpuPartRef(1, e1), MpuPartRef(2, e2)}
	}

	t.Run("minio_is_the_oracle", func(t *testing.T) {
		uploadID, parts := buildShuffled(t, direct)
		_, err := MpuComplete(ctx, direct, key, uploadID, parts)
		require.Error(t, err, "MinIO accepted an out-of-order part list")
		shape := MpuInspect(err)
		assert.Equal(t, "InvalidPartOrder", shape.Code, "MinIO: %s", shape)
		assert.Equal(t, http.StatusBadRequest, shape.Status, "MinIO: %s", shape)
	})

	t.Run("proxy", func(t *testing.T) {
		uploadID, parts := buildShuffled(t, proxy)
		out, err := MpuComplete(ctx, proxy, key, uploadID, parts)

		// DEVIATION D1: the proxy sorts completeUpload.Parts by part number before
		// it validates or forwards them (internal/proxy/handlers/multipart/complete.go),
		// so an out-of-order list that AWS and MinIO both refuse with
		// InvalidPartOrder succeeds here. A client whose part bookkeeping is broken
		// gets a silent success instead of the error that would have told it.
		require.NoErrorf(t, err, "deviation D1 may be fixed; the proxy now refuses: %s", MpuInspect(err))
		require.NotNil(t, out)
		t.Cleanup(func() {
			_, _ = proxy.Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket: aws.String(proxy.Bucket), Key: aws.String(key),
			})
		})

		// The bytes are assembled in ascending part order, which is what the
		// client presumably meant, so at least the object is not scrambled.
		body := MpuGetBody(t, ctx, proxy.Client, proxy.Bucket, key)
		assert.Equal(t, MpuDigest(ordered), MpuDigest(body),
			"the proxy assembled the out-of-order list into the wrong byte order")
	})
}

// Complete that names a part which was never uploaded must be InvalidPart, and a
// part whose ETag does not match the stored part must be InvalidPart too.
func TestMpuCompleteWithBadPartReferences(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	first := MpuPayload(t, MpuMinPartSize)
	second := MpuPayload(t, 256*1024)

	cases := []struct {
		name string
		// mutate turns the correct part list into the broken one under test.
		mutate func(parts []types.CompletedPart) []types.CompletedPart
	}{
		{
			name: "part_number_never_uploaded",
			mutate: func(parts []types.CompletedPart) []types.CompletedPart {
				// Parts 1 and 2 exist; part 3 does not.
				return append(parts, MpuPartRef(3, `"d41d8cd98f00b204e9800998ecf8427e"`))
			},
		},
		{
			name: "wrong_etag_for_an_existing_part",
			mutate: func(parts []types.CompletedPart) []types.CompletedPart {
				broken := append([]types.CompletedPart{}, parts...)
				broken[1] = MpuPartRef(2, `"00000000000000000000000000000000"`)
				return broken
			},
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			shapes := make(map[string]MpuShape, 2)

			for _, tg := range []MpuTarget{proxy, direct} {
				tg := tg
				key := MpuKey("badparts")
				uploadID := MpuCreate(t, ctx, tg, key)
				e1 := MpuPart(t, ctx, tg, key, uploadID, 1, first)
				e2 := MpuPart(t, ctx, tg, key, uploadID, 2, second)

				parts := c.mutate([]types.CompletedPart{MpuPartRef(1, e1), MpuPartRef(2, e2)})
				_, err := MpuComplete(ctx, tg, key, uploadID, parts)
				require.Errorf(t, err, "%s: a broken part list was accepted", tg.Name)

				shape := MpuInspect(err)
				shapes[tg.Name] = shape
				t.Logf("%s: %s", tg.Name, shape)

				assert.Equalf(t, "InvalidPart", shape.Code, "%s: %s", tg.Name, shape)
				assert.Equalf(t, http.StatusBadRequest, shape.Status, "%s: %s", tg.Name, shape)

				// No object may exist after a refused Complete.
				_, headErr := tg.Client.HeadObject(ctx, &s3.HeadObjectInput{
					Bucket: aws.String(tg.Bucket), Key: aws.String(key),
				})
				assert.Errorf(t, headErr, "%s: a refused Complete still produced an object", tg.Name)
			}

			assert.Equal(t, shapes["minio"].Code, shapes["proxy"].Code,
				"proxy and backend disagree on the error code")
			assert.Equal(t, shapes["minio"].Status, shapes["proxy"].Status,
				"proxy and backend disagree on the status")
		})
	}
}

// Complete with no parts at all. AWS answers 400 MalformedXML.
func TestMpuCompleteWithEmptyPartList(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	shapes := make(map[string]MpuShape, 2)
	for _, tg := range []MpuTarget{proxy, direct} {
		key := MpuKey("emptyparts")
		uploadID := MpuCreate(t, ctx, tg, key)
		MpuPart(t, ctx, tg, key, uploadID, 1, MpuPayload(t, 64*1024))

		_, err := MpuComplete(ctx, tg, key, uploadID, []types.CompletedPart{})
		require.Errorf(t, err, "%s: an empty part list was accepted", tg.Name)
		shapes[tg.Name] = MpuInspect(err)
		t.Logf("%s: %s", tg.Name, shapes[tg.Name])
	}

	// The backend answers the documented AWS way.
	assert.Contains(t, []string{"MalformedXML", "InvalidRequest"}, shapes["minio"].Code,
		"MinIO: %s", shapes["minio"])
	assert.Equal(t, http.StatusBadRequest, shapes["minio"].Status, "MinIO: %s", shapes["minio"])

	// DEVIATION D2: the proxy rejects the empty list with a bare fmt.Errorf
	// ("no parts provided"). That error carries no APIError and no HTTP status,
	// so response.MapError classifies it as internal and answers
	// 500 InternalError with the generic message. A client fault is reported as
	// a server fault, and retry logic that backs off on 5xx will retry a request
	// that can never succeed.
	assert.Equalf(t, http.StatusInternalServerError, shapes["proxy"].Status,
		"deviation D2 may be fixed; the proxy now answers %s", shapes["proxy"])
	assert.Equalf(t, "InternalError", shapes["proxy"].Code,
		"deviation D2 may be fixed; the proxy now answers %s", shapes["proxy"])
}

// A part below 5 MiB is only legal in the final position. Anywhere else AWS
// answers EntityTooSmall at Complete time.
func TestMpuPartTooSmallInNonFinalPosition(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	small := MpuPayload(t, 1024*1024) // 1 MiB, in position 1 of 2
	last := MpuPayload(t, 1024*1024)

	shapes := make(map[string]MpuShape, 2)
	for _, tg := range []MpuTarget{proxy, direct} {
		key := MpuKey("toosmall")
		uploadID := MpuCreate(t, ctx, tg, key)
		e1 := MpuPart(t, ctx, tg, key, uploadID, 1, small)
		e2 := MpuPart(t, ctx, tg, key, uploadID, 2, last)

		_, err := MpuComplete(ctx, tg, key, uploadID, []types.CompletedPart{MpuPartRef(1, e1), MpuPartRef(2, e2)})
		require.Errorf(t, err, "%s: an undersized non-final part was accepted", tg.Name)

		shapes[tg.Name] = MpuInspect(err)
		t.Logf("%s: %s", tg.Name, shapes[tg.Name])

		assert.Equalf(t, "EntityTooSmall", shapes[tg.Name].Code, "%s: %s", tg.Name, shapes[tg.Name])
		assert.Equalf(t, http.StatusBadRequest, shapes[tg.Name].Status, "%s: %s", tg.Name, shapes[tg.Name])
	}

	assert.Equal(t, shapes["minio"].Code, shapes["proxy"].Code, "proxy and backend disagree on the error code")
	assert.Equal(t, shapes["minio"].Status, shapes["proxy"].Status, "proxy and backend disagree on the status")
}

// UploadPart outside the 1..10000 part-number range. AWS answers
// 400 InvalidArgument with an S3 error document.
func TestMpuUploadPartWithInvalidPartNumber(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	for _, partNumber := range []int{0, 10001} {
		partNumber := partNumber
		t.Run(fmt.Sprintf("part_number_%d", partNumber), func(t *testing.T) {
			shapes := make(map[string]MpuShape, 2)

			for _, tg := range []MpuTarget{proxy, direct} {
				key := MpuKey("badpartnum")
				uploadID := MpuCreate(t, ctx, tg, key)

				_, err := tg.Client.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        aws.String(tg.Bucket),
					Key:           aws.String(key),
					UploadId:      aws.String(uploadID),
					PartNumber:    aws.Int32(int32(partNumber)),
					Body:          bytes.NewReader([]byte("payload")),
					ContentLength: aws.Int64(int64(len("payload"))),
				})
				require.Errorf(t, err, "%s: partNumber %d was accepted", tg.Name, partNumber)
				shapes[tg.Name] = MpuInspect(err)
				t.Logf("%s partNumber=%d: %s", tg.Name, partNumber, shapes[tg.Name])
			}

			// AWS answers InvalidArgument ("Part number must be an integer
			// between 1 and 10000, inclusive") for both ends of the range.
			// DEVIATION D3b, MinIO's own: it says InvalidArgument for 10001 but
			// InvalidPart for 0. The proxy is not the cause, and the assertion
			// accepts either so the backend's own quirk does not mask D3.
			assert.Equalf(t, http.StatusBadRequest, shapes["minio"].Status, "MinIO: %s", shapes["minio"])
			assert.Containsf(t, []string{"InvalidArgument", "InvalidPart"}, shapes["minio"].Code,
				"MinIO: %s", shapes["minio"])

			// DEVIATION D3: the proxy rejects the part number with
			// http.Error(w, "Invalid partNumber", 400) - a text/plain body with no
			// <Error> document at all. The SDK cannot parse a code out of that and
			// falls back to synthesising one from the status line, so the client
			// gets code "BadRequest", which is not an S3 error code, and the real
			// reason ("Invalid partNumber") never reaches it. The status class is
			// the only thing that survives.
			assert.Equalf(t, http.StatusBadRequest, shapes["proxy"].Status,
				"proxy: %s", shapes["proxy"])
			assert.Equalf(t, "BadRequest", shapes["proxy"].Code,
				"deviation D3 may be fixed; the proxy now returns %s", shapes["proxy"])
			assert.NotEqualf(t, "InvalidArgument", shapes["proxy"].Code,
				"deviation D3 is fixed; update this test: %s", shapes["proxy"])
		})
	}
}

// UploadPart against an uploadId that does not exist. AWS answers
// 404 NoSuchUpload.
func TestMpuUploadPartWithUnknownUploadID(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	unknown := "mpu-does-not-exist-" + integration.RandomString(16)
	shapes := make(map[string]MpuShape, 2)

	for _, tg := range []MpuTarget{proxy, direct} {
		key := MpuKey("unknownupload")
		_, err := tg.Client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(tg.Bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(unknown),
			PartNumber:    aws.Int32(1),
			Body:          bytes.NewReader([]byte("payload")),
			ContentLength: aws.Int64(int64(len("payload"))),
		})
		require.Errorf(t, err, "%s: an unknown uploadId was accepted", tg.Name)
		shapes[tg.Name] = MpuInspect(err)
		t.Logf("%s: %s", tg.Name, shapes[tg.Name])
	}

	// The backend answers the documented AWS way.
	assert.Equalf(t, http.StatusNotFound, shapes["minio"].Status, "MinIO: %s", shapes["minio"])
	assert.Equalf(t, "NoSuchUpload", shapes["minio"].Code, "MinIO: %s", shapes["minio"])

	// DEVIATION D4: the proxy looks the upload id up in its own session map and,
	// on a miss, answers http.Error(w, "Invalid upload ID", 400): the wrong
	// status class, and a text/plain body instead of an S3 <Error> document, so
	// the SDK reports the synthesised code "BadRequest". A client that retries or
	// restarts an upload on NoSuchUpload - the documented recovery path - never
	// sees it, and a proxy restart turns every in-flight upload into this.
	assert.Equalf(t, http.StatusBadRequest, shapes["proxy"].Status,
		"deviation D4 may be fixed; the proxy now answers %s", shapes["proxy"])
	assert.Equalf(t, "BadRequest", shapes["proxy"].Code,
		"deviation D4 may be fixed; the proxy now answers %s", shapes["proxy"])
	assert.NotEqualf(t, "NoSuchUpload", shapes["proxy"].Code,
		"deviation D4 is fixed; update this test: %s", shapes["proxy"])
}

// ListParts must report the parts that were uploaded, must page with max-parts
// and part-number-marker, and must answer NoSuchUpload once the upload is gone.
func TestMpuListParts(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	// Three parts so a max-parts of 2 has something to truncate.
	payloads := [][]byte{
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, 128*1024),
	}

	type listing struct {
		all        *s3.ListPartsOutput
		firstPage  *s3.ListPartsOutput
		secondPage *s3.ListPartsOutput
		afterAbort error
	}
	listings := make(map[string]listing, 2)

	for _, tg := range []MpuTarget{proxy, direct} {
		key := MpuKey("listparts")
		uploadID := MpuCreate(t, ctx, tg, key)
		for i, payload := range payloads {
			MpuPart(t, ctx, tg, key, uploadID, i+1, payload)
		}

		all, err := tg.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
		require.NoErrorf(t, err, "%s: ListParts", tg.Name)

		firstPage, err := tg.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
			MaxParts: aws.Int32(2),
		})
		require.NoErrorf(t, err, "%s: ListParts max-parts=2", tg.Name)

		secondPage, err := tg.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
			MaxParts: aws.Int32(2), PartNumberMarker: aws.String("2"),
		})
		require.NoErrorf(t, err, "%s: ListParts part-number-marker=2", tg.Name)

		_, err = tg.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
		require.NoErrorf(t, err, "%s: AbortMultipartUpload", tg.Name)

		_, afterAbort := tg.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})

		listings[tg.Name] = listing{all: all, firstPage: firstPage, secondPage: secondPage, afterAbort: afterAbort}
	}

	t.Run("minio_is_the_oracle", func(t *testing.T) {
		l := listings["minio"]
		require.Len(t, l.all.Parts, 3, "MinIO did not report all three parts")
		for i, part := range l.all.Parts {
			assert.Equal(t, int32(i+1), aws.ToInt32(part.PartNumber), "part numbers must ascend from 1")
			assert.NotEmpty(t, aws.ToString(part.ETag), "every listed part carries an ETag")
			assert.Positive(t, aws.ToInt64(part.Size), "every listed part carries a size")
		}

		assert.Len(t, l.firstPage.Parts, 2, "max-parts=2 must return two parts")
		assert.True(t, aws.ToBool(l.firstPage.IsTruncated), "max-parts=2 of three parts must be truncated")
		assert.Equal(t, "2", aws.ToString(l.firstPage.NextPartNumberMarker), "NextPartNumberMarker must name part 2")

		assert.Len(t, l.secondPage.Parts, 1, "the second page must return the remaining part")
		assert.False(t, aws.ToBool(l.secondPage.IsTruncated), "the second page must not be truncated")
		if len(l.secondPage.Parts) == 1 {
			assert.Equal(t, int32(3), aws.ToInt32(l.secondPage.Parts[0].PartNumber),
				"part-number-marker=2 must resume at part 3")
		}

		require.Error(t, l.afterAbort, "MinIO listed parts of an aborted upload")
		shape := MpuInspect(l.afterAbort)
		assert.Equal(t, "NoSuchUpload", shape.Code, "MinIO: %s", shape)
		assert.Equal(t, http.StatusNotFound, shape.Status, "MinIO: %s", shape)
	})

	// DEVIATION D5: internal/proxy/handlers/multipart/list.go HandleListParts is a
	// stub. It never asks the backend anything: it answers 200 with an empty
	// ListPartsResult for any uploadId, whether the upload has parts, was
	// aborted, or never existed at all. max-parts and part-number-marker are
	// ignored and the echoed MaxParts is always 1000.
	//
	// Consequences a client actually hits:
	//   - resumable uploaders (aws-cli, rclone, Velero's restic/kopia paths) ask
	//     ListParts to find out what still has to be sent and are told "nothing";
	//   - an aborted or expired upload id is reported as a live upload with zero
	//     parts instead of NoSuchUpload, so cleanup and retry logic cannot tell
	//     the two apart.
	t.Run("proxy_liststub", func(t *testing.T) {
		l := listings["proxy"]

		assert.Emptyf(t, l.all.Parts,
			"deviation D5 may be fixed; ListParts now reports %d parts", len(l.all.Parts))
		assert.Emptyf(t, l.firstPage.Parts, "deviation D5 may be fixed; max-parts now returns parts")
		assert.Emptyf(t, l.secondPage.Parts, "deviation D5 may be fixed; part-number-marker now returns parts")

		// max-parts=2 is echoed back as 1000: the request parameter is dropped.
		assert.Equalf(t, int32(1000), aws.ToInt32(l.firstPage.MaxParts),
			"deviation D5 may be fixed; the proxy now echoes max-parts (%d)", aws.ToInt32(l.firstPage.MaxParts))

		assert.NoErrorf(t, l.afterAbort,
			"deviation D5 may be fixed; ListParts on an aborted upload now fails: %s", MpuInspect(l.afterAbort))
	})

	// ListParts for an upload id that was never created anywhere. AWS: NoSuchUpload.
	t.Run("never_created_upload_id", func(t *testing.T) {
		unknown := "mpu-never-created-" + integration.RandomString(16)
		key := MpuKey("listpartsunknown")

		_, minioErr := direct.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(direct.Bucket), Key: aws.String(key), UploadId: aws.String(unknown),
		})
		require.Error(t, minioErr, "MinIO listed parts of an upload that never existed")
		assert.Equal(t, "NoSuchUpload", MpuInspect(minioErr).Code)

		// DEVIATION D5, same stub.
		_, proxyErr := proxy.Client.ListParts(ctx, &s3.ListPartsInput{
			Bucket: aws.String(proxy.Bucket), Key: aws.String(key), UploadId: aws.String(unknown),
		})
		assert.NoErrorf(t, proxyErr,
			"deviation D5 may be fixed; ListParts on an unknown upload now fails: %s", MpuInspect(proxyErr))
	})
}

// ListMultipartUploads must show an in-flight upload and stop showing it after
// the upload is aborted.
func TestMpuListMultipartUploads(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	t.Run("minio_is_the_oracle", func(t *testing.T) {
		key := MpuKey("listuploads")
		uploadID := MpuCreate(t, ctx, direct, key)
		MpuPart(t, ctx, direct, key, uploadID, 1, MpuPayload(t, 64*1024))

		inflight, err := direct.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(direct.Bucket), Prefix: aws.String(key),
		})
		require.NoError(t, err, "MinIO ListMultipartUploads")
		require.Len(t, inflight.Uploads, 1, "the in-flight upload must be listed")
		assert.Equal(t, uploadID, aws.ToString(inflight.Uploads[0].UploadId))
		assert.Equal(t, key, aws.ToString(inflight.Uploads[0].Key))

		_, err = direct.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(direct.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
		require.NoError(t, err, "MinIO AbortMultipartUpload")

		after, err := direct.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(direct.Bucket), Prefix: aws.String(key),
		})
		require.NoError(t, err, "MinIO ListMultipartUploads after abort")
		assert.Empty(t, after.Uploads, "an aborted upload must disappear from the listing")
	})

	// DEVIATION D6: the proxy routes GET /{bucket}?uploads to
	// ListHandler.HandleListMultipartUploads, which answers
	// 501 NotImplemented unconditionally. Together with the ListParts stub (D5)
	// this leaves a client with no way at all to discover or reconcile pending
	// uploads through the proxy: it can neither list them nor inspect one it
	// already knows about. Uploads a client abandons stay in the backend and are
	// billed until a bucket lifecycle rule removes them.
	t.Run("proxy_refuses", func(t *testing.T) {
		key := MpuKey("listuploads")
		uploadID := MpuCreate(t, ctx, proxy, key)
		MpuPart(t, ctx, proxy, key, uploadID, 1, MpuPayload(t, 64*1024))

		_, err := proxy.Client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(proxy.Bucket), Prefix: aws.String(key),
		})
		require.Errorf(t, err, "deviation D6 may be fixed; the proxy now implements ListMultipartUploads")

		shape := MpuInspect(err)
		assert.Equalf(t, http.StatusNotImplemented, shape.Status,
			"deviation D6 may be fixed; the proxy now answers %s", shape)
		assert.Equalf(t, "NotImplemented", shape.Code,
			"deviation D6 may be fixed; the proxy now answers %s", shape)

		// The upload really is in flight behind the proxy: the backend sees it.
		backend, listErr := tc.MinIOClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(proxy.Bucket), Prefix: aws.String(key),
		})
		require.NoError(t, listErr, "backend ListMultipartUploads")
		assert.Len(t, backend.Uploads, 1,
			"the upload the proxy will not list does exist in the backend")
	})
}

// AbortMultipartUpload must answer 204, and the aborted upload must be gone from
// the backend afterwards, so a client that gives up does not leak storage.
func TestMpuAbortRemovesTheUpload(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	for _, tg := range []MpuTarget{proxy, direct} {
		tg := tg
		t.Run(tg.Name, func(t *testing.T) {
			key := MpuKey("abort")
			uploadID := MpuCreate(t, ctx, tg, key)
			MpuPart(t, ctx, tg, key, uploadID, 1, MpuPayload(t, MpuMinPartSize))

			_, err := tg.Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket: aws.String(tg.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
			})
			require.NoErrorf(t, err, "%s: AbortMultipartUpload", tg.Name)

			// Read the truth from the backend for both sides: the proxy's own
			// ListMultipartUploads is not available (D6).
			backend, listErr := tc.MinIOClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
				Bucket: aws.String(tg.Bucket), Prefix: aws.String(key),
			})
			require.NoErrorf(t, listErr, "%s: backend ListMultipartUploads", tg.Name)
			assert.Emptyf(t, backend.Uploads, "%s: the aborted upload is still pending in the backend", tg.Name)

			// Completing an aborted upload must fail: AWS answers 404 NoSuchUpload.
			_, completeErr := MpuComplete(ctx, tg, key, uploadID, []types.CompletedPart{
				MpuPartRef(1, `"00000000000000000000000000000000"`),
			})
			require.Errorf(t, completeErr, "%s: an aborted upload was completed", tg.Name)
			shape := MpuInspect(completeErr)
			t.Logf("%s: complete-after-abort %s", tg.Name, shape)

			if tg.Name == "minio" {
				assert.Equal(t, http.StatusNotFound, shape.Status, "MinIO: %s", shape)
				assert.Equal(t, "NoSuchUpload", shape.Code, "MinIO: %s", shape)
			} else {
				// DEVIATION D8: the proxy asks its own session map first, and the
				// "multipart upload <id> not found" it gets back is a bare
				// fmt.Errorf. response.MapError sees no APIError and no HTTP status
				// on it, classifies it as internal, and answers 500 InternalError -
				// the same root cause as D2 and D4. Two costs: a client cannot tell
				// "this upload is gone, start over" from "the server broke", and the
				// SDK retries 5xx, so every completion of an expired or aborted
				// upload burns the full retry budget (this call takes seconds, the
				// MinIO one milliseconds) before failing anyway.
				assert.Equalf(t, http.StatusInternalServerError, shape.Status,
					"deviation D8 may be fixed; the proxy now answers %s", shape)
				assert.Equalf(t, "InternalError", shape.Code,
					"deviation D8 may be fixed; the proxy now answers %s", shape)
			}

			_, headErr := tg.Client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(tg.Bucket), Key: aws.String(key),
			})
			assert.Errorf(t, headErr, "%s: an aborted upload produced an object", tg.Name)
		})
	}
}

// AWS accepts parts in any upload order, and the aws-cli, rclone and the SDK's
// own s3manager.Uploader all send several parts at once, so part 3 routinely
// arrives before part 1.
//
// The proxy encrypts a multipart object with one AES-CTR keystream whose counter
// position depends on where a part sits in the object, so it processes parts
// strictly in ascending order: internal/orchestration/multipart.go
// processPartOrdered buffers a part that arrives early and BLOCKS its request in
// a channel receive with no context in the select, until the missing earlier
// parts show up.
//
// Two very different outcomes follow, and this test pins both:
//   - a client that uploads parts concurrently works, at the price of holding
//     every early part whole in proxy memory until its turn;
//   - a client that uploads sequentially but not in ascending order never gets a
//     response at all. AWS answers such a request immediately.
func TestMpuPartsUploadedOutOfOrder(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	proxy, direct := MpuTargets(t, tc)

	payloads := [][]byte{
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, MpuMinPartSize),
		MpuPayload(t, 2*1024*1024),
	}
	var whole []byte
	for _, part := range payloads {
		whole = append(whole, part...)
	}
	wantDigest := MpuDigest(whole)

	// Upload order 3, 1, 2. The completion list stays ascending, which is what
	// AWS requires and what every client sends.
	uploadOrder := []int{3, 1, 2}

	// The backend takes the parts in any order, one at a time, and reassembles
	// them by part number.
	t.Run("minio_is_the_oracle", func(t *testing.T) {
		key := MpuKey("uploadorder")
		uploadID := MpuCreate(t, ctx, direct, key)

		etags := make(map[int]string, len(payloads))
		for _, partNumber := range uploadOrder {
			etags[partNumber] = MpuPart(t, ctx, direct, key, uploadID, partNumber, payloads[partNumber-1])
		}

		parts := make([]types.CompletedPart, 0, len(payloads))
		for partNumber := 1; partNumber <= len(payloads); partNumber++ {
			parts = append(parts, MpuPartRef(partNumber, etags[partNumber]))
		}

		_, err := MpuComplete(ctx, direct, key, uploadID, parts)
		require.NoErrorf(t, err, "MinIO refused parts uploaded out of order: %s", MpuInspect(err))
		t.Cleanup(func() {
			_, _ = direct.Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket: aws.String(direct.Bucket), Key: aws.String(key),
			})
		})

		body := MpuGetBody(t, ctx, direct.Client, direct.Bucket, key)
		require.Equal(t, len(whole), len(body), "round-tripped length")
		assert.Equal(t, wantDigest, MpuDigest(body), "out-of-order parts round-tripped to different bytes")
	})

	// DEVIATION D9: a single UploadPart that arrives before its predecessors gets
	// no response at all. The request is parked in processPartOrdered's channel
	// receive; nothing in that select watches the request context, so a client
	// disconnect does not end it either. This case has to be measured with a
	// deadline, because there is nothing else to observe.
	t.Run("proxy_blocks_a_lone_early_part", func(t *testing.T) {
		key := MpuKey("uploadorder-lone")
		uploadID := MpuCreate(t, ctx, proxy, key)

		// Part 2 first, and part 1 is never sent.
		blockCtx, blockCancel := context.WithTimeout(ctx, 10*time.Second)
		defer blockCancel()

		started := time.Now()
		_, err := proxy.Client.UploadPart(blockCtx, &s3.UploadPartInput{
			Bucket:        aws.String(proxy.Bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(2),
			Body:          bytes.NewReader(payloads[1]),
			ContentLength: aws.Int64(int64(len(payloads[1]))),
		})
		waited := time.Since(started)

		require.Errorf(t, err,
			"deviation D9 may be fixed; the proxy answered a lone early part after %s", waited)
		assert.Truef(t, errors.Is(err, context.DeadlineExceeded),
			"deviation D9 may be fixed; the proxy failed the early part with %v instead of hanging", err)

		// Release the parked server goroutine: AbortSession is the only thing that
		// signals the pending part's error channel. Without this the goroutine and
		// the 5 MiB it holds stay alive for the lifetime of the process.
		_, abortErr := proxy.Client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
			Bucket: aws.String(proxy.Bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
		assert.NoError(t, abortErr, "aborting the stuck upload")
	})

	// The path real clients take: all parts in flight at once. Every early part is
	// buffered whole in proxy memory until its predecessor arrives, so peak proxy
	// memory here is the whole object, not one part.
	t.Run("proxy_accepts_concurrent_parts", func(t *testing.T) {
		key := MpuKey("uploadorder-concurrent")
		uploadID := MpuCreate(t, ctx, proxy, key)

		type partResult struct {
			partNumber int
			etag       string
			err        error
		}
		results := make(chan partResult, len(payloads))

		for _, partNumber := range uploadOrder {
			partNumber := partNumber
			go func() {
				out, err := proxy.Client.UploadPart(ctx, &s3.UploadPartInput{
					Bucket:        aws.String(proxy.Bucket),
					Key:           aws.String(key),
					UploadId:      aws.String(uploadID),
					PartNumber:    aws.Int32(int32(partNumber)),
					Body:          bytes.NewReader(payloads[partNumber-1]),
					ContentLength: aws.Int64(int64(len(payloads[partNumber-1]))),
				})
				r := partResult{partNumber: partNumber, err: err}
				if out != nil {
					r.etag = aws.ToString(out.ETag)
				}
				results <- r
			}()
		}

		etags := make(map[int]string, len(payloads))
		for range payloads {
			select {
			case r := <-results:
				require.NoErrorf(t, r.err, "concurrent UploadPart %d: %s", r.partNumber, MpuInspect(r.err))
				require.NotEmptyf(t, r.etag, "concurrent UploadPart %d returned no ETag", r.partNumber)
				etags[r.partNumber] = r.etag
			case <-time.After(2 * time.Minute):
				require.FailNow(t, "concurrent part uploads did not all finish; the ordering barrier deadlocked")
			}
		}

		parts := make([]types.CompletedPart, 0, len(payloads))
		for partNumber := 1; partNumber <= len(payloads); partNumber++ {
			parts = append(parts, MpuPartRef(partNumber, etags[partNumber]))
		}

		_, err := MpuComplete(ctx, proxy, key, uploadID, parts)
		require.NoErrorf(t, err, "Complete after concurrent part uploads: %s", MpuInspect(err))
		t.Cleanup(func() {
			_, _ = proxy.Client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
				Bucket: aws.String(proxy.Bucket), Key: aws.String(key),
			})
		})

		body := MpuGetBody(t, ctx, proxy.Client, proxy.Bucket, key)
		require.Equal(t, len(whole), len(body), "round-tripped length")
		assert.Equal(t, wantDigest, MpuDigest(body),
			"concurrently uploaded parts round-tripped to different bytes")
	})
}
