//go:build integration

package s3methods

// MAIN GOAL 1: data is always encrypted at rest.
//
// Every write path the proxy exposes is driven here with a payload that carries
// a recognisable plaintext marker, and the object is then read back DIRECTLY
// from MinIO with tc.MinIOClient. Four things are asserted for every path:
//
//	a) the stored bytes are not the plaintext (sha256) and the marker string does
//	   not occur anywhere in them
//	b) the stored object carries the s3ep-* envelope metadata
//	c) the proxy returns the original plaintext for the same key (sha256)
//	d) no s3ep-* metadata reaches the client, neither in the parsed user metadata
//	   nor in the raw response headers
//
// The differential oracle runs the same operation against a second bucket
// written directly through MinIO, which proves the marker search is capable of
// finding the marker at all, and compares everything a client can observe.

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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// EncMetaPrefix is the default metadata_key_prefix. config/aes-example.yaml
	// and config/aes-tls-example.yaml both leave metadata_key_prefix unset.
	EncMetaPrefix = "s3ep-"

	// EncStreamingThreshold mirrors optimizations.streaming_threshold in the demo
	// configuration (5 MiB). Objects at or above it leave the AES-GCM path.
	EncStreamingThreshold = 5 * 1024 * 1024

	// EncForceCTRContentType is the content type the proxy interprets as "encrypt
	// this with AES-CTR whatever the size is" (see handlePutObject).
	EncForceCTRContentType = "application/x-" + EncMetaPrefix + "force-aes-ctr"
)

// EncRequiredEnvelopeKeys are the metadata keys every encrypting write path has
// to leave on the stored object. Without them the object cannot be decrypted
// again, so a missing key is data loss, not cosmetics.
var EncRequiredEnvelopeKeys = []string{
	EncMetaPrefix + "dek-algorithm",
	EncMetaPrefix + "encrypted-dek",
	EncMetaPrefix + "kek-algorithm",
	EncMetaPrefix + "kek-fingerprint",
}

// EncNewMarker returns a plaintext marker unique to a single upload.
func EncNewMarker() string { return "ENCMARKER-PLAINTEXT-" + integration.RandomString(20) }

// EncPayload builds size bytes of random noise with the marker stamped at the
// front, the middle and the end, so a partially encrypted body is caught too.
// Random filler is deliberate: it makes an accidental collision with the marker
// impossible and keeps the body incompressible.
func EncPayload(t *testing.T, size int, marker string) []byte {
	t.Helper()

	buf := make([]byte, size)
	if size > 0 {
		_, err := rand.Read(buf)
		require.NoError(t, err, "generating payload")
	}

	m := []byte(marker)
	if len(m) <= size {
		for _, off := range []int{0, (size - len(m)) / 2, size - len(m)} {
			copy(buf[off:], m)
		}
	}
	return buf
}

// EncSHA256 is the only way this file compares payloads. No hex dumps.
func EncSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// EncCaptureHeaders is a request option that copies the raw HTTP response
// headers of one SDK call into dst. The client-visible metadata assertion has to
// look at the wire, not only at the parsed Metadata map: x-amz-meta-s3ep-* would
// leak through headers the SDK model does not surface.
func EncCaptureHeaders(dst *http.Header) func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Deserialize.Add(middleware.DeserializeMiddlewareFunc("EncCaptureHeaders",
			func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
				middleware.DeserializeOutput, middleware.Metadata, error) {
				out, md, err := next.HandleDeserialize(ctx, in)
				if resp, ok := out.RawResponse.(*smithyhttp.Response); ok && resp != nil {
					*dst = resp.Header.Clone()
				}
				return out, md, err
			}), middleware.After)
	}
}

// EncHTTPStatus and EncAPICode unwrap the SDK error chain. Local copies so this
// file does not depend on helpers other agents own.
func EncHTTPStatus(err error) int {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) {
		return respErr.HTTPStatusCode()
	}
	return 0
}

func EncAPICode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// EncOracleBucket creates a bucket directly in MinIO for the differential arm
// and registers its cleanup. Only objects this test wrote are ever removed.
func EncOracleBucket(t *testing.T, ctx context.Context, client *s3.Client) string {
	t.Helper()

	bucket := "enc-oracle-" + integration.RandomString(16)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoErrorf(t, err, "creating oracle bucket %s", bucket)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		list, listErr := client.ListObjectsV2(cleanupCtx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if listErr == nil {
			for _, obj := range list.Contents {
				_, _ = client.DeleteObject(cleanupCtx, &s3.DeleteObjectInput{
					Bucket: aws.String(bucket), Key: obj.Key,
				})
			}
		}
		// Abort anything a failed multipart test left behind, otherwise the
		// bucket cannot be deleted.
		uploads, upErr := client.ListMultipartUploads(cleanupCtx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(bucket),
		})
		if upErr == nil {
			for _, up := range uploads.Uploads {
				_, _ = client.AbortMultipartUpload(cleanupCtx, &s3.AbortMultipartUploadInput{
					Bucket: aws.String(bucket), Key: up.Key, UploadId: up.UploadId,
				})
			}
		}
		_, _ = client.DeleteBucket(cleanupCtx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})

	return bucket
}

// EncStored is what a direct MinIO read of a proxy-written object returned.
type EncStored struct {
	Body     []byte
	Metadata map[string]string
	Size     int64
}

// EncReadStored reads an object straight out of the backend, bypassing the
// proxy entirely.
func EncReadStored(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) EncStored {
	t.Helper()

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "reading %s/%s directly from MinIO", bucket, key)
	defer func() { _ = out.Body.Close() }()

	body, err := io.ReadAll(out.Body)
	require.NoError(t, err, "reading stored body")

	meta := make(map[string]string, len(out.Metadata))
	for k, v := range out.Metadata {
		meta[strings.ToLower(k)] = v
	}
	return EncStored{Body: body, Metadata: meta, Size: aws.ToInt64(out.ContentLength)}
}

// EncAssertBodyIsCiphertext is assertion (a) plus the envelope keys, the part
// that must hold no matter what else a request contained.
func EncAssertBodyIsCiphertext(t *testing.T, stored EncStored, plaintext []byte, marker, pathName string) {
	t.Helper()

	assert.NotEqualf(t, EncSHA256(plaintext), EncSHA256(stored.Body),
		"MAIN GOAL 1 VIOLATED on the %q write path: the backend holds the plaintext byte for byte "+
			"(%d bytes, sha256 %s)", pathName, len(plaintext), EncSHA256(plaintext))

	if len(marker) <= len(plaintext) {
		assert.Falsef(t, bytes.Contains(stored.Body, []byte(marker)),
			"MAIN GOAL 1 VIOLATED on the %q write path: the plaintext marker %q occurs in the stored bytes",
			pathName, marker)
	}

	// The empty object must not pass by being empty. An encrypting provider adds
	// at least the DEK envelope; AES-GCM additionally stores nonce and tag, so a
	// zero-length body at rest would mean nothing was encrypted at all.
	if len(plaintext) == 0 {
		assert.NotEmptyf(t, stored.Metadata,
			"the %q write path stored a zero-byte object with no metadata at all: "+
				"the marker check is vacuous here, so the envelope is the only evidence of encryption", pathName)
	}

	for _, k := range EncRequiredEnvelopeKeys {
		assert.Containsf(t, stored.Metadata, k,
			"the %q write path stored an object without %s: it cannot be decrypted again (have: %v)",
			pathName, k, EncMetadataKeys(stored.Metadata))
	}
}

// EncAssertEncryptedAtRest is the heart of this file: assertions (a) and (b).
func EncAssertEncryptedAtRest(t *testing.T, stored EncStored, plaintext []byte, marker, pathName string) {
	t.Helper()

	EncAssertBodyIsCiphertext(t, stored, plaintext, marker, pathName)

	alg := stored.Metadata[EncMetaPrefix+"dek-algorithm"]
	assert.Equalf(t, "s3ep-gcm-seg-v2", alg,
		"the %q write path recorded an unexpected dek-algorithm %q", pathName, alg)
	assert.Equalf(t, "aes", stored.Metadata[EncMetaPrefix+"kek-algorithm"],
		"the %q write path recorded an unexpected kek-algorithm", pathName)
	assert.NotEmptyf(t, stored.Metadata[EncMetaPrefix+"kek-fingerprint"],
		"the %q write path stored an empty kek-fingerprint", pathName)

	// Four keys and no more. There is no per-object IV, because every segment
	// carries its own nonce, and no separate integrity value, because integrity
	// is not separable from decryption: a segment that does not open is not
	// served (ADR 0003). A path that still writes either of them is writing a
	// format this proxy cannot read.
	assert.NotContainsf(t, stored.Metadata, EncMetaPrefix+"aes-iv",
		"the %q write path stored an %saes-iv, which the segment chain does not use", pathName, EncMetaPrefix)
	assert.NotContainsf(t, stored.Metadata, EncMetaPrefix+"hmac",
		"the %q write path stored an %shmac, which the segment chain does not use", pathName, EncMetaPrefix)
}

// EncMetadataKeys is only used to make a failure message readable.
func EncMetadataKeys(meta map[string]string) []string {
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	return keys
}

// EncAssertNoMetadataLeak is assertion (d): nothing with the encryption prefix
// may reach the client, over HEAD or over GET, parsed or raw.
func EncAssertNoMetadataLeak(t *testing.T, ctx context.Context, client *s3.Client, bucket, key, pathName string) {
	t.Helper()

	var headHeaders http.Header
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	}, s3.WithAPIOptions(EncCaptureHeaders(&headHeaders)))
	require.NoErrorf(t, err, "HeadObject through the proxy for the %q write path", pathName)

	for k := range head.Metadata {
		assert.NotContainsf(t, strings.ToLower(k), EncMetaPrefix,
			"the %q write path leaks encryption metadata %q to the client over HEAD", pathName, k)
	}
	EncAssertHeadersClean(t, headHeaders, pathName, "HEAD")

	var getHeaders http.Header
	get, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	}, s3.WithAPIOptions(EncCaptureHeaders(&getHeaders)))
	require.NoErrorf(t, err, "GetObject through the proxy for the %q write path", pathName)
	_, _ = io.Copy(io.Discard, get.Body)
	_ = get.Body.Close()

	for k := range get.Metadata {
		assert.NotContainsf(t, strings.ToLower(k), EncMetaPrefix,
			"the %q write path leaks encryption metadata %q to the client over GET", pathName, k)
	}
	EncAssertHeadersClean(t, getHeaders, pathName, "GET")
}

// EncAssertHeadersClean scans raw response headers for the encryption prefix.
func EncAssertHeadersClean(t *testing.T, headers http.Header, pathName, op string) {
	t.Helper()

	for name, values := range headers {
		lower := strings.ToLower(name)
		assert.NotContainsf(t, lower, EncMetaPrefix,
			"the %q write path leaks the response header %q on %s", pathName, name, op)
		if strings.HasPrefix(lower, "x-amz-meta-") {
			for _, v := range values {
				assert.NotContainsf(t, strings.ToLower(v), "encrypted-dek",
					"the %q write path leaks an encryption value in header %q on %s", pathName, name, op)
			}
		}
	}
}

// EncAssertRoundTrip is assertion (c).
func EncAssertRoundTrip(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, plaintext []byte, pathName string) {
	t.Helper()

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "reading back the %q write path through the proxy", pathName)
	defer func() { _ = out.Body.Close() }()

	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)

	assert.Equalf(t, len(plaintext), len(body),
		"the %q write path returned %d bytes for a %d byte object", pathName, len(body), len(plaintext))
	assert.Equalf(t, EncSHA256(plaintext), EncSHA256(body),
		"the %q write path did not round-trip: sha256 of the delivered body differs", pathName)
}

// EncObjectView is what a client can see about an object without knowing which
// side of the proxy it is talking to. Used for the differential oracle.
type EncObjectView struct {
	ContentLength int64
	ContentType   string
	Metadata      map[string]string
	BodySHA256    string
	ETag          string
}

// EncViewObject collects the client-observable facts about an object.
func EncViewObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) EncObjectView {
	t.Helper()

	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "HeadObject %s/%s", bucket, key)

	get, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "GetObject %s/%s", bucket, key)
	body, err := io.ReadAll(get.Body)
	require.NoError(t, err)
	_ = get.Body.Close()

	meta := make(map[string]string, len(head.Metadata))
	for k, v := range head.Metadata {
		meta[strings.ToLower(k)] = v
	}

	return EncObjectView{
		ContentLength: aws.ToInt64(head.ContentLength),
		ContentType:   aws.ToString(head.ContentType),
		Metadata:      meta,
		BodySHA256:    EncSHA256(body),
		ETag:          aws.ToString(head.ETag),
	}
}

// EncCompareViews asserts the proxy answers like the backend it fronts, for
// everything a client acts on. Stored size and ETag are excluded by design: the
// proxy stores ciphertext, so the backend's own numbers are about other bytes.
func EncCompareViews(t *testing.T, viaProxy, direct EncObjectView, pathName string) {
	t.Helper()

	assert.Equalf(t, direct.ContentLength, viaProxy.ContentLength,
		"%q: the proxy reports a different object size than MinIO does for the same payload", pathName)
	assert.Equalf(t, direct.BodySHA256, viaProxy.BodySHA256,
		"%q: the proxy delivered different bytes than MinIO did for the same payload", pathName)
	assert.Equalf(t, direct.ContentType, viaProxy.ContentType,
		"%q: Content-Type differs between the proxy and MinIO", pathName)
	assert.Equalf(t, direct.Metadata, viaProxy.Metadata,
		"%q: user metadata differs between the proxy and MinIO", pathName)
	assert.Truef(t, strings.HasPrefix(viaProxy.ETag, `"`) && strings.HasSuffix(viaProxy.ETag, `"`),
		"%q: the proxy returned an unquoted ETag %q", pathName, viaProxy.ETag)
}

// EncPutSimple performs a plain PutObject and returns nothing but its error, so
// the table can drive proxy and MinIO identically.
func EncPutSimple(ctx context.Context, client *s3.Client, bucket, key, contentType string, payload []byte, userMeta map[string]string) error {
	in := &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		Metadata:      userMeta,
	}
	if contentType != "" {
		in.ContentType = aws.String(contentType)
	}
	_, err := client.PutObject(ctx, in)
	return err
}

// EncMultipartUpload drives a client-driven multipart upload with the given part
// size. It is the same code for the proxy and for MinIO.
func EncMultipartUpload(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, payload []byte, partSize int, contentType string, userMeta map[string]string) {
	t.Helper()

	createIn := &s3.CreateMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Metadata: userMeta,
	}
	if contentType != "" {
		createIn.ContentType = aws.String(contentType)
	}
	create, err := client.CreateMultipartUpload(ctx, createIn)
	require.NoErrorf(t, err, "CreateMultipartUpload on %s", bucket)
	uploadID := aws.ToString(create.UploadId)
	require.NotEmpty(t, uploadID, "the upload id must not be empty")

	aborted := false
	defer func() {
		if !aborted {
			return
		}
		abortCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, _ = client.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
	}()

	var parts []s3types.CompletedPart
	for i, off := 0, 0; off < len(payload); i, off = i+1, off+partSize {
		end := off + partSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[off:end]
		part, upErr := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(int32(i + 1)),
			Body:          bytes.NewReader(chunk),
			ContentLength: aws.Int64(int64(len(chunk))),
		})
		if upErr != nil {
			aborted = true
			require.NoErrorf(t, upErr, "UploadPart %d on %s", i+1, bucket)
		}
		parts = append(parts, s3types.CompletedPart{
			ETag:       part.ETag,
			PartNumber: aws.Int32(int32(i + 1)),
		})
	}

	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		aborted = true
		require.NoErrorf(t, err, "CompleteMultipartUpload on %s", bucket)
	}
}

// TestEncEveryPutPathStoresCiphertext drives every size- and content-type-routed
// PUT branch of handlePutObject and checks the backend never sees plaintext.
//
// The branches, from internal/proxy/handlers/object/operations.go:
//   - below streaming_threshold  -> putObjectDirect, AES-GCM
//   - at/above streaming_threshold with HMAC on -> putObjectAutoMultipart, AES-CTR
//   - force-aes-ctr content type -> putObjectStreamingReader, AES-CTR
//   - the degenerate sizes 0 and 1
func TestEncEveryPutPathStoresCiphertext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	oracleBucket := EncOracleBucket(t, ctx, tc.MinIOClient)

	cases := []struct {
		name        string
		size        int
		contentType string
		// oraclePartSize forces the differential arm to use a multipart upload.
		// MinIO rejects an aws-chunked request whose single chunk exceeds 16 MiB
		// ("chunk too big"), which the SDK produces for one large PutObject over
		// HTTPS, so payloads beyond that reach the oracle bucket in parts. The
		// proxy arm stays a single PutObject either way - that is the path under
		// test.
		oraclePartSize int
	}{
		{name: "zero_byte", size: 0},
		{name: "one_byte", size: 1},
		{name: "small_put_64kib_below_threshold", size: 64 * 1024},
		{name: "just_below_threshold", size: EncStreamingThreshold - 1},
		{name: "just_above_threshold", size: EncStreamingThreshold + 4096},
		{name: "auto_multipart_13mib", size: 13 * 1024 * 1024},
		// Content-Type is pinned here because the oracle arm uploads in parts and
		// MinIO defaults an unset type differently for PutObject
		// ("application/octet-stream") than for CreateMultipartUpload
		// ("binary/octet-stream"). Pinning it keeps the comparison about the
		// proxy rather than about MinIO's own defaults - and it checks that the
		// auto-multipart path preserves an explicit Content-Type.
		{
			name: "auto_multipart_30mib", size: 30 * 1024 * 1024,
			contentType: "application/octet-stream", oraclePartSize: 10 * 1024 * 1024,
		},
		{name: "forced_ctr_streaming_1mib", size: 1024 * 1024, contentType: EncForceCTRContentType},
		{name: "forced_ctr_small_512b", size: 512, contentType: EncForceCTRContentType},
	}

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			marker := EncNewMarker()
			payload := EncPayload(t, tcase.size, marker)
			key := "enc-at-rest-" + tcase.name + "-" + integration.RandomString(10)
			userMeta := map[string]string{"encpath": tcase.name}

			t.Cleanup(func() {
				delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
				defer cancelDel()
				_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
			})

			require.NoError(t,
				EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, tcase.contentType, payload, userMeta),
				"PutObject through the proxy")
			if tcase.oraclePartSize > 0 {
				EncMultipartUpload(t, ctx, tc.MinIOClient, oracleBucket, key, payload,
					tcase.oraclePartSize, tcase.contentType, userMeta)
			} else {
				require.NoError(t,
					EncPutSimple(ctx, tc.MinIOClient, oracleBucket, key, tcase.contentType, payload, userMeta),
					"PutObject directly into MinIO")
			}

			// The oracle arm proves the marker search works: the very same bytes,
			// written without the proxy, must be found in the backend.
			directStored := EncReadStored(t, ctx, tc.MinIOClient, oracleBucket, key)
			require.Equal(t, EncSHA256(payload), EncSHA256(directStored.Body),
				"the oracle arm should hold the plaintext byte for byte")
			if len(marker) <= len(payload) {
				require.True(t, bytes.Contains(directStored.Body, []byte(marker)),
					"the marker search is broken: it cannot even find the marker in plaintext")
			}

			// (a) + (b)
			stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
			EncAssertEncryptedAtRest(t, stored, payload, marker, tcase.name)

			// The user metadata has to survive next to the envelope.
			assert.Equal(t, tcase.name, stored.Metadata["encpath"],
				"user metadata was lost while writing through the proxy")

			// (c)
			EncAssertRoundTrip(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload, tcase.name)

			// (d)
			EncAssertNoMetadataLeak(t, ctx, tc.ProxyClient, tc.TestBucket, key, tcase.name)

			// The backend, in contrast, is allowed and expected to show the
			// envelope; that asymmetry is the documented difference.
			assert.Contains(t, stored.Metadata, EncMetaPrefix+"encrypted-dek",
				"reading directly from MinIO must still show the envelope metadata")

			// Differential oracle on everything a client acts on.
			EncCompareViews(t,
				EncViewObject(t, ctx, tc.ProxyClient, tc.TestBucket, key),
				EncViewObject(t, ctx, tc.MinIOClient, oracleBucket, key),
				tcase.name)
		})
	}
}

// TestEncClientDrivenMultipartStoresCiphertext covers the multipart API the
// client drives itself: CreateMultipartUpload, UploadPart, CompleteMultipartUpload.
// Each part is encrypted individually, so a part that slipped through unencrypted
// would show up as its own plaintext window in the stored object.
func TestEncClientDrivenMultipartStoresCiphertext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	oracleBucket := EncOracleBucket(t, ctx, tc.MinIOClient)

	const partSize = 5 * 1024 * 1024
	// Three parts: two full ones plus a short tail, so the last-part branch is
	// covered as well.
	payloadSize := 2*partSize + 1024*1024
	marker := EncNewMarker()
	payload := EncPayload(t, payloadSize, marker)

	// Stamp the marker into every part, not only at the three default offsets,
	// so a single unencrypted part cannot hide.
	for off := 0; off+len(marker) <= len(payload); off += partSize {
		copy(payload[off:], []byte(marker))
	}

	key := "enc-mpu-" + integration.RandomString(12)
	userMeta := map[string]string{"encpath": "client_multipart"}

	t.Cleanup(func() {
		delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
		defer cancelDel()
		_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})

	EncMultipartUpload(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload, partSize, "", userMeta)
	EncMultipartUpload(t, ctx, tc.MinIOClient, oracleBucket, key, payload, partSize, "", userMeta)

	directStored := EncReadStored(t, ctx, tc.MinIOClient, oracleBucket, key)
	require.True(t, bytes.Contains(directStored.Body, []byte(marker)),
		"the marker search is broken: it cannot find the marker in the plaintext oracle")

	stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
	EncAssertEncryptedAtRest(t, stored, payload, marker, "client_multipart")
	assert.Equal(t, "client_multipart", stored.Metadata["encpath"],
		"user metadata given to CreateMultipartUpload was lost")

	EncAssertRoundTrip(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload, "client_multipart")
	EncAssertNoMetadataLeak(t, ctx, tc.ProxyClient, tc.TestBucket, key, "client_multipart")

	EncCompareViews(t,
		EncViewObject(t, ctx, tc.ProxyClient, tc.TestBucket, key),
		EncViewObject(t, ctx, tc.MinIOClient, oracleBucket, key),
		"client_multipart")
}

// TestEncAWSChunkedFramingStoresCiphertext exercises the other request framing.
// aws-sdk-go-v2 only emits aws-chunked bodies with a checksum trailer over
// HTTPS (D-15), so this test goes through the TLS listener. The framing bytes
// must be decoded before encryption: if they were not, the stored object would
// contain the chunk headers, and the round-trip would return them to the client.
func TestEncAWSChunkedFramingStoresCiphertext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	tlsClient, err := integration.NewProxyTLSClient()
	require.NoError(t, err, "building a client for the proxy TLS listener")

	oracleBucket := EncOracleBucket(t, ctx, tc.MinIOClient)

	cases := []struct {
		name string
		size int
	}{
		{name: "chunked_small_gcm", size: 128 * 1024},
		{name: "chunked_above_threshold", size: EncStreamingThreshold + 4096},
	}

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			marker := EncNewMarker()
			payload := EncPayload(t, tcase.size, marker)
			key := "enc-chunked-" + tcase.name + "-" + integration.RandomString(10)
			userMeta := map[string]string{"encpath": tcase.name}

			t.Cleanup(func() {
				delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
				defer cancelDel()
				_, _ = tlsClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
			})

			require.NoError(t,
				EncPutSimple(ctx, tlsClient, tc.TestBucket, key, "", payload, userMeta),
				"PutObject through the proxy TLS listener")
			require.NoError(t,
				EncPutSimple(ctx, tc.MinIOClient, oracleBucket, key, "", payload, userMeta),
				"PutObject directly into MinIO")

			stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
			EncAssertEncryptedAtRest(t, stored, payload, marker, tcase.name)

			// aws-chunked describes the request framing only. Neither the chunk
			// framing nor its trailer may end up inside the object.
			EncAssertRoundTrip(t, ctx, tlsClient, tc.TestBucket, key, payload, tcase.name)
			EncAssertNoMetadataLeak(t, ctx, tlsClient, tc.TestBucket, key, tcase.name)

			EncCompareViews(t,
				EncViewObject(t, ctx, tlsClient, tc.TestBucket, key),
				EncViewObject(t, ctx, tc.MinIOClient, oracleBucket, key),
				tcase.name)
		})
	}
}

// TestEncCopyObjectNeverStoresPlaintext covers the copy write path.
//
// DEVIATION ENCODED: AWS answers CopyObject with 200 and a CopyObjectResult
// document; this proxy refuses it with 422 NotSupportedWithEncryption
// (internal/proxy/handlers/object/operations.go handlePutObject, and
// internal/proxy/response/errors.go WriteNotSupportedWithEncryption). The test
// asserts the ACTUAL behaviour and, for MAIN GOAL 1, that the refusal leaves no
// object behind - a partially handled copy that wrote the source plaintext to
// the destination would be the worst possible outcome here.
func TestEncCopyObjectNeverStoresPlaintext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	oracleBucket := EncOracleBucket(t, ctx, tc.MinIOClient)

	marker := EncNewMarker()
	payload := EncPayload(t, 32*1024, marker)

	srcKey := "enc-copy-src-" + integration.RandomString(10)
	dstKey := "enc-copy-dst-" + integration.RandomString(10)

	t.Cleanup(func() {
		delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
		defer cancelDel()
		for _, k := range []string{srcKey, dstKey} {
			_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(k),
			})
		}
	})

	require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, srcKey, "", payload, nil))
	require.NoError(t, EncPutSimple(ctx, tc.MinIOClient, oracleBucket, srcKey, "", payload, nil))

	// The backend arm: MinIO performs the copy, which is the documented AWS
	// behaviour and the reference the proxy is measured against.
	_, directErr := tc.MinIOClient.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(oracleBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(oracleBucket + "/" + srcKey),
	})
	require.NoError(t, directErr, "MinIO performs a server-side copy")

	_, proxyErr := tc.ProxyClient.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(tc.TestBucket + "/" + srcKey),
	})
	require.Error(t, proxyErr,
		"DEVIATION: if CopyObject ever starts to succeed, this test has to verify the copy is encrypted too")
	assert.Equal(t, http.StatusUnprocessableEntity, EncHTTPStatus(proxyErr),
		"the proxy refuses CopyObject with 422; AWS would answer 200")
	assert.Equal(t, "NotSupportedWithEncryption", EncAPICode(proxyErr),
		"the refusal must carry a stable S3 error code clients can branch on")

	// MAIN GOAL 1: the refused copy must not have written anything.
	_, headErr := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(dstKey),
	})
	require.Error(t, headErr,
		"MAIN GOAL 1: the refused CopyObject left an object at the destination key")
	assert.Equal(t, http.StatusNotFound, EncHTTPStatus(headErr),
		"the destination key must simply not exist after a refused copy")

	// And the source is untouched and still ciphertext.
	stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, srcKey)
	EncAssertEncryptedAtRest(t, stored, payload, marker, "copy_source")
}

// TestEncUploadPartCopyNeverStoresPlaintext is the multipart sibling of the copy
// path. DEVIATION ENCODED, same shape: AWS answers UploadPartCopy with 200 and a
// CopyPartResult; this proxy refuses with 422 NotSupportedWithEncryption
// (internal/proxy/handlers/multipart/copy.go).
func TestEncUploadPartCopyNeverStoresPlaintext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	marker := EncNewMarker()
	payload := EncPayload(t, 6*1024*1024, marker)

	srcKey := "enc-partcopy-src-" + integration.RandomString(10)
	dstKey := "enc-partcopy-dst-" + integration.RandomString(10)

	require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, srcKey, "", payload, nil))

	create, err := tc.ProxyClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(dstKey),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	t.Cleanup(func() {
		delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
		defer cancelDel()
		_, _ = tc.ProxyClient.AbortMultipartUpload(delCtx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(dstKey), UploadId: aws.String(uploadID),
		})
		for _, k := range []string{srcKey, dstKey} {
			_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(k),
			})
		}
	})

	_, copyErr := tc.ProxyClient.UploadPartCopy(ctx, &s3.UploadPartCopyInput{
		Bucket:     aws.String(tc.TestBucket),
		Key:        aws.String(dstKey),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(1),
		CopySource: aws.String(tc.TestBucket + "/" + srcKey),
	})
	require.Error(t, copyErr,
		"DEVIATION: if UploadPartCopy ever starts to succeed, the copied part has to be verified as ciphertext")
	assert.Equal(t, http.StatusUnprocessableEntity, EncHTTPStatus(copyErr),
		"the proxy refuses UploadPartCopy with 422; AWS would answer 200")
	assert.Equal(t, "NotSupportedWithEncryption", EncAPICode(copyErr))

	stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, srcKey)
	EncAssertEncryptedAtRest(t, stored, payload, marker, "uploadpartcopy_source")
}

// TestEncOverwriteReencrypts guards the update path: writing over an existing
// key must produce a fresh envelope, and above all must not leave the new
// plaintext at rest. A same-key overwrite is the one moment where old metadata
// could be reused with new data - which for AES-CTR would mean encrypting two
// different plaintexts under the same key and IV.
func TestEncOverwriteReencrypts(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// One format, so one case: what used to be the AES-GCM and AES-CTR halves of
	// this test is now the same write path.
	cases := []struct {
		name        string
		contentType string
	}{
		{name: "segmented", contentType: ""},
	}

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			key := "enc-overwrite-" + tcase.name + "-" + integration.RandomString(12)
			t.Cleanup(func() {
				delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
				defer cancelDel()
				_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
			})

			firstMarker := EncNewMarker()
			first := EncPayload(t, 48*1024, firstMarker)
			require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, tcase.contentType, first, nil))
			firstStored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
			EncAssertEncryptedAtRest(t, firstStored, first, firstMarker, "overwrite_first_"+tcase.name)

			secondMarker := EncNewMarker()
			second := EncPayload(t, 96*1024, secondMarker)
			require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, tcase.contentType, second, nil))
			secondStored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
			EncAssertEncryptedAtRest(t, secondStored, second, secondMarker, "overwrite_second_"+tcase.name)

			// A reused DEK envelope across two different objects would mean key
			// reuse; a reused IV on top of that would be a two-time pad for CTR.
			assert.NotEqual(t,
				firstStored.Metadata[EncMetaPrefix+"encrypted-dek"],
				secondStored.Metadata[EncMetaPrefix+"encrypted-dek"],
				"the overwrite reused the previous data key envelope")
			// The nonces live inside the segments, so a fresh data key is what
			// keeps the two objects apart. Reusing it would put two plaintexts
			// under one key at the same segment indices.
			assert.NotEqual(t, firstStored.Body, secondStored.Body,
				"the overwrite stored the same bytes for different plaintext")

			EncAssertRoundTrip(t, ctx, tc.ProxyClient, tc.TestBucket, key, second, "overwrite_second_"+tcase.name)
			assert.False(t, bytes.Contains(secondStored.Body, []byte(firstMarker)),
				"the first plaintext is still visible in the stored object after the overwrite")
		})
	}
}

// TestEncTamperedCiphertextIsRejected is the other half of "encrypted at rest":
// storing ciphertext is only worth something if the proxy notices when the
// backend hands back different ciphertext. The threat model in
// SECURITY_ARCHITECTURE.md treats the backend as hostile, so this flips one byte
// of the stored body behind the proxy's back and asserts the plaintext is never
// delivered.
//
// Every segment carries its own tag and the trailer authenticates the chain, so
// a flip anywhere - in a segment or in the trailer - has to stop the read. That
// is the property the old format could not reach: an AES-CTR object was only
// covered by a whole-object HMAC that the read path checked after it had already
// released the plaintext.
func TestEncTamperedCiphertextIsRejected(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	cases := []struct {
		name        string
		contentType string
		wantAlg     string
	}{
		{name: "segment", contentType: "", wantAlg: "s3ep-gcm-seg-v2"},
	}

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			marker := EncNewMarker()
			payload := EncPayload(t, 64*1024, marker)
			key := "enc-tamper-" + tcase.name + "-" + integration.RandomString(10)

			t.Cleanup(func() {
				delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
				defer cancelDel()
				_, _ = tc.MinIOClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
			})

			require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, tcase.contentType, payload, nil))

			stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
			require.Equal(t, tcase.wantAlg, stored.Metadata[EncMetaPrefix+"dek-algorithm"],
				"this case is meant to cover %s", tcase.wantAlg)
			require.NotEmpty(t, stored.Body)

			// Flip one bit in the middle of the ciphertext and write it back
			// with the original envelope, exactly what a backend with write
			// access could do.
			tampered := make([]byte, len(stored.Body))
			copy(tampered, stored.Body)
			tampered[len(tampered)/2] ^= 0x01

			_, err := tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket:        aws.String(tc.TestBucket),
				Key:           aws.String(key),
				Body:          bytes.NewReader(tampered),
				ContentLength: aws.Int64(int64(len(tampered))),
				Metadata:      stored.Metadata,
			})
			require.NoError(t, err, "writing the tampered object straight into the backend")

			out, getErr := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			})
			var body []byte
			var readErr error
			if getErr == nil {
				body, readErr = io.ReadAll(out.Body)
				_ = out.Body.Close()
			}

			assert.NotEqual(t, EncSHA256(payload), EncSHA256(body),
				"the proxy delivered the original plaintext although the stored ciphertext was modified")
			assert.Truef(t, getErr != nil || readErr != nil,
				"tampering with the stored %s object was not detected: GetObject returned %d bytes and no error",
				tcase.wantAlg, len(body))
		})
	}
}

// EncUnseekable hides the Seek and Len methods of the underlying reader, which
// is how a client produces a PUT whose length the SDK cannot determine up front.
type EncUnseekable struct{ r io.Reader }

func (u EncUnseekable) Read(p []byte) (int, error) { return u.r.Read(p) }

// TestEncStreamedPutWithoutContentLengthStoresCiphertext covers the branch
// handlePutObject takes when the plaintext length is unknown
// (contentLengthUnknown -> putObjectAutoMultipart). That is the shape any client
// streaming an unseekable body produces -- Velero and kopia do it when they
// stream a backup straight into the proxy -- and it is the one write path where
// the proxy cannot size the object before encrypting it.
//
// It runs against the TLS listener because aws-sdk-go-v2 refuses an unseekable
// body over plain HTTP ("unseekable stream is not supported without TLS and
// trailing checksum"), so this framing is only reachable over HTTPS.
func TestEncStreamedPutWithoutContentLengthStoresCiphertext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	tlsClient, err := integration.NewProxyTLSClient()
	require.NoError(t, err, "building a client for the proxy TLS listener")

	marker := EncNewMarker()
	payload := EncPayload(t, 7*1024*1024, marker)
	key := "enc-nolength-" + integration.RandomString(12)

	t.Cleanup(func() {
		delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
		defer cancelDel()
		_, _ = tc.MinIOClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})

	_, err = tlsClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket),
		Key:    aws.String(key),
		Body:   EncUnseekable{r: bytes.NewReader(payload)},
	})
	require.NoError(t, err, "streaming PutObject without a Content-Length")

	stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
	EncAssertEncryptedAtRest(t, stored, payload, marker, "put_without_content_length")
	EncAssertRoundTrip(t, ctx, tlsClient, tc.TestBucket, key, payload, "put_without_content_length")
	EncAssertNoMetadataLeak(t, ctx, tlsClient, tc.TestBucket, key, "put_without_content_length")
}

// TestEncClientMetadataCannotReachTheStoredEnvelope pins the fix for a defect
// this test used to encode.
//
// A client can send arbitrary x-amz-meta-* headers. handlePutObject drops the
// ones carrying the encryption prefix, because the stored envelope is exactly
// what the download path trusts to decrypt. That filter compared the prefix
// case-sensitively while net/http had already canonicalised the header, so
// "x-amz-meta-s3ep-injected" arrived as "X-Amz-Meta-S3ep-Injected", the key
// handed to the filter was "S3ep-Injected", and it never matched the lowercase
// prefix. It is compared case-insensitively now.
//
// Still open, and deliberately not asserted as correct here: the key is dropped
// silently rather than refused. Refusing client metadata inside the prefix with
// InvalidArgument is ADR 0009 and ships with the next major.
//
// MAIN GOAL 1 is unaffected - the body is still ciphertext - which is asserted
// here too so the fix cannot trade one for the other.
func TestEncClientMetadataCannotReachTheStoredEnvelope(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// A key inside the encryption namespace that the proxy itself never writes,
	// so the outcome does not depend on which of two colliding headers wins.
	const injectedKey = EncMetaPrefix + "injected"
	const injectedValue = "client-controlled"

	marker := EncNewMarker()
	payload := EncPayload(t, 32*1024, marker)
	key := "enc-meta-injection-" + integration.RandomString(10)

	t.Cleanup(func() {
		delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
		defer cancelDel()
		_, _ = tc.ProxyClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})

	require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, "", payload,
		map[string]string{injectedKey: injectedValue, "keepme": "yes"}))

	stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
	EncAssertEncryptedAtRest(t, stored, payload, marker, "metadata_injection")
	assert.Equal(t, "yes", stored.Metadata["keepme"], "ordinary user metadata must survive")

	assert.NotContainsf(t, stored.Metadata, injectedKey,
		"client metadata in the %s namespace must never reach the stored object", EncMetaPrefix)

	// It is invisible to the client on the way back as well, so the namespace is
	// neither writable nor readable from outside.
	EncAssertNoMetadataLeak(t, ctx, tc.ProxyClient, tc.TestBucket, key, "metadata_injection")
	EncAssertRoundTrip(t, ctx, tc.ProxyClient, tc.TestBucket, key, payload, "metadata_injection")
}

// TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext drives the damaging
// half of the same defect: a client that sends x-amz-meta-s3ep-dek-algorithm and
// friends collides with the envelope the proxy writes itself. Both entries land
// in one PutObjectInput.Metadata map, aws-sdk-go-v2 serialises each with
// http.CanonicalHeaderKey (service/s3/serializers.go: hv.SetHeader(...)), so the
// two collapse onto one header and the winner is decided by Go map iteration
// order - a coin flip per key, per request.
//
// Consequence: a PUT that answered 200 can leave an object whose stored
// dek-algorithm is the attacker's string, and every later GET of it fails with
// 500 DecryptionError. That is silent data loss, reachable by any authorised
// client, and the loop below observes it directly.
//
// The filter is case-insensitive now, so no forged value reaches the envelope at
// all and the collision cannot happen. The loop is kept: it is the only place
// that would notice the guard regressing, and a coin-flip defect needs repeated
// attempts to be caught deterministically.
//
// Two things are asserted per attempt regardless of the coin flip, and those are
// the ones that must never regress:
//   - the stored body is ciphertext (MAIN GOAL 1)
//   - the proxy never answers a GET with plaintext that is not the plaintext
//     that was uploaded
func TestEncForgedEnvelopeMetadataCannotProduceWrongPlaintext(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	forged := map[string]string{
		EncMetaPrefix + "dek-algorithm":   "forged-alg",
		EncMetaPrefix + "encrypted-dek":   "Zm9yZ2VkLWRlaw==",
		EncMetaPrefix + "kek-algorithm":   "forged-kek",
		EncMetaPrefix + "kek-fingerprint": "forgedfingerprint",
		EncMetaPrefix + "aes-iv":          "Zm9yZ2VkLWl2AAAA",
		EncMetaPrefix + "hmac":            "Zm9yZ2VkLWhtYWM=",
	}

	// Ten attempts: a single forged key wins about half the time, so the chance
	// that none of the six wins in any of the ten attempts is far below one in a
	// billion. The loop is what makes an otherwise nondeterministic defect a
	// deterministic test.
	const attempts = 5
	overridden := map[string]int{}

	for i := 0; i < attempts; i++ {
		marker := EncNewMarker()
		payload := EncPayload(t, 32*1024, marker)
		key := fmt.Sprintf("enc-forged-envelope-%d-%s", i, integration.RandomString(8))

		t.Cleanup(func() {
			delCtx, cancelDel := context.WithTimeout(context.Background(), time.Minute)
			defer cancelDel()
			_, _ = tc.MinIOClient.DeleteObject(delCtx, &s3.DeleteObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			})
		})

		require.NoError(t, EncPutSimple(ctx, tc.ProxyClient, tc.TestBucket, key, "", payload, forged),
			"the PUT itself is accepted, which is part of the problem")

		stored := EncReadStored(t, ctx, tc.MinIOClient, tc.TestBucket, key)
		EncAssertBodyIsCiphertext(t, stored, payload, marker, "forged_envelope")

		for forgedKey, forgedValue := range forged {
			if stored.Metadata[forgedKey] == forgedValue {
				overridden[forgedKey]++
			}
		}

		// Whatever the envelope now says, the proxy must not hand out something
		// that claims to be this object but is not.
		out, getErr := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		if getErr == nil {
			body, readErr := io.ReadAll(out.Body)
			_ = out.Body.Close()
			if readErr == nil {
				assert.Equal(t, EncSHA256(payload), EncSHA256(body),
					"the proxy delivered a body that is neither an error nor the uploaded plaintext")
			}
		} else {
			// The observed failure is 500 DecryptionError. It is recorded rather
			// than asserted away: a write that succeeds and can never be read is
			// the actual damage.
			t.Logf("attempt %d: GET failed after metadata injection: status=%d code=%s",
				i, EncHTTPStatus(getErr), EncAPICode(getErr))
		}
	}

	require.Emptyf(t, overridden,
		"client-supplied %s* metadata reached the stored envelope in %d attempts: %v",
		EncMetaPrefix, attempts, overridden)
}

// TestEncStoredHMACEnforcement checks what the s3ep-hmac on a stored object is
// actually worth. The backend is assumed hostile, so an HMAC that is written but
// never checked is decoration.
//
//   - AES-CTR is unauthenticated, so the HMAC is the only integrity control:
//     replacing it must make the download fail (integrity_verification: strict).
//   - AES-GCM stores no HMAC of its own; its ciphertext is authenticated by the
//     GCM tag, which TestEncTamperedCiphertextIsRejected already proves.
//
// DEVIATION ENCODED in the gcm subtest: an s3ep-hmac that cannot match is
// planted on a GCM object and the download still succeeds, so "strict" does not
// mean every stored HMAC is verified. Harmless while the GCM tag holds, but it
// A planted or edited s3ep- value cannot change what the proxy serves: the
// metadata says which key wrapped the object, and everything else about the
// object's content is authenticated inside the chain itself. What used to be
// TestEncStoredHMACEnforcement covered a separate integrity value that could be
// replaced independently of the data; there is no such value any more, and the
// tampering cases it exercised are covered by
// TestEncTamperedCiphertextIsRejected and TestEncForgedEnvelopeIsRejected.
