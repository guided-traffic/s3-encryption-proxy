//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Header and metadata fidelity between PUT, GET and HEAD, checked differentially:
// every behaviour is exercised twice, once through the proxy and once directly
// against the MinIO bucket the proxy fronts, and the two answers are compared.
//
// The differences that are legitimate and therefore encoded rather than flagged:
//   - the proxy filters the s3ep-* metadata namespace out of client responses
//   - the bytes and the length the BACKEND reports are ciphertext
//   - the ETag is the digest of the ciphertext, so it does not equal the digest
//     MinIO reports for the same plaintext
//
// Everything else that differs is named as a deviation in the comment above the
// assertion that encodes it.

// ----------------------------------------------------------------------------
// The entity headers and user metadata every test in this file uploads.
// ----------------------------------------------------------------------------

const (
	hdrContentType        = "text/x-conformance; charset=utf-8"
	hdrContentEncoding    = "gzip"
	hdrContentDisposition = `attachment; filename="report.pdf"`
	hdrContentLanguage    = "de-DE"
	hdrCacheControl       = "max-age=3600, public"
)

// hdrExpires is far enough in the future that no cache heuristic can rewrite it.
var hdrExpires = time.Date(2099, 10, 21, 7, 28, 0, 0, time.UTC)

// HdrUserMetadata is the user metadata set under test: a plain key, a key with
// mixed case, an empty value, a value containing spaces and a UTF-8 value.
//
// The spaces here are single. A value with SEQUENTIAL whitespace cannot be
// uploaded through the proxy at all — see
// TestHdrSequentialWhitespaceInASignedHeaderBreaksTheProxySignature.
func HdrUserMetadata() map[string]string {
	return map[string]string{
		"simple":      "plain-value",
		"MixedCase":   "MixedValue",
		"empty":       "",
		"with-spaces": "one space between words",
		"utf8":        "grüße-☂",
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// HdrCaptureResponseHeaders returns a per-call option that copies the raw HTTP
// response headers of the operation into dst. The SDK's typed output hides both
// the exact header names and the headers it has no field for (Expires above
// all), and those are precisely what this file is about.
func HdrCaptureResponseHeaders(dst *http.Header) func(*s3.Options) {
	return func(o *s3.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Deserialize.Add(middleware.DeserializeMiddlewareFunc(
				"HdrCaptureResponseHeaders",
				func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
					middleware.DeserializeOutput, middleware.Metadata, error) {
					out, md, err := next.HandleDeserialize(ctx, in)
					if resp, ok := out.RawResponse.(*smithyhttp.Response); ok && resp != nil {
						*dst = resp.Header.Clone()
					}
					return out, md, err
				}), middleware.After)
		})
	}
}

// HdrCaptureResponseBody returns a per-call option that copies the raw response
// document into dst before the SDK parses it. Only for small documents: it
// buffers the whole body.
func HdrCaptureResponseBody(dst *[]byte) func(*s3.Options) {
	return func(o *s3.Options) {
		o.APIOptions = append(o.APIOptions, func(stack *middleware.Stack) error {
			return stack.Deserialize.Add(middleware.DeserializeMiddlewareFunc(
				"HdrCaptureResponseBody",
				func(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
					middleware.DeserializeOutput, middleware.Metadata, error) {
					out, md, err := next.HandleDeserialize(ctx, in)
					if resp, ok := out.RawResponse.(*smithyhttp.Response); ok && resp != nil && resp.Body != nil {
						body, readErr := io.ReadAll(resp.Body)
						_ = resp.Body.Close()
						if readErr == nil {
							*dst = body
							resp.Body = io.NopCloser(bytes.NewReader(body))
						}
					}
					return out, md, err
				}), middleware.After)
		})
	}
}

// HdrPutWithEntityHeaders uploads body with the full entity-header set and the
// given user metadata.
func HdrPutWithEntityHeaders(ctx context.Context, client *s3.Client, bucket, key string,
	body []byte, metadata map[string]string) (*s3.PutObjectOutput, error) {
	return client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:             aws.String(bucket),
		Key:                aws.String(key),
		Body:               bytes.NewReader(body),
		ContentLength:      aws.Int64(int64(len(body))),
		ContentType:        aws.String(hdrContentType),
		ContentEncoding:    aws.String(hdrContentEncoding),
		ContentDisposition: aws.String(hdrContentDisposition),
		ContentLanguage:    aws.String(hdrContentLanguage),
		CacheControl:       aws.String(hdrCacheControl),
		Expires:            aws.Time(hdrExpires),
		Metadata:           metadata,
	})
}

// HdrGetHeaders performs a GET, drains the body and returns the wire headers
// together with the sha256 of the delivered bytes.
func HdrGetHeaders(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) (http.Header, [32]byte, int) {
	t.Helper()

	var captured http.Header
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	}, HdrCaptureResponseHeaders(&captured))
	require.NoError(t, err, "GetObject %s/%s", bucket, key)
	body, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	_ = out.Body.Close()
	return captured, sha256.Sum256(body), len(body)
}

// HdrHeadHeaders performs a HEAD and returns the wire headers.
func HdrHeadHeaders(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) http.Header {
	t.Helper()

	var captured http.Header
	_, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	}, HdrCaptureResponseHeaders(&captured))
	require.NoError(t, err, "HeadObject %s/%s", bucket, key)
	return captured
}

// HdrIsObjectHeader reports whether a response header belongs to the object's S3
// contract, as opposed to transport, CORS or request-id noise that no two
// implementations are expected to agree on.
func HdrIsObjectHeader(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "x-amz-meta-") || strings.HasPrefix(n, "content-") {
		return true
	}
	switch n {
	case "cache-control", "expires", "etag", "last-modified", "accept-ranges":
		return true
	}
	return false
}

// HdrObjectHeaderNames returns the lower-cased names of the object headers in h.
func HdrObjectHeaderNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for name := range h {
		if HdrIsObjectHeader(name) {
			names = append(names, strings.ToLower(name))
		}
	}
	return names
}

// HdrNewDirectBucket creates a bucket that exists only for the direct-MinIO half
// of a differential test, and registers its cleanup.
func HdrNewDirectBucket(t *testing.T, ctx context.Context, client *s3.Client, lockEnabled bool) string {
	t.Helper()

	name := "hdr-direct-" + integration.RandomString(12)
	input := &s3.CreateBucketInput{Bucket: aws.String(name)}
	if lockEnabled {
		input.ObjectLockEnabledForBucket = aws.Bool(true)
	}
	_, err := client.CreateBucket(ctx, input)
	require.NoError(t, err, "create direct MinIO bucket %s", name)
	t.Cleanup(func() { HdrCleanupBucket(client, name) })
	return name
}

// HdrCleanupBucket removes a bucket created by this file, including the versions,
// delete markers, legal holds and governance retention an object-lock bucket
// carries. Best effort by design: it runs from t.Cleanup on failing tests too.
func HdrCleanupBucket(client *s3.Client, bucket string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if versions, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		for _, v := range versions.Versions {
			_, _ = client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket:    aws.String(bucket),
				Key:       v.Key,
				VersionId: v.VersionId,
				LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff},
			})
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:                    aws.String(bucket),
				Key:                       v.Key,
				VersionId:                 v.VersionId,
				BypassGovernanceRetention: aws.Bool(true),
			})
		}
		for _, m := range versions.DeleteMarkers {
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: m.Key, VersionId: m.VersionId,
			})
		}
	}

	if objects, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	}); err == nil {
		for _, o := range objects.Contents {
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: o.Key,
			})
		}
	}

	_, _ = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
}

// ----------------------------------------------------------------------------
// 1. Entity headers survive the round trip, and the proxy answers like MinIO
// ----------------------------------------------------------------------------

// The entity headers describe the plaintext, so encryption must not touch them.
// Both halves of the differential upload the identical request; the proxy's
// answer is compared against the backend's own.
func TestHdrEntityHeadersSurvivePutGetAndHead(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)

	payload := []byte("entity headers describe the plaintext, not the ciphertext")
	key := "entity-headers-" + integration.RandomString(10)
	metadata := HdrUserMetadata()

	_, err := HdrPutWithEntityHeaders(ctx, tc.ProxyClient, tc.TestBucket, key, payload, metadata)
	require.NoError(t, err, "PUT through the proxy")
	_, err = HdrPutWithEntityHeaders(ctx, tc.MinIOClient, directBucket, key, payload, metadata)
	require.NoError(t, err, "PUT directly into MinIO")

	proxyGet, proxyDigest, proxyLen := HdrGetHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	proxyHead := HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	minioGet, minioDigest, minioLen := HdrGetHeaders(t, ctx, tc.MinIOClient, directBucket, key)
	minioHead := HdrHeadHeaders(t, ctx, tc.MinIOClient, directBucket, key)

	t.Run("the_body_is_the_plaintext_on_both_sides", func(t *testing.T) {
		assert.Equal(t, sha256.Sum256(payload), proxyDigest, "the proxy delivered different bytes than were uploaded")
		assert.Equal(t, minioDigest, proxyDigest, "proxy and backend delivered different bytes")
		assert.Equal(t, len(payload), proxyLen)
		assert.Equal(t, len(payload), minioLen)
	})

	t.Run("the_forwarded_entity_headers_match_the_request_and_the_backend", func(t *testing.T) {
		for _, c := range []struct{ header, want string }{
			{"Content-Type", hdrContentType},
			{"Content-Encoding", hdrContentEncoding},
			{"Content-Disposition", hdrContentDisposition},
			{"Content-Language", hdrContentLanguage},
			{"Cache-Control", hdrCacheControl},
		} {
			assert.Equalf(t, c.want, proxyGet.Get(c.header), "GET through the proxy lost %s", c.header)
			assert.Equalf(t, c.want, proxyHead.Get(c.header), "HEAD through the proxy lost %s", c.header)
			assert.Equalf(t, minioGet.Get(c.header), proxyGet.Get(c.header),
				"GET: the proxy and the backend disagree on %s", c.header)
			assert.Equalf(t, minioHead.Get(c.header), proxyHead.Get(c.header),
				"HEAD: the proxy and the backend disagree on %s", c.header)
		}
	})

	// DEVIATION (confirmed defect). AWS documents Expires as an entity header
	// that PutObject stores and GET/HEAD return. The backend does exactly that.
	// The proxy parses no Expires on PUT — "Skip Expires header as it requires
	// time parsing", internal/proxy/handlers/object/operations.go:673, and
	// addRequestHeaders in helpers.go:150-169 has no branch for it either — so
	// the value never reaches storage and no read can return it. The PUT still
	// answers 200. This asserts the actual behaviour so the suite stays honest;
	// it is reported as a finding.
	t.Run("expires_is_dropped_by_the_proxy_but_kept_by_the_backend", func(t *testing.T) {
		require.NotEmpty(t, minioGet.Get("Expires"),
			"the backend is expected to round-trip Expires; without that there is no oracle here")
		assert.Equal(t, minioGet.Get("Expires"), minioHead.Get("Expires"),
			"the backend must return the same Expires on GET and HEAD")
		assert.Empty(t, proxyGet.Get("Expires"),
			"DEVIATION: the proxy drops Expires on PUT, so GET cannot return it")
		assert.Empty(t, proxyHead.Get("Expires"),
			"DEVIATION: the proxy drops Expires on PUT, so HEAD cannot return it")
	})

	t.Run("content_length_is_the_plaintext_length_on_get_and_head", func(t *testing.T) {
		want := strconv.Itoa(len(payload))
		assert.Equal(t, want, proxyGet.Get("Content-Length"),
			"GET Content-Length is not the plaintext length")
		assert.Equal(t, want, proxyHead.Get("Content-Length"),
			"HEAD Content-Length is not the plaintext length")
		assert.Equal(t, proxyGet.Get("Content-Length"), proxyHead.Get("Content-Length"),
			"GET and HEAD disagree on Content-Length")
		assert.Equal(t, want, minioGet.Get("Content-Length"))
		assert.Equal(t, want, minioHead.Get("Content-Length"))

		// The BACKEND is allowed to report more: it holds ciphertext. AES-GCM
		// adds a 12-byte nonce and a 16-byte tag, so this also proves the object
		// really is encrypted at rest.
		backend, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err)
		assert.Greater(t, aws.ToInt64(backend.ContentLength), int64(len(payload)),
			"the stored object is not larger than the plaintext: is it encrypted at all?")
	})
}

// ----------------------------------------------------------------------------
// 2. HEAD returns the same header set as GET
// ----------------------------------------------------------------------------

// AWS documents HeadObject as returning the same headers as GetObject. A header
// one returns and the other omits misleads any client that sizes a buffer or
// picks a decoder from a HEAD.
func TestHdrHeadReturnsTheSameHeaderSetAsGet(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)

	payload := []byte("head must not contradict get")
	key := "head-equals-get-" + integration.RandomString(10)

	_, err := HdrPutWithEntityHeaders(ctx, tc.ProxyClient, tc.TestBucket, key, payload, HdrUserMetadata())
	require.NoError(t, err)
	_, err = HdrPutWithEntityHeaders(ctx, tc.MinIOClient, directBucket, key, payload, HdrUserMetadata())
	require.NoError(t, err)

	proxyGet, _, _ := HdrGetHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	proxyHead := HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	minioGet, _, _ := HdrGetHeaders(t, ctx, tc.MinIOClient, directBucket, key)
	minioHead := HdrHeadHeaders(t, ctx, tc.MinIOClient, directBucket, key)

	assert.ElementsMatch(t, HdrObjectHeaderNames(proxyGet), HdrObjectHeaderNames(proxyHead),
		"the proxy returns a different set of object headers on HEAD than on GET")
	assert.ElementsMatch(t, HdrObjectHeaderNames(minioGet), HdrObjectHeaderNames(minioHead),
		"the backend returns a different set of object headers on HEAD than on GET")

	// The two implementations must also agree with each other, with Expires as
	// the single documented exception (see the Expires sub-test above).
	proxyNames := HdrObjectHeaderNames(proxyGet)
	backendNames := make([]string, 0, len(minioGet))
	for _, name := range HdrObjectHeaderNames(minioGet) {
		if name == "expires" {
			continue
		}
		backendNames = append(backendNames, name)
	}
	assert.ElementsMatch(t, backendNames, proxyNames,
		"the proxy and the backend expose different object headers for the same upload")

	// Every value the two do share must be identical, the ETag excluded: the
	// proxy's ETag is the digest of the ciphertext.
	for _, name := range proxyNames {
		if name == "etag" || name == "last-modified" {
			continue
		}
		assert.Equalf(t, minioGet.Get(name), proxyGet.Get(name), "GET: value of %s differs", name)
		assert.Equalf(t, minioHead.Get(name), proxyHead.Get(name), "HEAD: value of %s differs", name)
	}
}

// ----------------------------------------------------------------------------
// 3. User metadata fidelity
// ----------------------------------------------------------------------------

// User metadata keys are case-insensitive and the values are opaque. Whatever
// the backend does with them, the proxy has to do the same.
func TestHdrUserMetadataRoundTripsLikeTheBackend(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)

	payload := []byte("user metadata fidelity")
	key := "user-metadata-" + integration.RandomString(10)
	metadata := HdrUserMetadata()

	_, err := HdrPutWithEntityHeaders(ctx, tc.ProxyClient, tc.TestBucket, key, payload, metadata)
	require.NoError(t, err, "PUT through the proxy")
	_, err = HdrPutWithEntityHeaders(ctx, tc.MinIOClient, directBucket, key, payload, metadata)
	require.NoError(t, err, "PUT directly into MinIO")

	proxyGet, _, _ := HdrGetHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	proxyHead := HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	minioGet, _, _ := HdrGetHeaders(t, ctx, tc.MinIOClient, directBucket, key)

	for name, want := range metadata {
		header := "x-amz-meta-" + name // http.Header.Get is case-insensitive

		// The value the backend reports is the reference. S3 stores metadata
		// keys case-insensitively and MinIO re-encodes a non-ASCII value as
		// RFC 2047, so "what the backend says" is the only stable oracle.
		reference := minioGet.Get(header)
		assert.Equalf(t, reference, proxyGet.Get(header),
			"GET: metadata %q differs between proxy and backend", name)
		assert.Equalf(t, reference, proxyHead.Get(header),
			"HEAD: metadata %q differs between proxy and backend", name)
		assert.Equalf(t, proxyGet.Get(header), proxyHead.Get(header),
			"the proxy returns metadata %q differently on GET than on HEAD", name)

		if want != "" && !strings.ContainsAny(want, "üß☂") {
			assert.Equalf(t, want, proxyGet.Get(header),
				"metadata %q did not survive the round trip unchanged", name)
		}
	}

	// The empty value must survive as a present, empty header rather than
	// disappearing: a client cannot otherwise tell "unset" from "set to empty".
	assert.Containsf(t, HdrObjectHeaderNames(proxyGet), "x-amz-meta-empty",
		"the metadata key with an empty value vanished from the GET response")
	assert.Containsf(t, HdrObjectHeaderNames(proxyHead), "x-amz-meta-empty",
		"the metadata key with an empty value vanished from the HEAD response")
}

// DEVIATION (confirmed defect, security relevant). SigV4 canonicalisation
// requires sequential whitespace inside a header value to be collapsed to a
// single space before signing ("Trim excess white space before and after values,
// and convert sequential spaces to a single space"). The proxy only trims the
// ends — strings.TrimSpace at
// internal/proxy/middleware/s3auth_robust.go:382 — so every request whose signed
// headers contain sequential spaces is rejected as SignatureDoesNotMatch,
// although the client signed it exactly as AWS prescribes. The backend accepts
// the identical request. (A TAB inside a value is left out on purpose: the
// backend rejects that one too, so there is no oracle for it here.)
//
// This is not exotic: "Cache-Control: max-age=3600,  public" is enough.
func TestHdrSequentialWhitespaceInASignedHeaderBreaksTheProxySignature(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)

	payload := []byte("sequential whitespace")

	cases := []struct {
		name  string
		build func(bucket, key string) *s3.PutObjectInput
	}{
		{
			name: "metadata_value_with_two_spaces",
			build: func(bucket, key string) *s3.PutObjectInput {
				return &s3.PutObjectInput{
					Bucket: aws.String(bucket), Key: aws.String(key),
					Body:          bytes.NewReader(payload),
					ContentLength: aws.Int64(int64(len(payload))),
					Metadata:      map[string]string{"spaced": "a b  c"},
				}
			},
		},
		{
			name: "cache_control_with_two_spaces",
			build: func(bucket, key string) *s3.PutObjectInput {
				return &s3.PutObjectInput{
					Bucket: aws.String(bucket), Key: aws.String(key),
					Body:          bytes.NewReader(payload),
					ContentLength: aws.Int64(int64(len(payload))),
					CacheControl:  aws.String("max-age=3600,  public"),
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := "whitespace-" + integration.RandomString(10)

			_, backendErr := tc.MinIOClient.PutObject(ctx, c.build(directBucket, key))
			require.NoError(t, backendErr,
				"the backend is expected to accept this request; without that there is no oracle here")

			_, proxyErr := tc.ProxyClient.PutObject(ctx, c.build(tc.TestBucket, key))
			require.Error(t, proxyErr,
				"DEVIATION EXPECTED: the proxy is known to reject sequential whitespace in a signed header")
			assert.Equal(t, http.StatusForbidden, httpStatusOf(proxyErr),
				"the proxy rejects the request, but not as a signature failure")
			assert.Equal(t, "SignatureDoesNotMatch", apiCodeOf(proxyErr),
				"DEVIATION: the proxy answers SignatureDoesNotMatch to a correctly signed request")
		})
	}
}

// ----------------------------------------------------------------------------
// 4. The s3ep-* namespace never reaches the client
// ----------------------------------------------------------------------------

// hdrGenuineEncryptionKeys are the metadata keys the proxy itself writes, without
// the configurable prefix.
var hdrGenuineEncryptionKeys = []string{
	"dek-algorithm", "encrypted-dek", "aes-iv", "kek-algorithm", "kek-fingerprint", "hmac",
}

// No encryption metadata may be observable by a client, on GET, on HEAD or in a
// listing. The counter-check matters as much: the backend must actually hold
// that metadata, otherwise this test would pass on an unencrypted object.
func TestHdrEncryptionMetadataIsNeverVisibleToTheClient(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := []byte("the s3ep namespace is the proxy's own")
	key := "metadata-filter-" + integration.RandomString(10)

	// Two decoys that only LOOK like the reserved prefix, one lower case and one
	// upper case: S3 metadata keys are case-insensitive, so a case variant that
	// slipped through the filter would be a genuine leak.
	metadata := map[string]string{
		"harmless":     "user-value",
		"s3ep-notreal": "user-owned",
		"S3EP-Upper":   "user-upper",
	}
	_, err := HdrPutWithEntityHeaders(ctx, tc.ProxyClient, tc.TestBucket, key, payload, metadata)
	require.NoError(t, err, "PUT through the proxy")

	proxyGet, digest, _ := HdrGetHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	proxyHead := HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	require.Equal(t, sha256.Sum256(payload), digest, "the object did not read back intact")

	backend, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err, "HEAD directly against the backend")

	t.Run("the_backend_really_holds_encryption_metadata", func(t *testing.T) {
		lowered := make(map[string]string, len(backend.Metadata))
		for k, v := range backend.Metadata {
			lowered[strings.ToLower(k)] = v
		}
		require.Contains(t, lowered, "s3ep-encrypted-dek",
			"the stored object carries no encrypted DEK: the leak check below would be vacuous")
		require.Contains(t, lowered, "s3ep-kek-fingerprint")
	})

	t.Run("no_s3ep_key_is_visible_on_get_or_head", func(t *testing.T) {
		for _, headers := range []struct {
			what string
			h    http.Header
		}{{"GET", proxyGet}, {"HEAD", proxyHead}} {
			for _, name := range HdrObjectHeaderNames(headers.h) {
				assert.Falsef(t, strings.HasPrefix(name, "x-amz-meta-s3ep-"),
					"%s leaks the reserved metadata namespace: %s", headers.what, name)
			}
			for _, genuine := range hdrGenuineEncryptionKeys {
				assert.Emptyf(t, headers.h.Get("x-amz-meta-s3ep-"+genuine),
					"%s leaks the encryption metadata key %q", headers.what, genuine)
			}
			assert.Equalf(t, "user-value", headers.h.Get("x-amz-meta-harmless"),
				"%s: ordinary user metadata must survive the filter", headers.what)
		}
	})

	t.Run("no_s3ep_key_is_visible_in_a_listing", func(t *testing.T) {
		var document []byte
		listing, err := tc.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(tc.TestBucket), Prefix: aws.String(key),
		}, HdrCaptureResponseBody(&document))
		require.NoError(t, err)
		require.Len(t, listing.Contents, 1, "the object should be listed exactly once")
		assert.NotContains(t, strings.ToLower(string(document)), "s3ep-",
			"the listing document mentions the reserved metadata namespace")
	})

	// The reserved namespace is not client-writable: a key that merely starts
	// with the prefix is dropped at PUT, in either spelling, and never reaches
	// the backend. It used to be stored, because the PUT-side filter compared
	// the prefix case-sensitively against a key Go had already canonicalised to
	// "S3ep-Notreal" - which is what let a client-supplied
	// x-amz-meta-s3ep-encrypted-dek overwrite the real one.
	//
	// One deviation remains, deliberately: the key is dropped silently rather
	// than refused. AWS returns x-amz-meta-s3ep-notreal unchanged, and the
	// honest answer is InvalidArgument at PUT, which is ADR 0009 and ships with
	// the next major.
	t.Run("user_metadata_that_looks_like_the_prefix_is_swallowed", func(t *testing.T) {
		assert.Empty(t, proxyGet.Get("x-amz-meta-s3ep-notreal"),
			"DEVIATION: the proxy hides a user's own s3ep-prefixed metadata instead of refusing it at PUT")
		assert.Empty(t, proxyGet.Get("x-amz-meta-s3ep-upper"),
			"DEVIATION: same for the upper-case variant")
		assert.Empty(t, proxyHead.Get("x-amz-meta-s3ep-notreal"))
		assert.Empty(t, proxyHead.Get("x-amz-meta-s3ep-upper"))

		lowered := make(map[string]string, len(backend.Metadata))
		for k, v := range backend.Metadata {
			lowered[strings.ToLower(k)] = v
		}
		assert.NotContains(t, lowered, "s3ep-notreal",
			"the reserved namespace must not be writable by a client")
		assert.NotContains(t, lowered, "s3ep-upper",
			"the upper-case spelling canonicalises to the same key and must be dropped too")
	})
}

// ----------------------------------------------------------------------------
// 5. ETag
// ----------------------------------------------------------------------------

// A client caches an ETag and replays it in If-Match/If-None-Match, so it has to
// be present, quoted, and the same on every read until the object changes.
func TestHdrETagIsPresentAndStableAcrossRepeatedHeads(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)

	payload := []byte("etag stability")
	key := "etag-" + integration.RandomString(10)

	proxyPut, err := HdrPutWithEntityHeaders(ctx, tc.ProxyClient, tc.TestBucket, key, payload, HdrUserMetadata())
	require.NoError(t, err)
	minioPut, err := HdrPutWithEntityHeaders(ctx, tc.MinIOClient, directBucket, key, payload, HdrUserMetadata())
	require.NoError(t, err)

	require.NotEmpty(t, aws.ToString(proxyPut.ETag), "PUT returned no ETag")
	assert.True(t, strings.HasPrefix(aws.ToString(proxyPut.ETag), `"`),
		"the ETag must be a quoted string, as the backend's is: %q", aws.ToString(minioPut.ETag))

	first := HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key).Get("ETag")
	require.NotEmpty(t, first, "HEAD returned no ETag")
	for i := 0; i < 3; i++ {
		assert.Equalf(t, first, HdrHeadHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key).Get("ETag"),
			"the ETag changed between HEADs (repeat %d)", i+1)
	}

	getHeaders, _, _ := HdrGetHeaders(t, ctx, tc.ProxyClient, tc.TestBucket, key)
	assert.Equal(t, first, getHeaders.Get("ETag"), "GET and HEAD report different ETags")
	assert.Equal(t, aws.ToString(proxyPut.ETag), first, "PUT returned an ETag that HEAD does not confirm")

	// The proxy's ETag is the digest of the stored ciphertext, so it does not
	// match the backend's digest of the same plaintext. That is the product
	// working; it is recorded here because a client that verifies an upload by
	// comparing the ETag against its own MD5 will not succeed through the proxy.
	assert.NotEqual(t, aws.ToString(minioPut.ETag), aws.ToString(proxyPut.ETag),
		"the proxy's ETag equals the plaintext digest: is the object stored unencrypted?")
}

// ----------------------------------------------------------------------------
// 6. The storage headers a PUT forwards (ADR 0007 D3), and the three it refuses
// ----------------------------------------------------------------------------

// Every storage-control header reaches the backend and takes effect there. This
// test used to assert the opposite, header by header: accepted, dropped,
// answered 200. The oracle is the same in both directions - the same request is
// sent straight to MinIO and the two outcomes are compared.
func TestHdrStorageHeadersReachTheBackend(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := []byte("storage headers reach the backend")

	t.Run("x_amz_server_side_encryption", func(t *testing.T) {
		// This MinIO has no KMS, so it may refuse SSE outright. Forwarding means
		// the proxy gives the client the backend's own answer either way, which
		// is what this compares - not a fixed expectation about MinIO.
		directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)
		directKey := "sse-direct-" + integration.RandomString(10)
		_, directErr := tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(directBucket), Key: aws.String(directKey),
			Body:                 bytes.NewReader(payload),
			ContentLength:        aws.Int64(int64(len(payload))),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
		})

		proxyKey := "sse-proxy-" + integration.RandomString(10)
		_, proxyErr := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(proxyKey),
			Body:                 bytes.NewReader(payload),
			ContentLength:        aws.Int64(int64(len(payload))),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
		})

		if directErr != nil {
			require.Error(t, proxyErr,
				"the backend refuses this request; forwarding means the client is told so")
			assert.Equal(t, apiCodeOf(directErr), apiCodeOf(proxyErr))
			return
		}

		require.NoError(t, proxyErr)
		backend, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(proxyKey),
		})
		require.NoError(t, err)
		assert.Equal(t, types.ServerSideEncryptionAes256, backend.ServerSideEncryption,
			"the SSE mode the client asked for is the one the backend recorded")
	})

	t.Run("x_amz_storage_class", func(t *testing.T) {
		key := "storage-class-" + integration.RandomString(10)
		_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			StorageClass:  types.StorageClassReducedRedundancy,
		})
		require.NoError(t, err)

		listing, err := tc.MinIOClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(tc.TestBucket), Prefix: aws.String(key),
		})
		require.NoError(t, err)
		require.Len(t, listing.Contents, 1)
		assert.Equal(t, types.ObjectStorageClassReducedRedundancy, listing.Contents[0].StorageClass,
			"the requested storage class reached the backend")
	})

	t.Run("x_amz_tagging", func(t *testing.T) {
		key := "tagging-" + integration.RandomString(10)
		_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			Tagging:       aws.String("project=conformance&stage=test"),
		})
		require.NoError(t, err)

		tags, err := tc.MinIOClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err)
		assert.Len(t, tags.TagSet, 2,
			"the tags reached the backend - in the clear, on a ciphertext object (ADR 0007 D12)")
	})

	t.Run("x_amz_acl", func(t *testing.T) {
		// This MinIO answers GetObjectAcl with a fixed owner-only policy whatever
		// was asked for, so the oracle is agreement with the direct request
		// rather than the grant itself.
		directBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, false)
		directKey := "acl-direct-" + integration.RandomString(10)
		_, err := tc.MinIOClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(directBucket), Key: aws.String(directKey),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			ACL:           types.ObjectCannedACLPublicRead,
		})
		require.NoError(t, err)

		proxyKey := "acl-proxy-" + integration.RandomString(10)
		_, err = tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(proxyKey),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			ACL:           types.ObjectCannedACLPublicRead,
		})
		require.NoError(t, err, "a canned ACL is carried to the backend, not refused")

		directACL, err := tc.MinIOClient.GetObjectAcl(ctx, &s3.GetObjectAclInput{
			Bucket: aws.String(directBucket), Key: aws.String(directKey),
		})
		require.NoError(t, err)
		proxyACL, err := tc.MinIOClient.GetObjectAcl(ctx, &s3.GetObjectAclInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(proxyKey),
		})
		require.NoError(t, err)
		assert.Len(t, proxyACL.Grants, len(directACL.Grants),
			"the object written through the proxy carries the ACL the direct one does")
	})

	t.Run("x_amz_website_redirect_location", func(t *testing.T) {
		key := "redirect-" + integration.RandomString(10)
		_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			Body:                    bytes.NewReader(payload),
			ContentLength:           aws.Int64(int64(len(payload))),
			WebsiteRedirectLocation: aws.String("/somewhere-else"),
		})
		require.NoError(t, err)

		backend, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.NoError(t, err)
		assert.Equal(t, "/somewhere-else", aws.ToString(backend.WebsiteRedirectLocation))
	})

	t.Run("object_lock_headers", func(t *testing.T) {
		lockBucket := HdrNewDirectBucket(t, ctx, tc.MinIOClient, true)
		retain := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)

		lockInput := func(key string) *s3.PutObjectInput {
			return &s3.PutObjectInput{
				Bucket: aws.String(lockBucket), Key: aws.String(key),
				Body:                      bytes.NewReader(payload),
				ContentLength:             aws.Int64(int64(len(payload))),
				ObjectLockMode:            types.ObjectLockModeGovernance,
				ObjectLockRetainUntilDate: aws.Time(retain),
				ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatusOn,
			}
		}

		// The backend honours the identical request.
		directKey := "lock-direct-" + integration.RandomString(10)
		_, err := tc.MinIOClient.PutObject(ctx, lockInput(directKey))
		require.NoError(t, err)
		direct, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(lockBucket), Key: aws.String(directKey),
		})
		require.NoError(t, err)
		require.Equal(t, types.ObjectLockModeGovernance, direct.ObjectLockMode,
			"the backend was expected to apply the lock; without that there is no oracle here")
		require.Equal(t, types.ObjectLockLegalHoldStatusOn, direct.ObjectLockLegalHoldStatus)

		// And so does an object written through the proxy. WORM on the ciphertext
		// defends against a compromised credential, not against the backend
		// itself (ADR 0007 D12).
		proxyKey := "lock-proxy-" + integration.RandomString(10)
		_, err = tc.ProxyClient.PutObject(ctx, lockInput(proxyKey))
		require.NoError(t, err)

		locked, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(lockBucket), Key: aws.String(proxyKey),
		})
		require.NoError(t, err)
		assert.Equal(t, types.ObjectLockModeGovernance, locked.ObjectLockMode)
		require.NotNil(t, locked.ObjectLockRetainUntilDate)
		assert.Equal(t, retain, locked.ObjectLockRetainUntilDate.UTC().Truncate(time.Second))
		assert.Equal(t, types.ObjectLockLegalHoldStatusOn, locked.ObjectLockLegalHoldStatus)

		// HdrCleanupBucket releases the hold and bypasses the retention on the
		// way out, so both objects are removable.
	})

	t.Run("sse_c_headers_are_refused", func(t *testing.T) {
		// The SDK will not send a customer key without computing its MD5, so the
		// three headers go over a raw request. No read path carries the key, so
		// accepting one on upload would write an object nobody could read back
		// (ADR 0007 D6).
		for _, header := range []string{
			"x-amz-server-side-encryption-customer-algorithm",
			"x-amz-server-side-encryption-customer-key",
			"x-amz-server-side-encryption-customer-key-MD5",
		} {
			key := "ssec-" + integration.RandomString(10)
			status, body := hdrSignedPut(t, "/"+tc.TestBucket+"/"+key, payload,
				map[string]string{header: "AES256"})
			assert.Equal(t, http.StatusNotImplemented, status, "refused: %s", header)
			assert.Contains(t, string(body), "NotImplemented")
			assert.Contains(t, strings.ToLower(string(body)), strings.ToLower(header),
				"the refusal names the header so the client learns what to remove")

			_, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			})
			assert.Error(t, err, "a refused upload stores nothing")
		}
	})
}

// hdrSignedPut issues a signed PUT without the SDK, so a header the SDK refuses
// to send on its own can still be put on the wire.
func hdrSignedPut(t *testing.T, path string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()

	sum := sha256.Sum256(body)
	req, err := http.NewRequest(http.MethodPut, integration.ProxyEndpoint+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.ContentLength = int64(len(body))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	require.NoError(t, integration.SignHTTPRequestForS3WithCredentials(req, hex.EncodeToString(sum[:])))

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	answer, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, answer
}
