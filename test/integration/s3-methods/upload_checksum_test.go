//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/md5"  // #nosec G501 - Content-MD5 is the digest S3 defines for an upload
	"crypto/sha1" // #nosec G505 - x-amz-checksum-sha1 is a client-declared transmission check
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Client upload checksums, end to end (ADR 0012). Every request here is built
// and signed by hand: aws-sdk-go-v2 will not put a deliberately wrong trailer
// on the wire, and it only emits the trailer framing at all over TLS, so the
// framing this suite has to cover cannot be produced through the SDK.
//
// MinIO is the comparison baseline, not the oracle. ADR 0012 promises the
// proxy's own BadDigest and InvalidDigest; it does not promise to match a
// backend's code for every algorithm, so what MinIO answers is recorded rather
// than asserted, except for Content-MD5 where both are expected to agree.

// ckAlgorithms is how a client computes each declared value.
var ckAlgorithms = map[string]struct {
	header  string
	trailer string // empty for Content-MD5, which is never a trailer
	digest  func([]byte) []byte
}{
	"crc32": {
		header: "x-amz-checksum-crc32", trailer: "x-amz-checksum-crc32",
		digest: func(b []byte) []byte { return ckBE32(crc32.ChecksumIEEE(b)) },
	},
	"crc32c": {
		header: "x-amz-checksum-crc32c", trailer: "x-amz-checksum-crc32c",
		digest: func(b []byte) []byte {
			return ckBE32(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
		},
	},
	"crc64nvme": {
		header: "x-amz-checksum-crc64nvme", trailer: "x-amz-checksum-crc64nvme",
		digest: func(b []byte) []byte {
			h := crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5))
			_, _ = h.Write(b)
			return h.Sum(nil)
		},
	},
	"sha1": {
		header: "x-amz-checksum-sha1", trailer: "x-amz-checksum-sha1",
		digest: func(b []byte) []byte { s := sha1.Sum(b); return s[:] }, // #nosec G401
	},
	"sha256": {
		header: "x-amz-checksum-sha256", trailer: "x-amz-checksum-sha256",
		digest: func(b []byte) []byte { s := sha256.Sum256(b); return s[:] },
	},
	"md5": {
		header: "Content-MD5",
		digest: func(b []byte) []byte { s := md5.Sum(b); return s[:] }, // #nosec G401
	},
}

func ckBE32(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func ckEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// ckPayload is deterministic so a failure names a size rather than a seed.
func ckPayload(n int) []byte {
	out := make([]byte, n)
	state := uint32(0x2545f491)
	for i := range out {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		out[i] = byte(state)
	}
	return out
}

// ckAnswer is the whole client-visible result of one hand-built request.
type ckAnswer struct {
	status int
	code   string
}

func (a ckAnswer) String() string { return fmt.Sprintf("status=%d code=%q", a.status, a.code) }

func ckSend(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey string,
	method, path string, body []byte, headers map[string]string, payloadHash string,
) ckAnswer {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(body))
	require.NoError(t, err)
	req.ContentLength = int64(len(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	require.NoError(t, integration.SignHTTPRequestForS3(
		req, accessKey, secretKey, integration.TestRegion, payloadHash))

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	answer := ckAnswer{status: resp.StatusCode}
	if resp.StatusCode >= 300 {
		var doc struct {
			XMLName xml.Name `xml:"Error"`
			Code    string   `xml:"Code"`
		}
		if xml.Unmarshal(raw, &doc) == nil {
			answer.code = doc.Code
		}
	}
	return answer
}

// ---------------------------------------------------------------------------
// Header-declared digests on a plain PUT: the kopia-shaped case.
// ---------------------------------------------------------------------------

// A wrong Content-MD5 on an identity-framed PUT is 400 BadDigest and nothing is
// stored. This is the shape one widely used backup uploader sends on every blob
// it writes, and the defect ADR 0012 was opened for: it used to answer 200.
func TestCkPlainPutWithAWrongContentMD5IsRefused(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	payload := ckPayload(64 * 1024)
	key := "ck-md5-" + integration.RandomString(6)
	wrong := ckEncode(ckAlgorithms["md5"].digest([]byte("not the payload")))

	proxy := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPut, "/"+tc.TestBucket+"/"+key, payload,
		map[string]string{"Content-MD5": wrong}, ckPayloadSHA(payload))

	assert.Equal(t, http.StatusBadRequest, proxy.status, "proxy: %s", proxy)
	assert.Equal(t, "BadDigest", proxy.code)

	// Nothing was stored: the object must not exist afterwards.
	_, err := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.Error(t, err, "a refused upload must leave no object behind")

	// The backend answers the same request directly; this is the one algorithm
	// where the proxy and MinIO are expected to agree.
	direct := ckSend(t, tc.Ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		http.MethodPut, "/"+tc.TestBucket+"/"+key+"-direct", payload,
		map[string]string{"Content-MD5": wrong}, ckPayloadSHA(payload))
	assert.Equal(t, http.StatusBadRequest, direct.status, "MinIO: %s", direct)
	t.Logf("MinIO answers a wrong Content-MD5 with %s", direct)
}

func ckPayloadSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// Every algorithm, declared as a request header on a plain PUT: correct passes
// and the object reads back byte for byte, wrong is BadDigest, and a value that
// is not a digest is InvalidDigest.
func TestCkPlainPutHeaderDigests(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	payload := ckPayload(128 * 1024)
	want := sha256.Sum256(payload)

	for name, alg := range ckAlgorithms {
		t.Run(name, func(t *testing.T) {
			cases := map[string]struct {
				value  string
				status int
				code   string
			}{
				"correct":   {value: ckEncode(alg.digest(payload)), status: http.StatusOK},
				"wrong":     {value: ckEncode(alg.digest([]byte("x"))), status: http.StatusBadRequest, code: "BadDigest"},
				"malformed": {value: "not-base64!!", status: http.StatusBadRequest, code: "InvalidDigest"},
			}

			for caseName, tc2 := range cases {
				t.Run(caseName, func(t *testing.T) {
					key := fmt.Sprintf("ck-hdr-%s-%s-%s", name, caseName, integration.RandomString(6))

					got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
						integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
						http.MethodPut, "/"+tc.TestBucket+"/"+key, payload,
						map[string]string{alg.header: tc2.value}, ckPayloadSHA(payload))

					require.Equal(t, tc2.status, got.status, "%s", got)
					if tc2.code != "" {
						assert.Equal(t, tc2.code, got.code)
						_, err := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
							Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
						})
						require.Error(t, err, "a refused upload must leave no object behind")
						return
					}

					out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
						Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
					})
					require.NoError(t, err)
					defer func() { _ = out.Body.Close() }()
					read, err := io.ReadAll(out.Body)
					require.NoError(t, err)
					assert.Equal(t, want, sha256.Sum256(read), "the object must read back unchanged")
				})
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Trailer-declared digests, on both PUT routes.
// ---------------------------------------------------------------------------

// ckFramed builds an unsigned aws-chunked body with one trailer, the framing
// aws-sdk-go-v2 emits over TLS by default.
func ckFramed(payload []byte, chunkSize int, trailerName, trailerValue string) []byte {
	var buf bytes.Buffer
	if chunkSize <= 0 || chunkSize > len(payload) {
		chunkSize = len(payload)
	}
	for off := 0; off < len(payload); off += chunkSize {
		end := off + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		fmt.Fprintf(&buf, "%x\r\n", end-off)
		buf.Write(payload[off:end])
		buf.WriteString("\r\n")
	}
	buf.WriteString("0\r\n")
	if trailerName != "" {
		fmt.Fprintf(&buf, "%s:%s\r\n", trailerName, trailerValue)
	}
	buf.WriteString("\r\n")
	return buf.Bytes()
}

func ckChunkedHeaders(payloadLen int, trailerName string) map[string]string {
	h := map[string]string{
		"Content-Encoding":             "aws-chunked",
		"X-Amz-Content-Sha256":         "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
		"X-Amz-Decoded-Content-Length": strconv.Itoa(payloadLen),
		"Content-Type":                 "application/octet-stream",
	}
	if trailerName != "" {
		h["X-Amz-Trailer"] = trailerName
	}
	return h
}

// The two sizes select the two PUT routes: below optimizations.streaming_segment_size
// takes the single-request write, above it takes the internal multipart producer.
// The proxy's client-visible answer must be the same on both.
func TestCkChunkedTrailerOnBothPutRoutes(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	sizes := map[string]int{
		"single_request": 256 * 1024,
		"auto_multipart": 13 * 1024 * 1024,
	}

	for _, algName := range []string{"crc32", "crc32c", "crc64nvme"} {
		alg := ckAlgorithms[algName]
		for routeName, size := range sizes {
			payload := ckPayload(size)
			want := sha256.Sum256(payload)
			correct := ckEncode(alg.digest(payload))

			t.Run(algName+"/"+routeName+"/correct", func(t *testing.T) {
				key := fmt.Sprintf("ck-tr-%s-%s-%s", algName, routeName, integration.RandomString(6))
				framed := ckFramed(payload, 64*1024, alg.trailer, correct)

				got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
					integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
					http.MethodPut, "/"+tc.TestBucket+"/"+key, framed,
					ckChunkedHeaders(len(payload), alg.trailer),
					"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

				require.Equal(t, http.StatusOK, got.status, "%s", got)

				out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
				require.NoError(t, err)
				defer func() { _ = out.Body.Close() }()
				read, err := io.ReadAll(out.Body)
				require.NoError(t, err)
				assert.Equal(t, want, sha256.Sum256(read))
			})

			t.Run(algName+"/"+routeName+"/wrong", func(t *testing.T) {
				key := fmt.Sprintf("ck-trw-%s-%s-%s", algName, routeName, integration.RandomString(6))
				framed := ckFramed(payload, 64*1024, alg.trailer,
					ckEncode(alg.digest([]byte("not the payload"))))

				got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
					integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
					http.MethodPut, "/"+tc.TestBucket+"/"+key, framed,
					ckChunkedHeaders(len(payload), alg.trailer),
					"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

				require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
				assert.Equal(t, "BadDigest", got.code)

				_, err := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
				require.Error(t, err, "a refused upload must leave no object behind")

				// And no multipart upload is left for a client to discover and
				// clean up (ADR 0012 D7). Asked of MinIO directly: the proxy
				// answers ListMultipartUploads NotImplemented.
				uploads, lerr := tc.MinIOClient.ListMultipartUploads(tc.Ctx,
					&s3.ListMultipartUploadsInput{Bucket: aws.String(tc.TestBucket)})
				require.NoError(t, lerr)
				for _, u := range uploads.Uploads {
					assert.NotEqual(t, key, aws.ToString(u.Key),
						"an aborted upload must not stay behind")
				}
			})
		}
	}
}

// A trailer named in X-Amz-Trailer that never arrives is a failed verification,
// not an absent one (ADR 0012 D5): otherwise omitting it is a free opt-out from
// the check the client asked for.
func TestCkDeclaredTrailerThatNeverArrivesIsRefused(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	payload := ckPayload(32 * 1024)
	key := "ck-absent-" + integration.RandomString(6)
	framed := ckFramed(payload, 8*1024, "", "")

	got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPut, "/"+tc.TestBucket+"/"+key, framed,
		ckChunkedHeaders(len(payload), "x-amz-checksum-crc32"),
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

	require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
	assert.Equal(t, "BadDigest", got.code)
}

// The third way into the multipart producer: no X-Amz-Decoded-Content-Length, so
// the plaintext length is unknown and the route is chosen on that alone.
func TestCkChunkedWithoutADeclaredLength(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	payload := ckPayload(256 * 1024)
	alg := ckAlgorithms["crc32"]

	for name, value := range map[string]string{
		"correct": ckEncode(alg.digest(payload)),
		"wrong":   ckEncode(alg.digest([]byte("other"))),
	} {
		t.Run(name, func(t *testing.T) {
			key := "ck-nolen-" + name + "-" + integration.RandomString(6)
			framed := ckFramed(payload, 64*1024, alg.trailer, value)

			headers := ckChunkedHeaders(len(payload), alg.trailer)
			delete(headers, "X-Amz-Decoded-Content-Length")

			got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
				integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
				http.MethodPut, "/"+tc.TestBucket+"/"+key, framed, headers,
				"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

			if name == "correct" {
				require.Equal(t, http.StatusOK, got.status, "%s", got)
				out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
				require.NoError(t, err)
				defer func() { _ = out.Body.Close() }()
				read, err := io.ReadAll(out.Body)
				require.NoError(t, err)
				assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(read))
				return
			}
			require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
			assert.Equal(t, "BadDigest", got.code)
		})
	}
}

// An aws-chunked PUT without X-Amz-Decoded-Content-Length, carrying no checksum
// at all: the routing must not mistake the wire length for the plaintext length.
// It used to, and an upload whose framed size fitted one part was answered
// 500 InternalError because the backend was promised ciphertext the body could
// not fill.
func TestCkChunkedWithoutADeclaredLengthAndNoChecksum(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	payload := ckPayload(256 * 1024)
	key := "ck-nolen-plain-" + integration.RandomString(6)
	framed := ckFramed(payload, 64*1024, "", "")

	headers := ckChunkedHeaders(len(payload), "")
	delete(headers, "X-Amz-Decoded-Content-Length")

	got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPut, "/"+tc.TestBucket+"/"+key, framed, headers,
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

	require.Equal(t, http.StatusOK, got.status, "%s", got)

	out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer func() { _ = out.Body.Close() }()
	read, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(read))
}

// ---------------------------------------------------------------------------
// Client-driven multipart.
// ---------------------------------------------------------------------------

// A part whose declared digest does not match is refused on that part alone, and
// the upload survives it: the client can still abort cleanly.
func TestCkUploadPartWithAWrongDigest(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	key := "ck-mpu-" + integration.RandomString(6)
	create, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	part := ckPayload(6 * 1024 * 1024)
	alg := ckAlgorithms["crc32"]

	got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPut,
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", tc.TestBucket, key, uploadID),
		part, map[string]string{alg.header: ckEncode(alg.digest([]byte("wrong")))},
		ckPayloadSHA(part))

	require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
	assert.Equal(t, "BadDigest", got.code)

	// The upload is still there and aborts cleanly.
	_, err = tc.ProxyClient.AbortMultipartUpload(tc.Ctx, &s3.AbortMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
	})
	require.NoError(t, err, "a refused part must not take the upload down with it")
}

// ---------------------------------------------------------------------------
// The multi-object delete: a digest is mandatory (ADR 0012 D14).
// ---------------------------------------------------------------------------

func TestCkDeleteObjectsRequiresADigest(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	key := "ck-del-" + integration.RandomString(6)
	_, err := tc.ProxyClient.PutObject(tc.Ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Body: bytes.NewReader(ckPayload(1024)),
	})
	require.NoError(t, err)

	doc := []byte("<Delete><Object><Key>" + key + "</Key></Object></Delete>")
	correct := ckEncode(ckAlgorithms["md5"].digest(doc))

	for name, tc2 := range map[string]struct {
		headers map[string]string
		status  int
		code    string
	}{
		"no_digest": {headers: nil, status: http.StatusBadRequest, code: "InvalidRequest"},
		"wrong_digest": {
			headers: map[string]string{"Content-MD5": ckEncode(ckAlgorithms["md5"].digest([]byte("x")))},
			status:  http.StatusBadRequest, code: "BadDigest",
		},
		"malformed_digest": {
			headers: map[string]string{"Content-MD5": "deadbeefdeadbeefdeadbeef"},
			status:  http.StatusBadRequest, code: "InvalidDigest",
		},
		"correct_digest": {
			headers: map[string]string{"Content-MD5": correct},
			status:  http.StatusOK,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
				integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
				http.MethodPost, "/"+tc.TestBucket+"?delete", doc, tc2.headers,
				ckPayloadSHA(doc))

			require.Equal(t, tc2.status, got.status, "%s", got)
			if tc2.code != "" {
				assert.Equal(t, tc2.code, got.code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// An aws-chunked body on the paths that used to read r.Body raw (P-5).
// ---------------------------------------------------------------------------

// A multi-object delete framed as aws-chunked must have its framing stripped
// before the document is parsed, and its trailer verified.
func TestCkDeleteObjectsOverAWSChunked(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	key := "ck-delchunk-" + integration.RandomString(6)
	_, err := tc.ProxyClient.PutObject(tc.Ctx, &s3.PutObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		Body: bytes.NewReader(ckPayload(1024)),
	})
	require.NoError(t, err)

	doc := []byte("<Delete><Object><Key>" + key + "</Key></Object></Delete>")
	alg := ckAlgorithms["crc32"]

	t.Run("correct_trailer_deletes", func(t *testing.T) {
		framed := ckFramed(doc, 0, alg.trailer, ckEncode(alg.digest(doc)))
		got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
			integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
			http.MethodPost, "/"+tc.TestBucket+"?delete", framed,
			ckChunkedHeaders(len(doc), alg.trailer),
			"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

		require.Equal(t, http.StatusOK, got.status, "%s", got)
		_, herr := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
		require.Error(t, herr, "the document was parsed, so the key is gone")
	})

	t.Run("wrong_trailer_deletes_nothing", func(t *testing.T) {
		survivor := "ck-survivor-" + integration.RandomString(6)
		_, perr := tc.ProxyClient.PutObject(tc.Ctx, &s3.PutObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(survivor),
			Body: bytes.NewReader(ckPayload(1024)),
		})
		require.NoError(t, perr)

		body := []byte("<Delete><Object><Key>" + survivor + "</Key></Object></Delete>")
		framed := ckFramed(body, 0, alg.trailer, ckEncode(alg.digest([]byte("x"))))
		got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
			integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
			http.MethodPost, "/"+tc.TestBucket+"?delete", framed,
			ckChunkedHeaders(len(body), alg.trailer),
			"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

		require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
		assert.Equal(t, "BadDigest", got.code)

		_, herr := tc.ProxyClient.HeadObject(tc.Ctx, &s3.HeadObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(survivor),
		})
		require.NoError(t, herr, "a refused delete document must delete nothing")
	})
}

// CompleteMultipartUpload over aws-chunked (P-5 b), and the escaped-markup case
// that html.UnescapeString used to turn into real document structure.
func TestCkCompleteMultipartOverAWSChunked(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	key := "ck-complete-" + integration.RandomString(6)
	create, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	payload := ckPayload(6 * 1024 * 1024)
	part, err := tc.ProxyClient.UploadPart(tc.Ctx, &s3.UploadPartInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		UploadId: aws.String(uploadID), PartNumber: aws.Int32(1),
		Body: bytes.NewReader(payload),
	})
	require.NoError(t, err)

	doc := []byte(fmt.Sprintf(
		"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>",
		aws.ToString(part.ETag)))
	alg := ckAlgorithms["crc32"]
	framed := ckFramed(doc, 0, alg.trailer, ckEncode(alg.digest(doc)))

	got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPost, fmt.Sprintf("/%s/%s?uploadId=%s", tc.TestBucket, key, uploadID),
		framed, ckChunkedHeaders(len(doc), alg.trailer),
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER")

	require.Equal(t, http.StatusOK, got.status, "%s", got)

	out, err := tc.ProxyClient.GetObject(tc.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	defer func() { _ = out.Body.Close() }()
	read, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(read))
}

// An escaped &lt;Part&gt; inside an ETag must stay text. Pre-decoding the body
// with html.UnescapeString turned attacker-escaped text into document structure
// before the XML parser saw it.
func TestCkCompleteMultipartDoesNotUnescapeIntoMarkup(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	tc := integration.NewTestContext(t)
	defer tc.CleanupTestBucket()

	key := "ck-escape-" + integration.RandomString(6)
	create, err := tc.ProxyClient.CreateMultipartUpload(tc.Ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)
	defer func() {
		_, _ = tc.ProxyClient.AbortMultipartUpload(tc.Ctx, &s3.AbortMultipartUploadInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key), UploadId: aws.String(uploadID),
		})
	}()

	doc := []byte("<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>" +
		"<ETag>&amp;lt;Part&amp;gt;&amp;lt;PartNumber&amp;gt;2&amp;lt;/PartNumber&amp;gt;</ETag>" +
		"</Part></CompleteMultipartUpload>")

	got := ckSend(t, tc.Ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		http.MethodPost, fmt.Sprintf("/%s/%s?uploadId=%s", tc.TestBucket, key, uploadID),
		doc, nil, ckPayloadSHA(doc))

	// The document parses, the ETag stays text and matches no part the proxy
	// holds, so the completion is refused as a client mistake rather than
	// producing a second part out of escaped characters.
	require.Equal(t, http.StatusBadRequest, got.status, "%s", got)
	assert.Contains(t, []string{"InvalidPart", "MalformedXML"}, got.code, "%s", got)
}
