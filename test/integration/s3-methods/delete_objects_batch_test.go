//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

// ---------------------------------------------------------------------------
// POST /{bucket}?delete - the batch delete XML API.
//
// Every case is run twice against the same MinIO: once through the proxy into
// the proxy's bucket, once directly into a second bucket this file creates in
// MinIO. MinIO is the oracle - anywhere the two documents disagree outside the
// allowed list (filtered s3ep-* metadata, ciphertext sizes, deliberate 501s)
// the proxy is wrong. Where BOTH deviate from documented AWS behaviour the test
// says so in a comment and asserts the behaviour that actually exists, so the
// suite stays green while the deviation stays visible.
//
// Single-key DELETE lives in delete_object_test.go; nothing here duplicates it.
// ---------------------------------------------------------------------------

// DelDeletedEntry is one <Deleted> child of a DeleteResult.
type DelDeletedEntry struct {
	Key                   string `xml:"Key"`
	VersionID             string `xml:"VersionId"`
	DeleteMarker          bool   `xml:"DeleteMarker"`
	DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId"`
}

// DelErrorEntry is one <Error> child of a DeleteResult.
type DelErrorEntry struct {
	Key       string `xml:"Key"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	VersionID string `xml:"VersionId"`
}

// DelResultDoc is the AWS DeleteResult document, parsed the way a client parses
// it rather than compared as a string.
type DelResultDoc struct {
	XMLName xml.Name          `xml:"DeleteResult"`
	Deleted []DelDeletedEntry `xml:"Deleted"`
	Errors  []DelErrorEntry   `xml:"Error"`
}

// DelErrorDoc is the S3 REST error document.
type DelErrorDoc struct {
	XMLName xml.Name `xml:"Error"`
	Code    string   `xml:"Code"`
	Message string   `xml:"Message"`
}

// DelResponse is the raw HTTP answer to a batch delete, kept whole so the test
// can assert on status, headers and document shape together.
type DelResponse struct {
	Status      int
	ContentType string
	Header      http.Header
	Body        []byte
}

// DelRequestObject / DelRequestDoc build the request document through
// encoding/xml so that keys are escaped exactly the way a real client escapes
// them - that is the point of the escaping case.
type DelRequestObject struct {
	Key string `xml:"Key"`
}

type DelRequestDoc struct {
	XMLName xml.Name           `xml:"Delete"`
	Objects []DelRequestObject `xml:"Object"`
	Quiet   bool               `xml:"Quiet"`
}

// DelBuildDoc renders a well-formed Delete document for the given keys.
func DelBuildDoc(t *testing.T, quiet bool, keys []string) string {
	t.Helper()
	doc := DelRequestDoc{Quiet: quiet}
	for _, k := range keys {
		doc.Objects = append(doc.Objects, DelRequestObject{Key: k})
	}
	out, err := xml.Marshal(doc)
	require.NoError(t, err, "building the Delete document must not fail")
	return xml.Header + string(out)
}

// DelPostDelete signs and sends POST /{bucket}?delete with an arbitrary body,
// including the Content-MD5 that AWS requires for this operation. Raw HTTP
// rather than the SDK, because several cases are about documents the SDK would
// never produce (empty, truncated, over the key limit).
func DelPostDelete(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket, body string) DelResponse {
	t.Helper()
	return DelPostDeleteRaw(t, ctx, endpoint, accessKey, secretKey, bucket, body, DelAutoMD5)
}

// DelAutoMD5 tells DelPostDeleteRaw to compute the correct Content-MD5. An
// empty string omits the header entirely; any other value is sent verbatim.
const DelAutoMD5 = "auto"

// DelPostDeleteRaw is DelPostDelete with control over the integrity header AWS
// requires for DeleteObjects.
func DelPostDeleteRaw(t *testing.T, ctx context.Context, endpoint, accessKey, secretKey, bucket, body, contentMD5 string) DelResponse {
	t.Helper()

	url := strings.TrimSuffix(endpoint, "/") + "/" + bucket + "?delete="
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err, "building the request must not fail")
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/xml")

	switch contentMD5 {
	case "":
		// header deliberately omitted
	case DelAutoMD5:
		md5sum := md5.Sum([]byte(body)) // #nosec G401 - Content-MD5 is what the S3 API specifies here
		req.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString(md5sum[:]))
	default:
		req.Header.Set("Content-Md5", contentMD5)
	}

	sum := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signer := v4.NewSigner()
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	require.NoError(t, signer.SignHTTP(ctx, creds, req, payloadHash, "s3", integration.TestRegion, time.Now().UTC()),
		"signing the request must not fail")

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err, "the batch delete request must reach the server")
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading the response body must not fail")

	return DelResponse{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Header:      resp.Header.Clone(),
		Body:        raw,
	}
}

// DelParseResult parses a DeleteResult and fails when the answer is not one.
func DelParseResult(t *testing.T, r DelResponse) DelResultDoc {
	t.Helper()
	var doc DelResultDoc
	require.NoErrorf(t, xml.Unmarshal(r.Body, &doc),
		"the answer must be a parseable DeleteResult, got: %s", string(r.Body))
	require.Equalf(t, "DeleteResult", doc.XMLName.Local,
		"the root element must be DeleteResult, got: %s", string(r.Body))
	return doc
}

// DelParseError parses an S3 REST error document.
func DelParseError(t *testing.T, r DelResponse) DelErrorDoc {
	t.Helper()
	var doc DelErrorDoc
	require.NoErrorf(t, xml.Unmarshal(r.Body, &doc),
		"the answer must be a parseable Error document, got: %s", string(r.Body))
	return doc
}

// DelDeletedKeys returns the sorted Key values of the <Deleted> children.
func DelDeletedKeys(doc DelResultDoc) []string {
	keys := make([]string, 0, len(doc.Deleted))
	for _, d := range doc.Deleted {
		keys = append(keys, d.Key)
	}
	sort.Strings(keys)
	return keys
}

// DelNewMinIOBucket creates the oracle bucket directly in MinIO and registers
// its cleanup. Only buckets created here are ever touched.
func DelNewMinIOBucket(t *testing.T, ctx context.Context, client *s3.Client) string {
	t.Helper()
	name := "del-oracle-" + integration.RandomString(16)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(name)})
	require.NoErrorf(t, err, "creating the oracle bucket %s must succeed", name)
	t.Cleanup(func() { DelCleanupBucket(t, client, name) })
	return name
}

// DelCleanupBucket empties and removes one bucket this file created. It uses a
// fresh context so cleanup still runs when the test context is already done.
func DelCleanupBucket(t *testing.T, client *s3.Client, bucket string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var token *string
	for {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			ContinuationToken: token,
		})
		if err != nil {
			break
		}
		for _, obj := range out.Contents {
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: obj.Key,
			})
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			break
		}
		token = out.NextContinuationToken
	}
	_, _ = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
}

// DelPutKeys writes the same body under every key through the given client.
func DelPutKeys(t *testing.T, ctx context.Context, client *s3.Client, bucket string, keys []string, content string) {
	t.Helper()
	for _, k := range keys {
		_, err := client.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(k),
			Body:          strings.NewReader(content),
			ContentLength: aws.Int64(int64(len(content))),
		})
		require.NoErrorf(t, err, "putting %q into %s must succeed", k, bucket)
	}
}

// DelObjectExists reports whether a key is currently retrievable.
func DelObjectExists(ctx context.Context, client *s3.Client, bucket, key string) bool {
	_, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	return err == nil
}

// DelHasEncryptionMetadata reports whether the object stored in the backend
// carries s3ep-* metadata, i.e. whether it really went through encryption.
func DelHasEncryptionMetadata(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) bool {
	t.Helper()
	out, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	if err != nil {
		return false
	}
	for k := range out.Metadata {
		if strings.HasPrefix(strings.ToLower(k), "s3ep-") {
			return true
		}
	}
	return false
}

// DelKeySet builds n unique keys sharing a prefix.
func DelKeySet(prefix string, n int) []string {
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		keys = append(keys, fmt.Sprintf("%s-%02d-%s", prefix, i, integration.RandomString(8)))
	}
	return keys
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

// Three existing keys must all come back in <Deleted> and must really be gone,
// through the proxy exactly as directly in MinIO. The proxy side additionally
// proves the ciphertext left the backend, not just the client's view of it.
func TestDelBatchDeleteThreeExistingKeys(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	const content = "batch delete payload that is long enough to be encrypted"
	proxyKeys := DelKeySet("del-three", 3)
	oracleKeys := DelKeySet("del-three", 3)

	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyKeys, content)
	DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleKeys, content)

	// The proxy-written objects must be encrypted at rest, otherwise the rest
	// of this test proves nothing about removing ciphertext.
	for _, k := range proxyKeys {
		require.Truef(t, DelHasEncryptionMetadata(t, ctx, tc.MinIOClient, tc.TestBucket, k),
			"object %q must carry s3ep-* metadata in the backend before it is deleted", k)
	}

	proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, false, proxyKeys))
	oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, DelBuildDoc(t, false, oracleKeys))

	assert.Equal(t, oracleResp.Status, proxyResp.Status,
		"the proxy must answer a batch delete with the same status as the backend")
	assert.Equal(t, http.StatusOK, proxyResp.Status, "a batch delete of existing keys is 200")

	proxyDoc := DelParseResult(t, proxyResp)
	oracleDoc := DelParseResult(t, oracleResp)

	sortedProxy := append([]string(nil), proxyKeys...)
	sort.Strings(sortedProxy)
	sortedOracle := append([]string(nil), oracleKeys...)
	sort.Strings(sortedOracle)

	assert.Equal(t, sortedProxy, DelDeletedKeys(proxyDoc), "all three keys must appear in <Deleted>")
	assert.Equal(t, sortedOracle, DelDeletedKeys(oracleDoc), "MinIO must report the same three")
	assert.Empty(t, proxyDoc.Errors, "no <Error> children for existing keys")
	assert.Equal(t, len(oracleDoc.Errors), len(proxyDoc.Errors), "proxy and backend must agree on the error count")

	// Really gone: from the client's view AND from the backend.
	for _, k := range proxyKeys {
		assert.Falsef(t, DelObjectExists(ctx, tc.ProxyClient, tc.TestBucket, k),
			"key %q must be gone through the proxy", k)
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
			"the encrypted object for key %q must be gone from the backend", k)
	}
	for _, k := range oracleKeys {
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, oracle, k),
			"key %q must be gone in MinIO", k)
	}
}

// The SDK path is what a real client uses, so the same delete has to work
// through aws-sdk-go-v2 and produce the same document.
func TestDelBatchDeleteThroughTheSDK(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	proxyKeys := DelKeySet("del-sdk", 3)
	oracleKeys := DelKeySet("del-sdk", 3)
	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyKeys, "sdk batch delete payload")
	DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleKeys, "sdk batch delete payload")

	ids := func(keys []string) []types.ObjectIdentifier {
		out := make([]types.ObjectIdentifier, 0, len(keys))
		for _, k := range keys {
			out = append(out, types.ObjectIdentifier{Key: aws.String(k)})
		}
		return out
	}

	proxyOut, err := tc.ProxyClient.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(tc.TestBucket),
		Delete: &types.Delete{Objects: ids(proxyKeys), Quiet: aws.Bool(false)},
	})
	require.NoError(t, err, "DeleteObjects through the proxy must succeed")

	oracleOut, err := tc.MinIOClient.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(oracle),
		Delete: &types.Delete{Objects: ids(oracleKeys), Quiet: aws.Bool(false)},
	})
	require.NoError(t, err, "DeleteObjects against MinIO must succeed")

	assert.Len(t, proxyOut.Deleted, 3, "the SDK must see three deleted objects through the proxy")
	assert.Len(t, oracleOut.Deleted, len(proxyOut.Deleted), "proxy and backend must agree")
	assert.Empty(t, proxyOut.Errors, "no per-key errors through the proxy")
	assert.Empty(t, oracleOut.Errors, "no per-key errors in MinIO")

	for _, k := range proxyKeys {
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
			"the encrypted object for key %q must be gone from the backend", k)
	}
}

// Quiet=true suppresses the successes, Quiet=false lists them. Same document,
// same bucket state, only the flag differs - and the proxy must match MinIO in
// both directions.
func TestDelBatchDeleteQuietMode(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	cases := []struct {
		name  string
		quiet bool
	}{
		{"quiet_true_omits_successful_deletions", true},
		{"quiet_false_lists_successful_deletions", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyKeys := DelKeySet("del-quiet", 3)
			oracleKeys := DelKeySet("del-quiet", 3)
			DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyKeys, "quiet mode payload")
			DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleKeys, "quiet mode payload")

			proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
				integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
				tc.TestBucket, DelBuildDoc(t, c.quiet, proxyKeys))
			oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
				integration.MinIOAccessKey, integration.MinIOSecretKey,
				oracle, DelBuildDoc(t, c.quiet, oracleKeys))

			require.Equal(t, http.StatusOK, proxyResp.Status, "batch delete is 200")
			assert.Equal(t, oracleResp.Status, proxyResp.Status, "proxy and backend statuses must agree")

			proxyDoc := DelParseResult(t, proxyResp)
			oracleDoc := DelParseResult(t, oracleResp)

			if c.quiet {
				assert.Empty(t, proxyDoc.Deleted,
					"Quiet=true must omit successful deletions from the proxy response")
				assert.Empty(t, oracleDoc.Deleted,
					"Quiet=true must omit successful deletions from the MinIO response")
			} else {
				sorted := append([]string(nil), proxyKeys...)
				sort.Strings(sorted)
				assert.Equal(t, sorted, DelDeletedKeys(proxyDoc),
					"Quiet=false must list every successful deletion")
				assert.Len(t, oracleDoc.Deleted, len(proxyDoc.Deleted),
					"proxy and backend must report the same number of successes")
			}

			assert.Empty(t, proxyDoc.Errors, "no <Error> children expected")

			// Quiet only changes the report, never the effect.
			for _, k := range proxyKeys {
				assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
					"key %q must be gone from the backend regardless of Quiet", k)
			}
			for _, k := range oracleKeys {
				assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, oracle, k),
					"key %q must be gone in MinIO regardless of Quiet", k)
			}
		})
	}
}

// AWS reports the delete of a key that does not exist as a SUCCESS, not as an
// error: a batch of two existing and two missing keys yields four <Deleted>
// children and no <Error>.
func TestDelBatchDeleteMixOfExistingAndMissingKeys(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	proxyExisting := DelKeySet("del-mix-have", 2)
	oracleExisting := DelKeySet("del-mix-have", 2)
	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyExisting, "mixed batch payload")
	DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleExisting, "mixed batch payload")

	proxyMissing := DelKeySet("del-mix-gone", 2)
	oracleMissing := DelKeySet("del-mix-gone", 2)

	proxyAll := append(append([]string(nil), proxyExisting...), proxyMissing...)
	oracleAll := append(append([]string(nil), oracleExisting...), oracleMissing...)

	proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, false, proxyAll))
	oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, DelBuildDoc(t, false, oracleAll))

	require.Equal(t, http.StatusOK, proxyResp.Status, "a mixed batch is still 200")
	assert.Equal(t, oracleResp.Status, proxyResp.Status, "proxy and backend statuses must agree")

	proxyDoc := DelParseResult(t, proxyResp)
	oracleDoc := DelParseResult(t, oracleResp)

	sortedProxy := append([]string(nil), proxyAll...)
	sort.Strings(sortedProxy)
	assert.Equal(t, sortedProxy, DelDeletedKeys(proxyDoc),
		"deleting a non-existent key is a success in AWS: all four keys belong in <Deleted>")
	assert.Empty(t, proxyDoc.Errors,
		"a missing key must not produce an <Error> child")
	assert.Len(t, oracleDoc.Deleted, len(proxyDoc.Deleted),
		"MinIO must treat the missing keys the same way")
	assert.Empty(t, oracleDoc.Errors, "MinIO must not report an error either")

	for _, k := range proxyExisting {
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
			"the encrypted object for key %q must be gone from the backend", k)
	}
}

// Keys carrying XML metacharacters and non-ASCII text must survive the round
// trip through the request document and back out through the response document
// unchanged, and must really be deleted.
func TestDelBatchDeleteKeysNeedingXMLEscaping(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	suffix := integration.RandomString(8)
	shapes := []string{
		"del-esc-ampersand-a&b-" + suffix,
		"del-esc-angles-<tag>-" + suffix,
		`del-esc-quotes-"double"-'single'-` + suffix,
		"del-esc-utf8-schluessel-ue-ü-日本語-\U0001f510-" + suffix,
		"del-esc-mixed-a&b<c>d\"e-" + suffix,
	}

	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, shapes, "xml escaping payload")
	DelPutKeys(t, ctx, tc.MinIOClient, oracle, shapes, "xml escaping payload")

	for _, k := range shapes {
		require.Truef(t, DelObjectExists(ctx, tc.ProxyClient, tc.TestBucket, k),
			"key %q must exist through the proxy before the batch delete", k)
	}

	doc := DelBuildDoc(t, false, shapes)
	// The document really must contain escaped entities, otherwise this test
	// would silently prove nothing.
	require.Contains(t, doc, "&amp;", "the request document must escape &")
	require.Contains(t, doc, "&lt;", "the request document must escape <")

	proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, doc)
	oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, doc)

	require.Equal(t, http.StatusOK, proxyResp.Status, "escaped keys must not break the request")
	assert.Equal(t, oracleResp.Status, proxyResp.Status, "proxy and backend statuses must agree")

	proxyDoc := DelParseResult(t, proxyResp)
	oracleDoc := DelParseResult(t, oracleResp)

	sorted := append([]string(nil), shapes...)
	sort.Strings(sorted)
	assert.Equal(t, sorted, DelDeletedKeys(proxyDoc),
		"every escaped key must come back byte-identical through the proxy")
	assert.Equal(t, sorted, DelDeletedKeys(oracleDoc),
		"every escaped key must come back byte-identical from MinIO")
	assert.Empty(t, proxyDoc.Errors, "escaped keys must not produce errors")

	// The response must be well-formed XML the second time round too: the
	// entities have to be re-escaped on the way out, not emitted raw.
	assert.True(t, bytes.Contains(proxyResp.Body, []byte("&amp;")),
		"the response must re-escape & rather than emitting it raw")

	for _, k := range shapes {
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
			"the encrypted object for key %q must be gone from the backend", k)
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, oracle, k),
			"key %q must be gone in MinIO", k)
	}
}

// The answer has to be a DeleteResult with Deleted and Error children, served
// as XML. This pins the document shape itself rather than only its contents.
func TestDelBatchDeleteResponseDocumentShape(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	proxyKeys := DelKeySet("del-shape", 2)
	oracleKeys := DelKeySet("del-shape", 2)
	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyKeys, "shape payload")
	DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleKeys, "shape payload")

	proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, false, proxyKeys))
	oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, DelBuildDoc(t, false, oracleKeys))

	assert.Contains(t, strings.ToLower(proxyResp.ContentType), "xml",
		"a DeleteResult must be served as XML")
	assert.Contains(t, strings.ToLower(oracleResp.ContentType), "xml",
		"MinIO serves it as XML too")

	proxyDoc := DelParseResult(t, proxyResp)
	oracleDoc := DelParseResult(t, oracleResp)
	require.NotEmpty(t, proxyDoc.Deleted, "the shape test needs at least one <Deleted>")
	for _, d := range proxyDoc.Deleted {
		assert.NotEmpty(t, d.Key, "every <Deleted> child must carry a Key")
	}

	// The proxy must not leak its own encryption metadata into the batch
	// delete answer - that is the one place the two documents are allowed to
	// differ, and it must differ in this direction only.
	assert.NotContains(t, strings.ToLower(string(proxyResp.Body)), "s3ep-",
		"the batch delete response must not expose s3ep-* metadata")

	// DEVIATION, reported: AWS and MinIO both put the DeleteResult in the S3
	// namespace, the proxy emits it with no namespace at all. A namespace-aware
	// or schema-validating client sees a different document.
	assert.Equal(t, "http://s3.amazonaws.com/doc/2006-03-01/", oracleDoc.XMLName.Space,
		"the backend puts DeleteResult in the S3 namespace")
	assert.Equal(t, "", proxyDoc.XMLName.Space,
		"DEVIATION: the proxy emits DeleteResult without the S3 xmlns the backend and AWS use")

	// DEVIATION, reported: AWS emits x-amz-request-id (and x-amz-id-2) on every
	// response; MinIO does too. The proxy emits neither on this path, so a
	// client has no correlation id to report a failed batch delete with.
	assert.NotEmpty(t, oracleResp.Header.Get("x-amz-request-id"),
		"the backend returns a request id")
	assert.Empty(t, proxyResp.Header.Get("x-amz-request-id"),
		"DEVIATION: the proxy returns no x-amz-request-id on a batch delete")
}

// A batch delete must remove the ciphertext of large objects too. A 6 MiB body
// spans many segments and is written through the multipart producer, so this
// covers the other of the two write paths.
func TestDelBatchDeleteRemovesLargeEncryptedObjects(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	large := make([]byte, 6*1024*1024)
	for i := range large {
		large[i] = byte(i * 7 % 251)
	}
	plainDigest := sha256.Sum256(large)

	largeKey := "del-large-" + integration.RandomString(10)
	smallKey := "del-small-" + integration.RandomString(10)

	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(tc.TestBucket),
		Key:           aws.String(largeKey),
		Body:          bytes.NewReader(large),
		ContentLength: aws.Int64(int64(len(large))),
	})
	require.NoError(t, err, "the large put must succeed")
	DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, []string{smallKey}, "small object payload")

	// Encrypted at rest: the stored bytes must not hash to the plaintext.
	stored, err := tc.MinIOClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(largeKey),
	})
	require.NoError(t, err, "the backend must hold the object")
	storedHash := sha256.New()
	_, err = io.Copy(storedHash, stored.Body)
	require.NoError(t, err, "reading the stored bytes must not fail")
	require.NoError(t, stored.Body.Close())
	require.NotEqual(t, hex.EncodeToString(plainDigest[:]), hex.EncodeToString(storedHash.Sum(nil)),
		"the object must be stored as ciphertext, not plaintext")

	resp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, false, []string{largeKey, smallKey}))
	require.Equal(t, http.StatusOK, resp.Status, "the batch delete must be 200")

	doc := DelParseResult(t, resp)
	assert.ElementsMatch(t, []string{largeKey, smallKey}, DelDeletedKeys(doc),
		"both keys must appear in <Deleted>")
	assert.Empty(t, doc.Errors, "neither key may produce an <Error> child")

	for _, k := range []string{largeKey, smallKey} {
		assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
			"the ciphertext for %q must be gone from the backend", k)
		assert.Falsef(t, DelObjectExists(ctx, tc.ProxyClient, tc.TestBucket, k),
			"%q must be gone through the proxy", k)
	}
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

// An empty Delete document, a truncated body and a body that is not XML at all.
// AWS answers MalformedXML (400) to all three.
func TestDelBatchDeleteMalformedDocuments(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	cases := []struct {
		name string
		body string
		// compareBackend is false only where the difference is in the HTTP
		// transport rather than in the S3 API, see the note per case.
		compareBackend bool
	}{
		// AWS: a Delete document must carry at least one Object.
		{"empty_delete_document", `<?xml version="1.0" encoding="UTF-8"?><Delete></Delete>`, true},
		{"delete_document_with_only_quiet", `<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet></Delete>`, true},
		{"truncated_xml", `<?xml version="1.0" encoding="UTF-8"?><Delete><Object><Key>a</Key></Object>`, true},
		{"not_xml_at_all", `this is not xml`, true},
		// A zero-length body makes Go's client omit Content-Length, which MinIO
		// rejects with 411 MissingContentLength before it ever looks at the
		// document. That is a transport-level difference in the test client, so
		// only the proxy side is asserted here.
		{"empty_body", ``, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
				integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
				tc.TestBucket, c.body)

			require.Equalf(t, http.StatusBadRequest, proxyResp.Status,
				"a bad Delete document must be 400, got: %s", string(proxyResp.Body))
			assert.Equalf(t, "MalformedXML", DelParseError(t, proxyResp).Code,
				"AWS answers MalformedXML for a bad Delete document, got: %s", string(proxyResp.Body))

			if !c.compareBackend {
				return
			}

			oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
				integration.MinIOAccessKey, integration.MinIOSecretKey,
				oracle, c.body)

			assert.Equalf(t, oracleResp.Status, proxyResp.Status,
				"proxy and backend must agree on the status for %s", c.name)
			assert.Equalf(t, "MalformedXML", DelParseError(t, oracleResp).Code,
				"MinIO answers MalformedXML too, got: %s", string(oracleResp.Body))
		})
	}
}

// DEVIATION, reported: DeleteObjects is one of the few S3 operations for which
// AWS requires a body integrity header - Content-MD5, or one of the
// x-amz-checksum-* / x-amz-sdk-checksum-algorithm headers. Without it AWS
// answers InvalidRequest and MinIO answers MissingContentMD5; a wrong digest is
// BadDigest on both. The proxy checks neither: it parses the document and
// deletes whatever it managed to read, then re-signs its own request to the
// backend so the backend never sees the client's (missing or wrong) digest.
//
// The assertions below encode the behaviour that EXISTS, not the AWS
// behaviour, so the suite stays green while the gap stays visible.
func TestDelBatchDeleteIntegrityHeaderNotEnforced(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	cases := []struct {
		name       string
		contentMD5 string
		// backendRejects records what MinIO actually does. AWS rejects both of
		// these; MinIO only checks that the header is present, never that it
		// matches, so the second case is a deviation MinIO and the proxy share.
		backendRejects bool
		backendCode    string
	}{
		{"no_content_md5", "", true, "MissingContentMD5"},
		// A syntactically valid digest of different content. AWS: BadDigest.
		{"wrong_content_md5", base64.StdEncoding.EncodeToString(func() []byte {
			sum := md5.Sum([]byte("not the body")) // #nosec G401 - Content-MD5 is what the S3 API specifies here
			return sum[:]
		}()), false, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyKeys := DelKeySet("del-md5", 2)
			oracleKeys := DelKeySet("del-md5", 2)
			DelPutKeys(t, ctx, tc.ProxyClient, tc.TestBucket, proxyKeys, "integrity header payload")
			DelPutKeys(t, ctx, tc.MinIOClient, oracle, oracleKeys, "integrity header payload")

			oracleResp := DelPostDeleteRaw(t, ctx, integration.MinIOEndpoint,
				integration.MinIOAccessKey, integration.MinIOSecretKey,
				oracle, DelBuildDoc(t, false, oracleKeys), c.contentMD5)

			if c.backendRejects {
				require.Equalf(t, http.StatusBadRequest, oracleResp.Status,
					"the backend rejects a batch delete without a digest header, got: %s", string(oracleResp.Body))
				assert.Equal(t, c.backendCode, DelParseError(t, oracleResp).Code,
					"the backend names the missing digest")
				for _, k := range oracleKeys {
					assert.Truef(t, DelObjectExists(ctx, tc.MinIOClient, oracle, k),
						"the backend must not have deleted %q from a request it rejected", k)
				}
			} else {
				// DEVIATION, reported: AWS answers BadDigest when Content-MD5
				// does not match the body. MinIO only checks that the header
				// exists, so a corrupted body is executed here as well.
				require.Equalf(t, http.StatusOK, oracleResp.Status,
					"MinIO does not verify the Content-MD5 value, got: %s", string(oracleResp.Body))
			}

			proxyResp := DelPostDeleteRaw(t, ctx, integration.ProxyEndpoint,
				integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
				tc.TestBucket, DelBuildDoc(t, false, proxyKeys), c.contentMD5)

			// DEVIATION: AWS answers 400 in both cases, the proxy answers 200
			// and performs the delete.
			assert.Equalf(t, http.StatusOK, proxyResp.Status,
				"DEVIATION: the proxy executes a batch delete AWS rejects (%s), got status %d",
				c.name, proxyResp.Status)
			if proxyResp.Status == http.StatusOK {
				doc := DelParseResult(t, proxyResp)
				assert.Len(t, doc.Deleted, len(proxyKeys),
					"DEVIATION: the unverified document was executed in full")
				for _, k := range proxyKeys {
					assert.Falsef(t, DelObjectExists(ctx, tc.MinIOClient, tc.TestBucket, k),
						"DEVIATION: %q was deleted from the backend on an unverified request", k)
				}
			}
		})
	}
}

// AWS documents a hard limit of 1000 keys per batch delete and answers
// MalformedXML above it. The keys need not exist for the limit to apply.
func TestDelBatchDeleteKeyLimit(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()
	oracle := DelNewMinIOBucket(t, ctx, tc.MinIOClient)

	over := DelKeySet("del-limit", 1001)

	proxyResp := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, true, over))
	oracleResp := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, DelBuildDoc(t, true, over))

	// Observable behaviour is correct: 400 MalformedXML on both sides. Note
	// where it comes from - internal/proxy/handlers/object/operations.go
	// handleDeleteObjects has no key-count check of its own, it forwards the
	// whole list and relays the backend's refusal. Against a backend that does
	// not enforce the limit the proxy would accept an unbounded document.
	assert.Equal(t, oracleResp.Status, proxyResp.Status,
		"the proxy must answer an over-limit batch the same way the backend does")
	require.Equalf(t, http.StatusBadRequest, proxyResp.Status,
		"1001 keys must be refused, got: %.400s", string(proxyResp.Body))
	assert.Equal(t, "MalformedXML", DelParseError(t, proxyResp).Code,
		"AWS answers MalformedXML above 1000 keys")
	assert.Equal(t, "MalformedXML", DelParseError(t, oracleResp).Code,
		"MinIO answers MalformedXML above 1000 keys")

	// Exactly 1000 keys is still legal and must be accepted.
	atLimit := DelKeySet("del-atlimit", 1000)
	proxyAt := DelPostDelete(t, ctx, integration.ProxyEndpoint,
		integration.ProxyTestAccessKey, integration.ProxyTestSecretKey,
		tc.TestBucket, DelBuildDoc(t, true, atLimit))
	oracleAt := DelPostDelete(t, ctx, integration.MinIOEndpoint,
		integration.MinIOAccessKey, integration.MinIOSecretKey,
		oracle, DelBuildDoc(t, true, atLimit))

	assert.Equal(t, http.StatusOK, proxyAt.Status, "1000 keys is at the documented limit and must be accepted")
	assert.Equal(t, oracleAt.Status, proxyAt.Status, "proxy and backend must agree at the limit")
}
