//go:build conformance

package conformance

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The refusals cost nothing. A refused upload stores no object — the proxy holds
// the last payload byte back until the verdict is in — so this whole file runs
// under a zero byte budget and is the cheapest coverage in the suite.

// TestRefusedUploadsStoreNothing is the assertion that makes the rest of this
// file free: a refusal has to leave no object behind, or every run would pay for
// its own error cases.
func TestRefusedUploadsStoreNothing(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	key := Key("refused/never-stored")
	payload := []byte("this upload carries a digest of something else entirely")

	_, err := proxy.PutObject(ctx, &s3.PutObjectInput{
		Bucket:     aws.String(Bucket),
		Key:        aws.String(key),
		Body:       bytes.NewReader(payload),
		ContentMD5: aws.String("1B2M2Y8AsgTpgAmY7PhCfg=="), // the MD5 of the empty string
	})
	require.Error(t, err, "a wrong Content-MD5 is refused")
	assert.Equal(t, "BadDigest", apiCode(err))

	_, err = proxy.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(Bucket),
		Key:    aws.String(key),
	})
	require.Error(t, err, "the refused upload must not exist: it would be billed for ninety days")
	assert.Equal(t, http.StatusNotFound, statusOf(err))
}

// TestSSECustomerKeysAreRefusedByName covers ADR 0007 D6. No read path carries
// the customer key, so accepting one on upload would write an object this proxy
// could never read back.
func TestSSECustomerKeysAreRefusedByName(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	_, err := proxy.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(Bucket),
		Key:                  aws.String(Key("refused/sse-c")),
		Body:                 bytes.NewReader([]byte("x")),
		SSECustomerAlgorithm: aws.String("AES256"),
		SSECustomerKey:       aws.String(strings.Repeat("k", 32)),
	})
	require.Error(t, err)
	assert.Equal(t, http.StatusNotImplemented, statusOf(err))
}

// TestClientMetadataInsideTheProxyPrefixIsRefused covers ADR 0009 D6. The prefix
// is the proxy's namespace in both directions, and a client key inside it is
// named in the refusal rather than dropped.
func TestClientMetadataInsideTheProxyPrefixIsRefused(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	_, err := proxy.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(Bucket),
		Key:      aws.String(Key("refused/metadata")),
		Body:     bytes.NewReader([]byte("x")),
		Metadata: map[string]string{"s3ep-dek-algorithm": "something"},
	})
	require.Error(t, err)
	assert.Equal(t, "InvalidArgument", apiCode(err))
}

// TestServerSideCopyIsRefused covers the one thing this proxy cannot do: a copy
// at the backend would move ciphertext without re-encrypting it under the
// destination key.
func TestServerSideCopyIsRefused(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	_, err := proxy.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(Bucket),
		Key:        aws.String(Key("refused/copy")),
		CopySource: aws.String(Bucket + "/" + Key("tiny")),
	})
	require.Error(t, err)
	assert.Equal(t, http.StatusUnprocessableEntity, statusOf(err))
}

// TestReservedPartNumberIsRefusedBeforeTheUpload covers ADR 0011 D4. The refusal
// arrives before any byte is transferred, which is the point: the alternative is
// an upload that fails at Complete after everything has been sent and stored.
func TestReservedPartNumberIsRefusedBeforeTheUpload(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	key := Key("refused/reserved-part")
	create, err := proxy.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(Bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	uploadID := aws.ToString(create.UploadId)

	// Abort unconditionally: an upload left open holds billed parts.
	t.Cleanup(func() {
		abortCtx, abortCancel := Context(t)
		defer abortCancel()
		if _, aerr := proxy.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(Bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}); aerr != nil {
			t.Errorf("the upload was left open and its parts stay billed: %v", aerr)
		}
	})

	_, err = proxy.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:     aws.String(Bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(10000),
		Body:       bytes.NewReader([]byte("x")),
	})
	require.Error(t, err, "part 10000 belongs to the trailer")
}

// TestConditionalReadsAreHonoured covers ADR 0007 D7 on the read side. These are
// a classic backend difference: a proxy that drops a precondition answers 200
// where S3 answers 304 or 412, and the client transfers and decrypts a whole
// object it already had.
func TestConditionalReadsAreHonoured(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	head, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(Bucket),
		Key:    aws.String(Key("tiny")),
	})
	require.NoError(t, err)
	etag := aws.ToString(head.ETag)
	require.NotEmpty(t, etag)

	t.Run("if_none_match_on_the_current_etag_is_304", func(t *testing.T) {
		_, gerr := proxy.GetObject(ctx, &s3.GetObjectInput{
			Bucket:      aws.String(Bucket),
			Key:         aws.String(Key("tiny")),
			IfNoneMatch: aws.String(etag),
		})
		require.Error(t, gerr)
		assert.Equal(t, http.StatusNotModified, statusOf(gerr))
	})

	t.Run("if_match_on_a_foreign_etag_is_412", func(t *testing.T) {
		_, gerr := proxy.GetObject(ctx, &s3.GetObjectInput{
			Bucket:  aws.String(Bucket),
			Key:     aws.String(Key("tiny")),
			IfMatch: aws.String(`"00000000000000000000000000000000"`),
		})
		require.Error(t, gerr)
		assert.Equal(t, http.StatusPreconditionFailed, statusOf(gerr))
	})

	t.Run("head_and_get_agree", func(t *testing.T) {
		_, herr := proxy.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:      aws.String(Bucket),
			Key:         aws.String(Key("tiny")),
			IfNoneMatch: aws.String(etag),
		})
		require.Error(t, herr, "HEAD used to answer 200 where GET answered 304")
		assert.Equal(t, http.StatusNotModified, statusOf(herr))
	})
}

// TestBucketOwnerGuardIsForwarded is the assertion this suite was worth building
// for.
//
// x-amz-expected-bucket-owner is the client's defence against a bucket name it no
// longer owns. Dropping it fails open: the backend performs the operation and the
// proxy answers success, so the client believes a guard is in place. ADR 0007 D14
// carries it on every verb.
//
// MinIO does not implement the header — probed 2026-09-11, a wrong owner id
// succeeds against it directly — so against the local stack this test can only
// show that the request still works. Against a backend that does implement it,
// the wrong-owner case is a refusal, and that is what closes the residual risk
// ADR 0007 records. The test states both outcomes and reports which one it saw
// rather than skipping: a suite that silently stops asserting is worse than one
// that says what it could not prove.
func TestBucketOwnerGuardIsForwarded(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	t.Run("a_correct_request_is_unaffected", func(t *testing.T) {
		_, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(Bucket),
			Key:    aws.String(Key("tiny")),
		})
		require.NoError(t, err)
	})

	t.Run("a_wrong_owner", func(t *testing.T) {
		// Not 000000000000: that is LocalStack's default account id, so against
		// that backend it would be the *correct* owner and a success would be
		// misread as the header being ignored. The value has to be well-formed
		// (twelve digits) and owned by nobody.
		_, err := proxy.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket:              aws.String(Bucket),
			Key:                 aws.String(Key("tiny")),
			ExpectedBucketOwner: aws.String("999999999999"),
		})
		if err == nil {
			t.Logf("BACKEND DEVIATION (%s): x-amz-expected-bucket-owner is accepted and ignored. "+
				"The proxy forwards it (asserted by unit tests and by the source-level guard), "+
				"but this backend does not act on it, so the guard cannot be proven end to end here.",
				BackendName)
			return
		}
		// require, not assert: a wrong status here means the refusal came from
		// something other than the guard — a missing object, or a credential the
		// backend rejects outright — and reporting "proven end to end" after that
		// would be a false claim rather than a failed assertion.
		require.Equal(t, http.StatusForbidden, statusOf(err),
			"%s answered %d for a wrong bucket owner. A 404 means the object is not there, "+
				"so this says nothing about the guard; seed the corpus first.",
			BackendName, statusOf(err))
		t.Logf("%s enforces x-amz-expected-bucket-owner: ADR 0007 D14 is proven end to end here", BackendName)
	})
}

// TestMissingObjectsAndBucketsAnswerS3Codes covers the error surface. These are
// cheap and they are exactly where a proxy that composes its own responses can
// drift from the service it imitates.
func TestMissingObjectsAndBucketsAnswerS3Codes(t *testing.T) {
	ctx, cancel := Context(t)
	defer cancel()
	proxy := ProxyClient(t)

	t.Run("missing_key_is_404", func(t *testing.T) {
		_, err := proxy.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(Bucket),
			Key:    aws.String(Key("does-not-exist")),
		})
		require.Error(t, err)
		assert.Equal(t, http.StatusNotFound, statusOf(err))
	})

	t.Run("head_of_a_missing_bucket_is_404", func(t *testing.T) {
		_, err := proxy.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String("s3ep-conformance-no-such-bucket-0000"),
		})
		require.Error(t, err, "HeadBucket used to answer 200 for a bucket that does not exist")
		assert.Equal(t, http.StatusNotFound, statusOf(err))
	})
}

// apiCode returns the S3 error code of an SDK error, or "".
func apiCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

// statusOf returns the HTTP status of an SDK error, or 0.
func statusOf(err error) int {
	var resp *smithyhttp.ResponseError
	if errors.As(err, &resp) {
		return resp.HTTPStatusCode()
	}
	return 0
}
