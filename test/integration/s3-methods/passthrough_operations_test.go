//go:build integration

package s3methods

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

func TestPassthroughOperations_DeleteObjects(t *testing.T) {
	ctx := context.Background()
	testCtx := integration.NewTestContext(t)
	defer testCtx.CleanupTestBucket()

	bucketName := testCtx.TestBucket
	objectKey1 := "test-object-1.txt"
	objectKey2 := "test-object-2.txt"
	content := "test content for deletion"

	// Put two objects via proxy
	_, err := testCtx.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey1),
		Body:   strings.NewReader(content),
	})
	require.NoError(t, err)

	_, err = testCtx.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey2),
		Body:   strings.NewReader(content),
	})
	require.NoError(t, err)

	// Verify objects exist
	listResp, err := testCtx.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err)
	assert.Len(t, listResp.Contents, 2)

	// Delete objects using DeleteObjects operation
	deleteResp, err := testCtx.ProxyClient.DeleteObjects(ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucketName),
		Delete: &types.Delete{
			Objects: []types.ObjectIdentifier{
				{Key: aws.String(objectKey1)},
				{Key: aws.String(objectKey2)},
			},
			Quiet: aws.Bool(false),
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, deleteResp)

	// Verify objects are deleted
	listResp2, err := testCtx.ProxyClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	require.NoError(t, err)
	assert.Len(t, listResp2.Contents, 0)
}

func TestPassthroughOperations_GetObjectTorrent(t *testing.T) {
	ctx := context.Background()
	testCtx := integration.NewTestContext(t)
	defer testCtx.CleanupTestBucket()

	bucketName := testCtx.TestBucket
	objectKey := "test-object.txt"
	content := "test content for torrent"

	// Put object via proxy
	_, err := testCtx.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   strings.NewReader(content),
	})
	require.NoError(t, err)

	// ?torrent is refused by decision, not by the backend: the document would be
	// composed from the bytes the backend holds, which are the ciphertext, and a
	// response carries only what the proxy can vouch for. The request never
	// leaves the proxy (ADR 0008 D1/D11, ADR 0007 D1/D8).
	_, err = testCtx.ProxyClient.GetObjectTorrent(ctx, &s3.GetObjectTorrentInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})

	const rule = "?torrent under an encrypting provider is 422 NotSupportedWithEncryption, the proxy's " +
		"own refusal - not whatever the backend happens to answer (ADR 0007 D1/D8)"
	require.Error(t, err, rule)

	var api smithy.APIError
	require.ErrorAs(t, err, &api, "%s; got %v", rule, err)
	assert.Equal(t, "NotSupportedWithEncryption", api.ErrorCode(), rule)

	var httpErr *awshttp.ResponseError
	require.ErrorAs(t, err, &httpErr, rule)
	assert.Equal(t, http.StatusUnprocessableEntity, httpErr.HTTPStatusCode(), rule)
}

// TestPassthroughOperations_LegalHold is gone: it drove GET and PUT ?legal-hold
// and then swallowed whatever came back in a t.Logf, so it could not fail. What
// it was meant to cover is TestSubpassRetentionAndLegalHoldRoundTrip, which
// asserts ADR 0007 D4 for both verbs by reading the result straight from the
// backend.

func TestPassthroughOperations_SelectObjectContent(t *testing.T) {
	ctx := context.Background()
	testCtx := integration.NewTestContext(t)
	defer testCtx.CleanupTestBucket()

	bucketName := testCtx.TestBucket
	objectKey := "test-data.csv"
	csvContent := "name,age,city\nJohn,30,New York\nJane,25,San Francisco\nBob,35,Chicago"

	// Put CSV object via proxy
	_, err := testCtx.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
		Body:   strings.NewReader(csvContent),
	})
	require.NoError(t, err)

	// S3 Select is refused, not forwarded: the proxy would have to run a query
	// over plaintext the backend does not hold (ADR 0007 D8).
	_, err = testCtx.ProxyClient.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
		Bucket:         aws.String(bucketName),
		Key:            aws.String(objectKey),
		Expression:     aws.String("SELECT * FROM S3Object s WHERE s.age > '25'"),
		ExpressionType: types.ExpressionTypeSql,
		InputSerialization: &types.InputSerialization{
			CSV: &types.CSVInput{
				FileHeaderInfo: types.FileHeaderInfoUse,
			},
		},
		OutputSerialization: &types.OutputSerialization{
			CSV: &types.CSVOutput{},
		},
	})
	const rule = "S3 Select is 501 NotImplemented, the proxy's own refusal, rather than a query " +
		"forwarded to a backend that holds ciphertext (ADR 0007 D8)"
	require.Error(t, err, rule)

	var api smithy.APIError
	require.ErrorAs(t, err, &api, "%s; got %v", rule, err)
	assert.Equal(t, "NotImplemented", api.ErrorCode(), rule)

	var httpErr *awshttp.ResponseError
	require.ErrorAs(t, err, &httpErr, rule)
	assert.Equal(t, http.StatusNotImplemented, httpErr.HTTPStatusCode(), rule)
}
