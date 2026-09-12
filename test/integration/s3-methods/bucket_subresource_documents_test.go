//go:build integration

package s3methods

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every bucket sub-resource GET used to answer the aws-sdk-go-v2 output struct
// XML-encoded: the root element was the Go type name, the element names were Go
// field names, there was no S3 namespace and an internal <ResultMetadata>
// element leaked into every document. No S3 client could parse any of them.
//
// Two kinds of assertion here. The differential one is the strong one: the same
// call is made through the proxy and straight at MinIO, and the parsed results
// have to agree - which only happens if the proxy's document is the one the SDK
// expects. The raw one reads the bytes, because the SDK hides the root element,
// the namespace and the element order.

func TestBdocSubResourceDocumentsAreS3Documents(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	// Raw bytes: the root element, the namespace, and nothing of the SDK.
	for _, sub := range []struct {
		param string
		root  string
	}{
		{"versioning", "VersioningConfiguration"},
		{"location", "LocationConstraint"},
		{"acl", "AccessControlPolicy"},
	} {
		t.Run(sub.param, func(t *testing.T) {
			status, body := bdocProxyGet(t, "/"+tc.TestBucket, sub.param)
			require.Equal(t, http.StatusOK, status, "body: %s", body)

			assert.True(t, strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`),
				"the document opens with the XML declaration: %s", body)
			assert.Contains(t, body, "<"+sub.root+` xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`,
				"the root element is %s under the S3 namespace: %s", sub.root, body)
			assert.NotContains(t, body, "ResultMetadata",
				"the SDK's internal element must not reach a client")
			assert.NotContains(t, body, "Output>",
				"the root element must not be an SDK Go type name")
		})
	}

	// Differential: the SDK parses the proxy's answer into the same value it
	// parses the backend's into.
	t.Run("the SDK reads the same values through both legs", func(t *testing.T) {
		throughProxy, proxyErr := tc.ProxyClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(tc.TestBucket),
		})
		direct, directErr := tc.MinIOClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: aws.String(tc.TestBucket),
		})
		require.NoError(t, proxyErr)
		require.NoError(t, directErr)
		assert.Equal(t, direct.Status, throughProxy.Status)
		assert.Equal(t, direct.MFADelete, throughProxy.MFADelete)

		proxyACL, err := tc.ProxyClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(tc.TestBucket),
		})
		require.NoError(t, err, "an ACL document the SDK cannot parse fails here")
		directACL, err := tc.MinIOClient.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(tc.TestBucket),
		})
		require.NoError(t, err)
		assert.Len(t, proxyACL.Grants, len(directACL.Grants))
		if len(directACL.Grants) > 0 {
			assert.Equal(t, directACL.Grants[0].Permission, proxyACL.Grants[0].Permission)
			require.NotNil(t, proxyACL.Grants[0].Grantee)
			assert.Equal(t, directACL.Grants[0].Grantee.Type, proxyACL.Grants[0].Grantee.Type,
				"the xsi:type attribute survives, which is what names the grantee kind")
		}
	})
}

// A CORS document the client sends reaches the backend rule for rule, and comes
// back the same way. Both halves used to be lost: PUT parsed into a tagless SDK
// type and forwarded an empty rule set, and GET answered a document with the Go
// field names.
func TestBdocCORSDocumentRoundTrip(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	wanted := types.CORSRule{
		ID:             aws.String("bdoc-rule"),
		AllowedOrigins: []string{"https://example.test"},
		AllowedMethods: []string{"GET", "PUT"},
		AllowedHeaders: []string{"*"},
		ExposeHeaders:  []string{"ETag"},
		MaxAgeSeconds:  aws.Int32(3000),
	}

	_, err := tc.ProxyClient.PutBucketCors(ctx, &s3.PutBucketCorsInput{
		Bucket:            aws.String(tc.TestBucket),
		CORSConfiguration: &types.CORSConfiguration{CORSRules: []types.CORSRule{wanted}},
	})
	if err != nil {
		// The request goes through the proxy, so a failure here is as likely the
		// proxy's as the backend's, and skipping on any error hides exactly the
		// defect this test exists to catch. Only a backend that says it does not
		// implement the verb is a reason to stop.
		var api smithy.APIError
		if errors.As(err, &api) && api.ErrorCode() == "NotImplemented" {
			t.Skipf("this backend does not implement PutBucketCors: %v", err)
		}
		require.NoError(t, err, "the CORS configuration was refused")
	}

	// Straight from MinIO: the rule really arrived, it was not echoed by the proxy.
	stored, err := tc.MinIOClient.GetBucketCors(ctx, &s3.GetBucketCorsInput{
		Bucket: aws.String(tc.TestBucket),
	})
	require.NoError(t, err)
	require.Len(t, stored.CORSRules, 1, "the rule the client sent reached the backend")
	assert.ElementsMatch(t, wanted.AllowedMethods, stored.CORSRules[0].AllowedMethods)
	assert.ElementsMatch(t, wanted.AllowedOrigins, stored.CORSRules[0].AllowedOrigins)
	assert.Equal(t, int32(3000), aws.ToInt32(stored.CORSRules[0].MaxAgeSeconds))

	// And back through the proxy, parsed by the SDK.
	readBack, err := tc.ProxyClient.GetBucketCors(ctx, &s3.GetBucketCorsInput{
		Bucket: aws.String(tc.TestBucket),
	})
	require.NoError(t, err)
	require.Len(t, readBack.CORSRules, 1)
	assert.ElementsMatch(t, stored.CORSRules[0].AllowedMethods, readBack.CORSRules[0].AllowedMethods)
	assert.ElementsMatch(t, stored.CORSRules[0].AllowedOrigins, readBack.CORSRules[0].AllowedOrigins)

	status, body := bdocProxyGet(t, "/"+tc.TestBucket, "cors")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "<CORSRule>", "S3 names the element CORSRule, not CORSRules")
	assert.Contains(t, body, "<AllowedMethod>GET</AllowedMethod>")
	assert.NotContains(t, body, "<AllowedMethods>")

	_, err = tc.ProxyClient.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{
		Bucket: aws.String(tc.TestBucket),
	})
	require.NoError(t, err)
}

// A sub-resource document that does not parse answers MalformedXML through the
// proxy's own error document, not a bare transport error (ADR 0007 D5, D8).
func TestBdocMalformedBucketDocumentIsMalformedXML(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	for _, sub := range []string{"acl", "cors", "logging"} {
		t.Run(sub, func(t *testing.T) {
			status, body := hdrSignedPutQuery(t, "/"+tc.TestBucket, sub, []byte("<not-a-document"), nil)
			assert.Equal(t, http.StatusBadRequest, status)
			assert.Contains(t, string(body), "MalformedXML")
			assert.Contains(t, string(body), "<Error>",
				"the refusal is an S3 error document, not plain text")
		})
	}
}

// bdocProxyGet issues a signed sub-resource GET without the SDK and returns the
// raw answer: the SDK hides the root element, the namespace and the ordering.
func bdocProxyGet(t *testing.T, path, rawQuery string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, integration.ProxyEndpoint+path+"?"+rawQuery, nil)
	require.NoError(t, err)
	require.NoError(t, integration.SignHTTPRequestForS3WithCredentials(req,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))

	resp, err := integration.TLSHTTPClient().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}
