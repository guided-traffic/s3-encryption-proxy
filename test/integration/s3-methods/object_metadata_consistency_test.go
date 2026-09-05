//go:build integration

package s3methods

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// HEAD, LIST and GET must agree on how large an object is.
//
// They did not: AES-GCM stores a 12-byte nonce and a 16-byte tag alongside the
// payload, GET subtracted them and HEAD echoed the stored length, so every
// object below streaming_threshold looked 28 bytes larger over HEAD than it
// actually was. Clients that record a length from a listing or a HEAD and then
// read the object, kopia among them, see a size that does not match.
func TestObjectSizeIsConsistentAcrossHeadGetAndList(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	sizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"one_byte", 1},
		{"small_gcm_1kb", 1024},
		{"below_threshold_1mb", 1 << 20},
		{"above_threshold_6mb", 6 << 20},
	}

	for _, tcase := range sizes {
		t.Run(tcase.name, func(t *testing.T) {
			payload := make([]byte, tcase.size)
			if tcase.size > 0 {
				_, err := rand.Read(payload)
				require.NoError(t, err)
			}

			key := fmt.Sprintf("size-consistency-%s-%d", tcase.name, time.Now().UnixNano())
			_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
				Bucket:        aws.String(tc.TestBucket),
				Key:           aws.String(key),
				Body:          bytes.NewReader(payload),
				ContentLength: aws.Int64(int64(len(payload))),
			})
			require.NoError(t, err, "upload")
			t.Cleanup(func() {
				_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
					Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
				})
			})

			head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			})
			require.NoError(t, err, "HeadObject")

			get, err := tc.ProxyClient.GetObject(ctx, &s3.GetObjectInput{
				Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
			})
			require.NoError(t, err, "GetObject")
			body, err := io.ReadAll(get.Body)
			require.NoError(t, err)
			_ = get.Body.Close()

			assert.Equalf(t, tcase.size, len(body),
				"GET returned %d bytes for a %d byte object", len(body), tcase.size)
			assert.Equalf(t, int64(tcase.size), aws.ToInt64(head.ContentLength),
				"HEAD reports %d for a %d byte object: it is echoing the stored ciphertext length",
				aws.ToInt64(head.ContentLength), tcase.size)
			assert.Equalf(t, int64(tcase.size), aws.ToInt64(get.ContentLength),
				"GET Content-Length disagrees with the body it delivered")
		})
	}
}

// aws-chunked describes the framing of the request body. The proxy decodes it
// before encrypting, so it must not end up recorded on the stored object.
func TestAWSChunkedIsNotStoredAsContentEncoding(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)
	if !integration.ProxyIsTLS() {
		t.Skip("the SDK only frames requests as aws-chunked over HTTPS; run with S3EP_TEST_PROXY_ENDPOINT=https://...")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	payload := make([]byte, 64*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	key := fmt.Sprintf("content-encoding-%d", time.Now().UnixNano())
	_, err = tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(tc.TestBucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})

	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.NotContains(t, aws.ToString(head.ContentEncoding), "aws-chunked",
		"the request framing was recorded as the object encoding")

	// And the same on the backend, where the object actually lives.
	backendHead, err := tc.MinIOClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.NotContains(t, aws.ToString(backendHead.ContentEncoding), "aws-chunked",
		"the stored object carries aws-chunked as its Content-Encoding")
}

// A client-supplied encoding that is genuine must survive.
func TestRealContentEncodingIsPreserved(t *testing.T) {
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	tc := integration.NewTestContextWithTimeout(t, ctx)
	defer tc.CleanupTestBucket()

	key := fmt.Sprintf("gzip-encoding-%d", time.Now().UnixNano())
	_, err := tc.ProxyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(tc.TestBucket),
		Key:             aws.String(key),
		Body:            bytes.NewReader([]byte("pretend this is gzip")),
		ContentLength:   aws.Int64(20),
		ContentEncoding: aws.String("gzip"),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = tc.ProxyClient.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
		})
	})

	head, err := tc.ProxyClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(tc.TestBucket), Key: aws.String(key),
	})
	require.NoError(t, err)
	assert.Equal(t, "gzip", aws.ToString(head.ContentEncoding),
		"a genuine Content-Encoding must be preserved")
}
