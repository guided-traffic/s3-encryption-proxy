//go:build e2e

package harness

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// This file is the part of the harness that knows nothing about where a stack
// lives. Everything here takes the client and the bucket it should use, which is
// what lets the Velero suite — whose proxy and backend are Services in a kind
// cluster, not the demo compose stack — share it. The demo-stack-flavoured
// helpers, which resolve their own coordinates, are in backend.go and are used
// only by the client suites.

// StoredObject is one object as the backend sees it: the stored length, the
// entity tag the backend computed over the stored bytes, and the user metadata
// the proxy attached.
type StoredObject struct {
	Key      string
	Size     int64
	ETag     string
	Metadata map[string]string
}

// ListStored returns every object of a bucket under prefix, as stored. The
// client must be one that talks to the backend directly: reading through the
// proxy would prove nothing about what is on disk.
func ListStored(t *testing.T, ctx context.Context, client *s3.Client, bucket, prefix string) []StoredObject {
	t.Helper()

	var objects []StoredObject
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		require.NoErrorf(t, err, "listing %s/%s on the backend", bucket, prefix)
		for _, obj := range page.Contents {
			head, headErr := client.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(bucket), Key: obj.Key,
			})
			require.NoErrorf(t, headErr, "HeadObject %s", aws.ToString(obj.Key))
			objects = append(objects, StoredObject{
				Key:      aws.ToString(obj.Key),
				Size:     aws.ToInt64(obj.Size),
				ETag:     strings.Trim(aws.ToString(head.ETag), `"`),
				Metadata: head.Metadata,
			})
		}
	}
	return objects
}

// ReadStored returns the raw stored bytes of an object, ciphertext included.
func ReadStored(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key),
	})
	require.NoErrorf(t, err, "GetObject %s from the backend", key)
	defer func() { _ = out.Body.Close() }()
	data, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	return data
}

// MetadataValue returns a proxy metadata value by suffix, ignoring case: S3
// lower-cases user metadata keys on the way through.
func MetadataValue(meta map[string]string, prefix, suffix string) (string, bool) {
	want := strings.ToLower(prefix + suffix)
	for k, v := range meta {
		if strings.ToLower(k) == want {
			return v, true
		}
	}
	return "", false
}

// UserMetadata returns the object's metadata keys that are not the proxy's, so
// a suite can assert that a client's own annotation survived the round trip
// (rclone's md5chksum, s3cmd's s3cmd-attrs).
func UserMetadata(meta map[string]string, proxyPrefix string) map[string]string {
	out := map[string]string{}
	for k, v := range meta {
		if strings.HasPrefix(strings.ToLower(k), strings.ToLower(proxyPrefix)) {
			continue
		}
		out[strings.ToLower(k)] = v
	}
	return out
}
