//go:build integration
// +build integration

package integration

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc"
)

// The proxy and the library must agree on every byte and every metadata key:
// each one reads what the other wrote, at sizes that take the proxy's single
// request path and its internal multipart producer (above 12 MiB). The proxy is
// whichever endpoint the run points at, so the TLS run covers its aws-chunked
// trailer path too.
var interopSizes = []int64{0, 65537, 13<<20 + 3}

func TestProxyReadsWhatTheLibraryWrote(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: proxyKey(t)})
	px := s.proxy

	for _, n := range interopSizes {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key := objectKey(t, "from-library.bin")
			plain := randomBytes(t, n)
			res, err := c.Put(ctx, s.bucket, key, bytes.NewReader(plain), nil)
			if err != nil {
				t.Fatal(err)
			}

			head, err := px.HeadObject(ctx, &s3.HeadObjectInput{
				Bucket: aws.String(s.bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled,
			})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToInt64(head.ContentLength) != n || aws.ToString(head.ChecksumCRC32C) != res.CRC32C {
				t.Fatalf("proxy HEAD: length %d crc %q, want %d %q",
					aws.ToInt64(head.ContentLength), aws.ToString(head.ChecksumCRC32C), n, res.CRC32C)
			}

			out, err := px.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(out.Body)
			_ = out.Body.Close()
			if err != nil || digest(got) != digest(plain) {
				t.Fatalf("proxy GET: %d bytes, err %v", len(got), err)
			}

			if n > 65540 {
				out, err := px.GetObject(ctx, &s3.GetObjectInput{
					Bucket: aws.String(s.bucket), Key: aws.String(key), Range: aws.String("bytes=65530-65540"),
				})
				if err != nil {
					t.Fatal(err)
				}
				got, err := io.ReadAll(out.Body)
				_ = out.Body.Close()
				if err != nil || digest(got) != digest(plain[65530:65541]) {
					t.Fatalf("proxy ranged GET: %d bytes, err %v", len(got), err)
				}
			}
		})
	}
}

func TestLibraryReadsWhatTheProxyWrote(t *testing.T) {
	s := newStack(t)
	ctx := s.ctx
	c := s.client(t, s3enc.Options{ActiveKey: proxyKey(t)})
	px := s.proxy

	for _, n := range interopSizes {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			key := objectKey(t, "from-proxy.bin")
			plain := randomBytes(t, n)
			_, err := px.PutObject(ctx, &s3.PutObjectInput{
				Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(plain),
				Metadata: map[string]string{"owner": "proxy"},
			})
			if err != nil {
				t.Fatal(err)
			}

			info, err := c.Stat(ctx, s.bucket, key)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size != n || info.CRC32C != crc32cBase64(plain) || info.Metadata["owner"] != "proxy" {
				t.Fatalf("stat = %+v", info)
			}

			obj, err := c.Get(ctx, s.bucket, key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := readObject(obj)
			if err != nil || digest(got) != digest(plain) {
				t.Fatalf("get: %d bytes, err %v", len(got), err)
			}

			if n > 65540 {
				obj, err := c.GetRange(ctx, s.bucket, key, 65530, 11)
				if err != nil {
					t.Fatal(err)
				}
				got, err := readObject(obj)
				if err != nil || digest(got) != digest(plain[65530:65541]) {
					t.Fatalf("range: %d bytes, err %v", len(got), err)
				}
			}
		})
	}
}
