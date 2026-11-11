//go:build integration
// +build integration

// Package integration runs the client library against the demo stack: against
// MinIO directly, the way an application uses it, and against the proxy, which
// has to read every object the library writes and the other way round
// (ADR 0041).
package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/encryption/storedobject"
	"github.com/guided-traffic/s3-encryption-proxy/v5/pkg/s3enc"
	. "github.com/guided-traffic/s3-encryption-proxy/v5/test/integration"
)

// stack is one test's view of the demo stack: a fresh bucket, the backend
// client an attacker on the storage would hold, and the proxy client.
type stack struct {
	ctx     context.Context
	bucket  string
	backend *s3.Client
	proxy   *s3.Client
}

func newStack(t *testing.T) *stack {
	t.Helper()
	tc := NewTestContext(t)
	t.Cleanup(tc.CleanupTestBucket)
	return &stack{ctx: context.Background(), bucket: tc.TestBucket, backend: tc.MinIOClient, proxy: tc.ProxyClient}
}

// client is the library on top of the backend client.
func (s *stack) client(t *testing.T, opts s3enc.Options) *s3enc.Client {
	t.Helper()
	c, err := s3enc.New(s.backend, opts)
	require.NoError(t, err)
	return c
}

// proxyKey is the AES key the demo stack's proxy runs with; the integration
// package loads it from the repository's .env (ADR 0021).
func proxyKey(t *testing.T) string {
	t.Helper()
	key := os.Getenv("S3EP_AES_KEY")
	require.NotEmpty(t, key, "S3EP_AES_KEY is not set; ./start-demo.sh writes it to .env")
	return key
}

func randomKey(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(randomBytes(t, 32))
}

func objectKey(t *testing.T, name string) string {
	return fmt.Sprintf("%s/%d/%s", strings.ReplaceAll(t.Name(), "/", "_"), time.Now().UnixNano(), name)
}

func randomBytes(t *testing.T, n int64) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func crc32cBase64(b []byte) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	return base64.StdEncoding.EncodeToString(raw[:])
}

// formatKeys counts the stored metadata keys inside the default namespace.
func formatKeys(md map[string]string) int {
	n := 0
	for k := range md {
		if storedobject.IsReserved(storedobject.DefaultPrefix, k) {
			n++
		}
	}
	return n
}

// unknownLength hides Len and Seek, so the upload cannot learn the size.
type unknownLength struct{ io.Reader }

func (s *stack) rawGet(t *testing.T, key string) ([]byte, map[string]string) {
	t.Helper()
	out, err := s.backend.GetObject(s.ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	require.NoError(t, err)
	defer func() { _ = out.Body.Close() }()
	b, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	return b, out.Metadata
}

func (s *stack) rawPut(t *testing.T, key string, body []byte, md map[string]string) {
	t.Helper()
	_, err := s.backend.PutObject(s.ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(body), Metadata: md,
	})
	require.NoError(t, err)
}

func (s *stack) exists(t *testing.T, key string) bool {
	t.Helper()
	_, err := s.backend.HeadObject(s.ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	var notFound *types.NotFound
	if errors.As(err, &notFound) {
		return false
	}
	require.NoError(t, err)
	return true
}

// readObject reads o to the end and returns the error the end produced.
func readObject(o *s3enc.Object) ([]byte, error) {
	defer func() { _ = o.Close() }()
	return io.ReadAll(o)
}
