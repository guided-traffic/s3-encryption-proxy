//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

// Endpoints. The proxy endpoint is overridable so the whole SDK-based suite can
// be run twice: once against the plain-HTTP listener and once against the TLS
// listener (docker-compose service s3-encryption-proxy-tls, port 8443).
//
// This matters for coverage, not just for completeness: aws-sdk-go-v2 only
// switches to STREAMING-UNSIGNED-PAYLOAD-TRAILER framing with checksum trailers
// when the request scheme is https. Over plain HTTP that framing is unreachable,
// which is exactly why BUG-001 survived a full integration run.
var (
	// MinIOEndpoint is the direct S3 backend, used for at-rest assertions.
	MinIOEndpoint = envOr("S3EP_TEST_MINIO_ENDPOINT", "https://127.0.0.1:9000")
	// ProxyEndpoint is the proxy under test.
	ProxyEndpoint = envOr("S3EP_TEST_PROXY_ENDPOINT", "http://127.0.0.1:8080")
	// ProxyTLSEndpoint is the proxy TLS listener, regardless of what
	// ProxyEndpoint currently points at.
	ProxyTLSEndpoint = envOr("S3EP_TEST_PROXY_TLS_ENDPOINT", "https://127.0.0.1:8443")
)

// Test configuration constants for MinIO and Proxy
const (
	MinIOAccessKey = "minioadmin"    // From docker-compose.demo.yml
	MinIOSecretKey = "minioadmin123" // From docker-compose.demo.yml

	// Proxy test credentials (must match s3_clients config in example files)
	ProxyTestAccessKey = "username0"               // From config/*.yaml s3_clients
	ProxyTestSecretKey = "this-is-not-very-secure" // From config/*.yaml s3_clients

	TestRegion = "us-east-1"

	// Test timeout configurations
	DefaultTestTimeout = 30 * time.Second // Default for regular tests (performance tests use custom timeout)
	BucketOpTimeout    = 10 * time.Second
)

// RandomString generates a random string of the specified length
func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to timestamp-based string if crypto/rand fails
		return fmt.Sprintf("%d", time.Now().UnixNano()%1000000)[:length]
	}

	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// TestContext holds common test utilities and clients
type TestContext struct {
	MinIOClient *s3.Client
	ProxyClient *s3.Client
	TestBucket  string
	T           *testing.T
	Ctx         context.Context
}

// NewTestContext creates a new test context with MinIO and Proxy clients
func NewTestContext(t *testing.T) *TestContext {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTestTimeout)
	t.Cleanup(cancel)

	minioClient, err := createMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Generate unique bucket name for this test
	testBucket := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

	tc := &TestContext{
		MinIOClient: minioClient,
		ProxyClient: proxyClient,
		TestBucket:  testBucket,
		T:           t,
		Ctx:         ctx,
	}

	// Ensure bucket is created and cleaned up
	tc.EnsureTestBucket()

	return tc
}

// NewTestContextWithTimeout creates a new test context with a custom timeout context
func NewTestContextWithTimeout(t *testing.T, ctx context.Context) *TestContext {
	t.Helper()

	minioClient, err := createMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Generate unique bucket name for this test
	testBucket := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())

	tc := &TestContext{
		MinIOClient: minioClient,
		ProxyClient: proxyClient,
		TestBucket:  testBucket,
		T:           t,
		Ctx:         ctx,
	}

	// Ensure bucket is created and cleaned up
	tc.EnsureTestBucket()

	return tc
}

// EnsureTestBucket creates the test bucket if it doesn't exist
func (tc *TestContext) EnsureTestBucket() {
	tc.T.Helper()

	// Create bucket via MinIO (direct)
	_, err := tc.MinIOClient.CreateBucket(tc.Ctx, &s3.CreateBucketInput{
		Bucket: aws.String(tc.TestBucket),
	})
	if err != nil && !strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") &&
		!strings.Contains(err.Error(), "BucketAlreadyExists") {
		require.NoError(tc.T, err, "Failed to create test bucket")
	}

	// Wait a moment for bucket to be ready
	time.Sleep(100 * time.Millisecond)
}

// CleanupTestBucket removes the test bucket and everything that can keep it
// alive. It is best effort by design — it runs from a defer on failing tests too
// — but it reports what it could not remove, which the version it replaced did
// not: it listed one page of objects, deleted them without a versionId and
// discarded every error, so a bucket that stayed behind was invisible. Five
// buckets per run of the s3-methods suite piled up in MinIO with nothing
// failing.
//
// Four things keep a bucket alive and all four are handled here: more than one
// page of objects, object versions and delete markers, a legal hold or a
// governance retention on a version, and an incomplete multipart upload.
func (tc *TestContext) CleanupTestBucket() {
	tc.T.Helper()
	PurgeBucket(tc.T, tc.MinIOClient, tc.TestBucket)
}

// PurgeBucket empties and removes a bucket. Exported so a test that creates a
// second bucket of its own does not write a third copy of this.
func PurgeBucket(t *testing.T, client *s3.Client, bucket string) {
	t.Helper()

	// Its own context: this runs from a defer, and the test's context may be
	// nearly out of budget by the time a failing test reaches it.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	purgeIncompleteUploads(ctx, client, bucket)
	purgeObjects(ctx, client, bucket)
	purgeVersions(ctx, client, bucket)

	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
		if isNoSuchBucket(err) {
			return
		}
		t.Logf("cleanup: %s stays behind: %v", bucket, err)
	}
}

// purgeIncompleteUploads aborts every open multipart upload. One of them is
// enough to make DeleteBucket answer BucketNotEmpty on a bucket that lists no
// objects at all.
func purgeIncompleteUploads(ctx context.Context, client *s3.Client, bucket string) {
	var keyMarker, uploadIDMarker *string
	for round := 0; round < 50; round++ {
		out, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket:         aws.String(bucket),
			KeyMarker:      keyMarker,
			UploadIdMarker: uploadIDMarker,
		})
		if err != nil {
			return
		}
		for _, upload := range out.Uploads {
			_, _ = client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket: aws.String(bucket), Key: upload.Key, UploadId: upload.UploadId,
			})
		}
		if !aws.ToBool(out.IsTruncated) {
			return
		}
		keyMarker, uploadIDMarker = out.NextKeyMarker, out.NextUploadIdMarker
	}
}

// purgeObjects deletes every object, page by page. The version it replaced took
// the first page only, so a bucket holding more than a thousand keys was never
// emptied.
func purgeObjects(ctx context.Context, client *s3.Client, bucket string) {
	for round := 0; round < 50; round++ {
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
		if err != nil || len(out.Contents) == 0 {
			return
		}
		ids := make([]types.ObjectIdentifier, 0, len(out.Contents))
		for _, object := range out.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: object.Key})
		}
		if _, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(bucket),
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		}); err != nil {
			return
		}
	}
}

// purgeVersions removes the versions and delete markers a versioned bucket keeps,
// releasing a legal hold and bypassing a governance retention on the way. A
// delete without a versionId writes a marker instead of removing anything, which
// is how a versioned bucket survived the old teardown twice over.
func purgeVersions(ctx context.Context, client *s3.Client, bucket string) {
	for round := 0; round < 50; round++ {
		out, err := client.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		if err != nil || (len(out.Versions) == 0 && len(out.DeleteMarkers) == 0) {
			return
		}
		for _, version := range out.Versions {
			_, _ = client.PutObjectLegalHold(ctx, &s3.PutObjectLegalHoldInput{
				Bucket: aws.String(bucket), Key: version.Key, VersionId: version.VersionId,
				LegalHold: &types.ObjectLockLegalHold{Status: types.ObjectLockLegalHoldStatusOff},
			})
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: version.Key, VersionId: version.VersionId,
				BypassGovernanceRetention: aws.Bool(true),
			})
		}
		for _, marker := range out.DeleteMarkers {
			_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket), Key: marker.Key, VersionId: marker.VersionId,
			})
		}
	}
}

func isNoSuchBucket(err error) bool {
	return strings.Contains(err.Error(), "NoSuchBucket")
}

// createMinIOClient creates an S3 client for the MinIO backend.
func createMinIOClient() (*s3.Client, error) {
	return NewS3Client(MinIOEndpoint, MinIOAccessKey, MinIOSecretKey)
}

// createProxyClient creates an S3 client for the proxy under test.
func createProxyClient() (*s3.Client, error) {
	return NewS3Client(ProxyEndpoint, ProxyTestAccessKey, ProxyTestSecretKey)
}

// init loads the repository's .env into this process. The example
// configurations reference ${S3EP_AES_KEY} and no usable key is tracked
// (ADR 0021); the containers get the variable from Docker Compose, which reads
// the same file, and the suites that start a proxy in-process would otherwise
// fail the configuration load. An already-set variable wins, so a caller can
// still override it.
func init() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}
	for i := 0; i < 6; i++ {
		if content, readErr := os.ReadFile(filepath.Join(dir, ".env")); readErr == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				name, value, found := strings.Cut(line, "=")
				if !found || os.Getenv(name) != "" {
					continue
				}
				_ = os.Setenv(name, value)
			}
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

// envOr returns the environment value for key, or def when it is unset.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ProxyIsTLS reports whether the suite currently talks to the proxy over TLS.
// Tests that assert on SDK framing behaviour branch on this.
func ProxyIsTLS() bool {
	return strings.HasPrefix(ProxyEndpoint, "https://")
}

// testCAPool loads the CA that signed the local test certificates by walking up
// from the working directory to test/ssl-setup/ca.crt. Returns nil when the file
// is not found, in which case the caller falls back to skipping verification.
func testCAPool() *x509.CertPool {
	caPoolOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			return
		}
		for i := 0; i < 6; i++ {
			candidate := filepath.Join(dir, "test", "ssl-setup", "ca.crt")
			if pem, readErr := os.ReadFile(candidate); readErr == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(pem) {
					caPool = pool
				}
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return
			}
			dir = parent
		}
	})
	return caPool
}

var (
	caPoolOnce sync.Once
	caPool     *x509.CertPool
)

// tlsHTTPClient builds an HTTP client that trusts the local test CA. It falls
// back to skipping verification only when the CA file cannot be located, so a
// broken or expired certificate still fails the suite in the normal case.
func tlsHTTPClient() *http.Client {
	transport := &http.Transport{
		MaxIdleConnsPerHost: 64,
	}
	if pool := testCAPool(); pool != nil {
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	} else {
		// #nosec G402 - local test infrastructure only, and only when the CA
		// bundle produced by test/ssl-setup/gen-certs.sh is unavailable.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute}
}

// NewS3Client builds an S3 client for an arbitrary endpoint with the given
// credentials. It is the single place that knows how to talk to the local test
// infrastructure over TLS.
func NewS3Client(endpoint, accessKey, secretKey string) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithRegion(TestRegion),
		config.WithHTTPClient(tlsHTTPClient()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
	}), nil
}

// NewProxyTLSClient returns a client bound to the proxy TLS listener, whatever
// ProxyEndpoint is set to. Use it for tests that must exercise the SDK checksum
// trailer path explicitly.
func NewProxyTLSClient() (*s3.Client, error) {
	return NewS3Client(ProxyTLSEndpoint, ProxyTestAccessKey, ProxyTestSecretKey)
}

// TLSHTTPClient exposes the CA-trusting HTTP client for tests that build raw
// requests instead of going through the SDK.
func TLSHTTPClient() *http.Client { return tlsHTTPClient() }

// SkipIfMinIONotAvailable checks if MinIO is available and skips test if not
func SkipIfMinIONotAvailable(t *testing.T) {
	t.Helper()

	client, err := createMinIOClient()
	if err != nil {
		t.Skipf("MinIO not available: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Skipf("MinIO not responding: %v", err)
	}
}

// SkipIfProxyNotAvailable checks if the encryption proxy is available and skips test if not
func SkipIfProxyNotAvailable(t *testing.T) {
	t.Helper()

	client, err := createProxyClient()
	if err != nil {
		t.Skipf("Proxy not available: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Skipf("Proxy not responding: %v", err)
	}
}

// CompareObjectData compares object data between two S3 clients without verbose output
func CompareObjectData(t *testing.T, client1, client2 *s3.Client, bucket, key string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), BucketOpTimeout)
	defer cancel()

	// Get object from first client
	resp1, err := client1.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object from first client")
	defer resp1.Body.Close()

	// Get object from second client
	resp2, err := client2.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to get object from second client")
	defer resp2.Body.Close()

	// Read data from both responses
	data1 := make([]byte, 1024)
	n1, _ := resp1.Body.Read(data1)
	data1 = data1[:n1]

	data2 := make([]byte, 1024)
	n2, _ := resp2.Body.Read(data2)
	data2 = data2[:n2]

	// Compare data lengths and content using SHA256 hash to avoid hexdumps
	require.Equal(t, n1, n2, "Object data lengths don't match")

	hash1 := sha256.Sum256(data1)
	hash2 := sha256.Sum256(data2)
	require.Equal(t, hash1, hash2, "Object data content doesn't match - SHA256 hash verification failed")
}

// IsMinIOAvailable checks if MinIO service is running and available (deprecated)
func IsMinIOAvailable() bool {
	client, err := createMinIOClient()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

// IsProxyAvailable checks if the S3 encryption proxy is running and available (deprecated)
func IsProxyAvailable() bool {
	client, err := createProxyClient()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = client.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err == nil
}

// CreateMinIOClient creates an S3 client configured for MinIO (deprecated)
func CreateMinIOClient() (*s3.Client, error) {
	return createMinIOClient()
}

// CreateProxyClient creates an S3 client configured for the proxy (deprecated)
func CreateProxyClient() (*s3.Client, error) {
	return createProxyClient()
}

// EnsureMinIOAndProxyAvailable skips the test if either MinIO or proxy are not available
func EnsureMinIOAndProxyAvailable(t *testing.T) {
	SkipIfMinIONotAvailable(t)
	SkipIfProxyNotAvailable(t)
}

// EnsureMinIOAvailable skips the test if MinIO is not available (for tests that start their own proxy)
func EnsureMinIOAvailable(t *testing.T) {
	SkipIfMinIONotAvailable(t)
}

// CreateTestBucket creates a test bucket in MinIO (idempotent)
func CreateTestBucket(t *testing.T, client *s3.Client, bucketName string) {
	ctx := context.Background()

	// Try to create bucket (ignore error if it already exists)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})

	// Ignore "BucketAlreadyExists" errors
	if err != nil && !IsAlreadyExistsError(err) {
		t.Logf("Warning: Could not create test bucket %s: %v", bucketName, err)
	}
}

// CleanupTestBucket removes all objects and deletes the test bucket
func CleanupTestBucket(t *testing.T, client *s3.Client, bucketName string) {
	ctx := context.Background()

	// List and delete all objects in bucket
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err == nil && len(listResp.Contents) > 0 {
		for _, obj := range listResp.Contents {
			_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucketName),
				Key:    obj.Key,
			})
			if err != nil {
				t.Logf("Warning: Could not delete object %s: %v", *obj.Key, err)
			}
		}
	}

	// Delete the bucket itself
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Logf("Warning: Could not delete test bucket %s: %v", bucketName, err)
	}
}

// IsAlreadyExistsError checks if an error indicates the resource already exists
func IsAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errorStr := err.Error()
	return strings.Contains(errorStr, "BucketAlreadyExists") ||
		strings.Contains(errorStr, "BucketAlreadyOwnedByYou") ||
		strings.Contains(errorStr, "already exists")
}

// CreateProxyClientWithEndpoint creates an S3 client for a custom proxy endpoint
func CreateProxyClientWithEndpoint(endpoint string) (*s3.Client, error) {
	return NewS3Client(endpoint, ProxyTestAccessKey, ProxyTestSecretKey)
}

// WaitForHealthCheck waits for the health endpoint to become available
func WaitForHealthCheck(t *testing.T, endpoint string) {
	t.Helper()

	ready := false
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		resp, err := tlsHTTPClient().Get(endpoint + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
	}
	require.True(t, ready, "Proxy server did not become ready in time")
}

// SetupTestBucket creates or cleans up a test bucket for consistent testing
func SetupTestBucket(t *testing.T, ctx context.Context, client *s3.Client, bucketName string) {
	t.Helper()

	t.Logf("Setting up test bucket: %s", bucketName)

	// Try to create the bucket (may already exist)
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		// Bucket might already exist, that's OK
		t.Logf("Note: Could not create bucket %s (may already exist): %v", bucketName, err)
	}

	// Clear existing objects in the bucket for clean testing (but keep the bucket)
	t.Logf("Cleaning existing objects in bucket: %s", bucketName)
	ClearBucketObjects(t, ctx, client, bucketName)

	t.Logf("✅ Test bucket ready: %s", bucketName)
}

// ClearBucketObjects removes all objects from a bucket but keeps the bucket itself
func ClearBucketObjects(t *testing.T, ctx context.Context, client *s3.Client, bucketName string) {
	t.Helper()

	// List and delete all objects in bucket
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		t.Logf("Note: Could not list objects in bucket %s: %v", bucketName, err)
		return
	}

	if len(listResp.Contents) == 0 {
		t.Logf("Bucket %s is already empty", bucketName)
		return
	}

	t.Logf("Deleting %d existing objects from bucket %s", len(listResp.Contents), bucketName)
	for _, obj := range listResp.Contents {
		_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    obj.Key,
		})
		if err != nil {
			t.Logf("Warning: Could not delete object %s: %v", *obj.Key, err)
		}
	}
}
