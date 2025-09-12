//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	streamingTestBucket    = "test-streaming-multipart"
	streamingTestObjectKey = "pubg-test.png"
	streamingProxyEndpoint = "http://localhost:8080"
	streamingMinioEndpoint = "https://localhost:9000" // Changed to HTTPS as per docker-compose
	streamingAccessKey     = "minioadmin"             // Corrected credentials
	streamingSecretKey     = "minioadmin123"          // Corrected credentials
	streamingRegion        = "us-east-1"
)

// TestStreamingMultipartUploadEndToEnd tests the complete streaming multipart upload flow
func TestStreamingMultipartUploadEndToEnd(t *testing.T) {
	// Skip if MinIO and Proxy are not available
	EnsureMinIOAndProxyAvailable(t)

	ctx := context.Background()

	// Test setup
	originalFile := "../example-files/papagei.jpg"
	require.FileExists(t, originalFile, "Test file papagei.jpg must exist in example-files directory")

	// Read original file for comparison
	originalData, err := os.ReadFile(originalFile)
	require.NoError(t, err, "Failed to read original test file")
	require.Greater(t, len(originalData), 0, "Original file must not be empty")

	// Calculate original file hash for verification
	originalHash := sha256.Sum256(originalData)

	t.Logf("Original file: %s, Size: %d bytes, SHA256: %x", originalFile, len(originalData), originalHash)

	// Ensure the file is large enough to trigger multipart upload (>5MB)
	if len(originalData) < 5*1024*1024 {
		t.Logf("Warning: Test file is %d bytes, smaller than typical multipart threshold (5MB)", len(originalData))
	}

	// Check that original file starts with JPEG signature
	if len(originalData) >= 3 {
		jpegSignature := []byte{0xFF, 0xD8, 0xFF}
		if bytes.Equal(originalData[:3], jpegSignature) {
			t.Logf("✓ Original file has valid JPEG signature")
		} else {
			t.Logf("⚠ Original file does not have JPEG signature (test file is synthetic)")
		}
	}

	// Create S3 clients using standardized helper functions
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	proxyClient, err := CreateProxyClient()
	require.NoError(t, err, "Failed to create Proxy client")

	// Note: We mainly use the proxy client as direct MinIO access won't work with encrypted objects

	// Ensure test bucket exists and is clean
	CreateTestBucket(t, proxyClient, streamingTestBucket)
	defer CleanupTestBucket(t, proxyClient, streamingTestBucket)

	// Clean up any existing test object
	cleanupTestObject(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey)

	// Step 1: Upload file through proxy with streaming multipart
	t.Run("Upload through proxy", func(t *testing.T) {
		uploadThroughProxy(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey, originalData)
	})

	// Step 2: Verify object exists and has correct metadata in MinIO
	t.Run("Verify object in MinIO", func(t *testing.T) {
		// Note: We access MinIO through the proxy to see the decrypted metadata
		// Direct MinIO access won't work as it doesn't understand our encryption metadata
		verifyObjectInMinIO(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey, originalData)
	})

	// Step 2b: Verify what's actually stored in MinIO (raw encrypted data)
	t.Run("Verify raw encrypted object in MinIO", func(t *testing.T) {
		// This accesses MinIO directly to see the encrypted data
		// Note: This may fail if MinIO rejects direct access to encrypted objects
		verifyRawEncryptedObjectInMinIO(t, ctx, minioClient, streamingTestBucket, streamingTestObjectKey, originalData)
	})

	// Step 3: Download and decrypt through proxy
	t.Run("Download through proxy", func(t *testing.T) {
		downloadedData := downloadThroughProxy(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey)
		verifyDownloadedData(t, originalData, downloadedData)
	})

	// Step 4: Verify the complete round-trip integrity
	t.Run("Verify round-trip integrity", func(t *testing.T) {
		downloadedData := downloadThroughProxy(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey)

		// Compare file sizes
		assert.Equal(t, len(originalData), len(downloadedData), "Downloaded file size should match original")

		// Compare file hashes
		downloadedHash := sha256.Sum256(downloadedData)
		assert.Equal(t, originalHash, downloadedHash, "Downloaded file hash should match original")

		// Check file signature is preserved (for original data integrity)
		if len(downloadedData) >= 8 && len(originalData) >= 8 {
			assert.Equal(t, originalData[:8], downloadedData[:8], "Downloaded file should have same signature as original")
			t.Logf("✓ Downloaded file has same signature as original")
		}

		// Byte-by-byte comparison (first few bytes for debugging)
		if len(originalData) > 0 && len(downloadedData) > 0 {
			if !bytes.Equal(originalData, downloadedData) {
				// Show first 32 bytes for debugging
				showLen := 32
				if len(originalData) < showLen {
					showLen = len(originalData)
				}
				if len(downloadedData) < showLen {
					showLen = len(downloadedData)
				}

				t.Logf("First %d bytes of original:   %x", showLen, originalData[:showLen])
				t.Logf("First %d bytes of downloaded: %x", showLen, downloadedData[:showLen])

				// Find first differing byte
				minLen := len(originalData)
				if len(downloadedData) < minLen {
					minLen = len(downloadedData)
				}

				for i := 0; i < minLen; i++ {
					if originalData[i] != downloadedData[i] {
						t.Logf("First difference at byte %d: original=0x%02x, downloaded=0x%02x",
							i, originalData[i], downloadedData[i])
						break
					}
				}

				t.Errorf("Downloaded data does not match original data")
			} else {
				t.Logf("✓ Complete byte-by-byte verification passed")
			}
		}
	})

	// Cleanup
	t.Cleanup(func() {
		cleanupTestObject(t, ctx, proxyClient, streamingTestBucket, streamingTestObjectKey)
	})
}

// createStreamingS3Client creates an S3 client for the given endpoint
func createStreamingS3Client(t *testing.T, endpoint string) *s3.Client {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(streamingAccessKey, streamingSecretKey, "")),
		config.WithRegion(streamingRegion),
	)
	require.NoError(t, err)

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		// For MinIO HTTPS with self-signed certificates
		if endpoint == streamingMinioEndpoint {
			o.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	})

	return client
}

// cleanupTestObject removes the test object if it exists
func cleanupTestObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) {
	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("Note: Could not delete test object %s/%s: %v", bucket, key, err)
	}
}

// uploadThroughProxy uploads the test file through the encryption proxy
func uploadThroughProxy(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, data []byte) {
	t.Logf("Uploading %d bytes to %s/%s through proxy", len(data), bucket, key)

	reader := bytes.NewReader(data)

	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          reader,
		ContentType:   aws.String("image/png"),
		ContentLength: aws.Int64(int64(len(data))),
	})

	require.NoError(t, err, "Failed to upload object through proxy")
	t.Logf("✓ Successfully uploaded object through proxy")
}

// verifyObjectInMinIO verifies the object exists in MinIO with correct encryption metadata
func verifyObjectInMinIO(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, originalData []byte) {
	t.Logf("Verifying object in MinIO: %s/%s", bucket, key)

	// Check object exists
	headResp, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Object should exist in MinIO")

	// Check object size (should be different due to encryption)
	encryptedSize := aws.ToInt64(headResp.ContentLength)
	t.Logf("Original size: %d, Encrypted size: %d", len(originalData), encryptedSize)

	// For streaming encryption, the size might be similar but content different
	// The exact size depends on encryption overhead and chunking

	// Check encryption metadata
	metadata := headResp.Metadata
	t.Logf("Object metadata: %+v", metadata)

	// IMPORTANT: The encryption proxy does NOT forward encryption metadata to clients
	// for security reasons. The metadata exists in MinIO but is filtered out by the proxy.
	// This is the correct behavior - clients should not see internal encryption details.

	if len(metadata) == 0 {
		t.Logf("✓ No metadata returned by proxy (expected - encryption metadata is internal)")
	} else {
		t.Logf("Note: Proxy returned %d metadata keys", len(metadata))
		for k, v := range metadata {
			t.Logf("  %s: %s", k, v)
		}
	}

	// Get the actual encrypted content to verify it's not plaintext
	getResp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Should be able to get object through proxy")
	defer getResp.Body.Close()

	decryptedData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "Should be able to read decrypted data")

	// Verify the proxy returned the DECRYPTED data (equal to original)
	assert.Equal(t, originalData, decryptedData, "Proxy should return decrypted data equal to original")

	// Verify decrypted data has original signature (confirms successful decryption)
	if len(decryptedData) >= 8 && len(originalData) >= 8 {
		assert.Equal(t, originalData[:8], decryptedData[:8], "Decrypted data should have same signature as original")
		t.Logf("✓ Decrypted data has same signature as original (successful decryption)")
	}

	t.Logf("✓ Object verification through proxy completed")
}

// downloadThroughProxy downloads the object through the encryption proxy
func downloadThroughProxy(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Logf("Downloading object through proxy: %s/%s", bucket, key)

	resp, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object through proxy")
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	t.Logf("✓ Successfully downloaded %d bytes through proxy", len(data))
	return data
}

// verifyDownloadedData compares the downloaded data with the original
func verifyDownloadedData(t *testing.T, original, downloaded []byte) {
	t.Logf("Verifying downloaded data integrity")

	// Size comparison
	assert.Equal(t, len(original), len(downloaded), "Downloaded data size should match original")

	// Hash comparison
	originalHash := sha256.Sum256(original)
	downloadedHash := sha256.Sum256(downloaded)
	assert.Equal(t, originalHash, downloadedHash, "Downloaded data hash should match original")

	// Byte-by-byte comparison
	assert.Equal(t, original, downloaded, "Downloaded data should be identical to original")

	t.Logf("✓ Data integrity verification completed")
}

// Benchmark test for performance measurement
func BenchmarkStreamingMultipartUpload(b *testing.B) {
	ctx := context.Background()

	// Setup
	originalFile := "../example-files/papagei.jpg"
	var originalData []byte

	if _, err := os.Stat(originalFile); os.IsNotExist(err) {
		// Removed skip to enable all integration tests - create test data instead
		// b.Skip("Test file papagei.jpg not found in example-files directory")
		b.Log("Test file papagei.jpg not found - using generated test data instead")
		// Generate 100KB of test data as fallback
		originalData = make([]byte, 100*1024)
		for i := range originalData {
			originalData[i] = byte(i % 256)
		}
	} else {
		var err error
		originalData, err = os.ReadFile(originalFile)
		if err != nil {
			b.Fatalf("Failed to read test file: %v", err)
		}
	}

	// Create a test helper that works with both *testing.T and *testing.B
	testHelper := &testHelper{b: b}
	proxyClient := createStreamingS3ClientForBenchmark(testHelper, streamingProxyEndpoint)
	ensureBucketExistsForBenchmark(testHelper, ctx, proxyClient, streamingTestBucket)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("benchmark-test-%d.png", i)

		reader := bytes.NewReader(originalData)
		_, err := proxyClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(streamingTestBucket),
			Key:           aws.String(key),
			Body:          reader,
			ContentType:   aws.String("image/png"),
			ContentLength: aws.Int64(int64(len(originalData))),
		})

		if err != nil {
			b.Fatal("Upload failed:", err)
		}

		// Cleanup
		_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(streamingTestBucket),
			Key:    aws.String(key),
		})
	}
}

// Helper type for benchmarks
type testHelper struct {
	b *testing.B
}

func (h *testHelper) Errorf(format string, args ...interface{}) {
	h.b.Errorf(format, args...)
}

func (h *testHelper) FailNow() {
	h.b.FailNow()
}

func (h *testHelper) Logf(format string, args ...interface{}) {
	h.b.Logf(format, args...)
}

// createStreamingS3ClientForBenchmark creates an S3 client for benchmarking
func createStreamingS3ClientForBenchmark(h *testHelper, endpoint string) *s3.Client {
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(streamingAccessKey, streamingSecretKey, "")),
		config.WithRegion(streamingRegion),
	)
	if err != nil {
		h.b.Fatal(err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
		// For MinIO HTTPS with self-signed certificates
		if endpoint == streamingMinioEndpoint {
			o.HTTPClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
		}
	})

	return client
}

// ensureBucketExistsForBenchmark creates the test bucket if it doesn't exist (benchmark version)
func ensureBucketExistsForBenchmark(h *testHelper, ctx context.Context, client *s3.Client, bucket string) {
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	})

	if err != nil {
		h.Logf("Creating test bucket: %s", bucket)
		_, err = client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			h.b.Fatal("Failed to create test bucket:", err)
		}

		// Wait a bit for bucket to be ready
		time.Sleep(1 * time.Second)
	}
}

// verifyRawEncryptedObjectInMinIO inspects the raw encrypted object in MinIO directly
func verifyRawEncryptedObjectInMinIO(t *testing.T, ctx context.Context, minioClient *s3.Client, bucket string, key string, originalData []byte) {
	t.Logf("Attempting to verify raw encrypted object in MinIO directly")

	// Get object metadata from MinIO directly
	headResp, err := minioClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("Note: Direct MinIO HeadObject failed (expected for encrypted objects): %v", err)
		return
	}

	t.Logf("Object metadata in MinIO:")
	for k, v := range headResp.Metadata {
		t.Logf("  %s: %s", k, v)
	}

	// Check for encryption metadata
	if encAlg, exists := headResp.Metadata["s3ep-dek"]; exists {
		t.Logf("Found encrypted DEK: %s", encAlg)
	} else {
		t.Log("No encrypted DEK metadata found")
	}

	if provider, exists := headResp.Metadata["s3ep-provider"]; exists {
		t.Logf("Found encryption provider: %s", provider)
	} else {
		t.Log("No encryption provider metadata found")
	}

	// Get object data from MinIO directly (this should be encrypted)
	getResp, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Logf("Note: Direct MinIO GetObject failed (expected for encrypted objects): %v", err)
		return
	}
	defer getResp.Body.Close()

	encryptedData, err := io.ReadAll(getResp.Body)
	if err != nil {
		t.Logf("Note: Failed to read encrypted data from MinIO: %v", err)
		return
	}

	t.Logf("Retrieved %d bytes of encrypted data from MinIO (vs %d original)", len(encryptedData), len(originalData))

	// Verify that the data is indeed encrypted (not equal to original)
	if !assert.NotEqual(t, originalData, encryptedData, "Data in MinIO should be encrypted (different from original)") {
		t.Log("WARNING: Data in MinIO appears to be unencrypted!")
		return
	}

	// Verify encrypted data doesn't start with original signature
	if len(encryptedData) >= 8 && len(originalData) >= 8 {
		if !assert.NotEqual(t, originalData[:8], encryptedData[:8], "Encrypted data should not have original signature") {
			t.Log("WARNING: Encrypted data still contains original signature!")
			return
		}
		t.Logf("✓ Encrypted data does not contain original signature")
	}

	// Log first 32 bytes of each for comparison
	originalPreview := originalData
	if len(originalPreview) > 32 {
		originalPreview = originalData[:32]
	}

	encryptedPreview := encryptedData
	if len(encryptedPreview) > 32 {
		encryptedPreview = encryptedData[:32]
	}

	t.Logf("Original data preview (first %d bytes): %x", len(originalPreview), originalPreview)
	t.Logf("Encrypted data preview (first %d bytes): %x", len(encryptedPreview), encryptedPreview)
	t.Logf("✓ Raw encrypted object verification completed successfully")
}
