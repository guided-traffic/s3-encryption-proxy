//go:build integration
// +build integration

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
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
	chunkedTestBucket = "test-chunked-encoding"
	chunkedTestKey    = "chunked-test-file.txt"
)

// TestAWSChunkedEncodingIntegration tests AWS Signature V4 chunked encoding with the proxy
func TestAWSChunkedEncodingIntegration(t *testing.T) {
	ctx := context.Background()

	// Skip if services are not available
	SkipIfProxyNotAvailable(t)

	// Create proxy client using existing helper
	proxyClient, err := createProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Ensure test bucket exists using existing helper
	CreateTestBucket(t, proxyClient, chunkedTestBucket)

	// Clean up any existing test object (simple implementation)
	_, err = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(chunkedTestBucket),
		Key:    aws.String(chunkedTestKey),
	})
	// Ignore errors - object might not exist

	t.Run("Test chunked encoding upload and download", func(t *testing.T) {
		// Test data - use a known string to verify integrity
		testData := "This is test data for AWS Signature V4 chunked encoding. " +
			"The data should be transmitted in chunks with signatures and " +
			"then properly decrypted by the proxy server. " +
			"Let's make this longer to ensure multiple chunks are created. " +
			strings.Repeat("CHUNK_DATA_", 100) // Make it longer for multiple chunks

		// Upload with chunked encoding
		uploadWithChunkedEncoding(t, ctx, chunkedTestBucket, chunkedTestKey, testData)

		// Download and verify
		downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, chunkedTestKey)
		verifyDataMatches(t, []byte(testData), downloadedData)
	})

	t.Run("Test multiple chunk sizes", func(t *testing.T) {
		testCases := []struct {
			name      string
			chunkSize int
			dataSize  int
		}{
			{"Small chunks with small data", 10, 50},
			{"Small chunks with medium data", 32, 500},
			{"Medium chunks with large data", 128, 2000},
			{"Large chunks with small data", 512, 100},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Generate test data
				testData := strings.Repeat("X", tc.dataSize)
				testKey := fmt.Sprintf("chunked-test-%s.txt", strings.ReplaceAll(tc.name, " ", "-"))

				// Clean up using simple delete
				proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(chunkedTestBucket),
					Key:    aws.String(testKey),
				})

				// Upload with specific chunk size
				uploadWithChunkedEncodingAndChunkSize(t, ctx, chunkedTestBucket, testKey, testData, tc.chunkSize)

				// Download and verify
				downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
				verifyDataMatches(t, []byte(testData), downloadedData)

				// Clean up using simple delete
				proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(chunkedTestBucket),
					Key:    aws.String(testKey),
				})
			})
		}
	})

	t.Run("Test edge cases", func(t *testing.T) {
		edgeCases := []struct {
			name string
			data string
		}{
			{"Empty data", ""},
			{"Single character", "X"},
			{"Exact chunk boundary", strings.Repeat("A", 64)}, // Common chunk size
			{"Binary data", string([]byte{0x00, 0x01, 0xFF, 0xFE, 0x89, 0x50, 0x4E, 0x47})},
			{"Unicode data", "Hello 世界 🌍 Tëst"},
		}

		for _, tc := range edgeCases {
			t.Run(tc.name, func(t *testing.T) {
				testKey := fmt.Sprintf("chunked-edge-%s.bin", strings.ReplaceAll(tc.name, " ", "-"))

				// Clean up using simple delete
				proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(chunkedTestBucket),
					Key:    aws.String(testKey),
				})

				if len(tc.data) > 0 { // Skip upload for empty data
					// Upload with chunked encoding
					uploadWithChunkedEncoding(t, ctx, chunkedTestBucket, testKey, tc.data)

					// Download and verify
					downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
					verifyDataMatches(t, []byte(tc.data), downloadedData)
				}

				// Clean up using simple delete
				proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(chunkedTestBucket),
					Key:    aws.String(testKey),
				})
			})
		}
	})

	// Clean up bucket using existing helper
	t.Cleanup(func() {
		CleanupTestBucket(t, proxyClient, chunkedTestBucket)
	})
}

// uploadWithChunkedEncoding uploads data using AWS Signature V4 chunked encoding
func uploadWithChunkedEncoding(t *testing.T, ctx context.Context, bucket, key, data string) {
	uploadWithChunkedEncodingAndChunkSize(t, ctx, bucket, key, data, 64) // Default 64 byte chunks
}

// uploadWithChunkedEncodingAndChunkSize uploads data using AWS Signature V4 chunked encoding with specific chunk size
func uploadWithChunkedEncodingAndChunkSize(t *testing.T, ctx context.Context, bucket, key, data string, chunkSize int) {
	t.Helper()

	// Create chunked encoded body
	chunkedBody := createAWSChunkedEncodedBody(data, chunkSize)

	// Create HTTP request directly to proxy
	url := fmt.Sprintf("%s/%s/%s", ProxyEndpoint, bucket, key)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(chunkedBody))
	require.NoError(t, err, "Failed to create HTTP request")

	// Set headers for chunked encoding
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))

	// Add basic auth headers (simplified for test)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=test")

	t.Logf("Sending chunked encoding request: URL=%s, ChunkSize=%d, DataSize=%d, BodySize=%d",
		url, chunkSize, len(data), len(chunkedBody))

	// Send request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send chunked encoding request")
	defer resp.Body.Close()

	// Read response body for debugging
	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Response: Status=%d, Body=%s", resp.StatusCode, string(respBody))

	// Verify successful upload
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"Chunked encoding upload failed: %s", string(respBody))
}

// createAWSChunkedEncodedBody creates an AWS Signature V4 chunked encoded body
func createAWSChunkedEncodedBody(data string, chunkSize int) []byte {
	var buffer bytes.Buffer
	dataBytes := []byte(data)
	offset := 0

	chunkNum := 0
	for offset < len(dataBytes) {
		chunkNum++
		// Determine actual chunk size
		remainingBytes := len(dataBytes) - offset
		actualChunkSize := chunkSize
		if remainingBytes < chunkSize {
			actualChunkSize = remainingBytes
		}

		chunk := dataBytes[offset : offset+actualChunkSize]

		// Generate a mock signature for testing
		mockSignature := fmt.Sprintf("mock-signature-chunk-%d", chunkNum)

		// Write chunk size in hex followed by chunk signature
		chunkLine := fmt.Sprintf("%x;chunk-signature=%s\r\n", actualChunkSize, mockSignature)
		buffer.WriteString(chunkLine)

		// Write chunk data
		buffer.Write(chunk)
		buffer.WriteString("\r\n")

		offset += actualChunkSize
	}

	// Write final chunk (size 0)
	finalChunkLine := "0;chunk-signature=final-mock-signature\r\n\r\n"
	buffer.WriteString(finalChunkLine)

	return buffer.Bytes()
}

// createAWSChunkedEncodedBody creates an AWS Signature V4 chunked encoded body
func createAWSChunkedEncodedBody(data string, chunkSize int) []byte {
	var buffer bytes.Buffer
	dataBytes := []byte(data)
	offset := 0

	chunkNum := 0
	for offset < len(dataBytes) {
		chunkNum++
		// Determine actual chunk size
		remainingBytes := len(dataBytes) - offset
		actualChunkSize := chunkSize
		if remainingBytes < chunkSize {
			actualChunkSize = remainingBytes
		}

		chunk := dataBytes[offset : offset+actualChunkSize]

		// Generate a mock signature for testing
		mockSignature := fmt.Sprintf("mock-signature-chunk-%d", chunkNum)

		// Write chunk size in hex followed by chunk signature
		chunkLine := fmt.Sprintf("%x;chunk-signature=%s\r\n", actualChunkSize, mockSignature)
		buffer.WriteString(chunkLine)

		// Write chunk data
		buffer.Write(chunk)
		buffer.WriteString("\r\n")

		offset += actualChunkSize
	}

	// Write final chunk (size 0)
	finalChunkLine := "0;chunk-signature=final-mock-signature\r\n\r\n"
	buffer.WriteString(finalChunkLine)

	return buffer.Bytes()
}

// TestChunkedReaderUnit tests the chunked reader implementation in isolation

// cleanupChunkedTestObject removes a test object
func cleanupChunkedTestObject(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) {
	t.Helper()

	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil && !strings.Contains(err.Error(), "NoSuchKey") {
		t.Logf("Warning: Failed to cleanup test object %s/%s: %v", bucket, key, err)
	}
}

// cleanupChunkedBucket removes a test bucket and all its objects
func cleanupChunkedBucket(t *testing.T, ctx context.Context, client *s3.Client, bucket string) {
	t.Helper()

	// List and delete all objects
	listResp, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Logf("Warning: Failed to list objects for cleanup: %v", err)
		return
	}

	for _, obj := range listResp.Contents {
		_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    obj.Key,
		})
		if err != nil {
			t.Logf("Warning: Failed to delete object %s: %v", aws.ToString(obj.Key), err)
		}
	}

	// Delete bucket
	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	})
	if err != nil && !strings.Contains(err.Error(), "NoSuchBucket") {
		t.Logf("Warning: Failed to delete test bucket %s: %v", bucket, err)
	}
}

// downloadThroughChunkedProxy downloads an object through the proxy
func downloadThroughChunkedProxy(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object through proxy")
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	t.Logf("Downloaded %d bytes through proxy", len(data))
	return data
}

// verifyChunkedDownloadedData verifies that downloaded data matches original data
func verifyChunkedDownloadedData(t *testing.T, originalData, downloadedData []byte) {
	t.Helper()

	// Calculate hashes
	originalHash := sha256.Sum256(originalData)
	downloadedHash := sha256.Sum256(downloadedData)

	// Log details for debugging
	t.Logf("Original data: %d bytes, SHA256: %x", len(originalData), originalHash)
	t.Logf("Downloaded data: %d bytes, SHA256: %x", len(downloadedData), downloadedHash)

	// Verify data integrity
	assert.Equal(t, len(originalData), len(downloadedData), "Data length mismatch")
	assert.Equal(t, originalHash, downloadedHash, "Data hash mismatch")

	if len(originalData) > 0 && len(downloadedData) > 0 {
		// Compare first few bytes for debugging
		compareLen := 50
		if len(originalData) < compareLen {
			compareLen = len(originalData)
		}
		if len(downloadedData) < compareLen {
			compareLen = len(downloadedData)
		}

		t.Logf("First %d bytes - Original: %q", compareLen, string(originalData[:compareLen]))
		t.Logf("First %d bytes - Downloaded: %q", compareLen, string(downloadedData[:compareLen]))

		assert.Equal(t, originalData[:compareLen], downloadedData[:compareLen],
			"First %d bytes don't match", compareLen)
	}

	t.Logf("✓ Data integrity verified: %d bytes match perfectly", len(originalData))
}

// TestChunkedReaderUnit tests the chunked reader implementation in isolation
func TestChunkedReaderUnit(t *testing.T) {
	t.Run("Parse valid chunked data", func(t *testing.T) {
		// Create test chunked data
		testData := "Hello, World!"
		chunkedData := createAWSChunkedEncodedBody(testData, 5) // 5 byte chunks

		t.Logf("Generated chunked data (%d bytes):\n%s", len(chunkedData), string(chunkedData))

		// Create a mock chunked reader (simulating the awsChunkedReader)
		reader := bytes.NewReader(chunkedData)
		result := parseChunkedDataManually(t, reader)

		assert.Equal(t, testData, result, "Chunked data parsing failed")
	})

	t.Run("Parse empty chunked data", func(t *testing.T) {
		chunkedData := createAWSChunkedEncodedBody("", 10)
		reader := bytes.NewReader(chunkedData)
		result := parseChunkedDataManually(t, reader)

		assert.Equal(t, "", result, "Empty chunked data parsing failed")
	})

	t.Run("Parse single byte chunks", func(t *testing.T) {
		testData := "ABC"
		chunkedData := createAWSChunkedEncodedBody(testData, 1) // 1 byte chunks
		reader := bytes.NewReader(chunkedData)
		result := parseChunkedDataManually(t, reader)

		assert.Equal(t, testData, result, "Single byte chunked data parsing failed")
	})
}

// parseChunkedDataManually manually parses chunked data to test the logic
func parseChunkedDataManually(t *testing.T, reader io.Reader) string {
	t.Helper()

	var result bytes.Buffer
	bufReader := bufio.NewReader(reader)

	for {
		// Read chunk size line
		chunkSizeLine, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			require.NoError(t, err, "Failed to read chunk size line")
		}

		chunkSizeLine = strings.TrimSpace(chunkSizeLine)
		t.Logf("Processing chunk size line: %q", chunkSizeLine)

		// Parse chunk size
		parts := strings.Split(chunkSizeLine, ";")
		require.Greater(t, len(parts), 0, "Invalid chunk size line format")

		chunkSizeStr := parts[0]
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
		require.NoError(t, err, "Failed to parse chunk size")

		t.Logf("Parsed chunk size: %d", chunkSize)

		// If chunk size is 0, this is the final chunk
		if chunkSize == 0 {
			break
		}

		// Read chunk data
		chunkData := make([]byte, chunkSize)
		_, err = io.ReadFull(bufReader, chunkData)
		require.NoError(t, err, "Failed to read chunk data")

		// Read trailing CRLF
		bufReader.ReadString('\n')

		t.Logf("Read chunk data: %q", string(chunkData))
		result.Write(chunkData)
	}

	return result.String()
}

// BenchmarkChunkedEncoding benchmarks the chunked encoding performance
func BenchmarkChunkedEncoding(b *testing.B) {
	testData := strings.Repeat("BENCHMARK_DATA_", 1000) // ~15KB of data

	b.Run("Create chunked body", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = createAWSChunkedEncodedBody(testData, 64)
		}
	})

	b.Run("Parse chunked body", func(b *testing.B) {
		chunkedData := createAWSChunkedEncodedBody(testData, 64)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			reader := bytes.NewReader(chunkedData)
			_ = parseChunkedDataManuallyBench(b, reader)
		}
	})
}

// parseChunkedDataManually for benchmark - same as test version but with *testing.B
func parseChunkedDataManuallyBench(b *testing.B, reader io.Reader) string {
	b.Helper()

	var result bytes.Buffer
	bufReader := bufio.NewReader(reader)

	for {
		chunkSizeLine, err := bufReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			b.Fatalf("Failed to read chunk size line: %v", err)
		}

		chunkSizeLine = strings.TrimSpace(chunkSizeLine)

		parts := strings.Split(chunkSizeLine, ";")
		if len(parts) == 0 {
			b.Fatalf("Invalid chunk size line format")
		}

		chunkSizeStr := parts[0]
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
		if err != nil {
			b.Fatalf("Failed to parse chunk size: %v", err)
		}

		if chunkSize == 0 {
			break
		}

		chunkData := make([]byte, chunkSize)
		_, err = io.ReadFull(bufReader, chunkData)
		if err != nil {
			b.Fatalf("Failed to read chunk data: %v", err)
		}

		bufReader.ReadString('\n')
		result.Write(chunkData)
	}

	return result.String()
}

// downloadObjectSimple downloads an object from S3
func downloadObjectSimple(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string) []byte {
	t.Helper()

	result, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err, "Failed to download object")
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	return data
}

// verifyDataMatches verifies that downloaded data matches original data
func verifyDataMatches(t *testing.T, originalData, downloadedData []byte) {
	t.Helper()

	// Calculate hashes for comparison
	originalHash := sha256.Sum256(originalData)
	downloadedHash := sha256.Sum256(downloadedData)

	// Verify data integrity
	assert.Equal(t, len(originalData), len(downloadedData), "Data length mismatch")
	assert.Equal(t, originalHash, downloadedHash, "Data hash mismatch")

	// Log success
	t.Logf("✓ Data integrity verified: %d bytes match perfectly", len(originalData))
}
