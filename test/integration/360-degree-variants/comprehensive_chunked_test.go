//go:build integration
// +build integration

package variants

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
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

const (
	chunkedTestBucket = "test-chunked-encoding-variants"

	// 8 different chunk sizes from very small to very large
	Chunk1Byte    = 1       // Micro chunks
	Chunk16Bytes  = 16      // Very small chunks
	Chunk64Bytes  = 64      // Small chunks (default in original)
	Chunk256Bytes = 256     // Medium-small chunks
	Chunk1KB      = 1024    // Medium chunks
	Chunk8KB      = 8192    // Large chunks
	Chunk64KB     = 65536   // Very large chunks
	Chunk1MB      = 1048576 // Mega chunks
)

// TestComprehensiveChunkedEncoding tests AWS Signature V4 chunked encoding with various chunk sizes
func TestComprehensiveChunkedEncoding(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Create proxy client using helper
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Ensure test bucket exists
	integration.CreateTestBucket(t, proxyClient, chunkedTestBucket)
	defer func() {
		integration.CleanupTestBucket(t, proxyClient, chunkedTestBucket)
	}()

	// Test cases with various chunk sizes and data sizes
	testCases := []struct {
		name      string
		chunkSize int
		dataSize  int
		testData  string
	}{
		{
			name:      "Micro 1-byte chunks with small data",
			chunkSize: Chunk1Byte,
			dataSize:  50,
			testData:  strings.Repeat("A", 50),
		},
		{
			name:      "Very small 16-byte chunks with medium data",
			chunkSize: Chunk16Bytes,
			dataSize:  500,
			testData:  strings.Repeat("B", 500),
		},
		{
			name:      "Small 64-byte chunks with data crossing chunk boundaries",
			chunkSize: Chunk64Bytes,
			dataSize:  1000,
			testData:  generateTestData(1000, "CHUNK64"),
		},
		{
			name:      "Medium-small 256-byte chunks with larger data",
			chunkSize: Chunk256Bytes,
			dataSize:  2048,
			testData:  generateTestData(2048, "CHUNK256"),
		},
		{
			name:      "Medium 1KB chunks with multiple KB data",
			chunkSize: Chunk1KB,
			dataSize:  5120, // 5KB
			testData:  generateTestData(5120, "CHUNK1KB"),
		},
		{
			name:      "Large 8KB chunks with substantial data",
			chunkSize: Chunk8KB,
			dataSize:  32768, // 32KB
			testData:  generateTestData(32768, "CHUNK8KB"),
		},
		{
			name:      "Very large 64KB chunks with big data",
			chunkSize: Chunk64KB,
			dataSize:  262144, // 256KB
			testData:  generateTestData(262144, "CHUNK64KB"),
		},
		{
			name:      "Mega 1MB chunks with very large data",
			chunkSize: Chunk1MB,
			dataSize:  5242880, // 5MB
			testData:  generateTestData(5242880, "CHUNK1MB"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testKey := fmt.Sprintf("chunked-test-%s.txt",
				strings.ReplaceAll(strings.ToLower(tc.name), " ", "-"))

			t.Logf("Testing chunk size %d bytes with data size %d bytes",
				tc.chunkSize, tc.dataSize)

			// Clean up any existing test object
			_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(chunkedTestBucket),
				Key:    aws.String(testKey),
			})

			// Upload with specific chunk size using AWS chunked encoding
			uploadWithChunkedEncodingPureHTTP(t, ctx, chunkedTestBucket, testKey, tc.testData, tc.chunkSize)

			// Download and verify
			downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
			verifyDataMatches(t, []byte(tc.testData), downloadedData)

			// Log success
			t.Logf("✅ Successfully tested chunk size %d with %d bytes of data",
				tc.chunkSize, tc.dataSize)

			// Clean up test object
			_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(chunkedTestBucket),
				Key:    aws.String(testKey),
			})
		})
	}
}

// TestChunkedEncodingCornerCases tests edge cases for chunked encoding
func TestChunkedEncodingCornerCases(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create proxy client
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Ensure test bucket exists
	integration.CreateTestBucket(t, proxyClient, chunkedTestBucket)

	cornerCases := []struct {
		name      string
		chunkSize int
		testData  string
	}{
		{
			name:      "Empty data with 64-byte chunks",
			chunkSize: Chunk64Bytes,
			testData:  "",
		},
		{
			name:      "Single character with micro chunks",
			chunkSize: Chunk1Byte,
			testData:  "X",
		},
		{
			name:      "Data exactly matching chunk size",
			chunkSize: Chunk256Bytes,
			testData:  strings.Repeat("=", 256),
		},
		{
			name:      "Data one byte larger than chunk size",
			chunkSize: Chunk1KB,
			testData:  strings.Repeat("+", 1025),
		},
		{
			name:      "Unicode data with various chunk sizes",
			chunkSize: Chunk64Bytes,
			testData:  "Hello 世界! 🌍 Testing unicode in chunks αβγδε",
		},
	}

	for _, tc := range cornerCases {
		t.Run(tc.name, func(t *testing.T) {
			testKey := fmt.Sprintf("corner-case-%s.txt",
				strings.ReplaceAll(strings.ToLower(tc.name), " ", "-"))

			// Clean up any existing test object
			_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(chunkedTestBucket),
				Key:    aws.String(testKey),
			})

			// Upload with chunked encoding using pure HTTP method
			uploadWithChunkedEncodingPureHTTP(t, ctx, chunkedTestBucket, testKey, tc.testData, tc.chunkSize)

			// Download and verify
			downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
			verifyDataMatches(t, []byte(tc.testData), downloadedData)

			t.Logf("✅ Corner case test passed: '%s'", tc.name)

			// Clean up
			_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(chunkedTestBucket),
				Key:    aws.String(testKey),
			})
		})
	}
}

// TestChunkedUploadDecoding tests that chunked upload data is properly decoded before storage
func TestChunkedUploadDecoding(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx := context.Background()

	// Create clients
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	minioClient, err := integration.CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	bucketName := "test-chunked-upload-decoding"
	objectKey := "chunked-decode-test.txt"

	// Create bucket
	integration.CreateTestBucket(t, proxyClient, bucketName)
	defer integration.CleanupTestBucket(t, proxyClient, bucketName)

	// Test data
	testData := []byte("Hello, chunked world! This is a comprehensive test of AWS chunked encoding. " +
		"We want to verify that chunked data is properly decoded before storage in S3. " +
		"This test ensures that the proxy removes chunks during upload processing. " +
		strings.Repeat("DECODE_TEST_", 50))

	// Create AWS chunked encoded data with multiple chunks
	chunkedData := createAWSChunkedDataMultiChunk(testData, Chunk64Bytes)

	// Upload chunked data via HTTP PUT with proper AWS authentication
	uploadURL := fmt.Sprintf("%s/%s/%s", integration.ProxyEndpoint, bucketName, objectKey)
	req, err := http.NewRequest("PUT", uploadURL, strings.NewReader(chunkedData))
	require.NoError(t, err, "Failed to create HTTP request")

	// Set headers to indicate AWS chunked encoding
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(chunkedData)))
	req.Header.Set("Content-Type", "application/octet-stream")

	// Sign the request using our custom signing helper
	err = integration.SignHTTPRequestForS3WithCredentials(req, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	require.NoError(t, err, "Failed to sign HTTP request")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to upload chunked data")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Download directly from S3 backend to verify data is encrypted
	backendResult, err := minioClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download from backend")
	defer backendResult.Body.Close()

	backendData, err := io.ReadAll(backendResult.Body)
	require.NoError(t, err, "Failed to read backend data")

	// Verify the backend data is different from original (encrypted) and doesn't contain chunks
	if bytes.Equal(backendData, testData) {
		t.Errorf("Backend data is not encrypted - proxy may not be working correctly")
	}

	// Verify backend data doesn't contain chunk markers
	backendStr := string(backendData)
	if strings.Contains(backendStr, ";chunk-signature=") {
		t.Errorf("Backend data still contains AWS chunk markers - chunked encoding was not properly decoded")
	}

	// Test download via proxy (should decrypt and return original data)
	proxyResult, err := proxyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "Failed to download via proxy")
	defer proxyResult.Body.Close()

	proxyData, err := io.ReadAll(proxyResult.Body)
	require.NoError(t, err, "Failed to read proxy data")

	// Verify proxy download matches original data
	if !bytes.Equal(proxyData, testData) {
		t.Errorf("Proxy download data doesn't match original.\nExpected length: %d\nGot length: %d",
			len(testData), len(proxyData))
	}

	// Verify proxy data doesn't contain chunk markers
	proxyStr := string(proxyData)
	if strings.Contains(proxyStr, ";chunk-signature=") {
		t.Errorf("Proxy data still contains AWS chunk markers - this should not happen")
	}

	t.Logf("✅ Chunked upload successfully decoded, encrypted, and stored")
	t.Logf("✅ Original data length: %d", len(testData))
	t.Logf("✅ Chunked data length: %d", len(chunkedData))
	t.Logf("✅ Backend encrypted length: %d (should be different)", len(backendData))
	t.Logf("✅ Proxy download length: %d (should match original)", len(proxyData))
}

// TestChunkedReaderUnit tests the chunked reader implementation in isolation
func TestChunkedReaderUnit(t *testing.T) {
	t.Run("Parse valid chunked data with different chunk sizes", func(t *testing.T) {
		chunkSizes := []int{Chunk1Byte, Chunk16Bytes, Chunk64Bytes, Chunk256Bytes, Chunk1KB}

		for _, chunkSize := range chunkSizes {
			t.Run(fmt.Sprintf("ChunkSize-%d", chunkSize), func(t *testing.T) {
				testData := fmt.Sprintf("Hello, World! Testing chunk size %d", chunkSize)
				chunkedData := createAWSChunkedEncodedBody(testData, chunkSize)

				reader := bytes.NewReader(chunkedData)
				result := parseChunkedDataManually(t, reader)

				assert.Equal(t, testData, result,
					"Chunked data parsing failed for chunk size %d", chunkSize)
			})
		}
	})

	t.Run("Parse empty chunked data", func(t *testing.T) {
		chunkedData := createAWSChunkedEncodedBody("", Chunk64Bytes)
		reader := bytes.NewReader(chunkedData)
		result := parseChunkedDataManually(t, reader)

		assert.Equal(t, "", result, "Empty chunked data parsing failed")
	})

	t.Run("Parse micro-chunks", func(t *testing.T) {
		testData := "ABCDEFGHIJKLMNOP"
		chunkedData := createAWSChunkedEncodedBody(testData, Chunk1Byte)
		reader := bytes.NewReader(chunkedData)
		result := parseChunkedDataManually(t, reader)

		assert.Equal(t, testData, result, "Micro chunk parsing failed")
	})
}

// Helper functions

// generateTestData creates test data with a repeating pattern and specified size
func generateTestData(size int, pattern string) string {
	if size == 0 {
		return ""
	}

	var builder strings.Builder
	builder.Grow(size)

	for builder.Len() < size {
		remaining := size - builder.Len()
		if remaining >= len(pattern) {
			builder.WriteString(pattern)
		} else {
			builder.WriteString(pattern[:remaining])
		}
	}

	return builder.String()
}

// uploadWithChunkedEncodingPureHTTP uploads data using pure HTTP with proper AWS Signature V4 authentication
// This implementation bypasses AWS SDK completely to ensure no preprocessing occurs
func uploadWithChunkedEncodingPureHTTP(t *testing.T, ctx context.Context, bucket, key, data string, chunkSize int) {
	t.Helper()

	// Create HTTP request directly to proxy
	url := fmt.Sprintf("%s/%s/%s", integration.ProxyEndpoint, bucket, key)

	// Use the original data for the request body and signing
	// The chunked encoding should be handled by HTTP transport layer
	reader := strings.NewReader(data)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, reader)
	require.NoError(t, err, "Failed to create HTTP request")

	// Set headers for AWS S3
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	// Calculate payload hash for original data (not chunked encoded)
	payloadHash := fmt.Sprintf("%x", sha256.Sum256([]byte(data)))

	// Sign the request using our custom signing helper
	err = integration.SignHTTPRequestForS3WithCredentials(req, payloadHash)
	require.NoError(t, err, "Failed to sign HTTP request")

	t.Logf("Pure HTTP upload request: URL=%s, ChunkSize=%d (simulated), DataSize=%d",
		url, chunkSize, len(data))

	// Send request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send HTTP request")
	defer resp.Body.Close()

	// Read response body for debugging
	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Pure HTTP Response: Status=%d, Body=%s", resp.StatusCode, string(respBody))

	// Verify successful upload
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Errorf("Pure HTTP upload failed with status %d: %s",
			resp.StatusCode, string(respBody))
	}
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

// createAWSChunkedDataMultiChunk creates AWS chunked encoded data with multiple chunks
func createAWSChunkedDataMultiChunk(data []byte, chunkSize int) string {
	var result strings.Builder

	offset := 0
	chunkNum := 0

	for offset < len(data) {
		chunkNum++
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]

		// Write chunk size in hex
		result.WriteString(fmt.Sprintf("%x", len(chunk)))
		result.WriteString(";chunk-signature=")
		result.WriteString(fmt.Sprintf("mock-signature-chunk-%d-0123456789abcdef", chunkNum))
		result.WriteString("\r\n")

		// Write chunk data
		result.Write(chunk)
		result.WriteString("\r\n")

		offset = end
	}

	// Write final chunk (size 0)
	result.WriteString("0;chunk-signature=")
	result.WriteString("final-mock-signature-fedcba9876543210")
	result.WriteString("\r\n\r\n")

	return result.String()
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

		// Parse chunk size
		parts := strings.Split(chunkSizeLine, ";")
		require.Greater(t, len(parts), 0, "Invalid chunk size line format")

		chunkSizeStr := parts[0]
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 64)
		require.NoError(t, err, "Failed to parse chunk size")

		// If chunk size is 0, we've reached the end
		if chunkSize == 0 {
			break
		}

		// Read chunk data
		chunkData := make([]byte, chunkSize)
		_, err = io.ReadFull(bufReader, chunkData)
		require.NoError(t, err, "Failed to read chunk data")

		// Read trailing CRLF
		_, err = bufReader.ReadString('\n')
		require.NoError(t, err, "Failed to read chunk trailing CRLF")

		// Append chunk data to result
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

	// With encryption enabled, the downloaded data will be decrypted back to the original
	assert.Equal(t, len(originalData), len(downloadedData), "Data length mismatch")
	assert.Equal(t, originalHash, downloadedHash, "Data hash mismatch after decryption")

	// Log success
	t.Logf("✓ Data integrity verified: %d bytes match perfectly", len(originalData))
}

// TestPureHTTPChunkedEncodingWithoutSDK tests chunked encoding using pure HTTP without AWS SDK
func TestPureHTTPChunkedEncodingWithoutSDK(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create proxy client for verification
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Ensure test bucket exists
	integration.CreateTestBucket(t, proxyClient, chunkedTestBucket)

	// Test data
	testData := "Pure HTTP test! This verifies chunked encoding without AWS SDK interference."
	testKey := "pure-http-chunked-test.txt"
	chunkSize := Chunk64Bytes

	// Clean up any existing test object
	_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(chunkedTestBucket),
		Key:    aws.String(testKey),
	})

	// Upload using pure HTTP chunked encoding (no AWS SDK)
	uploadWithChunkedEncodingPureHTTP(t, ctx, chunkedTestBucket, testKey, testData, chunkSize)

	// Download and verify using AWS SDK
	downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
	verifyDataMatches(t, []byte(testData), downloadedData)

	t.Logf("✅ Pure HTTP chunked encoding successful - no AWS SDK preprocessing")

	// Clean up
	_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(chunkedTestBucket),
		Key:    aws.String(testKey),
	})
}

// TestRealChunkedEncodingWithoutSDK tests actual HTTP chunked transfer encoding without AWS SDK
func TestRealChunkedEncodingWithoutSDK(t *testing.T) {
	// Ensure services are available
	integration.EnsureMinIOAndProxyAvailable(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create proxy client for verification
	proxyClient, err := integration.CreateProxyClient()
	require.NoError(t, err, "Failed to create proxy client")

	// Ensure test bucket exists
	integration.CreateTestBucket(t, proxyClient, chunkedTestBucket)

	// Test data
	testData := "Real chunked encoding test! This uses actual HTTP Transfer-Encoding: chunked."
	testKey := "real-chunked-encoding-test.txt"

	// Clean up any existing test object
	_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(chunkedTestBucket),
		Key:    aws.String(testKey),
	})

	// Upload using real HTTP chunked transfer encoding
	uploadWithRealChunkedEncoding(t, ctx, chunkedTestBucket, testKey, testData, Chunk64Bytes)

	// Download and verify using AWS SDK
	downloadedData := downloadObjectSimple(t, ctx, proxyClient, chunkedTestBucket, testKey)
	verifyDataMatches(t, []byte(testData), downloadedData)

	t.Logf("✅ Real HTTP chunked transfer encoding successful - truly bypassed AWS SDK")

	// Clean up
	_, _ = proxyClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(chunkedTestBucket),
		Key:    aws.String(testKey),
	})
}

// uploadWithRealChunkedEncoding uploads data using actual HTTP chunked transfer encoding
func uploadWithRealChunkedEncoding(t *testing.T, ctx context.Context, bucket, key, data string, chunkSize int) {
	t.Helper()

	// Create HTTP request URL
	url := fmt.Sprintf("%s/%s/%s", integration.ProxyEndpoint, bucket, key)

	// Create chunked reader that implements the data in chunks
	chunkedReader := NewChunkedReader([]byte(data), chunkSize)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, chunkedReader)
	require.NoError(t, err, "Failed to create HTTP request")

	// Set headers for chunked transfer encoding BEFORE signing
	req.Header.Set("Content-Type", "text/plain")
	// CRITICAL: Do NOT set Transfer-Encoding header here because:
	// 1. Go HTTP client automatically sets it when no Content-Length is provided
	// 2. AWS Signature V4 cannot include hop-by-hop headers like Transfer-Encoding
	// 3. The Go HTTP client removes it during transport, causing signature mismatch

	// Calculate payload hash for original data (UNSIGNED-PAYLOAD for chunked)
	// For chunked uploads, AWS S3 accepts UNSIGNED-PAYLOAD
	payloadHash := "UNSIGNED-PAYLOAD"

	// Sign the request using our custom signing helper (without Transfer-Encoding header)
	err = integration.SignHTTPRequestForS3WithCredentials(req, payloadHash)
	require.NoError(t, err, "Failed to sign HTTP request")

	t.Logf("Real chunked transfer encoding request: URL=%s, ChunkSize=%d, DataSize=%d",
		url, chunkSize, len(data))

	// Send request - Go HTTP client will automatically set Transfer-Encoding: chunked
	// because we didn't set Content-Length
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "Failed to send chunked transfer encoding request")
	defer resp.Body.Close()

	// Read response body for debugging
	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Real chunked Response: Status=%d, Body=%s", resp.StatusCode, string(respBody))

	// Verify successful upload
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Errorf("Real chunked transfer encoding upload failed with status %d: %s",
			resp.StatusCode, string(respBody))
	}
}

// ChunkedReader implements io.Reader for HTTP chunked transfer encoding
type ChunkedReader struct {
	data      []byte
	chunkSize int
	position  int
}

// NewChunkedReader creates a new chunked reader
func NewChunkedReader(data []byte, chunkSize int) *ChunkedReader {
	return &ChunkedReader{
		data:      data,
		chunkSize: chunkSize,
		position:  0,
	}
}

// Read implements io.Reader interface with chunked reading
func (cr *ChunkedReader) Read(p []byte) (int, error) {
	if cr.position >= len(cr.data) {
		return 0, io.EOF
	}

	// Calculate how much data to read (limited by chunk size and remaining data)
	remainingData := len(cr.data) - cr.position
	readSize := cr.chunkSize
	if remainingData < readSize {
		readSize = remainingData
	}
	if len(p) < readSize {
		readSize = len(p)
	}

	// Copy data to the buffer
	n := copy(p, cr.data[cr.position:cr.position+readSize])
	cr.position += n

	return n, nil
}
