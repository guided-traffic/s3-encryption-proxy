package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	test_integration "github.com/guided-traffic/s3-encryption-proxy/test/integration"
)

func TestNewS3Handlers(t *testing.T) {
	_, router := setupHandlerTestServer(t)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Bucket ACL GET",
			method:         "GET",
			path:           "/test-bucket?acl",
			expectedStatus: http.StatusOK,
			expectedBody:   "AccessControlPolicy",
		},
		{
			name:           "Bucket CORS",
			method:         "GET",
			path:           "/test-bucket?cors",
			expectedStatus: http.StatusOK,
			expectedBody:   "CORSConfiguration",
		},
		{
			name:           "Bucket Versioning",
			method:         "GET",
			path:           "/test-bucket?versioning",
			expectedStatus: http.StatusOK,
			expectedBody:   "VersioningConfiguration",
		},
		{
			name:           "Bucket Policy",
			method:         "GET",
			path:           "/test-bucket?policy",
			expectedStatus: http.StatusOK,
			expectedBody:   "MockPolicyStatement",
		},
		{
			name:           "Object ACL",
			method:         "GET",
			path:           "/test-bucket/test-key?acl",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "ObjectACL",
		},
		{
			name:           "Object Tagging",
			method:         "GET",
			path:           "/test-bucket/test-key?tagging",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "ObjectTagging",
		},
		{
			name:           "Create Multipart Upload",
			method:         "POST",
			path:           "/test-bucket/test-key?uploads",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "CreateMultipartUpload",
		},
		{
			name:           "Copy Object",
			method:         "PUT",
			path:           "/test-bucket/test-key",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "CopyObject",
		},
		{
			name:           "Delete Objects",
			method:         "POST",
			path:           "/test-bucket?delete",
			expectedStatus: http.StatusNotImplemented,
			expectedBody:   "DeleteObjects",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip multipart upload test as it requires S3 client - tested in multipart handler tests
			if tt.name == "Create Multipart Upload" {
				t.Skip("Skipping multipart upload test - requires S3 client, tested in multipart handler tests")
				return
			}

			req, err := http.NewRequest(tt.method, tt.path, nil)
			require.NoError(t, err)

			// Add copy source header for copy object test
			if tt.name == "Copy Object" {
				req.Header.Set("x-amz-copy-source", "/source-bucket/source-key")
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedBody != "" {
				assert.Contains(t, rr.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestChunkedUploadDecoding(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// Create test context with MinIO and Proxy clients
	testCtx := test_integration.NewTestContext(t)
	defer testCtx.CleanupTestBucket()

	// Test data - make it larger to ensure proper chunking
	testData := []byte("Hello, chunked world! This is a test of AWS chunked encoding. " +
		"We want to verify that chunked data is properly decoded before storage in S3. " +
		"This test ensures that the proxy removes chunks during upload processing.")

	// Create AWS chunked encoded data with multiple chunks
	chunkedData := createAWSChunkedDataMultiChunk(testData)

	bucketName := "test-bucket"
	objectKey := "chunked-test.txt"

	// Use the test bucket from context
	bucketName = testCtx.TestBucket

	// Upload chunked data via HTTP POST (simulating chunked transfer encoding)
	uploadURL := fmt.Sprintf("http://localhost:8080/%s/%s", bucketName, objectKey)
	req, err := http.NewRequest("PUT", uploadURL, strings.NewReader(chunkedData))
	if err != nil {
		t.Fatalf("Failed to create HTTP request: %v", err)
	}

	// Set headers to indicate AWS chunked encoding (standard way)
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	req.Header.Set("x-amz-decoded-content-length", fmt.Sprintf("%d", len(testData)))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(chunkedData)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to upload chunked data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Download directly from S3 backend (bypassing proxy) to verify data is encrypted
	backendResult, err := testCtx.MinIOClient.GetObject(testCtx.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		t.Fatalf("Failed to download from backend: %v", err)
	}
	defer backendResult.Body.Close()

	backendData, err := io.ReadAll(backendResult.Body)
	if err != nil {
		t.Fatalf("Failed to read backend data: %v", err)
	}

	// Verify the backend data is different from original (encrypted) and doesn't contain chunks
	if bytes.Equal(backendData, testData) {
		t.Errorf("Backend data is not encrypted - this suggests the proxy is not working correctly")
	}

	// Verify backend data doesn't contain chunk markers from AWS chunked encoding
	backendStr := string(backendData)
	if strings.Contains(backendStr, ";chunk-signature=") {
		t.Errorf("Backend data still contains AWS chunk markers - chunked encoding was not properly decoded")
	}

	// Also test download via proxy (should also work)
	proxyResult, err := testCtx.ProxyClient.GetObject(testCtx.Ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		t.Fatalf("Failed to download via proxy: %v", err)
	}
	defer proxyResult.Body.Close()

	proxyData, err := io.ReadAll(proxyResult.Body)
	if err != nil {
		t.Fatalf("Failed to read proxy data: %v", err)
	}

	// Verify proxy download matches original data (chunks properly decoded and data properly decrypted)
	if !bytes.Equal(proxyData, testData) {
		t.Errorf("Proxy download data doesn't match original.\nExpected: %q\nGot: %q", testData, proxyData)
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

// createAWSChunkedDataMultiChunk creates AWS chunked encoded data with multiple chunks
func createAWSChunkedDataMultiChunk(data []byte) string {
	var result strings.Builder

	chunkSize := 32 // Small chunk size to create multiple chunks
	offset := 0

	for offset < len(data) {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[offset:end]

		// Write chunk size in hex
		result.WriteString(fmt.Sprintf("%x", len(chunk)))
		result.WriteString(";chunk-signature=")
		result.WriteString("0123456789abcdef0123456789abcdef01234567") // Mock signature
		result.WriteString("\r\n")

		// Write chunk data
		result.Write(chunk)
		result.WriteString("\r\n")

		offset = end
	}

	// Write final chunk (size 0)
	result.WriteString("0;chunk-signature=")
	result.WriteString("fedcba9876543210fedcba9876543210fedcba98") // Mock signature
	result.WriteString("\r\n\r\n")

	return result.String()
}
