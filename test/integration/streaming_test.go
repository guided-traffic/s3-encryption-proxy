//go:build integration
// +build integration

package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamingMultipartUpload(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Use test context
	tc := NewTestContext(t)

	bucketName := tc.TestBucket
	objectKey := fmt.Sprintf("streaming-test-%d", time.Now().Unix())

	t.Run("AES-CTR Streaming Multipart Upload", func(t *testing.T) {
		// Use a large file size to ensure multipart upload
		fileSize := 10 * 1024 * 1024 // 10MB
		originalData := make([]byte, fileSize)
		_, err := io.ReadFull(rand.Reader, originalData)
		require.NoError(t, err, "Failed to generate random data")

		// Use proxy endpoint
		proxyURL := ProxyEndpoint

		// Step 1: Create multipart upload
		createURL := fmt.Sprintf("%s/%s/%s?uploads", proxyURL, bucketName, objectKey)
		resp, err := http.Post(createURL, "application/octet-stream", nil)
		require.NoError(t, err, "Failed to create multipart upload")
		require.Equal(t, http.StatusOK, resp.StatusCode, "Unexpected status code for create multipart upload")

		createBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read create response body")
		resp.Body.Close()

		// Extract upload ID from response
		uploadID := extractUploadIDFromCreateResponse(string(createBody))
		require.NotEmpty(t, uploadID, "Upload ID should not be empty")

		t.Logf("Created multipart upload with ID: %s", uploadID)

		// Step 2: Upload parts in streaming fashion
		partSize := 5 * 1024 * 1024                      // 5MB per part
		numParts := (fileSize + partSize - 1) / partSize // Ceiling division
		etags := make([]string, numParts)

		for i := 0; i < numParts; i++ {
			partNumber := i + 1
			start := i * partSize
			end := start + partSize
			if end > fileSize {
				end = fileSize
			}

			partData := originalData[start:end]

			// Upload part via streaming
			uploadPartURL := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
				proxyURL, bucketName, objectKey, partNumber, uploadID)

			req, err := http.NewRequest("PUT", uploadPartURL, bytes.NewReader(partData))
			require.NoError(t, err, "Failed to create upload part request")

			client := &http.Client{}
			partResp, err := client.Do(req)
			require.NoError(t, err, "Failed to upload part %d", partNumber)
			require.Equal(t, http.StatusOK, partResp.StatusCode, "Unexpected status code for part %d", partNumber)

			etag := partResp.Header.Get("ETag")
			require.NotEmpty(t, etag, "ETag should not be empty for part %d", partNumber)
			etags[i] = etag
			partResp.Body.Close()

			t.Logf("Uploaded part %d with ETag: %s", partNumber, etag)
		}

		// Step 3: Complete multipart upload
		completePayload := buildCompleteMultipartUploadXML(etags)
		completeURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", proxyURL, bucketName, objectKey, uploadID)

		completeReq, err := http.NewRequest("POST", completeURL, bytes.NewReader([]byte(completePayload)))
		require.NoError(t, err, "Failed to create complete multipart upload request")
		completeReq.Header.Set("Content-Type", "application/xml")

		client := &http.Client{}
		completeResp, err := client.Do(completeReq)
		require.NoError(t, err, "Failed to complete multipart upload")
		require.Equal(t, http.StatusOK, completeResp.StatusCode, "Unexpected status code for complete multipart upload")
		completeResp.Body.Close()

		t.Log("Completed multipart upload")

		// Step 4: Download and verify the object
		getURL := fmt.Sprintf("%s/%s/%s", proxyURL, bucketName, objectKey)
		getResp, err := http.Get(getURL)
		require.NoError(t, err, "Failed to get object")
		require.Equal(t, http.StatusOK, getResp.StatusCode, "Unexpected status code for get object")

		downloadedData, err := io.ReadAll(getResp.Body)
		require.NoError(t, err, "Failed to read downloaded data")
		getResp.Body.Close()

		// Verify data integrity
		assert.Equal(t, len(originalData), len(downloadedData), "Downloaded data size should match original")
		assert.Equal(t, originalData, downloadedData, "Downloaded data should match original data")

		t.Log("Successfully verified streaming multipart upload and download")

		// Step 5: Verify object exists in S3 (encrypted)
		s3Object, err := tc.MinIOClient.GetObject(tc.Ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to get object from S3")

		s3Data, err := io.ReadAll(s3Object.Body)
		require.NoError(t, err, "Failed to read S3 object data")
		s3Object.Body.Close()

		// S3 data should be encrypted (different from original)
		assert.NotEqual(t, originalData, s3Data, "S3 data should be encrypted")
		assert.Greater(t, len(s3Data), len(originalData), "S3 data should include encryption overhead")

		// Verify streaming metadata
		if s3Object.Metadata != nil {
			if encMode, exists := s3Object.Metadata["encryption-mode"]; exists {
				assert.Equal(t, "aes-ctr-streaming", encMode, "Should be AES-CTR streaming")
			}
			if multipart, exists := s3Object.Metadata["multipart"]; exists {
				assert.Equal(t, "true", multipart, "Should be marked as multipart")
			}
		}

		t.Log("Successfully verified S3 encrypted data and metadata")
	})
}

func extractUploadIDFromCreateResponse(responseBody string) string {
	// Extract UploadId from XML response
	// Look for <UploadId>...</UploadId>
	startTag := "<UploadId>"
	endTag := "</UploadId>"

	start := strings.Index(responseBody, startTag)
	if start == -1 {
		return ""
	}
	start += len(startTag)

	end := strings.Index(responseBody[start:], endTag)
	if end == -1 {
		return ""
	}

	return responseBody[start : start+end]
}

func buildCompleteMultipartUploadXML(etags []string) string {
	xml := `<CompleteMultipartUpload>`
	for i, etag := range etags {
		partNumber := i + 1
		xml += fmt.Sprintf(`<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>`, partNumber, etag)
	}
	xml += `</CompleteMultipartUpload>`
	return xml
}

func TestStreamingVsStandardPerformance(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}

	// Use test context
	tc := NewTestContext(t)

	_ = tc.TestBucket // bucketName available in tc if needed
	fileSize := 20 * 1024 * 1024 // 20MB

	// Generate test data
	testData := make([]byte, fileSize)
	_, err := io.ReadFull(rand.Reader, testData)
	require.NoError(t, err, "Failed to generate test data")

	t.Run("Compare Streaming vs Standard Upload Performance", func(t *testing.T) {
		// This test is primarily for validation that streaming works
		// Performance comparison would need controlled environment

		// Test streaming upload
		streamingKey := fmt.Sprintf("streaming-perf-%d", time.Now().Unix())
		streamingStart := time.Now()

		err := performMultipartUpload(t, tc, streamingKey, testData, true)
		require.NoError(t, err, "Streaming upload should succeed")

		streamingDuration := time.Since(streamingStart)
		t.Logf("Streaming upload took: %v", streamingDuration)

		// Verify streaming upload
		downloadedData := downloadAndVerify(t, tc, streamingKey, testData)
		assert.Equal(t, testData, downloadedData, "Streaming upload data should match")

		t.Log("Streaming multipart upload performance test completed successfully")
	})
}

func performMultipartUpload(t *testing.T, tc *TestContext, objectKey string, data []byte, isStreaming bool) error {
	proxyURL := ProxyEndpoint
	bucketName := tc.TestBucket

	// Create multipart upload
	createURL := fmt.Sprintf("%s/%s/%s?uploads", proxyURL, bucketName, objectKey)
	resp, err := http.Post(createURL, "application/octet-stream", nil)
	if err != nil {
		return fmt.Errorf("failed to create multipart upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code for create multipart upload: %d", resp.StatusCode)
	}

	createBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read create response body: %w", err)
	}

	uploadID := extractUploadIDFromCreateResponse(string(createBody))
	if uploadID == "" {
		return fmt.Errorf("upload ID should not be empty")
	}

	// Upload parts
	partSize := 5 * 1024 * 1024 // 5MB per part
	numParts := (len(data) + partSize - 1) / partSize
	etags := make([]string, numParts)

	for i := 0; i < numParts; i++ {
		partNumber := i + 1
		start := i * partSize
		end := start + partSize
		if end > len(data) {
			end = len(data)
		}

		partData := data[start:end]

		uploadPartURL := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
			proxyURL, bucketName, objectKey, partNumber, uploadID)

		req, err := http.NewRequest("PUT", uploadPartURL, bytes.NewReader(partData))
		if err != nil {
			return fmt.Errorf("failed to create upload part request: %w", err)
		}

		client := &http.Client{}
		partResp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to upload part %d: %w", partNumber, err)
		}

		if partResp.StatusCode != http.StatusOK {
			partResp.Body.Close()
			return fmt.Errorf("unexpected status code for part %d: %d", partNumber, partResp.StatusCode)
		}

		etag := partResp.Header.Get("ETag")
		if etag == "" {
			partResp.Body.Close()
			return fmt.Errorf("ETag should not be empty for part %d", partNumber)
		}
		etags[i] = etag
		partResp.Body.Close()
	}

	// Complete multipart upload
	completePayload := buildCompleteMultipartUploadXML(etags)
	completeURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", proxyURL, bucketName, objectKey, uploadID)

	completeReq, err := http.NewRequest("POST", completeURL, bytes.NewReader([]byte(completePayload)))
	if err != nil {
		return fmt.Errorf("failed to create complete multipart upload request: %w", err)
	}
	completeReq.Header.Set("Content-Type", "application/xml")

	client := &http.Client{}
	completeResp, err := client.Do(completeReq)
	if err != nil {
		return fmt.Errorf("failed to complete multipart upload: %w", err)
	}
	defer completeResp.Body.Close()

	if completeResp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code for complete multipart upload: %d", completeResp.StatusCode)
	}

	return nil
}

func downloadAndVerify(t *testing.T, tc *TestContext, objectKey string, expectedData []byte) []byte {
	proxyURL := ProxyEndpoint
	bucketName := tc.TestBucket

	getURL := fmt.Sprintf("%s/%s/%s", proxyURL, bucketName, objectKey)
	getResp, err := http.Get(getURL)
	require.NoError(t, err, "Failed to get object")
	require.Equal(t, http.StatusOK, getResp.StatusCode, "Unexpected status code for get object")
	defer getResp.Body.Close()

	downloadedData, err := io.ReadAll(getResp.Body)
	require.NoError(t, err, "Failed to read downloaded data")

	return downloadedData
}
