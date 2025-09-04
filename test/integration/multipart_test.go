package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/providers"
)

// Mock S3 server for integration tests
type mockS3Server struct {
	uploads map[string]*mockMultipartUpload
	objects map[string][]byte
	parts   map[string]map[int32][]byte // uploadID -> partNumber -> data
}

type mockMultipartUpload struct {
	UploadID string
	Key      string
	Parts    map[int32]string // partNumber -> ETag
}

func newMockS3Server() *mockS3Server {
	return &mockS3Server{
		uploads: make(map[string]*mockMultipartUpload),
		objects: make(map[string][]byte),
		parts:   make(map[string]map[int32][]byte),
	}
}

func (m *mockS3Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse bucket and key from path
	path := strings.TrimPrefix(r.URL.Path, "/")
	pathParts := strings.SplitN(path, "/", 2)
	if len(pathParts) < 2 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}
	bucket := pathParts[0]
	key := pathParts[1]

	switch r.Method {
	case "POST":
		if r.URL.Query().Get("uploads") != "" {
			// Create multipart upload
			uploadID := fmt.Sprintf("upload-%d", time.Now().UnixNano())
			m.uploads[uploadID] = &mockMultipartUpload{
				UploadID: uploadID,
				Key:      key,
				Parts:    make(map[int32]string),
			}
			m.parts[uploadID] = make(map[int32][]byte)

			response := `<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <UploadId>%s</UploadId>
</InitiateMultipartUploadResult>`
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, response, bucket, key, uploadID)
		} else if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
			// Complete multipart upload
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			var completeReq struct {
				Parts []struct {
					PartNumber int32  `xml:"PartNumber"`
					ETag       string `xml:"ETag"`
				} `xml:"Part"`
			}

			if err := xml.Unmarshal(body, &completeReq); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Combine all parts
			var combined []byte
			for _, part := range completeReq.Parts {
				if partData, exists := m.parts[uploadID][part.PartNumber]; exists {
					combined = append(combined, partData...)
				}
			}

			// Store complete object
			m.objects[key] = combined

			response := `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult>
    <Bucket>%s</Bucket>
    <Key>%s</Key>
    <ETag>"complete-etag"</ETag>
</CompleteMultipartUploadResult>`
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, response, bucket, key)

			// Clean up
			delete(m.uploads, uploadID)
			delete(m.parts, uploadID)
		}

	case "PUT":
		if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
			// Upload part
			partNumberStr := r.URL.Query().Get("partNumber")
			partNumber, err := strconv.Atoi(partNumberStr)
			if err != nil {
				http.Error(w, "Invalid part number", http.StatusBadRequest)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Store part data
			if m.parts[uploadID] == nil {
				m.parts[uploadID] = make(map[int32][]byte)
			}
			m.parts[uploadID][int32(partNumber)] = body

			// Generate ETag
			etag := fmt.Sprintf("part-%s-%d", uploadID, partNumber)
			if upload := m.uploads[uploadID]; upload != nil {
				upload.Parts[int32(partNumber)] = etag
			}

			w.Header().Set("ETag", fmt.Sprintf(`"%s"`, etag))
			w.WriteHeader(http.StatusOK)
		} else {
			// Single object upload
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			m.objects[key] = body
			w.Header().Set("ETag", `"single-upload-etag"`)
			w.WriteHeader(http.StatusOK)
		}

	case "GET":
		// Get object
		if data, exists := m.objects[key]; exists {
			w.Write(data)
		} else {
			http.Error(w, "Object not found", http.StatusNotFound)
		}

	case "DELETE":
		if uploadID := r.URL.Query().Get("uploadId"); uploadID != "" {
			// Abort multipart upload
			delete(m.uploads, uploadID)
			delete(m.parts, uploadID)
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func setupIntegrationTest(t *testing.T) (*proxy.Server, *mockS3Server, string) {
	// Create mock S3 server
	mockS3 := newMockS3Server()
	s3Server := httptest.NewServer(mockS3)

	// Create encryption manager with AES-GCM provider
	encProvider, err := providers.NewAESGCMProvider([]byte("test-key-32-bytes-for-aes-256!!!"))
	require.NoError(t, err)

	encMgr := encryption.NewManager(encProvider)

	// Create S3 client pointing to mock server
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:               s3Server.URL,
			HostnameImmutable: true,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(customResolver),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
		config.WithRegion("us-east-1"),
	)
	require.NoError(t, err)

	s3Client := awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		o.UsePathStyle = true
	})

	s3Wrapper := s3wrapper.NewClient(s3Client)

	// Create proxy server
	proxyServer, err := proxy.NewServer(encMgr, s3Wrapper, "test-bucket", "", "", false, nil)
	require.NoError(t, err)

	return proxyServer, mockS3, s3Server.URL
}

func TestMultipartUploadEncryptionIntegration(t *testing.T) {
	proxyServer, mockS3, _ := setupIntegrationTest(t)

	// Create test recorder
	recorder := httptest.NewRecorder()

	// Create multipart upload
	req, err := http.NewRequest("POST", "/test-bucket/test-object?uploads", nil)
	require.NoError(t, err)

	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Parse upload ID from response
	var initResponse struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.Unmarshal(recorder.Body.Bytes(), &initResponse)
	require.NoError(t, err)
	uploadID := initResponse.UploadID

	// Upload multiple parts
	part1Data := []byte("This is part 1 of the multipart upload")
	part2Data := []byte("This is part 2 of the multipart upload")
	part3Data := []byte("This is part 3 of the multipart upload")

	partETags := make([]string, 0)

	// Upload part 1
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("PUT", fmt.Sprintf("/test-bucket/test-object?partNumber=1&uploadId=%s", uploadID), bytes.NewReader(part1Data))
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	partETags = append(partETags, strings.Trim(recorder.Header().Get("ETag"), `"`))

	// Upload part 2
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("PUT", fmt.Sprintf("/test-bucket/test-object?partNumber=2&uploadId=%s", uploadID), bytes.NewReader(part2Data))
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	partETags = append(partETags, strings.Trim(recorder.Header().Get("ETag"), `"`))

	// Upload part 3
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("PUT", fmt.Sprintf("/test-bucket/test-object?partNumber=3&uploadId=%s", uploadID), bytes.NewReader(part3Data))
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)
	partETags = append(partETags, strings.Trim(recorder.Header().Get("ETag"), `"`))

	// Complete multipart upload
	completeRequest := `<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>"%s"</ETag></Part>
		<Part><PartNumber>2</PartNumber><ETag>"%s"</ETag></Part>
		<Part><PartNumber>3</PartNumber><ETag>"%s"</ETag></Part>
	</CompleteMultipartUpload>`
	completeBody := fmt.Sprintf(completeRequest, partETags[0], partETags[1], partETags[2])

	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("POST", fmt.Sprintf("/test-bucket/test-object?uploadId=%s", uploadID), strings.NewReader(completeBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify the data was encrypted and stored correctly
	// The mock S3 should have received encrypted data
	expectedPlaintext := append(append(part1Data, part2Data...), part3Data...)
	storedData, exists := mockS3.objects["test-object"]
	require.True(t, exists, "Object should be stored in mock S3")

	// The stored data should be encrypted (different from plaintext)
	assert.NotEqual(t, expectedPlaintext, storedData, "Stored data should be encrypted")

	// Verify we can decrypt it back (via GET request through proxy)
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/test-bucket/test-object", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	decryptedData := recorder.Body.Bytes()
	assert.Equal(t, expectedPlaintext, decryptedData, "Decrypted data should match original plaintext")
}

func TestMultipartUploadLargeFile(t *testing.T) {
	proxyServer, _, _ := setupIntegrationTest(t)

	// Create a large test file (5MB in parts of 1MB each)
	partSize := 1024 * 1024 // 1MB
	numParts := 5
	largeData := make([]byte, partSize*numParts)
	_, err := rand.Read(largeData)
	require.NoError(t, err)

	// Create multipart upload
	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/test-bucket/large-object?uploads", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var initResponse struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.Unmarshal(recorder.Body.Bytes(), &initResponse)
	require.NoError(t, err)
	uploadID := initResponse.UploadID

	// Upload parts
	partETags := make([]string, numParts)
	for i := 0; i < numParts; i++ {
		start := i * partSize
		end := start + partSize
		partData := largeData[start:end]

		recorder = httptest.NewRecorder()
		req, err = http.NewRequest("PUT",
			fmt.Sprintf("/test-bucket/large-object?partNumber=%d&uploadId=%s", i+1, uploadID),
			bytes.NewReader(partData))
		require.NoError(t, err)

		proxyServer.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("Part %d upload failed", i+1))
		partETags[i] = strings.Trim(recorder.Header().Get("ETag"), `"`)
	}

	// Complete multipart upload
	var completeRequest strings.Builder
	completeRequest.WriteString("<CompleteMultipartUpload>")
	for i, etag := range partETags {
		completeRequest.WriteString(fmt.Sprintf(
			"<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>",
			i+1, etag))
	}
	completeRequest.WriteString("</CompleteMultipartUpload>")

	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("POST",
		fmt.Sprintf("/test-bucket/large-object?uploadId=%s", uploadID),
		strings.NewReader(completeRequest.String()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify we can retrieve the complete file
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/test-bucket/large-object", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	retrievedData := recorder.Body.Bytes()
	assert.Equal(t, largeData, retrievedData, "Retrieved data should match original large file")
}

func TestMultipartUploadAbortIntegration(t *testing.T) {
	proxyServer, mockS3, _ := setupIntegrationTest(t)

	// Create multipart upload
	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/test-bucket/abort-test?uploads", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var initResponse struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.Unmarshal(recorder.Body.Bytes(), &initResponse)
	require.NoError(t, err)
	uploadID := initResponse.UploadID

	// Upload a part
	partData := []byte("This part will be aborted")
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("PUT",
		fmt.Sprintf("/test-bucket/abort-test?partNumber=1&uploadId=%s", uploadID),
		bytes.NewReader(partData))
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify upload exists in mock S3
	assert.Contains(t, mockS3.uploads, uploadID, "Upload should exist before abort")

	// Abort the multipart upload
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("DELETE",
		fmt.Sprintf("/test-bucket/abort-test?uploadId=%s", uploadID), nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusNoContent, recorder.Code)

	// Verify upload is cleaned up in mock S3
	assert.NotContains(t, mockS3.uploads, uploadID, "Upload should be cleaned up after abort")
	assert.NotContains(t, mockS3.parts, uploadID, "Parts should be cleaned up after abort")

	// Verify object was not created
	_, exists := mockS3.objects["abort-test"]
	assert.False(t, exists, "Object should not exist after abort")
}

func TestMultipartUploadConcurrentParts(t *testing.T) {
	proxyServer, _, _ := setupIntegrationTest(t)

	// Create multipart upload
	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/test-bucket/concurrent-test?uploads", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	var initResponse struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.Unmarshal(recorder.Body.Bytes(), &initResponse)
	require.NoError(t, err)
	uploadID := initResponse.UploadID

	// Upload parts concurrently
	numParts := 10
	partData := make([][]byte, numParts)
	partETags := make([]string, numParts)

	for i := 0; i < numParts; i++ {
		partData[i] = []byte(fmt.Sprintf("Concurrent part %d data", i+1))
	}

	// Use channels for synchronization
	results := make(chan struct {
		partNum int
		etag    string
		err     error
	}, numParts)

	// Upload all parts concurrently
	for i := 0; i < numParts; i++ {
		go func(partNum int) {
			recorder := httptest.NewRecorder()
			req, err := http.NewRequest("PUT",
				fmt.Sprintf("/test-bucket/concurrent-test?partNumber=%d&uploadId=%s", partNum+1, uploadID),
				bytes.NewReader(partData[partNum]))
			if err != nil {
				results <- struct {
					partNum int
					etag    string
					err     error
				}{partNum, "", err}
				return
			}

			proxyServer.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				results <- struct {
					partNum int
					etag    string
					err     error
				}{partNum, "", fmt.Errorf("unexpected status code: %d", recorder.Code)}
				return
			}

			etag := strings.Trim(recorder.Header().Get("ETag"), `"`)
			results <- struct {
				partNum int
				etag    string
				err     error
			}{partNum, etag, nil}
		}(i)
	}

	// Collect results
	for i := 0; i < numParts; i++ {
		result := <-results
		require.NoError(t, result.err, fmt.Sprintf("Part %d failed", result.partNum+1))
		partETags[result.partNum] = result.etag
	}

	// Complete multipart upload
	var completeRequest strings.Builder
	completeRequest.WriteString("<CompleteMultipartUpload>")
	for i, etag := range partETags {
		completeRequest.WriteString(fmt.Sprintf(
			"<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>",
			i+1, etag))
	}
	completeRequest.WriteString("</CompleteMultipartUpload>")

	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("POST",
		fmt.Sprintf("/test-bucket/concurrent-test?uploadId=%s", uploadID),
		strings.NewReader(completeRequest.String()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/xml")
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify complete object
	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/test-bucket/concurrent-test", nil)
	require.NoError(t, err)
	proxyServer.ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusOK, recorder.Code)

	// Verify all part data is present in correct order
	retrievedData := recorder.Body.Bytes()
	var expectedData []byte
	for i := 0; i < numParts; i++ {
		expectedData = append(expectedData, partData[i]...)
	}
	assert.Equal(t, expectedData, retrievedData, "Retrieved data should contain all parts in correct order")
}
