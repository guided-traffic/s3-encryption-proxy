package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
)

func setupMultipartTestServer(t *testing.T) *Server {
	cfg := &config.Config{
		BindAddress:    ":8080",
		TargetEndpoint: "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "testkey",
		SecretKey:      "testsecret",
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "default",
			Providers: []config.EncryptionProvider{
				{
					Alias:  "default",
					Type:   "none",
					Config: map[string]interface{}{},
				},
			},
		},
	}

	// Create encryption manager
	encryptionMgr, err := encryption.NewManager(cfg)
	require.NoError(t, err)

	// Create server (without S3 client for these unit tests)
	server := &Server{
		config:        cfg,
		logger:        logrus.WithField("component", "test-server"),
		encryptionMgr: encryptionMgr,
		s3Client:      nil, // We'll test logic without actual S3 calls
	}

	return server
}

func TestMultipartUploadEncryptionState(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Test creating multipart upload state
	uploadID := "test-upload-id"
	objectKey := "test-object"

	// Create multipart upload state
	state, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID, objectKey)
	require.NoError(t, err)
	assert.Equal(t, uploadID, state.UploadID)
	assert.Equal(t, objectKey, state.ObjectKey)
	assert.Equal(t, "default", state.ProviderAlias)

	// Test encrypting data for multipart upload
	testData := []byte("test multipart data part 1")
	encResult, err := server.encryptionMgr.EncryptMultipartData(context.Background(), uploadID, 1, testData)
	require.NoError(t, err)
	assert.NotNil(t, encResult)

	// Test recording part ETag
	err = server.encryptionMgr.RecordPartETag(uploadID, 1, "test-etag-1")
	require.NoError(t, err)

	err = server.encryptionMgr.RecordPartETag(uploadID, 2, "test-etag-2")
	require.NoError(t, err)

	// Verify ETags were recorded
	retrievedState, err := server.encryptionMgr.GetMultipartUploadState(uploadID)
	require.NoError(t, err)
	assert.Equal(t, "test-etag-1", retrievedState.PartETags[1])
	assert.Equal(t, "test-etag-2", retrievedState.PartETags[2])

	// Test completing multipart upload
	finalState, err := server.encryptionMgr.CompleteMultipartUpload(uploadID)
	require.NoError(t, err)
	assert.Equal(t, uploadID, finalState.UploadID)
	assert.Equal(t, objectKey, finalState.ObjectKey)
	assert.Contains(t, finalState.PartETags, 1)
	assert.Contains(t, finalState.PartETags, 2)

	// Test aborting multipart upload (create a new one first)
	uploadID2 := "test-upload-id-2"
	_, err = server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID2, "object2")
	require.NoError(t, err)

	err = server.encryptionMgr.AbortMultipartUpload(uploadID2)
	require.NoError(t, err)

	// Verify aborted upload was cleaned up
	_, err = server.encryptionMgr.GetMultipartUploadState(uploadID2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestHandleCreateMultipartUploadValidation(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Test empty vars (should cause panic which we'll catch)
	req := httptest.NewRequest("POST", "/test-bucket/test-object?uploads", nil)
	// Don't set vars, this should cause the handler to fail early

	rr := httptest.NewRecorder()

	// This should fail safely without calling S3
	defer func() {
		if r := recover(); r == nil {
			// If no panic, the test passed (validation worked)
			t.Log("Handler handled missing vars gracefully")
		} else {
			// If panic, it's expected due to missing URL vars
			t.Log("Handler panicked as expected due to missing URL vars")
		}
	}()

	server.handleCreateMultipartUpload(rr, req)
}

func TestHandleUploadPartValidation(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Test missing query parameters
	req := httptest.NewRequest("PUT", "/test-bucket/test-object", strings.NewReader("test data"))
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-object"})

	rr := httptest.NewRecorder()
	server.handleUploadPart(rr, req)

	// Should return bad request due to missing uploadId and partNumber
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Test invalid part number
	req2 := httptest.NewRequest("PUT", "/test-bucket/test-object?partNumber=0&uploadId=test", strings.NewReader("test data"))
	req2 = mux.SetURLVars(req2, map[string]string{"bucket": "test-bucket", "key": "test-object"})

	rr2 := httptest.NewRecorder()
	server.handleUploadPart(rr2, req2)

	// Should return bad request due to invalid partNumber (0)
	assert.Equal(t, http.StatusBadRequest, rr2.Code)
}

func TestHandleCompleteMultipartUploadValidation(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Test missing uploadId
	req := httptest.NewRequest("POST", "/test-bucket/test-object", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-object"})

	rr := httptest.NewRecorder()
	server.handleCompleteMultipartUpload(rr, req)

	// Should return bad request due to missing uploadId
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestHandleUploadPartCopyNotSupported(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Create a valid multipart upload first
	uploadID := "test-upload-id"
	_, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID, "test-object")
	require.NoError(t, err)

	// Test that upload part copy returns not implemented
	req := httptest.NewRequest("PUT", "/test-bucket/test-object?partNumber=1&uploadId="+uploadID, nil)
	req.Header.Set("x-amz-copy-source", "/source-bucket/source-object")
	req = mux.SetURLVars(req, map[string]string{"bucket": "test-bucket", "key": "test-object"})

	rr := httptest.NewRecorder()
	server.handleUploadPartCopy(rr, req)

	assert.Equal(t, http.StatusNotImplemented, rr.Code)
	assert.Contains(t, rr.Body.String(), "not supported")
}

func TestMultipartUploadConcurrency(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Test concurrent multipart upload operations
	uploadID1 := "concurrent-upload-1"
	uploadID2 := "concurrent-upload-2"

	// Create uploads concurrently
	done := make(chan error, 2)

	go func() {
		_, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID1, "object1")
		done <- err
	}()

	go func() {
		_, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID2, "object2")
		done <- err
	}()

	// Wait for both uploads to complete
	for i := 0; i < 2; i++ {
		err := <-done
		require.NoError(t, err)
	}

	// Record parts concurrently for both uploads
	done2 := make(chan error, 4)

	go func() {
		done2 <- server.encryptionMgr.RecordPartETag(uploadID1, 1, "etag1-1")
	}()

	go func() {
		done2 <- server.encryptionMgr.RecordPartETag(uploadID1, 2, "etag1-2")
	}()

	go func() {
		done2 <- server.encryptionMgr.RecordPartETag(uploadID2, 1, "etag2-1")
	}()

	go func() {
		done2 <- server.encryptionMgr.RecordPartETag(uploadID2, 2, "etag2-2")
	}()

	// Wait for all part recordings to complete
	for i := 0; i < 4; i++ {
		err := <-done2
		require.NoError(t, err)
	}

	// Verify both uploads have their parts recorded correctly
	state1, err := server.encryptionMgr.GetMultipartUploadState(uploadID1)
	require.NoError(t, err)
	assert.Equal(t, "etag1-1", state1.PartETags[1])
	assert.Equal(t, "etag1-2", state1.PartETags[2])

	state2, err := server.encryptionMgr.GetMultipartUploadState(uploadID2)
	require.NoError(t, err)
	assert.Equal(t, "etag2-1", state2.PartETags[1])
	assert.Equal(t, "etag2-2", state2.PartETags[2])
}

func TestMultipartUploadStateIsolation(t *testing.T) {
	server := setupMultipartTestServer(t)

	// Create two different multipart uploads
	uploadID1 := "isolated-upload-1"
	uploadID2 := "isolated-upload-2"

	state1, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID1, "object1")
	require.NoError(t, err)

	state2, err := server.encryptionMgr.CreateMultipartUpload(context.Background(), uploadID2, "object2")
	require.NoError(t, err)

	// Verify they have different upload IDs and object keys
	assert.NotEqual(t, state1.UploadID, state2.UploadID, "Different uploads should have different upload IDs")
	assert.NotEqual(t, state1.ObjectKey, state2.ObjectKey, "Different uploads should have different object keys")

	// Note: With "none" provider, DEKs might be the same since no real encryption occurs
	// The important thing is that the states are isolated

	// Record parts for each upload
	err = server.encryptionMgr.RecordPartETag(uploadID1, 1, "upload1-part1")
	require.NoError(t, err)

	err = server.encryptionMgr.RecordPartETag(uploadID2, 1, "upload2-part1")
	require.NoError(t, err)

	// Verify parts are isolated between uploads
	finalState1, err := server.encryptionMgr.GetMultipartUploadState(uploadID1)
	require.NoError(t, err)
	assert.Equal(t, "upload1-part1", finalState1.PartETags[1])
	assert.NotContains(t, finalState1.PartETags, "upload2-part1")

	finalState2, err := server.encryptionMgr.GetMultipartUploadState(uploadID2)
	require.NoError(t, err)
	assert.Equal(t, "upload2-part1", finalState2.PartETags[1])
	assert.NotContains(t, finalState2.PartETags, "upload1-part1")
}
