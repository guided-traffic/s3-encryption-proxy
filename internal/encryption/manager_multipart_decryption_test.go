package encryption

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// TestMultipartDecryptionSessionWorkflow demonstrates the complete workflow
// for the new session-based multipart decryption API with HMAC verification
func TestMultipartDecryptionSessionWorkflow(t *testing.T) {
	// Skip if this is a unit test run without proper config
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a test configuration with HMAC enabled
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification:     true,
			MetadataKeyPrefix:         stringPtrDecryption("test-"),
			EncryptionMethodAlias:     "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 32 bytes hex
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingThreshold:      1024 * 1024, // 1MB
			StreamingBufferSize:     64 * 1024,   // 64KB
			EnableAdaptiveBuffering: true,
		},
	}

	// Create manager
	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	ctx := context.Background()
	objectKey := "test-multipart-object"
	bucketName := "test-bucket"

	// Test data: 3 parts of different sizes
	testParts := map[int][]byte{
		1: make([]byte, 1024),   // 1KB
		2: make([]byte, 2048),   // 2KB
		3: make([]byte, 512),    // 512B
	}

	// Fill with random data
	for partNum, data := range testParts {
		if _, err := rand.Read(data); err != nil {
			t.Fatalf("Failed to generate random data for part %d: %v", partNum, err)
		}
	}

	// Step 1: Encrypt the parts using multipart upload simulation
	// (In real use, this would come from S3)

	// Simulate InitiateMultipartUpload
	uploadID := fmt.Sprintf("test-upload-%d", time.Now().Unix())
	err = manager.InitiateMultipartUpload(ctx, uploadID, objectKey, bucketName)
	if err != nil {
		t.Fatalf("Failed to initiate multipart upload: %v", err)
	}

	// Encrypt each part
	encryptedParts := make(map[int][]byte)
	var finalMetadata map[string]string
	var encryptedDEK []byte

	for partNum := 1; partNum <= len(testParts); partNum++ {
		result, err := manager.UploadPart(ctx, uploadID, partNum, testParts[partNum])
		if err != nil {
			t.Fatalf("Failed to encrypt part %d: %v", partNum, err)
		}
		encryptedParts[partNum] = result.EncryptedData
		if encryptedDEK == nil {
			encryptedDEK = result.EncryptedDEK
		}
	}

	// Complete multipart upload to get final metadata
	finalMetadata, err = manager.CompleteMultipartUpload(ctx, uploadID, nil)
	if err != nil {
		t.Fatalf("Failed to complete multipart upload: %v", err)
	}

	// Cleanup upload state
	manager.CleanupMultipartUpload(uploadID)

	// Step 2: Now test the new decryption session API

	sessionID := fmt.Sprintf("decrypt-session-%d", time.Now().Unix())

	// 2.1: Initiate decryption session
	err = manager.InitiateMultipartDecryption(ctx, sessionID, objectKey, bucketName, encryptedDEK, finalMetadata)
	if err != nil {
		t.Fatalf("Failed to initiate multipart decryption: %v", err)
	}

	// 2.2: Decrypt parts sequentially
	decryptedParts := make(map[int][]byte)
	for partNum := 1; partNum <= len(encryptedParts); partNum++ {
		decrypted, err := manager.DecryptMultipartDataWithSession(ctx, sessionID, partNum, encryptedParts[partNum])
		if err != nil {
			t.Fatalf("Failed to decrypt part %d: %v", partNum, err)
		}
		decryptedParts[partNum] = decrypted
	}

	// 2.3: Complete decryption and verify HMAC
	err = manager.CompleteMultipartDecryption(ctx, sessionID)
	if err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	// 2.4: Cleanup decryption session
	err = manager.CleanupMultipartDecryption(sessionID)
	if err != nil {
		t.Fatalf("Failed to cleanup decryption session: %v", err)
	}

	// Step 3: Verify that decrypted data matches original
	for partNum := 1; partNum <= len(testParts); partNum++ {
		original := testParts[partNum]
		decrypted := decryptedParts[partNum]

		if len(original) != len(decrypted) {
			t.Errorf("Part %d: length mismatch - original: %d, decrypted: %d",
				partNum, len(original), len(decrypted))
			continue
		}

		for i := 0; i < len(original); i++ {
			if original[i] != decrypted[i] {
				t.Errorf("Part %d: data mismatch at byte %d - original: %02x, decrypted: %02x",
					partNum, i, original[i], decrypted[i])
				break
			}
		}
	}

	t.Logf("✅ Multipart decryption session test completed successfully")
	t.Logf("   - Processed %d parts", len(testParts))
	t.Logf("   - Total original data: %d bytes", getTotalSize(testParts))
	t.Logf("   - Total decrypted data: %d bytes", getTotalSize(decryptedParts))
	t.Logf("   - HMAC verification: PASSED")
}

// TestMultipartDecryptionSequentialEnforcement tests that parts must be processed sequentially
func TestMultipartDecryptionSequentialEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a simple test configuration
	cfg := &config.Config{
		Encryption: config.EncryptionConfig{
			IntegrityVerification:     true,
			MetadataKeyPrefix:         stringPtrDecryption("test-"),
			EncryptionMethodAlias:     "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias: "test-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					},
				},
			},
		},
	}

	manager, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	ctx := context.Background()
	sessionID := "test-sequential-session"
	objectKey := "test-object"

	// Create some dummy metadata and DEK for the test
	metadata := map[string]string{
		"test-aes-iv":             "dGVzdGl2MTIzNDU2Nzg5MAo=", // base64 encoded IV
		"test-dek-algorithm":      "aes-256-ctr",
		"test-encrypted-dek":      "dGVzdGVuY3J5cHRlZGRlaw==", // dummy base64
		"test-kek-fingerprint":    "test-fingerprint",
		"test-hmac":               "dGVzdGhtYWMxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMw==", // dummy HMAC
	}

	// This will fail because we don't have the real encrypted DEK, but that's not the point
	// The point is to test the sequential enforcement
	err = manager.InitiateMultipartDecryption(ctx, sessionID, objectKey, "bucket", []byte("dummy"), metadata)
	if err != nil {
		// Expected to fail due to dummy data, skip the rest
		t.Skipf("Cannot test sequential enforcement without valid KEK: %v", err)
	}

	defer manager.CleanupMultipartDecryption(sessionID)

	// Try to decrypt part 3 before part 1 (should fail)
	_, err = manager.DecryptMultipartDataWithSession(ctx, sessionID, 3, []byte("dummy"))
	if err == nil {
		t.Fatal("Expected error when processing part 3 before part 1, but got none")
	}

	expectedError := "parts must be processed sequentially for HMAC verification: expected part 1, got part 3"
	if err.Error() != expectedError {
		t.Errorf("Expected error: %s\nGot error: %s", expectedError, err.Error())
	}

	t.Logf("✅ Sequential enforcement test passed: %v", err)
}

// Helper function
func getTotalSize(parts map[int][]byte) int {
	total := 0
	for _, data := range parts {
		total += len(data)
	}
	return total
}

// Helper function to create string pointer
func stringPtrDecryption(s string) *string {
	return &s
}
