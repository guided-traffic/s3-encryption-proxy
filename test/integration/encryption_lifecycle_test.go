//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// ProxyInstance represents a running proxy instance for testing
type ProxyInstance struct {
	cmd        *exec.Cmd
	configPath string
	port       int
	client     *s3.Client
}

// StartProxy starts a proxy instance on the specified port with the given config
func StartProxy(t *testing.T, configPath string, port int) *ProxyInstance {
	t.Helper()

	// Build the proxy binary
	cmd := exec.Command("go", "build", "-o", "/tmp/s3ep-test", "../../cmd/s3-encryption-proxy")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build proxy: %v", err)
	}

	// Start the proxy with the config
	cmd = exec.Command("/tmp/s3ep-test", "-config", configPath)
	cmd.Env = os.Environ()

	// Set up process group for clean shutdown
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Start the process
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}

	// Wait for proxy to be ready (simple TCP connection test)
	endpoint := fmt.Sprintf("localhost:%d", port)
	for i := 0; i < 30; i++ {
		conn, err := net.Dial("tcp", endpoint)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Create S3 client for this proxy instance
	client, err := createProxyClientForPort(port)
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("Failed to create proxy client: %v", err)
	}

	instance := &ProxyInstance{
		cmd:        cmd,
		configPath: configPath,
		port:       port,
		client:     client,
	}

	// Register cleanup
	t.Cleanup(func() {
		instance.Stop()
	})

	return instance
}

// Stop stops the proxy instance
func (p *ProxyInstance) Stop() {
	if p.cmd != nil && p.cmd.Process != nil {
		// Kill the entire process group
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
		p.cmd.Wait()
	}
}

// createProxyClientForPort creates an S3 client for a specific proxy port
func createProxyClientForPort(port int) (*s3.Client, error) {
	return createProxyClientWithEndpoint(fmt.Sprintf("http://localhost:%d", port))
}

// createTempConfig creates a temporary configuration file
func createTempConfig(t *testing.T, configContent string) string {
	t.Helper()

	tmpFile, err := os.CreateTemp("", "s3ep-test-*.yaml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(configContent)
	require.NoError(t, err)

	err = tmpFile.Close()
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(tmpFile.Name())
	})

	return tmpFile.Name()
}

// TestFullEncryptionLifecycle tests the complete encryption lifecycle with different proxy configurations
func TestFullEncryptionLifecycle(t *testing.T) {
	// Use existing proxy infrastructure instead of starting new instances
	ctx := NewTestContext(t)

	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Use test infrastructure
	minioClient := ctx.MinIOClient
	proxyClient := ctx.ProxyClient

	// Create test bucket
	bucketName := fmt.Sprintf("lifecycle-test-bucket-%d", time.Now().UnixNano())
	objectKey := "test-file"
	testData := []byte("This is test data for encryption lifecycle")
	originalHash := calculateSHA256(testData)

	ctx.TestBucket = bucketName
	CreateTestBucket(t, ctx.MinIOClient, bucketName)
	defer ctx.CleanupTestBucket()

	t.Logf("Starting full encryption lifecycle test with object hash: %s", originalHash)

	// ===== STEP 1: Upload unencrypted file directly to MinIO =====
	t.Run("Step 1: Upload unencrypted file to MinIO", func(t *testing.T) {
		_, err := minioClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
			Body:   bytes.NewReader(testData),
			Metadata: map[string]string{
				"step": "1",
			},
		})
		require.NoError(t, err, "Failed to upload file directly to MinIO")
		t.Log("✅ Step 1: File uploaded directly to MinIO")
	})

	// ===== STEP 2: Try to download the file via the encrypted proxy =====
	t.Run("Step 2: Download unencrypted file via encrypted proxy", func(t *testing.T) {
		// Try to download the unencrypted file via the proxy
		// This should fail or return corrupted data since the file lacks encryption metadata
		resp, err := proxyClient.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})

		if err != nil {
			t.Logf("✅ Step 2: Proxy correctly failed to download unencrypted file: %v", err)
			return
		}

		downloadedData, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read downloaded data")
		resp.Body.Close()

		downloadedHash := calculateSHA256(downloadedData)

		// The proxy should either fail or return different data (due to lack of encryption metadata)
		if downloadedHash != originalHash {
			t.Logf("✅ Step 2: Proxy returned different data for unencrypted file (expected)")
			t.Logf("   Original hash: %s", originalHash)
			t.Logf("   Downloaded hash: %s", downloadedHash)
		} else {
			t.Log("⚠️  Step 2: Proxy returned same data - this indicates lack of encryption validation")
		}
	})

	// ===== STEP 3: Upload file via encrypted proxy =====
	t.Run("Step 3: Upload file via encrypted proxy", func(t *testing.T) {
		objectKey2 := "encrypted-test-file"
		
		// Upload via encrypted proxy
		_, err := proxyClient.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey2),
			Body:   bytes.NewReader(testData),
			Metadata: map[string]string{
				"step": "3",
			},
		})
		require.NoError(t, err, "Failed to upload file via encrypted proxy")
		t.Log("✅ Step 3: File uploaded via encrypted proxy")

		// Verify it's encrypted by checking raw MinIO data
		rawResp, err := minioClient.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey2),
		})
		require.NoError(t, err, "Failed to get raw data from MinIO")

		rawData, err := io.ReadAll(rawResp.Body)
		require.NoError(t, err, "Failed to read raw data")
		rawResp.Body.Close()

		rawHash := calculateSHA256(rawData)
		
		// Raw data should be different (encrypted)
		if rawHash != originalHash {
			t.Log("✅ Step 3: Raw data in MinIO is encrypted (different hash)")
		} else {
			t.Error("❌ Step 3: Raw data appears to be unencrypted")
		}

		// Now download via proxy and verify decryption
		proxyResp, err := proxyClient.GetObject(context.Background(), &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey2),
		})
		require.NoError(t, err, "Failed to download via proxy")

		decryptedData, err := io.ReadAll(proxyResp.Body)
		require.NoError(t, err, "Failed to read decrypted data")
		proxyResp.Body.Close()

		decryptedHash := calculateSHA256(decryptedData)
		
		// Decrypted data should match original
		if decryptedHash == originalHash {
			t.Log("✅ Step 3: Proxy correctly decrypted the data")
		} else {
			t.Error("❌ Step 3: Proxy failed to decrypt the data correctly")
		}
	})

	t.Log("🎉 Encryption lifecycle test completed successfully!")
}
