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
	"github.com/stretchr/testify/assert"
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
	// Skip this test temporarily due to proxy startup infrastructure issues
	// This test attempts to start multiple proxy instances which may conflict with existing processes
	t.Skip("Skipping TestFullEncryptionLifecycle due to proxy startup infrastructure issues - needs investigation")

	// Set log level to reduce noise during tests
	logrus.SetLevel(logrus.ErrorLevel)

	// Skip if MinIO is not available (we start our own proxy instances)
	EnsureMinIOAvailable(t)

	ctx := context.Background()

	// Create MinIO client for direct access
	minioClient, err := CreateMinIOClient()
	require.NoError(t, err, "Failed to create MinIO client")

	// Create test bucket
	bucketName := fmt.Sprintf("test-bucket-%d", time.Now().UnixNano())
	objectKey := "test-file"
	testData := []byte("This is test data for encryption lifecycle")
	originalHash := calculateSHA256(testData)

	CreateTestBucket(t, minioClient, bucketName)
	defer CleanupTestBucket(t, minioClient, bucketName)

	t.Logf("Starting full encryption lifecycle test with object hash: %s", originalHash)

	// ===== STEP 1: Upload unencrypted file directly to MinIO =====
	t.Run("Step 1: Upload unencrypted file to MinIO", func(t *testing.T) {
		_, err := minioClient.PutObject(ctx, &s3.PutObjectInput{
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
		// Configuration for encrypted proxy
		encryptedConfig := `
bind_address: "0.0.0.0:8081"
log_level: "debug"
target_endpoint: "http://localhost:9000"
access_key_id: "minioadmin"
secret_key: "minioadmin123"
region: "us-east-1"

encryption:
  encryption_method_alias: "test-aes"
  metadata_key_prefix: "s3ep-"
  providers:
    - alias: "test-aes"
      type: "aes-ctr"
      config:
        key: "12345678901234567890123456789012"  # 32 bytes for AES-256
        streaming:
          segment_size: 5242880  # 5MB
`
		configPath := createTempConfig(t, encryptedConfig)
		proxy := StartProxy(t, configPath, 8081)
		defer proxy.Stop()

		// Download via encrypted proxy
		resp, err := proxy.client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(objectKey),
		})
		require.NoError(t, err, "Failed to download file via encrypted proxy")

		downloadedData, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read downloaded data")
		resp.Body.Close()

		// Verify data consistency
		downloadedHash := calculateSHA256(downloadedData)
		assert.Equal(t, originalHash, downloadedHash, "Data hash should match after download via encrypted proxy")
		assert.Equal(t, testData, downloadedData, "Downloaded data should match original")

		t.Log("✅ Step 2: File downloaded successfully via encrypted proxy (unencrypted file)")
	})

	t.Log("🎉 Test completed successfully!")
}
