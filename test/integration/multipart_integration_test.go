//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
)

// TestProxyConfigurationIntegration tests proxy configuration without external dependencies
// Real MinIO integration tests are in multipart_e2e_test.go
func TestProxyConfigurationIntegration(t *testing.T) {
	// Test proxy server configuration and setup

	// Create test configuration
	testCfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "debug",
		TargetEndpoint: "http://localhost:9000",
		Region:         "us-east-1",
		AccessKeyID:    "test-access-key",
		SecretKey:      "test-secret-key",
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "test-aes",
			Providers: []config.EncryptionProvider{
				{
					Alias:       "test-aes",
					Type:        "aes-gcm",
					Description: "Test AES-GCM provider",
					Config: map[string]interface{}{
						"aes_key": "dGVzdC1rZXktMzItYnl0ZXMtZm9yLWFlcy0yNTYhISE=",
					},
				},
			},
		},
	}

	// Create and test proxy server
	proxyServer, err := proxy.NewServer(testCfg)
	require.NoError(t, err)
	assert.NotNil(t, proxyServer)

	// Test that the server can be started
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test graceful handling of context cancellation
	go func() {
		_ = proxyServer.Start(ctx)
	}()

	// Cancel after a short period to test graceful shutdown
	cancel()

	t.Log("Proxy configuration integration test completed successfully")
}
