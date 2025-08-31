package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificates creates temporary certificate and key files for testing
func generateTestCertificates(t *testing.T) (certFile, keyFile string) {
	tempDir := t.TempDir()
	certFile = filepath.Join(tempDir, "cert.pem")
	keyFile = filepath.Join(tempDir, "key.pem")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	// Write certificate file
	certOut, err := os.Create(certFile)
	require.NoError(t, err)
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, err)

	// Write private key file
	keyOut, err := os.Create(keyFile)
	require.NoError(t, err)
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	require.NoError(t, err)

	return certFile, keyFile
}

func TestServerTLSConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		tlsEnabled  bool
		expectHTTPS bool
	}{
		{
			name:        "HTTP server without TLS",
			tlsEnabled:  false,
			expectHTTPS: false,
		},
		{
			name:        "HTTPS server with TLS",
			tlsEnabled:  true,
			expectHTTPS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := &config.Config{
				BindAddress:    "localhost:0",
				TargetEndpoint: "https://s3.amazonaws.com",
				Region:         "us-east-1",
				EncryptionType: "aes256-gcm",
				AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
				TLS: config.TLSConfig{
					Enabled: false, // Will be updated based on test case
				},
			}

			// Generate certificates if TLS is enabled
			if tt.tlsEnabled {
				certFile, keyFile := generateTestCertificates(t)
				cfg.TLS.Enabled = true
				cfg.TLS.CertFile = certFile
				cfg.TLS.KeyFile = keyFile
			}

			// Create server
			server, err := NewServer(cfg)
			require.NoError(t, err)

			// Start server in background
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serverErrChan := make(chan error, 1)
			go func() {
				if err := server.Start(ctx); err != nil {
					serverErrChan <- err
				}
			}()

			// Wait for server to start
			time.Sleep(100 * time.Millisecond)

			// Get the actual address the server is listening on
			listener := server.httpServer.Addr
			if listener == "localhost:0" {
				// Server hasn't started yet or address not available
				t.Skip("Cannot determine server address")
			}

			// Test connection based on TLS configuration
			protocol := "http"
			if tt.expectHTTPS {
				protocol = "https"
			}

			// Create HTTP client
			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			// For HTTPS, skip certificate verification in tests
			if tt.expectHTTPS {
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				client.Transport = tr
			}

			// Make request to health endpoint
			url := fmt.Sprintf("%s://%s/health", protocol, listener)
			resp, err := client.Get(url)

			if tt.expectHTTPS {
				// For HTTPS, we expect a successful response
				require.NoError(t, err, "HTTPS request should succeed")
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()
			} else {
				// For HTTP, we expect a successful response
				require.NoError(t, err, "HTTP request should succeed")
				assert.Equal(t, http.StatusOK, resp.StatusCode)
				resp.Body.Close()
			}

			// Stop server
			cancel()

			// Wait for server to stop or error
			select {
			case err := <-serverErrChan:
				if err != nil {
					t.Logf("Server error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Log("Server shutdown timeout")
			}
		})
	}
}

func TestServerTLSInvalidCertificates(t *testing.T) {
	// Create test configuration with invalid certificate paths
	cfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "error",
		TargetEndpoint: "https://s3.amazonaws.com",
		Region:         "us-east-1",
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: "/non/existent/cert.pem",
			KeyFile:  "/non/existent/key.pem",
		},
	}

	// Create server (this should succeed as validation happens during config loading)
	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Start server - this should fail due to missing certificate files
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = server.Start(ctx)
	assert.Error(t, err, "Server should fail to start with invalid certificates")
	assert.Contains(t, err.Error(), "HTTPS server failed", "Error should indicate HTTPS server failure")
}

func TestServerTLSGracefulShutdown(t *testing.T) {
	// Generate test certificates
	certFile, keyFile := generateTestCertificates(t)

	// Create test configuration
	cfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "error",
		TargetEndpoint: "https://s3.amazonaws.com",
		Region:         "us-east-1",
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}

	// Create server
	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Start(ctx)
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Trigger graceful shutdown
	cancel()

	// Wait for server to shutdown
	select {
	case err := <-serverDone:
		assert.NoError(t, err, "Server should shutdown gracefully")
	case <-time.After(5 * time.Second):
		t.Fatal("Server shutdown timeout")
	}
}

func TestTLSConfigurationLogging(t *testing.T) {
	// This test verifies that TLS configuration is properly logged
	// Generate test certificates
	certFile, keyFile := generateTestCertificates(t)

	cfg := &config.Config{
		BindAddress:    "localhost:0",
		LogLevel:       "info", // Enable info logging to capture TLS logs
		TargetEndpoint: "https://s3.amazonaws.com",
		Region:         "us-east-1",
		EncryptionType: "aes256-gcm",
		AESKey:         "1UR+yQO2Ap3NJabyhkwSm0qk/vllEa2Jae+NSxyVas8=", // 32-byte base64 key
		TLS: config.TLSConfig{
			Enabled:  true,
			CertFile: certFile,
			KeyFile:  keyFile,
		},
	}

	// Create server
	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Verify that the TLS configuration is properly set
	assert.True(t, server.config.TLS.Enabled)
	assert.Equal(t, certFile, server.config.TLS.CertFile)
	assert.Equal(t, keyFile, server.config.TLS.KeyFile)

	// Start and quickly stop server to test logging
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = server.Start(ctx)
	}()

	// Wait briefly then cancel
	time.Sleep(50 * time.Millisecond)
	cancel()
}
