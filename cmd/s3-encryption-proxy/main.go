package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Build information injected at build time
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"

	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "s3-encryption-proxy",
		Short: "S3 Encryption Proxy provides transparent encryption for S3 objects",
		Long: `S3 Encryption Proxy is a transparent proxy that sits between S3 clients and S3 storage,
automatically encrypting objects before storage and decrypting them on retrieval.

The proxy uses envelope encryption with separate Key Encryption Key (KEK) and Data
Encryption Key (DEK) layers:

KEK Providers (key encryption):
- Tink with KMS integration (production, cloud-native)
- RSA asymmetric encryption (self-hosted, no external dependencies)
- AES symmetric encryption (fast, requires pre-shared key)

DEK Providers (data encryption):
- AES-GCM authenticated encryption (small files)
- AES-CTR streaming encryption (large files and multipart uploads)
- None provider (pass-through for testing/development)

All configuration is done through YAML configuration files. Use --config to specify
a configuration file, or the proxy will look for configuration in standard locations.`,
		Run: runProxy,
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to configuration file (YAML format)")
}

func initConfig() {
	config.InitConfig(cfgFile)
}

func runProxy(cmd *cobra.Command, args []string) {
	// Display build information at startup
	logrus.WithFields(logrus.Fields{
		"version":   version,
		"commit":    commit,
		"buildTime": buildTime,
	}).Info("S3 Encryption Proxy build information")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid log level")
	}
	logrus.SetLevel(level)

	// Check for "none" encryption method and warn user
	if cfg.Encryption.EncryptionMethodAlias != "" {
		// Find the active provider
		for _, provider := range cfg.Encryption.Providers {
			if provider.Alias == cfg.Encryption.EncryptionMethodAlias {
				if provider.Type == "none" {
					logrus.WithField("provider", provider.Alias).Warn("⚠️  SECURITY WARNING: Encryption is disabled! Objects will be stored unencrypted in S3. This should only be used for development/testing.")
				}
				break
			}
		}
	}

	// Create and start the proxy server
	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create proxy server")
	}

	// Graceful shutdown state tracking
	var (
		activeRequests int64     // Active request counter
		shutdownMode   int32     // 0 = normal, 1 = shutting down
		shutdownStart  time.Time // When shutdown started
	)

	// Set shutdown state handler for health checks
	proxyServer.SetShutdownStateHandler(func() (bool, time.Time) {
		return atomic.LoadInt32(&shutdownMode) == 1, shutdownStart
	})

	// Set request tracking handlers
	proxyServer.SetRequestTracker(
		func() { atomic.AddInt64(&activeRequests, 1) },  // on request start
		func() { atomic.AddInt64(&activeRequests, -1) }, // on request end
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		logrus.WithField("address", cfg.BindAddress).Info("Starting S3 encryption proxy server")
		if err := proxyServer.Start(ctx); err != nil && err != context.Canceled {
			logrus.WithError(err).Fatal("Proxy server failed")
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	logrus.WithField("signal", sig.String()).Info("Received shutdown signal, initiating graceful shutdown...")

	// Enter shutdown mode - health endpoint will now return 503
	atomic.StoreInt32(&shutdownMode, 1)
	shutdownStart = time.Now()

	// Stop accepting new connections
	cancel()

	// Wait for active requests to complete with timeout
	shutdownTimeout := 30 * time.Second
	if cfg.ShutdownTimeout > 0 {
		shutdownTimeout = time.Duration(cfg.ShutdownTimeout) * time.Second
	}

	logrus.WithFields(logrus.Fields{
		"timeout":        shutdownTimeout,
		"activeRequests": atomic.LoadInt64(&activeRequests),
	}).Info("Waiting for active requests to complete...")

	// Graceful shutdown with active request monitoring
	shutdownComplete := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				active := atomic.LoadInt64(&activeRequests)
				if active == 0 {
					logrus.Info("All requests completed, shutting down immediately")
					close(shutdownComplete)
					return
				}
				logrus.WithField("activeRequests", active).Debug("Still waiting for requests to complete...")
			case <-time.After(shutdownTimeout):
				active := atomic.LoadInt64(&activeRequests)
				if active > 0 {
					logrus.WithField("activeRequests", active).Warn("Shutdown timeout reached, forcing shutdown with active requests")
				}
				close(shutdownComplete)
				return
			}
		}
	}()

	// Wait for graceful shutdown to complete
	<-shutdownComplete

	duration := time.Since(shutdownStart)
	logrus.WithFields(logrus.Fields{
		"duration":       duration,
		"activeRequests": atomic.LoadInt64(&activeRequests),
	}).Info("Graceful shutdown completed")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
