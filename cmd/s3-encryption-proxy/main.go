package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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
- AES-GCM authenticated encryption (legacy compatibility)
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

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	go func() {
		logrus.WithField("address", cfg.BindAddress).Info("Starting S3 encryption proxy server")
		if err := proxyServer.Start(ctx); err != nil {
			logrus.WithError(err).Fatal("Proxy server failed")
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logrus.Info("Received shutdown signal, gracefully shutting down...")

	// Cancel context to trigger graceful shutdown
	cancel()

	logrus.Info("Server stopped")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
