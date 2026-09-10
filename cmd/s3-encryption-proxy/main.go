package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/monitoring"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Build information injected at build time
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"

	// Command line flags
	cfgFile           string
	monitoringEnabled bool
	monitoringPort    string

	rootCmd = &cobra.Command{
		Use:   "s3-encryption-proxy",
		Short: "S3 Encryption Proxy provides transparent encryption for S3 objects",
		Long: `S3 Encryption Proxy is a transparent proxy that sits between S3 clients and S3 storage,
automatically encrypting objects before storage and decrypting them on retrieval.

The proxy uses envelope encryption with separate Key Encryption Key (KEK) and Data
Encryption Key (DEK) layers:

KEK providers (key encryption):
- aes: AES-256-GCM under a locally configured key
- none: pass-through, no encryption (testing/development)

Objects are stored as an authenticated AES-256-GCM segment chain, so every
segment carries its own nonce and tag and a modified object is never delivered
whole.

All configuration is done through YAML configuration files. Use --config to specify
a configuration file, or the proxy will look for configuration in standard locations.`,
		Run: runProxy,
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to configuration file (YAML format)")
	rootCmd.PersistentFlags().BoolVar(&monitoringEnabled, "monitoring", false, "enable Prometheus monitoring endpoint")
	rootCmd.PersistentFlags().StringVar(&monitoringPort, "monitoring-port", ":9090", "port for Prometheus monitoring endpoint")
}

func initConfig() {
	config.InitConfig(cfgFile)
}

func runProxy(_ *cobra.Command, _ []string) {
	// Display build information at startup
	logrus.WithFields(logrus.Fields{
		"version":   version,
		"commit":    commit,
		"buildTime": buildTime,
	}).Info("S3 Encryption Proxy build information")

	// Load configuration and start license monitoring
	cfg, licenseValidator, err := config.LoadAndStartLicense()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to load configuration")
	}

	// Override monitoring configuration from command line flags
	if monitoringEnabled {
		cfg.Monitoring.Enabled = true
		if monitoringPort != ":9090" {
			cfg.Monitoring.BindAddress = monitoringPort
		}
	}

	// Set up Prometheus metrics with build information
	monitoring.SetServerInfo(version, commit, buildTime)

	// Set license information in metrics if available
	if licenseValidator != nil {
		// Get license validation result to access claims
		token := os.Getenv("S3EP_LICENSE_TOKEN")
		if token == "" {
			// Try to load from file
			if cfg.LicenseFile != "" {
				if data, err := os.ReadFile(cfg.LicenseFile); err == nil {
					token = strings.TrimSpace(string(data))
				}
			}
		}

		if token != "" {
			if result := licenseValidator.ValidateLicense(token); result.Valid && result.Info != nil {
				monitoring.SetLicenseInfo(
					result.Info.Claims.LicenseeName,
					result.Info.Claims.LicenseeCompany,
					result.Info.ExpiresAt.Format("2006-01-02 15:04:05 UTC"),
					true,
					float64(result.Info.ExpiresAt.Unix()),
				)
			}
		}
	}

	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.WithError(err).Fatal("Invalid log level")
	}
	logrus.SetLevel(level)

	// Set log format
	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	case "text", "":
		logrus.SetFormatter(&logrus.TextFormatter{
			ForceColors:   true,
			FullTimestamp: true,
		})
	default:
		logrus.WithField("log_format", cfg.LogFormat).Fatal("Invalid log format, use 'text' or 'json'")
	}

	// The exit provider stops encrypting new objects. Say so at every start.
	if cfg.Encryption.EncryptionMethodAlias != "" {
		// Find the active provider
		for _, provider := range cfg.Encryption.Providers {
			if provider.Alias == cfg.Encryption.EncryptionMethodAlias {
				if provider.Type == "exit" {
					logrus.WithField("provider", provider.Alias).Warn(
						"⚠️  Exit provider active: new objects are stored unencrypted. " +
							"Objects this proxy encrypted earlier are still decrypted on read, " +
							"as long as the provider holding their key stays configured.")
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

	// Start monitoring server if enabled
	var monitoringServer *monitoring.Server
	if cfg.Monitoring.Enabled {
		monitoringConfig := &monitoring.Config{
			BindAddress: cfg.Monitoring.BindAddress,
			MetricsPath: cfg.Monitoring.MetricsPath,
		}
		monitoringServer = monitoring.NewServer(monitoringConfig)

		// Start monitoring server in background
		go func() {
			if err := monitoringServer.Start(ctx); err != nil && err != context.Canceled {
				logrus.WithError(err).Error("Monitoring server failed")
			}
		}()
	}

	// pprof gets its own listener, independent of monitoring.enabled: it is a
	// different security surface, and tying it to the metrics flag is what made
	// pprof_enabled a knob that silently did nothing without it. Config
	// validation guarantees the address is loopback.
	if cfg.Monitoring.PprofEnabled {
		pprofServer := monitoring.NewPprofServer(cfg.Monitoring.PprofBindAddress)
		go func() {
			if err := pprofServer.Start(ctx); err != nil && err != context.Canceled {
				logrus.WithError(err).Error("pprof server failed")
			}
		}()
	}

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

		// One deadline for the whole wait. Evaluating time.After inside the
		// select re-armed it on every ticker tick, so the timeout could only
		// fire after a full shutdownTimeout without a single tick — and the
		// ticker fires every second, so it never fired at all.
		timeout := time.After(shutdownTimeout)

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
			case <-timeout:
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

	// Stop the encryption manager's background session cleanup. Bounded by the
	// same budget as the request drain above.
	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	if err := proxyServer.Shutdown(stopCtx); err != nil {
		logrus.WithError(err).Warn("Encryption manager shutdown reported an error")
	}
	stopCancel()

	// Stop license validator
	if licenseValidator != nil {
		licenseValidator.Stop()
	}

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
