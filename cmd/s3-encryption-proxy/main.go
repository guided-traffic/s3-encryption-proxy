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

	// What the active provider costs, said at every start. Both warnings are the
	// exit provider's: an encrypting provider cannot reach either of them,
	// because a plain-HTTP backend under one refuses the start (ADR 0013 D5).
	if provider, err := cfg.GetActiveProvider(); err == nil && provider != nil && provider.Type == "exit" {
		logrus.WithField("provider", provider.Alias).Warn(
			"⚠️  Exit provider active: new objects are stored unencrypted. " +
				"Objects this proxy encrypted earlier are still decrypted on read, " +
				"as long as the provider holding their key stays configured.")

		if strings.HasPrefix(cfg.S3Backend.TargetEndpoint, "http://") {
			logrus.WithField("target_endpoint", cfg.S3Backend.TargetEndpoint).Warn(
				"⚠️  Plain-HTTP S3 backend with the 'exit' provider: object bytes, " +
					"credentials, bucket names and object keys all travel in the clear " +
					"to the backend.")
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

	// Closed-on-idle, not polled: the shutdown budget is a ceiling, not a
	// duration (ADR 0029 D7). The last request to finish while draining says so
	// here, so the wait ends at that moment rather than on the next tick of a
	// one-second ticker.
	drained := make(chan struct{}, 1)
	signalDrained := func() {
		select {
		case drained <- struct{}{}:
		default:
		}
	}

	// Set shutdown state handler for health checks
	proxyServer.SetShutdownStateHandler(func() (bool, time.Time) {
		return atomic.LoadInt32(&shutdownMode) == 1, shutdownStart
	})

	// Set request tracking handlers
	proxyServer.SetRequestTracker(
		func() { atomic.AddInt64(&activeRequests, 1) },
		func() {
			if atomic.AddInt64(&activeRequests, -1) <= 0 && atomic.LoadInt32(&shutdownMode) == 1 {
				signalDrained()
			}
		},
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

	// The listener stays up. From here the drain guard answers every new S3
	// request with 503 and Retry-After while the transfers already running keep
	// their budget, so a client that arrives before a load balancer has taken this
	// instance out of rotation gets a retry rather than a connection refusal
	// (ADR 0029 D1). The listener is closed further down, once the drain is over.

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

		// Nothing in flight when the signal arrived: do not wait for a first tick
		// to discover it.
		if atomic.LoadInt64(&activeRequests) <= 0 {
			logrus.Info("Nothing in flight, draining is already done")
			close(shutdownComplete)
			return
		}

		for {
			select {
			case <-drained:
				if atomic.LoadInt64(&activeRequests) > 0 {
					continue
				}
				logrus.Info("All requests completed, shutting down immediately")
				close(shutdownComplete)
				return
			case <-ticker.C:
				// The ticker is only here to say what is still running; the line
				// above is what ends the wait.
				logrus.WithField("activeRequests", atomic.LoadInt64(&activeRequests)).
					Debug("Still waiting for requests to complete...")
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

	// Only now is the listener taken down: everything still in flight has either
	// finished or run out of budget, and a new request has been answered 503 since
	// the signal arrived.
	cancel()

	// Stop the background session cleanup and end the multipart uploads this
	// process is holding — nothing else can finish them once it exits (ADR 0029).
	//
	// Bounded by what is LEFT of the shutdown budget, not by a fresh one: the
	// chart derives the pod's termination grace period from the same value, so a
	// second full budget here is how a shutdown gets killed halfway through
	// cleaning up rather than finishing the uploads it still can.
	stopBudget := shutdownTimeout - time.Since(shutdownStart)
	if stopBudget <= 0 {
		logrus.WithField("timeout", shutdownTimeout).
			Warn("The request drain used the whole shutdown budget; open multipart uploads are left at the backend")
		stopBudget = time.Nanosecond
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), stopBudget)
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
