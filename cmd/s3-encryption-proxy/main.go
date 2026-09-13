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
	cfgFile string

	rootCmd = &cobra.Command{
		Use:   "s3-encryption-proxy",
		Short: "S3 Encryption Proxy provides transparent encryption for S3 objects",
		Long: `S3 Encryption Proxy is a transparent proxy that sits between S3 clients and S3 storage,
automatically encrypting objects before storage and decrypting them on retrieval.

The proxy uses envelope encryption with separate Key Encryption Key (KEK) and Data
Encryption Key (DEK) layers:

KEK providers (key encryption):
- aes: AES-256-GCM under a locally configured key
- exit: holds no key material. New objects are stored as the client sent them,
  while objects an aes provider wrote earlier are still decrypted on read, as
  long as that provider stays configured. "none" is refused by name.

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
}

func initConfig() {
	if err := config.InitConfig(cfgFile); err != nil {
		logrus.WithError(err).Fatal("Failed to read the configuration")
	}
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

	for _, warning := range startupWarnings(cfg) {
		logrus.WithFields(warning.fields).Warn(warning.message)
	}

	// Create and start the proxy server
	proxyServer, err := proxy.NewServer(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to create proxy server")
	}

	// Graceful shutdown state tracking. shutdownStart is Unix nanoseconds rather
	// than a time.Time because the drain guard reads it on every S3 request while
	// the signal handler writes it: a multi-word value needs the same atomic
	// treatment as the flag beside it.
	var (
		activeRequests int64 // Active request counter
		shutdownMode   int32 // 0 = normal, 1 = shutting down
		shutdownStart  atomic.Int64
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
		return atomic.LoadInt32(&shutdownMode) == 1, time.Unix(0, shutdownStart.Load())
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
	withMetrics, withPprof := monitoringPlan(cfg)
	var monitoringServer *monitoring.Server
	if withMetrics {
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
	if withPprof {
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

	// A licence that lapses while the proxy runs ends the process the same way a
	// SIGTERM does. Exiting from the monitoring goroutine instead skipped the
	// whole tail: no readiness 503, no drain, and every multipart upload this
	// process held left at the backend unfinishable (ADR 0029 D2). The exit code
	// stays 1 further down, so the container restarts into the startup licence
	// check (ADR 0016).
	licenseExpired := make(chan struct{}, 1)
	if licenseValidator != nil {
		licenseValidator.SetExpiryHandler(func() {
			select {
			case licenseExpired <- struct{}{}:
			default:
			}
		})
	}

	// Start server in goroutine
	go func() {
		logrus.WithField("address", cfg.BindAddress).Info("Starting S3 encryption proxy server")
		if err := proxyServer.Start(ctx); err != nil && err != context.Canceled {
			logrus.WithError(err).Fatal("Proxy server failed")
		}
	}()

	// Wait for a shutdown signal, or for the licence to lapse under us.
	exitCode := 0
	select {
	case sig := <-sigChan:
		logrus.WithField("signal", sig.String()).Info("Received shutdown signal, initiating graceful shutdown...")
	case <-licenseExpired:
		logrus.Error("License expired during runtime, initiating graceful shutdown...")
		exitCode = 1
	}

	// Enter shutdown mode - health endpoint will now return 503
	atomic.StoreInt32(&shutdownMode, 1)
	started := time.Now()
	shutdownStart.Store(started.UnixNano())

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

	// Steps 4 and 5 of ADR 0029 D1, in that order and on one budget. The
	// deadline is written once and handed to both phases: the same expression
	// spelled out twice is how the two ends of one budget drift apart.
	runShutdownTail(shutdownTail{
		deadline: started.Add(shutdownTimeout),
		budget:   shutdownTimeout,
		sweep:    proxyServer.Shutdown,
		closeListener: func(deadline time.Time) {
			proxyServer.SetShutdownDeadline(deadline)
			cancel()
		},
	})

	// Stop license validator
	if licenseValidator != nil {
		licenseValidator.Stop()
	}

	duration := time.Since(started)
	logrus.WithFields(logrus.Fields{
		"duration":       duration,
		"activeRequests": atomic.LoadInt64(&activeRequests),
	}).Info("Graceful shutdown completed")

	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// startupWarning is one line an operator has to see at every start.
type startupWarning struct {
	fields  logrus.Fields
	message string
}

// startupWarnings says what the active configuration costs.
//
// The warning is the exit provider's: an encrypting provider cannot reach it.
// It is the only thing that tells an operator the proxy is storing plaintext
// (ADR 0025 D10), so it is built here rather than written inline in the startup
// path, where nothing could read it back. The plain-HTTP backend that used to
// warn beside it refuses the start under every provider now (ADR 0013 D5).
func startupWarnings(cfg *config.Config) []startupWarning {
	provider, err := cfg.GetActiveProvider()
	if err != nil || provider == nil || provider.Type != "exit" {
		return nil
	}

	return []startupWarning{{
		fields: logrus.Fields{"provider": provider.Alias},
		message: "⚠️  Exit provider active: new objects are stored unencrypted. " +
			"Objects this proxy encrypted earlier are still decrypted on read, " +
			"as long as the provider holding their key stays configured.",
	}}
}

// monitoringPlan says which listeners a configuration asks for.
//
// The two are independent, and that independence is the decision (ADR 0013 D8):
// pprof is a different security surface from the metrics endpoint — it can dump
// a heap that holds data keys — so it has its own key, its own listener and its
// own loopback check. Nesting it inside monitoring.enabled is what made
// pprof_enabled a knob that silently did nothing on its own, and reading both
// through one function is what keeps the nesting from coming back unnoticed.
func monitoringPlan(cfg *config.Config) (metrics, pprof bool) {
	return cfg.Monitoring.Enabled, cfg.Monitoring.PprofEnabled
}

// shutdownTail is the part of ADR 0029 D1 that runs once the drain is over:
// sweep what cannot be finished, then close the listener. It is a struct with
// injected phases rather than straight-line code because the order is the
// decision and the budget arithmetic is where it went wrong before — both are
// worth a test, and neither is reachable from one against main().
type shutdownTail struct {
	// deadline is the one anchor of the whole shutdown: the moment the signal
	// arrived plus the operator's budget. Both phases are bounded by it, and it
	// is passed to the listener close rather than recomputed there.
	deadline      time.Time
	budget        time.Duration
	sweep         func(context.Context) error
	closeListener func(deadline time.Time)
}

// runShutdownTail ends every multipart upload this process is holding — nothing
// else can finish them once it exits (ADR 0029 D2) — and only then takes the
// listener down. The sweep gets what is LEFT of the operator's budget, not a
// fresh copy: the phases are sequential, so a second full budget is how a
// shutdown gets killed by the pod's grace period halfway through cleaning up
// (ADR 0029 D3).
//
// The listener closes last so that a readiness probe arriving during the sweep
// reads 503 shutting_down rather than a connection refusal, which a load
// balancer cannot tell apart from a dead backend (ADR 0029 D1 step 2).
func runShutdownTail(t shutdownTail) {
	remaining := time.Until(t.deadline)
	if remaining <= 0 {
		logrus.WithField("timeout", t.budget).
			Warn("The request drain used the whole shutdown budget; open multipart uploads are left at the backend")
		remaining = time.Nanosecond
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), remaining)
	if err := t.sweep(stopCtx); err != nil {
		logrus.WithError(err).Warn("Encryption manager shutdown reported an error")
	}
	stopCancel()

	t.closeListener(t.deadline)
}
