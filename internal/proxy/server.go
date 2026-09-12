package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	proxyconfig "github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/sirupsen/logrus"
)

// Server represents the S3 encryption proxy server
type Server struct {
	httpServer    *http.Server
	s3Backend     *s3.Client
	encryptionMgr *orchestration.Manager
	config        *proxyconfig.Config
	logger        *logrus.Entry

	// Graceful shutdown tracking
	shutdownStateHandler func() (bool, time.Time)
	requestStartHandler  func()
	requestEndHandler    func()

	// Middleware
	requestTracker *middleware.RequestTracker
	httpLogger     *middleware.Logger
	corsHandler    *middleware.CORS
	s3AuthService  *middleware.S3AuthenticationService
}

// NewServer creates a new proxy server instance
func NewServer(cfg *proxyconfig.Config) (*Server, error) {
	logger := logrus.WithField("component", "proxy-server")

	// Create encryption manager directly from the config
	encryptionMgr, err := orchestration.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	// Log information about loaded KEK providers
	providers := encryptionMgr.GetLoadedProviders()
	logger.WithField("totalProviders", len(providers)).Info("Loaded KEK (Key Encryption Key) providers")

	for _, provider := range providers {
		fields := logrus.Fields{
			"alias":       provider.Alias,
			"type":        provider.Type,
			"fingerprint": provider.Fingerprint,
		}

		if provider.IsActive {
			logger.WithFields(fields).Info("🔒🔑 Active KEK provider to encrypt and decrypt data")
		} else {
			logger.WithFields(fields).Info("🔑 Available KEK provider to decrypt data")
		}
	}

	// Get metadata prefix from encryption config
	metadataPrefix := "s3ep-" // default when not set
	var metadataSource string
	if cfg.Encryption.MetadataKeyPrefix != nil {
		// Key is explicitly set in config - use its value (even if empty)
		metadataPrefix = *cfg.Encryption.MetadataKeyPrefix
		if metadataPrefix == "" {
			metadataSource = "config (explicit empty)"
		} else {
			metadataSource = "config (explicit value)"
		}
	} else {
		metadataSource = "default (not set in config)"
	}

	// Log metadata prefix information
	logger.WithFields(logrus.Fields{
		"prefix": metadataPrefix,
		"source": metadataSource,
	}).Info("🏷️  Metadata prefix for encryption fields")

	// Create AWS SDK S3 client from the s3_backend configuration structure
	s3Config := cfg.S3Backend

	awsConfig := aws.Config{
		Region:      s3Config.Region,
		Credentials: credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretKey, ""),
	}

	// Configure endpoint resolver for MinIO/custom S3 endpoints
	s3Client := s3.NewFromConfig(awsConfig, backendClientOptions(s3Config, logger))

	// Create HTTP server with routes
	router := mux.NewRouter()
	server := &Server{
		s3Backend:     s3Client,
		encryptionMgr: encryptionMgr,
		config:        cfg,
		logger:        logger,
	}

	// The sweeper has to be able to tell the backend that an upload it is about to
	// forget is over; orchestration owns no S3 client, so the call is handed in
	// here. A backend that no longer knows the upload is the outcome asked for, so
	// NoSuchUpload is success.
	encryptionMgr.SetMultipartAbandoner(func(ctx context.Context, bucket, key, uploadID string) error {
		_, err := s3Client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		})
		var noSuchUpload *types.NoSuchUpload
		if errors.As(err, &noSuchUpload) {
			return nil
		}
		return err
	})

	// Setup routes
	server.setupRoutes(router)

	// ADR 0015. The two body budgets are 0 by default, which is net/http's "no
	// deadline": a transfer lasts as long as the client and the backend keep it
	// going, whatever the object size and the link speed. The fixed 30 s that
	// used to sit here made the largest servable object a function of the
	// client's bandwidth and reset healthy transfers mid-stream. The header and
	// idle budgets bound what is not a transfer and are never 0 (validated).
	httpServer := &http.Server{
		Addr:              cfg.BindAddress,
		Handler:           router,
		ReadTimeout:       time.Duration(cfg.ReadTimeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.WriteTimeout) * time.Second,
		ReadHeaderTimeout: time.Duration(cfg.ReadHeaderTimeout) * time.Second,
		IdleTimeout:       time.Duration(cfg.IdleTimeout) * time.Second,
	}

	server.httpServer = httpServer

	return server, nil
}

// backendClientOptions builds the option function for the S3 client the proxy
// uses to reach the backend.
//
// Extracted so the checksum settings below are testable: they are easy to get
// wrong in a way that only shows up under streaming load.
func backendClientOptions(s3Config proxyconfig.S3BackendConfig, logger *logrus.Entry) func(*s3.Options) {
	return func(o *s3.Options) {
		// Path-style addressing for MinIO and other custom S3 endpoints.
		o.UsePathStyle = true

		// The proxy hands the SDK an unseekable ciphertext stream: it is
		// produced on the fly so uploads never buffer a whole object. Asking the
		// SDK to compute a request checksum over such a stream fails outright
		// against a plain-HTTP backend ("unseekable stream is not supported
		// without TLS and trailing checksum") and costs a full extra pass over
		// every payload against an HTTPS one.
		//
		// WhenRequired keeps the checksums S3 mandates for specific operations
		// (DeleteObjects, for instance) and drops the opportunistic ones.
		// Object integrity between proxy and backend is not left uncovered: the
		// stored format is an authenticated segment chain, so the proxy detects
		// any modification when it opens the object (ADR 0003).
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired

		if s3Config.TargetEndpoint == "" {
			return
		}
		o.BaseEndpoint = aws.String(s3Config.TargetEndpoint)

		logger.WithFields(logrus.Fields{
			"target_endpoint":                 s3Config.TargetEndpoint,
			"s3_backend_insecure_skip_verify": s3Config.InsecureSkipVerify,
		}).Debug("TLS configuration for S3 client")

		if s3Config.InsecureSkipVerify {
			logger.Warn("TLS certificate verification is disabled - this should only be used for development/testing")
			// Build on the SDK's own client and override nothing but the TLS
			// configuration. A bare http.Transport here replaced every SDK
			// default at once — connection pool sizes, the dial, TLS handshake
			// and expect-continue budgets, and HTTP/2 — so the deployments that
			// skip certificate verification silently ran on a different
			// transport from the ones that do not.
			o.HTTPClient = awshttp.NewBuildableClient().WithTransportOptions(func(tr *http.Transport) {
				// Mutate, never replace: the SDK's own config carries
				// MinVersion TLS 1.2, and assigning a fresh tls.Config here
				// would silently drop it back to Go's default minimum.
				if tr.TLSClientConfig == nil {
					tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				}
				tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402 - configurable, and the user is warned
			})
			return
		}
		logger.Debug("TLS certificate verification is enabled")
	}
}

// SetShutdownStateHandler sets the handler to check shutdown state for health endpoint.
// Call it before Start: the routes read it while serving.
func (s *Server) SetShutdownStateHandler(handler func() (bool, time.Time)) {
	s.shutdownStateHandler = handler
}

// SetRequestTracker sets handlers for tracking active requests.
// Call it before Start: the routes read these while serving.
func (s *Server) SetRequestTracker(onStart, onEnd func()) {
	s.requestStartHandler = onStart
	s.requestEndHandler = onEnd
}

func (s *Server) Start(ctx context.Context) error {
	// Start HTTP server in a goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if s.config.TLS.Enabled {
			s.logger.WithFields(logrus.Fields{
				"address":   s.config.BindAddress,
				"cert_file": s.config.TLS.CertFile,
				"key_file":  s.config.TLS.KeyFile,
			}).Info("Starting HTTPS server")

			if err := s.httpServer.ListenAndServeTLS(s.config.TLS.CertFile, s.config.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		} else {
			s.logger.WithField("address", s.config.BindAddress).Info("Starting HTTP server")
			if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTP server failed: %w", err)
			}
		}
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-serverErrChan:
		return err
	case <-ctx.Done():
		protocol := "HTTP"
		if s.config.TLS.Enabled {
			protocol = "HTTPS"
		}
		s.logger.WithField("protocol", protocol).Info("Shutting down server")

		// shutdown_timeout is the single documented budget an in-flight transfer
		// gets when the process is asked to stop (ADR 0015 D4). A fixed 30 s here
		// used to cap the drain regardless of it, so an operator who set 120 got a
		// 120-second wait around a 30-second drain.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownBudget())
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.WithError(err).Error("Failed to gracefully shutdown server")
			return err
		}

		s.logger.Info("Server stopped")
		return nil
	}
}

// shutdownBudget is shutdown_timeout, with the documented 30-second fallback
// when it is unset or zero. main.go applies the same rule to the wait it puts
// around this drain; the two must agree or the shorter one silently wins.
func (s *Server) shutdownBudget() time.Duration {
	if s.config != nil && s.config.ShutdownTimeout > 0 {
		return time.Duration(s.config.ShutdownTimeout) * time.Second
	}
	return 30 * time.Second
}

// getMetadataPrefix returns the metadata prefix from config
// Shutdown releases what the server owns beyond its listener: the encryption
// manager's background session cleanup. The HTTP listener is stopped by
// cancelling the context passed to Start.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.encryptionMgr == nil {
		return nil
	}
	return s.encryptionMgr.Shutdown(ctx)
}

func (s *Server) getMetadataPrefix() string {
	if s.config.Encryption.MetadataKeyPrefix != nil {
		return *s.config.Encryption.MetadataKeyPrefix
	}
	return "s3ep-" // default
}
