package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	proxyconfig "github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/sirupsen/logrus"
)

// Server represents the S3 encryption proxy server
type Server struct {
	httpServer    *http.Server
	s3Backend     *s3.Client
	encryptionMgr *encryption.Manager
	config        *proxyconfig.Config
	logger        *logrus.Entry

	// Monitoring
	monitoringEnabled bool

	// Graceful shutdown tracking
	shutdownStateHandler func() (bool, time.Time)
	requestStartHandler  func()
	requestEndHandler    func()

	// Middleware
	requestTracker *middleware.RequestTracker
	httpLogger     *middleware.Logger
	corsHandler    *middleware.CORS
}

// NewServer creates a new proxy server instance
func NewServer(cfg *proxyconfig.Config) (*Server, error) {
	logger := logrus.WithField("component", "proxy-server")

	// Create encryption manager directly from the config
	encryptionMgr, err := encryption.NewManager(cfg)
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

	// Create AWS SDK S3 client using new s3_backend configuration structure
	// Falls back to legacy top-level fields for backward compatibility
	s3Config := cfg.S3Backend
	if s3Config.Region == "" {
		s3Config.Region = cfg.Region // fallback to legacy
	}
	if s3Config.AccessKeyID == "" {
		s3Config.AccessKeyID = cfg.AccessKeyID // fallback to legacy
	}
	if s3Config.SecretKey == "" {
		s3Config.SecretKey = cfg.SecretKey // fallback to legacy
	}
	if s3Config.TargetEndpoint == "" {
		s3Config.TargetEndpoint = cfg.TargetEndpoint // fallback to legacy
	}
	if !s3Config.UseTLS {
		s3Config.UseTLS = cfg.UseTLS // fallback to legacy
	}
	if !s3Config.InsecureSkipVerify {
		s3Config.InsecureSkipVerify = cfg.SkipSSLVerification // fallback to legacy
	}

	awsConfig := aws.Config{
		Region:      s3Config.Region,
		Credentials: credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretKey, ""),
	}

	// Configure endpoint resolver for MinIO/custom S3 endpoints
	s3Client := s3.NewFromConfig(awsConfig, func(o *s3.Options) {
		// Force path-style addressing for MinIO/custom S3 endpoints
		o.UsePathStyle = true

		// Disable checksum validation for MinIO compatibility
		// MinIO doesn't support AWS checksum headers, causing SDK warnings
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported

		// Configure custom endpoint if specified
		if s3Config.TargetEndpoint != "" {
			o.BaseEndpoint = aws.String(s3Config.TargetEndpoint)
		}
		// Configure TLS verification based on configuration
		if s3Config.TargetEndpoint != "" {
			// Use the unified s3Config which includes migrated values
			skipTLSVerification := s3Config.InsecureSkipVerify

			logger.WithFields(logrus.Fields{
				"target_endpoint":                 s3Config.TargetEndpoint,
				"s3_backend_insecure_skip_verify": s3Config.InsecureSkipVerify,
				"final_skip_tls_verification":     skipTLSVerification,
			}).Debug("TLS configuration for S3 client")

			if skipTLSVerification {
				logger.Warn("TLS certificate verification is disabled - this should only be used for development/testing")
				o.HTTPClient = &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true, // #nosec G402 - This is configurable and warns user
						},
					},
				}
			} else {
				logger.Debug("TLS certificate verification is enabled")
			}
		}
	})

	// Create HTTP server with routes
	router := mux.NewRouter()
	server := &Server{
		s3Backend:         s3Client,
		encryptionMgr:     encryptionMgr,
		config:            cfg,
		logger:            logger,
		monitoringEnabled: cfg.Monitoring.Enabled,
	}

	// Setup routes
	server.setupRoutes(router)

	httpServer := &http.Server{
		Addr:         cfg.BindAddress,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	server.httpServer = httpServer

	return server, nil
}

// SetShutdownStateHandler sets the handler to check shutdown state for health endpoint
func (s *Server) SetShutdownStateHandler(handler func() (bool, time.Time)) {
	s.shutdownStateHandler = handler
}

// SetRequestTracker sets handlers for tracking active requests
func (s *Server) SetRequestTracker(onStart, onEnd func()) {
	s.requestStartHandler = onStart
	s.requestEndHandler = onEnd
}

// GetHandler returns the HTTP handler for testing purposes
func (s *Server) GetHandler() http.Handler {
	router := mux.NewRouter()
	s.setupRoutes(router)
	return router
}

// Start starts the proxy server
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

		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.WithError(err).Error("Failed to gracefully shutdown server")
			return err
		}

		s.logger.Info("Server stopped")
		return nil
	}
}

// getMetadataPrefix returns the metadata prefix from config
func (s *Server) getMetadataPrefix() string {
	if s.config.Encryption.MetadataKeyPrefix != nil {
		return *s.config.Encryption.MetadataKeyPrefix
	}
	return "s3ep-" // default
}
