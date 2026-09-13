package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
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

	// Unix nanoseconds, 0 when unset. Read from the shutdown path, written by
	// the signal handler in another goroutine.
	shutdownDeadline atomic.Int64

	// listenAddr is the address the listener actually bound, which is not
	// httpServer.Addr whenever the configured port is 0. Written by Start,
	// read by anything that has to reach the running server.
	listenAddr atomic.Value

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

// Addr is the address the listener bound, once Start has bound it. It is the
// configured address with the port resolved, so a configuration that asks for
// port 0 can still be reached - and logged.
func (s *Server) Addr() string {
	addr, _ := s.listenAddr.Load().(string)
	return addr
}

func (s *Server) Start(ctx context.Context) error {
	// The listener is opened here rather than inside ListenAndServe so that a
	// port the operator did not choose - port 0, and every test that uses it -
	// is known, and so that a bind failure is this call's error rather than one
	// arriving on a channel after it has already returned.
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("cannot listen on %s: %w", s.httpServer.Addr, err)
	}
	s.listenAddr.Store(listener.Addr().String())

	// Start HTTP server in a goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		if s.config.TLS.Enabled {
			s.logger.WithFields(logrus.Fields{
				"address":   listener.Addr().String(),
				"cert_file": s.config.TLS.CertFile,
				"key_file":  s.config.TLS.KeyFile,
			}).Info("Starting HTTPS server")

			if err := s.httpServer.ServeTLS(listener, s.config.TLS.CertFile, s.config.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTPS server failed: %w", err)
			}
		} else {
			s.logger.WithField("address", listener.Addr().String()).Info("Starting HTTP server")
			if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
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

// SetShutdownDeadline bounds the listener close by the operator's budget as a
// whole rather than by a fresh copy of it. Without it the phases are
// sequential and therefore additive: main.go can spend the full budget
// draining, and this would then spend another full one, against a pod whose
// termination grace period is derived from a single budget (ADR 0029 D3).
func (s *Server) SetShutdownDeadline(deadline time.Time) {
	s.shutdownDeadline.Store(deadline.UnixNano())
}

// shutdownBudget is what is left of shutdown_timeout once a deadline has been
// set, and the whole of it otherwise, with the documented 30-second fallback
// when it is unset or zero. It never returns zero: a non-positive remainder
// still has to close the listener, it just does not get to wait.
func (s *Server) shutdownBudget() time.Duration {
	full := 30 * time.Second
	if s.config != nil && s.config.ShutdownTimeout > 0 {
		full = time.Duration(s.config.ShutdownTimeout) * time.Second
	}
	if ns := s.shutdownDeadline.Load(); ns != 0 {
		if remaining := time.Until(time.Unix(0, ns)); remaining < full {
			if remaining <= 0 {
				return time.Nanosecond
			}
			return remaining
		}
	}
	return full
}

// Shutdown releases what the server owns beyond its listener: the encryption
// manager's background session cleanup. The HTTP listener is stopped by
// cancelling the context passed to Start.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.encryptionMgr == nil {
		return nil
	}
	return s.encryptionMgr.Shutdown(ctx)
}
