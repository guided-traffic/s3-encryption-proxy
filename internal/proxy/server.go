package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/internal/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/internal/s3"
	"github.com/sirupsen/logrus"
)

// Server represents the S3 encryption proxy server
type Server struct {
	httpServer    *http.Server
	s3Client      *s3.Client
	encryptionMgr *encryption.Manager
	config        *config.Config
	logger        *logrus.Entry
}

// NewServer creates a new proxy server instance
func NewServer(cfg *config.Config) (*Server, error) {
	logger := logrus.WithField("component", "proxy-server")

	// Create encryption manager
	encCfg := &encryption.Config{
		KEKUri:          cfg.KEKUri,
		CredentialsPath: cfg.CredentialsPath,
		Algorithm:       cfg.Algorithm,
		KeyRotationDays: cfg.KeyRotationDays,
	}

	encryptionMgr, err := encryption.NewManager(encCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption manager: %w", err)
	}

	// Create S3 client
	s3Cfg := &s3.Config{
		Endpoint:       cfg.TargetEndpoint,
		Region:         cfg.Region,
		AccessKeyID:    cfg.AccessKeyID,
		SecretKey:      cfg.SecretKey,
		MetadataPrefix: cfg.MetadataKeyPrefix,
		DisableSSL:     false, // You might want to make this configurable
		ForcePathStyle: true,  // Common for S3-compatible services
	}

	s3Client, err := s3.NewClient(s3Cfg, encryptionMgr)
	if err != nil {
		return nil, fmt.Errorf("failed to create S3 client: %w", err)
	}

	// Create HTTP server with routes
	router := mux.NewRouter()
	server := &Server{
		s3Client:      s3Client,
		encryptionMgr: encryptionMgr,
		config:        cfg,
		logger:        logger,
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

// Start starts the proxy server
func (s *Server) Start(ctx context.Context) error {
	// Start HTTP server in a goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		s.logger.WithField("address", s.config.BindAddress).Info("Starting HTTP server")
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- fmt.Errorf("HTTP server failed: %w", err)
		}
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-serverErrChan:
		return err
	case <-ctx.Done():
		s.logger.Info("Shutting down HTTP server")

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

// setupRoutes configures the HTTP routes for the S3 API
func (s *Server) setupRoutes(router *mux.Router) {
	// Health check endpoint
	router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// S3 API endpoints
	// Bucket operations
	router.HandleFunc("/{bucket}", s.handleListObjects).Methods("GET")
	router.HandleFunc("/{bucket}/", s.handleListObjects).Methods("GET")

	// Object operations
	router.HandleFunc("/{bucket}/{key:.*}", s.handleObject).Methods("GET", "PUT", "DELETE", "HEAD")

	// Add middleware
	router.Use(s.loggingMiddleware)
	router.Use(s.corsMiddleware)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleListObjects handles bucket listing requests
func (s *Server) handleListObjects(w http.ResponseWriter, r *http.Request) {
	s.logger.Debug("Handling list objects request")
	// This would implement S3 ListObjects API
	// For now, return a simple response
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("ListObjects not implemented yet"))
}

// handleObject handles object operations (GET, PUT, DELETE, HEAD)
func (s *Server) handleObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling object request")

	switch r.Method {
	case "GET":
		s.handleGetObject(w, r, bucket, key)
	case "PUT":
		s.handlePutObject(w, r, bucket, key)
	case "DELETE":
		s.handleDeleteObject(w, r, bucket, key)
	case "HEAD":
		s.handleHeadObject(w, r, bucket, key)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetObject handles GET object requests
func (s *Server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// This would implement the actual S3 GetObject call through our encrypted client
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object")

	// For now, return not implemented
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("GetObject not implemented yet"))
}

// handlePutObject handles PUT object requests
func (s *Server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// This would implement the actual S3 PutObject call through our encrypted client
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Putting object")

	// For now, return not implemented
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("PutObject not implemented yet"))
}

// handleDeleteObject handles DELETE object requests
func (s *Server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// This would implement the actual S3 DeleteObject call through our client
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Deleting object")

	// For now, return not implemented
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte("DeleteObject not implemented yet"))
}

// handleHeadObject handles HEAD object requests
func (s *Server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	// This would implement the actual S3 HeadObject call through our client
	s.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object metadata")

	// For now, return not implemented
	w.WriteHeader(http.StatusNotImplemented)
}

// loggingMiddleware logs HTTP requests
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		s.logger.WithFields(logrus.Fields{
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     wrapped.statusCode,
			"duration":   time.Since(start),
			"user_agent": r.UserAgent(),
			"remote_ip":  r.RemoteAddr,
		}).Info("HTTP request")
	})
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Amz-*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
