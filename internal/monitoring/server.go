package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

// Server represents the monitoring server
type Server struct {
	httpServer *http.Server
	logger     *logrus.Entry
}

// Config holds monitoring server configuration
type Config struct {
	BindAddress string
	MetricsPath string
}

// NewServer creates a new monitoring server
func NewServer(cfg *Config) *Server {
	logger := logrus.WithField("component", "monitoring-server")

	mux := http.NewServeMux()

	// Prometheus metrics endpoint
	mux.Handle(cfg.MetricsPath, promhttp.Handler())

	// Health check endpoint for monitoring
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Log error but don't fail the health check
			_ = err // Error is already handled by the write operation itself
		}
	})

	// Server info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"service":"s3-encryption-proxy","monitoring":"enabled"}`)); err != nil {
			// Log error but don't fail the info endpoint
			_ = err // Error is already handled by the write operation itself
		}
	})

	httpServer := &http.Server{
		Addr:         cfg.BindAddress,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		httpServer: httpServer,
		logger:     logger,
	}
}

// Start starts the monitoring server
func (s *Server) Start(ctx context.Context) error {
	s.logger.WithField("address", s.httpServer.Addr).Info("Starting monitoring server")

	// Start server in goroutine
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithError(err).Error("Monitoring server error")
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	// Graceful shutdown
	s.logger.Info("Shutting down monitoring server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("monitoring server shutdown failed: %w", err)
	}

	s.logger.Info("Monitoring server stopped")
	return nil
}

// Stop stops the monitoring server
func (s *Server) Stop() error {
	return s.httpServer.Close()
}
