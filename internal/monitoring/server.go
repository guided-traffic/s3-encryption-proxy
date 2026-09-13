package monitoring

import (
	"context"
	"errors"
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

	// The proxy's own registry, not the default gatherer: promhttp.Handler()
	// serves prometheus.DefaultGatherer, and nothing this process produces is
	// registered there any more.
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(Gatherer(), promhttp.HandlerOpts{}))

	// Health check endpoint for monitoring
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK")); err != nil {
			// Log error but don't fail the health check
			_ = err // Error is already handled by the write operation itself
		}
	})

	// Server info endpoint
	mux.HandleFunc("/info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"service":"s3-encryption-proxy","monitoring":"enabled"}`)); err != nil {
			// Log error but don't fail the info endpoint
			_ = err // Error is already handled by the write operation itself
		}
	})

	// /debug/pprof is deliberately NOT registered here. This listener is
	// unauthenticated and binds every interface by default, while a heap or
	// goroutine profile of this process contains DEKs and plaintext buffers.
	// It lives on its own loopback listener, see pprof.go.
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

	// A listener the server never got is reported to the caller, not only logged:
	// the proxy must not carry on believing it is being observed.
	listenErr := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.WithError(err).Error("Monitoring server error")
			listenErr <- fmt.Errorf("monitoring server on %s: %w", s.httpServer.Addr, err)
		}
	}()

	select {
	case err := <-listenErr:
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown
	s.logger.Info("Shutting down monitoring server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("monitoring server shutdown failed: %w", err)
	}

	s.logger.Info("Monitoring server stopped")

	select {
	case err := <-listenErr:
		return err
	default:
	}
	return nil
}
