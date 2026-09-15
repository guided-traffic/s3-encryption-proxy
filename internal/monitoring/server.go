package monitoring

import (
	"context"
	"encoding/json"
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

	// Liveness, the same constant 200 the serving listener answers: the only
	// reaction to a failing liveness probe is a restart, and no precondition
	// outside this process is repaired by one (ADR 0034).
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// The one descriptive document, and nothing automatic acts on it. It sits
	// on this listener rather than the S3 one because it names the active
	// provider, which an unauthenticated client must not be able to read
	// (ADR 0030, ADR 0034).
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(StatusSnapshot()); err != nil {
			logger.WithError(err).Debug("Status document not delivered")
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
