package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/sirupsen/logrus"
)

// PprofServer serves net/http/pprof on a listener of its own.
//
// It is deliberately not on the monitoring mux: that listener is
// unauthenticated and binds every interface by default, while a heap or
// goroutine profile of this process contains DEKs, KEK-decrypted key material
// and plaintext object buffers. config.validateMonitoring refuses to start with
// a non-loopback bind address, so an operator reaches this through an SSH
// tunnel or kubectl port-forward rather than over the network.
type PprofServer struct {
	httpServer *http.Server
	logger     *logrus.Entry
}

// NewPprofServer creates the pprof listener for the given loopback address.
// The address is validated by the config loader, not here.
func NewPprofServer(bindAddress string) *PprofServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return &PprofServer{
		httpServer: &http.Server{
			Addr:        bindAddress,
			Handler:     mux,
			ReadTimeout: 30 * time.Second,
			// No WriteTimeout: /debug/pprof/profile streams for the requested
			// duration (30s by default) and would be cut off mid-profile.
			IdleTimeout: 60 * time.Second,
		},
		logger: logrus.WithField("component", "pprof-server"),
	}
}

// Start serves until the context is cancelled, then shuts down gracefully.
func (s *PprofServer) Start(ctx context.Context) error {
	s.logger.WithField("address", s.httpServer.Addr).
		Info("Starting pprof server on loopback - reach it with an SSH tunnel or kubectl port-forward")

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.WithError(err).Error("pprof server error")
		}
	}()

	<-ctx.Done()

	s.logger.Info("Shutting down pprof server")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		// A profile in flight holds its connection open for the full requested
		// duration. Drop it rather than delay the process exit any further.
		_ = s.httpServer.Close()
		return fmt.Errorf("pprof server shutdown failed: %w", err)
	}

	s.logger.Info("pprof server stopped")
	return nil
}
