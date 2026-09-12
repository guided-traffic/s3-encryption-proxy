package orchestration

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// Manager is the main orchestration layer for all encryption operations
// It coordinates between all specialized components with clear data paths
type Manager struct {
	config          *config.Config
	providerManager *ProviderManager

	// segmentedSessions holds the client-driven multipart uploads in flight.
	segmentedMu       sync.Mutex
	segmentedSessions map[string]*SegmentedSession
	metadataManager   *MetadataManager
	logger            *logrus.Entry // Public for testing

	// abandon tells the backend an upload is over. It is supplied by the layer
	// that owns the backend client; this package knows no S3 SDK. A nil error
	// means the upload is no longer at the backend, whether this call ended it or
	// it was already gone.
	abandon AbandonFunc

	// Background cleanup management
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWg     sync.WaitGroup
}

// AbandonFunc abandons a multipart upload at the backend.
type AbandonFunc func(ctx context.Context, bucket, key, uploadID string) error

// SetMultipartAbandoner supplies the call the sweeper makes before it forgets an
// idle upload. Call it before the manager serves requests. Without one the
// sweeper only forgets, which leaves the upload at the backend.
func (m *Manager) SetMultipartAbandoner(fn AbandonFunc) {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	m.abandon = fn
}

// NewManager creates a new encryption manager with modular architecture
func NewManager(cfg *config.Config) (*Manager, error) {
	if cfg == nil {
		return nil, fmt.Errorf("configuration cannot be nil")
	}

	logger := logrus.WithField("component", "encryption_manager")

	// Create provider manager first
	providerManager, err := NewProviderManager(cfg)
	if err != nil {
		logger.WithError(err).Error("Failed to create provider manager")
		return nil, fmt.Errorf("failed to create provider manager: %w", err)
	}

	// Create metadata manager
	metadataManager := NewMetadataManager(cfg, "")

	// Create background cleanup context
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	manager := &Manager{
		config:          cfg,
		providerManager: providerManager,
		metadataManager: metadataManager,
		logger:          logger,
		cleanupCtx:      cleanupCtx,
		cleanupCancel:   cleanupCancel,
	}

	// Start background cleanup if cleanup interval is configured
	if cfg.Optimizations.MultipartSessionCleanupInterval > 0 {
		manager.startBackgroundCleanup()
	}

	logger.WithFields(logrus.Fields{
		"provider_count":  len(providerManager.GetProviderAliases()),
		"active_provider": providerManager.GetActiveProviderAlias(),
		"metadata_prefix": metadataManager.GetMetadataPrefix(),
	}).Info("Successfully initialized Manager")

	return manager, nil
}

// ===== PROVIDER MANAGEMENT =====

// IsExitProvider reports whether the active provider is the exit provider: new
// objects are stored as the client sent them, while objects this proxy
// encrypted earlier are still decrypted on read.
func (m *Manager) IsExitProvider() bool {
	return m.providerManager.IsExitProvider()
}

// GetLoadedProviders returns information about all loaded providers
func (m *Manager) GetLoadedProviders() []ProviderSummary {
	return m.providerManager.GetLoadedProviders()
}

// ===== UTILITY METHODS =====

// GetMetadataKeyPrefix returns the configured metadata key prefix
func (m *Manager) GetMetadataKeyPrefix() string {
	return m.metadataManager.GetMetadataPrefix()
}

// ===== BACKGROUND CLEANUP =====

// startBackgroundCleanup starts a background goroutine that periodically cleans up expired multipart sessions
func (m *Manager) startBackgroundCleanup() {
	cleanupInterval := time.Duration(m.config.Optimizations.MultipartSessionCleanupInterval) * time.Second
	idleTimeout := time.Duration(m.config.Optimizations.MultipartSessionIdleTimeout) * time.Second

	m.cleanupWg.Add(1)
	go func() {
		defer m.cleanupWg.Done()

		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		m.logger.WithFields(logrus.Fields{
			"cleanup_interval":     cleanupInterval,
			"session_idle_timeout": idleTimeout,
		}).Info("Started background multipart session cleanup")

		for {
			select {
			case <-m.cleanupCtx.Done():
				m.logger.Debug("Background cleanup stopped")
				return
			case <-ticker.C:
				// Bounded on its own: the sweep talks to the backend, and it may
				// not outlive the tick that started it by much.
				sweepCtx, cancel := context.WithTimeout(m.cleanupCtx, cleanupInterval)
				expiredCount := m.CleanupExpiredSegmentedSessions(sweepCtx, idleTimeout)
				cancel()
				if expiredCount > 0 {
					m.logger.WithField("expired_sessions", expiredCount).Debug("Background cleanup completed")
				}
			}
		}
	}()
}

// Shutdown gracefully shuts down the manager and stops background cleanup
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down encryption manager")

	// Cancel background cleanup
	if m.cleanupCancel != nil {
		m.cleanupCancel()
	}

	// Wait for cleanup goroutine to finish with timeout
	done := make(chan struct{})
	go func() {
		m.cleanupWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Debug("Background cleanup stopped successfully")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for background cleanup to stop")
	}

	// The sweeper is stopped, so nothing else is touching the session map. What
	// is left in it are uploads no client can finish once this process is gone:
	// the data key and the part table live here and nowhere else. Ending them now
	// is the last moment at which the proxy can, and is what the shutdown budget
	// is for (ADR 0029).
	if ended, left := m.AbandonAllSessions(ctx); ended > 0 || left > 0 {
		m.logger.WithFields(logrus.Fields{
			"ended": ended,
			"left":  left,
		}).Info("Ended the multipart uploads this process was holding")
	}

	return nil
}
