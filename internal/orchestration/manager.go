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

	// Background cleanup management
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWg     sync.WaitGroup
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

// IsNoneProvider returns true if the active provider is the pass-through "none" provider
func (m *Manager) IsNoneProvider() bool {
	return m.providerManager.IsNoneProvider()
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
	maxAge := time.Duration(m.config.Optimizations.MultipartSessionMaxAge) * time.Second

	m.cleanupWg.Add(1)
	go func() {
		defer m.cleanupWg.Done()

		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		m.logger.WithFields(logrus.Fields{
			"cleanup_interval": cleanupInterval,
			"max_session_age":  maxAge,
		}).Info("Started background multipart session cleanup")

		for {
			select {
			case <-m.cleanupCtx.Done():
				m.logger.Debug("Background cleanup stopped")
				return
			case <-ticker.C:
				expiredCount := m.CleanupExpiredSegmentedSessions(maxAge)
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

	return nil
}
