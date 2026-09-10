package orchestration

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

// ===== Fixtures and helpers (all prefixed with the OrcMgr token) =====

// OrcMgrAESKeyB64 is a base64-encoded 256-bit AES KEK used by the test configs.
const OrcMgrAESKeyB64 = "ZEsubBlmU+Pr61y+JOwO09c0LOrHs5LITaO0D4JzSZE="

// OrcMgrSegmentSize is the configured S3 part size for the proxy's own multipart
// producer.
const OrcMgrSegmentSize int64 = 5 * 1024 * 1024

// OrcMgrPrefixPtr returns a pointer to s, for config.EncryptionConfig.MetadataKeyPrefix.
func OrcMgrPrefixPtr(s string) *string {
	return &s
}

// OrcMgrAESConfig builds a config with a single active AES provider.
func OrcMgrAESConfig() *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: "orcmgr-aes",
			MetadataKeyPrefix:     OrcMgrPrefixPtr("s3ep-"),
			Providers: []config.EncryptionProvider{
				{
					Alias: "orcmgr-aes",
					Type:  "aes",
					Config: map[string]interface{}{
						"aes_key": OrcMgrAESKeyB64,
					},
				},
			},
		},
		Optimizations: config.OptimizationsConfig{
			StreamingSegmentSize: OrcMgrSegmentSize,
		},
	}
}

// OrcMgrNewManager builds a Manager and registers a shutdown so background
// goroutines never outlive the test.
func OrcMgrNewManager(t *testing.T, cfg *config.Config) *Manager {
	t.Helper()
	m, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, m)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, m.Shutdown(shutdownCtx))
	})
	return m
}

// orcMgrSessionCount reads the live session map under its own lock, so it can be
// called while the background sweeper is running.
func orcMgrSessionCount(m *Manager) int {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	return len(m.segmentedSessions)
}

// orcMgrOpenSession files a client-driven upload under uploadID.
func orcMgrOpenSession(t *testing.T, m *Manager, uploadID string) {
	t.Helper()
	session, err := m.NewSegmentedSession("bucket/"+uploadID, "bucket", nil)
	require.NoError(t, err)
	m.RegisterSegmentedSession(uploadID, session)
}

// ===== NewManager: construction and every invalid-config branch =====

func TestOrcMgrNewManagerInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.Config
		errorMsg string
	}{
		{
			name:     "nil configuration",
			cfg:      nil,
			errorMsg: "configuration cannot be nil",
		},
		{
			name:     "no providers and no alias",
			cfg:      &config.Config{},
			errorMsg: "no encryption providers configured",
		},
		{
			name: "providers configured but no active alias",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "none"},
					},
				},
			},
			errorMsg: "encryption_method_alias is required when providers are configured",
		},
		{
			name: "active alias does not match any provider",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "missing",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "none"},
					},
				},
			},
			errorMsg: "active encryption provider 'missing' not found",
		},
		{
			name: "active provider has empty type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: ""},
					},
				},
			},
			errorMsg: "provider 'a' has empty type",
		},
		{
			name: "active provider has unknown type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "rot13"},
					},
				},
			},
			errorMsg: "provider 'a' has invalid type 'rot13'",
		},
		{
			name: "aes provider with malformed key",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "aes", Config: map[string]interface{}{"aes_key": "not-base64!!"}},
					},
				},
			},
			errorMsg: "failed to create key encryptor for provider 'a'",
		},
		{
			name: "aes provider without a key",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "aes", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "failed to create key encryptor for provider 'a'",
		},
		{
			name: "rsa is not a provider type any more",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "rsa", Config: map[string]interface{}{"private_key_pem": "x"}},
					},
				},
			},
			errorMsg: "provider 'a' has invalid type 'rsa'",
		},
		{
			name: "tink provider is rejected as an invalid active type",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "a",
					Providers: []config.EncryptionProvider{
						{Alias: "a", Type: "tink", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "provider 'a' has invalid type 'tink'",
		},
		{
			name: "secondary provider of unsupported type aborts construction",
			cfg: &config.Config{
				Encryption: config.EncryptionConfig{
					EncryptionMethodAlias: "good",
					Providers: []config.EncryptionProvider{
						{Alias: "good", Type: "aes", Config: map[string]interface{}{"aes_key": OrcMgrAESKeyB64}},
						{Alias: "bad", Type: "rot13", Config: map[string]interface{}{}},
					},
				},
			},
			errorMsg: "unsupported provider type: rot13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewManager(tt.cfg)
			require.Error(t, err)
			assert.Nil(t, m)
			assert.Contains(t, err.Error(), tt.errorMsg)
		})
	}
}

// ===== Accessors =====

func TestOrcMgrAccessorsAndMetadataFiltering(t *testing.T) {
	cfg := OrcMgrAESConfig()
	cfg.Encryption.MetadataKeyPrefix = OrcMgrPrefixPtr("orcmgr-")
	m := OrcMgrNewManager(t, cfg)

	assert.Equal(t, "orcmgr-", m.GetMetadataKeyPrefix())
	assert.False(t, m.IsNoneProvider())

	loaded := m.GetLoadedProviders()
	require.Len(t, loaded, 1)
	assert.Equal(t, "orcmgr-aes", loaded[0].Alias)
	assert.Equal(t, "aes", loaded[0].Type)
	assert.True(t, loaded[0].IsActive)
}

func TestOrcMgrCleanupExpiredSessions(t *testing.T) {
	m := OrcMgrNewManager(t, OrcMgrAESConfig())

	orcMgrOpenSession(t, m, "old-1")
	orcMgrOpenSession(t, m, "old-2")
	assert.Equal(t, 2, orcMgrSessionCount(m))

	assert.Equal(t, 0, m.CleanupExpiredSegmentedSessions(time.Hour), "young sessions survive")
	assert.Equal(t, 2, orcMgrSessionCount(m))

	assert.Equal(t, 2, m.CleanupExpiredSegmentedSessions(0), "a zero max age expires everything")
	assert.Equal(t, 0, orcMgrSessionCount(m))
}

// ===== Background cleanup and shutdown =====

func TestOrcMgrBackgroundCleanupRemovesExpiredSessions(t *testing.T) {
	cfg := OrcMgrAESConfig()
	cfg.Optimizations.MultipartSessionCleanupInterval = 1
	cfg.Optimizations.MultipartSessionMaxAge = 0

	m, err := NewManager(cfg)
	require.NoError(t, err)
	orcMgrOpenSession(t, m, "expiring")
	require.Equal(t, 1, orcMgrSessionCount(m))

	deadline := time.Now().Add(5 * time.Second)
	for orcMgrSessionCount(m) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	assert.Equal(t, 0, orcMgrSessionCount(m), "the background sweeper must drop the expired session")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, m.Shutdown(shutdownCtx))

	// Shutting down twice must stay safe.
	require.NoError(t, m.Shutdown(shutdownCtx))
}

func TestOrcMgrShutdownWithoutBackgroundCleanup(t *testing.T) {
	m, err := NewManager(OrcMgrAESConfig())
	require.NoError(t, err)
	require.NoError(t, m.Shutdown(context.Background()))
}

// TestOrcMgrShutdownReturnsWhenContextExpires proves Shutdown does not block
// forever if the cleanup goroutine refuses to stop.
func TestOrcMgrShutdownReturnsWhenContextExpires(t *testing.T) {
	m, err := NewManager(OrcMgrAESConfig())
	require.NoError(t, err)

	// Stand in for a cleanup worker that never finishes.
	var release sync.WaitGroup
	release.Add(1)
	m.cleanupWg.Add(1)
	go func() {
		release.Wait()
		m.cleanupWg.Done()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- m.Shutdown(ctx) }()

	select {
	case shutdownErr := <-done:
		require.NoError(t, shutdownErr)
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on a stuck cleanup goroutine")
	}
	release.Done()
}
