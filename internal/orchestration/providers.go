package orchestration

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

// dekCacheCapacity bounds the LRU of decrypted DEKs. Entries are tiny (~32 B
// of key material plus map overhead), so the absolute memory cost at the bound
// is negligible — the bound exists to stop unbounded growth on long-running
// proxies that touch many distinct objects.
const dekCacheCapacity = 1024

// exitProviderFingerprint is what the exit provider reports. Nothing is ever
// written under it — the exit provider stores plaintext — so it appears here
// only to identify the active provider.
const exitProviderFingerprint = "exit-provider-fingerprint"

type dekCacheEntry struct {
	key string
	dek []byte
}

// ProviderInfo contains information about a registered encryption provider
type ProviderInfo struct {
	Alias       string
	Type        string
	Fingerprint string
	IsActive    bool
	Encryptor   encryption.KeyEncryptor
}

// ProviderSummary holds information about a loaded provider
type ProviderSummary struct {
	Alias       string
	Type        string
	Fingerprint string
	IsActive    bool
}

// ProviderManager handles provider registration, lifecycle management, and KEK/DEK operations
type ProviderManager struct {
	factory             *factory.Factory
	activeFingerprint   string
	activeAlias         string
	config              *config.Config
	keyCacheMutex       sync.Mutex // guards keyCacheItems / keyCacheOrder
	keyCacheItems       map[string]*list.Element
	keyCacheOrder       *list.List // front = most recently used
	registeredProviders map[string]ProviderInfo
	providersMutex      sync.RWMutex
	logger              *logrus.Entry
}

// NewProviderManager creates a new provider manager with factory and configuration
func NewProviderManager(cfg *config.Config) (*ProviderManager, error) {
	logger := logrus.WithField("component", "provider_manager")

	// Create factory instance
	factoryInstance := factory.NewFactory()

	// Get active provider for encryption
	activeProvider, err := cfg.GetActiveProvider()
	if err != nil {
		logger.WithError(err).Error("Failed to get active provider")
		return nil, fmt.Errorf("failed to get active provider: %w", err)
	}

	// Create key encryptors for all providers and register them with the factory
	pm := &ProviderManager{
		factory:             factoryInstance,
		activeFingerprint:   "",
		activeAlias:         activeProvider.Alias,
		config:              cfg,
		keyCacheItems:       make(map[string]*list.Element),
		keyCacheOrder:       list.New(),
		registeredProviders: make(map[string]ProviderInfo),
		logger:              logger,
	}

	allProviders := cfg.GetAllProviders()
	var activeFingerprint string

	for _, provider := range allProviders {
		// Map KEK provider types to factory types
		var keyType factory.KeyEncryptionType
		switch provider.Type {
		case "aes":
			keyType = factory.KeyEncryptionTypeAES
		case "exit":
			keyType = factory.KeyEncryptionTypeExit
		default:
			logger.WithFields(logrus.Fields{
				"provider_alias": provider.Alias,
				"provider_type":  provider.Type,
			}).Error("Unsupported provider type")
			return nil, fmt.Errorf("unsupported provider type: %s", provider.Type)
		}

		// Create key encryptor
		keyEncryptor, err := factoryInstance.CreateKeyEncryptorFromConfig(keyType, provider.Config)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"provider_alias": provider.Alias,
				"provider_type":  provider.Type,
				"error":          err,
			}).Error("Failed to create key encryptor")
			return nil, fmt.Errorf("failed to create key encryptor for provider '%s': %w", provider.Alias, err)
		}

		// Register with factory
		factoryInstance.RegisterKeyEncryptor(keyEncryptor)

		// Create provider info and register in manager
		providerInfo := ProviderInfo{
			Alias:       provider.Alias,
			Type:        provider.Type,
			Fingerprint: keyEncryptor.Fingerprint(),
			IsActive:    provider.Alias == activeProvider.Alias,
			Encryptor:   keyEncryptor,
		}
		pm.registeredProviders[provider.Alias] = providerInfo

		// Track the active provider's fingerprint
		if provider.Alias == activeProvider.Alias {
			activeFingerprint = keyEncryptor.Fingerprint()
			logger.WithFields(logrus.Fields{
				"provider_alias": provider.Alias,
				"provider_type":  provider.Type,
				"fingerprint":    activeFingerprint,
			}).Info("Registered active provider")
		} else {
			logger.WithFields(logrus.Fields{
				"provider_alias": provider.Alias,
				"provider_type":  provider.Type,
				"fingerprint":    keyEncryptor.Fingerprint(),
			}).Info("Registered provider")
		}
	}

	if activeFingerprint == "" {
		logger.WithField("active_provider_alias", activeProvider.Alias).Error("Active provider not found or not supported")
		return nil, fmt.Errorf("active provider '%s' not found or not supported", activeProvider.Alias)
	}

	pm.activeFingerprint = activeFingerprint
	return pm, nil
}

// EncryptDEK encrypts a Data Encryption Key using the active provider
func (pm *ProviderManager) EncryptDEK(dek []byte, objectKey string) ([]byte, error) {
	// Validate input
	if len(dek) == 0 {
		return nil, fmt.Errorf("DEK cannot be empty")
	}

	// Get active provider from factory
	keyEncryptor, err := pm.factory.GetKeyEncryptor(pm.activeFingerprint)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": pm.activeFingerprint,
			"object_key":  objectKey,
			"error":       err,
		}).Error("Failed to get active key encryptor")
		return nil, fmt.Errorf("failed to get active key encryptor: %w", err)
	}

	// Encrypt the DEK
	encryptedDEK, err := keyEncryptor.EncryptDEK(context.Background(), dek)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": pm.activeFingerprint,
			"object_key":  objectKey,
			"error":       err,
		}).Error("Failed to encrypt DEK")
		return nil, fmt.Errorf("failed to encrypt DEK: %w", err)
	}

	pm.logger.WithFields(logrus.Fields{
		"fingerprint": pm.activeFingerprint,
		"object_key":  objectKey,
		"dek_size":    len(dek),
	}).Debug("Successfully encrypted DEK")

	return encryptedDEK, nil
}

// DecryptDEK decrypts a Data Encryption Key using the provider identified by fingerprint.
//
// The returned slice is either the cache's backing array (on a hit) or the
// encryptor's fresh allocation (on a miss); in both cases callers MUST treat
// it as read-only. Mutating (including zeroing) the returned slice will
// corrupt subsequent cache hits.
func (pm *ProviderManager) DecryptDEK(encryptedDEK []byte, fingerprint, objectKey string) ([]byte, error) {
	// Validate input
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("encrypted DEK cannot be empty")
	}

	// Cache key includes a hash of the encryptedDEK so that re-uploading an
	// object key (which produces a fresh DEK and therefore a fresh
	// encryptedDEK blob) does not collide with the previous entry. Without
	// this, the cache would serve a stale DEK for the new ciphertext and
	// HMAC verification would fail. See ADR 0002.
	cacheKey := buildDEKCacheKey(fingerprint, objectKey, encryptedDEK)
	if cachedDEK, ok := pm.cacheGet(cacheKey); ok {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"object_key":  objectKey,
		}).Debug("Retrieved DEK from cache")
		return cachedDEK, nil
	}

	// No fingerprint is special-cased here. The exit provider reports one, but it
	// holds no key material and answers both wrap and unwrap with an error, so a
	// backend that labelled an object with it gets a refusal rather than a data
	// key of its own choosing (ADR 0001).

	// Get provider by fingerprint
	keyEncryptor, err := pm.factory.GetKeyEncryptor(fingerprint)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"object_key":  objectKey,
			"error":       err,
		}).Error("Failed to get key encryptor by fingerprint")
		return nil, fmt.Errorf("no provider found with fingerprint '%s': %w", fingerprint, err)
	}

	// Decrypt the DEK
	dek, err := keyEncryptor.DecryptDEK(context.Background(), encryptedDEK)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"object_key":  objectKey,
			"error":       err,
		}).Error("Failed to decrypt DEK")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Cache the decrypted DEK. The cache owns the stored copy; callers of
	// DecryptDEK must treat the returned slice as read-only (see cacheGet).
	pm.cachePut(cacheKey, dek)

	pm.logger.WithFields(logrus.Fields{
		"fingerprint": fingerprint,
		"object_key":  objectKey,
		"dek_size":    len(dek),
	}).Debug("Successfully decrypted and cached DEK")

	return dek, nil
}

// GetActiveFingerprint returns the fingerprint of the active provider
func (pm *ProviderManager) GetActiveFingerprint() string {
	return pm.activeFingerprint
}

// GetActiveProviderAlias returns the alias of the active provider from configuration
func (pm *ProviderManager) GetActiveProviderAlias() string {
	activeProvider, err := pm.config.GetActiveProvider()
	if err != nil {
		pm.logger.WithError(err).Error("Failed to get active provider alias")
		return ""
	}
	return activeProvider.Alias
}

// GetActiveProviderAlgorithm returns the algorithm name of the active provider
func (pm *ProviderManager) GetActiveProviderAlgorithm() string {
	if pm.activeFingerprint == exitProviderFingerprint {
		return "exit"
	}

	keyEncryptor, err := pm.factory.GetKeyEncryptor(pm.activeFingerprint)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": pm.activeFingerprint,
			"error":       err,
		}).Error("Failed to get active provider for algorithm name")
		return ""
	}

	// The Name() method returns the algorithm name
	return keyEncryptor.Name()
}

func (pm *ProviderManager) GetProviderAliases() []string {
	allProviders := pm.config.GetAllProviders()
	aliases := make([]string, 0, len(allProviders))
	for _, provider := range allProviders {
		aliases = append(aliases, provider.Alias)
	}
	return aliases
}

// GetLoadedProviders returns information about all loaded encryption providers.
// The fingerprint comes from the per-alias registry: looking it up by provider
// type instead would hand every provider of the same type an arbitrary sibling's
// fingerprint, which is exactly wrong during a KEK rotation.
func (pm *ProviderManager) GetLoadedProviders() []ProviderSummary {
	allProviders := pm.config.GetAllProviders()

	pm.providersMutex.RLock()
	registered := make(map[string]string, len(pm.registeredProviders))
	for alias, info := range pm.registeredProviders {
		registered[alias] = info.Fingerprint
	}
	pm.providersMutex.RUnlock()

	var summaries []ProviderSummary
	activeAlias := pm.GetActiveProviderAlias()

	for _, provider := range allProviders {
		summaries = append(summaries, ProviderSummary{
			Alias:       provider.Alias,
			Type:        provider.Type,
			Fingerprint: registered[provider.Alias],
			IsActive:    provider.Alias == activeAlias,
		})
	}

	pm.logger.WithField("provider_count", len(summaries)).Debug("Retrieved loaded providers")
	return summaries
}

func buildDEKCacheKey(fingerprint, objectKey string, encryptedDEK []byte) string {
	sum := sha256.Sum256(encryptedDEK)
	return fmt.Sprintf("%s:%s:%s", fingerprint, objectKey, hex.EncodeToString(sum[:8]))
}

// cacheGet returns the cached DEK by reference and promotes the entry to MRU.
// The returned slice is the cache's own storage — callers MUST NOT mutate it.
// Skipping the per-hit copy keeps DEK lookups at zero allocations.
func (pm *ProviderManager) cacheGet(key string) ([]byte, bool) {
	pm.keyCacheMutex.Lock()
	defer pm.keyCacheMutex.Unlock()

	elem, ok := pm.keyCacheItems[key]
	if !ok {
		return nil, false
	}
	pm.keyCacheOrder.MoveToFront(elem)
	return elem.Value.(*dekCacheEntry).dek, true
}

// cachePut inserts (or refreshes) an entry and evicts the LRU entry when the
// cache exceeds dekCacheCapacity. The DEK is copied so the cache owns its
// backing array, independent of whatever the caller does with their input
// slice afterwards.
func (pm *ProviderManager) cachePut(key string, dek []byte) {
	pm.keyCacheMutex.Lock()
	defer pm.keyCacheMutex.Unlock()

	if elem, ok := pm.keyCacheItems[key]; ok {
		entry := elem.Value.(*dekCacheEntry)
		entry.dek = append([]byte(nil), dek...)
		pm.keyCacheOrder.MoveToFront(elem)
		return
	}

	entry := &dekCacheEntry{key: key, dek: append([]byte(nil), dek...)}
	pm.keyCacheItems[key] = pm.keyCacheOrder.PushFront(entry)

	for pm.keyCacheOrder.Len() > dekCacheCapacity {
		oldest := pm.keyCacheOrder.Back()
		if oldest == nil {
			break
		}
		pm.keyCacheOrder.Remove(oldest)
		delete(pm.keyCacheItems, oldest.Value.(*dekCacheEntry).key)
	}
}

func (pm *ProviderManager) IsExitProvider() bool {
	return pm.activeFingerprint == exitProviderFingerprint
}
