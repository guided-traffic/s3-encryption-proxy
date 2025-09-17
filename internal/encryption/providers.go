package encryption

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
)

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
	keyCache            map[string][]byte    // Cached DEKs for performance
	keyCacheMutex       sync.RWMutex         // Thread-safe access to key cache
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
		keyCache:            make(map[string][]byte),
		registeredProviders: make(map[string]ProviderInfo),
		logger:              logger,
	}

	allProviders := cfg.GetAllProviders()
	var activeFingerprint string

	for _, provider := range allProviders {
		// Handle "none" provider separately - no encryption, no metadata
		if provider.Type == "none" {
			providerInfo := ProviderInfo{
				Alias:       provider.Alias,
				Type:        provider.Type,
				Fingerprint: "none-provider-fingerprint",
				IsActive:    provider.Alias == activeProvider.Alias,
				Encryptor:   nil, // none provider has no encryptor
			}
			pm.registeredProviders[provider.Alias] = providerInfo

			if provider.Alias == activeProvider.Alias {
				activeFingerprint = "none-provider-fingerprint"
				logger.WithField("provider_alias", provider.Alias).Info("Registered none provider as active")
			}
			continue
		}

		// Map KEK provider types to factory types
		var keyType factory.KeyEncryptionType
		switch provider.Type {
		case "aes":
			keyType = factory.KeyEncryptionTypeAES
		case "rsa":
			keyType = factory.KeyEncryptionTypeRSA
		case "tink":
			keyType = factory.KeyEncryptionTypeTink
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

	if pm.activeFingerprint == "none-provider-fingerprint" {
		// For none provider, return the DEK as-is (no encryption)
		pm.logger.WithField("object_key", objectKey).Debug("Using none provider - DEK not encrypted")
		return dek, nil
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
	encryptedDEK, _, err := keyEncryptor.EncryptDEK(context.Background(), dek)
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

// DecryptDEK decrypts a Data Encryption Key using the provider identified by fingerprint
func (pm *ProviderManager) DecryptDEK(encryptedDEK []byte, fingerprint, objectKey string) ([]byte, error) {
	// Validate input
	if len(encryptedDEK) == 0 {
		return nil, fmt.Errorf("encrypted DEK cannot be empty")
	}

	// Check cache first for performance
	cacheKey := fmt.Sprintf("%s:%s", fingerprint, objectKey)
	pm.keyCacheMutex.RLock()
	if cachedDEK, exists := pm.keyCache[cacheKey]; exists {
		pm.keyCacheMutex.RUnlock()
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"object_key":  objectKey,
		}).Debug("Retrieved DEK from cache")
		return cachedDEK, nil
	}
	pm.keyCacheMutex.RUnlock()

	if fingerprint == "none-provider-fingerprint" {
		// For none provider, return the encrypted DEK as-is (no decryption)
		pm.logger.WithField("object_key", objectKey).Debug("Using none provider - DEK not decrypted")
		return encryptedDEK, nil
	}

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
	dek, err := keyEncryptor.DecryptDEK(context.Background(), encryptedDEK, fingerprint)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"object_key":  objectKey,
			"error":       err,
		}).Error("Failed to decrypt DEK")
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Cache the decrypted DEK for performance
	pm.keyCacheMutex.Lock()
	pm.keyCache[cacheKey] = dek
	pm.keyCacheMutex.Unlock()

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
	if pm.activeFingerprint == "none-provider-fingerprint" {
		return "none"
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

// GetProviderByFingerprint returns a key encryptor by its fingerprint
func (pm *ProviderManager) GetProviderByFingerprint(fingerprint string) (encryption.KeyEncryptor, error) {
	if fingerprint == "none-provider-fingerprint" {
		pm.logger.Debug("Requested none provider by fingerprint")
		return nil, fmt.Errorf("none provider does not support key encryption")
	}

	keyEncryptor, err := pm.factory.GetKeyEncryptor(fingerprint)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"fingerprint": fingerprint,
			"error":       err,
		}).Error("Failed to get provider by fingerprint")
		return nil, fmt.Errorf("no provider found with fingerprint '%s': %w", fingerprint, err)
	}

	return keyEncryptor, nil
}

// CreateEnvelopeEncryptor creates an envelope encryptor for the given content type
func (pm *ProviderManager) CreateEnvelopeEncryptor(contentType factory.ContentType, metadataPrefix string) (encryption.EnvelopeEncryptor, error) {
	envelopeEncryptor, err := pm.factory.CreateEnvelopeEncryptorWithPrefix(contentType, pm.activeFingerprint, metadataPrefix)
	if err != nil {
		pm.logger.WithFields(logrus.Fields{
			"content_type":     contentType,
			"fingerprint":      pm.activeFingerprint,
			"metadata_prefix":  metadataPrefix,
			"error":            err,
		}).Error("Failed to create envelope encryptor")
		return nil, fmt.Errorf("failed to create envelope encryptor: %w", err)
	}

	pm.logger.WithFields(logrus.Fields{
		"content_type":    contentType,
		"fingerprint":     pm.activeFingerprint,
		"metadata_prefix": metadataPrefix,
	}).Debug("Created envelope encryptor")

	return envelopeEncryptor, nil
}

// GetProviderAliases returns all provider aliases from configuration
func (pm *ProviderManager) GetProviderAliases() []string {
	allProviders := pm.config.GetAllProviders()
	aliases := make([]string, 0, len(allProviders))
	for _, provider := range allProviders {
		aliases = append(aliases, provider.Alias)
	}
	return aliases
}

// GetLoadedProviders returns information about all loaded encryption providers
func (pm *ProviderManager) GetLoadedProviders() []ProviderSummary {
	allProviders := pm.config.GetAllProviders()
	factoryProviders := pm.factory.GetRegisteredProviderInfo()

	// Create a map of fingerprints to provider info for quick lookup
	fingerprintToInfo := make(map[string]factory.ProviderInfo)
	for _, info := range factoryProviders {
		fingerprintToInfo[info.Fingerprint] = info
	}

	var summaries []ProviderSummary
	activeAlias := pm.GetActiveProviderAlias()

	for _, provider := range allProviders {
		summary := ProviderSummary{
			Alias:    provider.Alias,
			Type:     provider.Type,
			IsActive: provider.Alias == activeAlias,
		}

		if provider.Type == "none" {
			// Special case for none provider
			summary.Fingerprint = "none-provider-fingerprint"
		} else {
			// Find matching factory provider by searching through all registered providers
			// Since we don't have a direct mapping, we need to match by type and other characteristics
			for fingerprint, info := range fingerprintToInfo {
				if info.Type == provider.Type {
					summary.Fingerprint = fingerprint
					break
				}
			}
		}

		summaries = append(summaries, summary)
	}

	pm.logger.WithField("provider_count", len(summaries)).Debug("Retrieved loaded providers")
	return summaries
}

// ClearKeyCache clears the DEK cache for memory management
func (pm *ProviderManager) ClearKeyCache() {
	pm.keyCacheMutex.Lock()
	defer pm.keyCacheMutex.Unlock()

	cacheSize := len(pm.keyCache)
	pm.keyCache = make(map[string][]byte)

	pm.logger.WithField("cached_keys", cacheSize).Info("Cleared DEK cache")
}

// GetFactory returns the underlying factory instance (for advanced use cases)
func (pm *ProviderManager) GetFactory() *factory.Factory {
	return pm.factory
}

// IsNoneProvider returns true if the active provider is the "none" provider
func (pm *ProviderManager) IsNoneProvider() bool {
	return pm.activeFingerprint == "none-provider-fingerprint"
}

// registerProvider registers a single provider with the factory
func (pm *ProviderManager) registerProvider(provider config.EncryptionProvider) error {
	pm.logger.WithFields(logrus.Fields{
		"provider_alias": provider.Alias,
		"provider_type": provider.Type,
	}).Debug("Registering encryption provider")

	// Handle "none" provider separately - no encryption, no metadata
	if provider.Type == "none" {
		info := ProviderInfo{
			Alias:       provider.Alias,
			Type:        provider.Type,
			Fingerprint: "none-provider-fingerprint",
			IsActive:    provider.Alias == pm.activeAlias,
			Encryptor:   nil, // No encryptor for none provider
		}

		pm.providersMutex.Lock()
		pm.registeredProviders[provider.Alias] = info
		pm.providersMutex.Unlock()

		if provider.Alias == pm.activeAlias {
			pm.activeFingerprint = "none-provider-fingerprint"
		}
		return nil
	}

	// Map KEK provider types to factory types
	var keyType factory.KeyEncryptionType
	switch provider.Type {
	case "aes":
		keyType = factory.KeyEncryptionTypeAES
	case "rsa":
		keyType = factory.KeyEncryptionTypeRSA
	case "tink":
		keyType = factory.KeyEncryptionTypeTink
	default:
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}

	// Create key encryptor
	keyEncryptor, err := pm.factory.CreateKeyEncryptorFromConfig(keyType, provider.Config)
	if err != nil {
		return fmt.Errorf("failed to create key encryptor for provider '%s': %w", provider.Alias, err)
	}

	// Register with factory
	pm.factory.RegisterKeyEncryptor(keyEncryptor)

	// Store provider info
	info := ProviderInfo{
		Alias:       provider.Alias,
		Type:        provider.Type,
		Fingerprint: keyEncryptor.Fingerprint(),
		IsActive:    provider.Alias == pm.activeAlias,
		Encryptor:   keyEncryptor,
	}

	pm.providersMutex.Lock()
	pm.registeredProviders[provider.Alias] = info
	pm.providersMutex.Unlock()

	// Track the active provider's fingerprint
	if provider.Alias == pm.activeAlias {
		pm.activeFingerprint = keyEncryptor.Fingerprint()
	}

	pm.logger.WithFields(logrus.Fields{
		"provider_alias": provider.Alias,
		"provider_type": provider.Type,
		"fingerprint": keyEncryptor.Fingerprint(),
		"is_active": provider.Alias == pm.activeAlias,
	}).Info("Successfully registered encryption provider")

	return nil
}

// ClearCache clears the DEK cache
func (pm *ProviderManager) ClearCache() {
	pm.keyCacheMutex.Lock()
	defer pm.keyCacheMutex.Unlock()

	pm.keyCache = make(map[string][]byte)
	pm.logger.Debug("Cleared DEK cache")
}

// GetAllProviders returns all registered provider information
func (pm *ProviderManager) GetAllProviders() []ProviderInfo {
	pm.providersMutex.RLock()
	defer pm.providersMutex.RUnlock()

	providers := make([]ProviderInfo, 0, len(pm.registeredProviders))
	for _, provider := range pm.registeredProviders {
		providers = append(providers, provider)
	}

	return providers
}

// ValidateConfiguration validates the provider manager configuration
func (pm *ProviderManager) ValidateConfiguration() error {
	if pm.activeFingerprint == "" {
		return fmt.Errorf("no active provider fingerprint set")
	}

	pm.providersMutex.RLock()
	defer pm.providersMutex.RUnlock()

	if len(pm.registeredProviders) == 0 {
		return fmt.Errorf("no providers registered")
	}

	// Verify active provider exists
	activeProviderFound := false
	for _, provider := range pm.registeredProviders {
		if provider.Fingerprint == pm.activeFingerprint && provider.IsActive {
			activeProviderFound = true
			break
		}
	}

	if !activeProviderFound {
		return fmt.Errorf("active provider with fingerprint '%s' not found", pm.activeFingerprint)
	}

	return nil
}
