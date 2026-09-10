package orchestration

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/factory"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// ===== Fixtures and helpers (all prefixed with the OrcMeta token) =====

// OrcMetaAESKeyB64Alt is a second, distinct base64-encoded 256-bit AES KEK. It
// stands for a retired key that must keep decrypting its old objects.
const OrcMetaAESKeyB64Alt = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// OrcMetaNoneFingerprint is the fixed fingerprint the pass-through provider reports.
const OrcMetaNoneFingerprint = "none-provider-fingerprint"

var ()

// OrcMetaProviderConfig builds a config from a list of providers, with the first
// one active unless activeAlias says otherwise.
func OrcMetaProviderConfig(activeAlias string, providers ...config.EncryptionProvider) *config.Config {
	return &config.Config{
		Encryption: config.EncryptionConfig{
			EncryptionMethodAlias: activeAlias,
			MetadataKeyPrefix:     OrcMetaPrefixPtr("s3ep-"),
			IntegrityVerification: config.HMACVerificationStrict,
			Providers:             providers,
		},
	}
}

// OrcMetaAESProvider returns an AES provider definition with the given key.
func OrcMetaAESProvider(alias, keyB64 string) config.EncryptionProvider {
	return config.EncryptionProvider{
		Alias:  alias,
		Type:   "aes",
		Config: map[string]interface{}{"aes_key": keyB64},
	}
}

// OrcMetaNewProviderManager builds a ProviderManager with a single active AES provider.
func OrcMetaNewProviderManager(t *testing.T) *ProviderManager {
	t.Helper()
	pm, err := NewProviderManager(OrcMetaProviderConfig("orcmeta-aes",
		OrcMetaAESProvider("orcmeta-aes", OrcMetaAESKeyB64)))
	require.NoError(t, err)
	return pm
}

// OrcMetaCountingKEK is a KeyEncryptor that records how often DecryptDEK ran, so
// a cache hit can be proven instead of guessed. It XORs with 0xff, which is its
// own inverse, so encrypt/decrypt are real round trips.
type OrcMetaCountingKEK struct {
	fingerprint  string
	decryptCalls atomic.Int64
	decryptErr   error
	encryptErr   error
}

func (k *OrcMetaCountingKEK) EncryptDEK(_ context.Context, dek []byte) ([]byte, error) {
	if k.encryptErr != nil {
		return nil, k.encryptErr
	}
	return orcMetaXOR(dek), nil
}

func (k *OrcMetaCountingKEK) DecryptDEK(_ context.Context, encryptedDEK []byte) ([]byte, error) {
	k.decryptCalls.Add(1)
	if k.decryptErr != nil {
		return nil, k.decryptErr
	}
	return orcMetaXOR(encryptedDEK), nil
}

func (k *OrcMetaCountingKEK) Name() string        { return "orcmeta-counting" }
func (k *OrcMetaCountingKEK) Fingerprint() string { return k.fingerprint }

func orcMetaXOR(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ 0xff
	}
	return out
}

var _ encryption.KeyEncryptor = (*OrcMetaCountingKEK)(nil)

// ===== Registration by provider type =====

func TestOrcMetaProviderRegistrationAES(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("aes-active",
		OrcMetaAESProvider("aes-active", OrcMetaAESKeyB64)))
	require.NoError(t, err)

	assert.False(t, pm.IsNoneProvider())
	assert.Equal(t, "aes", pm.GetActiveProviderAlgorithm())
	assert.Equal(t, "aes-active", pm.GetActiveProviderAlias())
	assert.Len(t, pm.GetActiveFingerprint(), 64, "an AES fingerprint is a hex SHA-256")
	require.NoError(t, pm.ValidateConfiguration())

	encryptor, err := pm.GetProviderByFingerprint(pm.GetActiveFingerprint())
	require.NoError(t, err)
	assert.Equal(t, "aes", encryptor.Name())
}

func TestOrcMetaProviderRegistrationRSAIsGone(t *testing.T) {
	// One local key provider (ADR 0004): rsa is not a provider type any more,
	// and a configuration naming it fails before any key is touched.
	pm, err := NewProviderManager(OrcMetaProviderConfig("rsa-active", config.EncryptionProvider{
		Alias: "rsa-active",
		Type:  "rsa",
		Config: map[string]interface{}{
			"public_key_pem":  "irrelevant",
			"private_key_pem": "irrelevant",
		},
	}))
	assert.Nil(t, pm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider 'rsa-active' has invalid type 'rsa'")
}

func TestOrcMetaProviderRegistrationNone(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("none-active", config.EncryptionProvider{
		Alias:  "none-active",
		Type:   "none",
		Config: map[string]interface{}{},
	}))
	require.NoError(t, err)

	assert.True(t, pm.IsNoneProvider())
	assert.Equal(t, OrcMetaNoneFingerprint, pm.GetActiveFingerprint())
	assert.Equal(t, "none", pm.GetActiveProviderAlgorithm())

	// The none provider stores the DEK unencrypted - that is its contract, and
	// it is the one configuration in which key material reaches the backend.
	dek := []byte("orcmeta-plain-dek")
	encryptedDEK, err := pm.EncryptDEK(dek, "objects/none")
	require.NoError(t, err)
	assert.Equal(t, dek, encryptedDEK, "the none provider is pure pass-through")

	decrypted, err := pm.DecryptDEK(encryptedDEK, OrcMetaNoneFingerprint, "objects/none")
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted)

	// It is registered for lookups by alias, but refuses to hand out an encryptor.
	_, err = pm.GetProviderByFingerprint(OrcMetaNoneFingerprint)
	assert.EqualError(t, err, "none provider does not support key encryption")
}

// TestOrcMetaProviderRegistrationTinkIsUnimplemented pins that a "tink" provider
// cannot be loaded even though the type is accepted in the switch: the factory
// has no Tink implementation. The proxy fails to start rather than silently
// falling back to another provider.
func TestOrcMetaProviderRegistrationTinkIsUnimplemented(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("aes-active",
		OrcMetaAESProvider("aes-active", OrcMetaAESKeyB64),
		config.EncryptionProvider{
			Alias:  "tink-secondary",
			Type:   "tink",
			Config: map[string]interface{}{"kek_uri": "aws-kms://key"},
		},
	))

	assert.Nil(t, pm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create key encryptor for provider 'tink-secondary'")
	assert.Contains(t, err.Error(), "tink key encryption is not yet implemented")
}

func TestOrcMetaProviderRegistrationRejectsUnknownSecondaryType(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("aes-active",
		OrcMetaAESProvider("aes-active", OrcMetaAESKeyB64),
		config.EncryptionProvider{Alias: "mystery", Type: "quantum"},
	))

	assert.Nil(t, pm)
	assert.EqualError(t, err, "unsupported provider type: quantum")
}

func TestOrcMetaProviderRegistrationRejectsBrokenAESKey(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("aes-broken",
		OrcMetaAESProvider("aes-broken", "short-key")))

	assert.Nil(t, pm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create key encryptor for provider 'aes-broken'")
}

func TestOrcMetaProviderRegistrationRejectsMissingActiveProvider(t *testing.T) {
	pm, err := NewProviderManager(OrcMetaProviderConfig("", OrcMetaAESProvider("a", OrcMetaAESKeyB64)))
	assert.Nil(t, pm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption_method_alias is required")

	pm, err = NewProviderManager(OrcMetaProviderConfig(""))
	assert.Nil(t, pm)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no encryption providers configured")
}

// ===== Fingerprints =====

func TestOrcMetaFingerprintIsStableAcrossConstruction(t *testing.T) {
	newAES := func(keyB64 string) string {
		pm, err := NewProviderManager(OrcMetaProviderConfig("aes", OrcMetaAESProvider("aes", keyB64)))
		require.NoError(t, err)
		return pm.GetActiveFingerprint()
	}

	// Same key material, separate processes worth of construction: identical
	// fingerprint, otherwise every restart would orphan the stored objects.
	assert.Equal(t, newAES(OrcMetaAESKeyB64), newAES(OrcMetaAESKeyB64))

	// Distinct key material must not collide.
	assert.NotEqual(t, newAES(OrcMetaAESKeyB64), newAES(OrcMetaAESKeyB64Alt))
}

// TestOrcMetaDecryptionSelectsProviderByFingerprint is the KEK-rotation
// contract: an object written under the old key stays readable after the active
// provider changes, because the provider is chosen by the stored fingerprint.
func TestOrcMetaDecryptionSelectsProviderByFingerprint(t *testing.T) {
	old := OrcMetaAESProvider("retired", OrcMetaAESKeyB64Alt)
	current := OrcMetaAESProvider("current", OrcMetaAESKeyB64)

	before, err := NewProviderManager(OrcMetaProviderConfig("retired", old, current))
	require.NoError(t, err)

	dek := []byte("orcmeta-dek-32-bytes-bbbbbbbbbbb")
	require.Len(t, dek, 32)

	oldFingerprint := before.GetActiveFingerprint()
	encryptedUnderOld, err := before.EncryptDEK(dek, "objects/rotated")
	require.NoError(t, err)

	// Rotate: the same key set, but "current" is now the active provider.
	after, err := NewProviderManager(OrcMetaProviderConfig("current", old, current))
	require.NoError(t, err)
	newFingerprint := after.GetActiveFingerprint()
	require.NotEqual(t, oldFingerprint, newFingerprint)

	decrypted, err := after.DecryptDEK(encryptedUnderOld, oldFingerprint, "objects/rotated")
	require.NoError(t, err)
	assert.Equal(t, dek, decrypted, "an object written under the retired KEK must stay readable")

	// New writes go to the rotated-in key.
	encryptedUnderNew, err := after.EncryptDEK(dek, "objects/rotated")
	require.NoError(t, err)
	assert.NotEqual(t, encryptedUnderOld, encryptedUnderNew)

	// The wrap is authenticated (ADR 0004): asking the wrong registered KEK to
	// unwrap fails instead of returning garbage key material that only the
	// payload layer would have caught.
	wrongKey, err := after.DecryptDEK(encryptedUnderOld, newFingerprint, "objects/rotated")
	require.Error(t, err)
	assert.ErrorIs(t, err, keyencryption.ErrWrappedDEKAuth)
	assert.Nil(t, wrongKey)
}

func TestOrcMetaDecryptDEKUnknownFingerprint(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)

	_, err := pm.DecryptDEK([]byte("blob"), "0000000000000000", "objects/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider found with fingerprint '0000000000000000'")

	_, err = pm.GetProviderByFingerprint("0000000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider found with fingerprint '0000000000000000'")
}

func TestOrcMetaEncryptDEKRejectsEmptyAndUnknownActiveProvider(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)

	_, err := pm.EncryptDEK(nil, "objects/x")
	assert.EqualError(t, err, "DEK cannot be empty")
	_, err = pm.EncryptDEK([]byte{}, "objects/x")
	assert.EqualError(t, err, "DEK cannot be empty")

	_, err = pm.DecryptDEK(nil, pm.GetActiveFingerprint(), "objects/x")
	assert.EqualError(t, err, "encrypted DEK cannot be empty")

	// An active fingerprint that no longer resolves must fail loudly rather
	// than storing an unprotected DEK.
	pm.activeFingerprint = "gone"
	_, err = pm.EncryptDEK([]byte("dek"), "objects/x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get active key encryptor")
	assert.Equal(t, "", pm.GetActiveProviderAlgorithm(), "an unresolvable provider reports no algorithm")

	_, err = pm.CreateEnvelopeEncryptor(factory.ContentTypeWhole, "s3ep-")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create envelope encryptor")
}

// TestOrcMetaEncryptDEKSurfacesKEKFailure makes sure a KEK that refuses to wrap
// a DEK aborts the write instead of letting an unwrapped DEK through.
func TestOrcMetaEncryptDEKSurfacesKEKFailure(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)
	kek.encryptErr = errors.New("hsm offline")
	pm.activeFingerprint = kek.fingerprint

	encrypted, err := pm.EncryptDEK([]byte("orcmeta-dek-32-bytes-eeeeeeeeeee"), "objects/x")
	assert.Nil(t, encrypted)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to encrypt DEK")
	assert.Contains(t, err.Error(), "hsm offline")
}

func TestOrcMetaGetActiveProviderAliasHandlesBrokenConfig(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)
	assert.Equal(t, "orcmeta-aes", pm.GetActiveProviderAlias())

	pm.config = &config.Config{}
	assert.Equal(t, "", pm.GetActiveProviderAlias(),
		"a config without providers must not panic, it reports no alias")
	assert.Empty(t, pm.GetProviderAliases())
}

func TestOrcMetaCreateEnvelopeEncryptorPerContentType(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)

	whole, err := pm.CreateEnvelopeEncryptor(factory.ContentTypeWhole, "s3ep-")
	require.NoError(t, err)
	assert.NotNil(t, whole)

	multipart, err := pm.CreateEnvelopeEncryptor(factory.ContentTypeMultipart, "s3ep-")
	require.NoError(t, err)
	assert.NotNil(t, multipart)

	_, err = pm.CreateEnvelopeEncryptor(factory.ContentType("carrier-pigeon"), "s3ep-")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported content type: carrier-pigeon")

	assert.NotNil(t, pm.GetFactory())
}

// ===== GetLoadedProviders: the startup report operators read =====

func TestOrcMetaGetLoadedProvidersReportsEachAliasOwnFingerprint(t *testing.T) {
	retired := OrcMetaAESProvider("retired", OrcMetaAESKeyB64Alt)
	current := OrcMetaAESProvider("current", OrcMetaAESKeyB64)
	none := config.EncryptionProvider{Alias: "passthrough", Type: "none", Config: map[string]interface{}{}}

	pm, err := NewProviderManager(OrcMetaProviderConfig("current", retired, current, none))
	require.NoError(t, err)

	// Authoritative per-alias fingerprints, taken from the registry.
	expected := map[string]string{}
	for _, info := range pm.GetAllProviders() {
		expected[info.Alias] = info.Fingerprint
	}
	require.Len(t, expected, 3)
	require.NotEqual(t, expected["retired"], expected["current"],
		"two AES providers with different keys must have different fingerprints")

	// Map iteration order used to decide which fingerprint a summary got, so
	// repeat enough times that a type-based lookup could not pass by luck.
	for i := 0; i < 50; i++ {
		summaries := pm.GetLoadedProviders()
		require.Len(t, summaries, 3)

		for _, summary := range summaries {
			assert.Equal(t, expected[summary.Alias], summary.Fingerprint,
				"provider %q must report its own fingerprint", summary.Alias)
			assert.Equal(t, summary.Alias == "current", summary.IsActive)
		}
	}

	summaries := pm.GetLoadedProviders()
	byAlias := map[string]ProviderSummary{}
	for _, summary := range summaries {
		byAlias[summary.Alias] = summary
	}
	assert.Equal(t, "none", byAlias["passthrough"].Type)
	assert.Equal(t, OrcMetaNoneFingerprint, byAlias["passthrough"].Fingerprint)
	assert.Equal(t, "aes", byAlias["current"].Type)
}

// ===== DEK cache =====

// OrcMetaCachingManager builds a ProviderManager around a counting KEK so that
// cache hits and misses are observable.
func OrcMetaCachingManager(t *testing.T) (*ProviderManager, *OrcMetaCountingKEK) {
	t.Helper()
	pm := OrcMetaNewProviderManager(t)
	kek := &OrcMetaCountingKEK{fingerprint: "orcmeta-counting-fp"}
	pm.GetFactory().RegisterKeyEncryptor(kek)
	return pm, kek
}

func TestOrcMetaDEKCacheServesRepeatedReadsWithoutTouchingTheKEK(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)
	encryptedDEK := orcMetaXOR([]byte("orcmeta-dek-32-bytes-ccccccccccc"))

	first, err := pm.DecryptDEK(encryptedDEK, kek.fingerprint, "objects/hot")
	require.NoError(t, err)
	assert.Equal(t, []byte("orcmeta-dek-32-bytes-ccccccccccc"), first)
	assert.Equal(t, int64(1), kek.decryptCalls.Load())

	for i := 0; i < 5; i++ {
		again, err := pm.DecryptDEK(encryptedDEK, kek.fingerprint, "objects/hot")
		require.NoError(t, err)
		assert.Equal(t, first, again)
	}
	assert.Equal(t, int64(1), kek.decryptCalls.Load(), "repeat reads must be served from the cache")

	// A different object key is a different cache entry.
	_, err = pm.DecryptDEK(encryptedDEK, kek.fingerprint, "objects/other")
	require.NoError(t, err)
	assert.Equal(t, int64(2), kek.decryptCalls.Load())

	pm.ClearKeyCache()
	_, err = pm.DecryptDEK(encryptedDEK, kek.fingerprint, "objects/hot")
	require.NoError(t, err)
	assert.Equal(t, int64(3), kek.decryptCalls.Load(), "ClearKeyCache must force a fresh unwrap")

	pm.ClearCache()
	_, err = pm.DecryptDEK(encryptedDEK, kek.fingerprint, "objects/hot")
	require.NoError(t, err)
	assert.Equal(t, int64(4), kek.decryptCalls.Load(), "ClearCache must force a fresh unwrap")
}

// TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload is the stale-key
// regression of ADR 0002: re-uploading the same object key produces a fresh
// DEK, and the cache key includes a digest of the encrypted DEK so the new
// ciphertext is never unwrapped with the previous key.
func TestOrcMetaDEKCacheNeverServesStaleDEKAfterReupload(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)
	const objectKey = "objects/reuploaded"

	firstDEK := []byte("orcmeta-first-dek-32-bytes-aaaaa")
	secondDEK := []byte("orcmeta-second-dek-32-bytes-bbbb")
	require.Len(t, firstDEK, 32)
	require.Len(t, secondDEK, 32)

	firstWrapped := orcMetaXOR(firstDEK)
	secondWrapped := orcMetaXOR(secondDEK)
	require.NotEqual(t, firstWrapped, secondWrapped)

	got, err := pm.DecryptDEK(firstWrapped, kek.fingerprint, objectKey)
	require.NoError(t, err)
	require.Equal(t, firstDEK, got)
	require.Equal(t, int64(1), kek.decryptCalls.Load())

	// Pre-fix this returned firstDEK from the cache, and the object then failed
	// HMAC verification because it was decrypted with the wrong key.
	got, err = pm.DecryptDEK(secondWrapped, kek.fingerprint, objectKey)
	require.NoError(t, err)
	assert.Equal(t, secondDEK, got, "the re-uploaded object must use its own DEK")
	assert.Equal(t, int64(2), kek.decryptCalls.Load(), "a new encrypted DEK must miss the cache")

	// Both entries coexist: the older object is still readable.
	got, err = pm.DecryptDEK(firstWrapped, kek.fingerprint, objectKey)
	require.NoError(t, err)
	assert.Equal(t, firstDEK, got)
	assert.Equal(t, int64(2), kek.decryptCalls.Load())
}

func TestOrcMetaDEKCacheKeyIsScopedByFingerprint(t *testing.T) {
	blob := []byte("identical-wrapped-dek")

	a := buildDEKCacheKey("fp-a", "objects/x", blob)
	b := buildDEKCacheKey("fp-b", "objects/x", blob)
	c := buildDEKCacheKey("fp-a", "objects/y", blob)
	d := buildDEKCacheKey("fp-a", "objects/x", []byte("other-wrapped-dek"))

	assert.NotEqual(t, a, b, "two KEKs must never share a cache entry")
	assert.NotEqual(t, a, c, "two object keys must never share a cache entry")
	assert.NotEqual(t, a, d, "two wrapped DEKs must never share a cache entry")
	assert.Equal(t, a, buildDEKCacheKey("fp-a", "objects/x", blob), "the cache key is deterministic")
}

func TestOrcMetaDEKCacheDoesNotCacheFailedUnwrap(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)
	kek.decryptErr = errors.New("kek unavailable")

	_, err := pm.DecryptDEK([]byte("wrapped"), kek.fingerprint, "objects/broken")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt DEK")
	assert.Contains(t, err.Error(), "kek unavailable")

	// A failure must not poison the cache with an entry.
	kek.decryptErr = nil
	got, err := pm.DecryptDEK([]byte("wrapped"), kek.fingerprint, "objects/broken")
	require.NoError(t, err)
	assert.Equal(t, orcMetaXOR([]byte("wrapped")), got)
	assert.Equal(t, int64(2), kek.decryptCalls.Load())
}

func TestOrcMetaDEKCacheStoresACopyOfTheCallerSlice(t *testing.T) {
	pm := &ProviderManager{
		keyCacheItems: make(map[string]*list.Element),
		keyCacheOrder: list.New(),
		logger:        logrus.WithField("component", "orcmeta-test"),
	}

	source := []byte("orcmeta-dek-material")
	pm.cachePut("k", source)
	source[0] = 'X'

	cached, ok := pm.cacheGet("k")
	require.True(t, ok)
	assert.Equal(t, []byte("orcmeta-dek-material"), cached,
		"the cache must own its copy, independent of the caller's buffer")

	// Overwriting an existing key replaces the value and keeps one entry.
	pm.cachePut("k", []byte("replacement-dek"))
	cached, ok = pm.cacheGet("k")
	require.True(t, ok)
	assert.Equal(t, []byte("replacement-dek"), cached)
	assert.Equal(t, 1, pm.keyCacheOrder.Len())

	_, ok = pm.cacheGet("missing")
	assert.False(t, ok)
}

// TestOrcMetaDEKCacheReturnsSharedStorage documents the documented sharp edge:
// DecryptDEK hands back the cache's own slice, so a caller that zeroes or
// otherwise mutates it corrupts every later hit. No production caller does, and
// this test exists so a future one gets caught here.
func TestOrcMetaDEKCacheReturnsSharedStorage(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)
	wrapped := orcMetaXOR([]byte("orcmeta-dek-32-bytes-ddddddddddd"))

	// The first call misses the cache and returns the encryptor's own
	// allocation, so mutating it is harmless.
	first, err := pm.DecryptDEK(wrapped, kek.fingerprint, "objects/shared")
	require.NoError(t, err)
	original := append([]byte(nil), first...)
	first[0] ^= 0xff

	second, err := pm.DecryptDEK(wrapped, kek.fingerprint, "objects/shared")
	require.NoError(t, err)
	require.Equal(t, original, second, "a cache miss returns a private copy")

	// The second call was a hit and returned the cache's own storage, so
	// mutating that one is visible to every later hit.
	mutated := append([]byte(nil), second...)
	mutated[0] ^= 0xff
	second[0] ^= 0xff

	third, err := pm.DecryptDEK(wrapped, kek.fingerprint, "objects/shared")
	require.NoError(t, err)
	assert.Equal(t, mutated, third,
		"a cache hit returns shared storage: mutating a returned DEK corrupts later hits")
	assert.Equal(t, int64(1), kek.decryptCalls.Load())
}

func TestOrcMetaDEKCacheIsConcurrencySafe(t *testing.T) {
	pm, kek := OrcMetaCachingManager(t)

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errCh := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			objectKey := fmt.Sprintf("objects/%d", i%4)
			wrapped := orcMetaXOR([]byte(fmt.Sprintf("dek-for-%d-padded-to-length!!", i%4)))
			for j := 0; j < 25; j++ {
				dek, err := pm.DecryptDEK(wrapped, kek.fingerprint, objectKey)
				if err != nil {
					errCh <- err
					return
				}
				if string(dek) != fmt.Sprintf("dek-for-%d-padded-to-length!!", i%4) {
					errCh <- fmt.Errorf("wrong DEK for %s", objectKey)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		require.NoError(t, err)
	}
	assert.LessOrEqual(t, kek.decryptCalls.Load(), int64(goroutines*25))
}

// ===== ValidateConfiguration and dynamic registration =====

func TestOrcMetaValidateConfigurationRejectsInconsistentRegistry(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)
	require.NoError(t, pm.ValidateConfiguration())

	t.Run("no active fingerprint", func(t *testing.T) {
		broken := &ProviderManager{registeredProviders: map[string]ProviderInfo{}}
		assert.EqualError(t, broken.ValidateConfiguration(), "no active provider fingerprint set")
	})

	t.Run("no providers registered", func(t *testing.T) {
		broken := &ProviderManager{
			activeFingerprint:   "fp",
			registeredProviders: map[string]ProviderInfo{},
		}
		assert.EqualError(t, broken.ValidateConfiguration(), "no providers registered")
	})

	t.Run("active fingerprint not among registered providers", func(t *testing.T) {
		broken := &ProviderManager{
			activeFingerprint: "fp-active",
			registeredProviders: map[string]ProviderInfo{
				"other": {Alias: "other", Fingerprint: "fp-other", IsActive: false},
			},
		}
		assert.EqualError(t, broken.ValidateConfiguration(),
			"active provider with fingerprint 'fp-active' not found")
	})

	t.Run("registered but flagged inactive", func(t *testing.T) {
		broken := &ProviderManager{
			activeFingerprint: "fp-active",
			registeredProviders: map[string]ProviderInfo{
				"active": {Alias: "active", Fingerprint: "fp-active", IsActive: false},
			},
		}
		assert.EqualError(t, broken.ValidateConfiguration(),
			"active provider with fingerprint 'fp-active' not found")
	})
}

func TestOrcMetaRegisterProviderAddsToRegistryAndFactory(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)
	originalFingerprint := pm.GetActiveFingerprint()

	// A secondary provider joins without becoming active.
	require.NoError(t, pm.registerProvider(OrcMetaAESProvider("secondary", OrcMetaAESKeyB64Alt)))
	assert.Equal(t, originalFingerprint, pm.GetActiveFingerprint())

	registry := map[string]ProviderInfo{}
	for _, info := range pm.GetAllProviders() {
		registry[info.Alias] = info
	}
	require.Contains(t, registry, "secondary")
	assert.Equal(t, "aes", registry["secondary"].Type)
	assert.False(t, registry["secondary"].IsActive)
	assert.NotEqual(t, originalFingerprint, registry["secondary"].Fingerprint)

	encryptor, err := pm.GetProviderByFingerprint(registry["secondary"].Fingerprint)
	require.NoError(t, err)
	assert.Equal(t, registry["secondary"].Fingerprint, encryptor.Fingerprint())

	// Re-registering the active alias with different key material moves the
	// active fingerprint with it.
	require.NoError(t, pm.registerProvider(OrcMetaAESProvider("orcmeta-aes", OrcMetaAESKeyB64Alt)))
	assert.NotEqual(t, originalFingerprint, pm.GetActiveFingerprint())
	assert.Equal(t, registry["secondary"].Fingerprint, pm.GetActiveFingerprint(),
		"the same key material yields the same fingerprint")

	// A provider type that no longer exists is refused at registration.
	require.Error(t, pm.registerProvider(config.EncryptionProvider{
		Alias:  "rsa-late",
		Type:   "rsa",
		Config: map[string]interface{}{},
	}))

	// The none provider registers too, under its fixed fingerprint.
	require.NoError(t, pm.registerProvider(config.EncryptionProvider{
		Alias:  "passthrough",
		Type:   "none",
		Config: map[string]interface{}{},
	}))
	for _, info := range pm.GetAllProviders() {
		if info.Alias == "passthrough" {
			assert.Equal(t, OrcMetaNoneFingerprint, info.Fingerprint)
		}
	}
}

func TestOrcMetaRegisterProviderRejectsBadInput(t *testing.T) {
	pm := OrcMetaNewProviderManager(t)

	err := pm.registerProvider(config.EncryptionProvider{Alias: "mystery", Type: "quantum"})
	assert.EqualError(t, err, "unsupported provider type: quantum")

	err = pm.registerProvider(OrcMetaAESProvider("broken", "not-base64!"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create key encryptor for provider 'broken'")

	err = pm.registerProvider(config.EncryptionProvider{
		Alias:  "tink",
		Type:   "tink",
		Config: map[string]interface{}{},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tink key encryption is not yet implemented")

	for _, info := range pm.GetAllProviders() {
		assert.NotContains(t, []string{"mystery", "broken", "tink"}, info.Alias,
			"a provider that failed to load must not appear in the registry")
	}
}
