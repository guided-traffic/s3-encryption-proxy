package validation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

// Constants duplicated from the production code on purpose: if somebody changes
// the salt or info string in hkdf.go / hmac_manager.go, every object already
// stored in S3 becomes unverifiable. These literals pin the wire format.
const (
	ValFileHMACSalt = "s3-proxy-integrity-v1"
	ValFileHMACInfo = "file-hmac-key"
)

// ValderiveReference computes the expected HKDF output independently of the
// production helper, so the assertions below compare against a second
// implementation rather than against the function under test.
func ValderiveReference(t *testing.T, ikm, salt, info []byte, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	_, err := hkdf.New(sha256.New, ikm, salt, info).Read(out)
	require.NoError(t, err)
	return out
}

func TestValDeriveIntegrityKeyPackageLevel(t *testing.T) {
	dek := bytes.Repeat([]byte{0xA5}, 32)

	t.Run("rejects empty DEK", func(t *testing.T) {
		key, err := DeriveIntegrityKey(nil)
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "DEK cannot be empty")

		key, err = DeriveIntegrityKey([]byte{})
		require.Error(t, err)
		assert.Nil(t, key)
		assert.Contains(t, err.Error(), "DEK cannot be empty")
	})

	t.Run("derives a 32 byte key with the documented constants", func(t *testing.T) {
		key, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)
		require.Len(t, key, 32, "HMAC-SHA256 requires a 256 bit key")

		expected := ValderiveReference(t, dek, []byte(ValFileHMACSalt), []byte(ValFileHMACInfo), 32)
		assert.Equal(t, expected, key,
			"derived key must match HKDF-SHA256(dek, %q, %q); changing these constants breaks every stored object",
			ValFileHMACSalt, ValFileHMACInfo)
	})

	t.Run("is deterministic for the same DEK", func(t *testing.T) {
		first, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)
		second, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)
		assert.Equal(t, first, second)
	})

	t.Run("different DEKs give different keys", func(t *testing.T) {
		other := bytes.Repeat([]byte{0xA5}, 32)
		other[31] ^= 0x01 // single bit difference

		keyA, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)
		keyB, err := DeriveIntegrityKey(other)
		require.NoError(t, err)
		assert.NotEqual(t, keyA, keyB, "a one bit DEK change must change the integrity key")
	})

	t.Run("key is not the DEK itself", func(t *testing.T) {
		key, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)
		assert.NotEqual(t, dek, key, "the integrity key must never equal the raw DEK")
	})

	t.Run("a different salt or info yields a different key", func(t *testing.T) {
		key, err := DeriveIntegrityKey(dek)
		require.NoError(t, err)

		otherSalt := ValderiveReference(t, dek, []byte("s3-proxy-integrity-v2"), []byte(ValFileHMACInfo), 32)
		otherInfo := ValderiveReference(t, dek, []byte(ValFileHMACSalt), []byte("part-hmac-key"), 32)

		assert.NotEqual(t, otherSalt, key, "salt must be part of the derivation")
		assert.NotEqual(t, otherInfo, key, "info must be part of the derivation")
	})

	t.Run("accepts short and long DEKs", func(t *testing.T) {
		for _, size := range []int{1, 16, 24, 32, 64, 512} {
			ikm := bytes.Repeat([]byte{0x11}, size)
			key, err := DeriveIntegrityKey(ikm)
			require.NoError(t, err, "size %d", size)
			assert.Len(t, key, 32, "size %d", size)
		}
	})
}

// TestValDeriveIntegrityKeyMatchesManagerDerivation guards the invariant that the
// standalone helper and HMACManager.CreateCalculator derive the very same key.
// If they ever drift apart, HMACs written by one path cannot be verified by the
// other and objects would fail integrity verification on download.
func TestValDeriveIntegrityKeyMatchesManagerDerivation(t *testing.T) {
	dek := bytes.Repeat([]byte{0x3C}, 32)
	payload := bytes.Repeat([]byte("integrity"), 1000)

	key, err := DeriveIntegrityKey(dek)
	require.NoError(t, err)

	standalone, err := NewHMACCalculator(append([]byte(nil), key...))
	require.NoError(t, err)
	_, err = standalone.Add(payload)
	require.NoError(t, err)

	manager := NewHMACManagerWithoutConfig()
	viaManager, err := manager.CreateCalculator(dek)
	require.NoError(t, err)
	_, err = viaManager.Add(payload)
	require.NoError(t, err)

	assert.True(t, hmac.Equal(standalone.GetCurrentHash(), viaManager.GetCurrentHash()),
		"DeriveIntegrityKey and HMACManager.CreateCalculator must derive the same HMAC key")
}

func TestValHKDFConfigGetHashFunction(t *testing.T) {
	tests := []struct {
		name         string
		algorithm    string
		expectedSize int
		sameAsSHA256 bool
	}{
		{name: "sha256", algorithm: "sha256", expectedSize: sha256.Size, sameAsSHA256: true},
		{name: "sha512", algorithm: "sha512", expectedSize: sha512.Size, sameAsSHA256: false},
		// The default branch is defensive: Validate() rejects unknown algorithms
		// before DeriveIntegrityKey ever reaches here. It must never return nil,
		// because that would panic instead of degrading to SHA-256.
		{name: "unknown falls back to sha256", algorithm: "md5", expectedSize: sha256.Size, sameAsSHA256: true},
		{name: "empty falls back to sha256", algorithm: "", expectedSize: sha256.Size, sameAsSHA256: true},
	}

	probe := []byte("hash function probe")
	reference := sha256.Sum256(probe)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &HKDFConfig{HashAlgorithm: tt.algorithm}
			hashFunc := cfg.getHashFunction()
			require.NotNil(t, hashFunc)

			h := hashFunc()
			require.Equal(t, tt.expectedSize, h.Size())

			_, err := h.Write(probe)
			require.NoError(t, err)
			sum := h.Sum(nil)

			if tt.sameAsSHA256 {
				assert.Equal(t, reference[:], sum)
			} else {
				assert.NotEqual(t, reference[:], sum[:sha256.Size])
			}
		})
	}
}

func TestValHKDFConfigDerivationProperties(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x7E}, 32)

	t.Run("same salt gives the same key", func(t *testing.T) {
		cfg := NewHKDFConfig()
		salt, err := cfg.GenerateRandomSalt()
		require.NoError(t, err)
		require.Len(t, salt, DefaultHKDFSaltLength)

		first, err := cfg.DeriveIntegrityKeyWithSalt(masterKey, salt)
		require.NoError(t, err)
		second, err := cfg.DeriveIntegrityKeyWithSalt(masterKey, salt)
		require.NoError(t, err)

		assert.Equal(t, first.DerivedKey, second.DerivedKey)
		assert.Equal(t, salt, first.Salt)

		expected := ValderiveReference(t, masterKey, salt, []byte(HKDFIntegrityInfo), DefaultHMACKeySize)
		assert.Equal(t, expected, first.DerivedKey,
			"HKDFConfig must use the %q info string", HKDFIntegrityInfo)
	})

	t.Run("different salts give different keys", func(t *testing.T) {
		cfg := NewHKDFConfig()
		saltA := bytes.Repeat([]byte{0x01}, DefaultHKDFSaltLength)
		saltB := bytes.Repeat([]byte{0x01}, DefaultHKDFSaltLength)
		saltB[0] = 0x02

		keyA, err := cfg.DeriveIntegrityKeyWithSalt(masterKey, saltA)
		require.NoError(t, err)
		keyB, err := cfg.DeriveIntegrityKeyWithSalt(masterKey, saltB)
		require.NoError(t, err)

		assert.NotEqual(t, keyA.DerivedKey, keyB.DerivedKey)
	})

	t.Run("random salt derivation produces a fresh salt each call", func(t *testing.T) {
		cfg := NewHKDFConfig()
		first, err := cfg.DeriveIntegrityKeyWithRandomSalt(masterKey)
		require.NoError(t, err)
		second, err := cfg.DeriveIntegrityKeyWithRandomSalt(masterKey)
		require.NoError(t, err)

		assert.NotEqual(t, first.Salt, second.Salt)
		assert.NotEqual(t, first.DerivedKey, second.DerivedKey)
		assert.Len(t, first.Salt, DefaultHKDFSaltLength)
		assert.Len(t, first.DerivedKey, DefaultHMACKeySize)
	})

	t.Run("hash algorithm changes the derived key", func(t *testing.T) {
		salt := bytes.Repeat([]byte{0x5A}, DefaultHKDFSaltLength)

		sha256Cfg := NewHKDFConfig()
		sha512Cfg := NewHKDFConfig()
		sha512Cfg.HashAlgorithm = "sha512"

		keyA, err := sha256Cfg.DeriveIntegrityKeyWithSalt(masterKey, salt)
		require.NoError(t, err)
		keyB, err := sha512Cfg.DeriveIntegrityKeyWithSalt(masterKey, salt)
		require.NoError(t, err)

		assert.NotEqual(t, keyA.DerivedKey, keyB.DerivedKey)
	})

	t.Run("key size is honoured at the boundaries", func(t *testing.T) {
		salt := bytes.Repeat([]byte{0x33}, MinHKDFSaltLength)
		for _, size := range []int{MinHMACKeySize, MaxHMACKeySize} {
			cfg := &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    size,
				HKDFSaltLength: MinHKDFSaltLength,
			}
			result, err := cfg.DeriveIntegrityKeyWithSalt(masterKey, salt)
			require.NoError(t, err, "key size %d", size)
			assert.Len(t, result.DerivedKey, size)
		}
	})

	t.Run("rejects invalid config, empty master key and wrong salt length", func(t *testing.T) {
		cfg := NewHKDFConfig()

		_, err := cfg.DeriveIntegrityKey(nil, bytes.Repeat([]byte{0x00}, DefaultHKDFSaltLength))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "master key cannot be empty")

		_, err = cfg.DeriveIntegrityKeyWithSalt(masterKey, []byte("too-short"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "salt length must be 32 bytes, got 9")

		_, err = cfg.DeriveIntegrityKeyWithSalt(masterKey, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "salt cannot be nil")

		bad := &HKDFConfig{HashAlgorithm: "blake3", HMACKeySize: 32, HKDFSaltLength: 32}
		_, err = bad.DeriveIntegrityKey(masterKey, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HKDF config")

		_, err = bad.GenerateRandomSalt()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HKDF config")
	})
}
