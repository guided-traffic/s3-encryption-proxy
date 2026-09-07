package keyencryption

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"

	"crypto/x509"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	kekRSAOnce sync.Once
	kekRSAKey  *rsa.PrivateKey
	kekRSAErr  error
)

// KekSharedRSAKey returns a process-wide 2048-bit RSA key so the individual
// tests do not each pay for key generation.
func KekSharedRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	kekRSAOnce.Do(func() {
		kekRSAKey, kekRSAErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	require.NoError(t, kekRSAErr)
	return kekRSAKey
}

// KekPEM wraps DER bytes in a PEM block of the given type.
func KekPEM(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

// KekPKIXPublicPEM renders an RSA public key in PKIX ("PUBLIC KEY") form.
func KekPKIXPublicPEM(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return KekPEM("PUBLIC KEY", der)
}

// KekPKCS1PublicPEM renders an RSA public key in PKCS#1 ("RSA PUBLIC KEY") form.
func KekPKCS1PublicPEM(key *rsa.PublicKey) string {
	return KekPEM("RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(key))
}

// KekPKCS1PrivatePEM renders an RSA private key in PKCS#1 form.
func KekPKCS1PrivatePEM(key *rsa.PrivateKey) string {
	return KekPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
}

// KekPKCS8PrivatePEM renders an RSA private key in PKCS#8 form.
func KekPKCS8PrivatePEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return KekPEM("PRIVATE KEY", der)
}

// KekECDSAKeyPEMs returns a non-RSA key pair in PKIX / PKCS#8 PEM form.
func KekECDSAKeyPEMs(t *testing.T) (publicPEM, privatePEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return KekPEM("PUBLIC KEY", pubDER), KekPEM("PRIVATE KEY", privDER)
}

func TestKekRSADEKRoundTrip(t *testing.T) {
	key := KekSharedRSAKey(t)
	provider, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		dek  []byte
	}{
		{name: "empty dek", dek: []byte{}},
		{name: "32 byte dek", dek: KekBytePattern(32)},
		{name: "max OAEP payload for 2048 bit key", dek: KekBytePattern(190)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ciphertext, keyID, err := provider.EncryptDEK(ctx, tc.dek)
			require.NoError(t, err)
			assert.Equal(t, provider.Fingerprint(), keyID)
			assert.Len(t, ciphertext, 256, "OAEP output is one modulus block")
			assert.NotEqual(t, sha256.Sum256(tc.dek), sha256.Sum256(ciphertext))

			plaintext, err := provider.DecryptDEK(ctx, ciphertext, keyID)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(tc.dek), sha256.Sum256(plaintext))
		})
	}
}

func TestKekRSAEncryptDEKIsRandomized(t *testing.T) {
	key := KekSharedRSAKey(t)
	provider, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)
	ctx := context.Background()
	dek := KekBytePattern(32)

	first, _, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)
	second, _, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	assert.NotEqual(t, first, second, "OAEP must randomize each wrapping")
}

func TestKekRSAEncryptDEKTooLarge(t *testing.T) {
	key := KekSharedRSAKey(t)
	provider, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)

	// 2048-bit modulus with SHA-256 OAEP allows at most 190 payload bytes.
	ciphertext, keyID, err := provider.EncryptDEK(context.Background(), KekBytePattern(191))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to encrypt DEK with RSA")
	assert.Nil(t, ciphertext)
	assert.Empty(t, keyID)
}

func TestKekRSADecryptDEKFailures(t *testing.T) {
	key := KekSharedRSAKey(t)
	provider, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)
	ctx := context.Background()

	dek := KekBytePattern(32)
	ciphertext, keyID, err := provider.EncryptDEK(ctx, dek)
	require.NoError(t, err)

	t.Run("key id mismatch", func(t *testing.T) {
		_, err := provider.DecryptDEK(ctx, ciphertext, "not-our-fingerprint")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key ID mismatch")
		assert.Contains(t, err.Error(), provider.Fingerprint())
	})

	t.Run("tampered ciphertext is rejected", func(t *testing.T) {
		tampered := make([]byte, len(ciphertext))
		copy(tampered, ciphertext)
		tampered[len(tampered)-1] ^= 0x01

		_, err := provider.DecryptDEK(ctx, tampered, keyID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with RSA")
	})

	t.Run("truncated ciphertext is rejected", func(t *testing.T) {
		_, err := provider.DecryptDEK(ctx, ciphertext[:len(ciphertext)-1], keyID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with RSA")
	})

	t.Run("empty ciphertext is rejected", func(t *testing.T) {
		_, err := provider.DecryptDEK(ctx, nil, keyID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with RSA")
	})

	t.Run("wrong private key cannot unwrap", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		otherProvider, err := NewRSAProvider(&other.PublicKey, other)
		require.NoError(t, err)

		// Bypass the fingerprint gate on purpose: the crypto itself must fail.
		_, err = otherProvider.DecryptDEK(ctx, ciphertext, otherProvider.Fingerprint())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt DEK with RSA")
	})
}

func TestKekRSAFingerprintStabilityAndUniqueness(t *testing.T) {
	key := KekSharedRSAKey(t)
	first, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)
	second, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)

	assert.Equal(t, first.Fingerprint(), second.Fingerprint())
	assert.Len(t, first.Fingerprint(), 64)

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherProvider, err := NewRSAProvider(&other.PublicKey, other)
	require.NoError(t, err)
	assert.NotEqual(t, first.Fingerprint(), otherProvider.Fingerprint())

	// Known defect (tracked in docs/tickets/022): the fingerprint folds the
	// public exponent into a single byte, so exponents that share their low
	// byte collide for the same modulus. E=65537 (0x010001) and E=257
	// (0x000101) both reduce to 0x01.
	collidingA := &RSAProvider{publicKey: &rsa.PublicKey{N: key.N, E: 65537}}
	collidingB := &RSAProvider{publicKey: &rsa.PublicKey{N: key.N, E: 257}}
	assert.Equal(t, collidingA.Fingerprint(), collidingB.Fingerprint(),
		"documents the truncated-exponent fingerprint collision, do not fix here")
}

func TestKekRSANameAndRotateKEK(t *testing.T) {
	key := KekSharedRSAKey(t)
	provider, err := NewRSAProvider(&key.PublicKey, key)
	require.NoError(t, err)

	assert.Equal(t, "rsa", provider.Name())

	err = provider.RotateKEK(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key rotation is not implemented")
}

func TestKekRSAKeyPairValidationBranches(t *testing.T) {
	key := KekSharedRSAKey(t)

	t.Run("modulus mismatch", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		_, err = NewRSAProvider(&other.PublicKey, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "public key modulus N does not match private key")
	})

	t.Run("exponent mismatch", func(t *testing.T) {
		_, err := NewRSAProvider(&rsa.PublicKey{N: key.N, E: 3}, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "public key exponent E does not match private key")
	})

	t.Run("public key cannot encrypt", func(t *testing.T) {
		// E=1 is a structurally valid but unusable exponent: matching keys, but
		// EncryptOAEP refuses it.
		pub := &rsa.PublicKey{N: key.N, E: 1}
		priv := &rsa.PrivateKey{PublicKey: *pub, D: key.D, Primes: key.Primes}

		_, err := NewRSAProvider(pub, priv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt test message with public key")
	})

	t.Run("private key cannot decrypt", func(t *testing.T) {
		// Same modulus and exponent, but a corrupted private exponent.
		broken := &rsa.PrivateKey{
			PublicKey: key.PublicKey,
			D:         new(big.Int).Sub(key.D, big.NewInt(2)),
			Primes:    key.Primes,
		}
		_, err := NewRSAProvider(&key.PublicKey, broken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt test message with private key")
	})
}

func TestKekRSAProviderFromPEMFormats(t *testing.T) {
	key := KekSharedRSAKey(t)
	ecPublicPEM, ecPrivatePEM := KekECDSAKeyPEMs(t)

	tests := []struct {
		name       string
		publicPEM  string
		privatePEM string
		wantErr    string
	}{
		{
			name:       "PKIX public with PKCS8 private",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: KekPKCS8PrivatePEM(t, key),
		},
		{
			name:       "PKCS1 public with PKCS1 private",
			publicPEM:  KekPKCS1PublicPEM(&key.PublicKey),
			privatePEM: KekPKCS1PrivatePEM(key),
		},
		{
			name:       "PKIX public with PKCS1 private",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: KekPKCS1PrivatePEM(key),
		},
		{
			name:       "public key not PEM",
			publicPEM:  "definitely not pem",
			privatePEM: KekPKCS1PrivatePEM(key),
			wantErr:    "failed to decode PEM block",
		},
		{
			name:       "public key wrong block type",
			publicPEM:  KekPEM("CERTIFICATE", []byte("whatever")),
			privatePEM: KekPKCS1PrivatePEM(key),
			wantErr:    "invalid PEM block type: CERTIFICATE",
		},
		{
			name:       "public key PKIX body corrupt",
			publicPEM:  KekPEM("PUBLIC KEY", []byte("not-der")),
			privatePEM: KekPKCS1PrivatePEM(key),
			wantErr:    "failed to parse PKIX public key",
		},
		{
			name:       "public key PKCS1 body corrupt",
			publicPEM:  KekPEM("RSA PUBLIC KEY", []byte("not-der")),
			privatePEM: KekPKCS1PrivatePEM(key),
			wantErr:    "failed to parse PKCS1 public key",
		},
		{
			name:       "public key is not RSA",
			publicPEM:  ecPublicPEM,
			privatePEM: KekPKCS1PrivatePEM(key),
			wantErr:    "not an RSA public key",
		},
		{
			name:       "private key not PEM",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: "definitely not pem",
			wantErr:    "failed to decode PEM block",
		},
		{
			name:       "private key wrong block type",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: KekPEM("EC PRIVATE KEY", []byte("whatever")),
			wantErr:    "invalid PEM block type: EC PRIVATE KEY",
		},
		{
			name:       "private key PKCS1 body corrupt",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: KekPEM("RSA PRIVATE KEY", []byte("not-der")),
			wantErr:    "failed to parse PKCS1 private key",
		},
		{
			name:       "private key PKCS8 body corrupt",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: KekPEM("PRIVATE KEY", []byte("not-der")),
			wantErr:    "failed to parse PKCS8 private key",
		},
		{
			name:       "private key is not RSA",
			publicPEM:  KekPKIXPublicPEM(t, &key.PublicKey),
			privatePEM: ecPrivatePEM,
			wantErr:    "not an RSA private key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewRSAProviderFromPEM(tc.publicPEM, tc.privatePEM)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, provider)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, provider)

			ctx := context.Background()
			dek := KekBytePattern(32)
			ciphertext, keyID, err := provider.EncryptDEK(ctx, dek)
			require.NoError(t, err)
			plaintext, err := provider.DecryptDEK(ctx, ciphertext, keyID)
			require.NoError(t, err)
			assert.Equal(t, sha256.Sum256(dek), sha256.Sum256(plaintext))
		})
	}
}

func TestKekRSAProviderFromConfig(t *testing.T) {
	key := KekSharedRSAKey(t)
	publicPEM := KekPKIXPublicPEM(t, &key.PublicKey)
	privatePEM := KekPKCS8PrivatePEM(t, key)

	tests := []struct {
		name    string
		config  *RSAConfig
		wantErr string
	}{
		{
			name:   "valid config",
			config: &RSAConfig{PublicKeyPEM: publicPEM, PrivateKeyPEM: privatePEM},
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: "config cannot be nil",
		},
		{
			name:    "missing public key",
			config:  &RSAConfig{PrivateKeyPEM: privatePEM},
			wantErr: "public_key_pem is required",
		},
		{
			name:    "missing private key",
			config:  &RSAConfig{PublicKeyPEM: publicPEM},
			wantErr: "private_key_pem is required",
		},
		{
			name:    "unparsable public key",
			config:  &RSAConfig{PublicKeyPEM: "garbage", PrivateKeyPEM: privatePEM},
			wantErr: "failed to parse public key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewRSAProviderFromConfig(tc.config)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, provider)
				return
			}
			require.NoError(t, err)
			expected, err := NewRSAProvider(&key.PublicKey, key)
			require.NoError(t, err)
			assert.Equal(t, expected.Fingerprint(), provider.Fingerprint())
		})
	}
}

func TestKekRSAKeySizeBoundary(t *testing.T) {
	//nolint:gosec // G403: an undersized key is exactly what this test rejects
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&small.PublicKey, small)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key size must be at least 2048 bits, got 1024")
	assert.Nil(t, provider)

	// 2048 bits is accepted, so the boundary is inclusive.
	ok := KekSharedRSAKey(t)
	accepted, err := NewRSAProvider(&ok.PublicKey, ok)
	require.NoError(t, err)
	assert.Equal(t, 2048, ok.N.BitLen())
	assert.NotNil(t, accepted)
}
