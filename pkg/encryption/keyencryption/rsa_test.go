package keyencryption

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper function to generate RSA key pairs
func generateTestRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func TestRSAKeyEncryptor_Basic(t *testing.T) {
	// Generate test key pair
	privateKey, err := generateTestRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	ctx := context.Background()
	testDEK := []byte("12345678901234567890123456789012") // 32-byte DEK

	// Test EncryptDEK
	encryptedDEK, keyID, err := provider.EncryptDEK(ctx, testDEK)
	require.NoError(t, err)
	assert.NotEmpty(t, keyID)
	assert.NotEqual(t, testDEK, encryptedDEK)

	// Test DecryptDEK
	decryptedDEK, err := provider.DecryptDEK(ctx, encryptedDEK, keyID)
	require.NoError(t, err)
	assert.Equal(t, testDEK, decryptedDEK)
}

func TestRSAKeyEncryptor_Algorithm(t *testing.T) {
	privateKey, err := generateTestRSAKeyPair(2048)
	require.NoError(t, err)

	provider, err := NewRSAProvider(&privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	fingerprint := provider.Fingerprint()
	assert.NotEmpty(t, fingerprint)
}

func TestRSAProviderFromPEM(t *testing.T) {
	// Test key pair
	publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btPEFkOhb+1hCOgZL7CAxQGQ9mZJr1kHpq1vMpOiR
mSvDQJgvn0I/YEEiQqGfqzYHrSNPiJCYLI6hL1MZJJlS8Cq8SXF2Qxp3oB4s1qKb
3cVeLO5xyQ==
-----END PUBLIC KEY-----`

	privateKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btPEF
kOhb+1hCOgZL7CAxQGQ9mZJr1kHpq1vMpOiRmSvDQJgvn0I/YEEiQqGfqzYHrSNP
iJCYLI6hL1MZJJlS8Cq8SXF2Qxp3oB4s1qKbQEDAQABAoIBABF6VIlm3x3cXKB5
wCk6Z9ZlJLHo2tLB7peFNAL9Qb5ZqL8L2z3KyQ4QGbBTt7TfJL8VZq9g7t0R2x8L
3cVeLO5xyQABAoGBAJZf1BH4cUBM8G7h3rC6qFo7p+N7Q5l+3mPqKJGBvP2lP5J6
...
-----END RSA PRIVATE KEY-----`

	// This would fail with actual PEM, but that's OK for testing the error case
	_, err := NewRSAProviderFromPEM(publicKeyPEM, privateKeyPEM)
	assert.Error(t, err) // Expected to fail with this fake PEM
}

func TestRSAConfig(t *testing.T) {
	config := &RSAConfig{
		PublicKeyPEM:  "test-public-key",
		PrivateKeyPEM: "test-private-key",
	}

	// This will fail, but tests the config structure
	_, err := NewRSAProviderFromConfig(config)
	assert.Error(t, err) // Expected to fail with invalid PEM
}

func TestRSAKeyPairValidation(t *testing.T) {
	// Generate two different key pairs
	privateKey1, err := generateTestRSAKeyPair(2048)
	require.NoError(t, err)

	privateKey2, err := generateTestRSAKeyPair(2048)
	require.NoError(t, err)

	// Test that matching keys work
	_, err = NewRSAProvider(&privateKey1.PublicKey, privateKey1)
	assert.NoError(t, err)

	// Test that mismatched keys fail
	_, err = NewRSAProvider(&privateKey1.PublicKey, privateKey2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key pair validation failed")
}

func TestRSAKeyPairValidation_EdgeCases(t *testing.T) {
	// Test with nil keys
	_, err := NewRSAProvider(nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "public key cannot be nil")

	privateKey, err := generateTestRSAKeyPair(2048)
	require.NoError(t, err)

	_, err = NewRSAProvider(&privateKey.PublicKey, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")

	// Test with small key size
	smallKey, err := generateTestRSAKeyPair(1024)
	require.NoError(t, err)

	_, err = NewRSAProvider(&smallKey.PublicKey, smallKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key size must be at least 2048 bits")
}
