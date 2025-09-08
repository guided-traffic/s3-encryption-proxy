package meta

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoneProvider_Encrypt(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Test data
	plaintext := []byte("Hello, World! This is test data for encryption.")
	associatedData := []byte("test-object-key")

	// Encrypt data (should be pass-through)
	result, err := provider.Encrypt(context.Background(), plaintext, associatedData)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify that data is not actually encrypted
	assert.Equal(t, plaintext, result.EncryptedData, "None provider should return original data")
	assert.Empty(t, result.EncryptedDEK, "None provider should have empty DEK")

	// Verify metadata
	assert.Contains(t, result.Metadata, "algorithm")
	assert.Equal(t, "none", result.Metadata["algorithm"])
	assert.Contains(t, result.Metadata, "provider_type")
	assert.Equal(t, "none", result.Metadata["provider_type"])
}

func TestNoneProvider_Decrypt(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Test data
	testData := []byte("Hello, World! This is test data for decryption.")
	associatedData := []byte("test-object-key")
	emptyDEK := []byte{}

	// Decrypt data (should be pass-through)
	decrypted, err := provider.Decrypt(context.Background(), testData, emptyDEK, associatedData)
	require.NoError(t, err)

	// Verify that data is returned unchanged
	assert.Equal(t, testData, decrypted, "None provider should return data unchanged")
}

func TestNoneProvider_EncryptDecryptRoundTrip(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Test data
	originalData := []byte("Round trip test data for none provider.")
	associatedData := []byte("test-object-key-roundtrip")

	// Encrypt data
	encResult, err := provider.Encrypt(context.Background(), originalData, associatedData)
	require.NoError(t, err)
	require.NotNil(t, encResult)

	// Decrypt data
	decrypted, err := provider.Decrypt(context.Background(), encResult.EncryptedData, encResult.EncryptedDEK, associatedData)
	require.NoError(t, err)

	// Verify round trip
	assert.Equal(t, originalData, decrypted, "Round trip should return original data")
}

func TestNoneProvider_RotateKEK(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// RotateKEK should be a no-op
	err = provider.RotateKEK(context.Background())
	assert.NoError(t, err, "RotateKEK should succeed as no-op")
}

func TestNoneProvider_WithEmptyData(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Test with empty data
	emptyData := []byte{}
	associatedData := []byte("test-key")

	// Encrypt empty data
	encResult, err := provider.Encrypt(context.Background(), emptyData, associatedData)
	require.NoError(t, err)
	require.NotNil(t, encResult)
	assert.Equal(t, emptyData, encResult.EncryptedData)

	// Decrypt empty data
	decrypted, err := provider.Decrypt(context.Background(), encResult.EncryptedData, encResult.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, emptyData, decrypted)
}

func TestNoneProvider_WithLargeData(t *testing.T) {
	// Create none provider
	provider, err := NewNoneProvider(&NoneConfig{})
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Create larger test data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	associatedData := []byte("large-data-key")

	// Encrypt large data
	encResult, err := provider.Encrypt(context.Background(), largeData, associatedData)
	require.NoError(t, err)
	require.NotNil(t, encResult)
	assert.Equal(t, largeData, encResult.EncryptedData)

	// Decrypt large data
	decrypted, err := provider.Decrypt(context.Background(), encResult.EncryptedData, encResult.EncryptedDEK, associatedData)
	require.NoError(t, err)
	assert.Equal(t, largeData, decrypted)
}
