package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewHKDFConfig(t *testing.T) {
	config := NewHKDFConfig()

	if config.HashAlgorithm != "sha256" {
		t.Errorf("Expected default hash algorithm to be 'sha256', got '%s'", config.HashAlgorithm)
	}

	if config.HMACKeySize != DefaultHMACKeySize {
		t.Errorf("Expected default HMAC key size to be %d, got %d", DefaultHMACKeySize, config.HMACKeySize)
	}

	if config.HKDFSaltLength != DefaultHKDFSaltLength {
		t.Errorf("Expected default HKDF salt length to be %d, got %d", DefaultHKDFSaltLength, config.HKDFSaltLength)
	}
}

func TestHKDFConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *HKDFConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid default config",
			config:      NewHKDFConfig(),
			expectError: false,
		},
		{
			name: "valid sha512 config",
			config: &HKDFConfig{
				HashAlgorithm:  "sha512",
				HMACKeySize:    32,
				HKDFSaltLength: 32,
			},
			expectError: false,
		},
		{
			name: "empty hash algorithm",
			config: &HKDFConfig{
				HashAlgorithm:  "",
				HMACKeySize:    32,
				HKDFSaltLength: 32,
			},
			expectError: true,
			errorMsg:    "hash algorithm is required",
		},
		{
			name: "invalid hash algorithm",
			config: &HKDFConfig{
				HashAlgorithm:  "md5",
				HMACKeySize:    32,
				HKDFSaltLength: 32,
			},
			expectError: true,
			errorMsg:    "unsupported hash algorithm 'md5'",
		},
		{
			name: "HMAC key size too small",
			config: &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    15,
				HKDFSaltLength: 32,
			},
			expectError: true,
			errorMsg:    "HMAC key size must be at least 16 bytes",
		},
		{
			name: "HMAC key size too large",
			config: &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    65,
				HKDFSaltLength: 32,
			},
			expectError: true,
			errorMsg:    "HMAC key size must be at most 64 bytes",
		},
		{
			name: "HKDF salt length too small",
			config: &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    32,
				HKDFSaltLength: 15,
			},
			expectError: true,
			errorMsg:    "HKDF salt length must be at least 16 bytes",
		},
		{
			name: "HKDF salt length too large",
			config: &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    32,
				HKDFSaltLength: 65,
			},
			expectError: true,
			errorMsg:    "HKDF salt length must be at most 64 bytes",
		},
		{
			name: "minimum valid values",
			config: &HKDFConfig{
				HashAlgorithm:  "sha256",
				HMACKeySize:    MinHMACKeySize,
				HKDFSaltLength: MinHKDFSaltLength,
			},
			expectError: false,
		},
		{
			name: "maximum valid values",
			config: &HKDFConfig{
				HashAlgorithm:  "sha512",
				HMACKeySize:    MaxHMACKeySize,
				HKDFSaltLength: MaxHKDFSaltLength,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestHKDFConfig_DeriveIntegrityKey(t *testing.T) {
	config := NewHKDFConfig()
	masterKey := []byte("test-master-key-32-bytes-long!!")

	t.Run("derive with random salt", func(t *testing.T) {
		result, err := config.DeriveIntegrityKey(masterKey, nil)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if len(result.DerivedKey) != config.HMACKeySize {
			t.Errorf("Expected derived key length %d, got %d", config.HMACKeySize, len(result.DerivedKey))
		}

		if len(result.Salt) != config.HKDFSaltLength {
			t.Errorf("Expected salt length %d, got %d", config.HKDFSaltLength, len(result.Salt))
		}

		// Verify that the derived key is not all zeros
		allZeros := make([]byte, len(result.DerivedKey))
		if bytes.Equal(result.DerivedKey, allZeros) {
			t.Error("Derived key should not be all zeros")
		}
	})

	t.Run("derive with provided salt", func(t *testing.T) {
		salt := make([]byte, config.HKDFSaltLength)
		for i := range salt {
			salt[i] = byte(i)
		}

		result, err := config.DeriveIntegrityKey(masterKey, salt)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !bytes.Equal(result.Salt, salt) {
			t.Error("Result salt should match provided salt")
		}

		// Derive again with same salt - should get same key
		result2, err := config.DeriveIntegrityKey(masterKey, salt)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if !bytes.Equal(result.DerivedKey, result2.DerivedKey) {
			t.Error("Derived keys should be identical with same inputs")
		}
	})

	t.Run("derive with different salts produces different keys", func(t *testing.T) {
		salt1 := make([]byte, config.HKDFSaltLength)
		salt2 := make([]byte, config.HKDFSaltLength)

		for i := range salt1 {
			salt1[i] = byte(i)
			salt2[i] = byte(i + 1)
		}

		result1, err := config.DeriveIntegrityKey(masterKey, salt1)
		if err != nil {
			t.Fatalf("Expected no error for result1, got: %v", err)
		}

		result2, err := config.DeriveIntegrityKey(masterKey, salt2)
		if err != nil {
			t.Fatalf("Expected no error for result2, got: %v", err)
		}

		if bytes.Equal(result1.DerivedKey, result2.DerivedKey) {
			t.Error("Different salts should produce different derived keys")
		}
	})

	t.Run("empty master key", func(t *testing.T) {
		_, err := config.DeriveIntegrityKey([]byte{}, nil)
		if err == nil {
			t.Error("Expected error for empty master key")
		}
		if !contains(err.Error(), "master key cannot be empty") {
			t.Errorf("Expected error about empty master key, got: %v", err)
		}
	})

	t.Run("wrong salt length", func(t *testing.T) {
		wrongSalt := make([]byte, config.HKDFSaltLength-1)
		_, err := config.DeriveIntegrityKey(masterKey, wrongSalt)
		if err == nil {
			t.Error("Expected error for wrong salt length")
		}
		if !contains(err.Error(), "salt length must be") {
			t.Errorf("Expected error about salt length, got: %v", err)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		invalidConfig := &HKDFConfig{
			HashAlgorithm:  "",
			HMACKeySize:    32,
			HKDFSaltLength: 32,
		}
		_, err := invalidConfig.DeriveIntegrityKey(masterKey, nil)
		if err == nil {
			t.Error("Expected error for invalid config")
		}
		if !contains(err.Error(), "invalid HKDF config") {
			t.Errorf("Expected error about invalid config, got: %v", err)
		}
	})
}

func TestHKDFConfig_DeriveIntegrityKeyWithRandomSalt(t *testing.T) {
	config := NewHKDFConfig()
	masterKey := []byte("test-master-key-32-bytes-long!!")

	result1, err := config.DeriveIntegrityKeyWithRandomSalt(masterKey)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	result2, err := config.DeriveIntegrityKeyWithRandomSalt(masterKey)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Different calls should produce different salts and keys
	if bytes.Equal(result1.Salt, result2.Salt) {
		t.Error("Random salts should be different")
	}

	if bytes.Equal(result1.DerivedKey, result2.DerivedKey) {
		t.Error("Derived keys with random salts should be different")
	}
}

func TestHKDFConfig_DeriveIntegrityKeyWithSalt(t *testing.T) {
	config := NewHKDFConfig()
	masterKey := []byte("test-master-key-32-bytes-long!!")
	salt := make([]byte, config.HKDFSaltLength)

	t.Run("valid salt", func(t *testing.T) {
		_, err := config.DeriveIntegrityKeyWithSalt(masterKey, salt)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("nil salt", func(t *testing.T) {
		_, err := config.DeriveIntegrityKeyWithSalt(masterKey, nil)
		if err == nil {
			t.Error("Expected error for nil salt")
		}
		if !contains(err.Error(), "salt cannot be nil") {
			t.Errorf("Expected error about nil salt, got: %v", err)
		}
	})
}

func TestHKDFConfig_GenerateRandomSalt(t *testing.T) {
	config := NewHKDFConfig()

	t.Run("valid config", func(t *testing.T) {
		salt, err := config.GenerateRandomSalt()
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if len(salt) != config.HKDFSaltLength {
			t.Errorf("Expected salt length %d, got %d", config.HKDFSaltLength, len(salt))
		}

		// Generate another salt and verify they're different
		salt2, err := config.GenerateRandomSalt()
		if err != nil {
			t.Fatalf("Expected no error for second salt, got: %v", err)
		}

		if bytes.Equal(salt, salt2) {
			t.Error("Generated salts should be different")
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		invalidConfig := &HKDFConfig{
			HashAlgorithm:  "",
			HMACKeySize:    32,
			HKDFSaltLength: 32,
		}
		_, err := invalidConfig.GenerateRandomSalt()
		if err == nil {
			t.Error("Expected error for invalid config")
		}
		if !contains(err.Error(), "invalid HKDF config") {
			t.Errorf("Expected error about invalid config, got: %v", err)
		}
	})
}

func TestHKDFDifferentHashAlgorithms(t *testing.T) {
	masterKey := []byte("test-master-key-32-bytes-long!!")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	configSHA256 := &HKDFConfig{
		HashAlgorithm:  "sha256",
		HMACKeySize:    32,
		HKDFSaltLength: 32,
	}

	configSHA512 := &HKDFConfig{
		HashAlgorithm:  "sha512",
		HMACKeySize:    32,
		HKDFSaltLength: 32,
	}

	result256, err := configSHA256.DeriveIntegrityKey(masterKey, salt)
	if err != nil {
		t.Fatalf("Expected no error for SHA256, got: %v", err)
	}

	result512, err := configSHA512.DeriveIntegrityKey(masterKey, salt)
	if err != nil {
		t.Fatalf("Expected no error for SHA512, got: %v", err)
	}

	if bytes.Equal(result256.DerivedKey, result512.DerivedKey) {
		t.Error("Different hash algorithms should produce different derived keys")
	}
}

func TestHKDFConstants(t *testing.T) {
	// Test that constants have expected values
	if HKDFIntegrityInfo != "s3-encryption-proxy-integrity-verification" {
		t.Errorf("Unexpected HKDF integrity info: %s", HKDFIntegrityInfo)
	}

	if DefaultHMACKeySize != 32 {
		t.Errorf("Expected default HMAC key size to be 32, got %d", DefaultHMACKeySize)
	}

	if DefaultHKDFSaltLength != 32 {
		t.Errorf("Expected default HKDF salt length to be 32, got %d", DefaultHKDFSaltLength)
	}

	if MinHMACKeySize != 16 {
		t.Errorf("Expected minimum HMAC key size to be 16, got %d", MinHMACKeySize)
	}

	if MaxHMACKeySize != 64 {
		t.Errorf("Expected maximum HMAC key size to be 64, got %d", MaxHMACKeySize)
	}

	if MinHKDFSaltLength != 16 {
		t.Errorf("Expected minimum HKDF salt length to be 16, got %d", MinHKDFSaltLength)
	}

	if MaxHKDFSaltLength != 64 {
		t.Errorf("Expected maximum HKDF salt length to be 64, got %d", MaxHKDFSaltLength)
	}
}

func TestHKDFSecurityProperties(t *testing.T) {
	config := NewHKDFConfig()
	masterKey := []byte("test-master-key-32-bytes-long!!")

	// Test that same inputs always produce same outputs (deterministic)
	salt := make([]byte, config.HKDFSaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}

	result1, err := config.DeriveIntegrityKey(masterKey, salt)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	result2, err := config.DeriveIntegrityKey(masterKey, salt)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if !bytes.Equal(result1.DerivedKey, result2.DerivedKey) {
		t.Error("HKDF should be deterministic - same inputs should produce same outputs")
	}

	// Test that different master keys produce different outputs
	masterKey2 := []byte("different-master-key-32-bytes!")
	result3, err := config.DeriveIntegrityKey(masterKey2, salt)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if bytes.Equal(result1.DerivedKey, result3.DerivedKey) {
		t.Error("Different master keys should produce different derived keys")
	}
}

// BenchmarkHKDFDerivation benchmarks the HKDF key derivation process
func BenchmarkHKDFDerivation(b *testing.B) {
	config := NewHKDFConfig()
	masterKey := make([]byte, 32)
	salt := make([]byte, 32)

	// Fill with some data
	rand.Read(masterKey)
	rand.Read(salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := config.DeriveIntegrityKey(masterKey, salt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(substr) > 0 && len(s) > len(substr) &&
			(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
				func() bool {
					for i := 0; i <= len(s)-len(substr); i++ {
						if s[i:i+len(substr)] == substr {
							return true
						}
					}
					return false
				}())))
}
