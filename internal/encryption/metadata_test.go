package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestNewMetadataManager(t *testing.T) {
	prefix := "s3ep-"
	manager := NewMetadataManager(prefix)

	if manager.prefix != prefix {
		t.Errorf("Expected prefix %s, got %s", prefix, manager.prefix)
	}
}

func TestMetadataManager_AddHMACToMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name     string
		metadata map[string]string
		rawData  []byte
		dek      []byte
		enabled  bool
		wantErr  bool
		checkKey bool
	}{
		{
			name:     "valid HMAC addition",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      make([]byte, 32), // 256-bit key
			enabled:  true,
			wantErr:  false,
			checkKey: true,
		},
		{
			name:     "disabled integrity verification",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      make([]byte, 32),
			enabled:  false,
			wantErr:  false,
			checkKey: false,
		},
		{
			name:     "nil metadata",
			metadata: nil,
			rawData:  []byte("test data"),
			dek:      make([]byte, 32),
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
		{
			name:     "empty raw data",
			metadata: make(map[string]string),
			rawData:  []byte{},
			dek:      make([]byte, 32),
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
		{
			name:     "empty DEK",
			metadata: make(map[string]string),
			rawData:  []byte("test data"),
			dek:      []byte{},
			enabled:  true,
			wantErr:  true,
			checkKey: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Fill DEK with random data if not empty
			if len(tt.dek) > 0 {
				_, err := rand.Read(tt.dek)
				if err != nil {
					t.Fatalf("Failed to generate random DEK: %v", err)
				}
			}

			err := manager.AddHMACToMetadata(tt.metadata, tt.rawData, tt.dek, tt.enabled)

			if (err != nil) != tt.wantErr {
				t.Errorf("AddHMACToMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.checkKey {
				hmacKey := "s3ep-hmac"
				if _, exists := tt.metadata[hmacKey]; !exists {
					t.Errorf("Expected HMAC key %s to be present in metadata", hmacKey)
				}

				// Verify HMAC value is valid base64
				hmacValue := tt.metadata[hmacKey]
				_, err := base64.StdEncoding.DecodeString(hmacValue)
				if err != nil {
					t.Errorf("HMAC value is not valid base64: %v", err)
				}
			}

			if !tt.checkKey && tt.metadata != nil {
				hmacKey := "s3ep-hmac"
				if _, exists := tt.metadata[hmacKey]; exists {
					t.Errorf("HMAC key %s should not be present when disabled", hmacKey)
				}
			}
		})
	}
}

func TestMetadataManager_VerifyHMACFromMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")
	rawData := []byte("test data for verification")
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	if err != nil {
		t.Fatalf("Failed to generate random DEK: %v", err)
	}

	// Create metadata with valid HMAC
	metadata := make(map[string]string)
	err = manager.AddHMACToMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to add HMAC to metadata: %v", err)
	}

	tests := []struct {
		name     string
		metadata map[string]string
		rawData  []byte
		dek      []byte
		enabled  bool
		wantOK   bool
		wantErr  bool
	}{
		{
			name:     "valid HMAC verification",
			metadata: metadata,
			rawData:  rawData,
			dek:      dek,
			enabled:  true,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "disabled verification (should pass)",
			metadata: metadata,
			rawData:  rawData,
			dek:      dek,
			enabled:  false,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "missing HMAC (backward compatibility)",
			metadata: make(map[string]string),
			rawData:  rawData,
			dek:      dek,
			enabled:  true,
			wantOK:   true,
			wantErr:  false,
		},
		{
			name:     "corrupted data",
			metadata: metadata,
			rawData:  []byte("corrupted data"),
			dek:      dek,
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
		{
			name:     "wrong DEK",
			metadata: metadata,
			rawData:  rawData,
			dek:      make([]byte, 32), // Different DEK
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
		{
			name:     "empty raw data",
			metadata: metadata,
			rawData:  []byte{},
			dek:      dek,
			enabled:  true,
			wantOK:   false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate different DEK for "wrong DEK" test
			if tt.name == "wrong DEK" {
				_, err := rand.Read(tt.dek)
				if err != nil {
					t.Fatalf("Failed to generate different DEK: %v", err)
				}
			}

			ok, err := manager.VerifyHMACFromMetadata(tt.metadata, tt.rawData, tt.dek, tt.enabled)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyHMACFromMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if ok != tt.wantOK {
				t.Errorf("VerifyHMACFromMetadata() ok = %v, wantOK %v", ok, tt.wantOK)
			}
		})
	}
}

func TestMetadataManager_ExtractHMACFromMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name        string
		metadata    map[string]string
		wantHMAC    bool
		wantExists  bool
		wantErr     bool
	}{
		{
			name: "valid HMAC extraction",
			metadata: map[string]string{
				"s3ep-hmac": base64.StdEncoding.EncodeToString([]byte("test-hmac-value")),
			},
			wantHMAC:   true,
			wantExists: true,
			wantErr:    false,
		},
		{
			name:       "missing HMAC",
			metadata:   make(map[string]string),
			wantHMAC:   false,
			wantExists: false,
			wantErr:    false,
		},
		{
			name: "invalid base64 HMAC",
			metadata: map[string]string{
				"s3ep-hmac": "invalid-base64!",
			},
			wantHMAC:   false,
			wantExists: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmacBytes, exists, err := manager.ExtractHMACFromMetadata(tt.metadata)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractHMACFromMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if exists != tt.wantExists {
				t.Errorf("ExtractHMACFromMetadata() exists = %v, wantExists %v", exists, tt.wantExists)
			}

			if tt.wantHMAC && hmacBytes == nil {
				t.Error("Expected HMAC bytes to be returned")
			}

			if !tt.wantHMAC && hmacBytes != nil {
				t.Error("Expected HMAC bytes to be nil")
			}
		})
	}
}

func TestMetadataManager_IsHMACMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "HMAC metadata key",
			key:  "s3ep-hmac",
			want: true,
		},
		{
			name: "other encryption metadata",
			key:  "s3ep-encrypted-dek",
			want: false,
		},
		{
			name: "user metadata",
			key:  "user-metadata",
			want: false,
		},
		{
			name: "different prefix",
			key:  "other-hmac",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := manager.IsHMACMetadata(tt.key); got != tt.want {
				t.Errorf("IsHMACMetadata() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetadataManager_FilterHMACMetadata(t *testing.T) {
	manager := NewMetadataManager("s3ep-")

	tests := []struct {
		name     string
		input    map[string]string
		expected map[string]string
	}{
		{
			name: "filter HMAC from mixed metadata",
			input: map[string]string{
				"s3ep-hmac":          "hmac-value",
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
			expected: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
		},
		{
			name:     "nil metadata",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty metadata",
			input:    make(map[string]string),
			expected: make(map[string]string),
		},
		{
			name: "no HMAC metadata",
			input: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
			expected: map[string]string{
				"s3ep-encrypted-dek": "dek-value",
				"user-metadata":      "user-value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := manager.FilterHMACMetadata(tt.input)

			if result == nil && tt.expected == nil {
				return
			}

			if result == nil || tt.expected == nil {
				t.Errorf("FilterHMACMetadata() result = %v, expected = %v", result, tt.expected)
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("FilterHMACMetadata() result length = %d, expected length = %d", len(result), len(tt.expected))
				return
			}

			for key, expectedValue := range tt.expected {
				if resultValue, exists := result[key]; !exists || resultValue != expectedValue {
					t.Errorf("FilterHMACMetadata() key %s: got %s, expected %s", key, resultValue, expectedValue)
				}
			}

			// Ensure HMAC key is not present
			if _, exists := result["s3ep-hmac"]; exists {
				t.Error("FilterHMACMetadata() should remove HMAC metadata")
			}
		})
	}
}

func TestMetadataManager_GetHMACMetadataKey(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected string
	}{
		{
			name:     "default prefix",
			prefix:   "s3ep-",
			expected: "s3ep-hmac",
		},
		{
			name:     "custom prefix",
			prefix:   "myapp-",
			expected: "myapp-hmac",
		},
		{
			name:     "no prefix",
			prefix:   "",
			expected: "hmac",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewMetadataManager(tt.prefix)
			if got := manager.GetHMACMetadataKey(); got != tt.expected {
				t.Errorf("GetHMACMetadataKey() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestMetadataManager_HMACIntegration(t *testing.T) {
	// Integration test: Add HMAC, then verify it
	manager := NewMetadataManager("s3ep-")
	rawData := []byte("integration test data")
	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	if err != nil {
		t.Fatalf("Failed to generate random DEK: %v", err)
	}

	metadata := make(map[string]string)

	// Add HMAC
	err = manager.AddHMACToMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to add HMAC: %v", err)
	}

	// Verify HMAC
	ok, err := manager.VerifyHMACFromMetadata(metadata, rawData, dek, true)
	if err != nil {
		t.Fatalf("Failed to verify HMAC: %v", err)
	}

	if !ok {
		t.Error("HMAC verification should have succeeded")
	}

	// Test with modified data (should fail)
	modifiedData := []byte("modified data")
	ok, err = manager.VerifyHMACFromMetadata(metadata, modifiedData, dek, true)
	if err == nil {
		t.Error("Expected error for modified data")
	}

	if ok {
		t.Error("HMAC verification should have failed for modified data")
	}
}
