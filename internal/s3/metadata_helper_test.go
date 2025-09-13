package s3

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMetadataHelper_ExtractEncryptionMetadata(t *testing.T) {
	helper := NewMetadataHelper("s3ep-")

	tests := []struct {
		name         string
		metadata     map[string]string
		expectedDEK  string
		expectedEnc  bool
		expectedStr  bool
	}{
		{
			name: "prefixed encrypted metadata",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "dGVzdC1lbmNyeXB0ZWQtZGVr",
				"custom-header":      "value",
			},
			expectedDEK: "dGVzdC1lbmNyeXB0ZWQtZGVr",
			expectedEnc: true,
			expectedStr: false,
		},
		{
			name: "prefixed streaming metadata",
			metadata: map[string]string{
				"s3ep-encrypted-dek": "dGVzdC1lbmNyeXB0ZWQtZGVr",
				"s3ep-dek-algorithm": "aes-256-ctr",
				"custom-header":      "value",
			},
			expectedDEK: "dGVzdC1lbmNyeXB0ZWQtZGVr",
			expectedEnc: true,
			expectedStr: true,
		},
		{
			name: "legacy dek format",
			metadata: map[string]string{
				"s3ep-dek":      "dGVzdC1lbmNyeXB0ZWQtZGVr",
				"custom-header": "value",
			},
			expectedDEK: "dGVzdC1lbmNyeXB0ZWQtZGVr",
			expectedEnc: true,
			expectedStr: false,
		},
		{
			name: "unprefixed metadata",
			metadata: map[string]string{
				"encrypted-dek":  "dGVzdC1lbmNyeXB0ZWQtZGVr",
				"custom-header":  "value",
			},
			expectedDEK: "dGVzdC1lbmNyeXB0ZWQtZGVr",
			expectedEnc: true,
			expectedStr: false,
		},
		{
			name: "no encryption metadata",
			metadata: map[string]string{
				"custom-header": "value",
			},
			expectedDEK: "",
			expectedEnc: false,
			expectedStr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dek, isEnc, isStr := helper.ExtractEncryptionMetadata(tt.metadata)
			assert.Equal(t, tt.expectedDEK, dek)
			assert.Equal(t, tt.expectedEnc, isEnc)
			assert.Equal(t, tt.expectedStr, isStr)
		})
	}
}

func TestMetadataHelper_CleanMetadata(t *testing.T) {
	helper := NewMetadataHelper("s3ep-")

	input := map[string]string{
		"custom-header":          "value",
		"s3ep-encrypted-dek":     "should-be-removed",
		"s3ep-dek-algorithm":     "should-be-removed",
		"s3ep-kek-algorithm":     "should-be-removed",
		"s3ep-kek-fingerprint":   "should-be-removed",
		"dek-algorithm":          "should-be-removed",
		"kek-algorithm":          "should-be-removed",
		"kek-fingerprint":        "should-be-removed",
		"encrypted-dek":          "should-be-removed",
		"encryption-mode":        "should-be-removed",
		"upload-id":              "should-be-removed",
		"aes-iv":                 "should-be-removed",
		"another-custom-header":  "keep",
	}

	result := helper.CleanMetadata(input)

	expected := map[string]string{
		"custom-header":         "value",
		"another-custom-header": "keep",
	}

	assert.Equal(t, expected, result)
}

func TestMetadataHelper_PrepareEncryptionMetadata(t *testing.T) {
	helper := NewMetadataHelper("s3ep-")

	userMetadata := map[string]string{
		"custom-header": "value",
	}

	encryptionMetadata := map[string]string{
		"s3ep-encrypted-dek": "dGVzdC1lbmNyeXB0ZWQtZGVr",
		"s3ep-algorithm":     "aes-256-gcm",
	}

	result := helper.PrepareEncryptionMetadata(userMetadata, encryptionMetadata)

	expected := map[string]string{
		"custom-header":      "value",
		"s3ep-encrypted-dek": "dGVzdC1lbmNyeXB0ZWQtZGVr",
		"s3ep-algorithm":     "aes-256-gcm",
	}

	assert.Equal(t, expected, result)
}

func TestMetadataHelper_PrepareEncryptionMetadata_NilInputs(t *testing.T) {
	helper := NewMetadataHelper("s3ep-")

	// Test with nil user metadata
	result := helper.PrepareEncryptionMetadata(nil, map[string]string{"s3ep-key": "value"})
	expected := map[string]string{"s3ep-key": "value"}
	assert.Equal(t, expected, result)

	// Test with nil encryption metadata
	result = helper.PrepareEncryptionMetadata(map[string]string{"custom": "value"}, nil)
	expected = map[string]string{"custom": "value"}
	assert.Equal(t, expected, result)

	// Test with both nil
	result = helper.PrepareEncryptionMetadata(nil, nil)
	assert.Nil(t, result)
}

func TestMetadataHelper_DecodeEncryptedDEK(t *testing.T) {
	helper := NewMetadataHelper("s3ep-")

	// Valid base64
	validB64 := "dGVzdC1lbmNyeXB0ZWQtZGVr"
	result, err := helper.DecodeEncryptedDEK(validB64)
	assert.NoError(t, err)
	assert.Equal(t, []byte("test-encrypted-dek"), result)

	// Invalid base64
	invalidB64 := "invalid-base64!!!"
	_, err = helper.DecodeEncryptedDEK(invalidB64)
	assert.Error(t, err)
}
