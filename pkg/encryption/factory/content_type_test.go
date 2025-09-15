package factory

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Use 50MB as default threshold for these tests to maintain backwards compatibility
const testStreamingThreshold = 50 * 1024 * 1024

func TestDetermineContentTypeFromHTTPContentType(t *testing.T) {

	tests := []struct {
		name            string
		httpContentType string
		dataSize        int64
		isMultipart     bool
		expected        ContentType
		description     string
	}{
		// Content-Type forcing tests
		{
			name:            "Force AES-GCM single-part",
			httpContentType: ForceAESGCMContentType,
			dataSize:        1024,
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Should force AES-GCM regardless of size/multipart",
		},
		{
			name:            "Force AES-GCM multipart",
			httpContentType: ForceAESGCMContentType,
			dataSize:        100 * 1024 * 1024,
			isMultipart:     true,
			expected:        ContentTypeWhole,
			description:     "Should force AES-GCM even for multipart",
		},
		{
			name:            "Force AES-CTR single-part",
			httpContentType: ForceAESCTRContentType,
			dataSize:        1024,
			isMultipart:     false,
			expected:        ContentTypeMultipart,
			description:     "Should force AES-CTR regardless of size/multipart",
		},
		{
			name:            "Force AES-CTR multipart",
			httpContentType: ForceAESCTRContentType,
			dataSize:        100 * 1024 * 1024,
			isMultipart:     true,
			expected:        ContentTypeMultipart,
			description:     "Should force AES-CTR for multipart",
		},

		// Automatic logic tests
		{
			name:            "Small single-part automatic",
			httpContentType: "application/octet-stream",
			dataSize:        10 * 1024 * 1024, // 10MB
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Small single-part should use AES-GCM",
		},
		{
			name:            "Large single-part automatic",
			httpContentType: "application/octet-stream",
			dataSize:        100 * 1024 * 1024, // 100MB
			isMultipart:     false,
			expected:        ContentTypeMultipart,
			description:     "Large single-part should use AES-CTR",
		},
		{
			name:            "Multipart always AES-CTR",
			httpContentType: "application/octet-stream",
			dataSize:        1024, // Small, but multipart
			isMultipart:     true,
			expected:        ContentTypeMultipart,
			description:     "Multipart always uses AES-CTR",
		},

		// Boundary conditions around 50MB threshold
		{
			name:            "49MB single-part",
			httpContentType: "text/plain",
			dataSize:        49 * 1024 * 1024,
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Just below 50MB should use AES-GCM",
		},
		{
			name:            "50MB single-part",
			httpContentType: "text/plain",
			dataSize:        50 * 1024 * 1024,
			isMultipart:     false,
			expected:        ContentTypeMultipart,
			description:     "Exactly 50MB should use AES-CTR",
		},
		{
			name:            "51MB single-part",
			httpContentType: "text/plain",
			dataSize:        51 * 1024 * 1024,
			isMultipart:     false,
			expected:        ContentTypeMultipart,
			description:     "Just above 50MB should use AES-CTR",
		},

		// Edge cases
		{
			name:            "Empty Content-Type",
			httpContentType: "",
			dataSize:        1024,
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Empty Content-Type should use automatic logic",
		},
		{
			name:            "Zero size",
			httpContentType: "application/json",
			dataSize:        0,
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Zero size should use AES-GCM",
		},
		{
			name:            "Unknown Content-Type",
			httpContentType: "application/unknown-type",
			dataSize:        1024,
			isMultipart:     false,
			expected:        ContentTypeWhole,
			description:     "Unknown Content-Type should use automatic logic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetermineContentTypeFromHTTPContentType(tt.httpContentType, tt.dataSize, tt.isMultipart, testStreamingThreshold)
			assert.Equal(t, tt.expected, result, "Failed: %s", tt.description)

			// Convert result to human-readable algorithm name for logging
			var algorithmName string
			switch result {
			case ContentTypeWhole:
				algorithmName = "AES-GCM"
			case ContentTypeMultipart:
				algorithmName = "AES-CTR"
			default:
				algorithmName = "Unknown"
			}

			t.Logf("✅ %s: Content-Type=%q, Size=%dMB, Multipart=%v → %s",
				tt.name, tt.httpContentType, tt.dataSize/(1024*1024), tt.isMultipart, algorithmName)
		})
	}
}

func TestContentTypeConstants(t *testing.T) {
	// Verify the constants are correctly defined
	assert.Equal(t, "application/x-s3ep-force-aes-gcm", ForceAESGCMContentType,
		"ForceAESGCMContentType constant should match expected value")

	assert.Equal(t, "application/x-s3ep-force-aes-ctr", ForceAESCTRContentType,
		"ForceAESCTRContentType constant should match expected value")

	// Ensure they are different
	assert.NotEqual(t, ForceAESGCMContentType, ForceAESCTRContentType,
		"Forcing Content-Types should be different")

	t.Logf("✅ Content-Type constants verified:")
	t.Logf("   Force AES-GCM: %s", ForceAESGCMContentType)
	t.Logf("   Force AES-CTR: %s", ForceAESCTRContentType)
}

func TestAutomaticThresholdAccuracy(t *testing.T) {
	// Test the exact 50MB threshold
	threshold := int64(50 * 1024 * 1024) // 50MB

	testCases := []struct {
		name     string
		size     int64
		expected ContentType
	}{
		{
			name:     "1 byte below threshold",
			size:     threshold - 1,
			expected: ContentTypeWhole, // AES-GCM
		},
		{
			name:     "Exactly at threshold",
			size:     threshold,
			expected: ContentTypeMultipart, // AES-CTR
		},
		{
			name:     "1 byte above threshold",
			size:     threshold + 1,
			expected: ContentTypeMultipart, // AES-CTR
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := DetermineContentTypeFromHTTPContentType("application/octet-stream", tc.size, false, testStreamingThreshold)
			assert.Equal(t, tc.expected, result)

			algorithm := "AES-GCM"
			if result == ContentTypeMultipart {
				algorithm = "AES-CTR"
			}

			t.Logf("✅ %s (%d bytes): %s", tc.name, tc.size, algorithm)
		})
	}
}
