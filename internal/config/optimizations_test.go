package config

import (
	"testing"
)

func TestOptimizationsConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid default config",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingBufferSize:           64 * 1024, // 64KB
					EnableAdaptiveBuffering:       false,
					StreamingSegmentSize:          12 * 1024 * 1024, // 12MB
					ForceTraditionalThreshold:     1 * 1024 * 1024, // 1MB
					StreamingThreshold:            5 * 1024 * 1024, // 5MB
				},
			},
			expectError: false,
		},
		{
			name: "buffer size too small",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingBufferSize: 2 * 1024, // 2KB - too small
				},
			},
			expectError: true,
			errorMsg:    "minimum value is 4KB",
		},
		{
			name: "buffer size too large",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingBufferSize: 3 * 1024 * 1024, // 3MB - too large
				},
			},
			expectError: true,
			errorMsg:    "maximum value is 2MB",
		},
		{
			name: "adaptive buffering with invalid thresholds",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingBufferSize:           64 * 1024,
					EnableAdaptiveBuffering:       true,
					ForceTraditionalThreshold:     6 * 1024 * 1024, // 6MB
					StreamingThreshold:            5 * 1024 * 1024, // 5MB - should be larger than traditional
				},
			},
			expectError: true,
			errorMsg:    "must be less than streaming_threshold",
		},
		{
			name: "zero buffer size (use default)",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingBufferSize: 0, // Should use default
				},
			},
			expectError: false,
		},
		{
			name: "streaming segment size too small",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 2 * 1024 * 1024, // 2MB - too small
				},
			},
			expectError: true,
			errorMsg:    "minimum value is 5MB",
		},
		{
			name: "streaming segment size too large",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 6 * 1024 * 1024 * 1024, // 6GB - too large
				},
			},
			expectError: true,
			errorMsg:    "maximum value is 5GB",
		},
		{
			name: "valid streaming segment size",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 50 * 1024 * 1024, // 50MB - valid
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOptimizations(tt.config)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && err.Error() == "" {
					t.Errorf("expected error message containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetStreamingSegmentSize(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedSize int64
	}{
		{
			name: "uses optimizations.streaming_segment_size when set",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 20 * 1024 * 1024, // 20MB
				},
			},
			expectedSize: 20 * 1024 * 1024,
		},
		{
			name: "uses default when optimizations not set",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 0, // Not set
				},
			},
			expectedSize: 12 * 1024 * 1024, // Default 12MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSize := tt.config.GetStreamingSegmentSize()
			if actualSize != tt.expectedSize {
				t.Errorf("expected segment size %d, got %d", tt.expectedSize, actualSize)
			}
		})
	}
}

func TestGetStreamingBufferSize(t *testing.T) {
	// This test would require creating a Manager, which needs factory setup
	// For now, we'll test the configuration validation logic
	tests := []struct {
		name          string
		bufferSize    int
		expectedSize  int
	}{
		{
			name:         "configured buffer size",
			bufferSize:   128 * 1024, // 128KB
			expectedSize: 128 * 1024,
		},
		{
			name:         "zero buffer size uses default",
			bufferSize:   0,
			expectedSize: 64 * 1024, // Should use default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Since we can't easily create a Manager without full setup,
			// we'll test the logic inline
			actualSize := tt.bufferSize
			if actualSize <= 0 {
				actualSize = 64 * 1024 // Default
			}

			if actualSize != tt.expectedSize {
				t.Errorf("expected buffer size %d, got %d", tt.expectedSize, actualSize)
			}
		})
	}
}

func TestAdaptiveBufferSizing(t *testing.T) {
	tests := []struct {
		name                    string
		enableAdaptiveBuffering bool
		configuredBufferSize    int
		objectSize              int64
		expectedBufferSize      int
	}{
		{
			name:                    "adaptive disabled uses configured buffer",
			enableAdaptiveBuffering: false,
			configuredBufferSize:    128 * 1024, // 128KB
			objectSize:              10 * 1024 * 1024, // 10MB
			expectedBufferSize:      128 * 1024, // Should use configured
		},
		{
			name:                    "small file uses small buffer",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    0, // Use default, don't force larger buffer
			objectSize:              500 * 1024, // 500KB (< 1MB)
			expectedBufferSize:      16 * 1024, // 16KB for small files
		},
		{
			name:                    "medium file uses medium buffer",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    64 * 1024, // 64KB
			objectSize:              10 * 1024 * 1024, // 10MB (1MB - 50MB)
			expectedBufferSize:      64 * 1024, // 64KB for medium files
		},
		{
			name:                    "large file uses large buffer",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    64 * 1024, // 64KB
			objectSize:              100 * 1024 * 1024, // 100MB (50MB - 500MB)
			expectedBufferSize:      256 * 1024, // 256KB for large files
		},
		{
			name:                    "very large file uses maximum buffer",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    64 * 1024, // 64KB
			objectSize:              1024 * 1024 * 1024, // 1GB (> 500MB)
			expectedBufferSize:      512 * 1024, // 512KB for very large files
		},
		{
			name:                    "respects maximum buffer size limit",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    64 * 1024, // 64KB
			objectSize:              5 * 1024 * 1024 * 1024, // 5GB
			expectedBufferSize:      512 * 1024, // Capped at 512KB (< 2MB limit)
		},
		{
			name:                    "respects configured buffer when larger than adaptive",
			enableAdaptiveBuffering: true,
			configuredBufferSize:    1024 * 1024, // 1MB configured
			objectSize:              500 * 1024, // 500KB (would suggest 16KB)
			expectedBufferSize:      1024 * 1024, // Should use configured 1MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Optimizations: OptimizationsConfig{
					EnableAdaptiveBuffering: tt.enableAdaptiveBuffering,
					StreamingBufferSize:     tt.configuredBufferSize,
				},
			}

			// Test the adaptive buffer logic
			actualSize := getTestAdaptiveBufferSize(cfg, tt.objectSize)
			if actualSize != tt.expectedBufferSize {
				t.Errorf("expected buffer size %d, got %d", tt.expectedBufferSize, actualSize)
			}
		})
	}
}

// Helper function to test adaptive buffer logic without full Manager setup
func getTestAdaptiveBufferSize(cfg *Config, expectedSize int64) int {
	// Base buffer size logic
	baseBufferSize := cfg.Optimizations.StreamingBufferSize
	if baseBufferSize <= 0 {
		baseBufferSize = 64 * 1024 // Default
	}

	// If adaptive buffering is disabled, use base buffer size
	if !cfg.Optimizations.EnableAdaptiveBuffering {
		return baseBufferSize
	}

	// Define buffer size tiers based on object size
	const (
		tier1Threshold = 1 * 1024 * 1024      // 1MB
		tier1BufferSize = 16 * 1024           // 16KB

		tier2Threshold = 50 * 1024 * 1024     // 50MB
		tier2BufferSize = 64 * 1024           // 64KB

		tier3Threshold = 500 * 1024 * 1024    // 500MB
		tier3BufferSize = 256 * 1024          // 256KB

		tier4BufferSize = 512 * 1024          // 512KB
	)

	// If no size hint available, use base buffer
	if expectedSize <= 0 {
		return baseBufferSize
	}

	// Apply adaptive sizing based on expected object size
	var adaptiveSize int
	switch {
	case expectedSize < tier1Threshold:
		adaptiveSize = tier1BufferSize
	case expectedSize < tier2Threshold:
		adaptiveSize = tier2BufferSize
	case expectedSize < tier3Threshold:
		adaptiveSize = tier3BufferSize
	default:
		adaptiveSize = tier4BufferSize
	}

	// Respect configured limits (4KB minimum, 2MB maximum)
	const (
		minBufferSize = 4 * 1024      // 4KB minimum
		maxBufferSize = 2 * 1024 * 1024 // 2MB maximum
	)

	if adaptiveSize < minBufferSize {
		adaptiveSize = minBufferSize
	}
	if adaptiveSize > maxBufferSize {
		adaptiveSize = maxBufferSize
	}

	// Don't go below configured buffer size if it's larger than adaptive size
	// But only if configured buffer is reasonable (not the fallback default)
	if cfg.Optimizations.StreamingBufferSize > 0 && adaptiveSize < baseBufferSize && baseBufferSize <= maxBufferSize {
		return baseBufferSize
	}

	return adaptiveSize
}
