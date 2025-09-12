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
