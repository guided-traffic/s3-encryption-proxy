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
					StreamingSegmentSize: 12 * 1024 * 1024, // 12MB
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
