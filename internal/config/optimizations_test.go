package config

import (
	"strings"
	"testing"
)

// Every range validateOptimizations enforces, and the message each one is
// refused with: the message is what an operator reads at a failed start, so it
// is part of the contract and is compared rather than merely required to exist.
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
		{
			// A value in range but not a multiple of the segment size produces
			// parts the read path cannot verify, so it is refused at startup
			// rather than at the backend on every large upload (ADR 0003).
			name: "streaming segment size not segment-aligned",
			config: &Config{
				Optimizations: OptimizationsConfig{
					StreamingSegmentSize: 5*1024*1024 + 1,
				},
			},
			expectError: true,
			errorMsg:    "must be a multiple of 65536 bytes (64 KiB)",
		},
		{
			name: "short part buffer below the floor",
			config: &Config{
				Optimizations: OptimizationsConfig{
					MultipartShortPartBufferSize: 5*1024*1024 - 1,
				},
			},
			expectError: true,
			errorMsg:    "optimizations.multipart_short_part_buffer_size: minimum value is 5MB",
		},
		{
			// 5 MiB is the smallest budget in which one session can always
			// complete, so it is the floor and not below it.
			name: "short part buffer exactly at the floor",
			config: &Config{
				Optimizations: OptimizationsConfig{
					MultipartShortPartBufferSize: 5 * 1024 * 1024,
				},
			},
			expectError: false,
		},
		{
			name: "upload concurrency above the ceiling",
			config: &Config{
				Optimizations: OptimizationsConfig{
					MultipartUploadConcurrency: 33,
				},
			},
			expectError: true,
			errorMsg:    "optimizations.multipart_upload_concurrency: maximum value is 32",
		},
		{
			name: "upload concurrency below the floor",
			config: &Config{
				Optimizations: OptimizationsConfig{
					MultipartUploadConcurrency: -1,
				},
			},
			expectError: true,
			errorMsg:    "optimizations.multipart_upload_concurrency: minimum value is 1",
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
				// err.Error() is never empty when err is not nil, so comparing
				// against "" was a check that could not fail: the message an
				// operator sees has to be compared to the message expected.
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message containing %q, got %q", tt.errorMsg, err.Error())
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
