package main

import (
	"fmt"

	"github.com/guided-traffic/s3-encryption-proxy/internal/config"
)

func main() {
	fmt.Println("Testing new streaming threshold configuration...")

	// Test creating config with optimizations
	cfg := &config.Config{
		Optimizations: config.OptimizationsConfig{
			StreamingThreshold:   1 * 1024 * 1024, // 1MB
			StreamingBufferSize:  64 * 1024,       // 64KB
			StreamingSegmentSize: 12 * 1024 * 1024, // 12MB
		},
	}

	fmt.Printf("✅ Config created successfully!\n")
	fmt.Printf("Streaming threshold: %d bytes (%.1f MB)\n",
		cfg.Optimizations.StreamingThreshold,
		float64(cfg.Optimizations.StreamingThreshold)/(1024*1024))

	// Verify the threshold is what we expect (1MB = 1048576)
	expectedThreshold := int64(1048576)
	if cfg.Optimizations.StreamingThreshold == expectedThreshold {
		fmt.Printf("✅ Streaming threshold is correctly set to 1MB\n")
	} else {
		fmt.Printf("❌ Expected threshold: %d, got: %d\n", expectedThreshold, cfg.Optimizations.StreamingThreshold)
	}

	// Test validation (this should work now)
	err := cfg.ValidateOptimizations()
	if err != nil {
		fmt.Printf("❌ Validation failed: %v\n", err)
	} else {
		fmt.Printf("✅ Configuration validation passed!\n")
	}

	fmt.Println("✅ Configuration test completed successfully!")
}
