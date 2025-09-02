package proxy

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSafeInt32(t *testing.T) {
	tests := []struct {
		name     string
		input    int64
		expected int32
	}{
		{
			name:     "Normal value within int32 range",
			input:    1000,
			expected: 1000,
		},
		{
			name:     "Zero value",
			input:    0,
			expected: 0,
		},
		{
			name:     "Max int32 value",
			input:    math.MaxInt32,
			expected: math.MaxInt32,
		},
		{
			name:     "Value just above int32 max - should be clamped",
			input:    int64(math.MaxInt32) + 1,
			expected: math.MaxInt32,
		},
		{
			name:     "Very large value - should be clamped",
			input:    int64(math.MaxInt64),
			expected: math.MaxInt32,
		},
		{
			name:     "Negative value (should pass through since it's within range)",
			input:    -100,
			expected: -100,
		},
		{
			name:     "Min int32 value",
			input:    math.MinInt32,
			expected: math.MinInt32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeInt32(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSafeInt32SecurityProperty(t *testing.T) {
	// Security test: Ensure no integer overflow can occur
	testValues := []int64{
		math.MaxInt64,
		math.MaxInt32 + 1,
		math.MaxInt32 + 1000000,
		9223372036854775807, // Max int64
	}

	for _, value := range testValues {
		result := safeInt32(value)
		// Result should never exceed int32 max
		assert.LessOrEqual(t, result, int32(math.MaxInt32))
		// Result should never be negative when input is positive and clamped
		if value > math.MaxInt32 {
			assert.Equal(t, int32(math.MaxInt32), result)
		}
	}
}
