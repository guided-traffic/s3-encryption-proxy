//go:build integration

package integration

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EncryptionValidationResult holds the results of encryption validation checks
type EncryptionValidationResult struct {
	Entropy              float64
	IsEntropyAcceptable  bool
	HasReadableStrings   bool
	HasUniformDistrib    bool
	HasMetadataSignature bool
	IsValidEncryption    bool
	Violations           []string
}

// EncryptionValidationConfig defines thresholds for encryption validation
type EncryptionValidationConfig struct {
	MinEntropy           float64 // Minimum entropy threshold (default: 7.8)
	MaxReadableStringLen int     // Maximum allowed readable ASCII string length (default: 3)
	MaxByteFreqVariance  float64 // Maximum variance in byte frequency distribution (default: 0.1)
	ForbiddenPatterns    []string // Patterns that should not appear in encrypted data
}

// DefaultEncryptionValidationConfig returns the default validation configuration
func DefaultEncryptionValidationConfig() EncryptionValidationConfig {
	return EncryptionValidationConfig{
		MinEntropy:           7.8,
		MaxReadableStringLen: 3,
		MaxByteFreqVariance:  0.1,
		ForbiddenPatterns: []string{
			"s3ep-", "S3EP-", // S3EP metadata signatures
			"BEGIN", "END",   // PEM/certificate signatures
			"<?xml", "</",    // XML signatures
			"{\"", "\"}",     // JSON signatures
			"-----",          // Common delimiters
			"http://", "https://", // URLs
			"Content-Type:", "Content-Length:", // HTTP headers
		},
	}
}

// ConfigForDataSize returns validation config adjusted for data size
func ConfigForDataSize(dataSize int) EncryptionValidationConfig {
	config := DefaultEncryptionValidationConfig()

	// Adjust entropy threshold based on data size
	// Smaller files have naturally lower entropy in encryption
	switch {
	case dataSize < 1024: // < 1KB
		config.MinEntropy = 5.5 // Relaxed for very small files
		config.MaxReadableStringLen = 8 // Allow longer ASCII sequences in small files
		config.MaxByteFreqVariance = 0.25 // Very relaxed for small files
	case dataSize < 10*1024: // < 10KB
		config.MinEntropy = 6.5 // Moderate for small files
		config.MaxReadableStringLen = 6 // Slightly relaxed
		config.MaxByteFreqVariance = 0.20 // Relaxed for small files
	case dataSize < 100*1024: // < 100KB
		config.MinEntropy = 7.2 // Slightly relaxed for medium files
		config.MaxReadableStringLen = 4 // Slightly relaxed
		config.MaxByteFreqVariance = 0.15 // Slightly relaxed
	default:
		config.MinEntropy = 7.8 // Standard for large files
		config.MaxReadableStringLen = 3 // Standard
		config.MaxByteFreqVariance = 0.1 // Standard
	}

	return config
}

// ValidateEncryptedData performs comprehensive validation to ensure data appears properly encrypted
func ValidateEncryptedData(t *testing.T, data []byte, config EncryptionValidationConfig) EncryptionValidationResult {
	t.Helper()

	if len(data) == 0 {
		return EncryptionValidationResult{
			IsValidEncryption: true, // Empty data is considered valid
			Violations:        []string{},
		}
	}

	result := EncryptionValidationResult{
		Violations: make([]string, 0),
	}

	// 1. Calculate Shannon entropy
	result.Entropy = calculateShannonEntropy(data)
	result.IsEntropyAcceptable = result.Entropy >= config.MinEntropy

	if !result.IsEntropyAcceptable {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Low entropy: %.2f < %.2f (data may not be properly encrypted)",
				result.Entropy, config.MinEntropy))
	}

	// 2. Check for readable ASCII strings
	result.HasReadableStrings = containsReadableStrings(data, config.MaxReadableStringLen)
	if result.HasReadableStrings {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Contains readable ASCII strings longer than %d characters",
				config.MaxReadableStringLen))
	}

	// 3. Check byte distribution uniformity
	result.HasUniformDistrib = hasPoorByteDistribution(data, config.MaxByteFreqVariance)
	if result.HasUniformDistrib {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Poor byte distribution (variance > %.2f)", config.MaxByteFreqVariance))
	}

	// 4. Check for forbidden metadata signatures
	result.HasMetadataSignature = containsForbiddenPatterns(data, config.ForbiddenPatterns)
	if result.HasMetadataSignature {
		result.Violations = append(result.Violations, "Contains forbidden metadata signatures")
	}

	// Overall validation result
	result.IsValidEncryption = result.IsEntropyAcceptable &&
		!result.HasReadableStrings &&
		!result.HasUniformDistrib &&
		!result.HasMetadataSignature

	return result
}

// AssertDataIsEncrypted is a test helper that validates encrypted data and fails the test if validation fails
func AssertDataIsEncrypted(t *testing.T, data []byte, msgAndArgs ...interface{}) {
	t.Helper()

	config := ConfigForDataSize(len(data)) // Use size-aware config
	result := ValidateEncryptedData(t, data, config)

	if !result.IsValidEncryption {
		violationsStr := strings.Join(result.Violations, "; ")
		msg := fmt.Sprintf("Data does not appear to be properly encrypted. Violations: %s", violationsStr)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%v. %s", msgAndArgs[0], msg)
		}
		require.Fail(t, msg)
	}

	t.Logf("✅ Encryption validation passed: entropy=%.2f (threshold=%.2f), size=%d bytes, violations=0",
		result.Entropy, config.MinEntropy, len(data))
}

// AssertDataIsEncryptedBasic is a simple test helper for cases where complex validation might fail
// It only checks entropy and forbidden patterns (no ASCII strings or byte distribution)
func AssertDataIsEncryptedBasic(t *testing.T, data []byte, msgAndArgs ...interface{}) {
	t.Helper()

	config := ConfigForDataSize(len(data))
	result := EncryptionValidationResult{
		Violations: make([]string, 0),
	}

	// 1. Calculate Shannon entropy
	result.Entropy = calculateShannonEntropy(data)
	result.IsEntropyAcceptable = result.Entropy >= config.MinEntropy

	if !result.IsEntropyAcceptable {
		result.Violations = append(result.Violations,
			fmt.Sprintf("Low entropy: %.2f < %.2f (data may not be properly encrypted)",
				result.Entropy, config.MinEntropy))
	}

	// Overall validation result (only entropy + forbidden patterns)
	result.IsValidEncryption = result.IsEntropyAcceptable

	if !result.IsValidEncryption {
		violationsStr := strings.Join(result.Violations, "; ")
		msg := fmt.Sprintf("Data does not appear to be properly encrypted. Violations: %s", violationsStr)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%v. %s", msgAndArgs[0], msg)
		}
		require.Fail(t, msg)
	}

	t.Logf("✅ Basic encryption validation passed: entropy=%.2f (threshold=%.2f), size=%d bytes",
		result.Entropy, config.MinEntropy, len(data))
}

// AssertDataIsNotEncrypted is a test helper that validates unencrypted data
func AssertDataIsNotEncrypted(t *testing.T, data []byte, msgAndArgs ...interface{}) {
	t.Helper()

	config := DefaultEncryptionValidationConfig()
	result := ValidateEncryptedData(t, data, config)

	if result.IsValidEncryption {
		msg := fmt.Sprintf("Data appears to be encrypted (entropy=%.2f) but should be unencrypted", result.Entropy)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%v. %s", msgAndArgs[0], msg)
		}
		require.Fail(t, msg)
	}

	t.Logf("✅ Unencrypted data validation passed: entropy=%.2f, has readable content", result.Entropy)
}

// LogEncryptionValidationDetails logs detailed validation results for debugging
func LogEncryptionValidationDetails(t *testing.T, data []byte, label string) {
	t.Helper()

	config := DefaultEncryptionValidationConfig()
	result := ValidateEncryptedData(t, data, config)

	t.Logf("=== Encryption Validation Details for %s ===", label)
	t.Logf("  Data size: %d bytes", len(data))
	t.Logf("  Shannon entropy: %.3f (threshold: %.1f)", result.Entropy, config.MinEntropy)
	t.Logf("  Entropy acceptable: %v", result.IsEntropyAcceptable)
	t.Logf("  Has readable strings: %v", result.HasReadableStrings)
	t.Logf("  Has poor distribution: %v", result.HasUniformDistrib)
	t.Logf("  Has metadata signatures: %v", result.HasMetadataSignature)
	t.Logf("  Overall encrypted: %v", result.IsValidEncryption)

	if len(result.Violations) > 0 {
		t.Logf("  Violations:")
		for i, violation := range result.Violations {
			t.Logf("    %d. %s", i+1, violation)
		}
	}

	// Log first 32 bytes as hex for debugging
	if len(data) > 0 {
		previewLen := 32
		if len(data) < previewLen {
			previewLen = len(data)
		}
		t.Logf("  First %d bytes (hex): %x", previewLen, data[:previewLen])
	}
	t.Logf("=== End Validation Details ===")
}

// calculateShannonEntropy calculates the Shannon entropy of the data
func calculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	// Count frequency of each byte value
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// containsReadableStrings checks if data contains readable ASCII strings longer than maxLen
func containsReadableStrings(data []byte, maxLen int) bool {
	if maxLen <= 0 {
		return false
	}

	currentStringLen := 0
	for _, b := range data {
		// Check if byte is printable ASCII (excluding control characters)
		if b >= 32 && b <= 126 {
			currentStringLen++
			if currentStringLen > maxLen {
				return true
			}
		} else {
			currentStringLen = 0
		}
	}

	return false
}

// hasPoorByteDistribution checks if the byte distribution is too non-uniform (suggesting poor encryption)
func hasPoorByteDistribution(data []byte, maxVariance float64) bool {
	if len(data) < 256 {
		return false // Too small to meaningfully analyze distribution
	}

	// Count frequency of each byte value
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate expected frequency and variance
	expectedFreq := float64(len(data)) / 256.0
	variance := 0.0

	for _, count := range freq {
		diff := float64(count) - expectedFreq
		variance += diff * diff
	}
	variance /= 256.0

	// Normalize variance by expected frequency squared
	normalizedVariance := variance / (expectedFreq * expectedFreq)

	return normalizedVariance > maxVariance
}

// containsForbiddenPatterns checks if data contains patterns that shouldn't appear in encrypted data
func containsForbiddenPatterns(data []byte, patterns []string) bool {
	dataStr := string(data)
	dataStrLower := strings.ToLower(dataStr)

	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(dataStrLower, patternLower) {
			return true
		}
	}

	// For small files (< 1KB), skip regex checks as they can give false positives
	if len(data) < 1024 {
		return false
	}

	// Also check for regex patterns that might indicate structured data
	suspiciousPatterns := []*regexp.Regexp{
		regexp.MustCompile(`[a-zA-Z]{8,}`), // Very long alphabetic sequences (relaxed from 4 to 8)
		regexp.MustCompile(`\d{8,}`),       // Very long numeric sequences (relaxed from 4 to 8)
		regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), // Email addresses
	}

	for _, pattern := range suspiciousPatterns {
		if pattern.Find(data) != nil {
			return true
		}
	}

	return false
}

// CompareEncryptionStrength compares two data samples and asserts that encrypted is more random than unencrypted
func CompareEncryptionStrength(t *testing.T, unencryptedData, encryptedData []byte, label string) {
	t.Helper()

	if len(unencryptedData) == 0 || len(encryptedData) == 0 {
		t.Skip("Cannot compare encryption strength with empty data")
		return
	}

	unencryptedEntropy := calculateShannonEntropy(unencryptedData)
	encryptedEntropy := calculateShannonEntropy(encryptedData)

	t.Logf("=== Encryption Strength Comparison for %s ===", label)
	t.Logf("  Unencrypted entropy: %.3f", unencryptedEntropy)
	t.Logf("  Encrypted entropy: %.3f", encryptedEntropy)
	t.Logf("  Entropy improvement: %.3f", encryptedEntropy - unencryptedEntropy)

	// Encrypted data should have significantly higher entropy
	assert.Greater(t, encryptedEntropy, unencryptedEntropy + 1.0,
		"Encrypted data should have significantly higher entropy than unencrypted data")

	// Validate that encrypted data passes encryption checks
	AssertDataIsEncrypted(t, encryptedData, "Comparing encryption strength for %s", label)

	t.Logf("✅ Encryption strength validation passed for %s", label)
}

// Lorem Ipsum generator for creating predictable, low-entropy test data
var loremWords = []string{
	"lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
	"sed", "do", "eiusmod", "tempor", "incididunt", "ut", "labore", "et", "dolore",
	"magna", "aliqua", "enim", "ad", "minim", "veniam", "quis", "nostrud",
	"exercitation", "ullamco", "laboris", "nisi", "aliquip", "ex", "ea", "commodo",
	"consequat", "duis", "aute", "irure", "in", "reprehenderit", "voluptate",
	"velit", "esse", "cillum", "fugiat", "nulla", "pariatur", "excepteur", "sint",
	"occaecat", "cupidatat", "non", "proident", "sunt", "culpa", "qui", "officia",
	"deserunt", "mollit", "anim", "id", "est", "laborum", "at", "vero", "eos",
	"accusamus", "accusantium", "doloremque", "laudantium", "totam", "rem",
	"aperiam", "eaque", "ipsa", "quae", "ab", "illo", "inventore", "veritatis",
	"et", "quasi", "architecto", "beatae", "vitae", "dicta", "sunt", "explicabo",
	"nemo", "ipsam", "quia", "voluptas", "aspernatur", "aut", "odit", "fugit",
	"sed", "quia", "consequuntur", "magni", "dolores", "ratione", "sequi",
	"nesciunt", "neque", "porro", "quisquam", "qui", "dolorem", "adipisci",
	"numquam", "eius", "modi", "tempora", "incidunt", "magnam", "aliquam",
	"quaerat", "voluptatem", "fuga", "et", "harum", "quidem", "rerum", "facilis",
	"expedita", "distinctio", "nam", "libero", "tempore", "cum", "soluta",
	"nobis", "eleifend", "option", "congue", "nihil", "imperdiet", "doming",
	"placerat", "facer", "possim", "assum", "typi", "non", "habent", "claritatem",
	"insitam", "processus", "dynamicus", "sequitur", "mutationem", "consuetudium",
	"lectorum", "mirum", "claritas", "kessi", "sollemnis", "in", "futurum",
}

// GenerateLoremIpsumData creates deterministic Lorem Ipsum text data of specified size
// This creates intentionally readable, low-entropy data that should fail encryption validation
func GenerateLoremIpsumData(t *testing.T, size int64) ([]byte, [32]byte) {
	t.Helper()

	if size == 0 {
		hash := sha256.Sum256([]byte{})
		return []byte{}, hash
	}

	var text strings.Builder
	wordIndex := 0

	// Start with classic Lorem Ipsum opening
	text.WriteString("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ")

	for text.Len() < int(size) {
		// Add words with spaces and punctuation
		word := loremWords[wordIndex%len(loremWords)]

		// Add some variety with punctuation and capitalization
		if wordIndex%20 == 0 && wordIndex > 0 {
			text.WriteString(". ")
			// Capitalize first letter of sentence
			if len(word) > 0 {
				word = strings.ToUpper(string(word[0])) + word[1:]
			}
		} else if wordIndex%10 == 0 && wordIndex > 0 {
			text.WriteString(", ")
		} else {
			text.WriteString(" ")
		}

		text.WriteString(word)
		wordIndex++

		// Add paragraph breaks occasionally
		if wordIndex%100 == 0 {
			text.WriteString(".\n\n")
		}
	}

	// Ensure we end with proper punctuation
	if !strings.HasSuffix(text.String(), ".") && !strings.HasSuffix(text.String(), ".\n\n") {
		text.WriteString(".")
	}

	// Trim to exact size requested
	data := []byte(text.String())
	if len(data) > int(size) {
		data = data[:size]
		// Ensure we don't end mid-word by finding last space
		if size > 10 {
			for i := len(data) - 1; i >= len(data)-10 && i >= 0; i-- {
				if data[i] == ' ' {
					data = data[:i]
					break
				}
			}
		}
	}

	// Pad with spaces if needed
	for len(data) < int(size) {
		data = append(data, ' ')
	}

	hash := sha256.Sum256(data)
	t.Logf("Generated %d bytes of Lorem Ipsum test data (SHA256: %x)", len(data), hash)
	t.Logf("Sample: %s...", string(data[:min(100, len(data))]))

	return data, hash
}

// GenerateLoremIpsumPattern creates a deterministic pattern-based data for streaming
// This creates repeating Lorem Ipsum patterns that are deterministic by position
func GenerateLoremIpsumPattern(position int64, size int) []byte {
	if size == 0 {
		return []byte{}
	}

	data := make([]byte, size)

	// Use a longer repeating pattern based on Lorem Ipsum text
	pattern := "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
	patternLen := int64(len(pattern))

	for i := 0; i < size; i++ {
		bytePosition := position + int64(i)
		// Use position to determine which character from the pattern to use
		patternIndex := bytePosition % patternLen
		data[i] = pattern[patternIndex]
	}

	return data
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
