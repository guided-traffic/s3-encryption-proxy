//go:build integration
// +build integration

package integration

const (
	// 2GB file size for large multipart upload/download tests
	LargeFileSize2GB = 2 * 1024 * 1024 * 1024 // 2GB
	// 5MB part size for multipart uploads (minimum allowed by AWS S3)
	MultipartPartSize = 5 * 1024 * 1024 // 5MB
)

// generateDeterministicData creates reproducible test data using a simple PRNG
// This ensures we can verify data integrity without storing the entire 2GB in memory
func generateDeterministicData(size int, seed int64) []byte {
	data := make([]byte, size)

	// Use a simple PRNG for deterministic data generation
	rng := newSimplePRNG(seed)

	// Fill data in chunks to be more memory efficient
	chunkSize := 64 * 1024 // 64KB chunks
	for i := 0; i < size; i += chunkSize {
		end := i + chunkSize
		if end > size {
			end = size
		}

		for j := i; j < end; j++ {
			data[j] = byte(rng.next() & 0xFF)
		}
	}

	return data
}

// simplePRNG is a simple pseudo-random number generator for deterministic test data
type simplePRNG struct {
	state uint64
}

func newSimplePRNG(seed int64) *simplePRNG {
	return &simplePRNG{state: uint64(seed)}
}

func (p *simplePRNG) next() uint64 {
	// Linear congruential generator (simple but deterministic)
	p.state = p.state*1103515245 + 12345
	return p.state
}
