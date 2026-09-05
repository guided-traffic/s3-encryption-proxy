package encryption

import "testing"

func TestComputeCiphertextSize(t *testing.T) {
	tests := []struct {
		name          string
		plaintextSize int64
		algorithm     string
		want          int64
	}{
		{name: "gcm normal", plaintextSize: 1000, algorithm: "aes-gcm", want: 1028},
		{name: "gcm zero plaintext", plaintextSize: 0, algorithm: "aes-gcm", want: 28},
		{name: "ctr normal", plaintextSize: 1000, algorithm: "aes-ctr", want: 1000},
		{name: "ctr zero plaintext", plaintextSize: 0, algorithm: "aes-ctr", want: 0},
		{name: "none normal", plaintextSize: 1000, algorithm: "none", want: 1000},
		{name: "none zero plaintext", plaintextSize: 0, algorithm: "none", want: 0},
		{name: "unknown algorithm", plaintextSize: 1000, algorithm: "chacha20", want: -1},
		{name: "empty algorithm string", plaintextSize: 1000, algorithm: "", want: -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeCiphertextSize(tc.plaintextSize, tc.algorithm)
			if got != tc.want {
				t.Errorf("ComputeCiphertextSize(%d, %q) = %d, want %d", tc.plaintextSize, tc.algorithm, got, tc.want)
			}
		})
	}
}

// ComputePlaintextSize must be the exact inverse of ComputeCiphertextSize:
// ranged reads address plaintext offsets against an object stored as ciphertext,
// so a one-byte disagreement silently truncates or over-reads every range.
func TestComputePlaintextSize_InvertsComputeCiphertextSize(t *testing.T) {
	for _, algorithm := range []string{"aes-gcm", "aes-ctr", "none"} {
		for _, size := range []int64{0, 1, 15, 16, 17, 4096, 5 * 1024 * 1024, 1 << 30} {
			ciphertext := ComputeCiphertextSize(size, algorithm)
			if got := ComputePlaintextSize(ciphertext, algorithm); got != size {
				t.Errorf("%s: round trip of %d gave %d (ciphertext %d)", algorithm, size, got, ciphertext)
			}
		}
	}
}

func TestComputePlaintextSize_EdgeCases(t *testing.T) {
	cases := []struct {
		algorithm  string
		ciphertext int64
		want       int64
	}{
		{"aes-gcm", GCMOverhead, 0},
		{"aes-gcm", GCMOverhead - 1, -1}, // too short to hold nonce and tag
		{"aes-gcm", 0, -1},
		{"aes-ctr", 0, 0},
		{"none", 123, 123},
		{"", 123, 123}, // unencrypted object: no algorithm recorded
		{"chacha20", 123, -1},
	}
	for _, tc := range cases {
		if got := ComputePlaintextSize(tc.ciphertext, tc.algorithm); got != tc.want {
			t.Errorf("ComputePlaintextSize(%d, %q) = %d, want %d",
				tc.ciphertext, tc.algorithm, got, tc.want)
		}
	}
}
