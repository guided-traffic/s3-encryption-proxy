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
