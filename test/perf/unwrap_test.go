//go:build perf

package perf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// unwrapIterations is the inner loop per repetition; a single AES unwrap is
// hundreds of nanoseconds, far below clock resolution.
const unwrapIterations = 2000

// TestUnwrapMicrobenchmark measures the key-encryption-key operations on the
// read and write path. It needs no stack: the whole point is to isolate the
// unwrap from the transport (ADR 0020 D17).
func TestUnwrapMicrobenchmark(t *testing.T) {
	subjects := map[string]encryption.KeyEncryptor{}

	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("kek: %v", err)
	}
	aesKE, err := keyencryption.NewAESKeyEncryptor(kek)
	if err != nil {
		t.Fatalf("aes kek: %v", err)
	}
	subjects["aes-256"] = aesKE

	for _, bits := range []int{2048, 4096} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("rsa-%d: %v", bits, err)
		}
		p, err := keyencryption.NewRSAProvider(&key.PublicKey, key)
		if err != nil {
			t.Fatalf("rsa-%d provider: %v", bits, err)
		}
		subjects[rsaName(bits)] = p
	}

	ctx := context.Background()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("dek: %v", err)
	}

	for name, ke := range subjects {
		wrapped, keyID, err := ke.EncryptDEK(ctx, dek)
		if err != nil {
			t.Fatalf("%s wrap: %v", name, err)
		}

		iters := unwrapIterations
		if name != "aes-256" {
			// RSA private-key operations are ~1000x slower; keep the run bounded.
			iters = 50
		}

		var wrapSamples, unwrapSamples []float64
		for r := 0; r < Reps(); r++ {
			start := time.Now()
			for i := 0; i < iters; i++ {
				if _, _, err := ke.EncryptDEK(ctx, dek); err != nil {
					t.Fatalf("%s wrap: %v", name, err)
				}
			}
			wrapSamples = append(wrapSamples, float64(time.Since(start).Nanoseconds())/float64(iters))

			start = time.Now()
			for i := 0; i < iters; i++ {
				if _, err := ke.DecryptDEK(ctx, wrapped, keyID); err != nil {
					t.Fatalf("%s unwrap: %v", name, err)
				}
			}
			unwrapSamples = append(unwrapSamples, float64(time.Since(start).Nanoseconds())/float64(iters))
		}

		Record(Measurement{
			Instrument: "unwrap", Transport: "n/a", Operation: "wrap_dek",
			Subject: name, Unit: "ns/op", Samples: wrapSamples,
			Note: "KEK wrap of a 32-byte DEK, in process",
		})
		Record(Measurement{
			Instrument: "unwrap", Transport: "n/a", Operation: "unwrap_dek",
			Subject: name, Unit: "ns/op", Samples: unwrapSamples,
			Note: "KEK unwrap on the read path, in process, no DEK cache",
		})
		t.Logf("%s: wrap %.0f ns/op, unwrap %.0f ns/op",
			name, median(wrapSamples), median(unwrapSamples))
	}

	SetStatus("unwrap", "ok", "")
}

func rsaName(bits int) string {
	switch bits {
	case 2048:
		return "rsa-2048"
	case 4096:
		return "rsa-4096"
	}
	return "rsa"
}

// median is a small helper for log lines; the recorder computes its own.
func median(s []float64) float64 {
	c := append([]float64(nil), s...)
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j] < c[j-1]; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
	if len(c) == 0 {
		return 0
	}
	return c[len(c)/2]
}
