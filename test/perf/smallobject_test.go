//go:build perf

package perf

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// smallObjectSizes stay far below the segment size: what this instrument
// measures is per-request cost, not bandwidth (ADR 0020 D17).
var smallObjectSizes = []int64{1024, 16 * 1024, 64 * 1024}

var smallObjectConcurrency = []int{1, 8, 32}

// smallObjectOps keeps one batch long enough to average out per-request jitter
// and short enough that the whole matrix stays a local instrument.
func smallObjectOps(concurrency int) int {
	if concurrency == 1 {
		return 300
	}
	return 800
}

// TestSmallObjectRate measures the small-object request rate of the proxy leg
// against the direct backend leg, on both transports and at three concurrency
// levels. The concurrency is part of the operation name because the report
// pairs proxy with direct on (transport, operation, size).
func TestSmallObjectRate(t *testing.T) {
	const instrument = "smallobject"

	if !stackReady {
		SetStatus(instrument, "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}

	ctx := context.Background()
	for _, transport := range []string{"http", "tls"} {
		for _, conc := range smallObjectConcurrency {
			legs, err := legsFor(transport, conc)
			if err != nil {
				t.Fatalf("%s legs: %v", transport, err)
			}
			for _, l := range legs {
				if err := ensureBucket(ctx, l.client, l.bucket); err != nil {
					t.Fatalf("bucket %s: %v", l.bucket, err)
				}
				if err := emptyBucket(ctx, l.client, l.bucket); err != nil {
					t.Fatalf("clean %s: %v", l.bucket, err)
				}
			}

			for _, size := range smallObjectSizes {
				payload := make([]byte, size)
				if _, err := rand.Read(payload); err != nil {
					t.Fatalf("payload: %v", err)
				}
				keys := smallObjectKeys(transport, conc, size, smallObjectOps(conc))

				putRates := map[string][]float64{}
				getRates := map[string][]float64{}

				// Repetition 0 is the discarded warm-up; the leg order alternates
				// with the repetition index (ADR 0020 D7).
				for rep := 0; rep <= Reps(); rep++ {
					for _, l := range smallObjectLegOrder(legs, rep) {
						rate := smallObjectBatch(ctx, t, l, keys, payload, conc, "put")
						if rep > 0 && rate > 0 {
							putRates[l.subject] = append(putRates[l.subject], rate)
						}
					}
				}

				// The read set is written once, untimed, so the GET phase does not
				// depend on what the PUT phase left behind.
				for _, l := range legs {
					smallObjectBatch(ctx, t, l, keys, payload, conc, "put")
				}
				for rep := 0; rep <= Reps(); rep++ {
					for _, l := range smallObjectLegOrder(legs, rep) {
						rate := smallObjectBatch(ctx, t, l, keys, payload, conc, "get")
						if rep > 0 && rate > 0 {
							getRates[l.subject] = append(getRates[l.subject], rate)
						}
					}
				}

				note := fmt.Sprintf("%d objects across %d goroutines", len(keys), conc)
				for _, l := range legs {
					Record(Measurement{
						Instrument: instrument, Transport: transport,
						Operation: fmt.Sprintf("put_rate_c%d", conc),
						Subject:   l.subject, SizeBytes: size, Unit: "ops/s",
						Samples: putRates[l.subject], Note: note,
					})
					Record(Measurement{
						Instrument: instrument, Transport: transport,
						Operation: fmt.Sprintf("get_rate_c%d", conc),
						Subject:   l.subject, SizeBytes: size, Unit: "ops/s",
						Samples: getRates[l.subject], Note: note,
					})
				}
				t.Logf("%s %s c%d: put %.0f/%.0f ops/s, get %.0f/%.0f ops/s (proxy/direct)",
					transport, humanBytes(size), conc,
					median(putRates["proxy"]), median(putRates["direct"]),
					median(getRates["proxy"]), median(getRates["direct"]))
			}

			for _, l := range legs {
				if err := emptyBucket(ctx, l.client, l.bucket); err != nil {
					t.Errorf("clean %s: %v", l.bucket, err)
				}
			}
		}
	}

	SetStatus(instrument, "ok", "")
}

// smallObjectLegOrder returns the legs proxy-first on even repetitions and
// direct-first on odd ones, so a drifting backend cannot favour one leg.
func smallObjectLegOrder(legs []leg, rep int) []leg {
	if rep%2 == 0 || len(legs) < 2 {
		return legs
	}
	return []leg{legs[1], legs[0]}
}

func smallObjectKeys(transport string, conc int, size int64, n int) []string {
	keys := make([]string, n)
	for i := range keys {
		keys[i] = fmt.Sprintf("small/%s/c%d/%d/%05d", transport, conc, size, i)
	}
	return keys
}

// smallObjectBatch runs every key once, spread over conc goroutines by stride so
// each goroutine owns a disjoint key set, and returns the achieved ops/s.
func smallObjectBatch(ctx context.Context, t *testing.T, l leg, keys []string, payload []byte, conc int, op string) float64 {
	t.Helper()

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		failed  int
		firstEr error
	)

	start := time.Now()
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := worker; i < len(keys); i += conc {
				var err error
				if op == "get" {
					err = smallObjectGet(ctx, l, keys[i])
				} else {
					err = smallObjectPut(ctx, l, keys[i], payload)
				}
				if err != nil {
					mu.Lock()
					failed++
					if firstEr == nil {
						firstEr = err
					}
					mu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()

	if failed > 0 {
		t.Errorf("%s %s %s c%d: %d of %d operations failed, first: %v",
			l.subject, l.transport, op, conc, failed, len(keys), firstEr)
		return 0
	}
	if elapsed <= 0 {
		return 0
	}
	return float64(len(keys)) / elapsed
}

func smallObjectPut(ctx context.Context, l leg, key string, payload []byte) error {
	_, err := l.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(payload),
	})
	return err
}

func smallObjectGet(ctx context.Context, l leg, key string) error {
	out, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer func() { _ = out.Body.Close() }()
	_, err = io.Copy(io.Discard, out.Body)
	return err
}
