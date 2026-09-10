//go:build perf

package perf

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	// One source object per leg, uploaded once and never timed. Large enough
	// that a tail range is far past anything the backend read ahead for the
	// preceding cases.
	rangeSourceSize = 128 * 1024 * 1024
	rangeMidOffset  = rangeSourceSize / 2

	rangeSourceKey = "rangeread-source.bin"
)

// rangeCase is one offset kind at one range length. The unaligned offset is
// deliberately not a multiple of 64 KiB: the segmented format has to decrypt a
// partial leading segment for exactly this case (ADR 0003).
type rangeCase struct {
	operation string
	offset    int64
	length    int64
}

func rangeCases() []rangeCase {
	var cases []rangeCase
	for _, n := range []int64{64 * 1024, 1024 * 1024, 8 * 1024 * 1024} {
		cases = append(cases,
			rangeCase{"range_start", 0, n},
			rangeCase{"range_mid_aligned", rangeMidOffset, n},
			rangeCase{"range_mid_unaligned", rangeMidOffset + 4097, n},
			rangeCase{"range_tail", rangeSourceSize - n, n},
		)
	}
	return cases
}

// TestRangeRead measures ranged GET throughput of the proxy against the direct
// backend on both transports. It has to exist before the storage format change,
// with its direct leg, or the change has nothing to be compared against
// (ADR 0020 D17).
func TestRangeRead(t *testing.T) {
	if !stackReady {
		SetStatus("rangeread", "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}

	fail := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		SetStatus("rangeread", "blocked", msg)
		t.Fatal(msg)
	}

	ctx := context.Background()
	payload := make([]byte, rangeSourceSize)
	if _, err := rand.Read(payload); err != nil {
		fail("source payload: %v", err)
	}

	cases := rangeCases()

	for _, transport := range []string{"http", "tls"} {
		legs, err := legsFor(transport, 4)
		if err != nil {
			fail("%s legs: %v", transport, err)
		}

		for _, l := range legs {
			if err := ensureBucket(ctx, l.client, l.bucket); err != nil {
				fail("%s %s bucket: %v", transport, l.subject, err)
			}
			if err := emptyBucket(ctx, l.client, l.bucket); err != nil {
				fail("%s %s pre-clean: %v", transport, l.subject, err)
			}
			// A single PutObject of the source is rejected by the backend
			// ("chunk too big: choose chunk size <= 16MiB"), so the untimed
			// source upload goes through a multipart uploader. It is setup, not
			// a measured path.
			uploader := manager.NewUploader(l.client, func(u *manager.Uploader) {
				u.PartSize = 16 * 1024 * 1024
				u.Concurrency = 4
			})
			if _, err := uploader.Upload(ctx, &s3.PutObjectInput{
				Bucket: aws.String(l.bucket),
				Key:    aws.String(rangeSourceKey),
				Body:   bytes.NewReader(payload),
			}); err != nil {
				fail("%s %s upload source: %v", transport, l.subject, err)
			}
		}

		samples := make([][][]float64, len(legs))
		for i := range samples {
			samples[i] = make([][]float64, len(cases))
		}

		// Repetition 0 is the discarded warm-up; the order flips per repetition
		// so a drifting machine cannot favour one leg (ADR 0020 D7).
		for rep := 0; rep <= Reps(); rep++ {
			order := make([]int, 0, len(legs))
			for i := range legs {
				order = append(order, i)
			}
			if rep%2 == 1 {
				for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
					order[i], order[j] = order[j], order[i]
				}
			}
			for _, li := range order {
				for ci, c := range cases {
					mibps, err := timeRangeGet(ctx, legs[li], c)
					if err != nil {
						t.Errorf("%s %s %s at offset %d: %v", transport, legs[li].subject, c.operation, c.offset, err)
						continue
					}
					if rep == 0 {
						continue
					}
					samples[li][ci] = append(samples[li][ci], mibps)
				}
			}
		}

		for li, l := range legs {
			for ci, c := range cases {
				Record(Measurement{
					Instrument: "rangeread", Transport: transport, Operation: c.operation,
					Subject: l.subject, SizeBytes: c.length, Unit: "MiB/s",
					Samples: samples[li][ci], Note: rangeNote(l.subject),
				})
			}
			t.Logf("%s %s: %d range cases from a %s object recorded",
				transport, l.subject, len(cases), humanBytes(rangeSourceSize))
			if err := emptyBucket(ctx, l.client, l.bucket); err != nil {
				t.Errorf("%s %s post-clean: %v", transport, l.subject, err)
			}
		}
	}

	SetStatus("rangeread", "ok", "")
}

func timeRangeGet(ctx context.Context, l leg, c rangeCase) (float64, error) {
	start := time.Now()
	out, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(rangeSourceKey),
		Range:  aws.String(fmt.Sprintf("bytes=%d-%d", c.offset, c.offset+c.length-1)),
	})
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(io.Discard, out.Body)
	elapsed := time.Since(start).Seconds()
	_ = out.Body.Close()
	if copyErr != nil {
		return 0, copyErr
	}
	if n != c.length {
		return 0, fmt.Errorf("returned %d bytes, want %d", n, c.length)
	}
	if elapsed <= 0 {
		return 0, fmt.Errorf("elapsed time below clock resolution")
	}
	return float64(c.length) / (1024 * 1024) / elapsed, nil
}

func rangeNote(subject string) string {
	if subject == "proxy" {
		return "AES-CTR ranged decryption, not HMAC-verified on this path"
	}
	return "backend range read, no decryption"
}
