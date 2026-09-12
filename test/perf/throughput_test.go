//go:build perf

package perf

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// throughputOpTimeout bounds one PUT or GET. 128 MiB through the proxy on a
// loaded machine is minutes, not seconds.
const throughputOpTimeout = 15 * time.Minute

// throughputConns is the idle-connection budget per leg; a whole-object
// transfer uses one connection, the rest keep setup out of the measurement.
const throughputConns = 8

// throughputSizeSet spans the routing decisions of the write path. Two
// thresholds decide which code the number describes, and they are not the same
// one:
//
//   - 12 MiB, the configured streaming_segment_size, is where the PROXY stops
//     sending one request and drives its own multipart upload;
//   - 16 MiB, singlePutLimit, is where the CLIENT stops sending one PutObject,
//     because the backend refuses a larger aws-chunked chunk.
//
// The set used to jump from 8 MiB to 32 MiB, so every size was either below both
// thresholds or above both: the proxy's own producer — the path a large PUT from
// an ordinary client takes — was never measured, though the comment here said it
// was. 14 MiB is the size that reaches it.
var throughputSizeSet = []int64{
	1 * 1024,
	64 * 1024,
	256 * 1024,
	1 * 1024 * 1024,
	4 * 1024 * 1024,
	5 * 1024 * 1024,
	8 * 1024 * 1024,
	14 * 1024 * 1024,
	32 * 1024 * 1024,
	128 * 1024 * 1024,
}

// TestThroughput measures whole-object upload and download throughput of the
// proxy against the direct backend path, on both transports.
func TestThroughput(t *testing.T) {
	if !stackReady {
		SetStatus("throughput", "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}

	sizes := throughputSizes()
	if len(sizes) == 0 {
		SetStatus("throughput", "skipped", "S3EP_PERF_MAX_SIZE excluded every size")
		t.Skip("S3EP_PERF_MAX_SIZE excluded every size")
	}

	transports := []string{"http", "tls"}
	var failed []string
	for _, transport := range transports {
		for _, size := range sizes {
			if err := measureThroughput(t, transport, size); err != nil {
				failed = append(failed, fmt.Sprintf("%s/%s", transport, humanBytes(size)))
				t.Errorf("throughput %s at %s: %v", transport, humanBytes(size), err)
			}
		}
	}

	reason := ""
	if len(failed) > 0 {
		reason = fmt.Sprintf("%d of %d points failed: %v", len(failed), len(transports)*len(sizes), failed)
	}
	SetStatus("throughput", "ok", reason)
}

// throughputSizes drops everything above S3EP_PERF_MAX_SIZE so a quick run is
// possible without editing the size set.
func throughputSizes() []int64 {
	limit := int64(0)
	if v := os.Getenv("S3EP_PERF_MAX_SIZE"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			limit = n
		}
	}
	var out []int64
	for _, s := range throughputSizeSet {
		if limit > 0 && s > limit {
			continue
		}
		out = append(out, s)
	}
	return out
}

// The backend rejects an aws-chunked chunk above this, which a single
// PutObject of a larger body produces.
const singlePutLimit = 16 * 1024 * 1024

func measureThroughput(t *testing.T, transport string, size int64) error {
	t.Helper()

	legs, err := legsFor(transport, throughputConns)
	if err != nil {
		return fmt.Errorf("legs: %w", err)
	}

	ctx := context.Background()
	for _, l := range legs {
		if err := ensureBucket(ctx, l.client, l.bucket); err != nil {
			return err
		}
		if err := emptyBucket(ctx, l.client, l.bucket); err != nil {
			return fmt.Errorf("empty %s before: %w", l.bucket, err)
		}
	}
	defer func() {
		for _, l := range legs {
			if err := emptyBucket(context.Background(), l.client, l.bucket); err != nil {
				t.Logf("cleanup %s: %v", l.bucket, err)
			}
		}
	}()

	plain := make([]byte, size)
	if _, err := rand.Read(plain); err != nil {
		return fmt.Errorf("plaintext: %w", err)
	}

	// Warm-up: first transfer pays connection setup, bucket metadata and, on the
	// proxy leg, the DEK cache miss. Not timed.
	for _, l := range legs {
		key := fmt.Sprintf("throughput/%d/%s/warmup", size, l.subject)
		if _, err := putTimed(ctx, l, key, plain); err != nil {
			return fmt.Errorf("warm-up put %s: %w", l.subject, err)
		}
		if _, err := getTimed(ctx, l, key, size); err != nil {
			return fmt.Errorf("warm-up get %s: %w", l.subject, err)
		}
	}

	mib := float64(size) / (1024 * 1024)
	upload := map[string][]float64{}
	download := map[string][]float64{}

	for r := 0; r < Reps(); r++ {
		// ADR 0020 D7: alternate the leg order so a drifting backend cannot
		// favour one subject systematically.
		order := legs
		if r%2 == 1 {
			order = []leg{legs[1], legs[0]}
		}
		for _, l := range order {
			key := fmt.Sprintf("throughput/%d/%s/r%d", size, l.subject, r)
			put, err := putTimed(ctx, l, key, plain)
			if err != nil {
				return fmt.Errorf("put %s rep %d: %w", l.subject, r, err)
			}
			get, err := getTimed(ctx, l, key, size)
			if err != nil {
				return fmt.Errorf("get %s rep %d: %w", l.subject, r, err)
			}
			upload[l.subject] = append(upload[l.subject], mib/put.Seconds())
			download[l.subject] = append(download[l.subject], mib/get.Seconds())
		}
	}

	for _, l := range legs {
		Record(Measurement{
			Instrument: "throughput", Transport: transport, Operation: "upload",
			Subject: l.subject, SizeBytes: size, Unit: "MiB/s",
			Samples: upload[l.subject],
			Note:    uploadNote(size),
		})
		Record(Measurement{
			Instrument: "throughput", Transport: transport, Operation: "download",
			Subject: l.subject, SizeBytes: size, Unit: "MiB/s",
			Samples: download[l.subject],
			Note:    "whole-object GetObject drained to io.Discard",
		})
	}
	t.Logf("%s %s: upload proxy %.1f / direct %.1f MiB/s, download proxy %.1f / direct %.1f MiB/s",
		transport, humanBytes(size),
		median(upload["proxy"]), median(upload["direct"]),
		median(download["proxy"]), median(download["direct"]))
	return nil
}

func putTimed(ctx context.Context, l leg, key string, body []byte) (time.Duration, error) {
	opCtx, cancel := context.WithTimeout(ctx, throughputOpTimeout)
	defer cancel()

	start := time.Now()
	if int64(len(body)) > singlePutLimit {
		// The backend refuses an aws-chunked chunk above 16 MiB, which a single
		// PutObject of a large body produces. Both legs therefore switch to the
		// uploader at the same size, so the comparison stays a comparison — and
		// it is what an SDK client does with a large object anyway.
		uploader := manager.NewUploader(l.client, func(u *manager.Uploader) {
			u.PartSize = singlePutLimit
			u.Concurrency = 4
		})
		_, err := uploader.Upload(opCtx, &s3.PutObjectInput{
			Bucket: aws.String(l.bucket),
			Key:    aws.String(key),
			Body:   bytes.NewReader(body),
		})
		return time.Since(start), err
	}
	_, err := l.client.PutObject(opCtx, &s3.PutObjectInput{
		Bucket:        aws.String(l.bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
	})
	return time.Since(start), err
}

// uploadNote says which client method produced the number, because the two are
// not the same measurement.
func uploadNote(size int64) string {
	if size > singlePutLimit {
		return "multipart upload, 16 MiB parts, 4 in flight"
	}
	if size > throughputProducerFloor {
		return "whole-object PutObject, one connection; the proxy drives its own multipart upload behind it"
	}
	return "whole-object PutObject, one connection"
}

// throughputProducerFloor is the configured streaming_segment_size of the demo
// stack: above it a single PutObject becomes the proxy's internal multipart
// producer (config/aes-example.yaml).
const throughputProducerFloor = 12 * 1024 * 1024

func getTimed(ctx context.Context, l leg, key string, want int64) (time.Duration, error) {
	opCtx, cancel := context.WithTimeout(ctx, throughputOpTimeout)
	defer cancel()

	start := time.Now()
	out, err := l.client.GetObject(opCtx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, out.Body)
	_ = out.Body.Close()
	elapsed := time.Since(start)
	if err != nil {
		return 0, err
	}
	if n != want {
		return 0, fmt.Errorf("short read: got %d bytes, want %d", n, want)
	}
	return elapsed, nil
}
