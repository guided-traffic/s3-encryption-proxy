//go:build perf

package perf

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// selfCopySizes are the object sizes the proxy's auto-multipart path produces.
var selfCopySizes = []int64{8 << 20, 32 << 20, 128 << 20}

// TestSelfCopy times the operation the proxy performs after every multipart
// completion: a server-side copy of the object onto itself with
// MetadataDirective=REPLACE, to attach metadata that only exists once the last
// part is encrypted.
//
// This is a profiling harness, not a gate: it has one leg by nature, because the
// operation has no proxy-side counterpart to compare against (ADR 0020 D12). It
// exists to settle whether the second write is what the upload ratio is paying
// for, which the throughput instrument can only infer.
func TestSelfCopy(t *testing.T) {
	if !stackReady {
		SetStatus("selfcopy", "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}

	ctx := context.Background()
	client, err := newS3Client(minioEndpoint, minioAccessKey, minioSecretKey, 8)
	if err != nil {
		SetStatus("selfcopy", "blocked", err.Error())
		t.Fatalf("client: %v", err)
	}
	const bucket = "perf-selfcopy"
	if err := ensureBucket(ctx, client, bucket); err != nil {
		SetStatus("selfcopy", "blocked", err.Error())
		t.Fatalf("bucket: %v", err)
	}
	if err := emptyBucket(ctx, client, bucket); err != nil {
		t.Fatalf("pre-clean: %v", err)
	}
	defer func() {
		if err := emptyBucket(context.Background(), client, bucket); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = 16 << 20
		u.Concurrency = 4
	})

	for _, size := range selfCopySizes {
		payload := make([]byte, size)
		key := fmt.Sprintf("selfcopy/%d.bin", size)
		if _, err := uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(payload),
		}); err != nil {
			t.Errorf("upload %d: %v", size, err)
			continue
		}

		var samples []float64
		mib := float64(size) / (1024 * 1024)
		// One untimed copy first: the object is cold in the backend otherwise.
		if err := selfCopy(ctx, client, bucket, key); err != nil {
			t.Errorf("warm-up copy %d: %v", size, err)
			continue
		}
		for r := 0; r < Reps(); r++ {
			start := time.Now()
			if err := selfCopy(ctx, client, bucket, key); err != nil {
				t.Errorf("copy %d: %v", size, err)
				break
			}
			samples = append(samples, mib/time.Since(start).Seconds())
		}
		Record(Measurement{
			Instrument: "selfcopy", Transport: "n/a", Operation: "self_copy_replace",
			Subject: "backend", SizeBytes: size, Unit: "MiB/s", Samples: samples,
			Note: "server-side CopyObject onto itself with MetadataDirective=REPLACE, " +
				"the operation the proxy runs after every multipart completion",
		})
		t.Logf("self-copy at %s: %.1f MiB/s", humanBytes(size), median(samples))
	}

	SetStatus("selfcopy", "ok", "single-leg profiling harness, not a gate")
}

func selfCopy(ctx context.Context, c *s3.Client, bucket, key string) error {
	_, err := c.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(key),
		CopySource:        aws.String(bucket + "/" + key),
		MetadataDirective: types.MetadataDirectiveReplace,
		Metadata:          map[string]string{"s3ep-probe": "1"},
	})
	return err
}
