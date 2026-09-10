//go:build perf

package perf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// altProxyEnv names a second proxy endpoint configured with
// `integrity_verification: off`. With it set, the same object size routes onto
// the streaming write path instead of auto-multipart, which is what separates
// the pipeline's cost from the cipher's.
//
//	sed 's/integrity_verification: "strict"/integrity_verification: "off"/' \
//	    config/aes-example.yaml > /tmp/aes-nohmac.yaml
//	docker run -d --name proxy-nohmac \
//	    --network s3-encryption-proxy_s3-demo -p 8090:8080 \
//	    -e S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" \
//	    -v /tmp/aes-nohmac.yaml:/etc/s3ep/config.yaml:ro \
//	    -v "$PWD/test/ssl-setup:/certs:ro" \
//	    s3-encryption-proxy-s3-encryption-proxy \
//	    ./s3-encryption-proxy --config /etc/s3ep/config.yaml
//	S3EP_PERF_ALT_PROXY=http://127.0.0.1:8090 make perf-baseline
const altProxyEnv = "S3EP_PERF_ALT_PROXY"

// uploadPathSizes stay at or below what a single PutObject can carry: the
// backend refuses an aws-chunked chunk above 16 MiB, and switching a leg to a
// multipart uploader would change the very thing under test.
var uploadPathSizes = []int64{8 << 20, 12 << 20, 16 << 20}

// TestUploadPathComparison separates the cost of the auto-multipart pipeline
// from the cost of the cipher. Three legs write the same object with the same
// client call: the backend directly, a proxy on the streaming write path, and a
// proxy on the auto-multipart path.
//
// It is the instrument that falsified the self-copy hypothesis: the streaming
// proxy is faster than the backend it writes to, so neither the extra hop nor
// the cipher is what the auto-multipart ratio pays for.
func TestUploadPathComparison(t *testing.T) {
	if !stackReady {
		SetStatus("uploadpath", "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}
	alt := os.Getenv(altProxyEnv)
	if alt == "" {
		SetStatus("uploadpath", "skipped",
			"set "+altProxyEnv+" to a proxy with integrity_verification off; see the comment on altProxyEnv")
		t.Skip(altProxyEnv + " is not set")
	}

	ctx := context.Background()
	type namedLeg struct {
		subject  string
		endpoint string
		key      string
		secret   string
	}
	legs := []namedLeg{
		{"direct", minioEndpoint, minioAccessKey, minioSecretKey},
		{"proxy-streaming", alt, proxyAccessKey, proxySecretKey},
		{"proxy", proxyHTTPEndpoint, proxyAccessKey, proxySecretKey},
	}

	clients := make([]*s3.Client, len(legs))
	for i, l := range legs {
		c, err := newS3Client(l.endpoint, l.key, l.secret, 8)
		if err != nil {
			SetStatus("uploadpath", "blocked", err.Error())
			t.Fatalf("%s client: %v", l.subject, err)
		}
		clients[i] = c
		bucket := "perf-uploadpath-" + l.subject
		if err := ensureBucket(ctx, c, bucket); err != nil {
			SetStatus("uploadpath", "blocked", err.Error())
			t.Fatalf("%s bucket: %v", l.subject, err)
		}
		if err := emptyBucket(ctx, c, bucket); err != nil {
			t.Fatalf("%s pre-clean: %v", l.subject, err)
		}
	}
	defer func() {
		for i, l := range legs {
			if err := emptyBucket(context.Background(), clients[i], "perf-uploadpath-"+l.subject); err != nil {
				t.Logf("%s cleanup: %v", l.subject, err)
			}
		}
	}()

	for _, size := range uploadPathSizes {
		payload := make([]byte, size)
		mib := float64(size) / (1024 * 1024)
		samples := make([][]float64, len(legs))

		for rep := 0; rep <= Reps(); rep++ {
			// Alternate the leg order so a drifting machine cannot favour one.
			order := make([]int, len(legs))
			for i := range order {
				order[i] = i
			}
			if rep%2 == 1 {
				for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
					order[i], order[j] = order[j], order[i]
				}
			}
			for _, i := range order {
				key := fmt.Sprintf("uploadpath/%d/r%d.bin", size, rep)
				start := time.Now()
				_, err := clients[i].PutObject(ctx, &s3.PutObjectInput{
					Bucket:        aws.String("perf-uploadpath-" + legs[i].subject),
					Key:           aws.String(key),
					Body:          bytes.NewReader(payload),
					ContentLength: aws.Int64(size),
				})
				if err != nil {
					t.Errorf("%s put %s: %v", legs[i].subject, humanBytes(size), err)
					continue
				}
				if rep == 0 {
					continue // warm-up
				}
				samples[i] = append(samples[i], mib/time.Since(start).Seconds())
			}
		}

		for i, l := range legs {
			note := "single PutObject; the auto-multipart write path"
			switch l.subject {
			case "direct":
				note = "single PutObject straight to the backend"
			case "proxy-streaming":
				note = "single PutObject through a proxy with integrity verification off, " +
					"which routes this size onto the streaming write path"
			}
			Record(Measurement{
				Instrument: "uploadpath", Transport: "http", Operation: "upload",
				Subject: l.subject, SizeBytes: size, Unit: "MiB/s",
				Samples: samples[i], Note: note,
			})
		}
		t.Logf("%s: direct %.1f | streaming %.1f | auto-multipart %.1f MiB/s",
			humanBytes(size), median(samples[0]), median(samples[1]), median(samples[2]))
	}

	SetStatus("uploadpath", "ok", "")
}
