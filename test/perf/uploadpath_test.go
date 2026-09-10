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

// altProxyEnv names a second proxy whose optimizations.streaming_segment_size
// is above every size measured here. With it, the same object that the demo
// proxy routes onto the multipart producer is written by the alternate proxy in
// one request, which is what separates the pipeline's cost from the cipher's.
//
//	sed 's/streaming_segment_size: 12582912/streaming_segment_size: 5368709120/' \
//	    config/aes-example.yaml > /tmp/aes-onepart.yaml
//	docker run -d --name proxy-onepart \
//	    --network s3-encryption-proxy_s3-demo -p 8090:8080 \
//	    -e S3EP_LICENSE_TOKEN="$(cat config/license.jwt)" \
//	    -v /tmp/aes-onepart.yaml:/etc/s3ep/config.yaml:ro \
//	    s3-encryption-proxy-s3-encryption-proxy \
//	    ./s3-encryption-proxy --config /etc/s3ep/config.yaml
//	S3EP_PERF_ALT_PROXY=http://127.0.0.1:8090 make perf-baseline
const altProxyEnv = "S3EP_PERF_ALT_PROXY"

// maxDirectSinglePut is where the direct leg stops: the backend refuses an
// aws-chunked chunk above 16 MiB, and switching that leg to a multipart
// uploader would change the very thing under test.
const maxDirectSinglePut = 16 << 20

// uploadPathSizes carry all three legs. 16 MiB is the only size that can: it is
// above the demo proxy's 12 MiB segment size, so the two proxy legs take
// different write paths, and not above what the direct leg can send in one
// request.
var uploadPathSizes = []int64{16 << 20}

// uploadPathProxySizes drop the direct leg and compare the two proxy write
// paths with each other. Both proxies re-frame towards the backend, so a single
// PutObject of these sizes succeeds where the direct leg cannot reach — which
// is what makes the two write paths comparable above 16 MiB at all. This is the
// range the multipart producer is judged on.
var uploadPathProxySizes = []int64{24 << 20, 64 << 20, 256 << 20}

// TestUploadPathComparison separates the cost of the multipart producer from
// the cost of the cipher. Three legs write the same object with the same client
// call: the backend directly, a proxy that takes the single-request write path
// at this size, and a proxy that takes the multipart one. Both proxies seal the
// same segment chain, so the cipher is common to them and the difference is the
// pipeline.
func TestUploadPathComparison(t *testing.T) {
	if !stackReady {
		SetStatus("uploadpath", "blocked", "no proxy stack")
		t.Skip("no proxy stack; start it with ./start-demo.sh")
	}
	alt := os.Getenv(altProxyEnv)
	if alt == "" {
		SetStatus("uploadpath", "skipped",
			"set "+altProxyEnv+" to a proxy whose streaming_segment_size is above every size measured here; "+
				"see the comment on altProxyEnv")
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

	sizes := append(append([]int64{}, uploadPathSizes...), uploadPathProxySizes...)
	for _, size := range sizes {
		payload := make([]byte, size)
		mib := float64(size) / (1024 * 1024)
		samples := make([][]float64, len(legs))
		active := make([]int, 0, len(legs))
		for i, l := range legs {
			if l.subject == "direct" && size > maxDirectSinglePut {
				continue
			}
			active = append(active, i)
		}

		for rep := 0; rep <= Reps(); rep++ {
			// Alternate the leg order so a drifting machine cannot favour one.
			order := make([]int, len(active))
			copy(order, active)
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

		for _, i := range active {
			note := "single PutObject; the multipart producer write path"
			switch legs[i].subject {
			case "direct":
				note = "single PutObject straight to the backend"
			case "proxy-streaming":
				note = "single PutObject through a proxy whose segment size is above this object, " +
					"which routes it onto the single-request write path"
			}
			if size > maxDirectSinglePut {
				note += "; no direct leg at this size, the two proxy paths compare with each other only"
			}
			Record(Measurement{
				Instrument: "uploadpath", Transport: "http", Operation: "upload",
				Subject: legs[i].subject, SizeBytes: size, Unit: "MiB/s",
				Samples: samples[i], Note: note,
			})
		}
		if size > maxDirectSinglePut {
			t.Logf("%s: single-request %.1f | multipart %.1f MiB/s (no direct leg)",
				humanBytes(size), median(samples[1]), median(samples[2]))
		} else {
			t.Logf("%s: direct %.1f | single-request %.1f | multipart %.1f MiB/s",
				humanBytes(size), median(samples[0]), median(samples[1]), median(samples[2]))
		}
	}

	SetStatus("uploadpath", "ok", "")
}
