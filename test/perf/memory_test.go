//go:build perf

package perf

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
)

const (
	// 128 MiB is far above streaming_segment_size, so every large PUT below
	// goes through the multipart producer.
	memoryLargeSize = 128 * 1024 * 1024
	memorySmallSize = 1 * 1024 * 1024
	// Large PUT+GET cycles per repetition. Two is enough to reach the plateau
	// without turning the run into a bandwidth test.
	memoryLargeCycles = 2
	memorySampleEvery = 250 * time.Millisecond

	// docker-compose.demo.yml, service s3-encryption-proxy.
	containerMemoryLimit = 512 * 1024 * 1024

	// The two optimisation keys the demo stack runs with
	// (config/aes-example.yaml): 12 MiB parts, four upload workers. A run
	// against a proxy configured differently has to move these with it.
	memoryStreamingSegmentSize = 12 * 1024 * 1024
	memoryUploadConcurrency    = 4

	// What the producer holds while a large PUT runs: one buffer per worker plus
	// the one being filled (ADR 0024 D4).
	memoryFreeList = int64(memoryStreamingSegmentSize) * (memoryUploadConcurrency + 1)

	// The bound the load has to stay inside. Twice the free list is the
	// collector's headroom: Go returns pages to the operating system lazily, so
	// resident memory follows the live set with a lag. It sits below the object
	// size on purpose — a proxy that buffered one would cross it.
	memoryLoadBound = 2 * memoryFreeList

	profileObjectSize     = 64 * 1024 * 1024
	defaultProfileSeconds = 30
	pprofBase             = "http://127.0.0.1:6060/debug/pprof"
)

// TestProxyMemory records the proxy's resident memory around a load, idle and
// peak (ADR 0020 D14). It records only: the bound is not asserted here.
func TestProxyMemory(t *testing.T) {
	if !stackReady {
		SetStatus("memory", "blocked", "no proxy stack")
		t.Skip("no proxy stack")
	}

	// The stack is up, so anything that fails from here is a failure, not a
	// reason to pass: skipping on an error is how an instrument stops measuring
	// and keeps reporting green (ADR 0019 D4).
	legs, err := legsFor("http", 4)
	if err != nil {
		SetStatus("memory", "failed", err.Error())
		t.Fatalf("clients: %v", err)
	}
	proxy := legs[0]
	proxy.bucket = "perf-memory"

	ctx := context.Background()
	if err := ensureBucket(ctx, proxy.client, proxy.bucket); err != nil {
		SetStatus("memory", "failed", err.Error())
		t.Fatalf("bucket: %v", err)
	}
	if err := emptyBucket(ctx, proxy.client, proxy.bucket); err != nil {
		t.Fatalf("clean before: %v", err)
	}
	defer func() {
		if err := emptyBucket(context.Background(), proxy.client, proxy.bucket); err != nil {
			t.Logf("clean after: %v", err)
		}
	}()

	large, err := randomPayload(memoryLargeSize)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	small, err := randomPayload(memorySmallSize)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	scraper := insecureClient()
	if _, err := scrapeRSS(scraper, proxyMetricsHTTP); err != nil {
		// The metrics endpoint is the instrument. Without it there is no
		// measurement, and saying so is the point (ADR 0020 D20).
		SetStatus("memory", "failed", err.Error())
		t.Fatalf("the monitoring endpoint must answer for the memory instrument: %v", err)
	}

	// The settled numbers below are taken after a warm-up, so they say what a
	// running proxy costs. The cold reading says what it costs to get there,
	// which is the figure a container limit has to cover.
	coldRSS, err := scrapeRSS(scraper, proxyMetricsHTTP)
	if err != nil {
		t.Fatalf("scrape cold: %v", err)
	}
	var coldPeak float64

	var idleSamples, peakSamples, deltaSamples []float64
	// One warm-up repetition is discarded: the first large PUT grows the part
	// buffers that every later repetition then reuses.
	for r := 0; r < Reps()+1; r++ {
		idle, err := scrapeRSS(scraper, proxyMetricsHTTP)
		if err != nil {
			t.Fatalf("scrape idle: %v", err)
		}

		sampler := startRSSSampler(scraper, proxyMetricsHTTP)
		loadErr := driveMemoryLoad(ctx, proxy, large, small)
		peak := sampler.peak()
		if loadErr != nil {
			t.Fatalf("load: %v", loadErr)
		}
		if peak < idle {
			peak = idle
		}
		if r == 0 {
			coldPeak = peak
			continue
		}
		idleSamples = append(idleSamples, idle)
		peakSamples = append(peakSamples, peak)
		deltaSamples = append(deltaSamples, peak-idle)
	}

	// ADR 0020 D14: the bound is a test that fails, not a number in a report.
	// What the load costs has to stay inside what the configuration budgets for
	// it, and above all it must not scale with the object size — MAIN GOAL 3 is
	// streaming, and a proxy that buffered a whole object would show it here.
	delta := median(deltaSamples)
	assert.Less(t, delta, float64(memoryLoadBound),
		"peak-minus-idle is %s, above the %s this configuration budgets: "+
			"%s of part buffers (streaming_segment_size × (1 + multipart_upload_concurrency)) "+
			"and the same again for the collector's headroom (ADR 0020 D14)",
		humanBytes(int64(delta)), humanBytes(memoryLoadBound), humanBytes(memoryFreeList))
	assert.Less(t, delta, float64(memoryLargeSize),
		"what the load costs scales with the object size (%s): the proxy is holding "+
			"objects rather than streaming them (MAIN GOAL 3)", humanBytes(memoryLargeSize))

	const note = "recorded, and bounded by the assertion above"
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_idle", Subject: "proxy",
		Unit: "bytes", Samples: idleSamples,
		Note: "process_resident_memory_bytes before each repetition's load; after the warm-up this is the settled level, not a cold process — " + note,
	})
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_peak", Subject: "proxy",
		Unit: "bytes", Samples: peakSamples,
		Note: fmt.Sprintf("maximum of a %v sample while %d×%s PUT+GET plus %s PUT+GET ran — %s",
			memorySampleEvery, memoryLargeCycles, humanBytes(memoryLargeSize), humanBytes(memorySmallSize), note),
	})
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_peak_minus_idle", Subject: "proxy",
		Unit: "bytes", Samples: deltaSamples,
		Note: "what the load itself costs; the bound of ADR 0020 D14 applies to this figure — " + note,
	})
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_cold", Subject: "proxy",
		Unit: "bytes", Samples: []float64{coldRSS},
		Note: "resident memory before this run touched the proxy — " + note,
	})
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_cold_load_peak", Subject: "proxy",
		Unit: "bytes", Samples: []float64{coldPeak},
		Note: "peak during the first (warm-up) load, i.e. what reaching the settled level costs — " + note,
	})
	Record(Measurement{
		Instrument: "memory", Transport: "http", Operation: "rss_limit", Subject: "proxy",
		Unit: "bytes", Samples: []float64{containerMemoryLimit},
		Note: "container memory limit from docker-compose.demo.yml — " + note,
	})

	t.Logf("rss cold %s, cold-load peak %s, settled idle %s, settled peak %s, delta %s (limit %s)",
		humanBytes(int64(coldRSS)), humanBytes(int64(coldPeak)),
		humanBytes(int64(median(idleSamples))), humanBytes(int64(median(peakSamples))),
		humanBytes(int64(median(deltaSamples))), humanBytes(containerMemoryLimit))

	SetStatus("memory", "ok", "")
}

// TestCPUProfiles captures a CPU and a heap profile of the proxy under load
// (ADR 0020 D17). pprof binds loopback inside the container on purpose (a heap
// profile holds DEKs), so the capture shares the container's network namespace,
// exactly as config/aes-example.yaml documents.
func TestCPUProfiles(t *testing.T) {
	if !stackReady {
		SetStatus("profiles", "blocked", "no proxy stack")
		t.Skip("no proxy stack")
	}

	seconds := profileSeconds()

	// The run directory id only exists at Emit() time, so profiles land in a
	// fixed sibling directory and the measurement carries the path.
	dir := filepath.Join(OutDir(), "profiles-pending")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		SetStatus("profiles", "failed", err.Error())
		t.Fatalf("profile directory: %v", err)
	}
	cpuPath := filepath.Join(dir, "proxy-cpu.pprof")
	heapPath := filepath.Join(dir, "proxy-heap.pprof")

	legs, err := legsFor("http", 4)
	if err != nil {
		SetStatus("profiles", "failed", err.Error())
		t.Fatalf("clients: %v", err)
	}
	proxy := legs[0]
	proxy.bucket = "perf-profiles"

	ctx := context.Background()
	if err := ensureBucket(ctx, proxy.client, proxy.bucket); err != nil {
		SetStatus("profiles", "failed", err.Error())
		t.Fatalf("bucket: %v", err)
	}
	if err := emptyBucket(ctx, proxy.client, proxy.bucket); err != nil {
		t.Fatalf("clean before: %v", err)
	}
	defer func() {
		if err := emptyBucket(context.Background(), proxy.client, proxy.bucket); err != nil {
			t.Logf("clean after: %v", err)
		}
	}()

	payload, err := randomPayload(profileObjectSize)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	loadCtx, stopLoad := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; loadCtx.Err() == nil; i++ {
			key := fmt.Sprintf("profile-load-%d", i%2)
			if err := putGet(loadCtx, proxy, key, payload); err != nil && loadCtx.Err() == nil {
				t.Logf("profile load stopped: %v", err)
				return
			}
		}
	}()

	captureErr := capturePprof(cpuPath, fmt.Sprintf("%s/profile?seconds=%d", pprofBase, seconds),
		time.Duration(seconds)*time.Second+3*time.Minute)
	if captureErr == nil {
		captureErr = capturePprof(heapPath, pprofBase+"/heap", 3*time.Minute)
	}

	stopLoad()
	wg.Wait()

	if captureErr != nil {
		// pprof is off, or bound somewhere this run cannot reach it. That is a
		// configuration this instrument cannot measure, and it says so rather
		// than passing: ADR 0020 D17 lists the profiles as part of the set a
		// rewrite is judged with.
		SetStatus("profiles", "failed", captureErr.Error())
		t.Fatalf("capturing the profiles failed; is monitoring.pprof_enabled set? %v", captureErr)
	}

	Record(Measurement{
		Instrument: "profiles", Transport: "http", Operation: "cpu_profile_seconds", Subject: "proxy",
		Unit: "s", Samples: []float64{float64(seconds)},
		Note: fmt.Sprintf("%s and %s, captured under a %s PUT+GET loop", cpuPath, heapPath, humanBytes(profileObjectSize)),
	})
	t.Logf("profiles written to %s", dir)

	SetStatus("profiles", "ok", "")
}

func profileSeconds() int {
	if v := os.Getenv("S3EP_PERF_PROFILE_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultProfileSeconds
}

// capturePprof pulls one pprof endpoint through a throwaway container that
// shares the proxy's network namespace, since pprof is loopback-only.
func capturePprof(path, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "container:proxy",
		"curlimages/curl", "-s", url, "-o", "-")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker run for %s: %w (%s)", url, err, strings.TrimSpace(stderr.String()))
	}
	if out.Len() == 0 {
		return fmt.Errorf("empty profile from %s (%s)", url, strings.TrimSpace(stderr.String()))
	}
	return os.WriteFile(path, out.Bytes(), 0o644)
}

// scrapeRSS reads process_resident_memory_bytes off a Prometheus endpoint.
func scrapeRSS(c *http.Client, url string) (float64, error) {
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	const key = "process_resident_memory_bytes "
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, key) {
			continue
		}
		return strconv.ParseFloat(strings.TrimSpace(line[len(key):]), 64)
	}
	return 0, fmt.Errorf("process_resident_memory_bytes not exported at %s", url)
}

type rssSampler struct {
	stop chan struct{}
	max  chan float64
}

func startRSSSampler(c *http.Client, url string) *rssSampler {
	s := &rssSampler{stop: make(chan struct{}), max: make(chan float64, 1)}
	go func() {
		ticker := time.NewTicker(memorySampleEvery)
		defer ticker.Stop()
		var peak float64
		for {
			select {
			case <-s.stop:
				s.max <- peak
				return
			case <-ticker.C:
				if v, err := scrapeRSS(c, url); err == nil && v > peak {
					peak = v
				}
			}
		}
	}()
	return s
}

func (s *rssSampler) peak() float64 {
	close(s.stop)
	return <-s.max
}

func driveMemoryLoad(ctx context.Context, l leg, large, small []byte) error {
	for i := 0; i < memoryLargeCycles; i++ {
		if err := putGet(ctx, l, fmt.Sprintf("mem-large-%d", i), large); err != nil {
			return err
		}
	}
	// One object below streaming_segment_size, so the single-request write path
	// is in the sample too.
	return putGet(ctx, l, "mem-small", small)
}

func putGet(ctx context.Context, l leg, key string, payload []byte) error {
	if _, err := l.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(payload),
	}); err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	out, err := l.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(l.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("get %s: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()
	if _, err := io.Copy(io.Discard, out.Body); err != nil {
		return fmt.Errorf("read %s: %w", key, err)
	}
	return nil
}

func randomPayload(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
