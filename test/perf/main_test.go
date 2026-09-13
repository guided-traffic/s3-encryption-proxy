//go:build perf

package perf

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	minioEndpoint     = "https://127.0.0.1:9000"
	proxyHTTPEndpoint = "http://127.0.0.1:8080"
	proxyTLSEndpoint  = "https://127.0.0.1:8443"
	proxyMetricsHTTP  = "http://127.0.0.1:9090/metrics"
	proxyMetricsTLS   = "http://127.0.0.1:9091/metrics"
)

// stackReady is set by TestMain; instruments that need the proxy skip without it.
var stackReady bool

func TestMain(m *testing.M) {
	Init()
	stack := detectStack()
	stackReady = stack.Available
	SetStack(stack)

	code := m.Run()

	dir, err := Emit()
	switch {
	case errors.Is(err, ErrNothingMeasured):
		fmt.Println("\nperf: nothing was measured, no run recorded")
	case err != nil:
		fmt.Fprintf(os.Stderr, "perf: writing report failed: %v\n", err)
		os.Exit(1)
	default:
		fmt.Printf("\nperf: report written to %s\n", dir)
	}
	os.Exit(code)
}

func insecureClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // demo stack uses a self-signed CA
		},
	}
}

func reachable(url string) bool {
	resp, err := insecureClient().Get(url)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

func detectStack() StackInfo {
	s := StackInfo{
		Endpoints: map[string]string{
			"minio":      minioEndpoint,
			"proxy_http": proxyHTTPEndpoint,
			"proxy_tls":  proxyTLSEndpoint,
		},
	}

	var missing []string
	if !reachable(minioEndpoint + "/minio/health/live") {
		missing = append(missing, "minio")
	}
	if !reachable(proxyHTTPEndpoint + "/health") {
		missing = append(missing, "proxy(:8080)")
	}
	if !reachable(proxyTLSEndpoint + "/health") {
		missing = append(missing, "proxy-tls(:8443)")
	}
	if len(missing) > 0 {
		s.Available = false
		s.Reason = "unreachable: " + strings.Join(missing, ", ") + " — start it with ./start-demo.sh"
		return s
	}

	s.Available = true
	s.Images = map[string]string{}
	for name, container := range map[string]string{"minio": "minio", "proxy": "proxy", "proxy_tls": "proxy-tls"} {
		if out, err := exec.Command("docker", "inspect", "-f", "{{.Config.Image}}", container).Output(); err == nil {
			s.Images[name] = strings.TrimSpace(string(out))
		}
	}
	s.ProxyConfig = readProxyConfig()
	return s
}

// readProxyConfig lifts the settings that change the numbers out of the demo
// config, so a report says what stack produced it.
func readProxyConfig() map[string]string {
	want := []string{
		"streaming_segment_size",
		"multipart_upload_concurrency",
		"metadata_key_prefix",
	}
	out := map[string]string{}
	b, err := os.ReadFile("../../config/aes-example.yaml")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		for _, k := range want {
			if strings.HasPrefix(t, k+":") {
				v := strings.TrimSpace(strings.TrimPrefix(t, k+":"))
				if i := strings.Index(v, "#"); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
				out[k] = strings.Trim(v, `"`)
			}
		}
	}
	// The active provider type decides which KEK the unwrap numbers describe.
	if strings.Contains(string(b), `type: "aes"`) {
		out["provider_type"] = "aes"
	}
	return out
}
