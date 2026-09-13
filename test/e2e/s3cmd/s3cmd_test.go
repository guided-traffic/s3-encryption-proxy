//go:build e2e

// Package s3cmd holds the end-to-end suite that runs the real s3cmd binary
// against the s3-encryption-proxy on the demo compose stack.
//
// s3cmd is the second client whose verification logic the entity-tag question
// turns on, and it is the one that checks a tag per UPLOADED PART rather than
// per object. A claim about it rests on this suite, not on reported behaviour
// (ADR 0006 D5 and D7, ADR 0019 D1). Scenarios must not be skipped or disabled
// once merged (ADR 0019).
//
// The stack is created by test/e2e/s3cmd/e2e-up.sh (make e2e-s3cmd-up), not by
// TestMain.
package s3cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

var verdicts = harness.NewRecorder("s3cmd")

func TestMain(m *testing.M) {
	code := m.Run()
	if path, err := verdicts.Report(reportDir()); err != nil {
		fmt.Fprintf(os.Stderr, "could not write the verdict table: %v\n", err)
	} else if path != "" {
		fmt.Fprintf(os.Stderr, "\nverdict table: %s\n", path)
	}
	os.Exit(code)
}

func reportDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "test-results"
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return filepath.Join(dir, "test-results")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "test-results"
}

// storedFormat is the contract the at-rest cases assert against. Its two values
// are spelled out in demo-stack.env rather than imported from the product: this
// suite is a black-box client, and a silent change to the metadata prefix or to
// the stored format's identifier has to fail here.
func storedFormat(t *testing.T) harness.Format {
	t.Helper()
	e := harness.DemoStack(t)
	return harness.Format{
		MetadataPrefix: e.Get(t, "S3EP_METADATA_PREFIX"),
		ID:             e.Get(t, "S3EP_FORMAT_ID"),
	}
}

// --- the endpoints ----------------------------------------------------------

// endpoint is one of the proxy's two listeners. s3cmd signs every request with
// the header form and the real payload SHA-256 — it emits no aws-chunked body
// and no trailer — so unlike rclone it exercises the same proxy code on both.
// Both are run anyway: that the two agree is the assertion.
type endpoint struct {
	name  string
	host  string // host:port, no scheme; s3cmd takes the scheme from use_https
	https bool
}

func endpoints(t *testing.T) []endpoint {
	t.Helper()
	e := harness.DemoStack(t)
	return []endpoint{
		{name: "http", host: stripScheme(e.Get(t, "S3EP_HTTP_ENDPOINT")), https: false},
		{name: "tls", host: stripScheme(e.Get(t, "S3EP_TLS_ENDPOINT")), https: true},
	}
}

func stripScheme(url string) string {
	url = strings.TrimPrefix(url, "https://")
	return strings.TrimPrefix(url, "http://")
}

// --- driving the binary -----------------------------------------------------

type suite struct {
	bin    string
	config string
	work   string
	bucket string
	ep     endpoint
}

func newSuite(t *testing.T, ctx context.Context, name string, ep endpoint) *suite {
	t.Helper()
	s := &suite{
		bin:    s3cmdBin(t),
		work:   t.TempDir(),
		bucket: uniqueBucket(name),
		ep:     ep,
	}
	s.config = writeConfig(t, ep)
	harness.EnsureBucket(t, ctx, s.bucket)
	return s
}

// writeConfig renders a .s3cfg for one endpoint.
//
// host_bucket is set to the same value as host_base, which is how s3cmd is told
// to address a bucket in the path: its rule is that virtual-host style applies
// if and only if host_bucket carries the literal %(bucket)s. Upstream's own CI
// configuration against MinIO does exactly this.
//
// bucket_location is spelled out rather than left at its default "US": while the
// cached region for a bucket is still "US", s3cmd fires a GET ?location before
// every signed request, which would put a request class in front of the proxy
// that no user of a configured client sends.
func writeConfig(t *testing.T, ep endpoint) string {
	t.Helper()
	e := harness.DemoStack(t)
	path := filepath.Join(t.TempDir(), "s3cfg")

	var b strings.Builder
	b.WriteString("[default]\n")
	fmt.Fprintf(&b, "access_key = %s\n", e.Get(t, "S3EP_ACCESS_KEY"))
	fmt.Fprintf(&b, "secret_key = %s\n", e.Get(t, "S3EP_SECRET_KEY"))
	fmt.Fprintf(&b, "host_base = %s\n", ep.host)
	fmt.Fprintf(&b, "host_bucket = %s\n", ep.host)
	fmt.Fprintf(&b, "use_https = %s\n", boolWord(ep.https))
	if ep.https {
		fmt.Fprintf(&b, "ca_certs_file = %s\n", harness.CACert(t))
		b.WriteString("check_ssl_certificate = True\n")
		b.WriteString("check_ssl_hostname = True\n")
	}
	b.WriteString("signature_v2 = False\n")
	fmt.Fprintf(&b, "bucket_location = %s\n", e.Get(t, "S3EP_REGION"))
	b.WriteString("enable_multipart = True\n")

	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

func boolWord(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

// run invokes s3cmd with the flags every case needs.
//
//   - --max-retries=1 gives two attempts. Its default of 5 means six uploads of
//     the same file before the verdict, and --max-retries=0 swallows the reason
//     ("Upload failed for: <resource>" and nothing more), which is the one thing
//     these cases are for.
//   - --no-mime-magic because python-magic needs a C library pip does not ship,
//     and its absence is otherwise a warning on every invocation.
//   - --no-progress is already the default off a terminal; it is passed so the
//     output does not change when someone runs the suite from one.
//
// LANG is pinned: s3cmd aborts on a non-UTF-8 locale.
func (s *suite) run(t *testing.T, ctx context.Context, args ...string) harness.Result {
	t.Helper()
	full := append([]string{
		"-c", s.config,
		"--max-retries=1",
		"--no-progress",
		"--no-mime-magic",
	}, args...)
	r := harness.RunWithEnv(ctx, []string{"LANG=C.UTF-8", "LC_ALL=C.UTF-8"}, s.bin, full...)
	t.Logf("$ s3cmd %s\nexit %d\n%s", strings.Join(args, " "), r.ExitCode, r.Combined)
	return r
}

func (s *suite) says(r harness.Result) string {
	return harness.Redact(pickVerdictLine(r), s.work)
}

// pickVerdictLine lifts s3cmd's own summary out of its output. Its ERROR line
// carries the reason; its WARNING lines are the attempts leading up to it.
func pickVerdictLine(r harness.Result) string {
	for _, prefix := range []string{"ERROR: ", "WARNING: ", "upload: ", "download: "} {
		for _, line := range strings.Split(r.Combined, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), prefix) {
				return strings.TrimSpace(line)
			}
		}
	}
	return r.Combined
}

// outcome maps an exit code to what the client made of the operation.
//
// s3cmd's transfer commands do not stop on the first failure: a refused upload
// is EX_PARTIAL (2), not a general error, and the run continues. That is the
// code a refusal produces here; --stop-on-error would make it EX_DATAERR (65).
func outcome(r harness.Result) harness.Outcome {
	if r.OK() {
		return harness.Accepts
	}
	return harness.Refuses
}

func s3cmdBin(t *testing.T) string {
	t.Helper()
	return harness.Binary(t, "S3CMD_BIN", "test", "e2e", "s3cmd", "venv", "bin", "s3cmd")
}

func (s *suite) uri(key string) string {
	if key == "" {
		return "s3://" + s.bucket
	}
	return "s3://" + s.bucket + "/" + key
}

func preflight(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	t.Cleanup(cancel)

	want := harness.LoadEnv(t, "test", "e2e", "s3cmd", "versions.env").Get(t, "S3CMD_VERSION")
	v := harness.RunWithEnv(ctx, []string{"LANG=C.UTF-8"}, s3cmdBin(t), "--version")
	require.Truef(t, v.OK(), "s3cmd is not usable:\n%s", v.Combined)
	require.Containsf(t, v.Stdout, want,
		"versions.env pins s3cmd %s but the binary reports:\n%s", want, v.Stdout)

	_, err := harness.ProxyClient(t).ListBuckets(ctx, nil)
	require.NoError(t, err,
		"the proxy is not reachable. Run 'make e2e-s3cmd-up' (or ./start-demo.sh) first.")

	return ctx
}

func TestPreflight(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name+"/lists_buckets", func(t *testing.T) {
			s := newSuite(t, ctx, "preflight-"+ep.name, ep)
			r := s.run(t, ctx, "ls")
			require.Truef(t, r.OK(), "s3cmd cannot list over %s:\n%s", ep.name, r.Combined)
			require.Contains(t, r.Stdout, s.bucket, "the bucket this test created is not in the listing")
		})
	}

	t.Run("the_backend_is_readable_directly", func(t *testing.T) {
		_, err := harness.BackendClient(t).ListBuckets(ctx, nil)
		require.NoError(t, err, "MinIO is not reachable directly, so nothing can be checked at rest")
	})
}

// uniqueBucket gives every test its own bucket. Lower-cased because a bucket
// name is DNS-shaped and the scenario ids are not: "R2a" would be refused with
// InvalidBucketName before the case under test ever runs.
func uniqueBucket(scenario string) string {
	return strings.ToLower(fmt.Sprintf("e2e-s3cmd-%s-%d", scenario, time.Now().UnixNano()%1_000_000_000))
}
