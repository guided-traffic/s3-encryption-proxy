//go:build e2e

// Package rclone holds the end-to-end suite that runs the real rclone binary
// against the s3-encryption-proxy on the demo compose stack.
//
// rclone is a named in-scope client (README, ADR 0006 D1) and it is the client
// that verifies what it uploaded. That is why this suite exists: a claim about a
// client rests on a suite that exercises it, not on a probe (ADR 0006 D5 and D7,
// ADR 0019 D1). Scenarios must not be skipped or disabled once merged
// (ADR 0019).
//
// The stack is created by test/e2e/rclone/e2e-up.sh (make e2e-rclone-up), not by
// TestMain.
package rclone

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

// verdicts collects what rclone made of every case; TestMain writes the table.
var verdicts = harness.NewRecorder("rclone")

func TestMain(m *testing.M) {
	code := m.Run()
	if path, err := verdicts.Report(reportDir()); err != nil {
		fmt.Fprintf(os.Stderr, "could not write the verdict table: %v\n", err)
	} else if path != "" {
		fmt.Fprintf(os.Stderr, "\nverdict table: %s\n", path)
	}
	os.Exit(code)
}

// reportDir resolves test-results/ without a *testing.T, which TestMain has not
// got. A failure to locate it is not worth failing the run over: the table is
// evidence, the assertions are the gate.
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

// endpoint is one of the proxy's two listeners. Every case runs over both:
// rclone is on aws-sdk-go-v2 and, like the SDK, frames an upload with the
// unsigned trailer only over HTTPS, so only the TLS endpoint reaches the trailer
// decoder. A case that behaved differently over the two would be the finding.
type endpoint struct {
	name string
	url  string
}

func endpoints(t *testing.T) []endpoint {
	t.Helper()
	e := harness.DemoStack(t)
	return []endpoint{
		{name: "http", url: e.Get(t, "S3EP_HTTP_ENDPOINT")},
		{name: "tls", url: e.Get(t, "S3EP_TLS_ENDPOINT")},
	}
}

// --- the remotes ------------------------------------------------------------

// remote is one entry of the generated rclone configuration. The three variants
// are R2's question: what a user gets with the provider default they
// would pick, and whether rclone's own setting is an answer.
type remote struct {
	name string
	// provider is rclone's s3 provider quirk table entry. It decides, among
	// other things, whether rclone verifies the multipart entity tag.
	provider string
	// multipartETag, when set, overrides the provider default explicitly.
	multipartETag *bool
}

func ptr(b bool) *bool { return &b }

var remotes = []remote{
	{name: "minio", provider: "Minio"},
	{name: "other", provider: "Other"},
	{name: "minio-noetag", provider: "Minio", multipartETag: ptr(false)},
}

// remoteName is the configuration section a case addresses: one per remote per
// endpoint, so a single generated file serves the whole suite.
func remoteName(r remote, ep endpoint) string { return r.name + "-" + ep.name }

// writeConfig renders every remote for every endpoint into a temporary rclone
// configuration and returns its path. Generated rather than committed: it
// carries the demo stack's credentials, and it has to stay in step with
// demo-stack.env.
func writeConfig(t *testing.T) string {
	t.Helper()
	e := harness.DemoStack(t)
	path := filepath.Join(t.TempDir(), "rclone.conf")

	var b strings.Builder
	for _, ep := range endpoints(t) {
		for _, r := range remotes {
			fmt.Fprintf(&b, "[%s]\n", remoteName(r, ep))
			b.WriteString("type = s3\n")
			fmt.Fprintf(&b, "provider = %s\n", r.provider)
			b.WriteString("env_auth = false\n")
			fmt.Fprintf(&b, "access_key_id = %s\n", e.Get(t, "S3EP_ACCESS_KEY"))
			fmt.Fprintf(&b, "secret_access_key = %s\n", e.Get(t, "S3EP_SECRET_KEY"))
			fmt.Fprintf(&b, "endpoint = %s\n", ep.url)
			fmt.Fprintf(&b, "region = %s\n", e.Get(t, "S3EP_REGION"))
			b.WriteString("force_path_style = true\n")
			if r.multipartETag != nil {
				fmt.Fprintf(&b, "use_multipart_etag = %t\n", *r.multipartETag)
			}
			b.WriteString("\n")
		}
	}
	require.NoError(t, os.WriteFile(path, []byte(b.String()), 0o600))
	return path
}

// --- driving the binary -----------------------------------------------------

// suite is the per-test context: the binary, the generated configuration, a
// scratch directory for payloads, and the bucket this test owns.
type suite struct {
	bin    string
	config string
	work   string
	bucket string
}

func newSuite(t *testing.T, ctx context.Context, name string) *suite {
	t.Helper()
	s := &suite{
		bin:    rcloneBin(t),
		config: writeConfig(t),
		work:   t.TempDir(),
		bucket: uniqueBucket(name),
	}
	harness.EnsureBucket(t, ctx, s.bucket)
	return s
}

// run invokes rclone with the flags every case needs and returns what it said.
//
//   - --retries 1 because a retry is not a second opinion here: rclone's
//     multipart failure leaves the object in the bucket, and its second attempt
//     then finds a destination of matching size and modification time and reports
//     success. Observed 2026-09-13: "Attempt 1/3 failed ... Attempt 2/3 succeeded"
//     for an upload whose entity tag never matched.
//   - --ca-cert rather than --no-check-certificate: the proxy certificate is part
//     of what an end-to-end run validates.
//   - --stats 0 and --log-level INFO so the output is the client's decisions and
//     nothing else.
func (s *suite) run(t *testing.T, ctx context.Context, args ...string) harness.Result {
	t.Helper()
	full := append([]string{
		"--config", s.config,
		"--ca-cert", harness.CACert(t),
		"--retries", "1",
		"--stats", "0",
		"--log-level", "INFO",
	}, args...)
	r := harness.Run(ctx, s.bin, full...)
	t.Logf("$ rclone %s\nexit %d\n%s", strings.Join(args, " "), r.ExitCode, r.Combined)
	return r
}

// says returns the client's own words for the verdict table, with the scratch
// directory redacted: rclone prints absolute source paths in its errors.
func (s *suite) says(r harness.Result) string {
	return harness.Redact(pickVerdictLine(r), s.work)
}

// pickVerdictLine lifts rclone's own summary out of its log. rclone repeats a
// failure as a per-file ERROR, an attempt summary and a closing NOTICE; the
// NOTICE is the one sentence a user reads, and its absence means the run was a
// success.
func pickVerdictLine(r harness.Result) string {
	for _, prefix := range []string{"NOTICE:", "ERROR :", "ERROR:"} {
		for _, line := range strings.Split(r.Combined, "\n") {
			if idx := strings.Index(line, prefix); idx >= 0 {
				return strings.TrimSpace(line[idx:])
			}
		}
	}
	for _, line := range strings.Split(r.Combined, "\n") {
		if strings.Contains(line, "INFO  :") {
			return strings.TrimSpace(line[strings.Index(line, "INFO  :"):])
		}
	}
	return r.Combined
}

// outcome maps an exit code to what the client made of the operation. rclone
// exits non-zero on any error it reported, and a checksum refusal is one.
func outcome(r harness.Result) harness.Outcome {
	if r.OK() {
		return harness.Accepts
	}
	return harness.Refuses
}

func rcloneBin(t *testing.T) string {
	t.Helper()
	return harness.Binary(t, "RCLONE_BIN", "test", "e2e", "rclone", "bin", "rclone")
}

// remotePath addresses a bucket, or a key inside it, on one remote.
func (s *suite) remotePath(r remote, ep endpoint, key string) string {
	p := remoteName(r, ep) + ":" + s.bucket
	if key != "" {
		p += "/" + key
	}
	return p
}

// preflight asserts the demo stack is up and the pinned binary is the one under
// test, so a missing stack fails once with a clear message instead of once per
// case with an opaque one.
func preflight(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	t.Cleanup(cancel)

	want := harness.LoadEnv(t, "test", "e2e", "rclone", "versions.env").Get(t, "RCLONE_VERSION")
	v := harness.Run(ctx, rcloneBin(t), "version")
	require.Truef(t, v.OK(), "rclone is not usable:\n%s", v.Combined)
	require.Containsf(t, v.Stdout, want,
		"versions.env pins rclone %s but the binary reports:\n%s", want, v.Stdout)

	// The stack itself: a bucket listing through the proxy proves the listener,
	// the credentials and the backend leg in one call.
	_, err := harness.ProxyClient(t).ListBuckets(ctx, nil)
	require.NoError(t, err,
		"the proxy is not reachable. Run 'make e2e-rclone-up' (or ./start-demo.sh) first.")

	return ctx
}

// TestPreflight fails fast and loudly when the environment is not up.
func TestPreflight(t *testing.T) {
	ctx := preflight(t)

	t.Run("both_endpoints_answer", func(t *testing.T) {
		s := newSuite(t, ctx, "preflight")
		for _, ep := range endpoints(t) {
			r := s.run(t, ctx, "lsd", remoteName(remotes[0], ep)+":")
			require.Truef(t, r.OK(), "rclone cannot list over %s:\n%s", ep.name, r.Combined)
		}
	})

	t.Run("the_backend_is_readable_directly", func(t *testing.T) {
		// Every at-rest assertion in this suite depends on it.
		_, err := harness.BackendClient(t).ListBuckets(ctx, nil)
		require.NoError(t, err, "MinIO is not reachable directly, so nothing can be checked at rest")
	})
}

// uniqueBucket gives every test its own bucket. Lower-cased because a bucket
// name is DNS-shaped and the scenario ids are not: "R2a" would be refused with
// InvalidBucketName before the case under test ever runs.
func uniqueBucket(scenario string) string {
	return strings.ToLower(fmt.Sprintf("e2e-rclone-%s-%d", scenario, time.Now().UnixNano()%1_000_000_000))
}
