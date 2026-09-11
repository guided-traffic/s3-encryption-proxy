//go:build conformance

// Package conformance asserts what S3 specifies, against a proxy pointed at any
// backend. It exists because MinIO is not S3: the development backend ignores
// headers a real implementation acts on, so a suite that only ever runs against
// MinIO cannot tell a proxy that forwards a header from one that drops it.
//
// The same binary runs twice. `make test-conformance` runs it against the local
// MinIO stack and costs nothing; `make test-conformance-wasabi` runs it against a
// proxy backed by Wasabi and costs money. **The difference between the two runs
// is the finding** — an assertion that passes on Wasabi and fails on MinIO is a
// backend deviation, and the suite names it rather than hiding it behind a skip.
//
// Cost is a first-class constraint here, because the paid backend bills every
// written byte for a minimum of ninety days and deleting the object does not
// refund it. Two mechanisms keep it bounded, and both are code rather than
// convention: a byte budget that fails the run before an oversized write reaches
// the backend (see Budget), and a corpus that is seeded once and then only read
// (see Corpus and SeedBudgetBytes).
package conformance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// Environment. Everything is overridable so one binary serves both backends.
var (
	// ProxyEndpoint is the proxy under test. The suite never talks to the
	// backend through it for writes it has not budgeted.
	ProxyEndpoint = envOr("S3EP_CONFORMANCE_PROXY_ENDPOINT", "http://127.0.0.1:8080")

	// BackendEndpoint is the storage behind the proxy, used only for at-rest
	// assertions: the suite reads the stored object and checks it is ciphertext.
	BackendEndpoint = envOr("S3EP_CONFORMANCE_BACKEND_ENDPOINT", "https://127.0.0.1:9000")

	// BackendRegion is what the backend leg signs with. Wasabi validates it;
	// MinIO does not care.
	BackendRegion = envOr("S3EP_CONFORMANCE_BACKEND_REGION", "us-east-1")

	// Bucket is the one bucket this suite uses. It is never created or deleted
	// by the suite against a paid backend: the operator creates it once.
	Bucket = envOr("S3EP_CONFORMANCE_BUCKET", "conformance")

	// KeyPrefix namespaces the corpus so the bucket can hold other things.
	KeyPrefix = envOr("S3EP_CONFORMANCE_PREFIX", "s3ep-conformance/v1/")

	// BackendName labels the run. It steers nothing: an assertion that depends
	// on which backend is behind the proxy is a deviation this suite exists to
	// report, not to accommodate.
	BackendName = envOr("S3EP_CONFORMANCE_BACKEND_NAME", "minio")
)

// Credentials. The proxy leg uses the shipped example client; the backend leg
// uses whatever reads the raw stored bytes.
var (
	ProxyAccessKey = envOr("S3EP_CONFORMANCE_PROXY_ACCESS_KEY", "username0")
	ProxySecretKey = envOr("S3EP_CONFORMANCE_PROXY_SECRET_KEY", "this-is-not-very-secure")

	BackendAccessKey = envOr("S3EP_CONFORMANCE_BACKEND_ACCESS_KEY", "minioadmin")
	BackendSecretKey = envOr("S3EP_CONFORMANCE_BACKEND_SECRET_KEY", "minioadmin123")
)

// SeedBudgetBytes is the ceiling for a seeding run. The corpus below is about
// 10.3 MiB; the headroom covers the per-object overhead of the segment chain and
// nothing else. It is deliberately not a round large number: raising it is a
// decision someone has to make on purpose, in a pull request, with this comment
// in the diff.
const SeedBudgetBytes int64 = 16 << 20

// IsSeedRun reports whether this process is allowed to write at all. Everything
// outside the seed runs with a zero budget, so a read-only run that starts
// writing fails on the first byte rather than on the invoice.
func IsSeedRun() bool { return os.Getenv("S3EP_CONFORMANCE_SEED") == "1" }

// Budget bounds what one run may write. It reserves before the write rather than
// accounting after it: a budget checked afterwards has already been paid.
type Budget struct {
	limit   int64
	written atomic.Int64
}

// NewBudget returns the budget for this process: the seed ceiling for a seeding
// run, and zero for every other run.
func NewBudget() *Budget {
	if IsSeedRun() {
		return &Budget{limit: SeedBudgetBytes}
	}
	return &Budget{limit: 0}
}

// Authorize reserves n bytes or fails the test. It fails rather than skips: a
// run that silently stopped asserting is worse than one that stops.
func (b *Budget) Authorize(t *testing.T, key string, n int64) {
	t.Helper()
	if n <= 0 {
		return
	}
	total := b.written.Add(n)
	if total > b.limit {
		b.written.Add(-n)
		if b.limit == 0 {
			t.Fatalf("this run may not write: %q asked for %d bytes and the budget is zero. "+
				"Only a seeding run writes (S3EP_CONFORMANCE_SEED=1); every other test reads "+
				"the corpus that is already there.", key, n)
		}
		t.Fatalf("byte budget exhausted: %q asked for %d bytes, %d of %d already reserved. "+
			"The paid backend bills every written byte for ninety days, so this is a hard stop. "+
			"Shrink the payload, or raise SeedBudgetBytes deliberately.",
			key, n, total-n, b.limit)
	}
}

// Spent reports what this run has reserved, for the summary a run prints.
func (b *Budget) Spent() int64 { return b.written.Load() }

// CorpusObject is one seeded object. Size is the plaintext length; the content
// is derived from the key, so a seed is reproducible and a read can verify it by
// SHA-256 without holding a fixture.
type CorpusObject struct {
	Key  string
	Size int64
	Why  string
}

// Corpus is every object this suite needs, and nothing more. Each entry states
// what it unlocks, because the next person to add one has to justify the bytes.
//
// The segment size is the reason most of this is small: the stored format seals
// 64 KiB per segment, so multi-segment behaviour costs kilobytes. The two
// multipart entries are the only expensive ones, and they are expensive for one
// reason — S3 refuses a part below 5 MiB unless it is the object's last.
var Corpus = []CorpusObject{
	{
		Key:  "tiny",
		Size: 1,
		Why:  "one segment, one backend request on read, and the object every header and checksum test reuses",
	},
	{
		Key:  "empty",
		Size: 0,
		Why:  "a zero-length object is a chain of no segments and only a trailer",
	},
	{
		Key:  "seg-exact",
		Size: dataencryption.SegmentSize,
		Why:  "the segment boundary exactly, where an off-by-one in the chain arithmetic shows",
	},
	{
		Key:  "seg-plus-one",
		Size: dataencryption.SegmentSize + 1,
		Why:  "the first size whose whole-object GET costs two backend requests (tail first, then the beginning)",
	},
	{
		Key:  "seg-three",
		Size: 3 * dataencryption.SegmentSize,
		Why:  "a middle segment exists, so a range can start and end inside different segments",
	},
	{
		Key:  "mpu-client",
		Size: 5<<20 + dataencryption.SegmentSize,
		Why:  "client-driven multipart with a real two-part layout: one part at the S3 minimum, one short last part",
	},
	{
		Key:  "mpu-producer",
		Size: 5<<20 + 1,
		Why:  "the proxy's internal producer, which needs streaming_segment_size at its 5 MiB minimum to split here",
	},
}

// ListCorpusSize is how many one-byte objects the listing tests need. They are
// one byte each because a listing asserts names, counts and plaintext sizes, and
// none of that needs content.
const ListCorpusSize = 10

// ListKey is the key of the nth listing object.
func ListKey(n int) string { return fmt.Sprintf("list/%03d", n) }

// Content returns the deterministic body of a corpus object.
//
// It is readable ASCII on purpose, not random bytes: the at-rest assertion
// checks that what the backend stored has high entropy and carries no readable
// strings, and a plaintext that was already random would make that assertion
// pass no matter what the proxy did.
func Content(key string, size int64) []byte {
	if size == 0 {
		return nil
	}
	seed := sha256.Sum256([]byte("s3ep-conformance/" + key))
	line := fmt.Sprintf("s3ep conformance corpus %s %s ", key, hex.EncodeToString(seed[:8]))
	out := make([]byte, 0, size+int64(len(line)))
	for int64(len(out)) < size {
		out = append(out, line...)
	}
	return out[:size]
}

// SHA256 is how this suite compares payloads. Never dump a body.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Key returns the full object key of a corpus entry.
func Key(name string) string { return KeyPrefix + name }

// Context returns a context with the suite's timeout.
func Context(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ProxyClient returns a client bound to the proxy under test.
//
// It signs with us-east-1 whatever the backend's region is: the proxy verifies
// the signature against the region in the client's own credential scope and does
// not compare it to the backend's, so the client leg is independent of where the
// bytes end up.
func ProxyClient(t *testing.T) *s3.Client {
	t.Helper()
	return newClient(t, ProxyEndpoint, ProxyAccessKey, ProxySecretKey, "us-east-1")
}

// BackendClient returns a client bound to the storage behind the proxy. It is
// used only to read stored bytes for the at-rest assertions.
func BackendClient(t *testing.T) *s3.Client {
	t.Helper()
	return newClient(t, BackendEndpoint, BackendAccessKey, BackendSecretKey, BackendRegion)
}

func newClient(t *testing.T, endpoint, access, secret, region string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(access, secret, "")),
		awsconfig.WithRegion(region),
		awsconfig.WithHTTPClient(httpClient()),
	)
	if err != nil {
		t.Fatalf("building an S3 client for %s: %v", endpoint, err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		// Wasabi serves virtual-host style too, but path style is what the local
		// stack needs and what keeps one code path for both.
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenSupported
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenSupported
	})
}

// httpClient trusts the local development certificate when the endpoint is the
// local stack, and nothing extra otherwise. A paid backend is reached over the
// public trust store, and a suite that disabled verification for it would be
// asserting against whatever answered.
func httpClient() *http.Client {
	local := strings.Contains(BackendEndpoint, "127.0.0.1") ||
		strings.Contains(BackendEndpoint, "localhost")
	if !local {
		return &http.Client{Timeout: 5 * time.Minute}
	}
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			// #nosec G402 - the local development backend serves a self-signed
			// certificate; this branch is unreachable for any other endpoint.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
