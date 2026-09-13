//go:build e2e

package s3cmd

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// corpus is what the read cases need. s3cmd cannot place either object through
// its own verification (S1, S2), so both are written through the proxy with the
// SDK, with the x-amz-meta-s3cmd-attrs header s3cmd would have written itself.
// That is the honest way to test the read side of a client whose write side is
// refused: the stored object is exactly what a working s3cmd would have left.
type corpus struct {
	singleSrc string
	singleKey string
	multiSrc  string
	multiKey  string
}

func seedCorpus(t *testing.T, ctx context.Context, s *suite) corpus {
	t.Helper()
	c := corpus{
		singleSrc: harness.WriteRandomFile(t, filepath.Join(s.work, "src"), "small.bin", singlePartSize),
		singleKey: "corpus/small.bin",
		multiSrc:  harness.WriteRandomFile(t, filepath.Join(s.work, "src"), "producer.bin", producerSize),
		multiKey:  "corpus/producer.bin",
	}

	// The single-part object: s3cmd's own put stores it and then reports
	// failure (S1), and the object it leaves is exactly the one this case needs.
	placed := s.run(t, ctx, "put", c.singleSrc, s.uri(c.singleKey))
	require.Falsef(t, placed.OK(), "S1's premise changed: the single-part put succeeded:\n%s", placed.Combined)
	require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, c.singleKey), 1,
		"the refused put left no object, so the read cases have nothing to read")

	// The large object goes up in one request, which the proxy answers with a
	// hyphenated tag, so s3cmd accepts it (S2b).
	multi := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", c.multiSrc, s.uri(c.multiKey))
	require.Truef(t, multi.OK(), "could not place the large object:\n%s", multi.Combined)

	return c
}

// TestS3_Get is the read side: what s3cmd pulls back has to be, byte for byte,
// what went in — including for the object it had just called corrupted.
func TestS3_Get(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s3-"+ep.name, ep)
			c := seedCorpus(t, ctx, s)

			for _, obj := range []struct{ name, key, src string }{
				{"single_part", c.singleKey, c.singleSrc},
				{"large", c.multiKey, c.multiSrc},
			} {
				t.Run(obj.name, func(t *testing.T) {
					out := filepath.Join(s.work, "down", obj.name+".bin")
					r := s.run(t, ctx, "--force", "get", s.uri(obj.key), out)
					require.Truef(t, r.OK(), "the download was refused:\n%s", r.Combined)
					require.Equal(t, harness.SHA256File(t, obj.src), harness.SHA256File(t, out),
						"what came back is not what went in")
				})
			}

			t.Run("a_digest_s3cmd_cannot_verify_is_only_a_warning", func(t *testing.T) {
				// s3cmd prefers the md5 in its own x-amz-meta-s3cmd-attrs over
				// the entity tag, and the proxy preserves that header, so the
				// single-part object verifies. Where it could not, the mismatch
				// is a warning and the file is kept — so unlike the upload leg,
				// the read leg never loses data over the entity tag. That is
				// worth pinning: it is the reason the defect is a write-side
				// defect only.
				out := filepath.Join(s.work, "down", "warn.bin")
				r := s.run(t, ctx, "--force", "get", s.uri(c.singleKey), out)
				require.True(t, r.OK())
				require.NotContains(t, r.Combined, "MD5 signatures do not match",
					"s3cmd could not verify the object from its own attrs header; the proxy dropped it")
			})

			verdicts.Record(t, harness.Case{
				ID:       "S3",
				Endpoint: ep.name,
				What:     "get both objects, SHA-256 against the source",
				Expect:   harness.Accepts,
			}, harness.Accepts, "both objects round-tripped byte-identical")
		})
	}
}

// TestS5_ReportedDigests asks what s3cmd reports as the MD5, and
// where it got it.
//
// The finding is that the two commands disagree with each other. `info` issues a
// HEAD and prefers x-amz-meta-s3cmd-attrs, so it reports the plaintext digest.
// `ls --list-md5` reads the listing, where the entity tag is all there is, and
// only falls back to the attrs when that tag carries a hyphen — which a
// single-request object's does not. So the same object has two different
// "MD5 sum"s depending on which command a user types.
func TestS5_ReportedDigests(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s5-"+ep.name, ep)
			c := seedCorpus(t, ctx, s)
			want := harness.MD5File(t, c.singleSrc)

			info := s.run(t, ctx, "info", s.uri(c.singleKey))
			require.Containsf(t, info.Stdout, want,
				"`info` did not report the plaintext MD5:\n%s", info.Stdout)

			ls := s.run(t, ctx, "--list-md5", "ls", s.uri("corpus")+"/")
			require.Truef(t, ls.OK(), "ls failed:\n%s", ls.Combined)
			storedTag := harness.ProxyETag(t, ctx, s.bucket, c.singleKey)
			require.Containsf(t, ls.Stdout, storedTag,
				"`ls --list-md5` did not report the entity tag for the single-part object:\n%s", ls.Stdout)
			require.NotContainsf(t, lineFor(ls.Stdout, c.singleKey), want,
				"`ls --list-md5` reported the plaintext MD5; the suite assumed it cannot for a bare 32-hex tag")

			verdicts.Record(t, harness.Case{
				ID:       "S5",
				Endpoint: ep.name,
				What:     "info and ls --list-md5 for the same single-part object",
				Expect:   harness.Refuses,
				Defect: "the two commands report different digests for one object: `info` HEADs and prefers " +
					"x-amz-meta-s3cmd-attrs, `ls --list-md5` has only the listing's entity tag and falls back to " +
					"the attrs only when that tag carries a hyphen — so the listing answers a digest of the " +
					"STORED bytes (ADR 0010 D12, ADR 0010 on what a listing may cost)",
			}, harness.Refuses,
				"`info` says "+want+", `ls --list-md5` says "+storedTag+" for the same object")
		})
	}
}

// lineFor returns the output line mentioning key, so an assertion about one
// object does not accidentally match another object's column.
func lineFor(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, key) {
			return line
		}
	}
	return ""
}
