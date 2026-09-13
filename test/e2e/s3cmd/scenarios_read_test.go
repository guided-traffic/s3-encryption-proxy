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

	// The single-part object: s3cmd's put stores it whatever it then reports, so
	// the object it leaves is the one the read cases need. The exit code is not
	// asserted here — that is S1's job, and this is setup.
	s.run(t, ctx, "put", c.singleSrc, s.uri(c.singleKey))
	require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, c.singleKey), 1,
		"the put left no object, so the read cases have nothing to read")

	multi := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", c.multiSrc, s.uri(c.multiKey))
	require.Truef(t, multi.OK(), "could not place the large object:\n%s", multi.Combined)

	return c
}

// TestS3_Get is the read side: what comes back has to be what went in, byte for
// byte, for both objects.
func TestS3_Get(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s3-"+ep.name, ep)
			c := seedCorpus(t, ctx, s)

			ok := true
			var said string
			for _, obj := range []struct{ name, key, src string }{
				{"single_part", c.singleKey, c.singleSrc},
				{"large", c.multiKey, c.multiSrc},
			} {
				out := filepath.Join(s.work, "down", obj.name+".bin")
				r := s.run(t, ctx, "--force", "get", s.uri(obj.key), out)
				if !r.OK() {
					ok = false
					said = s.says(r)
					continue
				}
				require.Equal(t, harness.SHA256File(t, obj.src), harness.SHA256File(t, out),
					"what came back is not what went in for %s", obj.name)
			}

			verdicts.Want(t, harness.Case{
				ID:       "S3",
				Endpoint: ep.name,
				What:     "get both objects and compare by SHA-256",
				Wants:    "serve both objects and let the client verify them",
			}, ok, said)

			t.Run("the_download_verifies", func(t *testing.T) {
				// s3cmd prefers the md5 in its own x-amz-meta-s3cmd-attrs over
				// the entity tag, and the proxy preserves that header. Where it
				// could not verify, the mismatch is a warning and the file is
				// kept — the read leg never loses data over the entity tag.
				out := filepath.Join(s.work, "down", "verify.bin")
				r := s.run(t, ctx, "--force", "get", s.uri(c.singleKey), out)
				require.True(t, r.OK())
				require.NotContains(t, r.Combined, "MD5 signatures do not match",
					"s3cmd could not verify the object from its own attrs header; the proxy dropped it")
			})
		})
	}
}

// TestS5_ReportedDigests: `info` and `ls --list-md5` are two ways of asking the
// same question about the same object. They have to give the same answer, and it
// has to be the object's own digest.
func TestS5_ReportedDigests(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s5-"+ep.name, ep)
			c := seedCorpus(t, ctx, s)
			want := harness.MD5File(t, c.singleSrc)

			info := s.run(t, ctx, "info", s.uri(c.singleKey))
			ls := s.run(t, ctx, "--list-md5", "ls", s.uri("corpus")+"/")
			lsLine := lineFor(ls.Stdout, c.singleKey)

			infoOK := strings.Contains(info.Stdout, want)
			lsOK := strings.Contains(lsLine, want)

			verdicts.Want(t, harness.Case{
				ID:       "S5",
				Endpoint: ep.name,
				What:     "info and ls --list-md5 for the same single-part object",
				Wants: "report the same digest, and that digest is the object's own. `info` HEADs and prefers " +
					"x-amz-meta-s3cmd-attrs; `ls --list-md5` has only the listing's entity tag and falls back " +
					"to the attrs only when that tag carries a hyphen, so the listing answers a digest of the " +
					"STORED bytes and the two commands disagree about one object (ADR 0010 D12)",
			}, infoOK && lsOK,
				"`info` "+reported(infoOK, want)+", `ls --list-md5` said "+oneField(lsLine)+"; the file's md5 is "+want)
		})
	}
}

func reported(ok bool, want string) string {
	if ok {
		return "said " + want
	}
	return "did not report the plaintext md5"
}

// oneField picks the md5 column out of an `ls --list-md5` line.
func oneField(line string) string {
	f := strings.Fields(line)
	if len(f) >= 4 {
		return f[3]
	}
	return "(nothing)"
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
