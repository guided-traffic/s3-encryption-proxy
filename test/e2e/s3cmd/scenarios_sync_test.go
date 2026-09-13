//go:build e2e

package s3cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestS4_Sync asks what s3cmd treats as changed, and whether an
// entity tag that is not its MD5 re-uploads everything on every run.
//
// s3cmd compares size and MD5 — never a modification time. The remote MD5 comes
// from the listing's entity tag, and s3cmd only issues the HEAD that would read
// its own x-amz-meta-s3cmd-attrs when that tag already carries a hyphen. So for
// a single-request object the comparison is against a digest of the stored bytes
// forever, and every run decides the file has changed.
func TestS4_Sync(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s4-"+ep.name, ep)
			dir := filepath.Join(s.work, "syncsrc")
			src := harness.WriteRandomFile(t, dir, "small.bin", singlePartSize)
			dest := s.uri("s4") + "/"

			t.Run("the_first_run_uploads_and_is_refused", func(t *testing.T) {
				r := s.run(t, ctx, "sync", dir+"/", dest)
				require.Falsef(t, r.OK(), "S1's premise changed: the sync upload succeeded:\n%s", r.Combined)
				require.Contains(t, r.Combined, "MD5 Sums don't match!")
				// Refused and stored, exactly as in S1.
				require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "s4/small.bin"), 1)
			})

			t.Run("every_further_run_uploads_it_again", func(t *testing.T) {
				// The object is already there, unchanged, the same size. A sync
				// that compared size alone would stop here.
				r := s.run(t, ctx, "sync", dir+"/", dest)

				verdicts.Record(t, harness.Case{
					ID:       "S4",
					Endpoint: ep.name,
					What:     "sync the same unchanged 1 MiB file up twice",
					Expect:   harness.Refuses,
					Defect: "the listing's entity tag is a digest of the STORED bytes and carries no hyphen, so " +
						"s3cmd never issues the HEAD that would read its own x-amz-meta-s3cmd-attrs; it compares " +
						"against that tag, decides an unchanged file has changed, re-uploads it on every run, and " +
						"the re-upload is then refused by the same tag (ADR 0010 D12)",
				}, outcome(r), s.says(r))

				require.Contains(t, r.Combined, "MD5 Sums don't match!",
					"the second sync did not even attempt the upload; the suite assumed it re-uploads")
			})

			t.Run("no_check_md5_settles_it_by_comparing_size_alone", func(t *testing.T) {
				// The documented escape, and what it costs: --no-check-md5 drops
				// the digest from the sync comparison AND from the attrs header
				// s3cmd writes, so from then on nothing about the content is
				// compared at either end — a changed file of unchanged length is
				// not transferred.
				r := s.run(t, ctx, "--no-check-md5", "sync", dir+"/", dest)
				require.Truef(t, r.OK(), "--no-check-md5 did not settle the sync:\n%s", r.Combined)
				require.NotContains(t, r.Stdout, "upload:",
					"--no-check-md5 still re-uploaded the unchanged file")

				verdicts.Record(t, harness.Case{
					ID:       "S4b",
					Endpoint: ep.name,
					What:     "sync the same unchanged file with --no-check-md5",
					Expect:   harness.Accepts,
				}, harness.Accepts,
					"nothing was transferred, at the cost of comparing size alone from then on")
			})

			t.Run("sync_down_returns_the_plaintext", func(t *testing.T) {
				out := filepath.Join(s.work, "down")
				r := s.run(t, ctx, "sync", dest, out+"/")
				require.Truef(t, r.OK(), "sync down failed:\n%s", r.Combined)
				require.Equal(t, harness.SHA256File(t, src),
					harness.SHA256File(t, filepath.Join(out, "small.bin")),
					"what came back is not what went in")
			})
		})
	}
}
