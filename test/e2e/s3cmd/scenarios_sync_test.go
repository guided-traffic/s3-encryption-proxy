//go:build e2e

package s3cmd

import (
	"path/filepath"
	"strings"
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

			// The first run is the upload; whether it is accepted is S1's
			// assertion. This case is about what the SECOND run decides.
			s.run(t, ctx, "sync", dir+"/", dest)
			require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "s4/small.bin"), 1,
				"the first sync stored nothing, so there is nothing to compare against")

			second := s.run(t, ctx, "sync", dir+"/", dest)

			verdicts.Want(t, harness.Case{
				ID:       "S4",
				Endpoint: ep.name,
				What:     "sync the same unchanged 1 MiB file up twice",
				Wants: "transfer nothing on the second run. s3cmd compares size and MD5, takes the remote MD5 " +
					"from the listing's entity tag, and only issues the HEAD that would read its own " +
					"x-amz-meta-s3cmd-attrs when that tag carries a hyphen — so against a tag shaped like a " +
					"content digest it decides an unchanged file has changed, on every run, forever " +
					"(ADR 0010 D12)",
			}, second.OK() && !strings.Contains(second.Stdout, "upload:"), s.says(second))

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
