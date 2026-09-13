//go:build e2e

package rclone

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestR4_CheckAndSync is what runs unattended, and therefore what costs an
// operator most: `rclone check` is how a backup is verified after the fact, and
// `rclone sync --checksum` is how a mirror is kept honest. Both have to agree
// that intact data is intact.
func TestR4_CheckAndSync(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r4-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("check_multipart_object", func(t *testing.T) {
				// Directory against directory: rclone's check compares two
				// listings, and handing it a file is "is a file not a directory".
				r := s.run(t, ctx, "check", c.multiDir, s.remotePath(remotes[0], ep, "corpus/multi")+"/")

				verdicts.Want(t, harness.Case{
					ID:       "R4a",
					Endpoint: ep.name,
					What:     "check a multipart object against its source",
					Wants:    "report no differences for an object that is byte-identical to its source",
				}, r.OK() && strings.Contains(r.Combined, "0 differences found"), s.says(r))
			})

			t.Run("check_single_part_object", func(t *testing.T) {
				r := s.run(t, ctx, "check", c.singleDir, s.remotePath(remotes[0], ep, "corpus/single")+"/")

				// The object really is intact; the proof must not come from rclone.
				require.Equal(t, harness.SHA256File(t, c.singleSrc),
					harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, c.singleKey)),
					"the object is genuinely different from its source, which would be a separate defect")

				verdicts.Want(t, harness.Case{
					ID:       "R4b",
					Endpoint: ep.name,
					What:     "check a single-part object against its source",
					Wants: "report no differences. The object is byte-identical to its source; rclone compares " +
						"the entity tag against the file's MD5 and calls intact data corrupt, which is a " +
						"verification tool giving the one answer it must never give wrongly (ADR 0010 D12)",
				}, r.OK() && strings.Contains(r.Combined, "0 differences found"), s.says(r))
			})

			t.Run("sync_multipart_object_settles", func(t *testing.T) {
				dest := s.remotePath(remotes[2], ep, "r4-sync") + "/"

				r1 := s.run(t, ctx, append([]string{"sync", c.multiDir, dest}, multipartFlags...)...)
				require.Truef(t, r1.OK(), "the first sync failed:\n%s", r1.Combined)
				require.Contains(t, r1.Combined, "Copied (new)")

				r2 := s.run(t, ctx, append([]string{"sync", c.multiDir, dest}, multipartFlags...)...)
				r3 := s.run(t, ctx, append([]string{"sync", "--checksum", c.multiDir, dest}, multipartFlags...)...)

				settled := r2.OK() && strings.Contains(r2.Combined, "There was nothing to transfer") &&
					r3.OK() && strings.Contains(r3.Combined, "There was nothing to transfer")

				verdicts.Want(t, harness.Case{
					ID:       "R4c",
					Endpoint: ep.name,
					What:     "sync a multipart object up twice, then once with --checksum",
					Wants:    "transfer nothing on the second and third runs: nothing changed between them",
				}, settled, s.says(r3))
			})

			t.Run("sync_checksum_single_part_object_settles", func(t *testing.T) {
				dest := s.remotePath(remotes[0], ep, "r4-spsync") + "/"

				// Placed with the escape R1 is about, so this case is about sync
				// and not about the upload. The flag comes out when R1 passes.
				placed := s.run(t, ctx, "--ignore-checksum", "sync", c.singleDir, dest)
				require.Truef(t, placed.OK(), "could not place the object:\n%s", placed.Combined)

				// Size and modification time agree, so a sync that compares those settles …
				bySize := s.run(t, ctx, "--ignore-checksum", "sync", c.singleDir, dest)
				require.Truef(t, bySize.OK(), "the size-and-time sync failed:\n%s", bySize.Combined)
				require.Contains(t, bySize.Combined, "There was nothing to transfer")

				// … and the same sync asked to compare digests has to settle too.
				r := s.run(t, ctx, "--checksum", "sync", c.singleDir, dest)

				verdicts.Want(t, harness.Case{
					ID:       "R4d",
					Endpoint: ep.name,
					What:     "sync --checksum a single-part object that is already there and unchanged",
					Wants: "transfer nothing. The entity tag is not the file's digest, so --checksum sees every " +
						"unchanged object as changed and re-uploads it, and the re-upload is then refused by the " +
						"same tag: a mirror that can never converge (ADR 0010 D12)",
				}, r.OK() && strings.Contains(r.Combined, "There was nothing to transfer"), s.says(r))
			})
		})
	}
}
