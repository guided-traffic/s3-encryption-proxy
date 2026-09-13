//go:build e2e

package rclone

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestR4_CheckAndSync asks what rclone treats as changed, and on
// which hash.
//
// It is the case that costs an operator most, because it is the one that runs
// unattended. `rclone check` is how a backup is verified after the fact, and
// `rclone sync --checksum` is how a mirror is kept honest; both read the same
// hash R5 shows rclone getting wrong for a single-request object.
func TestR4_CheckAndSync(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r4-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("check_passes_for_the_multipart_object", func(t *testing.T) {
				// Directory against directory: rclone's check compares two
				// listings, and handing it a file is "is a file not a directory".
				r := s.run(t, ctx, "check", c.multiDir, s.remotePath(remotes[0], ep, "corpus/multi")+"/")
				require.Truef(t, r.OK(), "check failed for an object rclone can verify:\n%s", r.Combined)
				require.Contains(t, r.Combined, "0 differences found")

				verdicts.Record(t, harness.Case{
					ID:       "R4a",
					Endpoint: ep.name,
					What:     "check a multipart object against its source",
					Expect:   harness.Accepts,
				}, harness.Accepts, s.says(r))
			})

			t.Run("check_reports_a_difference_for_the_single_part_object", func(t *testing.T) {
				r := s.run(t, ctx, "check", c.singleDir, s.remotePath(remotes[0], ep, "corpus/single")+"/")

				verdicts.Record(t, harness.Case{
					ID:       "R4b",
					Endpoint: ep.name,
					What:     "check a single-part object against its source",
					Expect:   harness.Refuses,
					Defect: "rclone compares the entity tag against the file's MD5 and reports an intact object " +
						"as differing — a verification tool answering \"corrupt\" about data that is whole " +
						"(ADR 0010 D12)",
				}, outcome(r), s.says(r))

				require.Contains(t, r.Combined, "md5 differ",
					"check refused, but not over the digest")
				require.Contains(t, r.Combined, "1 differences found")

				// The object really is intact; only the comparison is wrong.
				require.Equal(t, harness.SHA256File(t, c.singleSrc),
					harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, c.singleKey)),
					"the object rclone calls different is in fact different, which is a separate defect")
			})

			t.Run("sync_of_the_multipart_object_settles", func(t *testing.T) {
				dir := c.multiDir
				dest := s.remotePath(remotes[2], ep, "r4-sync") + "/"

				first := append([]string{"sync", dir, dest}, multipartFlags...)
				r1 := s.run(t, ctx, first...)
				require.Truef(t, r1.OK(), "the first sync failed:\n%s", r1.Combined)
				require.Contains(t, r1.Combined, "Copied (new)")

				second := append([]string{"sync", dir, dest}, multipartFlags...)
				r2 := s.run(t, ctx, second...)
				require.Truef(t, r2.OK(), "the second sync failed:\n%s", r2.Combined)
				require.Contains(t, r2.Combined, "There was nothing to transfer",
					"the second sync transferred something; nothing changed between them")

				third := append([]string{"sync", "--checksum", dir, dest}, multipartFlags...)
				r3 := s.run(t, ctx, third...)
				require.Truef(t, r3.OK(), "sync --checksum failed:\n%s", r3.Combined)
				require.Contains(t, r3.Combined, "There was nothing to transfer")

				verdicts.Record(t, harness.Case{
					ID:       "R4c",
					Endpoint: ep.name,
					What:     "sync a multipart object up twice, then once with --checksum",
					Expect:   harness.Accepts,
				}, harness.Accepts, "the second and third runs transferred nothing")
			})

			t.Run("sync_checksum_of_the_single_part_object_never_settles", func(t *testing.T) {
				dir := c.singleDir
				dest := s.remotePath(remotes[0], ep, "r4-spsync") + "/"

				// Place it once; the upload itself is R1's verdict, so the escape
				// R1 identified is used to get past it.
				placed := s.run(t, ctx, "--ignore-checksum", "sync", dir, dest)
				require.Truef(t, placed.OK(), "could not place the object:\n%s", placed.Combined)

				// Size and modification time agree, so a default sync settles …
				bySize := s.run(t, ctx, "--ignore-checksum", "sync", dir, dest)
				require.Truef(t, bySize.OK(), "the size-and-time sync failed:\n%s", bySize.Combined)
				require.Contains(t, bySize.Combined, "There was nothing to transfer")

				// … and the same sync asked to compare digests does not.
				r := s.run(t, ctx, "--checksum", "sync", dir, dest)

				verdicts.Record(t, harness.Case{
					ID:       "R4d",
					Endpoint: ep.name,
					What:     "sync --checksum a single-part object that is already there and unchanged",
					Expect:   harness.Refuses,
					Defect: "the entity tag is not the file's digest, so --checksum sees every unchanged object as " +
						"changed, re-uploads it, and the re-upload is then refused by R1's check: a mirror that " +
						"can never converge (ADR 0010 D12)",
				}, outcome(r), s.says(r))

				require.Contains(t, r.Combined, "corrupted on transfer: md5 hashes differ")
			})
		})
	}
}
