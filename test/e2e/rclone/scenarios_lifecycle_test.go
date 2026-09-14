//go:build e2e

package rclone

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestR6_Lifecycle covers the bucket and object lifecycle a user
// drives, with rclone's own vocabulary rather than the SDK's.
//
// It is here because the entity-tag cases cannot see it: a client's lifecycle
// verbs map onto S3 operations the proxy has to route, and rclone's mapping is
// not the AWS CLI's. Its own bucket is created and destroyed here, so this case
// does not use the harness's setup.
func TestR6_Lifecycle(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS

	s := &suite{
		bin:    rcloneBin(t),
		config: writeConfig(t),
		work:   t.TempDir(),
		bucket: uniqueBucket("r6"),
	}
	// Not EnsureBucket: rclone creates it. The cleanup still runs, so a case
	// that fails half way does not leave a bucket behind.
	t.Cleanup(func() { harness.EmptyAndDeleteBucket(t, ctx, s.bucket) })

	remote := remoteName(remotes[0], ep)
	src := harness.WriteRandomFile(t, s.work, "payload.bin", singlePartSize)

	t.Run("mkdir_creates_the_bucket", func(t *testing.T) {
		r := s.run(t, ctx, "mkdir", remote+":"+s.bucket)
		require.Truef(t, r.OK(), "mkdir failed:\n%s", r.Combined)

		ls := s.run(t, ctx, "lsd", remote+":")
		require.Contains(t, ls.Stdout, s.bucket, "the bucket rclone created is not in the listing")
	})

	t.Run("delete_removes_one_object", func(t *testing.T) {
		up := s.run(t, ctx, "--ignore-checksum", "copyto", src, s.remotePath(remotes[0], ep, "gone.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)
		require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "gone.bin"), 1)

		r := s.run(t, ctx, "delete", s.remotePath(remotes[0], ep, "gone.bin"))
		require.Truef(t, r.OK(), "delete failed:\n%s", r.Combined)
		require.Empty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "gone.bin"))
	})

	t.Run("purge_empties_and_removes_the_bucket", func(t *testing.T) {
		up := s.run(t, ctx, "--ignore-checksum", "copyto", src, s.remotePath(remotes[0], ep, "kept/payload.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)

		r := s.run(t, ctx, "purge", remote+":"+s.bucket)
		require.Truef(t, r.OK(), "purge failed:\n%s", r.Combined)

		ls := s.run(t, ctx, "lsd", remote+":")
		require.NotContains(t, ls.Stdout, s.bucket,
			"rclone purge left the bucket behind; it removes the bucket as well as its contents")
	})

	verdicts.Want(t, harness.Case{
		ID:       "R6",
		Endpoint: ep.name,
		What:     "mkdir, copy, delete, purge — the lifecycle a user drives",
		Wants:    "accept every lifecycle verb rclone issues",
	}, true, "every lifecycle verb was accepted")
}
