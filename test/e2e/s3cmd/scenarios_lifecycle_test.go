//go:build e2e

package s3cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/v5/test/e2e/harness"
)

// TestS6_Lifecycle covers the lifecycle of a bucket s3cmd creates, fills and
// removes itself.
//
// s3cmd addresses a bucket with a trailing slash. `del --recursive s3://b/`
// sends `POST /b/?delete`, and `multipart s3://b` sends `GET /b/?uploads` — both
// the bucket resource, both what S3 answers as a bucket operation. The proxy has
// to route every bucket operation in that form as well as without the slash, or
// a client that always writes it cannot delete recursively, cannot list its open
// uploads, and — because of that — cannot remove its own bucket.
func TestS6_Lifecycle(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS

	s := &suite{
		bin:  s3cmdBin(t),
		work: t.TempDir(),
		ep:   ep,
	}
	s.config = writeConfig(t, ep)
	s.bucket = uniqueBucket("s6")
	// Not EnsureBucket: s3cmd creates it. The cleanup still runs, because this
	// case's own teardown is one of the things under test.
	t.Cleanup(func() { harness.EmptyAndDeleteBucket(t, ctx, s.bucket) })

	src := harness.WriteRandomFile(t, s.work, "payload.bin", producerSize)

	t.Run("mb_creates_the_bucket", func(t *testing.T) {
		r := s.run(t, ctx, "mb", s.uri(""))
		verdicts.Want(t, harness.Case{
			ID:       "S6",
			Endpoint: ep.name,
			What:     "mb — create a bucket",
			Wants:    "create the bucket",
		}, r.OK() && strings.Contains(r.Stdout, "created"), s.says(r))
	})

	t.Run("put_and_del_one_object", func(t *testing.T) {
		up := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("gone.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)

		r := s.run(t, ctx, "del", s.uri("gone.bin"))
		require.Truef(t, r.OK(), "deleting one object by its full key failed:\n%s", r.Combined)
		require.Empty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "gone.bin"))
	})

	t.Run("del_recursive_over_a_prefix", func(t *testing.T) {
		up := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("tree/payload.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)

		r := s.run(t, ctx, "--recursive", "--force", "del", s.uri("tree")+"/")
		left := harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "tree/")

		verdicts.Want(t, harness.Case{
			ID:       "S6a",
			Endpoint: ep.name,
			What:     "del --recursive over a prefix",
			Wants: "delete the objects. s3cmd sends DeleteObjects as POST on the bucket WITH a trailing " +
				"slash, and the proxy must route it there like the path without it — not hand it to the " +
				"object handler with an empty key",
		}, r.OK() && len(left) == 0, s.says(r))
	})

	t.Run("listing_open_uploads", func(t *testing.T) {
		r := s.run(t, ctx, "multipart", s.uri(""))

		verdicts.Want(t, harness.Case{
			ID:       "S6b",
			Endpoint: ep.name,
			What:     "multipart — list the bucket's open uploads",
			Wants: "answer the listing. Same trailing slash: ListMultipartUploads must be routed on " +
				"GET /bucket/?uploads, not handed to the plain bucket handler, or a client cannot see or " +
				"abort an upload it left open",
		}, r.OK(), s.says(r))
	})

	t.Run("rb_removes_an_empty_bucket", func(t *testing.T) {
		// Emptied with the backend client so this case judges rb alone: when S6a
		// is red, its leftovers must not turn this verdict red as well.
		harness.EmptyBucket(t, ctx, s.bucket)

		r := s.run(t, ctx, "rb", s.uri(""))
		verdicts.Want(t, harness.Case{
			ID:       "S6c",
			Endpoint: ep.name,
			What:     "rb an empty bucket",
			Wants:    "remove the bucket",
		}, r.OK(), s.says(r))
	})
}
