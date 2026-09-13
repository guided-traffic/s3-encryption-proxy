//go:build e2e

package s3cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestS6_Lifecycle covers the lifecycle, and it turned up a second defect that has
// nothing to do with the entity tag.
//
// s3cmd addresses a bucket with a trailing slash. `del --recursive s3://b/`
// sends `POST /b/?delete`, and `multipart s3://b` sends `GET /b/?uploads` — both
// the bucket resource, both what S3 answers as a bucket operation. This proxy
// routes neither: its DeleteObjects route matches the path without the trailing
// slash, and the trailing-slash route carries no POST at all, so the request
// falls through to the object handler with an empty key. A client that always
// writes the slash therefore cannot delete recursively, cannot list its open
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
		require.Truef(t, r.OK(), "mb failed:\n%s", r.Combined)
		require.Contains(t, r.Stdout, "created")
	})

	t.Run("put_and_del_one_object", func(t *testing.T) {
		up := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("gone.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)

		r := s.run(t, ctx, "del", s.uri("gone.bin"))
		require.Truef(t, r.OK(), "deleting one object by its full key failed:\n%s", r.Combined)
		require.Empty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "gone.bin"))
	})

	t.Run("del_recursive_over_a_prefix_is_refused", func(t *testing.T) {
		up := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("tree/payload.bin"))
		require.Truef(t, up.OK(), "could not place the object:\n%s", up.Combined)

		r := s.run(t, ctx, "--recursive", "--force", "del", s.uri("tree")+"/")

		verdicts.Record(t, harness.Case{
			ID:       "S6a",
			Endpoint: ep.name,
			What:     "del --recursive over a prefix (POST /bucket/?delete)",
			Expect:   harness.Refuses,
			Defect: "s3cmd sends DeleteObjects as POST on the bucket WITH a trailing slash; the proxy routes " +
				"DeleteObjects only on the path without it, and its trailing-slash bucket route carries no POST, " +
				"so the request reaches the object handler with an empty key and is answered 501 NotImplemented " +
				"(ObjectSubResource). Unrelated to the entity tag; a routing gap",
		}, outcome(r), s.says(r))

		require.Contains(t, r.Combined, "501",
			"del --recursive was refused, but not with the 501 this case is about")
		require.Contains(t, r.Combined, "ObjectSubResource")
		require.Len(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "tree/"), 1,
			"the refused recursive delete removed the object after all")
	})

	t.Run("listing_open_uploads_is_refused", func(t *testing.T) {
		r := s.run(t, ctx, "multipart", s.uri(""))

		verdicts.Record(t, harness.Case{
			ID:       "S6b",
			Endpoint: ep.name,
			What:     "multipart — list the bucket's open uploads (GET /bucket/?uploads)",
			Expect:   harness.Refuses,
			Defect: "same trailing slash: the proxy routes ListMultipartUploads on the bucket path without it, " +
				"and the trailing-slash route hands GET to the plain bucket handler, which does not know the " +
				"uploads sub-resource and answers 405. So a client whose multipart upload was refused part by " +
				"part (S2) can neither see nor abort what it left open",
		}, outcome(r), s.says(r))

		require.Contains(t, r.Combined, "405")
	})

	t.Run("rb_removes_an_empty_bucket", func(t *testing.T) {
		// Emptied with the backend client, because the client's own recursive
		// delete is refused above. That is the point: without an operator with
		// backend credentials, this bucket cannot be removed by its owner.
		harness.EmptyBucket(t, ctx, s.bucket)

		r := s.run(t, ctx, "rb", s.uri(""))
		require.Truef(t, r.OK(), "rb of an empty bucket failed:\n%s", r.Combined)
	})
}
