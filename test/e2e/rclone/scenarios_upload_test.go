//go:build e2e

package rclone

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

const (
	// singlePartSize stays far below optimizations.streaming_segment_size, so
	// the object is written by the single-request PUT path and the backend
	// answers a bare 32-hex entity tag — the one shape S3 reserves for a content
	// digest.
	singlePartSize = 1 << 20 // 1 MiB
	// multiPartSize with a 5 MiB chunk is three parts, so the completion answers
	// the <hex>-N shape instead.
	multiPartSize = 12 << 20 // 12 MiB
)

// multipartFlags forces rclone to upload in parts. Its own default cutoff is
// far above multiPartSize, so without these the case would silently be R1 again.
var multipartFlags = []string{"--s3-upload-cutoff", "5M", "--s3-chunk-size", "5M"}

// etagIsCiphertextDigest is what R1 and R4/R5's single-part rows pin. The
// wording stays on the product's side of the boundary: what the client does is
// the observation, this is the cause.
const etagIsCiphertextDigest = "the entity tag of a single-request PUT is the backend's MD5 of the STORED bytes " +
	"in the exact shape S3 reserves for a content digest, so a client that verifies its upload compares it with " +
	"the digest of its plaintext and they never agree (ADR 0010 D12 leaves this open; ADR 0012's residual risk " +
	"that no examined client verifies the entity tag is refuted by this case)"

// TestR1_SinglePartUpload is the single-part verdict: what a user gets
// from `rclone copy` with a remote configured the documented way and no flag at
// all.
func TestR1_SinglePartUpload(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r1-"+ep.name)
			src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

			r := s.run(t, ctx, "copy", src, s.remotePath(remotes[0], ep, "r1")+"/")

			verdicts.Record(t, harness.Case{
				ID:       "R1",
				Endpoint: ep.name,
				What:     "copy a 1 MiB file up, remote with provider defaults, no flags",
				Expect:   harness.Refuses,
				Defect:   etagIsCiphertextDigest,
			}, outcome(r), s.says(r))

			// Not just "it failed": it failed for the reason this case is about,
			// and it took the object with it. A refusal for any other reason is a
			// different defect wearing this one's clothes.
			require.Contains(t, r.Combined, "corrupted on transfer: md5 hashes differ",
				"rclone refused the upload, but not over the entity tag")
			require.Contains(t, r.Combined, "Removing failed copy",
				"rclone did not remove the object it had just uploaded")

			require.Empty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "r1/"),
				"rclone reported the transfer as corrupted and still left an object behind")
		})
	}
}

// TestR1b_SinglePartETagIsNotStable is the half of the single-part finding that
// no probe recorded: the entity tag of one unchanged file is a different value
// on every upload, because the data key is fresh per object (ADR 0002). A client
// that uses the entity tag to decide whether something changed — which is what
// the shape invites — sees every object as changed, every time.
func TestR1b_SinglePartETagIsNotStable(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS: the path a modern client actually takes

	s := newSuite(t, ctx, "r1b")
	src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

	seen := map[string]bool{}
	const uploads = 3
	for i := 0; i < uploads; i++ {
		// A distinct key each time: rclone skips a destination whose size and
		// modification time already match, so re-copying to one key would upload
		// once and compare one entity tag with itself.
		key := fmt.Sprintf("r1b/upload-%d.bin", i)
		// --ignore-checksum: rclone cannot write a single-part object through
		// this proxy at all (R1), and the point here is the value, not the verdict.
		r := s.run(t, ctx, "--ignore-checksum", "copyto", src, s.remotePath(remotes[0], ep, key))
		require.Truef(t, r.OK(), "the upload itself failed:\n%s", r.Combined)
		seen[harness.ProxyETag(t, ctx, s.bucket, key)] = true
	}

	require.Lenf(t, seen, uploads,
		"the entity tag repeated across %d uploads of identical bytes; the suite assumed a fresh data key per object", uploads)
	require.NotContainsf(t, seen, harness.MD5File(t, src),
		"the entity tag equalled the plaintext MD5, which would mean the object was not encrypted")

	verdicts.Record(t, harness.Case{
		ID:       "R1b",
		Endpoint: ep.name,
		What:     "upload identical bytes three times, compare the entity tag each time",
		Expect:   harness.Refuses,
		Defect: "the entity tag of a single-request PUT changes on every upload of unchanged bytes, because the " +
			"data key is fresh per object (ADR 0002), while its shape promises a content digest (ADR 0010 D12)",
	}, harness.Refuses, "three uploads of one unchanged file produced three different entity tags")
}

// TestR2_MultipartUpload is the multipart verdict, per provider
// default, and whether rclone's own setting is the answer.
func TestR2_MultipartUpload(t *testing.T) {
	ctx := preflight(t)

	cases := []struct {
		id     string
		remote remote
		what   string
		expect harness.Outcome
		defect string
	}{
		{
			id:     "R2a",
			remote: remotes[0], // provider = Minio, defaults
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Minio defaults",
			expect: harness.Refuses,
			defect: "under a provider whose default verifies it, the entity tag of a completed multipart upload is " +
				"the backend's formula over the SEALED parts, and the client computes the same formula over its " +
				"plaintext parts; the part count agrees and the digest cannot (ADR 0010 D12)",
		},
		{
			id:     "R2b",
			remote: remotes[1], // provider = Other, defaults
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Other defaults",
			expect: harness.Accepts,
		},
		{
			id:     "R2c",
			remote: remotes[2], // provider = Minio, use_multipart_etag = false
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Minio with use_multipart_etag = false",
			expect: harness.Accepts,
		},
	}

	for _, ep := range endpoints(t) {
		for _, c := range cases {
			t.Run(c.id+"/"+ep.name, func(t *testing.T) {
				s := newSuite(t, ctx, c.id+"-"+ep.name)
				src := harness.WriteRandomFile(t, s.work, "multi-part.bin", multiPartSize)

				args := append([]string{"copy", src, s.remotePath(c.remote, ep, c.id) + "/"}, multipartFlags...)
				r := s.run(t, ctx, args...)

				verdicts.Record(t, harness.Case{
					ID: c.id, Endpoint: ep.name, What: c.what, Expect: c.expect, Defect: c.defect,
				}, outcome(r), s.says(r))

				if c.expect == harness.Refuses {
					require.Contains(t, r.Combined, "multipart upload corrupted: Etag differ",
						"rclone refused the upload, but not over the entity tag")
					// Unlike the single-part case the object stays. That is what
					// lets a retry report success over an upload whose entity tag
					// never matched, which is why every case here runs --retries 1.
					require.NotEmpty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, c.id+"/"),
						"the suite assumed a refused multipart upload leaves its object behind")
					return
				}

				// An accepted upload has to be a correct one. Byte equality is
				// asserted through the proxy in R3; here it is enough that the
				// object exists, is stored encrypted, and is the size it should be.
				stored := harness.AssertEncryptedAtRest(t, ctx, harness.BackendClient(t), s.bucket, c.id+"/", storedFormat(t))
				require.Len(t, stored, 1)
			})
		}
	}
}
