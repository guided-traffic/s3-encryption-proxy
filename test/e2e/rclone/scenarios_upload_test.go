//go:build e2e

package rclone

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

const (
	// singlePartSize stays far below optimizations.streaming_segment_size, so
	// the object is written by the single-request PUT path.
	singlePartSize = 1 << 20 // 1 MiB
	// multiPartSize with a 5 MiB chunk is three parts.
	multiPartSize = 12 << 20 // 12 MiB
)

// multipartFlags forces rclone to upload in parts. Its own default cutoff is
// far above multiPartSize, so without these the case would silently be R1 again.
var multipartFlags = []string{"--s3-upload-cutoff", "5M", "--s3-chunk-size", "5M"}

// contentDigestShape is the one entity-tag shape S3 reserves for a digest of the
// object's content: 32 lower-case hex digits and nothing else. Every client that
// verifies an upload keys off it.
var contentDigestShape = regexp.MustCompile(`^[0-9a-f]{32}$`)

// TestR1_SinglePartUpload: a user copies a file up with a remote configured the
// documented way and no flags. It has to work.
func TestR1_SinglePartUpload(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r1-"+ep.name)
			src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

			r := s.run(t, ctx, "copy", src, s.remotePath(remotes[0], ep, "r1")+"/")

			verdicts.Want(t, harness.Case{
				ID:       "R1",
				Endpoint: ep.name,
				What:     "copy a 1 MiB file up, remote with provider defaults, no flags",
				Wants: "accept the upload. rclone compares the entity tag with the MD5 of the file it sent, " +
					"so the tag a single-request PUT answers must not be a digest of the STORED bytes in the " +
					"shape S3 reserves for a content digest (ADR 0010 D12)",
			}, r.OK(), s.says(r))

			stored := harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "r1/")
			require.Len(t, stored, 1, "the upload reported success but stored nothing")
			require.Equal(t, harness.SHA256File(t, src),
				harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, "r1/one-part.bin")),
				"what was stored is not what rclone sent")
		})
	}
}

// TestR1b_EntityTagIsNotAContentDigest: the data key is fresh per object
// (ADR 0002), so the entity tag of a single-request PUT cannot be a stable
// digest of the content — it changes on every upload of identical bytes. It must
// therefore not be answered in the shape that promises one.
func TestR1b_EntityTagIsNotAContentDigest(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS: the path a modern client takes

	s := newSuite(t, ctx, "r1b")
	src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

	seen := map[string]bool{}
	var tags []string
	const uploads = 3
	for i := 0; i < uploads; i++ {
		key := fmt.Sprintf("r1b/upload-%d.bin", i)
		// --ignore-checksum only so this case measures the VALUE; whether the
		// upload is accepted at all is R1's assertion, not this one's.
		r := s.run(t, ctx, "--ignore-checksum", "copyto", src, s.remotePath(remotes[0], ep, key))
		require.Truef(t, r.OK(), "the upload itself failed:\n%s", r.Combined)
		tag := harness.ProxyETag(t, ctx, s.bucket, key)
		seen[tag] = true
		tags = append(tags, tag)
	}

	// The premise: a fresh data key per object means the tag is not stable.
	require.Lenf(t, seen, uploads,
		"the entity tag repeated across %d uploads of identical bytes; this case assumed a fresh data key per object", uploads)

	shaped := contentDigestShape.MatchString(tags[0])
	verdicts.Want(t, harness.Case{
		ID:       "R1b",
		Endpoint: ep.name,
		What:     "upload identical bytes three times and look at the entity tag",
		Wants: "answer an entity tag that is NOT 32 bare hex digits. That shape promises a digest of the " +
			"content, and this value changes on every upload of unchanged bytes because the data key is " +
			"fresh per object (ADR 0002, ADR 0010 D12)",
	}, !shaped, "three uploads of one unchanged file produced three different tags, all shaped like a content digest: "+tags[0])
}

// TestR2_MultipartUpload: the same file uploaded in parts has to work too, and
// with the provider a user of this backend would actually configure.
func TestR2_MultipartUpload(t *testing.T) {
	ctx := preflight(t)

	cases := []struct {
		id     string
		remote remote
		what   string
		wants  string
	}{
		{
			id:     "R2a",
			remote: remotes[0], // provider = Minio, defaults
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Minio defaults",
			wants: "accept the upload. rclone computes S3's multipart formula over its plaintext parts and " +
				"compares it with what CompleteMultipartUpload answered, which the backend computed over the " +
				"SEALED parts (ADR 0010 D12)",
		},
		{
			id:     "R2b",
			remote: remotes[1], // provider = Other, defaults
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Other defaults",
			wants:  "accept the upload",
		},
		{
			id:     "R2c",
			remote: remotes[2], // provider = Minio, use_multipart_etag = false
			what:   "copy a 12 MiB file up in 5 MiB parts, provider = Minio with use_multipart_etag = false",
			wants:  "accept the upload",
		},
	}

	for _, ep := range endpoints(t) {
		for _, c := range cases {
			t.Run(c.id+"/"+ep.name, func(t *testing.T) {
				s := newSuite(t, ctx, c.id+"-"+ep.name)
				src := harness.WriteRandomFile(t, s.work, "multi-part.bin", multiPartSize)

				args := append([]string{"copy", src, s.remotePath(c.remote, ep, c.id) + "/"}, multipartFlags...)
				r := s.run(t, ctx, args...)

				verdicts.Want(t, harness.Case{
					ID: c.id, Endpoint: ep.name, What: c.what, Wants: c.wants,
				}, r.OK(), s.says(r))

				stored := harness.AssertEncryptedAtRest(t, ctx, harness.BackendClient(t),
					s.bucket, c.id+"/", storedFormat(t))
				require.Len(t, stored, 1)
			})
		}
	}
}
