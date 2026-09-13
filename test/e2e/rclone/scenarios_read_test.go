//go:build e2e

package rclone

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// corpus is the pair of objects the read cases need: one written by a single
// request, one written in parts.
//
// Placing them needs escape flags today — --ignore-checksum for the single-part
// object, use_multipart_etag = false for the other — because the write defects
// R1 and R2a are open. That is setup working around a defect, not an assertion
// about it: the read cases have to be able to run and fail on their own reasons
// while the write side is broken. **When R1 and R2a pass, these flags come out**,
// and the narrowest one is used for each so a blanket --ignore-checksum cannot
// hide which defect is which.
//
// Each object sits alone in a directory on both sides, because rclone's own
// comparison verbs (check, sync) take directories, not files.
type corpus struct {
	singleDir string // local directory holding exactly the single-part file
	singleSrc string
	singleKey string
	multiDir  string
	multiSrc  string
	multiKey  string
}

const (
	singleName = "one-part.bin"
	multiName  = "multi-part.bin"
)

func seedCorpus(t *testing.T, ctx context.Context, s *suite, ep endpoint) corpus {
	t.Helper()
	c := corpus{
		singleDir: filepath.Join(s.work, "src", "single"),
		singleKey: "corpus/single/" + singleName,
		multiDir:  filepath.Join(s.work, "src", "multi"),
		multiKey:  "corpus/multi/" + multiName,
	}
	c.singleSrc = harness.WriteRandomFile(t, c.singleDir, singleName, singlePartSize)
	c.multiSrc = harness.WriteRandomFile(t, c.multiDir, multiName, multiPartSize)

	single := s.run(t, ctx, "--ignore-checksum", "copyto",
		c.singleSrc, s.remotePath(remotes[0], ep, c.singleKey))
	require.Truef(t, single.OK(), "could not place the single-part object:\n%s", single.Combined)

	args := append([]string{"copyto", c.multiSrc, s.remotePath(remotes[2], ep, c.multiKey)}, multipartFlags...)
	multi := s.run(t, ctx, args...)
	require.Truef(t, multi.OK(), "could not place the multipart object:\n%s", multi.Combined)

	return c
}

// TestR3_Download is the read side: what a user pulls back has to be, byte for
// byte, what went in — for an object written by one request as much as for one
// written in parts.
func TestR3_Download(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r3-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("multipart_object", func(t *testing.T) {
				out := filepath.Join(s.work, "down", multiName)
				r := s.run(t, ctx, "copyto", s.remotePath(remotes[0], ep, c.multiKey), out)

				verdicts.Want(t, harness.Case{
					ID:       "R3a",
					Endpoint: ep.name,
					What:     "copy a multipart object down",
					Wants:    "serve the object and let the client verify it",
				}, r.OK(), s.says(r))

				require.Equal(t, harness.SHA256File(t, c.multiSrc), harness.SHA256File(t, out),
					"what came back is not what went in")
			})

			t.Run("single_part_object", func(t *testing.T) {
				out := filepath.Join(s.work, "down", singleName)
				r := s.run(t, ctx, "copyto", s.remotePath(remotes[0], ep, c.singleKey), out)

				verdicts.Want(t, harness.Case{
					ID:       "R3b",
					Endpoint: ep.name,
					What:     "copy a single-part object down",
					Wants: "serve the object and let the client verify it. rclone verifies a download against " +
						"the entity tag the same way it verifies an upload, so a tag shaped like a content " +
						"digest makes it call an intact transfer corrupted and delete the file it wrote — with " +
						"a remote configured the documented way such an object is unreachable in both " +
						"directions (ADR 0010 D12)",
				}, r.OK(), s.says(r))

				require.Equal(t, harness.SHA256File(t, c.singleSrc), harness.SHA256File(t, out),
					"what came back is not what went in")
			})
		})
	}
}

// TestR5_ReportedHashes: whatever digest rclone reports for an object has to be
// the digest of that object's content. Reporting a different value as the
// object's md5 is worse than reporting none: a user who compares it concludes
// their data is corrupt.
func TestR5_ReportedHashes(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r5-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("multipart_object", func(t *testing.T) {
				got := hashsum(t, ctx, s, ep, c.multiKey)
				want := harness.MD5File(t, c.multiSrc)
				verdicts.Want(t, harness.Case{
					ID:       "R5a",
					Endpoint: ep.name,
					What:     "hashsum md5 of a multipart object",
					Wants:    "report the plaintext MD5, or no hash at all — never a different value",
				}, got == "" || got == want, "rclone reported "+got+"; the file's md5 is "+want)
			})

			t.Run("single_part_object", func(t *testing.T) {
				got := hashsum(t, ctx, s, ep, c.singleKey)
				want := harness.MD5File(t, c.singleSrc)
				verdicts.Want(t, harness.Case{
					ID:       "R5b",
					Endpoint: ep.name,
					What:     "hashsum md5 of a single-part object",
					Wants: "report the plaintext MD5, or no hash at all. rclone writes X-Amz-Meta-Md5chksum " +
						"only on a multipart upload, so for a single-request object it falls back to the entity " +
						"tag and reports the MD5 of the STORED bytes as the object's md5 — a wrong answer " +
						"rather than no answer (ADR 0010 D12)",
				}, got == "" || got == want, "rclone reported "+got+"; the file's md5 is "+want)
			})

			t.Run("lsjson_carries_the_same_hash_and_the_proxy_metadata_is_not_visible", func(t *testing.T) {
				r := s.run(t, ctx, "lsjson", "--hash", "--metadata",
					s.remotePath(remotes[0], ep, c.multiKey))
				require.Truef(t, r.OK(), "lsjson failed:\n%s", r.Combined)

				var entries []struct {
					Name     string            `json:"Name"`
					Size     int64             `json:"Size"`
					Hashes   map[string]string `json:"Hashes"`
					Metadata map[string]string `json:"Metadata"`
				}
				require.NoError(t, json.Unmarshal([]byte(r.Stdout), &entries), "lsjson output is not JSON:\n%s", r.Stdout)
				require.Len(t, entries, 1)

				require.Equal(t, harness.MD5File(t, c.multiSrc), entries[0].Hashes["md5"])
				require.Equal(t, int64(multiPartSize), entries[0].Size,
					"lsjson reports a size that is not the plaintext length")

				// ADR 0009 D6: the proxy's namespace is stripped on the way out.
				prefix := harness.DemoStack(t).Get(t, "S3EP_METADATA_PREFIX")
				for k := range entries[0].Metadata {
					require.NotContainsf(t, strings.ToLower(k), prefix,
						"the proxy's own metadata key %q reached the client", k)
				}
			})
		})
	}
}

// hashsum returns the md5 rclone reports for one object.
func hashsum(t *testing.T, ctx context.Context, s *suite, ep endpoint, key string) string {
	t.Helper()
	r := s.run(t, ctx, "hashsum", "md5", s.remotePath(remotes[0], ep, key))
	require.Truef(t, r.OK(), "hashsum failed:\n%s", r.Combined)
	fields := strings.Fields(r.Stdout)
	require.NotEmptyf(t, fields, "hashsum printed nothing:\n%s", r.Combined)
	return fields[0]
}
