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
// request, one written in parts. Both have to be placed in spite of R1 and R2a,
// so each uses the narrowest escape its own case identified — --ignore-checksum
// for the single-part object, use_multipart_etag = false for the other. Using
// the narrowest escape is deliberate: a corpus placed with a blanket
// --ignore-checksum would hide which of the two defects is which.
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

// TestR3_Download is the read side, and it is where this suite parts company
// with what was believed before it existed.
//
// rclone verifies a download the same way it verifies an upload: against the
// entity tag. For the multipart object that tag carries a hyphen, rclone knows
// not to read it as a digest, and the download succeeds. For the single-request
// object it is a bare 32-hex value, rclone compares it with the MD5 of the bytes
// it just wrote to disk, calls the transfer corrupted and DELETES the partial
// file it had already written.
//
// So the defect is not confined to the upload leg: with a remote configured the
// documented way, an object written through this proxy cannot be fetched back by
// rclone at all.
func TestR3_Download(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r3-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("multipart_object_comes_back_byte_identical", func(t *testing.T) {
				out := filepath.Join(s.work, "down", multiName)
				r := s.run(t, ctx, "copyto", s.remotePath(remotes[0], ep, c.multiKey), out)
				require.Truef(t, r.OK(), "the download was refused:\n%s", r.Combined)
				require.Equal(t, harness.SHA256File(t, c.multiSrc), harness.SHA256File(t, out),
					"what came back is not what went in")

				verdicts.Record(t, harness.Case{
					ID:       "R3a",
					Endpoint: ep.name,
					What:     "copy a multipart object down, SHA-256 against the source",
					Expect:   harness.Accepts,
				}, harness.Accepts, "the object round-tripped byte-identical")
			})

			t.Run("single_part_object_cannot_be_downloaded", func(t *testing.T) {
				out := filepath.Join(s.work, "down", singleName)
				r := s.run(t, ctx, "copyto", s.remotePath(remotes[0], ep, c.singleKey), out)

				verdicts.Record(t, harness.Case{
					ID:       "R3b",
					Endpoint: ep.name,
					What:     "copy a single-part object down",
					Expect:   harness.Refuses,
					Defect: "rclone verifies a download against the entity tag too, so the bare 32-hex tag of a " +
						"single-request object makes it call an intact transfer corrupted and delete the file it " +
						"had written; with a remote configured the documented way such an object cannot be " +
						"fetched back at all (ADR 0010 D12)",
				}, outcome(r), s.says(r))

				require.Contains(t, r.Combined, "corrupted on transfer: md5 hashes differ",
					"the download was refused, but not over the entity tag")
				require.NoFileExists(t, out,
					"rclone kept the file it called corrupted; the suite assumed it removes it")

				// The bytes are whole. Only rclone's comparison is wrong, and the
				// proof has to come from somewhere that does not use rclone.
				require.Equal(t, harness.SHA256File(t, c.singleSrc),
					harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, c.singleKey)),
					"the object rclone calls corrupted really is corrupt, which is a different defect")
			})

			t.Run("the_escape_works_and_what_it_costs", func(t *testing.T) {
				// --ignore-checksum is the only flag that gets the object down.
				// It is global: from then on rclone verifies nothing at all, on
				// any transfer in that invocation, including against real
				// corruption. That is the cost the README would have to state.
				out := filepath.Join(s.work, "down-forced", singleName)
				r := s.run(t, ctx, "--ignore-checksum", "copyto",
					s.remotePath(remotes[0], ep, c.singleKey), out)
				require.Truef(t, r.OK(), "even --ignore-checksum did not get the object down:\n%s", r.Combined)
				require.Equal(t, harness.SHA256File(t, c.singleSrc), harness.SHA256File(t, out))
			})
		})
	}
}

// TestR5_ReportedHashes asks which digest rclone reports for an
// object, and where it got it.
//
// The two objects answer differently, and that is the finding. rclone writes its
// own X-Amz-Meta-Md5chksum on a multipart upload and reads it back, so a
// multipart object reports the plaintext MD5. It writes no such header for a
// single-request upload, so there it falls back to the entity tag — and reports
// the MD5 of bytes the user has never held, as though it were the file's.
func TestR5_ReportedHashes(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r5-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			t.Run("multipart_object_reports_the_plaintext_md5", func(t *testing.T) {
				got := hashsum(t, ctx, s, ep, c.multiKey)
				require.Equal(t, harness.MD5File(t, c.multiSrc), got,
					"rclone did not report the plaintext MD5 for the multipart object")

				verdicts.Record(t, harness.Case{
					ID:       "R5a",
					Endpoint: ep.name,
					What:     "hashsum md5 of a multipart object",
					Expect:   harness.Accepts,
				}, harness.Accepts, "rclone reported the plaintext MD5, read back from X-Amz-Meta-Md5chksum")
			})

			t.Run("single_part_object_reports_the_ciphertext_digest", func(t *testing.T) {
				got := hashsum(t, ctx, s, ep, c.singleKey)
				want := harness.MD5File(t, c.singleSrc)
				require.NotEqualf(t, want, got,
					"rclone reported the plaintext MD5 for a single-part object; the suite assumed it cannot")
				require.Equalf(t, harness.ProxyETag(t, ctx, s.bucket, c.singleKey), got,
					"rclone reported %q, which is neither the plaintext MD5 nor the entity tag", got)

				verdicts.Record(t, harness.Case{
					ID:       "R5b",
					Endpoint: ep.name,
					What:     "hashsum md5 of a single-part object",
					Expect:   harness.Refuses,
					Defect: "rclone writes X-Amz-Meta-Md5chksum only on a multipart upload, so for a " +
						"single-request object it falls back to the entity tag and reports the MD5 of the STORED " +
						"bytes as the object's md5 — a wrong answer rather than no answer (ADR 0010 D12)",
				}, harness.Refuses, "rclone reported the entity tag "+got+" as the object's md5; the file's is "+want)
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
