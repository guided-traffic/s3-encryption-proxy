//go:build e2e

package s3cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

const (
	// singlePartSize is below both s3cmd's own multipart threshold and
	// optimizations.streaming_segment_size, so one PUT reaches the proxy and the
	// backend answers a bare 32-hex entity tag.
	singlePartSize = 1 << 20 // 1 MiB
	// multiPartSize with a 5 MiB chunk is three client parts.
	multiPartSize = 12 << 20 // 12 MiB
	// producerSize is above optimizations.streaming_segment_size (12 MiB), so a
	// single client PUT becomes the proxy's internal multipart producer and the
	// answer carries the <hex>-N shape instead. See TestS2b.
	producerSize = 20 << 20 // 20 MiB
	// producerChunkMB keeps s3cmd from splitting producerSize itself: its own
	// multipart threshold has to stay above the file for the case to be about
	// the proxy's part layout and not about s3cmd's.
	producerChunkMB = "200"
)

// etagIsCiphertextDigest is what S1's and S4's rows pin.
const etagIsCiphertextDigest = "the entity tag of a single-request PUT is the backend's MD5 of the STORED bytes " +
	"in the exact shape S3 reserves for a content digest, and s3cmd compares every PUT response tag with the MD5 " +
	"of the bytes it sent (ADR 0010 D12 leaves this open; ADR 0012's residual risk that no examined client " +
	"verifies the entity tag is refuted by this case)"

// TestS1_SinglePartPut is the single-part verdict: what a user gets from `s3cmd put`
// with a configuration written the documented way and no flag at all.
func TestS1_SinglePartPut(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s1-"+ep.name, ep)
			src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

			r := s.run(t, ctx, "put", src, s.uri("small.bin"))

			verdicts.Record(t, harness.Case{
				ID:       "S1",
				Endpoint: ep.name,
				What:     "put a 1 MiB file, defaults",
				Expect:   harness.Refuses,
				Defect:   etagIsCiphertextDigest,
			}, outcome(r), s.says(r))

			require.Contains(t, r.Combined, "MD5 Sums don't match!",
				"s3cmd refused the upload, but not over the entity tag")
			require.Contains(t, r.Combined, "failed too many times",
				"s3cmd did not exhaust its retries the way the case assumes")
			require.Equalf(t, 2, r.ExitCode,
				"a refused transfer is EX_PARTIAL (2) without --stop-on-error; got %d", r.ExitCode)

			// The half of this that a user pays for twice: s3cmd reports the
			// upload as failed and the object IS in the bucket, decryptable and
			// whole. A caller that trusts the exit code believes it stored
			// nothing. rclone, by contrast, deletes what it could not vouch for.
			stored := harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "small.bin")
			require.Lenf(t, stored, 1,
				"the suite assumed a refused s3cmd put leaves its object behind; it stored %d", len(stored))
			require.Equal(t, harness.SHA256File(t, src),
				harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, "small.bin")),
				"the object s3cmd reported as corrupted does not read back as the file it sent")
		})
	}
}

// TestS2_MultipartPut is the multipart verdict, and the question the object-level
// entity tag cannot answer: s3cmd checks a tag per UPLOADED PART.
func TestS2_MultipartPut(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s2-"+ep.name, ep)
			src := harness.WriteRandomFile(t, s.work, "multi-part.bin", multiPartSize)

			r := s.run(t, ctx, "--multipart-chunk-size-mb=5", "put", src, s.uri("big.bin"))

			verdicts.Record(t, harness.Case{
				ID:       "S2",
				Endpoint: ep.name,
				What:     "put a 12 MiB file in 5 MiB parts",
				Expect:   harness.Refuses,
				Defect: "s3cmd compares the entity tag of every UploadPart response with the MD5 of that part, and " +
					"under an encrypting provider a part's tag is the backend's MD5 of the SEALED part; the upload " +
					"is refused on the first part and never reaches CompleteMultipartUpload, so no object-level " +
					"entity tag can answer it (ADR 0010 D12)",
			}, outcome(r), s.says(r))

			require.Contains(t, r.Combined, "MD5 Sums don't match!")
			// The first part, not the last: a per-part refusal, not a completion
			// that was checked afterwards.
			require.Contains(t, r.Combined, "part 1 failed",
				"the suite assumed s3cmd refuses the FIRST part; it got further")
			require.Contains(t, r.Combined, "abortmp",
				"s3cmd did not print the abort instructions this case expects")

			// Nothing was completed, so nothing is stored — but an upload was
			// opened and left open. The client cannot clean it up: the proxy
			// answers `s3cmd multipart` with 405 (see TestS6).
			require.Empty(t, harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "big.bin"),
				"a multipart upload refused at part 1 still produced an object")
			require.NotEmpty(t, harness.OpenUploads(t, ctx, s.bucket),
				"the suite assumed a refused multipart put leaves the upload open on the backend")
		})
	}
}

// TestS2b_AHyphenInTheEntityTagDisablesEveryCheck is the case the decision turns
// on, and it needs no change to the product to run.
//
// s3cmd skips its entity-tag comparison whenever the tag contains a hyphen — the
// test it uses to recognise a completed multipart upload, whose tag S3 itself
// calls opaque. The proxy already answers that shape for an object above
// optimizations.streaming_segment_size, because such a PUT becomes the internal
// multipart producer.
//
// So the SAME client uploading through the SAME proxy under the SAME encryption
// succeeds or is refused depending on nothing but whether the answer happens to
// carry a hyphen. That is the measurement behind the proposed marker: it says
// the marker is sufficient for s3cmd at object level, and — with S2 — that it is
// necessary at part level too, which is a wider scope than an object-level rule.
func TestS2b_AHyphenInTheEntityTagDisablesEveryCheck(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS

	s := newSuite(t, ctx, "s2b", ep)
	src := harness.WriteRandomFile(t, s.work, "producer.bin", producerSize)

	// One client PUT, above the proxy's single-request ceiling.
	r := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("producer.bin"))
	require.Truef(t, r.OK(), "the upload was refused, which is the opposite of this case:\n%s", r.Combined)

	tag := harness.ProxyETag(t, ctx, s.bucket, "producer.bin")
	require.Containsf(t, tag, "-",
		"this case needs the proxy to answer a hyphenated entity tag for a %d byte object; it answered %q. "+
			"Either optimizations.streaming_segment_size moved above the payload, or the producer's answer changed",
		producerSize, tag)
	require.NotEqualf(t, harness.MD5File(t, src), strings.SplitN(tag, "-", 2)[0],
		"the entity tag's digest half equals the plaintext MD5, so this case is no longer about an opaque tag")

	verdicts.Record(t, harness.Case{
		ID:       "S2b",
		Endpoint: ep.name,
		What:     "put a 20 MiB file, one client request, so the proxy answers <hex>-N",
		Expect:   harness.Accepts,
	}, outcome(r), s.says(r))

	// And the two consequences of the hyphen that S1 and S4 are refused for.
	t.Run("ls_reports_the_plaintext_md5", func(t *testing.T) {
		// With a hyphenated tag s3cmd stops trusting it and reads the digest out
		// of its own x-amz-meta-s3cmd-attrs instead — which the proxy preserved.
		// With a bare 32-hex tag it reports that tag, i.e. a digest of bytes the
		// user never had (TestS5).
		ls := s.run(t, ctx, "--list-md5", "ls", s.uri("")+"/")
		require.Contains(t, ls.Stdout, harness.MD5File(t, src),
			"`ls --list-md5` did not report the plaintext MD5 for an object with a hyphenated entity tag")
	})

	t.Run("sync_transfers_nothing_on_a_second_run", func(t *testing.T) {
		dir := t.TempDir()
		harness.CopyFile(t, src, filepath.Join(dir, "producer.bin"))

		first := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB,
			"sync", dir+"/", s.uri("hyphen-sync")+"/")
		require.Truef(t, first.OK(), "the first sync failed:\n%s", first.Combined)
		require.Contains(t, first.Stdout, "upload:", "the first sync transferred nothing")

		second := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB,
			"sync", dir+"/", s.uri("hyphen-sync")+"/")
		require.Truef(t, second.OK(), "the second sync failed:\n%s", second.Combined)
		require.NotContains(t, second.Stdout, "upload:",
			"s3cmd re-uploaded an unchanged file whose entity tag carries a hyphen")
	})
}
