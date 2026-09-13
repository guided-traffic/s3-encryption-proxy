//go:build e2e

package s3cmd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

const (
	// singlePartSize is below both s3cmd's own multipart threshold and
	// optimizations.streaming_segment_size, so one PUT reaches the proxy.
	singlePartSize = 1 << 20 // 1 MiB
	// multiPartSize with a 5 MiB chunk is three client parts.
	multiPartSize = 12 << 20 // 12 MiB
	// producerSize is above optimizations.streaming_segment_size (12 MiB), so a
	// single client PUT becomes the proxy's internal multipart producer.
	producerSize = 20 << 20 // 20 MiB
	// producerChunkMB keeps s3cmd from splitting producerSize itself.
	producerChunkMB = "200"
)

// TestS1_SinglePartPut: a user puts a file with a configuration written the
// documented way and no flags. It has to work, and the exit code has to tell
// the truth about what was stored.
func TestS1_SinglePartPut(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s1-"+ep.name, ep)
			src := harness.WriteRandomFile(t, s.work, "one-part.bin", singlePartSize)

			r := s.run(t, ctx, "put", src, s.uri("small.bin"))

			verdicts.Want(t, harness.Case{
				ID:       "S1",
				Endpoint: ep.name,
				What:     "put a 1 MiB file, defaults",
				Wants: "accept the upload. s3cmd compares the entity tag of every PUT response with the MD5 " +
					"of the bytes it sent, so the tag a single-request PUT answers must not be a digest of the " +
					"STORED bytes; it has no option that switches the check off (ADR 0010 D12)",
			}, r.OK(), s.says(r))

			// A non-zero exit while the object is in the bucket is its own
			// defect: a caller that trusts the exit code concludes nothing was
			// written. Asserted after the verdict so it is reached once S1 passes.
			stored := harness.ListStored(t, ctx, harness.BackendClient(t), s.bucket, "small.bin")
			require.Len(t, stored, 1, "the upload reported success but stored nothing")
			require.Equal(t, harness.SHA256File(t, src),
				harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, "small.bin")),
				"what was stored is not what s3cmd sent")
		})
	}
}

// TestS2_MultipartPut: the same file in parts. s3cmd checks the entity tag of
// every UploadPart response against that part's MD5, so this is the case no
// object-level answer can satisfy — the upload is decided part by part and never
// reaches CompleteMultipartUpload.
func TestS2_MultipartPut(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s2-"+ep.name, ep)
			src := harness.WriteRandomFile(t, s.work, "multi-part.bin", multiPartSize)

			r := s.run(t, ctx, "--multipart-chunk-size-mb=5", "put", src, s.uri("big.bin"))

			// Whatever the verdict, the client must not be left holding an upload
			// it cannot see or abort (S6b). Checked before the assertion so a
			// failing case still reports it.
			open := harness.OpenUploads(t, ctx, s.bucket)

			verdicts.Want(t, harness.Case{
				ID:       "S2",
				Endpoint: ep.name,
				What:     "put a 12 MiB file in 5 MiB parts",
				Wants: "accept the upload. Under an encrypting provider a part's entity tag is the backend's " +
					"MD5 of the SEALED part, so s3cmd is refused on the first part and never reaches " +
					"CompleteMultipartUpload — no object-level entity tag can answer this, the rule has to " +
					"cover a part's answer too (ADR 0010 D12)",
			}, r.OK(), s.says(r))

			require.Emptyf(t, open, "the upload left %d multipart upload(s) open on the backend", len(open))
			require.Equal(t, harness.SHA256File(t, src),
				harness.SHA256Bytes(harness.ReadViaProxy(t, ctx, s.bucket, "big.bin")),
				"what was stored is not what s3cmd sent")
		})
	}
}

// TestS2b_ProducerObject: an object above the single-request ceiling goes up in
// one client request and through the proxy's internal multipart producer. It has
// to work, and its own digest has to survive the round trip.
//
// It is worth keeping beside S1 and S2 because the only difference between them
// is the shape of the answer: s3cmd skips its check whenever the entity tag
// carries a hyphen, which is what the producer's `<hex>-N` happens to do. That
// measurement is what says an entity-tag marker would answer S1 — and, since S2
// is decided per part, that it has to reach a part's answer as well.
func TestS2b_ProducerObject(t *testing.T) {
	ctx := preflight(t)
	ep := endpoints(t)[1] // TLS

	s := newSuite(t, ctx, "s2b", ep)
	src := harness.WriteRandomFile(t, s.work, "producer.bin", producerSize)

	r := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "put", src, s.uri("producer.bin"))

	verdicts.Want(t, harness.Case{
		ID:       "S2b",
		Endpoint: ep.name,
		What:     "put a 20 MiB file in one client request, above the single-request ceiling",
		Wants:    "accept the upload",
	}, r.OK(), s.says(r))

	t.Run("ls_reports_the_plaintext_md5", func(t *testing.T) {
		ls := s.run(t, ctx, "--list-md5", "ls", s.uri("")+"/")
		want := harness.MD5File(t, src)
		verdicts.Want(t, harness.Case{
			ID:       "S2c",
			Endpoint: ep.name,
			What:     "ls --list-md5 of that object",
			Wants:    "report the plaintext MD5, which s3cmd preserved in its own x-amz-meta-s3cmd-attrs",
		}, ls.OK() && lineFor(ls.Stdout, "producer.bin") != "" &&
			containsStr(lineFor(ls.Stdout, "producer.bin"), want), s.says(ls))
	})

	t.Run("sync_settles", func(t *testing.T) {
		dir := t.TempDir()
		harness.CopyFile(t, src, filepath.Join(dir, "producer.bin"))

		first := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "sync", dir+"/", s.uri("hyphen-sync")+"/")
		require.Truef(t, first.OK(), "the first sync failed:\n%s", first.Combined)

		second := s.run(t, ctx, "--multipart-chunk-size-mb="+producerChunkMB, "sync", dir+"/", s.uri("hyphen-sync")+"/")
		verdicts.Want(t, harness.Case{
			ID:       "S2d",
			Endpoint: ep.name,
			What:     "sync that object up twice",
			Wants:    "transfer nothing on the second run",
		}, second.OK() && !containsStr(second.Stdout, "upload:"), s.says(second))
	})
}
