//go:build e2e

package rclone

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestR7_EncryptionAtRest is main goal 1 for this client: whatever rclone wrote,
// the backend holds ciphertext under the four metadata keys of ADR 0009.
//
// Read straight from MinIO with the backend credentials — never through the
// proxy — which is what makes it an assertion about storage rather than about
// the read path (ADR 0019 D6).
func TestR7_EncryptionAtRest(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "r7-"+ep.name)
			c := seedCorpus(t, ctx, s, ep)

			objects := harness.AssertEncryptedAtRest(t, ctx, harness.BackendClient(t), s.bucket, "corpus/", storedFormat(t))
			require.Len(t, objects, 2, "the corpus is one single-part and one multipart object")

			for _, obj := range []struct{ key, src string }{
				{c.singleKey, c.singleSrc},
				{c.multiKey, c.multiSrc},
			} {
				harness.AssertStoredIsNotPlaintext(t, ctx, harness.BackendClient(t), s.bucket, obj.key, obj.src)
			}

			t.Run("the_clients_own_annotation_survives_the_round_trip", func(t *testing.T) {
				// rclone stores the plaintext MD5 as X-Amz-Meta-Md5chksum on a
				// multipart upload and reads it back on every listing. It is the
				// only reason R4a and R5a pass at all, so the proxy preserving it
				// is load-bearing, not incidental (ADR 0009 D6 refuses only the
				// proxy's own prefix).
				prefix := harness.DemoStack(t).Get(t, "S3EP_METADATA_PREFIX")
				for _, obj := range objects {
					if obj.Key != c.multiKey {
						continue
					}
					user := harness.UserMetadata(obj.Metadata, prefix)
					require.Containsf(t, user, "md5chksum",
						"rclone's own md5chksum annotation did not survive; the stored keys are %v", user)
					// base64, not hex: that is the spelling rclone writes.
					require.Equal(t, harness.MD5Base64File(t, c.multiSrc), user["md5chksum"],
						"the preserved annotation is not the plaintext MD5 rclone wrote")
				}
			})

			verdicts.Record(t, harness.Case{
				ID:       "R7",
				Endpoint: ep.name,
				What:     "every object rclone wrote is ciphertext at rest under the four s3ep- keys",
				Expect:   harness.Accepts,
			}, harness.Accepts, "both objects are encrypted at rest and carry the segmented format id")
		})
	}
}
