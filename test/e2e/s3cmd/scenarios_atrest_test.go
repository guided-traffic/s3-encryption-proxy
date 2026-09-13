//go:build e2e

package s3cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/test/e2e/harness"
)

// TestS7_EncryptionAtRest is main goal 1 for this client: whatever s3cmd wrote —
// including the object it reported as corrupted — the backend holds as
// ciphertext under the four metadata keys of ADR 0009.
//
// Read straight from MinIO with the backend credentials, never through the proxy
// (ADR 0019 D6).
func TestS7_EncryptionAtRest(t *testing.T) {
	ctx := preflight(t)

	for _, ep := range endpoints(t) {
		t.Run(ep.name, func(t *testing.T) {
			s := newSuite(t, ctx, "s7-"+ep.name, ep)
			c := seedCorpus(t, ctx, s)

			objects := harness.AssertEncryptedAtRest(t, ctx, harness.BackendClient(t), s.bucket, "corpus/", storedFormat(t))
			require.Len(t, objects, 2)

			for _, obj := range []struct{ key, src string }{
				{c.singleKey, c.singleSrc},
				{c.multiKey, c.multiSrc},
			} {
				harness.AssertStoredIsNotPlaintext(t, ctx, harness.BackendClient(t), s.bucket, obj.key, obj.src)
			}

			t.Run("the_clients_own_annotation_survives_the_round_trip", func(t *testing.T) {
				// x-amz-meta-s3cmd-attrs carries the plaintext MD5 and is the
				// only reason `info` and `get` verify at all. ADR 0009 D6 refuses
				// a client key inside the proxy's prefix and nothing else, so
				// preserving this one is the rule working, not an accident.
				prefix := harness.DemoStack(t).Get(t, "S3EP_METADATA_PREFIX")
				for _, obj := range objects {
					user := harness.UserMetadata(obj.Metadata, prefix)
					require.Containsf(t, user, "s3cmd-attrs",
						"object %s lost s3cmd's own attrs header; the stored keys are %v", obj.Key, user)
				}

				single := storedByKey(t, objects, c.singleKey)
				require.Containsf(t, single.Metadata["s3cmd-attrs"], "md5:"+harness.MD5File(t, c.singleSrc),
					"the preserved attrs header does not carry the plaintext MD5 s3cmd wrote")
			})

			t.Run("the_proxys_own_metadata_is_on_the_object_and_not_in_the_answer", func(t *testing.T) {
				// Both halves of ADR 0009 in one assertion: the four keys are on
				// the stored object, and a client listing never sees them.
				prefix := harness.DemoStack(t).Get(t, "S3EP_METADATA_PREFIX")
				single := storedByKey(t, objects, c.singleKey)
				_, ok := harness.MetadataValue(single.Metadata, prefix, "kek-fingerprint")
				require.True(t, ok, "the stored object carries no KEK fingerprint")

				info := s.run(t, ctx, "info", s.uri(c.singleKey))
				require.NotContains(t, info.Stdout, prefix,
					"the proxy's own metadata prefix reached the client")
			})

			verdicts.Want(t, harness.Case{
				ID:       "S7",
				Endpoint: ep.name,
				What:     "read every object s3cmd wrote straight from the backend",
				Wants:    "store every object as ciphertext under the four s3ep- keys of ADR 0009",
			}, true, "both objects are encrypted at rest and carry the segmented format id")
		})
	}
}

func storedByKey(t *testing.T, objects []harness.StoredObject, key string) harness.StoredObject {
	t.Helper()
	for _, o := range objects {
		if o.Key == key {
			return o
		}
	}
	t.Fatalf("no stored object with key %s", key)
	return harness.StoredObject{}
}
