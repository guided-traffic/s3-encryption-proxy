//go:build e2e

package harness

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// Format is the stored contract a suite asserts against: the proxy's exclusive
// metadata prefix and the identifier the stored format names.
//
// It is a parameter and not a constant here on purpose. Each suite spells its
// own values out and passes them in, so the assertion is shared while the claim
// stays the suite's own: a suite is a black-box client, the identifier is part
// of the stored format's contract, and a silent change to it must fail in every
// suite separately rather than being edited once in this package.
type Format struct {
	MetadataPrefix string
	ID             string
}

// AssertEncryptedAtRest is main goal 1 of this product, asserted the way
// ADR 0019 D6 requires: read straight from the backend, never through the proxy.
//
// Every object under prefix must carry the four metadata keys of ADR 0009 with
// the format's identifier. An empty prefix scan is a failed scan, not a passing
// one: if nothing was written, the case proved nothing (ADR 0019 D12).
//
// client must talk to the backend directly. It is a parameter because the suites
// that share this assertion reach their backend in different ways — the client
// suites over the demo stack's published port, the Velero suite over a NodePort
// of its kind cluster.
func AssertEncryptedAtRest(t *testing.T, ctx context.Context, client *s3.Client,
	bucket, prefix string, format Format) []StoredObject {
	t.Helper()

	objects := ListStored(t, ctx, client, bucket, prefix)
	require.NotEmptyf(t, objects, "nothing is stored under %s/%s, so nothing was checked", bucket, prefix)

	for _, obj := range objects {
		if obj.Size == 0 {
			continue // an empty object has no ciphertext to describe
		}

		algo, ok := MetadataValue(obj.Metadata, format.MetadataPrefix, "dek-algorithm")
		require.Truef(t, ok, "object %s (%d bytes) has no %sdek-algorithm, so it was stored unencrypted: %v",
			obj.Key, obj.Size, format.MetadataPrefix, obj.Metadata)
		require.Equalf(t, format.ID, algo, "object %s names an unexpected stored format %q", obj.Key, algo)

		_, ok = MetadataValue(obj.Metadata, format.MetadataPrefix, "encrypted-dek")
		require.Truef(t, ok, "object %s has no wrapped data key", obj.Key)

		_, ok = MetadataValue(obj.Metadata, format.MetadataPrefix, "kek-algorithm")
		require.Truef(t, ok, "object %s has no KEK algorithm", obj.Key)

		_, ok = MetadataValue(obj.Metadata, format.MetadataPrefix, "kek-fingerprint")
		require.Truef(t, ok, "object %s has no KEK fingerprint, so it could never be decrypted", obj.Key)
	}

	t.Logf("at rest: %d objects under %s/%s carry %s* and the %s format",
		len(objects), bucket, prefix, format.MetadataPrefix, format.ID)
	return objects
}

// AssertStoredIsNotPlaintext compares one stored object against the file the
// client sent: the two must differ, and the stored object must be longer,
// because the segment chain adds a tag per segment and a sealed trailer.
func AssertStoredIsNotPlaintext(t *testing.T, ctx context.Context, client *s3.Client,
	bucket, key, sourcePath string) {
	t.Helper()
	stored := ReadStored(t, ctx, client, bucket, key)
	plainSum := SHA256File(t, sourcePath)
	storedSum := SHA256Bytes(stored)

	require.NotEqualf(t, plainSum, storedSum,
		"object %s is byte-identical at rest and at the source: nothing was encrypted", key)

	info, err := statSize(sourcePath)
	require.NoError(t, err)
	require.Greaterf(t, int64(len(stored)), info,
		"object %s is stored in %d bytes for a %d byte plaintext, which no segment chain can produce",
		key, len(stored), info)
}

func statSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}
