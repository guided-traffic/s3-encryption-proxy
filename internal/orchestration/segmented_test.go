package orchestration

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

func segManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(OrcMetaProviderConfig("seg-aes", OrcMetaAESProvider("seg-aes", OrcMetaAESKeyB64)))
	require.NoError(t, err)
	return m
}

func segPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	return buf
}

func TestSegmentedWriteRoundTrip(t *testing.T) {
	sizes := []int{0, 1, dataencryption.SegmentSize - 1, dataencryption.SegmentSize, 3*dataencryption.SegmentSize + 17}

	for _, size := range sizes {
		m := segManager(t)
		plaintext := segPlaintext(t, size)

		write, err := m.NewSegmentedWrite("bucket/object", bytes.NewReader(plaintext), int64(size), nil)
		require.NoError(t, err, "size %d", size)

		stored, err := io.ReadAll(write.Body)
		require.NoError(t, err)
		assert.Equal(t, write.ContentLength, int64(len(stored)),
			"size %d: the declared Content-Length must be what the backend receives", size)

		reader, err := m.OpenSegmented("bucket/object", write.Metadata, bytes.NewReader(stored))
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got, "size %d", size)
	}
}

func TestSegmentedWriteMetadataSet(t *testing.T) {
	m := segManager(t)

	write, err := m.NewSegmentedWrite("bucket/object", bytes.NewReader(nil), 0,
		map[string]string{"owner": "hans"})
	require.NoError(t, err)

	assert.Equal(t, dataencryption.FormatID, write.Metadata["s3ep-dek-algorithm"])
	assert.NotEmpty(t, write.Metadata["s3ep-encrypted-dek"])
	assert.NotEmpty(t, write.Metadata["s3ep-kek-fingerprint"])
	assert.Equal(t, "aes", write.Metadata["s3ep-kek-algorithm"])
	assert.Equal(t, "hans", write.Metadata["owner"], "user metadata must survive")

	// The two keys of the old format are gone; a reader that still expects them
	// would silently look at nothing.
	assert.NotContains(t, write.Metadata, "s3ep-aes-iv")
	assert.NotContains(t, write.Metadata, "s3ep-hmac")
}

// The object key is authenticated, so a chain served under another name must not
// open. This is the defence against a backend that serves object A's bytes as B.
func TestSegmentedReadRefusesAnotherObjectsBytes(t *testing.T) {
	m := segManager(t)
	plaintext := segPlaintext(t, 4096)

	write, err := m.NewSegmentedWrite("bucket/a", bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)

	reader, err := m.OpenSegmented("bucket/b", write.Metadata, bytes.NewReader(stored))
	require.NoError(t, err, "the key is only bound at decryption time")
	_, err = io.ReadAll(reader)
	require.Error(t, err)
}

func TestSegmentedOpenRefusesForeignObjects(t *testing.T) {
	m := segManager(t)

	cases := map[string]map[string]string{
		"no metadata at all":  {},
		"no encrypted dek":    {"s3ep-dek-algorithm": dataencryption.FormatID},
		"another format":      {"s3ep-dek-algorithm": "aes-ctr", "s3ep-encrypted-dek": "Zm9v"},
		"no algorithm at all": {"s3ep-encrypted-dek": "Zm9v"},
	}

	for name, metadata := range cases {
		t.Run(name, func(t *testing.T) {
			assert.False(t, m.IsSegmentedObject(metadata))

			_, err := m.OpenSegmented("bucket/object", metadata, bytes.NewReader(nil))
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrForeignObject)
		})
	}
}

// TestSegmentedOpenRefusesAnEditedKeyWrap: a wrap that does not authenticate is
// its own answer, not a generic failure. It is permanent - the wrap will not
// unwrap on a later attempt either - so the read path has to be able to tell it
// apart from something worth retrying.
func TestSegmentedOpenRefusesAnEditedKeyWrap(t *testing.T) {
	m := segManager(t)

	write, err := m.NewSegmentedWrite("bucket/object", bytes.NewReader(segPlaintext(t, 100)), 100, nil)
	require.NoError(t, err)
	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)

	// One bit of the wrapped key, which is what a backend can edit without
	// touching a sealed byte of the object.
	metadata := make(map[string]string, len(write.Metadata))
	for key, value := range write.Metadata {
		metadata[key] = value
	}
	wrapped, err := base64.StdEncoding.DecodeString(metadata["s3ep-encrypted-dek"])
	require.NoError(t, err)
	wrapped[len(wrapped)-1] ^= 0x01
	metadata["s3ep-encrypted-dek"] = base64.StdEncoding.EncodeToString(wrapped)

	require.True(t, m.IsSegmentedObject(metadata), "the object still names this format")
	_, err = m.OpenSegmented("bucket/object", metadata, bytes.NewReader(stored))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyMaterialUnreadable)
	assert.NotErrorIs(t, err, ErrForeignObject, "this object is the proxy's own; only its key wrap is not")
}

// A multipart upload must produce the same bytes as a single write: same format,
// same reader, no rewrite afterwards.
func TestSegmentedUploadRoundTrip(t *testing.T) {
	const partSize = 2 * dataencryption.SegmentSize
	m := segManager(t)
	plaintext := segPlaintext(t, 5*dataencryption.SegmentSize+123)

	upload, err := m.NewSegmentedUpload("bucket/object", nil)
	require.NoError(t, err)
	assert.Equal(t, dataencryption.FormatID, upload.Metadata()["s3ep-dek-algorithm"])

	var stored bytes.Buffer
	var sum dataencryption.Checksum

	for offset := 0; offset < len(plaintext); offset += partSize {
		end := offset + partSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		part, err := upload.SealPart(int64(offset), plaintext[offset:end], end == len(plaintext))
		require.NoError(t, err)

		body, err := part.Body()
		require.NoError(t, err)
		n, err := io.Copy(&stored, body)
		require.NoError(t, err)
		assert.Equal(t, part.StoredLen, n, "a part's declared length must be what it writes")

		sum = sum.Append(part.Sum)
	}

	trailer, err := upload.Trailer(sum)
	require.NoError(t, err)
	stored.Write(trailer)

	want, err := dataencryption.CiphertextSize(int64(len(plaintext)))
	require.NoError(t, err)
	assert.Equal(t, want, int64(stored.Len()))

	reader, err := m.OpenSegmented("bucket/object", upload.Metadata(), bytes.NewReader(stored.Bytes()))
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// A part is re-sealed from the retained plaintext, so a backend that fails
// mid-part is retried without asking the client for the same bytes again
// (ADR 0024 D5).
func TestSegmentedPartRetryReSealsTheSamePlaintext(t *testing.T) {
	m := segManager(t)
	plaintext := segPlaintext(t, dataencryption.SegmentSize)

	upload, err := m.NewSegmentedUpload("bucket/object", nil)
	require.NoError(t, err)

	part, err := upload.SealPart(0, plaintext, true)
	require.NoError(t, err)

	first, err := part.Body()
	require.NoError(t, err)
	firstBytes, err := io.ReadAll(first)
	require.NoError(t, err)

	second, err := part.Body()
	require.NoError(t, err)
	secondBytes, err := io.ReadAll(second)
	require.NoError(t, err)

	assert.Equal(t, len(firstBytes), len(secondBytes))
	assert.NotEqual(t, firstBytes, secondBytes, "a retry draws fresh nonces")

	// Either attempt reads back as the same object.
	for _, attempt := range [][]byte{firstBytes, secondBytes} {
		trailer, err := upload.Trailer(part.Sum)
		require.NoError(t, err)

		reader, err := m.OpenSegmented("bucket/object", upload.Metadata(), bytes.NewReader(append(attempt, trailer...)))
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, plaintext, got)
	}
}

func TestSegmentedPartRefusesLayoutsTheReaderCannotOpen(t *testing.T) {
	m := segManager(t)
	upload, err := m.NewSegmentedUpload("bucket/object", nil)
	require.NoError(t, err)

	_, err = upload.SealPart(1, make([]byte, dataencryption.SegmentSize), true)
	assert.ErrorIs(t, err, dataencryption.ErrNotWellFormed, "an offset inside a segment cannot be sealed")

	_, err = upload.SealPart(0, make([]byte, dataencryption.SegmentSize-1), false)
	assert.ErrorIs(t, err, dataencryption.ErrPartNotAligned, "a middle part may not end inside a segment")
}

func TestSegmentedRangeRead(t *testing.T) {
	m := segManager(t)
	plaintext := segPlaintext(t, 3*dataencryption.SegmentSize+500)

	write, err := m.NewSegmentedWrite("bucket/object", bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)

	ranges := []struct{ offset, length int64 }{
		{0, 10},
		{dataencryption.SegmentSize - 5, 10},
		{dataencryption.SegmentSize, dataencryption.SegmentSize},
		{2*dataencryption.SegmentSize + 7, 1000},
		{int64(len(plaintext)) - 1, 1},
	}

	for _, r := range ranges {
		window, err := PlanRange(r.offset, r.length, int64(len(plaintext)))
		require.NoError(t, err)

		body := stored[window.CiphertextOffset : window.CiphertextOffset+window.CiphertextLength]
		reader, err := m.OpenSegmentedRange("bucket/object", write.Metadata, bytes.NewReader(body), window)
		require.NoError(t, err)

		got, err := io.ReadAll(reader)
		require.NoError(t, err, "range %d+%d", r.offset, r.length)
		assert.Equal(t, plaintext[r.offset:r.offset+r.length], got, "range %d+%d", r.offset, r.length)
	}
}

// What HEAD answers with, since ADR 0003 D14: the trailer, read from the last 40
// stored bytes. The length it authenticates is the one the client is told, and
// the checksum it carries is served as x-amz-checksum-crc32c - the stored length
// is only the backend's word about itself (ADR 0001).
//
// The test used to convert the stored length and stop there, which is the
// pre-D14 HEAD: it never opened the trailer it is named for, so the whole
// mechanism HEAD now rests on was pinned by nothing here.
func TestSegmentedTrailerAnswersHead(t *testing.T) {
	m := segManager(t)
	plaintext := segPlaintext(t, dataencryption.SegmentSize+42)

	write, err := m.NewSegmentedWrite("bucket/object", bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)

	// The 40 bytes HEAD asks for, and nothing else.
	trailer := stored[len(stored)-dataencryption.TrailerSize:]
	sum, err := m.OpenSegmentedTrailer("bucket/object", write.Metadata, trailer)
	require.NoError(t, err, "the object's own trailer must open under its metadata")
	assert.Equal(t, int64(len(plaintext)), sum.Length,
		"the length HEAD reports is the authenticated one")
	assert.Equal(t, dataencryption.NewChecksum(plaintext).Value, sum.Value,
		"and the checksum it serves is the CRC32C of the whole plaintext")

	// The unauthenticated conversion has to agree with it. Where they disagree,
	// the read path refuses the object rather than choosing one (ADR 0003 D14).
	fromStored, err := PlaintextSize(int64(len(stored)))
	require.NoError(t, err)
	assert.Equal(t, sum.Length, fromStored)
	assert.Equal(t, write.ContentLength, int64(len(stored)))

	// A trailer from another object does not open under this one's key.
	other, err := m.NewSegmentedWrite("bucket/other", bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	otherStored, err := io.ReadAll(other.Body)
	require.NoError(t, err)
	_, err = m.OpenSegmentedTrailer("bucket/object", write.Metadata,
		otherStored[len(otherStored)-dataencryption.TrailerSize:])
	assert.ErrorIs(t, err, dataencryption.ErrCorrupt)
}

// ADR 0002 D1: one data key per object, never reused. Nothing pinned it before:
// two objects written under a shared key still produce different stored bytes
// (fresh segment nonces) and different wrapped keys (fresh wrap nonces), so every
// existing assertion passes with the key hoisted to a package-level constant.
// The only way to see it is to unwrap what was stored and compare the keys.
func TestSegmentedWriteDrawsAFreshDataKeyPerObject(t *testing.T) {
	m := segManager(t)

	// The same object key twice as well: a re-upload of one object must not
	// reuse the key the previous version was sealed under either.
	keys := []string{"bucket/first", "bucket/second", "bucket/first"}

	seen := make(map[string]string, len(keys))
	for i, objectKey := range keys {
		write, err := m.NewSegmentedWrite(objectKey, bytes.NewReader(segPlaintext(t, 1024)), 1024, nil)
		require.NoError(t, err)
		_, err = io.ReadAll(write.Body)
		require.NoError(t, err)

		wrapped, err := m.metadataManager.GetEncryptedDEK(write.Metadata)
		require.NoError(t, err)
		fingerprint, err := m.metadataManager.GetFingerprint(write.Metadata)
		require.NoError(t, err)

		dek, err := m.providerManager.DecryptDEK(wrapped, fingerprint, objectKey)
		require.NoError(t, err)
		require.Len(t, dek, dekSize)

		fresh := base64.StdEncoding.EncodeToString(dek)
		if previous, ok := seen[fresh]; ok {
			t.Fatalf("write %d of %q reused the data key of %q", i+1, objectKey, previous)
		}
		seen[fresh] = objectKey
	}
	assert.Len(t, seen, len(keys), "every write draws its own data key")
}

// ADR 0003 D5: the bucket is not in the associated data. An object is bound to
// its key and to nothing else, so the same object key under two buckets opens
// either object's segments - and that is the decision, not an oversight: the
// proxy sees one bucket namespace and a copy between buckets would otherwise
// have to be re-encrypted.
func TestSegmentedAssociatedDataDoesNotBindTheBucket(t *testing.T) {
	m := segManager(t)
	plaintext := segPlaintext(t, 100)

	write, err := m.NewSegmentedWrite("shared/object", bytes.NewReader(plaintext), int64(len(plaintext)), nil)
	require.NoError(t, err)
	stored, err := io.ReadAll(write.Body)
	require.NoError(t, err)

	// The handlers pass the object key alone; a bucket-qualified name is a
	// different string and must not open it.
	opened, err := m.OpenSegmented("shared/object", write.Metadata, bytes.NewReader(stored))
	require.NoError(t, err)
	got, err := io.ReadAll(opened)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)

	qualified, err := m.OpenSegmented("other-bucket/shared/object", write.Metadata, bytes.NewReader(stored))
	require.NoError(t, err)
	_, err = io.ReadAll(qualified)
	assert.ErrorIs(t, err, dataencryption.ErrCorrupt,
		"the object key is in the associated data, so a different string must not open it")
}
