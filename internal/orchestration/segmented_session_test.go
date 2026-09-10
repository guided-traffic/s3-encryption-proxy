package orchestration

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

const segShortBuffer = 64 << 20

// segPartSize is a part the backend will accept in the middle of an upload: a
// whole number of segments and at or above the 5 MiB minimum.
const segPartSize = 5 << 20

// segRegisteredSession prepares a session and files it, as the create handler does.
func segRegisteredSession(t *testing.T, m *Manager, uploadID string) (*SegmentedSession, error) {
	t.Helper()
	session, err := m.NewSegmentedSession("bucket/object", "bucket", nil)
	if err == nil {
		m.RegisterSegmentedSession(uploadID, session)
	}
	return session, err
}

// assembleSession plays a client-driven upload through the session and returns
// the stored object, exactly as the backend would hold it.
func assembleSession(t *testing.T, session *SegmentedSession, parts [][]byte) []byte {
	t.Helper()

	stored := make(map[int][]byte)
	for i, plaintext := range parts {
		partNumber := i + 1
		part, err := session.SealPart(partNumber, plaintext, segShortBuffer)
		require.NoError(t, err, "part %d", partNumber)
		if part == nil {
			// A short part waits for Complete.
			continue
		}
		body, err := part.Body()
		require.NoError(t, err)
		sealed, err := io.ReadAll(body)
		require.NoError(t, err)
		assert.Equal(t, part.StoredLen, int64(len(sealed)), "part %d declared length", partNumber)
		stored[partNumber] = sealed
		session.RecordETag(partNumber, "etag")
	}

	final, err := session.Complete()
	require.NoError(t, err)
	stored[final.PartNumber] = final.Body
	session.RecordETag(final.PartNumber, "etag-final")

	// Every stored part has to reach the list Complete is built from. A part the
	// table forgets is a part the backend drops.
	require.Equal(t, len(stored), len(session.PartNumbers()),
		"the part table lost a part the proxy stored")
	for _, number := range session.PartNumbers() {
		etag, ok := session.PartETag(number)
		require.True(t, ok, "part %d is not in the table", number)
		require.NotEmpty(t, etag, "part %d would be sent to Complete without an ETag", number)
	}

	var object bytes.Buffer
	for number := 1; number <= len(stored); number++ {
		body, ok := stored[number]
		require.True(t, ok, "part %d missing from the stored object", number)
		object.Write(body)
	}
	return object.Bytes()
}

func TestSegmentedSessionShortLastPart(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-1")
	require.NoError(t, err)

	// The shape every SDK uploader produces: equal parts and a short remainder.
	first := segPlaintext(t, segPartSize)
	second := segPlaintext(t, segPartSize)
	third := segPlaintext(t, 1234)

	object := assembleSession(t, session, [][]byte{first, second, third})

	want, err := dataencryption.CiphertextSize(int64(len(first) + len(second) + len(third)))
	require.NoError(t, err)
	assert.Equal(t, want, int64(len(object)))

	reader, err := m.OpenSegmented("bucket/object", session.Upload.Metadata(), bytes.NewReader(object))
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, append(append(append([]byte{}, first...), second...), third...), got)
}

// With no short part the trailer is a part of its own. S3 exempts only the last
// part from its minimum size, and that is exactly what this is.
func TestSegmentedSessionTrailerAsItsOwnPart(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-2")
	require.NoError(t, err)

	first := segPlaintext(t, segPartSize)
	second := segPlaintext(t, segPartSize)

	object := assembleSession(t, session, [][]byte{first, second})

	reader, err := m.OpenSegmented("bucket/object", session.Upload.Metadata(), bytes.NewReader(object))
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, first...), second...), got)
}

// A part re-uploaded with different content replaces its own term and nothing
// else, which is what makes an SDK retry harmless (ADR 0011).
func TestSegmentedSessionPartReupload(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-3")
	require.NoError(t, err)

	first := segPlaintext(t, segPartSize)
	replacement := segPlaintext(t, segPartSize)
	second := segPlaintext(t, segPartSize)

	// Part 1 arrives, is replaced, and only then does part 2 follow.
	_, err = session.SealPart(1, first, segShortBuffer)
	require.NoError(t, err)

	stored := make(map[int][]byte)
	part, err := session.SealPart(1, replacement, segShortBuffer)
	require.NoError(t, err)
	body, err := part.Body()
	require.NoError(t, err)
	stored[1], err = io.ReadAll(body)
	require.NoError(t, err)

	part, err = session.SealPart(2, second, segShortBuffer)
	require.NoError(t, err)
	body, err = part.Body()
	require.NoError(t, err)
	stored[2], err = io.ReadAll(body)
	require.NoError(t, err)

	final, err := session.Complete()
	require.NoError(t, err)
	stored[final.PartNumber] = final.Body

	var object bytes.Buffer
	for number := 1; number <= len(stored); number++ {
		object.Write(stored[number])
	}

	reader, err := m.OpenSegmented("bucket/object", session.Upload.Metadata(), bytes.NewReader(object.Bytes()))
	require.NoError(t, err)
	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, replacement...), second...), got,
		"the object must carry the replacement, not the first attempt")
}

func TestSegmentedSessionRefusesASecondShortPart(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-4")
	require.NoError(t, err)

	_, err = session.SealPart(1, segPlaintext(t, segPartSize), segShortBuffer)
	require.NoError(t, err)
	_, err = session.SealPart(2, segPlaintext(t, 100), segShortBuffer)
	require.NoError(t, err)

	_, err = session.SealPart(3, segPlaintext(t, 100), segShortBuffer)
	assert.ErrorIs(t, err, ErrShortPartAlreadyBuffered)
}

func TestSegmentedSessionRefusesABufferAboveTheLimit(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-5")
	require.NoError(t, err)

	_, err = session.SealPart(1, segPlaintext(t, 4096), 1024)
	assert.ErrorIs(t, err, ErrShortPartBufferFull)
}

// TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst: every uploader
// dispatches part 1 first, but nothing makes it arrive first, and a client that
// puts all its parts in flight at once regularly delivers the short last one
// ahead of the rest. The part size is inferred from the parts that could be
// middle parts (ADR 0011 D3), and the held part's offset follows from it at
// Complete - so the object is the same whichever order they land in.
func TestSegmentedSessionInfersThePartSizeWhateverArrivesFirst(t *testing.T) {
	full, tail := segPlaintext(t, segPartSize), segPlaintext(t, 100)

	open := func(t *testing.T, order []int) []byte {
		t.Helper()
		m := segManager(t)
		session, err := segRegisteredSession(t, m, "upload-order")
		require.NoError(t, err)

		stored := map[int][]byte{}
		for _, number := range order {
			plaintext := full
			if number == 3 {
				plaintext = tail
			}
			part, err := session.SealPart(number, plaintext, segShortBuffer)
			require.NoErrorf(t, err, "part %d", number)
			if part == nil {
				continue // held until Complete
			}
			body, err := part.Body()
			require.NoError(t, err)
			sealed, err := io.ReadAll(body)
			require.NoError(t, err)
			stored[number] = sealed
		}

		final, err := session.Complete()
		require.NoError(t, err)
		stored[final.PartNumber] = final.Body

		var object bytes.Buffer
		for number := 1; number <= len(stored); number++ {
			object.Write(stored[number])
		}
		reader, err := m.OpenSegmented("bucket/object", session.Upload.Metadata(), bytes.NewReader(object.Bytes()))
		require.NoError(t, err)
		got, err := io.ReadAll(reader)
		require.NoError(t, err)
		return got
	}

	want := append(append(append([]byte{}, full...), full...), tail...)
	assert.Equal(t, want, open(t, []int{1, 2, 3}), "parts in order")
	assert.Equal(t, want, open(t, []int{3, 1, 2}), "the short last part first")
	assert.Equal(t, want, open(t, []int{2, 3, 1}), "part 1 last")
}

func TestSegmentedSessionRefusesALayoutItCannotStore(t *testing.T) {
	m := segManager(t)

	t.Run("a gap in the part numbers", func(t *testing.T) {
		session, err := segRegisteredSession(t, m, "upload-6")
		require.NoError(t, err)

		_, err = session.SealPart(1, segPlaintext(t, segPartSize), segShortBuffer)
		require.NoError(t, err)
		_, err = session.SealPart(3, segPlaintext(t, segPartSize), segShortBuffer)
		require.NoError(t, err)

		_, err = session.Complete()
		assert.ErrorIs(t, err, ErrPartTableInvalid)
	})

	t.Run("a middle part smaller than the others", func(t *testing.T) {
		session, err := segRegisteredSession(t, m, "upload-7")
		require.NoError(t, err)

		// Only the last part may differ in size. A middle part that does puts
		// every segment after it at an offset the reader does not compute.
		_, err = session.SealPart(1, segPlaintext(t, 6<<20), segShortBuffer)
		require.NoError(t, err)
		_, err = session.SealPart(2, segPlaintext(t, segPartSize), segShortBuffer)
		require.NoError(t, err)
		_, err = session.SealPart(3, segPlaintext(t, segPartSize), segShortBuffer)
		require.NoError(t, err)

		_, err = session.Complete()
		assert.ErrorIs(t, err, ErrPartTableInvalid)
	})

	t.Run("no parts at all", func(t *testing.T) {
		session, err := segRegisteredSession(t, m, "upload-8")
		require.NoError(t, err)

		_, err = session.Complete()
		assert.ErrorIs(t, err, ErrPartTableInvalid)
	})
}

func TestSegmentedSessionLifecycle(t *testing.T) {
	m := segManager(t)

	_, err := segRegisteredSession(t, m, "upload-9")
	require.NoError(t, err)

	_, ok := m.SegmentedSession("upload-9")
	assert.True(t, ok)

	m.CloseSegmentedSession("upload-9")
	_, ok = m.SegmentedSession("upload-9")
	assert.False(t, ok, "an aborted or completed upload must not stay in memory")
}
