package orchestration

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

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

// A last part larger than the whole short-part budget can never be held, so it
// is refused outright: no other upload finishing makes room for it, and the
// back-pressure answer would have an SDK retry it to its own attempt limit
// (ADR 0011 D5).
func TestSegmentedSessionRefusesABufferAboveTheLimit(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-5")
	require.NoError(t, err)

	_, err = session.SealPart(1, segPlaintext(t, 4096), 1024)
	assert.ErrorIs(t, err, ErrShortPartTooLarge)
	assert.Zero(t, m.ShortPartBytesHeld(), "a refused part must hold no budget")
}

// The budget is the process's, not the session's: what one upload holds is not
// available to the next. Without that accounting the configured cap bounds one
// upload and the real ceiling is the cap times the number of uploads a client
// chooses to open (ADR 0011 D5).
func TestSegmentedSessionShortPartBudgetIsSharedAcrossSessions(t *testing.T) {
	m := segManager(t)
	m.config.Optimizations.MultipartShortPartBufferSize = 6000

	first, err := segRegisteredSession(t, m, "upload-a")
	require.NoError(t, err)
	second, err := segRegisteredSession(t, m, "upload-b")
	require.NoError(t, err)

	_, err = first.SealPart(1, segPlaintext(t, 4000), m.ShortPartBufferSize())
	require.NoError(t, err)
	assert.Equal(t, int64(4000), m.ShortPartBytesHeld())

	// It would fit on its own, and it does not fit beside the first.
	_, err = second.SealPart(1, segPlaintext(t, 4000), m.ShortPartBufferSize())
	assert.ErrorIs(t, err, ErrShortPartBufferFull,
		"back pressure, not a refusal: the first upload will finish")
	assert.Equal(t, int64(4000), m.ShortPartBytesHeld())

	// The first upload ends, however it ends, and the room comes back.
	m.CloseSegmentedSession("upload-a")
	assert.Zero(t, m.ShortPartBytesHeld())

	_, err = second.SealPart(1, segPlaintext(t, 4000), m.ShortPartBufferSize())
	require.NoError(t, err)
	assert.Equal(t, int64(4000), m.ShortPartBytesHeld())
}

// Every path that forgets a session gives its buffer back, or a proxy that has
// swept idle uploads for a while can no longer hold a short part at all.
func TestSegmentedSessionShortPartBudgetIsReleasedOnEveryEnding(t *testing.T) {
	endings := map[string]func(t *testing.T, m *Manager, uploadID string){
		"the client aborts or completes": func(_ *testing.T, m *Manager, uploadID string) {
			m.CloseSegmentedSession(uploadID)
		},
		"the idle sweep ends it": func(t *testing.T, m *Manager, _ string) {
			m.SetMultipartAbandoner(func(context.Context, string, string, string) error { return nil })
			require.Equal(t, 1, m.CleanupExpiredSegmentedSessions(context.Background(), 0))
		},
		"shutdown sweeps it": func(t *testing.T, m *Manager, _ string) {
			m.SetMultipartAbandoner(func(context.Context, string, string, string) error { return nil })
			ended, left := m.AbandonAllSessions(context.Background())
			require.Equal(t, 1, ended)
			require.Zero(t, left)
		},
	}

	for name, end := range endings {
		t.Run(name, func(t *testing.T) {
			m := segManager(t)
			session, err := segRegisteredSession(t, m, "upload-x")
			require.NoError(t, err)

			_, err = session.SealPart(1, segPlaintext(t, 4096), m.ShortPartBufferSize())
			require.NoError(t, err)
			require.Equal(t, int64(4096), m.ShortPartBytesHeld())

			end(t, m, "upload-x")
			assert.Zero(t, m.ShortPartBytesHeld())
		})
	}
}

// A client may send any part number again. When a part that was being held comes
// back large enough to be stored where it lies, the held copy is no longer part
// of the object: leaving it would have Complete store those bytes under that
// number while the part table describes these - an object that stores cleanly
// and fails authentication on every read.
func TestSegmentedSessionHeldPartReplacedByAStorableOne(t *testing.T) {
	m := segManager(t)
	session, err := segRegisteredSession(t, m, "upload-replace")
	require.NoError(t, err)

	// Part 2 arrives short and is held.
	_, err = session.SealPart(2, segPlaintext(t, 4096), m.ShortPartBufferSize())
	require.NoError(t, err)
	require.Equal(t, int64(4096), m.ShortPartBytesHeld())

	// Part 1, then part 2 again - this time large enough to be stored where it
	// lies, which makes it a middle part and not the object's last.
	_, err = session.SealPart(1, segPlaintext(t, segPartSize), m.ShortPartBufferSize())
	require.NoError(t, err)
	part, err := session.SealPart(2, segPlaintext(t, segPartSize), m.ShortPartBufferSize())
	require.NoError(t, err)
	require.NotNil(t, part, "a part that covers whole segments is stored where it lies")
	assert.Zero(t, m.ShortPartBytesHeld(), "the superseded copy must be given back")

	// The completion is the trailer alone: no part is being held any more.
	final, err := session.Complete()
	require.NoError(t, err)
	assert.Equal(t, 3, final.PartNumber, "the trailer follows the two stored parts")
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

// ADR 0028 D1: the idle clock measures from the last part an upload received,
// not from when it started. The clock is only worth anything if every way a part
// can arrive moves it - and nothing pinned that: emptying touchLocked() left the
// whole suite green, because the one test of the clock wrote lastTouched by hand
// and so proved only that the sweep compares against that field.
//
// Each case below ages the session past the timeout, lets a part arrive the way
// that case's client would, and then runs the real sweep.
func TestSegmentedSessionEveryPartMovesTheIdleClock(t *testing.T) {
	const idle = time.Hour

	arrivals := map[string]func(t *testing.T, m *Manager, s *SegmentedSession){
		"a part the proxy holds": func(t *testing.T, m *Manager, s *SegmentedSession) {
			_, err := s.SealPart(1, segPlaintext(t, 4096), m.ShortPartBufferSize())
			require.NoError(t, err)
		},
		"a part the proxy streams": func(t *testing.T, _ *Manager, s *SegmentedSession) {
			_, err := s.SealStreamingPart(1, segPartSize, bytes.NewReader(segPlaintext(t, segPartSize)))
			require.NoError(t, err)
		},
		"a streamed part being recorded": func(_ *testing.T, _ *Manager, s *SegmentedSession) {
			s.RecordStreamedPart(1, 0, dataencryption.NewChecksum(nil))
		},
		"the backend answering with an entity tag": func(_ *testing.T, _ *Manager, s *SegmentedSession) {
			s.RecordETag(1, "an-etag")
		},
	}

	for name, arrive := range arrivals {
		t.Run(name, func(t *testing.T) {
			m := segManager(t)
			m.SetMultipartAbandoner(func(context.Context, string, string, string) error { return nil })
			session, err := segRegisteredSession(t, m, "upload-idle")
			require.NoError(t, err)

			// Long enough ago that the next sweep would end it.
			session.mu.Lock()
			session.lastTouched = time.Now().Add(-2 * idle)
			session.mu.Unlock()
			require.Greater(t, session.idleFor(), idle, "the fixture must start past the timeout")

			arrive(t, m, session)

			assert.Zero(t, m.CleanupExpiredSegmentedSessions(context.Background(), idle),
				"an upload that just received a part must not be abandoned under its client")
			_, alive := m.SegmentedSession("upload-idle")
			assert.True(t, alive, "the session must still be there")
		})
	}

	// The other half: an upload nobody is feeding is ended, whatever it is
	// holding, and the backend is told.
	t.Run("an upload nobody feeds is ended at the backend", func(t *testing.T) {
		m := segManager(t)
		var abandoned []string
		m.SetMultipartAbandoner(func(_ context.Context, bucket, key, uploadID string) error {
			abandoned = append(abandoned, bucket+"/"+key+"#"+uploadID)
			return nil
		})
		session, err := segRegisteredSession(t, m, "upload-stale")
		require.NoError(t, err)

		_, err = session.SealPart(1, segPlaintext(t, 4096), m.ShortPartBufferSize())
		require.NoError(t, err)

		session.mu.Lock()
		session.lastTouched = time.Now().Add(-2 * idle)
		session.mu.Unlock()

		require.Equal(t, 1, m.CleanupExpiredSegmentedSessions(context.Background(), idle))
		assert.Equal(t, []string{"bucket/bucket/object#upload-stale"}, abandoned,
			"the upload is ended at the backend, not merely forgotten (ADR 0028)")
		assert.Zero(t, m.ShortPartBytesHeld())
	})
}

// A last part that is itself segment-aligned and at or above 5 MiB is
// indistinguishable from a middle part while it is arriving, so the proxy seals
// it where the part size it has seen so far puts it. When it arrives before the
// larger parts, that offset is wrong and the segment indices sealed into it are
// wrong with it - and nothing can repair that at Complete, because the index is
// in the associated data of every segment it carries.
//
// What the part table check of ADR 0011 D3 is for is to turn that into a refusal
// rather than an object that stores cleanly and reads back as an authentication
// failure. Nothing reached it: every order in the inference test above ends in
// the same unaligned 100-byte tail, which is the case that works.
func TestSegmentedSessionAlignedLastPartOutOfOrderIsRefused(t *testing.T) {
	const middle = 10 << 20 // two parts of 10 MiB
	const last = 6 << 20    // and a last one that could be a middle part

	parts := map[int][]byte{
		1: segPlaintext(t, middle),
		2: segPlaintext(t, middle),
		3: segPlaintext(t, last),
	}

	cases := map[string]struct {
		order   []int
		refused bool
	}{
		// The part size is known before the last part is sealed, so its offset
		// is right and the chain lines up.
		"the last part arrives last": {order: []int{1, 2, 3}},
		// 6 MiB arrives first and becomes the inferred part size, so part 3 is
		// sealed at 12 MiB when it belongs at 20 MiB.
		"the last part arrives first": {order: []int{3, 1, 2}, refused: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m := segManager(t)
			session, err := segRegisteredSession(t, m, "upload-aligned")
			require.NoError(t, err)

			for _, number := range tc.order {
				sealed, sealErr := session.SealPart(number, parts[number], m.ShortPartBufferSize())
				require.NoError(t, sealErr, "part %d", number)
				require.NotNil(t, sealed, "a part of this size is stored where it lies, not held")
				// Every byte is at the backend by now: the refusal, when it
				// comes, costs the whole transfer. That is the trade ADR 0011 D3
				// makes, and it is worth seeing in the test.
				_, readErr := io.ReadAll(func() io.Reader { body, e := sealed.Body(); require.NoError(t, e); return body }())
				require.NoError(t, readErr)
			}

			final, err := session.Complete()
			if tc.refused {
				require.ErrorIs(t, err, ErrPartTableInvalid,
					"a part sealed at the wrong offset must be refused, never completed")
				assert.Nil(t, final)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, final)
			assert.Equal(t, 4, final.PartNumber, "the trailer is a part of its own behind three full parts")
		})
	}
}
