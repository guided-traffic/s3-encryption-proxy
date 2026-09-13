package orchestration

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// SegmentedSession is one client-driven multipart upload. The proxy owns the
// part layout it stores (ADR 0011): one client part becomes one backend part,
// each part but the last covers whole segments, and the part table the session
// keeps is the authority at Complete — not the list the client sends.
type SegmentedSession struct {
	Upload    *SegmentedUpload
	ObjectKey string
	Bucket    string
	CreatedAt time.Time

	mu sync.Mutex
	// lastTouched is when this upload last received a part. The sweeper measures
	// against it rather than against CreatedAt: an upload that is still moving
	// bytes is not abandoned, however long it has been running, and an upload
	// nobody is feeding is abandoned whether it started an hour ago or a minute
	// ago.
	lastTouched time.Time
	// abandonFailures counts how often the backend refused to be told this upload
	// is over. It bounds the retrying, so a backend that never accepts an abort
	// cannot pin a session in memory for good.
	abandonFailures int
	// partSize is the largest part seen that could be a middle part (ADR 0011
	// D3). A short last part never contributes, so the inference does not depend
	// on which part arrives first.
	partSize int64
	parts    map[int]sessionPart
	// pending holds the one part that does not cover whole segments. It cannot
	// be stored on its own, so it waits for Complete, where it is sealed
	// together with the trailer.
	pending    []byte
	pendingNum int
	// reserved is what pending costs against the process-wide budget. It is
	// given back when the session ends, however it ends (ADR 0011 D5).
	reserved int64
	// mgr is the manager holding that budget. A session cannot account for
	// memory it shares with every other session on its own.
	mgr *Manager
}

type sessionPart struct {
	offset       int64
	plaintextLen int64
	sum          dataencryption.Checksum
	etag         string
	uploadedAt   time.Time
}

// SessionPart is one part of a live upload as ListParts reports it: the
// plaintext length the client sent, never the stored one (ADR 0010).
type SessionPart struct {
	PartNumber   int
	PlaintextLen int64
	ETag         string
	UploadedAt   time.Time
}

// FinalPart is a part the proxy has to upload itself at Complete: either the
// short last part the client sent, sealed with the trailer behind it, or the
// trailer alone.
type FinalPart struct {
	PartNumber int
	Body       []byte
}

// s3MinimumPartSize is what S3 refuses below, for every part but the last. A
// part smaller than it can only ever be an object's last part, so the proxy
// cannot put the trailer, or anything else, behind it.
const s3MinimumPartSize = 5 * 1024 * 1024

var (
	// ErrShortPartAlreadyBuffered marks a second part that does not cover whole
	// segments. Only the last part of an object may be short, and the session
	// already holds one.
	ErrShortPartAlreadyBuffered = fmt.Errorf("only the last part may be shorter than one segment")

	// ErrPartTableInvalid marks a part layout the proxy cannot store as a chain.
	ErrPartTableInvalid = fmt.Errorf("the parts of this upload do not form a segment chain")

	// ErrShortPartBufferFull marks a short last part that does not fit in what is
	// left of optimizations.multipart_short_part_buffer_size while other uploads
	// hold their own. It is back pressure, not a refusal: the upload stays open
	// and the part can be sent again once they are done (ADR 0011 D5).
	ErrShortPartBufferFull = fmt.Errorf("the short-part buffer is full")

	// ErrShortPartTooLarge marks a short last part larger than the whole budget.
	// No other upload finishing can make room for it, so it is a refusal rather
	// than back pressure: retrying it forever is what an SDK does with a 503.
	ErrShortPartTooLarge = fmt.Errorf("the last part is larger than optimizations.multipart_short_part_buffer_size")

	// ErrPartNumberReserved marks the one part number a client may not use. The
	// trailer needs a number of its own whenever the last client part is large
	// enough to carry a part behind it, and S3 stops at 10000, so the last one
	// belongs to the proxy (ADR 0011 D4).
	ErrPartNumberReserved = fmt.Errorf("part number %d is reserved for the object's authenticated trailer", maxClientPartNumber+1)
)

// maxClientPartNumber is what a client-driven upload may use. S3 allows 10000;
// the proxy keeps the last one for the trailer, so refusing it here costs the
// client one part number and saves it an upload that fails at Complete, after
// every byte has been transferred.
const maxClientPartNumber = 9999

// ShortPartBufferSize is what all open client-driven uploads together may hold
// for parts that do not cover whole segments. The budget is the process's, not
// a session's (ADR 0011 D5).
func (m *Manager) ShortPartBufferSize() int64 {
	if m.config != nil && m.config.Optimizations.MultipartShortPartBufferSize > 0 {
		return m.config.Optimizations.MultipartShortPartBufferSize
	}
	return 64 << 20
}

// NewSegmentedSession prepares a client-driven upload. Its metadata has to go
// into CreateMultipartUpload, so the session exists before the backend has
// given out an upload id; RegisterSegmentedSession files it under that id
// afterwards.
func (m *Manager) NewSegmentedSession(
	objectKey, bucket string, userMetadata map[string]string,
) (*SegmentedSession, error) {
	upload, err := m.NewSegmentedUpload(objectKey, userMetadata)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &SegmentedSession{
		Upload:      upload,
		ObjectKey:   objectKey,
		Bucket:      bucket,
		CreatedAt:   now,
		lastTouched: now,
		parts:       make(map[int]sessionPart),
		mgr:         m,
	}, nil
}

// RegisterSegmentedSession files a prepared session under the backend's upload id.
func (m *Manager) RegisterSegmentedSession(uploadID string, session *SegmentedSession) {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	if m.segmentedSessions == nil {
		m.segmentedSessions = make(map[string]*SegmentedSession)
	}
	m.segmentedSessions[uploadID] = session
}

// RegisterProducerUpload files an upload the proxy drives itself: the internal
// multipart producer creates a real backend upload, and nothing but this process
// knows its id, so it is as unfinishable after an exit as a client-driven
// session and is swept the same way (ADR 0029 D2).
//
// It is kept apart from the client-driven sessions because the idle sweeper must
// never see it: a producer upload has no client feeding it parts, so the idle
// clock of ADR 0028 would abandon a PUT that is still streaming.
func (m *Manager) RegisterProducerUpload(uploadID, bucket, objectKey string) {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	if m.producerUploads == nil {
		m.producerUploads = make(map[string]producerUpload)
	}
	m.producerUploads[uploadID] = producerUpload{bucket: bucket, objectKey: objectKey}
}

// ForgetProducerUpload drops an upload the producer has finished with, whether
// it completed or aborted it itself.
func (m *Manager) ForgetProducerUpload(uploadID string) {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	delete(m.producerUploads, uploadID)
}

// SegmentedSession looks up a live upload.
func (m *Manager) SegmentedSession(uploadID string) (*SegmentedSession, bool) {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()
	session, ok := m.segmentedSessions[uploadID]
	return session, ok
}

// CloseSegmentedSession forgets an upload, whether it completed or was aborted.
func (m *Manager) CloseSegmentedSession(uploadID string) {
	m.segmentedMu.Lock()
	session := m.segmentedSessions[uploadID]
	delete(m.segmentedSessions, uploadID)
	m.segmentedMu.Unlock()
	m.releaseSessionBudget(session)
}

// reserveShortPart moves a session's claim on the process-wide short-part budget
// from held to want. It is the second bound of ADR 0011 D5: without it the
// configured cap bounds one upload and the real ceiling is that cap times the
// number of uploads a client chooses to open at once.
func (m *Manager) reserveShortPart(held, want int64) bool {
	budget := m.ShortPartBufferSize()

	m.shortPartMu.Lock()
	defer m.shortPartMu.Unlock()
	if m.shortPartHeld-held+want > budget {
		return false
	}
	m.shortPartHeld += want - held
	return true
}

// releaseShortPart gives buffered bytes back to the budget.
func (m *Manager) releaseShortPart(n int64) {
	if n <= 0 {
		return
	}
	m.shortPartMu.Lock()
	defer m.shortPartMu.Unlock()
	m.shortPartHeld -= n
	if m.shortPartHeld < 0 {
		m.shortPartHeld = 0
	}
}

// releaseSessionBudget gives back whatever a session was holding. Every path
// that forgets a session goes through it: a completion, an abort, the idle
// sweep and the shutdown sweep all free the same memory.
func (m *Manager) releaseSessionBudget(session *SegmentedSession) {
	if session == nil {
		return
	}
	session.mu.Lock()
	reserved := session.reserved
	session.reserved = 0
	session.pending = nil
	session.mu.Unlock()
	m.releaseShortPart(reserved)
}

// ShortPartBytesHeld reports what the short-part buffers of all live uploads
// currently hold.
func (m *Manager) ShortPartBytesHeld() int64 {
	m.shortPartMu.Lock()
	defer m.shortPartMu.Unlock()
	return m.shortPartHeld
}

// touchLocked records that this upload just received a part. The caller holds mu.
func (s *SegmentedSession) touchLocked() { s.lastTouched = time.Now() }

// idleFor reports how long this upload has gone without a part.
func (s *SegmentedSession) idleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastTouched)
}

// AbandonAllSessions ends every upload this process still holds and reports how
// many it ended and how many it had to leave.
//
// It belongs to shutdown, not to the sweeper. A session is process-local — it
// holds the object's data key and the part table Complete is built from — so no
// other process can adopt it and no client can finish the upload once this
// process is gone. The upload is therefore already dead when shutdown begins;
// leaving it behind only turns it into stored bytes nothing can reach
// (ADR 0029).
//
// The uploads are ended one at a time and the walk stops when ctx expires: the
// budget is what is left of the operator's shutdown timeout, and overrunning it
// is how a pod gets killed mid-abort instead of finishing the ones it can.
func (m *Manager) AbandonAllSessions(ctx context.Context) (ended, left int) {
	m.segmentedMu.Lock()
	remaining := make(map[string]producerUpload, len(m.segmentedSessions)+len(m.producerUploads))
	for uploadID, session := range m.segmentedSessions {
		remaining[uploadID] = producerUpload{bucket: session.Bucket, objectKey: session.ObjectKey}
	}
	// A PUT large enough to become an internal multipart upload is still running
	// when the drain gives up on it, and its upload id lives nowhere else.
	for uploadID, upload := range m.producerUploads {
		remaining[uploadID] = upload
	}
	abandon := m.abandon
	m.segmentedMu.Unlock()

	if len(remaining) == 0 {
		return 0, 0
	}
	if abandon == nil {
		// Nothing to speak to. Say so once: the uploads stay at the backend.
		m.logger.WithField("uploads", len(remaining)).
			Warn("Shutting down with multipart uploads open and no backend to end them with")
		return 0, len(remaining)
	}

	for uploadID, upload := range remaining {
		if ctx.Err() != nil {
			left++
			continue
		}
		if err := abandon(ctx, upload.bucket, upload.objectKey, uploadID); err != nil {
			m.logger.WithError(err).WithFields(logrus.Fields{
				"upload_id": uploadID,
				"bucket":    upload.bucket,
				"key":       upload.objectKey,
			}).Error("Could not end a multipart upload while shutting down; it stays at the backend " +
				"until a client aborts it or a lifecycle rule removes it")
			left++
			continue
		}
		m.segmentedMu.Lock()
		session := m.segmentedSessions[uploadID]
		delete(m.segmentedSessions, uploadID)
		delete(m.producerUploads, uploadID)
		m.segmentedMu.Unlock()
		m.releaseSessionBudget(session)
		ended++
	}
	return ended, left
}

// maxAbandonAttempts bounds how often the sweeper asks the backend to abort one
// upload before it gives the session up regardless. Without a bound, a backend
// that answers nothing but errors would keep every abandoned session — with its
// data key and its short part — resident for the life of the process.
const maxAbandonAttempts = 5

// CleanupExpiredSegmentedSessions abandons uploads whose client has stopped
// feeding them: it tells the backend the upload is over and only then forgets
// it. Dropping the session on its own leaves the upload and every part already
// in it at the backend, invisible to a listing and unreachable by the client,
// which is answered NoSuchUpload from then on.
//
// The backend call happens outside the session lock, so a slow or unreachable
// backend cannot block an upload in progress.
func (m *Manager) CleanupExpiredSegmentedSessions(ctx context.Context, idle time.Duration) int {
	type expired struct {
		uploadID string
		session  *SegmentedSession
		idleFor  time.Duration
	}

	m.segmentedMu.Lock()
	candidates := make([]expired, 0, len(m.segmentedSessions))
	for uploadID, session := range m.segmentedSessions {
		if idleTime := session.idleFor(); idleTime > idle {
			candidates = append(candidates, expired{uploadID, session, idleTime})
		}
	}
	abandon := m.abandon
	m.segmentedMu.Unlock()

	removed := 0
	for _, c := range candidates {
		if abandon != nil {
			if err := abandon(ctx, c.session.Bucket, c.session.ObjectKey, c.uploadID); err != nil {
				c.session.mu.Lock()
				c.session.abandonFailures++
				attempts := c.session.abandonFailures
				c.session.mu.Unlock()

				if attempts < maxAbandonAttempts {
					// Kept for the next tick. The upload is still at the backend
					// either way; what is not yet lost is the proxy's ability to
					// say so.
					m.logger.WithError(err).WithFields(logrus.Fields{
						"upload_id": c.uploadID,
						"bucket":    c.session.Bucket,
						"attempt":   attempts,
					}).Warn("Could not abandon an idle multipart upload at the backend; will try again")
					continue
				}
				m.logger.WithError(err).WithFields(logrus.Fields{
					"upload_id": c.uploadID,
					"bucket":    c.session.Bucket,
					"key":       c.session.ObjectKey,
					"attempts":  attempts,
				}).Error("Giving up on abandoning an idle multipart upload; it and its parts stay at the backend " +
					"until a client aborts it or a lifecycle rule removes it")
			}
		}

		m.segmentedMu.Lock()
		delete(m.segmentedSessions, c.uploadID)
		m.segmentedMu.Unlock()
		m.releaseSessionBudget(c.session)
		removed++

		// At Info, one line per upload, because from the client's side this is a
		// 404 NoSuchUpload with no explanation and there is nothing else to
		// correlate it with. The clock moves when a part arrives, not while one
		// is arriving, so a single part slower than the timeout ends up here
		// too — and then this line is the only thing that says which knob to
		// turn.
		m.logger.WithFields(logrus.Fields{
			"upload_id":    c.uploadID,
			"bucket":       c.session.Bucket,
			"key":          c.session.ObjectKey,
			"idle_for":     c.idleFor.Round(time.Second),
			"idle_timeout": idle,
		}).Info("Ended an idle multipart upload at the backend; raise " +
			"optimizations.multipart_session_idle_timeout if the client was still uploading")
	}
	return removed
}

// dropPendingLocked forgets the held part and gives its bytes back. The caller
// holds mu.
func (s *SegmentedSession) dropPendingLocked() {
	s.pending = nil
	if s.mgr != nil {
		s.mgr.releaseShortPart(s.reserved)
	}
	s.reserved = 0
}

// reserveLocked claims want bytes of the process-wide budget for the held part,
// giving back what this session already had. The caller holds mu.
func (s *SegmentedSession) reserveLocked(want int64) bool {
	if s.mgr == nil {
		return true
	}
	if !s.mgr.reserveShortPart(s.reserved, want) {
		return false
	}
	s.reserved = want
	return true
}

// SealPart prepares one client part for the backend. It returns nil when the
// part covers no whole segment: such a part cannot be stored on its own, so the
// session holds it until Complete and the caller answers the client without a
// backend round trip.
//
// shortBufferLimit bounds what one session may hold that way.
func (s *SegmentedSession) SealPart(partNumber int, plaintext []byte, shortBufferLimit int64) (*SealedPart, error) {
	if partNumber < 1 || partNumber > maxClientPartNumber+1 {
		return nil, fmt.Errorf("part number %d is outside 1..%d", partNumber, maxClientPartNumber+1)
	}
	if partNumber > maxClientPartNumber {
		return nil, ErrPartNumberReserved
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchLocked()

	// A part can be stored where it lies only if it can be a middle part: it has
	// to cover whole segments, because a short segment inside a chain writes
	// cleanly and never reads, and it has to clear the backend's minimum part
	// size, because the trailer or a later part goes behind it.
	canBeMiddle := len(plaintext) > 0 &&
		int64(len(plaintext))%dataencryption.SegmentSize == 0 &&
		int64(len(plaintext)) >= s3MinimumPartSize
	if canBeMiddle {
		// A client may send any part number again with different bytes. When the
		// part it replaces is the one being held, the held copy is no longer part
		// of this object: leaving it would have Complete store those bytes under
		// this number while the table describes these, an object that stores
		// cleanly and fails authentication on every read.
		if s.pending != nil && s.pendingNum == partNumber {
			s.dropPendingLocked()
		}
		// Only a part that could be a middle part may set the inferred size. A
		// short last part is by definition not the part size, and letting it
		// contribute makes the inference wrong whenever it arrives first.
		if int64(len(plaintext)) > s.partSize {
			s.partSize = int64(len(plaintext))
		}
		offset := int64(partNumber-1) * s.partSize
		part, err := s.Upload.SealPart(offset, plaintext, false)
		if err != nil {
			return nil, err
		}
		s.parts[partNumber] = sessionPart{
			offset:       offset,
			plaintextLen: int64(len(plaintext)),
			sum:          part.Sum,
			uploadedAt:   time.Now(),
		}
		return part, nil
	}

	// Only one part of an upload can be last, so only one may be held.
	if s.pending != nil && s.pendingNum != partNumber {
		return nil, ErrShortPartAlreadyBuffered
	}
	if int64(len(plaintext)) > shortBufferLimit {
		return nil, ErrShortPartTooLarge
	}
	// The budget is shared with every other upload in this process, so what one
	// session may hold depends on what the others hold right now (ADR 0011 D5).
	if !s.reserveLocked(int64(len(plaintext))) {
		return nil, ErrShortPartBufferFull
	}

	sum := dataencryption.NewChecksum(plaintext)
	s.pending = append(s.pending[:0], plaintext...)
	s.pendingNum = partNumber
	s.parts[partNumber] = sessionPart{
		// No offset yet. The part is sealed at Complete, by when the inferred
		// part size is final; taking it here would freeze whatever size had
		// arrived first, which under concurrent uploads is not the part size.
		plaintextLen: int64(len(plaintext)),
		sum:          sum,
		// The part is not at the backend yet, so there is no backend ETag to
		// return. The client needs one all the same - it puts the value in its
		// Complete request - and the proxy replaces it with the real one once the
		// part is stored. It is derived from the part so a retry of the same
		// bytes answers the same value.
		etag:       fmt.Sprintf("%08x-%d", sum.Value, sum.Length),
		uploadedAt: time.Now(),
	}
	return nil, nil
}

// CanStreamPart reports whether a part of this declared plaintext length can be
// forwarded to the backend while it is still arriving. Only a part that could be
// a middle part can: it has to cover whole segments and clear the backend's
// minimum part size, because a short part is sealed at Complete together with
// the trailer and so has to be held.
//
// It is a function of the length alone, deliberately: the caller has to decide
// whether to stream before it looks the session up, or a part for an upload that
// does not exist stops being answered the way it was.
func CanStreamPart(plaintextLen int64) bool {
	return plaintextLen > 0 &&
		plaintextLen%dataencryption.SegmentSize == 0 &&
		plaintextLen >= s3MinimumPartSize
}

// SealStreamingPart prepares a part the proxy forwards while it receives it
// (ADR 0024 D1). plaintextLen is the length the client declared: it fixes the
// backend Content-Length, and a body that does not deliver it fails the backend
// request instead of storing a part of the wrong size.
//
// Nothing is written to the part table here. A streamed part's length and its
// checksum are only known once the backend has pulled the body, and an attempt
// that fails has to leave the table exactly as it found it: S3 keeps a part
// stored under a number when a later attempt at that number fails, and a client
// that completes with the ETags it already holds must still get its object
// (ADR 0006). RecordStreamedPart writes the entry once the part is stored.
func (s *SegmentedSession) SealStreamingPart(partNumber int, plaintextLen int64, src io.Reader) (*SealedPart, error) {
	if partNumber < 1 || partNumber > maxClientPartNumber+1 {
		return nil, fmt.Errorf("part number %d is outside 1..%d", partNumber, maxClientPartNumber+1)
	}
	if partNumber > maxClientPartNumber {
		return nil, ErrPartNumberReserved
	}
	if !CanStreamPart(plaintextLen) {
		return nil, dataencryption.ErrPartNotAligned
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchLocked()

	if plaintextLen > s.partSize {
		s.partSize = plaintextLen
	}
	offset := int64(partNumber-1) * s.partSize
	return s.Upload.SealStreamingPart(offset, plaintextLen, src, false)
}

// RecordStreamedPart enters a streamed part in the table, once the backend has
// stored it. The length and the checksum are the sealed truth rather than what
// the client declared, and they are what Complete combines into the object's
// trailer.
func (s *SegmentedSession) RecordStreamedPart(partNumber int, offset int64, sum dataencryption.Checksum) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchLocked()
	// A client may send any part number again with different bytes. When the
	// part it replaces is the one being held, the held copy is no longer part of
	// this object: leaving it would have Complete store those bytes under this
	// number while the table describes these, an object that stores cleanly and
	// fails authentication on every read. The drop belongs here rather than in
	// SealStreamingPart because every failure between the two returns without
	// touching the table, and a held part is a part the client uploaded
	// successfully: it may only disappear once its replacement stands.
	if s.pending != nil && s.pendingNum == partNumber {
		s.dropPendingLocked()
	}
	s.parts[partNumber] = sessionPart{
		offset:       offset,
		plaintextLen: sum.Length,
		sum:          sum,
		uploadedAt:   time.Now(),
	}
}

// RecordETag stores what the backend answered for a part the proxy uploaded.
func (s *SegmentedSession) RecordETag(partNumber int, etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchLocked()
	if part, ok := s.parts[partNumber]; ok {
		part.etag = etag
		s.parts[partNumber] = part
	}
}

// PartETag reports what a part was stored under.
func (s *SegmentedSession) PartETag(partNumber int) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	part, ok := s.parts[partNumber]
	return part.etag, ok
}

// Complete validates the part table and returns the part the proxy still has to
// upload: the short last part sealed together with the trailer, or the trailer
// on its own. Both are the object's last part, which is the one part S3 exempts
// from its minimum size.
func (s *SegmentedSession) Complete() (*FinalPart, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.parts) == 0 {
		return nil, ErrPartTableInvalid
	}

	// The held part's offset follows from the inferred part size, which is only
	// final now that every part has arrived.
	if s.pending != nil {
		held := s.parts[s.pendingNum]
		held.offset = int64(s.pendingNum-1) * s.partSize
		s.parts[s.pendingNum] = held
	}

	highest := 0
	for number := range s.parts {
		if number > highest {
			highest = number
		}
	}

	// Contiguous from 1, uniform in size except for the last, segment-aligned,
	// and each at the offset the arithmetic puts it at. Anything else produces an
	// object whose segments do not line up with what a reader computes.
	for number := 1; number <= highest; number++ {
		part, ok := s.parts[number]
		if !ok {
			return nil, ErrPartTableInvalid
		}
		if part.offset != int64(number-1)*s.partSize {
			return nil, ErrPartTableInvalid
		}
		if number == highest {
			continue
		}
		if part.plaintextLen != s.partSize || part.plaintextLen%dataencryption.SegmentSize != 0 {
			return nil, ErrPartTableInvalid
		}
	}

	var sum dataencryption.Checksum
	for number := 1; number <= highest; number++ {
		sum = sum.Append(s.parts[number].sum)
	}

	if s.pending != nil {
		part, err := s.Upload.SealPart(s.parts[s.pendingNum].offset, s.pending, true)
		if err != nil {
			return nil, err
		}
		body, _, err := part.BodyWithTrailer(sum)
		if err != nil {
			return nil, err
		}
		sealed, err := io.ReadAll(body)
		if err != nil {
			return nil, err
		}
		return &FinalPart{PartNumber: s.pendingNum, Body: sealed}, nil
	}

	trailer, err := s.Upload.Trailer(sum)
	if err != nil {
		return nil, err
	}
	// The trailer is a part like any other and has to be in the table, or the
	// list Complete is built from leaves it out, the backend drops it, and the
	// object stores cleanly and never reads.
	trailerNumber := highest + 1
	s.parts[trailerNumber] = sessionPart{
		offset:       s.parts[highest].offset + s.parts[highest].plaintextLen,
		plaintextLen: 0,
	}
	return &FinalPart{PartNumber: trailerNumber, Body: trailer}, nil
}

// VerifyClientParts checks the list the client sent against the part table the
// proxy kept (ADR 0011 D6). The table is what Complete is built from, but a
// client that describes a different upload has to be told so rather than handed
// an object it did not ask for.
//
// It runs before Complete adds the trailer to the table, so the two part sets
// are expected to match exactly.
func (s *SegmentedSession) VerifyClientParts(claimed map[int]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for number, etag := range claimed {
		part, ok := s.parts[number]
		if !ok {
			return fmt.Errorf("part %d was never uploaded", number)
		}
		if !strings.EqualFold(part.etag, etag) {
			return fmt.Errorf("the entity tag given for part %d is not the one it was stored under", number)
		}
	}
	for number := range s.parts {
		if _, ok := claimed[number]; !ok {
			return fmt.Errorf("part %d was uploaded but is not in the completion list", number)
		}
	}
	return nil
}

// Parts lists what the client has uploaded so far, in part-number order, for
// ListParts (ADR 0011 D6). The part the session holds for Complete is in it: the
// client uploaded it and was answered an ETag for it, so a listing that left it
// out would tell that client its part is missing.
func (s *SegmentedSession) Parts() []SessionPart {
	s.mu.Lock()
	defer s.mu.Unlock()

	listed := make([]SessionPart, 0, len(s.parts))
	for number, part := range s.parts {
		listed = append(listed, SessionPart{
			PartNumber:   number,
			PlaintextLen: part.plaintextLen,
			ETag:         part.etag,
			UploadedAt:   part.uploadedAt,
		})
	}
	sort.Slice(listed, func(i, j int) bool { return listed[i].PartNumber < listed[j].PartNumber })
	return listed
}

// PartNumbers lists the object's parts in order. It is what Complete is built
// from: the proxy stored these parts, so it knows their numbers and their tags
// without trusting the list a client sends.
func (s *SegmentedSession) PartNumbers() []int {
	s.mu.Lock()
	defer s.mu.Unlock()

	numbers := make([]int, 0, len(s.parts))
	for number := range s.parts {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)
	return numbers
}
