package orchestration

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

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

	// ErrShortPartBufferFull marks a short last part the session cannot hold
	// within optimizations.multipart_short_part_buffer_size. It is back pressure,
	// not a refusal: the upload stays open and the part can be sent again.
	ErrShortPartBufferFull = fmt.Errorf("the short-part buffer is full")

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

// ShortPartBufferSize is what one client-driven upload may hold for a part that
// does not cover whole segments.
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

	return &SegmentedSession{
		Upload:    upload,
		ObjectKey: objectKey,
		Bucket:    bucket,
		CreatedAt: time.Now(),
		parts:     make(map[int]sessionPart),
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
	defer m.segmentedMu.Unlock()
	delete(m.segmentedSessions, uploadID)
}

// CleanupExpiredSegmentedSessions drops uploads a client never finished.
func (m *Manager) CleanupExpiredSegmentedSessions(maxAge time.Duration) int {
	m.segmentedMu.Lock()
	defer m.segmentedMu.Unlock()

	removed := 0
	for uploadID, session := range m.segmentedSessions {
		if time.Since(session.CreatedAt) > maxAge {
			delete(m.segmentedSessions, uploadID)
			removed++
		}
	}
	return removed
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

	// A part can be stored where it lies only if it can be a middle part: it has
	// to cover whole segments, because a short segment inside a chain writes
	// cleanly and never reads, and it has to clear the backend's minimum part
	// size, because the trailer or a later part goes behind it.
	canBeMiddle := len(plaintext) > 0 &&
		int64(len(plaintext))%dataencryption.SegmentSize == 0 &&
		int64(len(plaintext)) >= s3MinimumPartSize
	if canBeMiddle {
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

// RecordETag stores what the backend answered for a part the proxy uploaded.
func (s *SegmentedSession) RecordETag(partNumber int, etag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
