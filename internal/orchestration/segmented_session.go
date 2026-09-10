package orchestration

import (
	"fmt"
	"io"
	"sort"
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
	// partSize is the largest part the client has sent so far. Every uploader
	// dispatches part 1 before a short last part, so it is known in time.
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
}

// FinalPart is a part the proxy has to upload itself at Complete: either the
// short last part the client sent, sealed with the trailer behind it, or the
// trailer alone.
type FinalPart struct {
	PartNumber int
	Body       []byte
}

var (
	// ErrShortPartAlreadyBuffered marks a second part that does not cover whole
	// segments. Only the last part of an object may be short, and the session
	// already holds one.
	ErrShortPartAlreadyBuffered = fmt.Errorf("only the last part may be shorter than one segment")

	// ErrPartTableInvalid marks a part layout the proxy cannot store as a chain.
	ErrPartTableInvalid = fmt.Errorf("the parts of this upload do not form a segment chain")
)

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
	if partNumber < 1 || partNumber > 10000 {
		return nil, fmt.Errorf("part number %d is outside 1..10000", partNumber)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if int64(len(plaintext)) > s.partSize {
		s.partSize = int64(len(plaintext))
	}

	// A part that covers whole segments can be sealed and stored where it lies.
	if int64(len(plaintext))%dataencryption.SegmentSize == 0 && len(plaintext) > 0 {
		offset := int64(partNumber-1) * s.partSize
		part, err := s.Upload.SealPart(offset, plaintext, false)
		if err != nil {
			return nil, err
		}
		s.parts[partNumber] = sessionPart{
			offset:       offset,
			plaintextLen: int64(len(plaintext)),
			sum:          part.Sum,
		}
		return part, nil
	}

	if s.pending != nil && s.pendingNum != partNumber {
		return nil, ErrShortPartAlreadyBuffered
	}
	if int64(len(plaintext)) > shortBufferLimit {
		return nil, fmt.Errorf("a short last part of %d bytes exceeds the configured buffer of %d",
			len(plaintext), shortBufferLimit)
	}

	s.pending = append(s.pending[:0], plaintext...)
	s.pendingNum = partNumber
	s.parts[partNumber] = sessionPart{
		offset:       int64(partNumber-1) * s.partSize,
		plaintextLen: int64(len(plaintext)),
		sum:          dataencryption.NewChecksum(plaintext),
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
	return &FinalPart{PartNumber: highest + 1, Body: trailer}, nil
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
