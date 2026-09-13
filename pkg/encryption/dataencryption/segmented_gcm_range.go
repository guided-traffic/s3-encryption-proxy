package dataencryption

import (
	"errors"
	"fmt"
	"io"
)

// ErrRangeNotSatisfiable marks a range that lies outside the object.
var ErrRangeNotSatisfiable = errors.New("segmented gcm: range not satisfiable")

// Window is the contiguous stretch of stored bytes a ranged read must fetch, and
// what to do with it. It is produced without the data key (ADR 0003 D9).
type Window struct {
	// CiphertextOffset and CiphertextLength address the backend request.
	CiphertextOffset int64
	CiphertextLength int64

	// FirstSegment is the index the first sealed segment in the window carries in
	// its associated data.
	FirstSegment uint64

	// SkipInFirst is how much plaintext to drop from the first opened segment.
	SkipInFirst int64

	// PlaintextLength is how much plaintext to hand to the client after the skip.
	PlaintextLength int64

	// IncludesTrailer is set when the window reaches the end of the object, so
	// the read can check the authenticated length against what the backend
	// claimed the stored length was.
	IncludesTrailer bool

	// TotalPlaintext is the object length the window was planned against.
	TotalPlaintext int64
}

// PlanRange maps a plaintext range onto the stored layout. length may exceed what
// remains, in which case the window ends at the object's end; a start at or past
// the end is not satisfiable.
func PlanRange(offset, length, totalPlaintext int64) (Window, error) {
	if totalPlaintext < 0 || totalPlaintext > MaxPlaintextLen {
		return Window{}, ErrNotWellFormed
	}
	if offset < 0 || length <= 0 {
		return Window{}, ErrRangeNotSatisfiable
	}
	if offset >= totalPlaintext {
		return Window{}, ErrRangeNotSatisfiable
	}
	// Clamp before any multiplication. A client may legally ask for
	// bytes=0-9223372036854775806, and the segment arithmetic below overflows
	// into a negative window if the length is carried through unclamped.
	if length > totalPlaintext-offset {
		length = totalPlaintext - offset
	}

	segments := segmentCount(totalPlaintext)
	first := offset / SegmentSize
	last := (offset + length - 1) / SegmentSize
	if last >= segments {
		return Window{}, ErrNotWellFormed
	}

	const stride = SegmentSize + SegmentOverhead
	start := first * stride
	end := last*stride + segmentStoredLen(last, segments, totalPlaintext)

	w := Window{
		CiphertextOffset: start,
		FirstSegment:     uint64(first),
		SkipInFirst:      offset - first*SegmentSize,
		PlaintextLength:  length,
		TotalPlaintext:   totalPlaintext,
	}
	if last == segments-1 {
		// The trailer sits immediately after the last segment. Fetching it costs
		// 40 bytes and lets the read verify the length the backend reported.
		end += TrailerSize
		w.IncludesTrailer = true
	}
	w.CiphertextLength = end - start
	if w.CiphertextLength <= 0 || start < 0 || end < start {
		return Window{}, ErrNotWellFormed
	}
	return w, nil
}

// segmentStoredLen is the stored size of segment i. Only the last segment of an
// object may be short.
func segmentStoredLen(i, segments, totalPlaintext int64) int64 {
	if i < segments-1 {
		return SegmentSize + SegmentOverhead
	}
	return totalPlaintext - (segments-1)*SegmentSize + SegmentOverhead
}

// rangeReader opens the segments of a window and yields exactly the plaintext the
// range asked for. Like the sequential reader it releases nothing it has not
// authenticated.
type rangeReader struct {
	codec  *Codec
	src    io.Reader
	window Window

	sealed   []byte // one sealed segment
	plainBuf []byte
	plain    []byte // authenticated plaintext not yet handed out

	index     uint64
	remaining int64 // plaintext still owed to the caller
	skip      int64
	done      bool
	err       error
}

// NewRangeReader reads the window planned by PlanRange from src, which must
// deliver exactly the window's bytes.
func (c *Codec) NewRangeReader(src io.Reader, w Window) io.ReadCloser {
	return &rangeReader{
		codec:     c,
		src:       src,
		window:    w,
		sealed:    make([]byte, SegmentSize+SegmentOverhead),
		plainBuf:  make([]byte, 0, SegmentSize),
		index:     w.FirstSegment,
		remaining: w.PlaintextLength,
		skip:      w.SkipInFirst,
	}
}

func (r *rangeReader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.remaining == 0 || r.done {
			if err := r.finish(); err != nil {
				r.err = err
				return 0, err
			}
			return 0, io.EOF
		}
		if err := r.next(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *rangeReader) next() error {
	segments := segmentCount(r.window.TotalPlaintext)
	if r.index > maxSegmentIndex {
		return ErrCorrupt
	}
	want := segmentStoredLen(int64(r.index), segments, r.window.TotalPlaintext)
	if _, err := io.ReadFull(r.src, r.sealed[:want]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrCorrupt
		}
		return fmt.Errorf("segmented gcm: read segment %d: %w", r.index, err)
	}
	plain, err := r.codec.openSegment(r.plainBuf[:0], r.sealed[:want], r.index)
	if err != nil {
		return err
	}
	r.plainBuf = plain
	r.index++

	if r.skip > 0 {
		if r.skip >= int64(len(plain)) {
			// A window whose first segment does not reach the offset is malformed.
			return ErrCorrupt
		}
		plain = plain[r.skip:]
		r.skip = 0
	}
	if int64(len(plain)) > r.remaining {
		plain = plain[:r.remaining]
	}
	r.remaining -= int64(len(plain))
	r.plain = plain
	return nil
}

// finish consumes and verifies the trailer when the window carried one.
func (r *rangeReader) finish() error {
	if r.done {
		return nil
	}
	r.done = true
	if !r.window.IncludesTrailer {
		return nil
	}
	trailer := make([]byte, TrailerSize)
	if _, err := io.ReadFull(r.src, trailer); err != nil {
		return ErrCorrupt
	}
	sum, err := r.codec.openTrailer(trailer)
	if err != nil {
		return err
	}
	// The window was planned against a length the backend reported. The trailer
	// is the authenticated copy of it.
	if sum.Length != r.window.TotalPlaintext {
		return ErrCorrupt
	}
	return nil
}

func (r *rangeReader) Close() error { return nil }
