package dataencryption

import (
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

// readBufferSize holds one full sealed segment plus the trailer, so the last
// segment and the trailer arrive in a single read (codec API design, 013).
const readBufferSize = SegmentSize + SegmentOverhead + TrailerSize

// Writer seals a plaintext stream into the segment chain and closes it with the
// trailer. It is not safe for concurrent use.
type Writer struct {
	codec *Codec
	dst   io.Writer

	pending []byte // plaintext not yet sealed, at most SegmentSize
	sealBuf []byte // reused ciphertext buffer
	index   uint64
	crc     uint32 // running checksum; combining per segment costs more than the cipher
	length  int64
	closed  bool
	err     error
}

// NewWriter returns a Writer that seals into dst. Close must be called: it seals
// the final partial segment and writes the trailer.
func (c *Codec) NewWriter(dst io.Writer) *Writer {
	return &Writer{
		codec:   c,
		dst:     dst,
		pending: make([]byte, 0, SegmentSize),
		sealBuf: make([]byte, 0, SegmentSize+SegmentOverhead),
	}
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("segmented gcm: write after close")
	}
	written := 0
	for len(p) > 0 {
		// A caller that hands over whole segments should not pay for a copy into
		// the pending buffer first; at 64 KiB that memmove is a large share of
		// the cipher pass.
		if len(w.pending) == 0 && len(p) >= SegmentSize {
			if err := w.sealFrom(p[:SegmentSize]); err != nil {
				w.err = err
				return written, err
			}
			p = p[SegmentSize:]
			written += SegmentSize
			continue
		}
		room := SegmentSize - len(w.pending)
		take := min(room, len(p))
		w.pending = append(w.pending, p[:take]...)
		p = p[take:]
		written += take
		if len(w.pending) == SegmentSize {
			if err := w.flushSegment(); err != nil {
				w.err = err
				return written, err
			}
		}
	}
	return written, nil
}

// flushSegment seals whatever is pending, whether or not it fills a segment.
// Only the last segment of an object may be short.
func (w *Writer) flushSegment() error {
	if err := w.sealFrom(w.pending); err != nil {
		return err
	}
	w.pending = w.pending[:0]
	return nil
}

func (w *Writer) sealFrom(plaintext []byte) error {
	if w.length+int64(len(plaintext)) > MaxPlaintextLen {
		return ErrTooLarge
	}
	sealed, err := w.codec.sealSegment(w.sealBuf[:0], plaintext, w.index)
	if err != nil {
		return err
	}
	if _, err := w.dst.Write(sealed); err != nil {
		return fmt.Errorf("segmented gcm: write segment %d: %w", w.index, err)
	}
	w.sealBuf = sealed
	w.crc = crc32.Update(w.crc, crcTable, plaintext)
	w.length += int64(len(plaintext))
	w.index++
	return nil
}

// Close seals the final partial segment, if any, and writes the trailer.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return nil
	}
	w.closed = true
	// A zero-length object has no segments at all, only a trailer.
	if len(w.pending) > 0 {
		if err := w.flushSegment(); err != nil {
			w.err = err
			return err
		}
	}
	trailer, err := w.codec.sealTrailer(nil, w.Checksum())
	if err != nil {
		w.err = err
		return err
	}
	if _, err := w.dst.Write(trailer); err != nil {
		w.err = fmt.Errorf("segmented gcm: write trailer: %w", err)
		return w.err
	}
	return nil
}

// Checksum reports the plaintext checksum and length sealed into the trailer.
// Valid after Close.
func (w *Writer) Checksum() Checksum { return Checksum{Value: w.crc, Length: w.length} }

// reader opens a sealed chain sequentially. It never releases a plaintext byte
// it has not authenticated, and it verifies the trailer before reporting io.EOF.
//
// The buffer holds one full sealed segment plus a trailer. A segment is only
// known to be the last one when the read that would have completed the next
// buffer hits the end of the stream, so the trailer-sized remainder is carried
// forward between fills.
type reader struct {
	codec *Codec
	src   io.Reader

	buf      []byte // sealed bytes; the first carry bytes are already read
	carry    int
	plainBuf []byte // backing store for one segment of plaintext
	plain    []byte // authenticated plaintext not yet handed out

	index   uint64
	crc     uint32
	length  int64
	trailer *Checksum
	done    bool
	err     error
}

// NewReader opens the chain in src. It verifies every segment and, at the end,
// that the trailer's authenticated length and checksum match what was read.
func (c *Codec) NewReader(src io.Reader) io.ReadCloser {
	return &reader{
		codec:    c,
		src:      src,
		buf:      make([]byte, readBufferSize),
		plainBuf: make([]byte, 0, SegmentSize),
	}
}

func (r *reader) Read(p []byte) (int, error) {
	for len(r.plain) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.fill(); err != nil {
			r.err = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *reader) fill() error {
	n, err := io.ReadFull(r.src, r.buf[r.carry:])
	have := r.carry + n
	switch {
	case err == nil:
		// The buffer is full, so the first sealed segment is a complete one and
		// what follows it is the start of the next segment or the trailer.
		const full = SegmentSize + SegmentOverhead
		if err := r.openInto(r.buf[:full]); err != nil {
			return err
		}
		r.carry = copy(r.buf, r.buf[full:have])
		return nil
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return r.consumeTail(r.buf[:have])
	default:
		return fmt.Errorf("segmented gcm: read: %w", err)
	}
}

// consumeTail handles the end of the object: an optional short final segment
// followed by the trailer.
func (r *reader) consumeTail(tail []byte) error {
	if len(tail) < TrailerSize {
		return ErrCorrupt
	}
	if segment := tail[:len(tail)-TrailerSize]; len(segment) > 0 {
		if err := r.openInto(segment); err != nil {
			return err
		}
	}
	trailer, err := r.codec.openTrailer(tail[len(tail)-TrailerSize:])
	if err != nil {
		return err
	}
	r.done = true
	// The trailer is the authenticated statement of what the object is. A chain
	// that opens segment by segment but disagrees with it has been truncated,
	// extended, or reassembled wrongly.
	if trailer.Length != r.length || trailer.Value != r.crc {
		return ErrCorrupt
	}
	r.trailer = &trailer
	return nil
}

func (r *reader) openInto(segment []byte) error {
	plain, err := r.codec.openSegment(r.plainBuf[:0], segment, r.index)
	if err != nil {
		return err
	}
	r.plainBuf = plain
	r.plain = plain
	r.crc = crc32.Update(r.crc, crcTable, plain)
	r.length += int64(len(plain))
	r.index++
	return nil
}

func (r *reader) Close() error { return nil }

// Checksum reports what the trailer authenticated. It is valid only once the
// reader has returned io.EOF.
func (r *reader) Checksum() (Checksum, bool) {
	if r.trailer == nil {
		return Checksum{}, false
	}
	return *r.trailer, true
}
