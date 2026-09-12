// Segmented storage format, ADR 0003: the encryption path the handlers use.
//
// Every write produces the same byte layout — a chain of sealed segments closed
// by a sealed trailer — whether it comes from a single PutObject, from the
// proxy's own multipart producer, or from a client-driven multipart upload. The
// data key, the wrapped key and the full metadata set exist before the first
// backend byte is sent, which is what removes the rewrite that used to follow
// every multipart completion.
package orchestration

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/keyencryption"
)

// ErrForeignObject marks an object this proxy did not write: no encryption
// metadata, or metadata naming a format it does not read. Under an encrypting
// provider that is an error on every read verb, never a pass-through (ADR 0003).
var ErrForeignObject = errors.New("object is not encrypted by this proxy")

// ErrKeyMaterialUnreadable marks an object whose wrapped data key does not
// authenticate under the provider its fingerprint names. It is permanent: the
// wrap was either edited after it was written or never sealed by that key
// (ADR 0001), and no later attempt can succeed. It is kept apart from a
// transient failure so the read can be refused rather than retried.
var ErrKeyMaterialUnreadable = errors.New("the object's wrapped data key does not authenticate")

// dekSize is the data key length: one random AES-256 key per object (ADR 0002).
const dekSize = 32

// SegmentedWrite is a single-request write: the ciphertext stream, its exact
// stored length, and the metadata that makes the object readable.
type SegmentedWrite struct {
	Body          io.Reader
	ContentLength int64
	Metadata      map[string]string

	sealer *dataencryption.EncryptReader
}

// NewSegmentedWrite prepares a write whose plaintext length is known: a fresh
// data key, the object metadata, and a body that seals as the backend pulls it.
// Nothing beyond one segment is ever buffered.
func (m *Manager) NewSegmentedWrite(
	objectKey string, plaintext io.Reader, plaintextLen int64, userMetadata map[string]string,
) (*SegmentedWrite, error) {
	if plaintextLen < 0 {
		return nil, fmt.Errorf("segmented write needs a known plaintext length")
	}

	storedLen, err := dataencryption.CiphertextSize(plaintextLen)
	if err != nil {
		return nil, err
	}

	codec, metadata, err := m.newSegmentedObject(objectKey, userMetadata)
	if err != nil {
		return nil, err
	}

	sealer := codec.NewEncryptReader(plaintext)
	return &SegmentedWrite{
		Body:          sealer,
		ContentLength: storedLen,
		Metadata:      metadata,
		sealer:        sealer,
	}, nil
}

// SegmentedUpload is one multipart upload's encryption state, fixed at
// CreateMultipartUpload. Parts are sealed independently and in any order,
// because a segment's position is authenticated by its own index rather than by
// when it was written.
type SegmentedUpload struct {
	codec    *dataencryption.Codec
	metadata map[string]string
}

// NewSegmentedUpload prepares a multipart upload. Its metadata goes into
// CreateMultipartUpload, so the object is readable the moment Complete returns.
func (m *Manager) NewSegmentedUpload(
	objectKey string, userMetadata map[string]string,
) (*SegmentedUpload, error) {
	codec, metadata, err := m.newSegmentedObject(objectKey, userMetadata)
	if err != nil {
		return nil, err
	}
	return &SegmentedUpload{codec: codec, metadata: metadata}, nil
}

// Metadata is the object metadata this upload carries.
func (u *SegmentedUpload) Metadata() map[string]string { return u.metadata }

// SealedPart is one part ready for the backend, in one of two shapes.
//
// A retained part holds its plaintext until the backend has acknowledged it, so
// a failed attempt is re-sealed from it rather than asked for again
// (ADR 0024 D5). Re-sealing draws fresh nonces, which is safe: a part's segments
// are bound to their own indices, never to when they were written.
//
// A streamed part holds a reader instead, and seals the client's body as the
// backend pulls it (ADR 0024 D1). It can be sent once: the bytes are the
// client's request body and nothing retains them. That is the same trade the
// single-request PUT already makes, and it is what keeps a client-driven part
// from being materialised before any of it moves.
type SealedPart struct {
	upload     *SegmentedUpload
	offset     int64
	plaintext  []byte
	src        io.Reader
	sealer     *dataencryption.EncryptReader
	endsObject bool

	// StoredLen is the exact backend Content-Length for this part.
	StoredLen int64
	// Sum covers this part's plaintext alone; Complete combines the parts in
	// order. It is set up front for a retained part and only once a streamed
	// part's body has been consumed — see Checksum.
	Sum dataencryption.Checksum
}

// Offset is where this part's plaintext begins in the object. It fixes the
// segment indices the part is sealed under, so it is decided before the first
// byte moves and recorded only once the part is stored.
func (p *SealedPart) Offset() int64 { return p.offset }

// Streamed reports whether this part seals the client's body as the backend
// pulls it rather than from a retained copy.
func (p *SealedPart) Streamed() bool { return p.src != nil }

// Checksum reports what the part actually carried. For a streamed part it is
// valid only once the body has been read to the end, which is the point where
// the backend has taken every byte; before that it reports false.
func (p *SealedPart) Checksum() (dataencryption.Checksum, bool) {
	if p.sealer == nil {
		return p.Sum, true
	}
	return p.sealer.Checksum()
}

// SealPart prepares one part. plaintextOffset is where the part starts in the
// object and must be a multiple of the segment size; endsObject marks the part
// carrying the object's last, possibly partial, segment.
func (u *SegmentedUpload) SealPart(plaintextOffset int64, plaintext []byte, endsObject bool) (*SealedPart, error) {
	if plaintextOffset < 0 || plaintextOffset%dataencryption.SegmentSize != 0 {
		return nil, dataencryption.ErrNotWellFormed
	}
	if !endsObject && int64(len(plaintext))%dataencryption.SegmentSize != 0 {
		return nil, dataencryption.ErrPartNotAligned
	}

	return &SealedPart{
		upload:     u,
		offset:     plaintextOffset,
		plaintext:  plaintext,
		endsObject: endsObject,
		StoredLen:  PartStoredLen(int64(len(plaintext))),
		Sum:        dataencryption.NewChecksum(plaintext),
	}, nil
}

// SealStreamingPart prepares one part whose plaintext the proxy never holds.
// plaintextLen is what the client declared; it decides the backend
// Content-Length, and a body that does not match it fails the backend request
// rather than storing a part of the wrong size.
func (u *SegmentedUpload) SealStreamingPart(plaintextOffset, plaintextLen int64, src io.Reader, endsObject bool) (*SealedPart, error) {
	if plaintextOffset < 0 || plaintextOffset%dataencryption.SegmentSize != 0 {
		return nil, dataencryption.ErrNotWellFormed
	}
	if !endsObject && plaintextLen%dataencryption.SegmentSize != 0 {
		return nil, dataencryption.ErrPartNotAligned
	}

	return &SealedPart{
		upload:     u,
		offset:     plaintextOffset,
		src:        src,
		endsObject: endsObject,
		StoredLen:  PartStoredLen(plaintextLen),
	}, nil
}

// Body returns a reader that seals the part as the backend pulls it, so the
// producer that made this part is free to receive the next one instead of
// encrypting first (ADR 0024 D2). For a retained part, calling it again
// re-seals the same plaintext for a retry; a streamed part can only be sent
// once, and its checksum is read off the reader afterwards.
func (p *SealedPart) Body() (io.Reader, error) {
	if p.src != nil {
		sealer, err := p.upload.codec.NewPartEncryptReader(p.src, p.offset, p.endsObject, true)
		if err != nil {
			return nil, err
		}
		p.sealer = sealer
		return sealer, nil
	}
	return p.upload.codec.NewPartEncryptReader(bytes.NewReader(p.plaintext), p.offset, p.endsObject, false)
}

// BodyWithTrailer is Body for the part that closes an object the proxy laid out
// itself: the trailer rides on the last part instead of costing one of its own.
// sum must cover the whole object, this part included.
func (p *SealedPart) BodyWithTrailer(sum dataencryption.Checksum) (io.Reader, int64, error) {
	body, err := p.Body()
	if err != nil {
		return nil, 0, err
	}
	trailer, err := p.upload.codec.SealTrailer(sum)
	if err != nil {
		return nil, 0, err
	}
	return io.MultiReader(body, bytes.NewReader(trailer)), p.StoredLen + int64(len(trailer)), nil
}

// Trailer seals the record that closes the object, from the parts' combined
// checksum. It is a part of its own on the client-driven path and rides on the
// proxy's last part where the proxy chooses the layout.
func (u *SegmentedUpload) Trailer(sum dataencryption.Checksum) ([]byte, error) {
	return u.codec.SealTrailer(sum)
}

// PartStoredLen is what a part of this plaintext length occupies once sealed. A
// part carries no trailer: the trailer closes the object, once, at Complete.
func PartStoredLen(plaintextLen int64) int64 {
	segments := plaintextLen / dataencryption.SegmentSize
	if plaintextLen%dataencryption.SegmentSize != 0 {
		segments++
	}
	return plaintextLen + segments*dataencryption.SegmentOverhead
}

// OpenSegmented returns a reader over the object's plaintext. It hands out
// nothing it has not authenticated, and it reports an error rather than io.EOF
// when the chain disagrees with the trailer.
func (m *Manager) OpenSegmented(objectKey string, metadata map[string]string, body io.Reader) (io.ReadCloser, error) {
	codec, err := m.codecFor(objectKey, metadata)
	if err != nil {
		return nil, err
	}
	return codec.NewReader(body), nil
}

// OpenSegmentedRange returns a reader over exactly the plaintext the window
// describes. body must deliver the window's stored bytes and nothing else.
func (m *Manager) OpenSegmentedRange(
	objectKey string, metadata map[string]string, body io.Reader, window dataencryption.Window,
) (io.ReadCloser, error) {
	codec, err := m.codecFor(objectKey, metadata)
	if err != nil {
		return nil, err
	}
	return codec.NewRangeReader(body, window), nil
}

// OpenSegmentedTrailer opens the record that closes an object and returns what
// it authenticates: the plaintext length and the CRC32C of the whole plaintext.
//
// The read paths take the trailer from one ranged backend read of the object's
// last bytes, so a HEAD and a whole-object GET answer with an **authenticated**
// length and with the client's checksum, rather than with the length the backend
// reports about itself (ADR 0003 D14, ADR 0001).
func (m *Manager) OpenSegmentedTrailer(
	objectKey string, metadata map[string]string, trailer []byte,
) (dataencryption.Checksum, error) {
	codec, err := m.codecFor(objectKey, metadata)
	if err != nil {
		return dataencryption.Checksum{}, err
	}
	return codec.OpenTrailer(trailer)
}

// IsSegmentedObject reports whether the metadata describes an object this proxy
// wrote in the current format. Anything else is refused on read.
func (m *Manager) IsSegmentedObject(metadata map[string]string) bool {
	algorithm, err := m.metadataManager.GetAlgorithm(metadata)
	if err != nil || algorithm != dataencryption.FormatID {
		return false
	}
	_, err = m.metadataManager.GetEncryptedDEK(metadata)
	return err == nil
}

// newSegmentedObject draws a data key, wraps it, and builds the object metadata.
func (m *Manager) newSegmentedObject(
	objectKey string, userMetadata map[string]string,
) (*dataencryption.Codec, map[string]string, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	codec, err := dataencryption.NewCodec(dek, objectKey)
	if err != nil {
		return nil, nil, err
	}

	wrappedDEK, err := m.providerManager.EncryptDEK(dek, objectKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wrap data key: %w", err)
	}

	metadata := m.metadataManager.BuildSegmentedMetadata(
		wrappedDEK,
		m.providerManager.GetActiveFingerprint(),
		m.providerManager.GetActiveProviderAlgorithm(),
		userMetadata,
	)
	return codec, metadata, nil
}

// codecFor unwraps the object's data key and binds it to the key the client
// used. The provider is chosen by the fingerprint stored on the object, so a
// retired key still reads what it wrote.
func (m *Manager) codecFor(objectKey string, metadata map[string]string) (*dataencryption.Codec, error) {
	if !m.IsSegmentedObject(metadata) {
		return nil, ErrForeignObject
	}

	encryptedDEK, err := m.metadataManager.GetEncryptedDEK(metadata)
	if err != nil {
		return nil, ErrForeignObject
	}
	fingerprint, err := m.metadataManager.GetFingerprint(metadata)
	if err != nil {
		return nil, ErrForeignObject
	}

	dek, err := m.providerManager.DecryptDEK(encryptedDEK, fingerprint, objectKey)
	if err != nil {
		// Three permanent states of this object under this configuration, all
		// answered the same way: a wrap that does not authenticate, a
		// fingerprint naming a provider that is not loaded, and the exit
		// provider's own fingerprint, which holds no key material at all. None
		// of them can succeed on a retry, so none may reach the client as a 5xx
		// (ADR 0001). Anything else — a provider with a network round trip
		// behind it, when one exists — stays a 5xx, because a retry is the right
		// answer to an outage.
		if errors.Is(err, keyencryption.ErrWrappedDEKAuth) ||
			errors.Is(err, ErrUnknownFingerprint) ||
			errors.Is(err, keyencryption.ErrExitProviderKeyUse) {
			return nil, ErrKeyMaterialUnreadable
		}
		return nil, fmt.Errorf("failed to unwrap data key: %w", err)
	}
	return dataencryption.NewCodec(dek, objectKey)
}

// PlanRange maps a plaintext range onto the stored layout. It needs no key, so a
// handler can issue the backend request before it unwraps anything.
func PlanRange(offset, length, totalPlaintext int64) (dataencryption.Window, error) {
	return dataencryption.PlanRange(offset, length, totalPlaintext)
}

// PlaintextSize converts a stored length into the plaintext length it carries,
// without a key and without a round trip — which is what lets HEAD and the
// listings report plaintext sizes (ADR 0010). It converts a number the backend
// reports; only the trailer authenticates it.
func PlaintextSize(storedLen int64) (int64, error) {
	return dataencryption.PlaintextSize(storedLen)
}
