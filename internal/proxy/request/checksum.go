package request

import (
	"bytes"
	"crypto/md5"  // #nosec G501 - Content-MD5 is a client-declared transmission check, not a security primitive
	"crypto/sha1" // #nosec G505 - x-amz-checksum-sha1 is a client-declared transmission check
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net/http"
	"strings"
)

// Client upload checksums are verified against the plaintext payload and never
// forwarded to the backend (ADR 0012). The value the client declares describes
// the plaintext; the body the proxy uploads is a sealed segment chain, so the
// backend could not check it even if it were sent.
//
// docu: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html

const (
	// contentMD5Header is the one declaration that is not an x-amz-checksum-* name.
	contentMD5Header = "Content-MD5"
	// trailerDeclarationHeader names the trailers the client promises to send.
	trailerDeclarationHeader = "X-Amz-Trailer"
)

// ErrChecksumMismatch and ErrChecksumMalformed are the two verdicts. A mismatch
// answers 400 BadDigest, a value that is not base64 of the algorithm's digest
// length answers 400 InvalidDigest (ADR 0012 D6).
var (
	ErrChecksumMismatch  = errors.New("client checksum does not match the payload")
	ErrChecksumMalformed = errors.New("client checksum value is malformed")
)

// ChecksumError carries which declaration failed, for the log. The client-facing
// wording is fixed per S3 error code and never quotes this text.
type ChecksumError struct {
	Declaration string // the header or trailer name the client used
	Detail      string
	verdict     error
}

func (e *ChecksumError) Error() string {
	return fmt.Sprintf("%s: %s%s", e.Declaration, e.verdict, e.Detail)
}

func (e *ChecksumError) Unwrap() error { return e.verdict }

func mismatch(declaration string) error {
	return &ChecksumError{Declaration: declaration, verdict: ErrChecksumMismatch}
}

func malformed(declaration, detail string) error {
	return &ChecksumError{Declaration: declaration, Detail: " (" + detail + ")", verdict: ErrChecksumMalformed}
}

// checksumAlgorithm binds a declaration name to its hash and digest length.
type checksumAlgorithm struct {
	name      string
	newHash   func() hash.Hash
	digestLen int
}

// checksumAlgorithms holds every algorithm S3 defines for an upload. All of them
// are stdlib; the CRCs run on dedicated instructions on both supported
// architectures, MD5 on none.
var checksumAlgorithms = map[string]*checksumAlgorithm{
	"x-amz-checksum-crc32":     {name: "x-amz-checksum-crc32", newHash: func() hash.Hash { return crc32.NewIEEE() }, digestLen: 4},
	"x-amz-checksum-crc32c":    {name: "x-amz-checksum-crc32c", newHash: func() hash.Hash { return crc32.New(crc32.MakeTable(crc32.Castagnoli)) }, digestLen: 4},
	"x-amz-checksum-crc64nvme": {name: "x-amz-checksum-crc64nvme", newHash: newCRC64NVME, digestLen: 8},
	"x-amz-checksum-sha1":      {name: "x-amz-checksum-sha1", newHash: func() hash.Hash { return sha1.New() }, digestLen: 20}, // #nosec G401
	"x-amz-checksum-sha256":    {name: "x-amz-checksum-sha256", newHash: func() hash.Hash { return sha256.New() }, digestLen: 32},
	// Content-MD5 is keyed by its lowercase header name so the lookup is uniform;
	// it never arrives as an aws-chunked trailer.
	"content-md5": {name: contentMD5Header, newHash: func() hash.Hash { return md5.New() }, digestLen: 16}, // #nosec G401
}

// declaration is one algorithm the request asked to have verified, together with
// the running hash over the payload.
type declaration struct {
	alg *checksumAlgorithm
	sum hash.Hash
	// want is the digest from a request header, decoded. nil when the value is
	// promised as a trailer instead.
	want []byte
	// wantName is the header name the client used, for the error.
	wantName string
	// trailer is the lowercase trailer name that must deliver the value, empty
	// when the value came in a header.
	trailer string
}

// checksumReader hashes the decoded payload as it passes and compares at EOF.
//
// The bytes are hashed out of the caller's own buffer, so there is no staging
// copy and no second traversal. What bounds a read is the source — the
// aws-chunked decoder's 128 KiB bufio, or whatever the socket has — so the data
// is still in cache when the hash runs.
type checksumReader struct {
	src          io.Reader
	declarations []*declaration
	trailers     func() map[string]string

	// held is the last payload byte read so far. Holding it back is what makes
	// the verdict land before anything is committed (ADR 0012 D7): a consumer
	// streaming the body straight to the backend can never have delivered the
	// complete payload while verification is still open.
	held    byte
	hasHeld bool

	done   bool
	failed error
}

// Verdict returns the verification failure this reader produced, or nil.
//
// A handler asks the reader directly rather than inspecting the error it got
// back: on the single-request PUT path the read error travels through net/http,
// *url.Error and smithy wrapping before the handler sees it.
func (v *checksumReader) Verdict() error { return v.failed }

func (v *checksumReader) Read(p []byte) (int, error) {
	if v.failed != nil {
		return 0, v.failed
	}
	if len(p) == 0 {
		return 0, nil
	}

	n := 0
	if v.hasHeld {
		p[0] = v.held
		v.hasHeld = false
		n = 1
		if len(p) == 1 {
			// No room to read and hold again; refill the hold next call.
			return 1, nil
		}
	}

	read, err := v.src.Read(p[n:])
	if read > 0 {
		for _, d := range v.declarations {
			_, _ = d.sum.Write(p[n : n+read])
		}
		read--
		v.held = p[n+read]
		v.hasHeld = true
		n += read
	}

	if err == nil {
		return n, nil
	}
	if err != io.EOF {
		return n, err
	}
	if verr := v.finish(); verr != nil {
		v.failed = verr
		return n, verr
	}
	if v.hasHeld {
		// p[n] is free: it held the byte that was kept back, and read was
		// bounded by len(p)-n.
		p[n] = v.held
		v.hasHeld = false
		n++
	}
	return n, io.EOF
}

// finish compares every declaration once the payload is complete.
func (v *checksumReader) finish() error {
	if v.done {
		return nil
	}
	v.done = true

	var trailers map[string]string
	if v.trailers != nil {
		trailers = v.trailers()
	}

	for _, d := range v.declarations {
		got := d.sum.Sum(nil)

		if d.want != nil {
			if !bytes.Equal(got, d.want) {
				return mismatch(d.wantName)
			}
		}
		if d.trailer == "" {
			continue
		}

		raw, ok := trailers[d.trailer]
		if !ok || raw == "" {
			// A trailer named in X-Amz-Trailer that never arrives is a failed
			// verification, not an absent one (ADR 0012 D5): otherwise omitting
			// it is a free opt-out from the check the client asked for.
			return mismatch(d.trailer)
		}
		want, err := decodeDigest(raw, d.alg)
		if err != nil {
			return &ChecksumError{Declaration: d.trailer, Detail: " (" + err.Error() + ")", verdict: ErrChecksumMalformed}
		}
		if !bytes.Equal(got, want) {
			return mismatch(d.trailer)
		}
	}
	return nil
}

// decodeDigest turns a declared value into the raw digest it must equal.
//
// Padding is accepted either way: S3 specifies padded base64, and being lenient
// about the padding only avoids refusing a correct client. The length check is
// what actually gates the value.
func decodeDigest(value string, alg *checksumAlgorithm) ([]byte, error) {
	value = strings.TrimSpace(value)
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(value)
	}
	if err != nil {
		return nil, errors.New("not valid base64")
	}
	if len(raw) != alg.digestLen {
		return nil, fmt.Errorf("expected %d digest bytes, got %d", alg.digestLen, len(raw))
	}
	return raw, nil
}

// declaredChecksums collects what the request asked to have verified. It returns
// nil when the request declares nothing, which is what keeps the cost of an
// upload without a checksum at exactly zero.
func declaredChecksums(r *http.Request) ([]*declaration, error) {
	var out []*declaration

	add := func(alg *checksumAlgorithm) *declaration {
		for _, d := range out {
			if d.alg == alg {
				return d
			}
		}
		d := &declaration{alg: alg, sum: alg.newHash()}
		out = append(out, d)
		return d
	}

	for key, alg := range checksumAlgorithms {
		value := r.Header.Get(key)
		if value == "" {
			continue
		}
		want, err := decodeDigest(value, alg)
		if err != nil {
			// Refused before a byte of the body is read, so no backend request
			// is ever opened for a declaration that cannot be satisfied.
			return nil, malformed(alg.name, err.Error())
		}
		d := add(alg)
		d.want = want
		d.wantName = alg.name
	}

	for _, name := range strings.Split(r.Header.Get(trailerDeclarationHeader), ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		alg, ok := checksumAlgorithms[name]
		// Content-MD5 is not a trailer, and an unknown name is not a checksum.
		if !ok || alg.name == contentMD5Header {
			continue
		}
		add(alg).trailer = name
	}

	return out, nil
}

// DeclaresChecksum reports whether the request carries a verifiable digest, in a
// header or promised as a trailer. The multi-object delete refuses a request
// that carries none (ADR 0012 D14).
func DeclaresChecksum(r *http.Request) bool {
	declared, err := declaredChecksums(r)
	return err != nil || len(declared) > 0
}

// Verdict returns the checksum verification failure a reader produced, or nil
// for a reader that verifies nothing.
func Verdict(src io.Reader) error {
	if v, ok := src.(*checksumReader); ok {
		return v.Verdict()
	}
	return nil
}

// IsChecksumFailure reports whether err is a checksum verdict, and which one.
func IsChecksumFailure(err error) (malformedValue bool, ok bool) {
	switch {
	case errors.Is(err, ErrChecksumMalformed):
		return true, true
	case errors.Is(err, ErrChecksumMismatch):
		return false, true
	default:
		return false, false
	}
}

// verifying wraps src when the request declares a checksum, and returns src
// untouched when it does not — not even a Read indirection.
func verifying(r *http.Request, src io.Reader, trailers func() map[string]string) (io.Reader, error) {
	declared, err := declaredChecksums(r)
	if err != nil {
		return nil, err
	}
	if len(declared) == 0 {
		return src, nil
	}
	return &checksumReader{src: src, declarations: declared, trailers: trailers}, nil
}
