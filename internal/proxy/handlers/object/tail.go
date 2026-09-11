package object

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// An object's end is read before its beginning (ADR 0003 D14).
//
// The trailer is the object's only authenticated statement about itself: its
// plaintext length and the CRC32C over the whole plaintext, sealed under the
// object's own data key. Everything else a read could use — the stored length,
// the entity tag — is the backend's word, and the backend is the adversary
// (ADR 0001). Reading the trailer first is what lets `HEAD` report an
// authenticated length and lets both verbs serve `x-amz-checksum-crc32c` before
// the first body byte.
//
// It costs no extra request where the object is at most one segment, because the
// same read returns the whole object; above that a whole-object `GET` pays one
// more backend request for the remainder.
const (
	// tailFetchLen is what a whole-object GET asks for first: one full segment
	// with its framing, plus the trailer.
	tailFetchLen = dataencryption.SegmentSize + dataencryption.SegmentOverhead + dataencryption.TrailerSize

	// trailerFetchLen is what HEAD asks for: the trailer alone.
	trailerFetchLen = dataencryption.TrailerSize
)

// objectTail is the answer to that one ranged read.
type objectTail struct {
	// output carries the object's headers and metadata. Its body is drained and
	// closed by the time this exists.
	output *s3.GetObjectOutput
	// storedTotal is the whole object's stored length, from the answer's own
	// Content-Range. It is the backend's number, and sum.Length is checked
	// against it.
	storedTotal int64
	// stored is what the read returned: the last tailFetchLen stored bytes, or
	// the whole object when it is shorter than that.
	stored []byte
	// sum is what the trailer authenticates.
	sum dataencryption.Checksum
}

// coversWholeObject reports whether the read already returned every stored byte,
// which is the case for every object of at most one segment.
func (t *objectTail) coversWholeObject() bool { return int64(len(t.stored)) == t.storedTotal }

// fetchObjectTail reads the last want stored bytes of an object and opens the
// trailer in them. The client's conditional headers ride along, so a
// revalidating read is answered by the backend on this request rather than after
// the object has been fetched.
func (h *Handler) fetchObjectTail(r *http.Request, bucket, key string, want int64) (*objectTail, error) {
	input := &s3.GetObjectInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
		Range:               aws.String(fmt.Sprintf("bytes=-%d", want)),
	}
	ReadConditionalHeaders(r).ApplyToGetObject(input)

	output, err := h.s3Backend.GetObject(r.Context(), input)
	if err != nil {
		// An object with fewer bytes than a trailer cannot be one this proxy
		// wrote, so the backend's "range not satisfiable" is the foreign-object
		// refusal rather than a range error of the client's making.
		if response.MapError(err).StatusCode == http.StatusRequestedRangeNotSatisfiable {
			return nil, orchestration.ErrForeignObject
		}
		return nil, err
	}
	defer func() { _ = output.Body.Close() }()

	if !h.encryptionMgr.IsSegmentedObject(output.Metadata) {
		return nil, orchestration.ErrForeignObject
	}

	// A suffix range larger than the object comes back as the whole object, and
	// whether that is a 206 with a Content-Range or a 200 without one is the
	// backend's choice; both are handled.
	storedTotal := aws.ToInt64(output.ContentLength)
	if contentRange := aws.ToString(output.ContentRange); contentRange != "" {
		storedTotal, err = contentRangeTotal(contentRange)
		if err != nil {
			return nil, err
		}
	}

	// One allocation of exactly the window: this buffer is held for the whole
	// response on a GET, so io.ReadAll's doubling would leave a larger one behind
	// per request.
	buf := make([]byte, want)
	n, err := io.ReadFull(output.Body, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	stored := buf[:n]
	if int64(len(stored)) != min(storedTotal, want) || len(stored) < dataencryption.TrailerSize {
		return nil, dataencryption.ErrCorrupt
	}

	sum, err := h.encryptionMgr.OpenSegmentedTrailer(key, output.Metadata,
		stored[len(stored)-dataencryption.TrailerSize:])
	if err != nil {
		return nil, err
	}

	// The trailer is the authenticated statement of how long the plaintext is;
	// the stored length is the backend's. A disagreement is a truncation or an
	// extension, and it is caught here rather than as a body that stops short of
	// the Content-Length already sent.
	plaintext, err := orchestration.PlaintextSize(storedTotal)
	if err != nil || plaintext != sum.Length {
		return nil, dataencryption.ErrCorrupt
	}

	return &objectTail{output: output, storedTotal: storedTotal, stored: stored, sum: sum}, nil
}

// checksumHeader renders a sealed CRC32C the way S3 does: base64 of the four
// bytes, big-endian (ADR 0003 D14, ADR 0012).
func checksumHeader(sum dataencryption.Checksum) string {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], sum.Value)
	return base64.StdEncoding.EncodeToString(raw[:])
}

// writeReadError answers a failed read: a refusal the proxy decided itself, or
// whatever the backend said about the request.
func (h *Handler) writeReadError(w http.ResponseWriter, err error, bucket, key string) {
	if errors.Is(err, orchestration.ErrForeignObject) ||
		errors.Is(err, orchestration.ErrKeyMaterialUnreadable) ||
		errors.Is(err, dataencryption.ErrCorrupt) {
		h.writeDecryptionError(w, err, bucket, key)
		return
	}
	h.errorWriter.WriteS3Error(w, err, bucket, key)
}
