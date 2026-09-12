package object

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// byteRange is a resolved range over a known plaintext length.
type byteRange struct {
	start  int64
	length int64
	total  int64
}

func (b byteRange) end() int64 { return b.start + b.length - 1 }

// contentRange renders the Content-Range header value for a 206 response.
func (b byteRange) contentRange() string {
	return fmt.Sprintf("bytes %d-%d/%d", b.start, b.end(), b.total)
}

var (
	errUnsatisfiableRange = errors.New("range not satisfiable")
	errMultipleRanges     = errors.New("multiple ranges are not supported")
	errMalformedRange     = errors.New("malformed range header")
)

// parseByteRange resolves an HTTP Range header against a known total size.
//
// Supported forms, matching what S3 accepts:
//
//	bytes=start-end   an explicit window
//	bytes=start-      from start to the end of the object
//	bytes=-suffix     the last suffix bytes
//
// Multiple ranges are rejected: S3 does not serve them either, and a client that
// asks for them would otherwise silently receive only the first.
func parseByteRange(header string, total int64) (byteRange, error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return byteRange{}, errMalformedRange
	}
	if strings.Contains(spec, ",") {
		return byteRange{}, errMultipleRanges
	}

	startStr, endStr, ok := strings.Cut(spec, "-")
	if !ok {
		return byteRange{}, errMalformedRange
	}
	startStr, endStr = strings.TrimSpace(startStr), strings.TrimSpace(endStr)

	// Suffix form: the last N bytes.
	if startStr == "" {
		if endStr == "" {
			return byteRange{}, errMalformedRange
		}
		suffix, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffix < 0 {
			return byteRange{}, errMalformedRange
		}
		if suffix == 0 {
			return byteRange{}, errUnsatisfiableRange
		}
		if suffix > total {
			suffix = total
		}
		return byteRange{start: total - suffix, length: suffix, total: total}, nil
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return byteRange{}, errMalformedRange
	}
	if start >= total {
		return byteRange{}, errUnsatisfiableRange
	}

	end := total - 1
	if endStr != "" {
		end, err = strconv.ParseInt(endStr, 10, 64)
		if err != nil || end < start {
			return byteRange{}, errMalformedRange
		}
		if end > total-1 {
			end = total - 1
		}
	}
	return byteRange{start: start, length: end - start + 1, total: total}, nil
}

// rangeSpec is a Range header before it is resolved against a length. Only an
// explicit "bytes=a-b" carries enough to plan a window without knowing the
// object's size; the other two forms are relative to the end.
type rangeSpec struct {
	start    int64
	end      int64
	explicit bool
}

// parseRangeSpec classifies a Range header without needing the object's size.
func parseRangeSpec(header string) (rangeSpec, error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(header), "bytes=")
	if !ok {
		return rangeSpec{}, errMalformedRange
	}
	if strings.Contains(spec, ",") {
		return rangeSpec{}, errMultipleRanges
	}
	startStr, endStr, ok := strings.Cut(spec, "-")
	if !ok {
		return rangeSpec{}, errMalformedRange
	}
	startStr, endStr = strings.TrimSpace(startStr), strings.TrimSpace(endStr)
	if startStr == "" || endStr == "" {
		// A suffix range, or one that runs to the end: both need the length.
		return rangeSpec{}, nil
	}

	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start < 0 {
		return rangeSpec{}, errMalformedRange
	}
	end, err := strconv.ParseInt(endStr, 10, 64)
	if err != nil {
		return rangeSpec{}, errMalformedRange
	}
	if end < start {
		// Both bounds are numbers, so the header is understood — it just asks
		// for a range that cannot exist. The backend answers 416 for it, and so
		// does the proxy.
		return rangeSpec{}, errUnsatisfiableRange
	}
	return rangeSpec{start: start, end: end, explicit: true}, nil
}

// handleGetObjectRange serves a Range request over the segment chain.
//
// A plaintext range covers a run of segments, and that run is one contiguous
// stretch of stored bytes, so one backend request carries it. Read amplification
// is at most two segments — 128 KiB — against the whole object if the unit of
// authentication were the object, or a backend part if it were the part.
//
// The window has to be planned against the object's plaintext length, which the
// proxy learns from the stored length. For an explicit range it takes that from
// the Content-Range of the same answer: the window is planned as if every
// segment were full, the backend clamps what does not exist, and the plan is
// redone against the real length before a byte is opened. A suffix range and an
// open-ended one are relative to the end, so they cost one HEAD first.
func (h *Handler) handleGetObjectRange(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	log := h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
		"range":  rangeHeader,
	})

	// Under the exit provider the decision is per object: a bucket on the way out
	// holds both what this proxy encrypted before the switch and what was written
	// plainly since. A ranged read has to choose the stored window before it asks
	// for it, so this one costs a HEAD. Only the exit provider pays it — under an
	// encrypting provider an explicit range still costs a single backend request
	// (ADR 0003 D9), and a foreign object is refused when its metadata arrives.
	if h.encryptionMgr.IsExitProvider() {
		segmented, headErr := h.objectIsSegmented(r, bucket, key)
		if headErr != nil {
			h.writeDecryptionError(w, headErr, bucket, key)
			return
		}
		if !segmented {
			h.passThroughRange(w, r, bucket, key, rangeHeader)
			return
		}
	}

	spec, err := parseRangeSpec(rangeHeader)
	if errors.Is(err, errUnsatisfiableRange) {
		total, headErr := h.plaintextLength(r, bucket, key)
		if headErr != nil {
			h.writeDecryptionError(w, headErr, bucket, key)
			return
		}
		h.writeRangeError(w, errUnsatisfiableRange, total)
		return
	}
	if errors.Is(err, errMalformedRange) || errors.Is(err, errMultipleRanges) {
		// A Range header the proxy will not act on is ignored, and the whole
		// object is served: that is what RFC 7233 asks for and what AWS and the
		// backend do for both a header that cannot be parsed and a multi-range
		// header. Answering 200 without a Content-Range says plainly that no
		// range was applied, so nothing is accepted and quietly discarded.
		log.WithError(err).Debug("Ignoring a Range header the proxy does not act on")
		h.serveWholeObject(w, r, bucket, key)
		return
	}
	if err != nil {
		h.writeRangeError(w, err, 0)
		return
	}

	// The range sent to the backend is always computed, never the client's own
	// header: that one is in plaintext coordinates and would address the wrong
	// bytes of the stored object. Declared without a value so a path that forgets
	// to set it does not compile into forwarding the client's.
	var fetch string
	if spec.explicit {
		fetch = provisionalWindow(spec)
	} else {
		total, headErr := h.plaintextLength(r, bucket, key)
		if headErr != nil {
			h.writeDecryptionError(w, headErr, bucket, key)
			return
		}
		resolved, parseErr := parseByteRange(rangeHeader, total)
		if parseErr != nil {
			h.writeRangeError(w, parseErr, total)
			return
		}
		window, planErr := orchestration.PlanRange(resolved.start, resolved.length, total)
		if planErr != nil {
			h.writeRangeError(w, errUnsatisfiableRange, total)
			return
		}
		fetch = fmt.Sprintf("bytes=%d-%d", window.CiphertextOffset,
			window.CiphertextOffset+window.CiphertextLength-1)
	}

	input := &s3.GetObjectInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		Range:               aws.String(fetch),
		VersionId:           objectVersionID(r),
	}
	ReadConditionalHeaders(r).ApplyToGetObject(input)

	output, err := h.s3Backend.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer func() { closeDrained(output.Body) }()

	storedTotal, err := contentRangeTotal(aws.ToString(output.ContentRange))
	if err != nil {
		log.WithError(err).Error("Backend returned an unusable Content-Range for a ranged read")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError",
			"Failed to serve the requested range")
		return
	}
	total, err := orchestration.PlaintextSize(storedTotal)
	if err != nil {
		h.writeDecryptionError(w, orchestration.ErrForeignObject, bucket, key)
		return
	}

	resolved, err := parseByteRange(rangeHeader, total)
	if err != nil {
		h.writeRangeError(w, err, total)
		return
	}
	window, err := orchestration.PlanRange(resolved.start, resolved.length, total)
	if err != nil {
		h.writeRangeError(w, errUnsatisfiableRange, total)
		return
	}

	// The provisional window assumed every segment was full, so the answer may
	// carry more bytes than the real window needs. The reader must see exactly
	// the window and nothing after it.
	decrypted, err := h.encryptionMgr.OpenSegmentedRange(key, output.Metadata,
		io.LimitReader(output.Body, window.CiphertextLength), window)
	if err != nil {
		h.writeDecryptionError(w, err, bucket, key)
		return
	}

	h.writeRangeResponse(w, decrypted, resolved.contentRange(), resolved.length, output)
}

// maxWindowOverAsk bounds what provisionalWindow can ask for beyond the real
// window: one segment, because it assumes the last segment of the range is full,
// plus the trailer it always appends.
const maxWindowOverAsk = dataencryption.SegmentSize + dataencryption.SegmentOverhead + dataencryption.TrailerSize

// closeDrained returns the backend body after consuming what the reader left.
// A ranged read asks for a provisional window and then reads exactly the real
// one, so a few bytes are always unread; closing an HTTP body that is not at EOF
// makes Go's transport drop the connection instead of pooling it, and every
// ranged read then pays a new handshake. Measured on 2026-09-11: without this,
// a 1 MiB ranged read through the proxy runs at 155 MiB/s against a backend
// doing 220, and with it at 193.
func closeDrained(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxWindowOverAsk))
	_ = body.Close()
}

// provisionalWindow is the stored range an explicit plaintext range needs if the
// object is large enough to hold it. It is deliberately generous by one trailer:
// a range that reaches the end of the object then carries the trailer with it,
// and a range that does not costs 40 bytes the reader never looks at.
func provisionalWindow(spec rangeSpec) string {
	const stride = dataencryption.SegmentSize + dataencryption.SegmentOverhead
	first := spec.start / dataencryption.SegmentSize
	last := spec.end / dataencryption.SegmentSize
	from := first * stride
	to := (last+1)*stride - 1 + dataencryption.TrailerSize
	return fmt.Sprintf("bytes=%d-%d", from, to)
}

// objectIsSegmented asks the backend whether this object carries the proxy's
// metadata. It costs one HEAD and is only reached under the exit provider,
// where the answer decides between decrypting the object and serving it
// verbatim.
func (h *Handler) objectIsSegmented(r *http.Request, bucket, key string) (bool, error) {
	head, err := h.s3Backend.HeadObject(r.Context(), &s3.HeadObjectInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
	})
	if err != nil {
		return false, err
	}
	if !h.encryptionMgr.IsSegmentedObject(head.Metadata) {
		if h.encryptionMgr.ClaimsSegmentedFormat(head.Metadata) {
			// Ours, and the wrapped key is gone or unreadable. Pass-through here
			// would serve a window of the segment chain as a 206.
			return false, orchestration.ErrKeyMaterialUnreadable
		}
		return false, nil
	}
	return true, nil
}

// plaintextLength asks the backend how large the object is and converts the
// answer. It costs one HEAD, and only the two range forms that are relative to
// the end of the object pay it.
func (h *Handler) plaintextLength(r *http.Request, bucket, key string) (int64, error) {
	head, err := h.s3Backend.HeadObject(r.Context(), &s3.HeadObjectInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
	})
	if err != nil {
		return 0, err
	}
	if !h.encryptionMgr.IsSegmentedObject(head.Metadata) {
		return 0, orchestration.ErrForeignObject
	}
	return orchestration.PlaintextSize(aws.ToInt64(head.ContentLength))
}

// passThroughRange serves a ranged read under the pass-through provider, where
// stored bytes and plaintext are the same bytes.
func (h *Handler) passThroughRange(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	input := &s3.GetObjectInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		Range:               aws.String(rangeHeader),
		VersionId:           objectVersionID(r),
	}
	ReadConditionalHeaders(r).ApplyToGetObject(input)

	output, err := h.s3Backend.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer func() { _ = output.Body.Close() }()

	h.writeRangeResponse(w, output.Body, aws.ToString(output.ContentRange),
		aws.ToInt64(output.ContentLength), output)
}

// contentRangeTotal extracts the total size from a "bytes start-end/total"
// header.
func contentRangeTotal(contentRange string) (int64, error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(contentRange), "bytes ")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	_, totalStr, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	total, err := strconv.ParseInt(strings.TrimSpace(totalStr), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected Content-Range %q: %w", contentRange, err)
	}
	return total, nil
}

func (h *Handler) writeRangeResponse(w http.ResponseWriter, body io.Reader, contentRange string, length int64, output *s3.GetObjectOutput) {
	header := w.Header()
	header.Set("Accept-Ranges", "bytes")
	if contentRange != "" {
		header.Set("Content-Range", contentRange)
	}
	if length >= 0 {
		header.Set("Content-Length", strconv.FormatInt(length, 10))
	}
	if output.ContentType != nil {
		header.Set("Content-Type", aws.ToString(output.ContentType))
	}
	if output.ETag != nil {
		header.Set("ETag", aws.ToString(output.ETag))
	}
	if output.LastModified != nil {
		header.Set("Last-Modified", output.LastModified.UTC().Format(http.TimeFormat))
	}
	for name, value := range h.cleanMetadata(output.Metadata) {
		header.Set("x-amz-meta-"+name, value)
	}
	writeVersionHeaders(w, output.VersionId, nil)
	writeEntityHeaders(w, storedEntityHeaders{
		ContentEncoding:    output.ContentEncoding,
		ContentDisposition: output.ContentDisposition,
		ContentLanguage:    output.ContentLanguage,
		CacheControl:       output.CacheControl,
		Expires:            output.ExpiresString,
	})

	w.WriteHeader(http.StatusPartialContent)
	// Same pooled buffer as the whole-object GET, for the same reason: the body
	// is a decrypting reader, so ReadFrom can never reach sendfile and degrades
	// to a fresh 32 KiB buffer per request. Measured by BenchmarkGetResponseCopy.
	if _, err := copyWithPooledBuffer(w, body); err != nil {
		// The status line is already sent; all that is left is to record it.
		h.logger.WithError(err).Warn("Failed to write the ranged response body")
	}
}

// writeRangeError maps a range parsing failure onto the S3 error S3 itself
// returns for it.
func (h *Handler) writeRangeError(w http.ResponseWriter, err error, total int64) {
	switch {
	case errors.Is(err, errUnsatisfiableRange):
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", total))
		h.errorWriter.WriteGenericError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange",
			"The requested range is not satisfiable")
	case errors.Is(err, errMultipleRanges):
		h.errorWriter.WriteGenericError(w, http.StatusNotImplemented, "NotImplemented",
			"Multiple byte ranges in a single request are not supported")
	default:
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"Malformed Range header")
	}
}
