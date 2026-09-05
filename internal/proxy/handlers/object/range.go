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
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption"
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

// handleGetObjectRange serves a Range request on a possibly encrypted object.
//
// Strategy, one backend request in the common case:
//
//   - Ask the backend for the same byte window. For AES-CTR and for unencrypted
//     objects the ciphertext offsets equal the plaintext offsets, so the window
//     is exact.
//   - AES-CTR: decrypt the returned bytes with the keystream seeked to the
//     range start. This is what kopia needs; it reads its pack blobs with small
//     ranged GETs and would otherwise have to fetch every blob in full.
//   - AES-GCM: the authentication tag covers the whole ciphertext, so the
//     partial response is discarded and the object is fetched and decrypted in
//     full before the range is taken. Bounded work: GCM is only used below
//     optimizations.streaming_threshold.
func (h *Handler) handleGetObjectRange(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	log := h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
		"range":  rangeHeader,
	})

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Range:  aws.String(rangeHeader),
	}
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		input.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch := r.Header.Get("If-None-Match"); ifNoneMatch != "" {
		input.IfNoneMatch = aws.String(ifNoneMatch)
	}

	output, err := h.s3Backend.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer func() { _ = output.Body.Close() }()

	if _, hasEncryption, _ := h.extractEncryptionMetadata(output.Metadata); !hasEncryption {
		// Nothing to decrypt: hand the backend's partial response straight through.
		log.Debug("Ranged read of an unencrypted object, passing through")
		h.writeRangeResponse(w, output.Body, aws.ToString(output.ContentRange),
			aws.ToInt64(output.ContentLength), output)
		return
	}

	algorithm := h.encryptionMgr.GetMetadataAlgorithm(output.Metadata)
	if algorithm != "aes-ctr" {
		// AES-GCM (or anything else that is not seekable): close the partial
		// response and take the range from a full decryption.
		_ = output.Body.Close()
		log.WithField("algorithm", algorithm).Debug("Ranged read requires full decryption")
		h.serveRangeByFullDecryption(w, r, bucket, key, rangeHeader)
		return
	}

	// The backend answered with the ciphertext window. For AES-CTR ciphertext
	// and plaintext offsets coincide, so its Content-Range is already the one
	// the client should see.
	contentRange := aws.ToString(output.ContentRange)
	start, parseErr := contentRangeStart(contentRange)
	if parseErr != nil {
		log.WithError(parseErr).Error("Backend returned an unusable Content-Range for a ranged read")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError",
			"Failed to serve the requested range")
		return
	}

	decrypted, err := h.encryptionMgr.CreateRangeDecryptionReader(r.Context(), output.Body,
		output.Metadata, key, start)
	if err != nil {
		var unsupported *orchestration.RangeReadUnsupportedError
		if errors.As(err, &unsupported) {
			_ = output.Body.Close()
			h.serveRangeByFullDecryption(w, r, bucket, key, rangeHeader)
			return
		}
		log.WithError(err).Error("Failed to create a ranged decryption reader")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError",
			"Failed to decrypt the requested range")
		return
	}

	h.writeRangeResponse(w, decrypted, contentRange, aws.ToInt64(output.ContentLength), output)
}

// serveRangeByFullDecryption decrypts the whole object and returns the requested
// window of the plaintext. Used for algorithms whose ciphertext cannot be
// decrypted from an arbitrary offset.
func (h *Handler) serveRangeByFullDecryption(w http.ResponseWriter, r *http.Request, bucket, key, rangeHeader string) {
	output, err := h.s3Backend.GetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer func() { _ = output.Body.Close() }()

	algorithm := h.encryptionMgr.GetMetadataAlgorithm(output.Metadata)
	total := encryption.ComputePlaintextSize(aws.ToInt64(output.ContentLength), algorithm)
	if total < 0 {
		h.logger.WithField("algorithm", algorithm).Error("Cannot determine the plaintext size for a ranged read")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError",
			"Failed to serve the requested range")
		return
	}

	br, err := parseByteRange(rangeHeader, total)
	if err != nil {
		h.writeRangeError(w, err, total)
		return
	}

	plaintext, err := h.encryptionMgr.DecryptDataWithMetadata(r.Context(), output.Body, output.Metadata, key)
	if err != nil {
		h.logger.WithError(err).Error("Failed to decrypt object for a ranged read")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError",
			"Failed to decrypt object data")
		return
	}
	defer func() { _ = plaintext.Close() }()

	if _, err := io.CopyN(io.Discard, plaintext, br.start); err != nil {
		h.logger.WithError(err).Error("Failed to skip to the range start")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError",
			"Failed to serve the requested range")
		return
	}

	h.writeRangeResponse(w, io.LimitReader(plaintext, br.length), br.contentRange(), br.length, output)
}

// writeRangeResponse emits a 206 with the decrypted window.
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

	w.WriteHeader(http.StatusPartialContent)
	if _, err := io.Copy(w, body); err != nil {
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

// contentRangeStart extracts the start offset from a "bytes start-end/total"
// header.
func contentRangeStart(contentRange string) (int64, error) {
	spec, ok := strings.CutPrefix(strings.TrimSpace(contentRange), "bytes ")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	rangePart, _, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	startStr, _, ok := strings.Cut(rangePart, "-")
	if !ok {
		return 0, fmt.Errorf("unexpected Content-Range %q", contentRange)
	}
	start, err := strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("unexpected Content-Range %q: %w", contentRange, err)
	}
	return start, nil
}
