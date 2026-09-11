package object

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/utils"
	"github.com/guided-traffic/s3-encryption-proxy/pkg/encryption/dataencryption"
)

// handleGetObject handles GET object requests with decryption support
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object")

	// A ranged read addresses plaintext offsets while the backend holds the
	// sealed chain, so it plans its own window and takes a separate path.
	if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
		h.handleGetObjectRange(w, r, bucket, key, rangeHeader)
		return
	}

	h.serveWholeObject(w, r, bucket, key)
}

// serveWholeObject reads an object from the first byte to the last.
func (h *Handler) serveWholeObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	input := &s3.GetObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: objectVersionID(r),
	}
	ReadConditionalHeaders(r).ApplyToGetObject(input)

	output, err := h.s3Backend.GetObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer output.Body.Close()

	// The decision is per object, not per provider. Under the exit provider a
	// bucket legitimately holds both: objects this proxy encrypted before the
	// switch, which are still decrypted here, and objects written since, which
	// are stored as the client sent them. Under an encrypting provider an object
	// the proxy did not write is refused instead of passed through (ADR 0001).
	if !h.encryptionMgr.IsSegmentedObject(output.Metadata) {
		if h.encryptionMgr.IsExitProvider() {
			h.writeGetObjectResponse(w, output, false)
			return
		}
		h.writeDecryptionError(w, orchestration.ErrForeignObject, bucket, key)
		return
	}

	plaintext, err := h.encryptionMgr.OpenSegmented(key, output.Metadata, output.Body)
	if err != nil {
		h.writeDecryptionError(w, err, bucket, key)
		return
	}

	// The stored length converts to the plaintext length without a second round
	// trip. It is the backend's number until the trailer confirms it, which the
	// reader does before it reports the end of the object.
	var plaintextLen *int64
	if output.ContentLength != nil {
		size, sizeErr := orchestration.PlaintextSize(aws.ToInt64(output.ContentLength))
		if sizeErr != nil {
			h.writeDecryptionError(w, orchestration.ErrForeignObject, bucket, key)
			return
		}
		plaintextLen = aws.Int64(size)
	}

	// Only the fields writeGetObjectResponse emits are carried over. Everything
	// else the backend returned describes the stored ciphertext, not the
	// plaintext this response delivers.
	h.writeGetObjectResponse(w, &s3.GetObjectOutput{
		Body:               plaintext,
		CacheControl:       output.CacheControl,
		ContentDisposition: output.ContentDisposition,
		ContentEncoding:    output.ContentEncoding,
		ContentLanguage:    output.ContentLanguage,
		ContentLength:      plaintextLen,
		ContentType:        output.ContentType,
		ExpiresString:      output.ExpiresString,
		ETag:               output.ETag,
		LastModified:       output.LastModified,
		Metadata:           h.cleanMetadata(output.Metadata),
		VersionId:          output.VersionId,
	}, true)
}

// writeDecryptionError answers a read the proxy cannot serve. An object it did
// not write is InvalidObjectState with 403: the object exists and the client is
// allowed, so neither NoSuchKey nor AccessDenied says what happened, and there
// is no opt-out that would let the ciphertext through (ADR 0003).
//
// A wrapped key that does not authenticate gets the same answer, for the same
// reason and one more: it is a permanent state of that object, and a 5xx would
// have the client's SDK retry a read that cannot succeed and report a corrupted
// object as a passing outage.
func (h *Handler) writeDecryptionError(w http.ResponseWriter, err error, bucket, key string) {
	if errors.Is(err, orchestration.ErrForeignObject) {
		h.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Warn("Refusing to serve an object this proxy did not write")
		h.errorWriter.WriteGenericError(w, http.StatusForbidden, "InvalidObjectState",
			"Object is not encrypted by this proxy")
		return
	}

	if errors.Is(err, orchestration.ErrKeyMaterialUnreadable) {
		h.logger.WithFields(map[string]interface{}{
			"bucket": bucket,
			"key":    key,
		}).Warn("Refusing to serve an object whose wrapped data key does not authenticate")
		h.errorWriter.WriteGenericError(w, http.StatusForbidden, "InvalidObjectState",
			"Object key material failed authentication")
		return
	}

	h.logger.WithError(err).WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Error("Failed to open the object")
	h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "DecryptionError", "Failed to decrypt object data")
}

// writeGetObjectResponse writes the GET object response to the HTTP response writer.
//
// The response is composed from an allowlist, never proxied: the backend's
// x-amz-checksum-* values describe the stored ciphertext while this response carries
// plaintext, so no checksum header is ever emitted here.
func (h *Handler) writeGetObjectResponse(w http.ResponseWriter, output *s3.GetObjectOutput, _ bool) {
	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	if output.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*output.ContentLength, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.UTC().Format(http.TimeFormat))
	}
	// Ranged reads work for every object the proxy stores, encrypted included.
	w.Header().Set("Accept-Ranges", "bytes")
	writeVersionHeaders(w, output.VersionId, nil)
	writeEntityHeaders(w, storedEntityHeaders{
		ContentEncoding:    output.ContentEncoding,
		ContentDisposition: output.ContentDisposition,
		ContentLanguage:    output.ContentLanguage,
		CacheControl:       output.CacheControl,
		Expires:            output.ExpiresString,
	})

	// Copy metadata headers (encryption metadata is already cleaned)
	if output.Metadata != nil {
		for key, value := range output.Metadata {
			w.Header().Set("x-amz-meta-"+key, value)
		}
	}

	w.WriteHeader(http.StatusOK)

	// A pooled buffer, because the body is a decrypting reader: ReadFrom can
	// never reach sendfile here and would allocate a fresh 32 KiB buffer per
	// request. Measured by BenchmarkGetResponseCopy.
	if _, err := copyWithPooledBuffer(w, output.Body); err != nil {
		h.logger.WithError(err).Error("Failed to write object data")
		return
	}

	// Closing is what makes a failure visible: the reader verifies the trailer
	// against what it produced, and reports it here rather than by handing out
	// bytes it could not authenticate.
	if output.Body != nil {
		if err := output.Body.Close(); err != nil {
			h.logger.WithError(err).Error("Object failed verification while it was served")
		}
	}
}

// handlePutObject handles PUT object requests with encryption support
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Putting object")

	// Check if this is a CopyObject request (PUT with x-amz-copy-source header)
	if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
		h.logger.WithFields(map[string]interface{}{
			"bucket":     bucket,
			"key":        key,
			"copySource": copySource,
		}).Debug("CopyObject operation detected")

		// CopyObject is not supported with encryption because:
		// 1. Server-side copy operations work at the S3 storage level
		// 2. Our encryption happens at the proxy level before storage
		// 3. Copying encrypted data would require decrypting source and re-encrypting
		// 4. This breaks the efficiency and security model of server-side copy operations
		h.errorWriter.WriteNotSupportedWithEncryption(w, "CopyObject")
		return
	}

	// The storage headers are read once, for both upload paths, so the two cannot
	// answer the same request differently (ADR 0007 D3).
	entity, attrs, err := ReadUploadHeaders(r)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
		return
	}

	// Every routing decision is on the PLAINTEXT length, and only on a number
	// that really describes the plaintext. r.ContentLength is the wire length:
	// for an aws-chunked upload it counts the chunk framing and the checksum
	// trailer, so an upload framed that way without X-Amz-Decoded-Content-Length
	// would be routed to the single-request write with a length larger than the
	// object, and the backend would be promised ciphertext the body cannot fill.
	plaintextLen, known := h.requestParser.PlaintextContentLength(r)

	// A single PutObject needs a stored length up front, and under the segment
	// chain that length is a pure function of the plaintext length. An undeclared
	// length, or an object larger than one part, goes to the multipart producer -
	// there is no threshold to tune and no second cipher to choose.
	if !known || plaintextLen > h.config.Optimizations.StreamingSegmentSize {
		h.putObjectAutoMultipart(w, r, bucket, key, entity, attrs)
		return
	}

	h.putObjectSegmented(w, r, bucket, key, plaintextLen, entity, attrs)
}

// putObjectSegmented writes an object in one request. The body seals as the
// backend pulls it, so nothing beyond a segment is ever held, and the stored
// length is known before the first byte moves (ADR 0003, ADR 0024 D1).
func (h *Handler) putObjectSegmented(
	w http.ResponseWriter, r *http.Request, bucket, key string, plaintextLen int64,
	entity EntityHeaders, attrs StorageAttributes,
) {
	// A declared checksum the proxy cannot even parse is refused here, before a
	// backend request is opened (ADR 0012 D6).
	body, err := h.requestParser.StreamingReader(r)
	if err != nil {
		h.errorWriter.WriteChecksumVerdict(w, err)
		return
	}

	// A zero-length body is never pulled: the SDK attaches no stream when the
	// content length is zero, so nothing would drive the verifier to a verdict
	// and a client that declared a digest of content it then failed to send
	// would be answered 200. That is precisely the fault a checksum exists to
	// catch, so the verdict is taken here instead.
	if plaintextLen == 0 {
		if _, derr := io.Copy(io.Discard, body); derr != nil {
			if h.errorWriter.WriteChecksumVerdict(w, derr) {
				return
			}
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "IncompleteBody",
				"The request body terminated before the declared number of bytes was read")
			return
		}
		if verdict := request.Verdict(body); verdict != nil {
			h.errorWriter.WriteChecksumVerdict(w, verdict)
			return
		}
		body = bytes.NewReader(nil)
	}

	putInput := &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	entity.ApplyToPutObject(putInput)
	attrs.ApplyToPutObject(putInput)
	// If-None-Match: * against an existing key is what makes a create-if-absent
	// upload possible; the backend answers 412 rather than overwriting.
	ReadConditionalHeaders(r).ApplyToPutObject(putInput)

	if h.encryptionMgr.IsExitProvider() {
		// Pass-through: the object is stored as the client sent it, with no
		// proxy metadata at all.
		putInput.Body = body
		putInput.ContentLength = aws.Int64(plaintextLen)
		putInput.Metadata = h.userMetadataFromRequest(r)
	} else {
		write, werr := h.encryptionMgr.NewSegmentedWrite(key, body, plaintextLen, h.userMetadataFromRequest(r))
		if werr != nil {
			h.logger.WithError(werr).Error("Failed to prepare the encrypted object")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to encrypt object data")
			return
		}
		putInput.Body = write.Body
		putInput.ContentLength = aws.Int64(write.ContentLength)
		putInput.Metadata = write.Metadata
	}

	putOutput, err := h.s3Backend.PutObject(r.Context(), putInput)

	// The verifier is asked directly, and whatever the backend answered: its
	// error reaches here through net/http, *url.Error and smithy wrapping, so
	// the answer for a client mistake must not depend on that chain staying
	// unwrappable — nor on the backend having refused the short body that a
	// failed verification produces.
	if verdict := request.Verdict(body); verdict != nil {
		h.errorWriter.WriteChecksumVerdict(w, verdict)
		return
	}
	if err != nil {
		h.logger.WithError(err).Error("Failed to upload object to S3")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	h.logger.WithFields(map[string]interface{}{
		"bucket":        bucket,
		"key":           key,
		"plaintextSize": plaintextLen,
		"storedSize":    aws.ToInt64(putInput.ContentLength),
	}).Debug("Single-request upload completed")

	w.Header().Set("ETag", aws.ToString(putOutput.ETag))
	writeVersionHeaders(w, putOutput.VersionId, nil)
	w.WriteHeader(http.StatusOK)
}

// handleDeleteObject handles DELETE object requests
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Deleting object")

	input := &s3.DeleteObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: objectVersionID(r),
	}

	output, err := h.s3Backend.DeleteObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	writeVersionHeaders(w, output.VersionId, output.DeleteMarker)
	w.WriteHeader(http.StatusNoContent)
}

// handleHeadObject handles HEAD object requests with encryption metadata filtering
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"bucket": bucket,
		"key":    key,
	}).Debug("Getting object metadata")

	input := &s3.HeadObjectInput{
		Bucket:    aws.String(bucket),
		Key:       aws.String(key),
		VersionId: objectVersionID(r),
	}
	// The same preconditions a GET honours, so the two verbs give the same
	// answer to the same request (ADR 0007 D7).
	ReadConditionalHeaders(r).ApplyToHeadObject(input)

	output, err := h.s3Backend.HeadObject(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	// Set response headers
	if output.ContentType != nil {
		w.Header().Set("Content-Type", *output.ContentType)
	}
	// An encrypting proxy does not describe an object it did not write, whether
	// or not the backend told it how large that object is. HEAD leaks less than
	// GET, but it still confirms the object and hands out its metadata.
	segmented := h.encryptionMgr.IsSegmentedObject(output.Metadata)
	if !segmented && !h.encryptionMgr.IsExitProvider() {
		h.writeDecryptionError(w, orchestration.ErrForeignObject, bucket, key)
		return
	}

	if output.ContentLength != nil {
		// The backend reports the stored length; a client reads plaintext. The two
		// differ by the segment framing and the trailer, and the difference is a
		// pure function of the stored length, so no round trip is needed to state
		// it (ADR 0010).
		length := aws.ToInt64(output.ContentLength)
		if segmented {
			plaintext, sizeErr := orchestration.PlaintextSize(length)
			if sizeErr != nil {
				h.writeDecryptionError(w, orchestration.ErrForeignObject, bucket, key)
				return
			}
			length = plaintext
		}
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	}
	if output.ETag != nil {
		w.Header().Set("ETag", *output.ETag)
	}
	if output.LastModified != nil {
		w.Header().Set("Last-Modified", output.LastModified.UTC().Format(http.TimeFormat))
	}
	// Ranged reads work for every object the proxy stores, encrypted included.
	w.Header().Set("Accept-Ranges", "bytes")
	writeVersionHeaders(w, output.VersionId, nil)

	// Entity headers stored with the object. HEAD is documented to return the
	// same headers as GET, and a client that decides how to handle a body from
	// a HEAD (Content-Encoding above all) is misled when they are dropped.
	writeEntityHeaders(w, storedEntityHeaders{
		ContentEncoding:    output.ContentEncoding,
		ContentDisposition: output.ContentDisposition,
		ContentLanguage:    output.ContentLanguage,
		CacheControl:       output.CacheControl,
		Expires:            output.ExpiresString,
	})

	// Copy metadata headers (but filter out encryption metadata)
	cleanedMetadata := h.cleanMetadata(output.Metadata)
	for key, value := range cleanedMetadata {
		w.Header().Set("x-amz-meta-"+key, value)
	}

	w.WriteHeader(http.StatusOK)
}

// ===== PASSTHROUGH OPERATIONS =====
// These operations are passed through to S3 without encryption/decryption

// handleDeleteObjects handles bulk object deletion
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "delete-objects",
		"bucket":    bucket,
	}).Debug("Handling delete objects (passthrough)")

	// S3 requires an integrity header on this request and refuses without one.
	// The body is a few kilobytes and the operation is destructive, so there is
	// no cost argument against checking it (ADR 0012 D14).
	if !request.DeclaresChecksum(r) {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest",
			"Missing required header for this request: Content-MD5 or x-amz-checksum-*")
		return
	}

	// Through the parser: the digest is verified against the decoded body before
	// the document is parsed, and an aws-chunked body is decoded rather than
	// parsed with its framing.
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		if h.errorWriter.WriteChecksumVerdict(w, err) {
			return
		}
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read request body")
		return
	}

	// Parse XML delete request
	var deleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			Key       string `xml:"Key"`
			VersionID string `xml:"VersionId,omitempty"`
		} `xml:"Object"`
		Quiet bool `xml:"Quiet"`
	}

	// #nosec G709 - encoding/xml resolves no external entities and errors on an
	// unknown one in strict mode, so a client document cannot expand or fetch.
	if err := xml.Unmarshal(body, &deleteRequest); err != nil {
		h.logger.WithFields(map[string]interface{}{
			"operation": "delete-objects",
			"bucket":    bucket,
			"error":     err.Error(),
			"bodySize":  len(body),
		}).Error("Failed to parse delete objects XML request")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML", "The XML you provided was not well-formed")
		return
	}

	// Convert parsed objects to AWS SDK types
	objects := make([]types.ObjectIdentifier, len(deleteRequest.Objects))
	for i, obj := range deleteRequest.Objects {
		objects[i] = types.ObjectIdentifier{
			Key: aws.String(obj.Key),
		}
		if obj.VersionID != "" {
			objects[i].VersionId = aws.String(obj.VersionID)
		}
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(deleteRequest.Quiet),
		},
	}

	h.logger.WithFields(map[string]interface{}{
		"operation":   "delete-objects",
		"bucket":      bucket,
		"objectCount": len(objects),
		"quiet":       deleteRequest.Quiet,
	}).Debug("Calling S3 delete objects")

	output, err := h.s3Backend.DeleteObjects(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	// Set response headers
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)

	// Create XML response structure
	type DeleteError struct {
		Key       string `xml:"Key"`
		Code      string `xml:"Code"`
		Message   string `xml:"Message"`
		VersionID string `xml:"VersionId,omitempty"`
	}

	type Deleted struct {
		Key                   string `xml:"Key"`
		VersionID             string `xml:"VersionId,omitempty"`
		DeleteMarker          bool   `xml:"DeleteMarker,omitempty"`
		DeleteMarkerVersionID string `xml:"DeleteMarkerVersionId,omitempty"`
	}

	type DeleteResult struct {
		XMLName xml.Name      `xml:"DeleteResult"`
		Deleted []Deleted     `xml:"Deleted"`
		Errors  []DeleteError `xml:"Error"`
	}

	result := DeleteResult{}

	// Add successfully deleted objects. The delete-marker fields tell a client on a
	// versioned bucket what the delete actually did; without them it cannot undo the
	// delete or address the marker.
	for _, deleted := range output.Deleted {
		result.Deleted = append(result.Deleted, Deleted{
			Key:                   aws.ToString(deleted.Key),
			VersionID:             aws.ToString(deleted.VersionId),
			DeleteMarker:          aws.ToBool(deleted.DeleteMarker),
			DeleteMarkerVersionID: aws.ToString(deleted.DeleteMarkerVersionId),
		})
	}

	// Add errors
	for _, errItem := range output.Errors {
		deleteErr := DeleteError{
			Key:     aws.ToString(errItem.Key),
			Code:    aws.ToString(errItem.Code),
			Message: aws.ToString(errItem.Message),
		}
		if errItem.VersionId != nil {
			deleteErr.VersionID = aws.ToString(errItem.VersionId)
		}
		result.Errors = append(result.Errors, deleteErr)
	}

	// Marshal and write XML response
	xmlData, err := xml.Marshal(result)
	if err != nil {
		h.logger.WithFields(map[string]interface{}{
			"operation": "delete-objects",
			"bucket":    bucket,
			"error":     err.Error(),
		}).Error("Failed to marshal delete objects response")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError", "Failed to generate response")
		return
	}

	// Write XML declaration and response
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		h.logger.WithError(err).Error("Failed to write XML header")
		return
	}
	if _, err := w.Write(xmlData); err != nil {
		h.logger.WithError(err).Error("Failed to write XML data")
		return
	}

	h.logger.WithFields(map[string]interface{}{
		"operation": "delete-objects",
		"bucket":    bucket,
		"deleted":   len(output.Deleted),
		"errors":    len(output.Errors),
	}).Debug("Delete objects completed")
}

// handleObjectTorrent handles object torrent operations
func (h *Handler) handleObjectTorrent(w http.ResponseWriter, r *http.Request, bucket, key string) {
	h.logger.WithFields(map[string]interface{}{
		"operation": "object-torrent",
		"bucket":    bucket,
		"key":       key,
	}).Debug("Handling object torrent (passthrough)")

	input := &s3.GetObjectTorrentInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	output, err := h.s3Backend.GetObjectTorrent(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	defer output.Body.Close()

	// Set content type for torrent file
	w.Header().Set("Content-Type", "application/x-bittorrent")

	// Copy the torrent data
	w.WriteHeader(http.StatusOK)
	_, err = copyWithPooledBuffer(w, output.Body)
	if err != nil {
		h.logger.WithError(err).Error("Failed to copy torrent data")
	}
}

// handleSelectObjectContent refuses S3 Select. The previous implementation
// fabricated its own query, drained the event stream into a discard and answered
// 200 with an empty body, so a client could not tell that nothing was selected.
func (h *Handler) handleSelectObjectContent(w http.ResponseWriter, _ *http.Request, _, _ string) {
	h.errorWriter.WriteNotImplemented(w, "SelectObjectContent")
}

// fillPart reads one part's worth of plaintext and reports whether the stream
// ended, cleanly.
//
// Only a literal io.EOF counts as the end of the object. io.ReadFull cannot make
// that distinction: it reports io.ErrUnexpectedEOF both for the legitimate short
// last read and for a source that stopped early, and the aws-chunked decoder
// raises exactly that error for a body with no terminating chunk. Treating the
// two alike committed a truncated object that then verified against its own
// trailer — a silently short backup that passes every later check — and the
// declared-length guard below cannot catch it, because this path is the one
// taken when no length was declared (ADR 0012 D12).
func fillPart(src io.Reader, buf []byte) (int, bool, error) {
	n := 0
	for n < len(buf) {
		read, err := src.Read(buf[n:])
		n += read
		if err == nil {
			continue
		}
		if err == io.EOF { //nolint:errorlint // the io.Reader contract is an untyped io.EOF; a wrapped one means a framing failure, not the end of the object
			return n, true, nil
		}
		return n, false, err
	}
	return n, false, nil
}

// putObjectAutoMultipart turns a PUT the proxy cannot send in one request — an
// undeclared length, or a plaintext larger than one part — into an internal
// multipart upload the client never sees. It reads into a bounded pool of
// buffers while the upload workers seal and send, so receiving and sending
// overlap (ADR 0024).
//
// Create → UploadParts → Complete, and nothing after it: every metadata value
// exists before the first backend byte, so the finished object is never
// rewritten to attach anything (ADR 0011 D8).
func (h *Handler) putObjectAutoMultipart(
	w http.ResponseWriter, r *http.Request, bucket, key string,
	entity EntityHeaders, attrs StorageAttributes,
) {
	ctx := r.Context()
	partSize := h.getSegmentSize()

	log := h.logger.WithFields(map[string]interface{}{
		"bucket":    bucket,
		"key":       key,
		"part_size": partSize,
	})
	log.Debug("Starting the multipart producer")

	// Under the exit provider the object is stored as the client sent it, on this
	// path as on the single-request one, so no data key is created and no proxy
	// metadata is written. Everything below — the free list, the workers, the
	// abort, the completion — is the same either way; only the sealing step is
	// skipped.
	passThrough := h.encryptionMgr.IsExitProvider()

	var upload *orchestration.SegmentedUpload
	storedMetadata := h.userMetadataFromRequest(r)
	if !passThrough {
		var err error
		upload, err = h.encryptionMgr.NewSegmentedUpload(key, storedMetadata)
		if err != nil {
			log.WithError(err).Error("Failed to prepare the multipart upload")
			h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError", "Failed to prepare encryption for upload")
			return
		}
		// The metadata is complete before the first byte is sent, which is what
		// removes the server-side rewrite that used to follow every completion.
		storedMetadata = upload.Metadata()
	}

	createInput := &s3.CreateMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Metadata: storedMetadata,
	}
	entity.ApplyToCreateMultipartUpload(createInput)
	attrs.ApplyToCreateMultipartUpload(createInput)

	createOutput, err := h.s3Backend.CreateMultipartUpload(ctx, createInput)
	if err != nil {
		log.WithError(err).Error("Failed to create the backend multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}
	uploadID := aws.ToString(createOutput.UploadId)

	// A client disconnect mid-PUT cancels the request context, which is exactly
	// when the abort matters most, so it runs on a context of its own.
	abortUpload := func(reason string, cause error) {
		log.WithError(cause).Errorf("Aborting the multipart upload: %s", reason)
		cleanupCtx, cancelCleanup := utils.CleanupContext(r)
		defer cancelCleanup()
		if _, aerr := h.s3Backend.AbortMultipartUpload(cleanupCtx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		}); aerr != nil {
			log.WithError(aerr).Warn("Failed to abort the backend multipart upload")
		}
	}

	body, berr := h.requestParser.StreamingReader(r)
	if berr != nil {
		// Nothing has been created on the backend at this point but the upload
		// id, so the abort is the whole cleanup.
		abortUpload("the client declared a checksum that is not a digest", berr)
		h.errorWriter.WriteChecksumVerdict(w, berr)
		return
	}
	concurrency := h.getMultipartUploadConcurrency()

	// The producer receives into a buffer while workers seal and send the parts
	// that came before it, so the two never wait for each other (ADR 0024 D2).
	// The free list is what bounds the memory that costs: at most one part per
	// worker plus the one being filled (D4).
	free := make(chan []byte, concurrency+1)
	for i := 0; i <= concurrency; i++ {
		free <- make([]byte, partSize)
	}

	type partJob struct {
		partNumber int
		body       io.Reader
		storedLen  int64
		buffer     []byte
	}
	type partResult struct {
		partNumber int
		etag       string
		err        error
	}

	uploadCtx, cancelUploads := context.WithCancel(ctx)
	defer cancelUploads()

	jobs := make(chan partJob, concurrency)
	results := make(chan partResult, concurrency)

	var workers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				out, err := h.s3Backend.UploadPart(uploadCtx, &s3.UploadPartInput{
					Bucket:        aws.String(bucket),
					Key:           aws.String(key),
					UploadId:      aws.String(uploadID),
					PartNumber:    aws.Int32(int32(job.partNumber)), // #nosec G115 - the producer refuses anything above 10000
					Body:          job.body,
					ContentLength: aws.Int64(job.storedLen),
				})
				// The buffer goes back only once the backend is done with it:
				// the body seals straight out of it while the request runs.
				free <- job.buffer
				if err != nil {
					results <- partResult{partNumber: job.partNumber, err: err}
					continue
				}
				results <- partResult{
					partNumber: job.partNumber,
					etag:       strings.Trim(aws.ToString(out.ETag), "\""),
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	partETags := make(map[int]string)
	var firstUploadErr error
	var firstUploadErrPart int
	var collector sync.WaitGroup
	collector.Add(1)
	go func() {
		defer collector.Done()
		for res := range results {
			if res.err != nil {
				if firstUploadErr == nil {
					firstUploadErr = res.err
					firstUploadErrPart = res.partNumber
					cancelUploads()
				}
				continue
			}
			partETags[res.partNumber] = res.etag
		}
	}()

	var (
		totalPlaintext int64
		sum            dataencryption.Checksum
		producerErr    error
		partNumber     = 1
	)

producerLoop:
	for {
		if uploadCtx.Err() != nil {
			break
		}

		buffer := <-free
		n, eof, readErr := fillPart(body, buffer)
		if readErr != nil {
			free <- buffer
			producerErr = fmt.Errorf("body read failed at part %d: %w", partNumber, readErr)
			cancelUploads()
			break
		}
		if n == 0 && partNumber > 1 {
			// A plaintext that is an exact multiple of the part size ends here,
			// with the previous part already sealed as a middle part. The
			// trailer that closes the chain has to become a part of its own, or
			// the object is stored 40 bytes short and every read of it fails
			// authentication while the upload answered 200 (ADR 0003).
			if passThrough {
				free <- buffer
				break
			}
			trailer, terr := upload.Trailer(sum)
			if terr != nil {
				free <- buffer
				producerErr = fmt.Errorf("trailer after part %d: %w", partNumber-1, terr)
				cancelUploads()
				break
			}
			select {
			case jobs <- partJob{
				partNumber: partNumber,
				body:       bytes.NewReader(trailer),
				storedLen:  int64(len(trailer)),
				buffer:     buffer,
			}:
			case <-uploadCtx.Done():
				free <- buffer
			}
			break
		}
		if partNumber > 10000 {
			free <- buffer
			producerErr = fmt.Errorf("part number %d exceeds the S3 limit of 10000", partNumber)
			cancelUploads()
			break
		}

		var (
			partBody  io.Reader
			storedLen int64
			err       error
		)
		if passThrough {
			partBody = bytes.NewReader(buffer[:n])
			storedLen = int64(n)
			totalPlaintext += int64(n)
		} else {
			var part *orchestration.SealedPart
			part, err = upload.SealPart(totalPlaintext, buffer[:n], eof)
			if err != nil {
				free <- buffer
				producerErr = fmt.Errorf("part %d: %w", partNumber, err)
				cancelUploads()
				break
			}
			totalPlaintext += int64(n)
			sum = sum.Append(part.Sum)

			storedLen = part.StoredLen
			if eof {
				// The proxy chose this layout, so the last part it builds is the
				// last part of the object and the trailer rides on it.
				partBody, storedLen, err = part.BodyWithTrailer(sum)
			} else {
				partBody, err = part.Body()
			}
		}
		if err != nil {
			free <- buffer
			producerErr = fmt.Errorf("part %d: %w", partNumber, err)
			cancelUploads()
			break
		}

		select {
		case jobs <- partJob{partNumber: partNumber, body: partBody, storedLen: storedLen, buffer: buffer}:
		case <-uploadCtx.Done():
			free <- buffer
			break producerLoop
		}

		partNumber++
		if eof {
			break
		}
	}

	close(jobs)
	collector.Wait()

	// A client that hangs up mid-body makes io.ReadFull return
	// io.ErrUnexpectedEOF, which the loop above treats as a clean end of stream.
	// Committing that would store a short object that verifies against its own
	// trailer: a silently truncated backup that passes every check.
	if expected, known := h.requestParser.PlaintextContentLength(r); producerErr == nil && known && totalPlaintext < expected {
		producerErr = fmt.Errorf("client sent %d bytes but declared %d", totalPlaintext, expected)
	}

	// A checksum verdict is the client's mistake, not a proxy failure, so it is
	// answered as the 400 it is rather than through the producer's 500. Asking
	// the verifier is more direct than threading its error out of io.ReadFull,
	// which swallows it whenever a part buffer happened to fill exactly.
	if verdict := request.Verdict(body); verdict != nil {
		abortUpload("the client checksum did not verify", verdict)
		h.errorWriter.WriteChecksumVerdict(w, verdict)
		return
	}

	if producerErr != nil {
		abortUpload("the producer failed", producerErr)
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "UploadError", producerErr.Error())
		return
	}
	if firstUploadErr != nil {
		abortUpload(fmt.Sprintf("UploadPart failed for part %d", firstUploadErrPart), firstUploadErr)
		h.errorWriter.WriteS3Error(w, firstUploadErr, bucket, key)
		return
	}

	partNumbers := make([]int, 0, len(partETags))
	for pn := range partETags {
		partNumbers = append(partNumbers, pn)
	}
	sort.Ints(partNumbers)
	completedParts := make([]types.CompletedPart, 0, len(partNumbers))
	for _, pn := range partNumbers {
		completedParts = append(completedParts, types.CompletedPart{
			PartNumber: aws.Int32(int32(pn)), // #nosec G115 - refused above 10000 by the producer
			ETag:       aws.String(partETags[pn]),
		})
	}

	completeOutput, err := h.s3Backend.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completedParts},
	})
	if err != nil {
		abortUpload("CompleteMultipartUpload failed", err)
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithFields(map[string]interface{}{
		"parts":           len(completedParts),
		"plaintext_bytes": totalPlaintext,
	}).Debug("Multipart producer completed")

	w.Header().Set("ETag", aws.ToString(completeOutput.ETag))
	writeVersionHeaders(w, completeOutput.VersionId, nil)
	w.WriteHeader(http.StatusOK)
}
