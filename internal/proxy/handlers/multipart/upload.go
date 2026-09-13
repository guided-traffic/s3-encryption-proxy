package multipart

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// UploadHandler handles upload part operations
type UploadHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewUploadHandler creates a new upload handler
func NewUploadHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *UploadHandler {
	return &UploadHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles upload part requests
func (h *UploadHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	// Detailed request logging for debugging
	h.logger.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"uploadId":      uploadID,
		"partNumber":    partNumberStr,
		"method":        r.Method,
		"contentLength": r.ContentLength,
		"contentType":   r.Header.Get("Content-Type"),
		"userAgent":     r.Header.Get("User-Agent"),
		"contentEnc":    r.Header.Get("Content-Encoding"),
		"host":          r.Host,
		"remoteAddr":    r.RemoteAddr,
		"requestURI":    r.RequestURI,
	}).Debug("UploadPart - Request details")

	if uploadID == "" || partNumberStr == "" {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumberStr,
		}).Error("Missing uploadId or partNumber")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"A part upload requires both the uploadId and the partNumber query parameters")
		return
	}

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 || partNumber > 10000 {
		h.logger.WithFields(logrus.Fields{
			"bucket":       bucket,
			"key":          key,
			"uploadId":     uploadID,
			"partNumber":   partNumberStr,
			"parsedNumber": partNumber,
			"parseError":   err,
		}).Error("Invalid partNumber")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"Part number must be an integer between 1 and 10000, inclusive")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Trace("UploadPart - Parameters validated successfully")

	// Under the exit provider the part is stored as the client sent it, so there
	// is no session and nothing to seal — the backend owns the part layout.
	if h.encryptionMgr.IsExitProvider() {
		bodyData, ok := h.readWholePart(w, r)
		if !ok {
			return
		}
		h.uploadPassThroughPart(w, r, bucket, key, uploadID, partNumber, bodyData)
		return
	}

	// A part whose declared plaintext length covers whole segments and clears the
	// backend's minimum is forwarded while it arrives (ADR 0024 D1). Everything
	// else — a short last part, or a length the request does not really declare —
	// is held, because it is sealed at Complete together with the trailer.
	//
	// The decision is taken on the length alone and before the session lookup, so
	// a part the proxy will hold is still read before the upload is looked up, the
	// way it always was.
	plaintextLen, lengthKnown := h.requestParser.PlaintextContentLength(r)
	if lengthKnown && orchestration.CanStreamPart(plaintextLen) {
		session, ok := h.encryptionMgr.SegmentedSession(uploadID)
		if !ok {
			h.noSuchUpload(w, bucket, key, uploadID, partNumber)
			return
		}
		h.uploadStreamedPart(w, r, bucket, key, uploadID, partNumber, session, plaintextLen)
		return
	}

	// A part that is held is held in memory, so the budget that bounds the hold
	// has to bound the read as well: reading first and refusing afterwards means
	// any part a client cares to send is buffered in full before the proxy
	// decides it may not keep it (ADR 0011 D5).
	bodyData, bodyOK := h.readHeldPart(w, r, h.encryptionMgr.ShortPartBufferSize())
	if !bodyOK {
		return
	}

	session, ok := h.encryptionMgr.SegmentedSession(uploadID)
	if !ok {
		h.noSuchUpload(w, bucket, key, uploadID, partNumber)
		return
	}

	h.uploadSegmentedPart(w, r, bucket, key, uploadID, partNumber, session, bodyData)
}

// noSuchUpload answers a part for an upload this proxy does not have.
func (h *UploadHandler) noSuchUpload(w http.ResponseWriter, bucket, key, uploadID string, partNumber int) {
	h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	}).Error("No such upload")
	h.errorWriter.WriteGenericError(w, http.StatusNotFound, "NoSuchUpload",
		"The specified multipart upload does not exist")
}

// readWholePart reads a part the proxy has to hold, answering the client itself
// and reporting false when it could not. A checksum the client declared and the
// part did not match is that client's mistake, and the part never reaches the
// backend (ADR 0012 D7).
func (h *UploadHandler) readWholePart(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	bodyData, err := h.requestParser.ReadBody(r)
	return h.readPart(w, r, bodyData, err)
}

// readHeldPart reads a part the proxy has to keep until Complete, refusing one
// larger than the short-part budget before its bytes are in memory rather than
// after.
func (h *UploadHandler) readHeldPart(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	bodyData, err := h.requestParser.ReadBodyLimited(r, limit)
	if errors.Is(err, request.ErrBodyTooLarge) {
		h.logger.WithField("limit", limit).
			Error("Refusing a last part larger than optimizations.multipart_short_part_buffer_size")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge",
			orchestration.ErrShortPartTooLarge.Error())
		return nil, false
	}
	return h.readPart(w, r, bodyData, err)
}

func (h *UploadHandler) readPart(w http.ResponseWriter, r *http.Request, bodyData []byte, err error) ([]byte, bool) {
	if err != nil {
		if h.errorWriter.WriteChecksumVerdict(w, err) {
			return nil, false
		}
		h.logger.WithError(err).Error("Failed to read request body")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "IncompleteBody",
			"The request body terminated before the declared number of bytes was read")
		return nil, false
	}
	h.requestParser.ResetBody(r, bodyData)
	return bodyData, true
}

// uploadStreamedPart seals one client part as the backend pulls it, so no byte
// of the part waits for the last byte of the part to arrive (ADR 0024 D1).
//
// The checksum verdict still lands before anything is committed: the verifier
// holds the final payload byte back, so the sealed body cannot satisfy the
// Content-Length this request promised while verification is still open, and the
// backend refuses a part it did not fully receive (ADR 0012 D7).
func (h *UploadHandler) uploadStreamedPart(
	w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int,
	session *orchestration.SegmentedSession, plaintextLen int64,
) {
	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	})

	body, err := h.requestParser.StreamingReader(r)
	if err != nil {
		h.errorWriter.WriteChecksumVerdict(w, err)
		return
	}

	part, err := session.SealStreamingPart(partNumber, plaintextLen, body)
	if err != nil {
		if errors.Is(err, orchestration.ErrPartNumberReserved) {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
			return
		}
		log.WithError(err).Error("Refusing the part")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPart", err.Error())
		return
	}

	sealed, err := part.Body()
	if err != nil {
		log.WithError(err).Error("Failed to seal the part")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError",
			"Failed to encrypt the part")
		return
	}

	result, uploadErr := h.s3Backend.UploadPart(r.Context(), &s3.UploadPartInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		UploadId:            aws.String(uploadID),
		PartNumber:          aws.Int32(int32(partNumber)), // #nosec G115 - validated against 1..10000 above
		Body:                sealed,
		ContentLength:       aws.Int64(part.StoredLen),
		// The client's Content-MD5 describes the plaintext part while the body
		// here is ciphertext, so client checksums never reach the backend.
	})

	// The verifier is asked directly, and whatever the backend answered: its
	// error reaches here through net/http, *url.Error and smithy wrapping, so the
	// answer for a client mistake must not depend on that chain staying
	// unwrappable — nor on the backend having refused the short body that a
	// failed verification produces.
	if verdict := request.Verdict(body); verdict != nil {
		h.errorWriter.WriteChecksumVerdict(w, verdict)
		return
	}
	if uploadErr != nil {
		log.WithError(uploadErr).Error("Failed to upload the part")
		h.errorWriter.WriteS3Error(w, uploadErr, bucket, key)
		return
	}

	// What the part actually carried, which is what Complete combines into the
	// object's trailer. A streamed part has no checksum before this point, and it
	// only has the right one if the backend pulled the whole body: a backend that
	// answers a part it did not take in full has not stored it, whatever it says,
	// and entering what was sealed up to that point would put a length and a
	// checksum in the table that describe no part. Every failure above returns
	// without touching the table, so a part stored under this number by an earlier
	// attempt survives a later one that fails.
	sum, ok := part.Checksum()
	if !ok || sum.Length != plaintextLen {
		log.WithFields(logrus.Fields{
			"declared_bytes": plaintextLen,
			"sealed_bytes":   sum.Length,
		}).Error("The backend acknowledged a part it did not take in full")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "InternalError",
			"The part was not stored completely")
		return
	}
	session.RecordStreamedPart(partNumber, part.Offset(), sum)

	cleanETag := strings.Trim(aws.ToString(result.ETag), "\"")
	session.RecordETag(partNumber, cleanETag)

	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)

	log.WithFields(logrus.Fields{
		"plaintext_bytes": sum.Length,
		"stored_bytes":    part.StoredLen,
		"etag":            cleanETag,
	}).Debug("Part streamed and stored")
}

// uploadSegmentedPart seals one client part and stores it as one backend part.
//
// A part that covers whole segments is sealed and sent straight away. A part
// that does not cannot be stored on its own — a chain with a short segment in
// the middle writes cleanly and never reads — so the session holds it until
// Complete, and the client gets an answer without a backend round trip. Only one
// such part may exist per upload, because only one can be last (ADR 0011).
//
// The client's range of part numbers is 1..9999 here rather than S3's 1..10000:
// the trailer needs a part number of its own whenever the last client part is
// large enough to carry one behind it (ADR 0011 D4).
func (h *UploadHandler) uploadSegmentedPart(
	w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int,
	session *orchestration.SegmentedSession, plaintext []byte,
) {
	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	})

	part, err := session.SealPart(partNumber, plaintext, h.encryptionMgr.ShortPartBufferSize())
	if err != nil {
		log.WithError(err).Error("Refusing the part")
		if errors.Is(err, orchestration.ErrShortPartAlreadyBuffered) {
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooSmall",
				"Only the last part of an upload may be shorter than the part size")
			return
		}
		if errors.Is(err, orchestration.ErrPartNumberReserved) {
			// S3 allows 10000 parts; the proxy keeps the last number for the
			// trailer (ADR 0011 D4). Refusing it here costs the client one part
			// number instead of failing the upload at Complete, after every byte
			// has been transferred.
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument", err.Error())
			return
		}
		if errors.Is(err, orchestration.ErrShortPartBufferFull) {
			// Back pressure, not a refusal (ADR 0011 D5): the bytes are held by
			// other uploads right now, SDKs retry this with backoff, and the
			// upload is still there when they do.
			h.errorWriter.WriteGenericError(w, http.StatusServiceUnavailable, "SlowDown",
				"Please reduce your request rate.")
			return
		}
		if errors.Is(err, orchestration.ErrShortPartTooLarge) {
			// Larger than the whole budget: no other upload finishing can make
			// room, so this is permanent and a 503 would have the SDK retry it
			// until its own attempt limit.
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "EntityTooLarge", err.Error())
			return
		}
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPart", err.Error())
		return
	}

	if part == nil {
		// Held for Complete. The ETag the client gets back is the proxy's own:
		// the part table, not the client's list, is what Complete is built from.
		etag, _ := session.PartETag(partNumber)
		log.WithField("bytes", len(plaintext)).Debug("Holding the last part until Complete")
		w.Header().Set("ETag", `"`+etag+`"`)
		w.WriteHeader(http.StatusOK)
		return
	}

	body, err := part.Body()
	if err != nil {
		log.WithError(err).Error("Failed to seal the part")
		h.errorWriter.WriteGenericError(w, http.StatusInternalServerError, "EncryptionError",
			"Failed to encrypt the part")
		return
	}

	result, err := h.s3Backend.UploadPart(r.Context(), &s3.UploadPartInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		UploadId:            aws.String(uploadID),
		PartNumber:          aws.Int32(int32(partNumber)), // #nosec G115 - validated against 1..10000 above
		Body:                body,
		ContentLength:       aws.Int64(part.StoredLen),
		// The client's Content-MD5 describes the plaintext part while the body
		// here is ciphertext, so client checksums never reach the backend.
	})
	if err != nil {
		log.WithError(err).Error("Failed to upload the part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	cleanETag := strings.Trim(aws.ToString(result.ETag), "\"")
	session.RecordETag(partNumber, cleanETag)

	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)

	log.WithFields(logrus.Fields{
		"plaintext_bytes": len(plaintext),
		"stored_bytes":    part.StoredLen,
		"etag":            cleanETag,
	}).Debug("Part stored")
}

// uploadPassThroughPart stores one client part unchanged. Under the exit
// provider the proxy adds nothing to a part, so it also imposes no part layout:
// the backend's own rules about part sizes are the ones the client meets.
func (h *UploadHandler) uploadPassThroughPart(
	w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int, plaintext []byte,
) {
	log := h.logger.WithFields(logrus.Fields{
		"bucket":     bucket,
		"key":        key,
		"uploadId":   uploadID,
		"partNumber": partNumber,
	})

	result, err := h.s3Backend.UploadPart(r.Context(), &s3.UploadPartInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		UploadId:            aws.String(uploadID),
		PartNumber:          aws.Int32(int32(partNumber)), // #nosec G115 - validated against 1..10000 above
		Body:                bytes.NewReader(plaintext),
		ContentLength:       aws.Int64(int64(len(plaintext))),
	})
	if err != nil {
		log.WithError(err).Error("Failed to upload the part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)
}
