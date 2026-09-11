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
		"transferEnc":   r.Header.Get("Transfer-Encoding"),
		"contentEnc":    r.Header.Get("Content-Encoding"),
		"host":          r.Host,
		"remoteAddr":    r.RemoteAddr,
		"requestURI":    r.RequestURI,
	}).Debug("UploadPart - Request details")

	// Read request body with automatic chunked decoding if needed
	bodyData, err := h.requestParser.ReadBody(r)
	if err != nil {
		// A checksum the client declared and the part did not match is that
		// client's mistake, and the part never reaches the backend (ADR 0012 D7).
		if h.errorWriter.WriteChecksumVerdict(w, err) {
			return
		}
		h.logger.WithError(err).Error("Failed to read request body")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "IncompleteBody",
			"The request body terminated before the declared number of bytes was read")
		return
	}

	// Reset request body with processed data
	h.requestParser.ResetBody(r, bodyData)

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
		h.uploadPassThroughPart(w, r, bucket, key, uploadID, partNumber, bodyData)
		return
	}

	session, ok := h.encryptionMgr.SegmentedSession(uploadID)
	if !ok {
		h.logger.WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadId":   uploadID,
			"partNumber": partNumber,
		}).Error("No such upload")
		h.errorWriter.WriteGenericError(w, http.StatusNotFound, "NoSuchUpload",
			"The specified multipart upload does not exist")
		return
	}

	h.uploadSegmentedPart(w, r, bucket, key, uploadID, partNumber, session, bodyData)
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
			// Back pressure, not a refusal (ADR 0011 D5): SDKs retry this with
			// backoff and the upload is still there when they do.
			h.errorWriter.WriteGenericError(w, http.StatusServiceUnavailable, "SlowDown",
				"Please reduce your request rate.")
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
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)), // #nosec G115 - validated against 1..10000 above
		Body:          body,
		ContentLength: aws.Int64(part.StoredLen),
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
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		UploadId:      aws.String(uploadID),
		PartNumber:    aws.Int32(int32(partNumber)), // #nosec G115 - validated against 1..10000 above
		Body:          bytes.NewReader(plaintext),
		ContentLength: aws.Int64(int64(len(plaintext))),
	})
	if err != nil {
		log.WithError(err).Error("Failed to upload the part")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	w.Header().Set("ETag", aws.ToString(result.ETag))
	w.WriteHeader(http.StatusOK)
}
