package multipart

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/middleware"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// maxPartsLimit is what S3 returns at most for one ListParts page, and what a
// larger max-parts is clamped to.
const maxPartsLimit = 1000

// lastModifiedFormat is what S3 emits for a timestamp inside a listing.
const lastModifiedFormat = "2006-01-02T15:04:05.000Z"

// ListHandler handles list operations for multipart uploads
type ListHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewListHandler creates a new list handler
func NewListHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *ListHandler {
	return &ListHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// HandleListParts answers ListParts from the proxy's own part table.
//
// The backend cannot answer it: its part sizes are stored sizes, its ETags are
// over ciphertext the proxy produced, and the object's last part may still be
// held in the session rather than uploaded (ADR 0011 D6, ADR 0010). The table
// the session keeps is what Complete is built from, so it is also what a client
// verifying its own upload has to be told.
//
// It used to answer a fabricated empty document with 200 for any upload id at
// all, which is the accept-discard-report-success shape ADR 0007 exists to
// forbid: a client checking what it had uploaded was told it had uploaded
// nothing.
func (h *ListHandler) HandleListParts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	query := r.URL.Query()
	uploadID := query.Get("uploadId")

	log := h.logger.WithFields(logrus.Fields{
		"method":   r.Method,
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	})

	if uploadID == "" {
		log.Error("Missing uploadId")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"The uploadId query parameter is required")
		return
	}

	maxParts, err := parseListingCount(query.Get("max-parts"), maxPartsLimit, maxPartsLimit)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"The max-parts parameter must be a non-negative integer")
		return
	}
	marker, err := parseListingCount(query.Get("part-number-marker"), 0, 0)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"The part-number-marker parameter must be a non-negative integer")
		return
	}

	// Under the exit provider the proxy keeps no part table: the parts are the
	// client's own bytes at the backend, so the backend is the one that can
	// answer, and its sizes are the plaintext sizes.
	if h.encryptionMgr.IsExitProvider() {
		h.listPassThroughParts(w, r, bucket, key, uploadID, marker, maxParts)
		return
	}

	session, ok := h.encryptionMgr.SegmentedSession(uploadID)
	// An upload id that names a session for another object is not this object's
	// upload, which is what S3 says with NoSuchUpload as well.
	if !ok || session.ObjectKey != key || session.Bucket != bucket {
		log.Debug("No such upload")
		h.errorWriter.WriteGenericError(w, http.StatusNotFound, "NoSuchUpload",
			"The specified multipart upload does not exist")
		return
	}

	doc := listPartsResult{
		XMLNS:            s3Namespace,
		Bucket:           bucket,
		Key:              key,
		UploadID:         uploadID,
		StorageClass:     "STANDARD",
		PartNumberMarker: marker,
		MaxParts:         maxParts,
		Owner:            callerOwner(r),
	}

	for _, part := range session.Parts() {
		if part.PartNumber <= marker {
			continue
		}
		if len(doc.Parts) == maxParts {
			doc.IsTruncated = true
			break
		}
		doc.Parts = append(doc.Parts, partEntry{
			PartNumber:   part.PartNumber,
			LastModified: formatListTime(part.UploadedAt),
			ETag:         `"` + part.ETag + `"`,
			// The plaintext length the client sent. The part the session still
			// holds is listed with it too: the client uploaded it and was answered
			// an ETag for it.
			Size: part.PlaintextLen,
		})
	}
	if len(doc.Parts) > 0 {
		doc.NextPartNumberMarker = doc.Parts[len(doc.Parts)-1].PartNumber
	}

	h.xmlWriter.WriteS3Document(w, doc)
	log.WithField("parts", len(doc.Parts)).Debug("Listed the upload's parts")
}

// listPassThroughParts answers ListParts from the backend, which under the exit
// provider is where the whole truth about the upload lives.
func (h *ListHandler) listPassThroughParts(
	w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, marker, maxParts int,
) {
	input := &s3.ListPartsInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		UploadId:            aws.String(uploadID),
		MaxParts:            aws.Int32(int32(maxParts)), // #nosec G115 - bounded by maxPartsLimit above
	}
	if marker > 0 {
		input.PartNumberMarker = aws.String(strconv.Itoa(marker))
	}

	output, err := h.s3Backend.ListParts(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	doc := listPartsResult{
		XMLNS:            s3Namespace,
		Bucket:           bucket,
		Key:              key,
		UploadID:         uploadID,
		StorageClass:     string(output.StorageClass),
		PartNumberMarker: marker,
		MaxParts:         maxParts,
		IsTruncated:      aws.ToBool(output.IsTruncated),
		Owner:            callerOwner(r),
	}
	if doc.StorageClass == "" {
		doc.StorageClass = "STANDARD"
	}
	for i := range output.Parts {
		part := &output.Parts[i]
		doc.Parts = append(doc.Parts, partEntry{
			PartNumber:   int(aws.ToInt32(part.PartNumber)),
			LastModified: formatListTime(aws.ToTime(part.LastModified)),
			ETag:         aws.ToString(part.ETag),
			Size:         aws.ToInt64(part.Size),
		})
	}
	if len(doc.Parts) > 0 {
		doc.NextPartNumberMarker = doc.Parts[len(doc.Parts)-1].PartNumber
	}

	h.xmlWriter.WriteS3Document(w, doc)
}

// HandleListMultipartUploads forwards the listing to the backend. It names
// uploads rather than bytes, so nothing in it describes a stored size and
// nothing has to be converted; the document is still the proxy's own, because
// the backend's is the backend's description of itself (ADR 0008).
func (h *ListHandler) HandleListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	query := r.URL.Query()

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling list multipart uploads")

	maxUploads, err := parseListingCount(query.Get("max-uploads"), maxPartsLimit, maxPartsLimit)
	if err != nil {
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"The max-uploads parameter must be a non-negative integer")
		return
	}

	input := &s3.ListMultipartUploadsInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		MaxUploads:          aws.Int32(int32(maxUploads)), // #nosec G115 - bounded by maxPartsLimit above
	}
	for _, p := range []struct {
		name  string
		field **string
	}{
		{"prefix", &input.Prefix},
		{"delimiter", &input.Delimiter},
		{"key-marker", &input.KeyMarker},
		{"upload-id-marker", &input.UploadIdMarker},
	} {
		if v := query.Get(p.name); v != "" {
			*p.field = aws.String(v)
		}
	}

	output, err := h.s3Backend.ListMultipartUploads(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	owner := callerOwner(r)
	doc := listMultipartUploadsResult{
		XMLNS:              s3Namespace,
		Bucket:             bucket,
		KeyMarker:          aws.ToString(output.KeyMarker),
		UploadIDMarker:     aws.ToString(output.UploadIdMarker),
		NextKeyMarker:      aws.ToString(output.NextKeyMarker),
		NextUploadIDMarker: aws.ToString(output.NextUploadIdMarker),
		Delimiter:          aws.ToString(output.Delimiter),
		Prefix:             aws.ToString(output.Prefix),
		MaxUploads:         aws.ToInt32(output.MaxUploads),
		IsTruncated:        aws.ToBool(output.IsTruncated),
	}
	for i := range output.Uploads {
		upload := &output.Uploads[i]
		doc.Uploads = append(doc.Uploads, uploadEntry{
			Key:          aws.ToString(upload.Key),
			UploadID:     aws.ToString(upload.UploadId),
			Initiated:    formatListTime(aws.ToTime(upload.Initiated)),
			StorageClass: string(upload.StorageClass),
			// The backend's own owner and initiator name the account the proxy
			// holds credentials for, which is not the client that made this
			// request and is not the client's business (ADR 0008).
			Owner:     owner,
			Initiator: owner,
		})
	}
	for i := range output.CommonPrefixes {
		doc.CommonPrefixes = append(doc.CommonPrefixes, commonPrefix{
			Prefix: aws.ToString(output.CommonPrefixes[i].Prefix),
		})
	}

	h.xmlWriter.WriteS3Document(w, doc)
}

// parseListingCount reads a non-negative listing parameter. An absent value is
// fallback, a value above limit is clamped to it (limit 0 means no ceiling), and
// anything that is not a non-negative number is an error: a client that asked
// for something the proxy cannot do is told, not served a page it did not ask
// for.
func parseListingCount(raw string, fallback, limit int) (int, error) {
	if raw == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 0, errors.New("not a non-negative integer")
	}
	if limit > 0 && n > limit {
		n = limit
	}
	return n, nil
}

// callerOwner describes the authenticated client, the same identity the object
// listings report (ADR 0008).
func callerOwner(r *http.Request) *ownerEntry {
	id := middleware.ClientIdentity(r.Context())
	if id == "" {
		return nil
	}
	return &ownerEntry{ID: id, DisplayName: id}
}

func formatListTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(lastModifiedFormat)
}
