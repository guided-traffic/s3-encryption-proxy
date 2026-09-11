package multipart

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/orchestration"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/handlers/object"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/utils"
	"github.com/sirupsen/logrus"
)

// CompleteHandler handles complete multipart upload operations
type CompleteHandler struct {
	s3Backend     interfaces.S3BackendInterface
	encryptionMgr *orchestration.Manager
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewCompleteHandler creates a new complete handler
func NewCompleteHandler(
	s3Backend interfaces.S3BackendInterface,
	encryptionMgr *orchestration.Manager,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *CompleteHandler {
	return &CompleteHandler{
		s3Backend:     s3Backend,
		encryptionMgr: encryptionMgr,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// CompleteMultipartUpload represents the XML payload for completing a multipart upload
type CompleteMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompletedPart represents a completed part in the multipart upload
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// Handle handles complete multipart upload requests
func (h *CompleteHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	// Parse query parameters
	uploadID := r.URL.Query().Get("uploadId")

	log := h.logger.WithFields(logrus.Fields{
		"bucket":   bucket,
		"key":      key,
		"uploadID": uploadID,
		"method":   r.Method,
	})

	log.Debug("CompleteMultipartUpload - Request received")

	if uploadID == "" {
		log.Error("Missing uploadId")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidArgument",
			"The uploadId query parameter is required")
		return
	}

	// Read and decode the request body
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Error("Failed to read request body")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	log.WithField("body_size", len(bodyData)).Debug("Read request body")

	// Parse the XML. encoding/xml resolves entity references itself; pre-decoding
	// with html.UnescapeString would turn an escaped &lt;Part&gt; inside an ETag
	// into real markup and let the request body inject elements.
	var completeUpload CompleteMultipartUpload
	if err := xml.Unmarshal(bodyData, &completeUpload); err != nil {
		log.WithError(err).WithField("body", string(bodyData)).Error("Failed to parse XML body")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema")
		return
	}

	log.WithField("parts_count", len(completeUpload.Parts)).Debug("Parsed XML successfully")

	// Validate and sort parts
	if len(completeUpload.Parts) == 0 {
		log.Error("No parts provided")
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidRequest",
			"You must specify at least one part")
		return
	}

	// Sort parts by part number
	sort.Slice(completeUpload.Parts, func(i, j int) bool {
		return completeUpload.Parts[i].PartNumber < completeUpload.Parts[j].PartNumber
	})

	// Validate part sequence
	for i, part := range completeUpload.Parts {
		if part.PartNumber < 1 || part.PartNumber > 10000 {
			log.WithField("part_number", part.PartNumber).Error("Invalid part number")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartNumber",
				"Part number must be between 1 and 10000")
			return
		}
		if part.ETag == "" {
			log.WithField("part_number", part.PartNumber).Error("Missing ETag")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPart",
				"One or more of the specified parts could not be found. The part may not have been "+
					"uploaded, or the specified entity tag may not have matched the part's entity tag.")
			return
		}
		// Check for duplicate part numbers
		if i > 0 && completeUpload.Parts[i-1].PartNumber == part.PartNumber {
			log.WithField("part_number", part.PartNumber).Error("Duplicate part number")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartOrder",
				"The list of parts was not in ascending order. Parts must be ordered by part number.")
			return
		}
	}

	// log.WithField("parts", completeUpload.Parts).Debug("Parts validated and sorted")

	ctx := r.Context()

	// What the client says it uploaded. Complete is built from the proxy's own
	// part table; this map exists to check the two against each other.
	parts := make(map[int]string, len(completeUpload.Parts))
	for _, part := range completeUpload.Parts {
		// Validate part number is within int32 range
		if part.PartNumber < 1 || part.PartNumber > 10000 {
			h.logger.WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": part.PartNumber,
			}).Error("Part number out of valid range in complete request")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPartNumber", "Part number must be between 1 and 10000")
			return
		}

		parts[part.PartNumber] = strings.Trim(part.ETag, "\"")
	}

	// Under the exit provider the proxy added nothing to any part, so it also
	// owns no part table: the list the client sent is the object, and the backend
	// is the one that checks it. Nothing is sealed and no record closes the
	// object, because there is no chain to close.
	var completedParts []types.CompletedPart
	if h.encryptionMgr.IsExitProvider() {
		numbers := make([]int, 0, len(parts))
		for number := range parts {
			numbers = append(numbers, number)
		}
		sort.Ints(numbers)
		completedParts = make([]types.CompletedPart, 0, len(numbers))
		for _, number := range numbers {
			completedParts = append(completedParts, types.CompletedPart{
				PartNumber: aws.Int32(int32(number)), // #nosec G115 - validated above against 1..10000
				ETag:       aws.String(parts[number]),
			})
		}
	} else {
		session, ok := h.encryptionMgr.SegmentedSession(uploadID)
		if !ok {
			log.Error("No such upload")
			h.errorWriter.WriteGenericError(w, http.StatusNotFound, "NoSuchUpload",
				"The specified multipart upload does not exist")
			return
		}
		// The client's list is not what the object is built from, but it is what
		// the client believes it uploaded. A disagreement is reported rather than
		// silently overruled (ADR 0011 D6). The upload survives it, as it does at
		// S3, so a client that sent a wrong list can complete again with the right
		// one.
		if err := session.VerifyClientParts(parts); err != nil {
			log.WithError(err).Warn("Refusing a completion list that does not describe this upload")
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPart",
				"One or more of the specified parts could not be found. The part may not have been "+
					"uploaded, or the specified entity tag may not have matched the part's entity tag.")
			return
		}

		defer h.encryptionMgr.CloseSegmentedSession(uploadID)

		// The part table the proxy kept is the authority, not the list the client
		// sent: the proxy chose where every part starts, and a layout it cannot
		// store as a chain is refused here rather than discovered on the first read.
		final, err := session.Complete()
		if err != nil {
			log.WithError(err).Error("Refusing to complete an upload whose parts do not form a chain")
			h.abortUpload(r, bucket, key, uploadID, log)
			h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "InvalidPart",
				"The parts of this upload do not form a segment chain")
			return
		}

		// The record that closes the object: the short last part sealed with the
		// trailer behind it, or the trailer as a part of its own. Either way it is
		// the object's last part, the one part S3 exempts from its minimum size.
		finalResult, err := h.s3Backend.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      aws.String(uploadID),
			PartNumber:    aws.Int32(int32(final.PartNumber)), // #nosec G115 - part numbers are validated on upload
			Body:          bytes.NewReader(final.Body),
			ContentLength: aws.Int64(int64(len(final.Body))),
		})
		if err != nil {
			log.WithError(err).Error("Failed to store the record that closes the object")
			h.abortUpload(r, bucket, key, uploadID, log)
			h.errorWriter.WriteS3Error(w, err, bucket, key)
			return
		}
		session.RecordETag(final.PartNumber, strings.Trim(aws.ToString(finalResult.ETag), "\""))

		completedParts = make([]types.CompletedPart, 0, len(parts)+1)
		for _, number := range session.PartNumbers() {
			etag, _ := session.PartETag(number)
			completedParts = append(completedParts, types.CompletedPart{
				PartNumber: aws.Int32(int32(number)), // #nosec G115 - validated on upload
				ETag:       aws.String(etag),
			})
		}
	}

	completeInput := &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: completedParts},
	}
	// The verb that commits the object takes the two entity-tag preconditions,
	// so a create-if-absent multipart upload behaves as it does at S3
	// (ADR 0007 D7).
	object.ReadConditionalHeaders(r).ApplyToCompleteMultipartUpload(completeInput)

	result, err := h.s3Backend.CompleteMultipartUpload(ctx, completeInput)
	if err != nil {
		log.WithError(err).Error("Failed to complete multipart upload")
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	finalETag := aws.ToString(result.ETag)
	finalVersionID := aws.ToString(result.VersionId)

	// Set response headers
	if finalETag != "" {
		w.Header().Set("ETag", finalETag)
	}
	if finalVersionID != "" {
		w.Header().Set("x-amz-version-id", finalVersionID)
	}
	if result.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(result.ServerSideEncryption))
	}
	if result.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *result.SSEKMSKeyId)
	}

	writeXMLDocument(w, h.logger, completeMultipartUploadResult{
		Location: completionLocation(r),
		Bucket:   bucket,
		Key:      key,
		ETag:     finalETag,
	})

	log.WithFields(logrus.Fields{
		"etag":        finalETag,
		"versionID":   finalVersionID,
		"parts_count": len(completedParts),
	}).Debug("Successfully completed multipart upload")
}

// abortUpload removes an upload the proxy refuses to complete. It runs on a
// context of its own: the client may already be gone, and the parts would
// otherwise stay behind at the backend.
func (h *CompleteHandler) abortUpload(r *http.Request, bucket, key, uploadID string, log *logrus.Entry) {
	abortCtx, cancelAbort := utils.CleanupContext(r)
	defer cancelAbort()
	if _, err := h.s3Backend.AbortMultipartUpload(abortCtx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}); err != nil {
		log.WithError(err).Warn("Failed to abort the refused multipart upload")
	}
}

// completionLocation builds the <Location> element of the completion document.
//
// It points at the proxy, never at the backend: the backend's own Location names
// the internal storage endpoint and is text that endpoint controls, so it must
// not reach a client.
//
// X-Forwarded-Proto and X-Forwarded-Host win over the connection the proxy sees,
// because r.TLS describes the last hop only: behind a TLS-terminating ingress
// the proxy reports http:// for a connection the client made over https://.
// Both headers are client-settable when this proxy is exposed directly, and no
// trusted-proxy list guards them — deliberately. The element is reflected only
// to the sender of the request and drives no decision here, so a client forging
// them misleads only itself (ADR 0007, 023 decision 6).
func completionLocation(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}

	host := r.Host
	if forwarded := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = forwarded
	}

	return scheme + "://" + host + r.URL.EscapedPath()
}

// firstForwardedValue takes the first entry of a comma-separated forwarding
// header, which is the value the original client sent.
func firstForwardedValue(header string) string {
	first, _, _ := strings.Cut(header, ",")
	return strings.TrimSpace(first)
}
