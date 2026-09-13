package object

import (
	"encoding/xml"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// TaggingHandler handles object tagging operations
type TaggingHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewTaggingHandler creates a new object tagging handler
func NewTaggingHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *TaggingHandler {
	return &TaggingHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles object tagging operations (?tagging). The tags travel to the
// backend and the backend's answer comes back: they carry no plaintext of the
// object and the proxy has nothing to add to them (ADR 0007 D4). They are stored
// in the clear next to the ciphertext, which SECURITY_ARCHITECTURE.md §3.6
// states as the accepted cost.
func (h *TaggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
		"key":    key,
	}).Debug("Handling object tagging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetTagging(w, r, bucket, key)
	case http.MethodPut:
		h.handlePutTagging(w, r, bucket, key)
	case http.MethodDelete:
		h.handleDeleteTagging(w, r, bucket, key)
	default:
		h.errorWriter.WriteNotImplemented(w, "ObjectTagging_"+r.Method)
	}
}

func (h *TaggingHandler) handleGetTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	output, err := h.s3Backend.GetObjectTagging(r.Context(), &s3.GetObjectTaggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	writeVersionHeaders(w, output.VersionId, nil)
	h.xmlWriter.WriteS3Document(w, newTaggingDocument(output.TagSet))
}

func (h *TaggingHandler) handlePutTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	body, ok := readDocument(w, r, h.requestParser, h.errorWriter, h.logger, bucket, key)
	if !ok {
		return
	}

	var doc taggingDocument
	if err := xml.Unmarshal(body, &doc); err != nil { // #nosec G709 -- encoding/xml fills a fixed struct and resolves no entities
		h.errorWriter.WriteGenericError(w, http.StatusBadRequest, "MalformedXML",
			"The XML you provided was not well-formed or did not validate against our published schema")
		return
	}

	output, err := h.s3Backend.PutObjectTagging(r.Context(), &s3.PutObjectTaggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
		Tagging:             &types.Tagging{TagSet: doc.tagSet()},
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	writeVersionHeaders(w, output.VersionId, nil)
	w.WriteHeader(http.StatusOK)
}

func (h *TaggingHandler) handleDeleteTagging(w http.ResponseWriter, r *http.Request, bucket, key string) {
	output, err := h.s3Backend.DeleteObjectTagging(r.Context(), &s3.DeleteObjectTaggingInput{
		Bucket:              aws.String(bucket),
		ExpectedBucketOwner: request.ExpectedBucketOwner(r),
		Key:                 aws.String(key),
		VersionId:           objectVersionID(r),
	})
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, key)
		return
	}

	writeVersionHeaders(w, output.VersionId, nil)
	w.WriteHeader(http.StatusNoContent)
}
