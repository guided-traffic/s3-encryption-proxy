package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/interfaces"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/request"
	"github.com/guided-traffic/s3-encryption-proxy/internal/proxy/response"
	"github.com/sirupsen/logrus"
)

// TaggingHandler handles bucket tagging operations
type TaggingHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewTaggingHandler creates a new tagging handler
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

// Handle handles bucket tagging requests
func (h *TaggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket tagging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketTagging(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketTagging(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteBucketTagging(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketTagging_"+r.Method)
	}
}

// handleGetBucketTagging gets bucket tags
func (h *TaggingHandler) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket tags")

	input := &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketTagging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketTagging sets bucket tags
func (h *TaggingHandler) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket tags")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketTaggingInput{
		Bucket: aws.String(bucket),
	}

	// Parse tagging configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.errorWriter.WriteNotImplemented(w, "PutBucketTagging with body parsing")
		return
	}

	output, err := h.s3Backend.PutBucketTagging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handleDeleteBucketTagging deletes bucket tags
func (h *TaggingHandler) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket tags")

	input := &s3.DeleteBucketTaggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.DeleteBucketTagging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
