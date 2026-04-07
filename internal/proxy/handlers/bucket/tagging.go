package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// TaggingHandler handles bucket tagging operations
type TaggingHandler struct {
	BaseSubResourceHandler
}

// NewTaggingHandler creates a new tagging handler
func NewTaggingHandler(base BaseSubResourceHandler) *TaggingHandler {
	return &TaggingHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket tagging requests
func (h *TaggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
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
		h.ErrorWriter.WriteNotImplemented(w, "BucketTagging_"+r.Method)
	}
}

// handleGetBucketTagging gets bucket tags
func (h *TaggingHandler) handleGetBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket tags")

	input := &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketTagging(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutBucketTagging sets bucket tags
func (h *TaggingHandler) handlePutBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket tags")

	// Read the request body
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
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
		h.ErrorWriter.WriteNotImplemented(w, "PutBucketTagging with body parsing")
		return
	}

	output, err := h.S3Backend.PutBucketTagging(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handleDeleteBucketTagging deletes bucket tags
func (h *TaggingHandler) handleDeleteBucketTagging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Deleting bucket tags")

	input := &s3.DeleteBucketTaggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.DeleteBucketTagging(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}
