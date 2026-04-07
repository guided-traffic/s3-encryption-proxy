package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// WebsiteHandler handles bucket website operations
type WebsiteHandler struct {
	BaseSubResourceHandler
}

// NewWebsiteHandler creates a new website handler
func NewWebsiteHandler(base BaseSubResourceHandler) *WebsiteHandler {
	return &WebsiteHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket website requests
func (h *WebsiteHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket website operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketWebsite(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketWebsite(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteBucketWebsite(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketWebsite_"+r.Method)
	}
}

// handleGetBucketWebsite gets bucket website configuration
func (h *WebsiteHandler) handleGetBucketWebsite(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket website configuration")

	input := &s3.GetBucketWebsiteInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketWebsite(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutBucketWebsite sets bucket website configuration
func (h *WebsiteHandler) handlePutBucketWebsite(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket website configuration")

	// For now, return not implemented
	h.ErrorWriter.WriteNotImplemented(w, "PutBucketWebsite")
}

// handleDeleteBucketWebsite deletes bucket website configuration
func (h *WebsiteHandler) handleDeleteBucketWebsite(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Deleting bucket website configuration")

	input := &s3.DeleteBucketWebsiteInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.DeleteBucketWebsite(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}
