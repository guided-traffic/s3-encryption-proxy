package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// AccelerateHandler handles bucket acceleration operations
type AccelerateHandler struct {
	BaseSubResourceHandler
}

// NewAccelerateHandler creates a new accelerate handler
func NewAccelerateHandler(base BaseSubResourceHandler) *AccelerateHandler {
	return &AccelerateHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket acceleration requests
func (h *AccelerateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket acceleration operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketAccelerateConfiguration(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketAccelerateConfiguration(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketAccelerate_"+r.Method)
	}
}

// handleGetBucketAccelerateConfiguration gets bucket acceleration configuration
func (h *AccelerateHandler) handleGetBucketAccelerateConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket acceleration configuration")

	input := &s3.GetBucketAccelerateConfigurationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketAccelerateConfiguration(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutBucketAccelerateConfiguration sets bucket acceleration configuration
func (h *AccelerateHandler) handlePutBucketAccelerateConfiguration(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket acceleration configuration")

	// For now, return not implemented
	h.ErrorWriter.WriteNotImplemented(w, "PutBucketAccelerateConfiguration")
}
