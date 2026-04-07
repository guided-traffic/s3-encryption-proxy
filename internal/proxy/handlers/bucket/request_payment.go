package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// RequestPaymentHandler handles bucket request payment operations
type RequestPaymentHandler struct {
	BaseSubResourceHandler
}

// NewRequestPaymentHandler creates a new request payment handler
func NewRequestPaymentHandler(base BaseSubResourceHandler) *RequestPaymentHandler {
	return &RequestPaymentHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket request payment requests
func (h *RequestPaymentHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket request payment operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketRequestPayment(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketRequestPayment(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketRequestPayment_"+r.Method)
	}
}

// handleGetBucketRequestPayment gets bucket request payment configuration
func (h *RequestPaymentHandler) handleGetBucketRequestPayment(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket request payment configuration")

	input := &s3.GetBucketRequestPaymentInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketRequestPayment(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutBucketRequestPayment sets bucket request payment configuration
func (h *RequestPaymentHandler) handlePutBucketRequestPayment(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket request payment configuration")

	// For now, return not implemented
	h.ErrorWriter.WriteNotImplemented(w, "PutBucketRequestPayment")
}
