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

// RequestPaymentHandler handles bucket request payment operations
type RequestPaymentHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewRequestPaymentHandler creates a new request payment handler
func NewRequestPaymentHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *RequestPaymentHandler {
	return &RequestPaymentHandler{
		s3Backend:      s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket request payment requests
func (h *RequestPaymentHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket request payment operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketRequestPayment(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketRequestPayment(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketRequestPayment_"+r.Method)
	}
}

// handleGetBucketRequestPayment gets bucket request payment configuration
func (h *RequestPaymentHandler) handleGetBucketRequestPayment(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket request payment configuration")

	input := &s3.GetBucketRequestPaymentInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketRequestPayment(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketRequestPayment sets bucket request payment configuration
func (h *RequestPaymentHandler) handlePutBucketRequestPayment(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket request payment configuration")

	// For now, return not implemented
	h.errorWriter.WriteNotImplemented(w, "PutBucketRequestPayment")
}
