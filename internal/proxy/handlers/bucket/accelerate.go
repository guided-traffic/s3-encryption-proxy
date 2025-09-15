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

// AccelerateHandler handles bucket acceleration operations
type AccelerateHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewAccelerateHandler creates a new accelerate handler
func NewAccelerateHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *AccelerateHandler {
	return &AccelerateHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket acceleration requests
func (h *AccelerateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket acceleration operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketAccelerateConfiguration(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketAccelerateConfiguration(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketAccelerate_"+r.Method)
	}
}

// handleGetBucketAccelerateConfiguration gets bucket acceleration configuration
func (h *AccelerateHandler) handleGetBucketAccelerateConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket acceleration configuration")

	input := &s3.GetBucketAccelerateConfigurationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketAccelerateConfiguration(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketAccelerateConfiguration sets bucket acceleration configuration
func (h *AccelerateHandler) handlePutBucketAccelerateConfiguration(w http.ResponseWriter, _ *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket acceleration configuration")

	// For now, return not implemented
	h.errorWriter.WriteNotImplemented(w, "PutBucketAccelerateConfiguration")
}
