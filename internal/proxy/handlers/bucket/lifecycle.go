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

// LifecycleHandler handles bucket lifecycle operations
type LifecycleHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewLifecycleHandler creates a new lifecycle handler
func NewLifecycleHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *LifecycleHandler {
	return &LifecycleHandler{
		s3Backend:      s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket lifecycle requests
func (h *LifecycleHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket lifecycle operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketLifecycleConfiguration(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketLifecycleConfiguration(w, r, bucket)
	case http.MethodDelete:
		h.handleDeleteBucketLifecycle(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketLifecycle_"+r.Method)
	}
}

// handleGetBucketLifecycleConfiguration gets bucket lifecycle configuration
func (h *LifecycleHandler) handleGetBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket lifecycle configuration")

	input := &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketLifecycleConfiguration(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketLifecycleConfiguration sets bucket lifecycle configuration
func (h *LifecycleHandler) handlePutBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket lifecycle configuration")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	}

	// Parse lifecycle configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.errorWriter.WriteNotImplemented(w, "PutBucketLifecycleConfiguration with body parsing")
		return
	}

	output, err := h.s3Backend.PutBucketLifecycleConfiguration(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handleDeleteBucketLifecycle deletes bucket lifecycle configuration
func (h *LifecycleHandler) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket lifecycle configuration")

	input := &s3.DeleteBucketLifecycleInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.DeleteBucketLifecycle(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
