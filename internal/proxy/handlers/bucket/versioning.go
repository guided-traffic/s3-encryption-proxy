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

// VersioningHandler handles bucket versioning operations
type VersioningHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewVersioningHandler creates a new versioning handler
func NewVersioningHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *VersioningHandler {
	return &VersioningHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket versioning requests
func (h *VersioningHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket versioning operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketVersioning(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketVersioning(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketVersioning_"+r.Method)
	}
}

// handleGetBucketVersioning gets bucket versioning configuration
func (h *VersioningHandler) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket versioning configuration")

	input := &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.GetBucketVersioning(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketVersioning sets bucket versioning configuration
func (h *VersioningHandler) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket versioning configuration")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
	}

	// Parse versioning configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.errorWriter.WriteNotImplemented(w, "PutBucketVersioning with body parsing")
		return
	}

	output, err := h.s3Client.PutBucketVersioning(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
