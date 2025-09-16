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

// NotificationHandler handles bucket notification operations
type NotificationHandler struct {
	s3Backend     interfaces.S3BackendInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(
	s3Backend interfaces.S3BackendInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *NotificationHandler {
	return &NotificationHandler{
		s3Backend:     s3Backend,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket notification requests
func (h *NotificationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket notification operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketNotificationConfiguration(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketNotificationConfiguration(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketNotification_"+r.Method)
	}
}

// handleGetBucketNotificationConfiguration gets bucket notification configuration
func (h *NotificationHandler) handleGetBucketNotificationConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket notification configuration")

	input := &s3.GetBucketNotificationConfigurationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Backend.GetBucketNotificationConfiguration(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketNotificationConfiguration sets bucket notification configuration
func (h *NotificationHandler) handlePutBucketNotificationConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket notification configuration")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketNotificationConfigurationInput{
		Bucket: aws.String(bucket),
	}

	// Parse notification configuration from body
	// Note: For now, we'll let the S3 client handle the body parsing
	// In a more complete implementation, we'd parse the XML here
	if len(body) > 0 {
		// This would need proper XML parsing in a complete implementation
		h.errorWriter.WriteNotImplemented(w, "PutBucketNotificationConfiguration with body parsing")
		return
	}

	output, err := h.s3Backend.PutBucketNotificationConfiguration(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
