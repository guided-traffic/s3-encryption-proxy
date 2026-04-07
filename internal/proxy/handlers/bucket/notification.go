package bucket

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// NotificationHandler handles bucket notification operations
type NotificationHandler struct {
	BaseSubResourceHandler
}

// NewNotificationHandler creates a new notification handler
func NewNotificationHandler(base BaseSubResourceHandler) *NotificationHandler {
	return &NotificationHandler{BaseSubResourceHandler: base}
}

// Handle handles bucket notification requests
func (h *NotificationHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.Logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket notification operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetBucketNotificationConfiguration(w, r, bucket)
	case http.MethodPut:
		h.handlePutBucketNotificationConfiguration(w, r, bucket)
	default:
		h.ErrorWriter.WriteNotImplemented(w, "BucketNotification_"+r.Method)
	}
}

// handleGetBucketNotificationConfiguration gets bucket notification configuration
func (h *NotificationHandler) handleGetBucketNotificationConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Getting bucket notification configuration")

	input := &s3.GetBucketNotificationConfigurationInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.S3Backend.GetBucketNotificationConfiguration(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}

// handlePutBucketNotificationConfiguration sets bucket notification configuration
func (h *NotificationHandler) handlePutBucketNotificationConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	h.Logger.WithField("bucket", bucket).Debug("Setting bucket notification configuration")

	// Read the request body
	body, err := h.RequestParser.ReadBody(r)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
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
		h.ErrorWriter.WriteNotImplemented(w, "PutBucketNotificationConfiguration with body parsing")
		return
	}

	output, err := h.S3Backend.PutBucketNotificationConfiguration(r.Context(), input)
	if err != nil {
		h.ErrorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.XMLWriter.WriteXML(w, output)
}
