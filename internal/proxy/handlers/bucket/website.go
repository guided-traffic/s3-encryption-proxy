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

// WebsiteHandler handles bucket website operations
type WebsiteHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewWebsiteHandler creates a new website handler
func NewWebsiteHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *WebsiteHandler {
	return &WebsiteHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket website requests
func (h *WebsiteHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
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
		h.errorWriter.WriteNotImplemented(w, "BucketWebsite_"+r.Method)
	}
}

// handleGetBucketWebsite gets bucket website configuration
func (h *WebsiteHandler) handleGetBucketWebsite(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket website configuration")

	input := &s3.GetBucketWebsiteInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.GetBucketWebsite(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutBucketWebsite sets bucket website configuration
func (h *WebsiteHandler) handlePutBucketWebsite(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket website configuration")

	// For now, return not implemented
	h.errorWriter.WriteNotImplemented(w, "PutBucketWebsite")
}

// handleDeleteBucketWebsite deletes bucket website configuration
func (h *WebsiteHandler) handleDeleteBucketWebsite(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Deleting bucket website configuration")

	input := &s3.DeleteBucketWebsiteInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.DeleteBucketWebsite(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}
