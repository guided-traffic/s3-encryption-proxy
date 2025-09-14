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

// LoggingHandler handles bucket logging operations
type LoggingHandler struct {
	s3Client      interfaces.S3ClientInterface
	logger        *logrus.Entry
	xmlWriter     *response.XMLWriter
	errorWriter   *response.ErrorWriter
	requestParser *request.Parser
}

// NewLoggingHandler creates a new logging handler
func NewLoggingHandler(
	s3Client interfaces.S3ClientInterface,
	logger *logrus.Entry,
	xmlWriter *response.XMLWriter,
	errorWriter *response.ErrorWriter,
	requestParser *request.Parser,
) *LoggingHandler {
	return &LoggingHandler{
		s3Client:      s3Client,
		logger:        logger,
		xmlWriter:     xmlWriter,
		errorWriter:   errorWriter,
		requestParser: requestParser,
	}
}

// Handle handles bucket logging operations (?logging)
func (h *LoggingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	h.logger.WithFields(logrus.Fields{
		"method": r.Method,
		"bucket": bucket,
	}).Debug("Handling bucket logging operation")

	switch r.Method {
	case http.MethodGet:
		h.handleGetLogging(w, r, bucket)
	case http.MethodPut:
		h.handlePutLogging(w, r, bucket)
	default:
		h.errorWriter.WriteNotImplemented(w, "BucketLogging_"+r.Method)
	}
}

// handleGetLogging handles GET bucket logging requests
func (h *LoggingHandler) handleGetLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Getting bucket logging configuration")

	input := &s3.GetBucketLoggingInput{
		Bucket: aws.String(bucket),
	}

	output, err := h.s3Client.GetBucketLogging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	h.xmlWriter.WriteXML(w, output)
}

// handlePutLogging handles PUT bucket logging requests
func (h *LoggingHandler) handlePutLogging(w http.ResponseWriter, r *http.Request, bucket string) {
	h.logger.WithField("bucket", bucket).Debug("Setting bucket logging configuration")

	// Read the request body
	body, err := h.requestParser.ReadBody(r)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	input := &s3.PutBucketLoggingInput{
		Bucket: aws.String(bucket),
	}

	// Note: In a complete implementation, we'd parse the logging configuration from the body
	if len(body) > 0 {
		h.errorWriter.WriteNotImplemented(w, "PutBucketLogging with body parsing")
		return
	}

	_, err = h.s3Client.PutBucketLogging(r.Context(), input)
	if err != nil {
		h.errorWriter.WriteS3Error(w, err, bucket, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}
